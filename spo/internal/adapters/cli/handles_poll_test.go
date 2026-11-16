package cli

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/handles"
	"github.com/mochipool/workbench/spo/internal/app/wallet"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

type fakeHandles struct {
	asked []string
	err   error
}

func (f *fakeHandles) Resolve(_ context.Context, text string) (handles.Resolved, error) {
	f.asked = append(f.asked, text)
	if f.err != nil {
		return handles.Resolved{}, f.err
	}
	return handles.Resolved{Address: sendTo, Kind: handles.RootCIP68, VerifiedBy: "holder utxo"}, nil
}

func withHandles(f *sendFixture, hr HandleResolver, offline bool) {
	wire := f.deps.Wire
	f.deps.Wire = func(st ports.Store, o WireOptions) (*Env, error) {
		env, err := wire(st, o)
		env.Handles = hr
		if offline {
			env.Mode = ModeOffline
			env.Absent(CapAdaHandle, handles.ErrOffline.Error())
		}
		return env, err
	}
}

// The operator sees the handle AND the address it resolved to, before the
// question, and the default answer is No.
func TestHandleDestinationShownWithItsAddressBeforeTheQuestion(t *testing.T) {
	f := newSendFixture(t)
	hr := &fakeHandles{}
	withHandles(f, hr, false)
	term := &scriptTerm{t: t, lines: []string{""}}
	err := f.run(t, term, "wallet", "send", "w", "$Alice", "ALL")
	if !errors.Is(err, wallet.ErrDeclined) {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	out := f.out.String()
	if !strings.Contains(out, "to           $alice ("+sendTo+")") {
		t.Errorf("the handle and its address are not both shown:\n%s", out)
	}
	if len(hr.asked) != 1 || hr.asked[0] != "$alice" || len(f.queue.got) != 0 || term.asked != 1 {
		t.Errorf("asked %v, queued %d, questions %d", hr.asked, len(f.queue.got), term.asked)
	}
}

func TestHandleRefusals(t *testing.T) {
	// Offline: the resolver refuses with its reason.
	f := newSendFixture(t)
	withHandles(f, handles.Resolver{Offline: true}, true)
	err := f.run(t, &scriptTerm{t: t}, "wallet", "send", "w", "$alice", "ALL")
	if err == nil || !strings.Contains(err.Error(), "not offline") {
		t.Errorf("offline: %v", err)
	}
	// No resolver at all.
	f = newSendFixture(t)
	if err := f.run(t, &scriptTerm{t: t}, "wallet", "send", "w", "$alice", "ALL"); err == nil || !strings.Contains(err.Error(), "ADA Handle") {
		t.Errorf("no resolver: %v", err)
	}
	// An unresolvable handle is an error, nothing is queued.
	f = newSendFixture(t)
	withHandles(f, &fakeHandles{err: handles.ErrNotFound}, false)
	if err := f.run(t, &scriptTerm{t: t}, "wallet", "send", "w", "$alice", "ALL", "--yes"); !errors.Is(err, handles.ErrNotFound) || len(f.queue.got) != 0 {
		t.Errorf("not found: %v", err)
	}
}

func TestAdaHandleCapabilityByMode(t *testing.T) {
	e := &Env{Mode: ModeLight, Handles: &fakeHandles{}}
	if !e.Has(CapAdaHandle) {
		t.Error("light mode with a resolver lacks ada-handle")
	}
	e = &Env{Mode: ModeOffline, Handles: handles.Resolver{Offline: true}}
	e.Absent(CapAdaHandle, handles.ErrOffline.Error())
	if e.Has(CapAdaHandle) || !strings.Contains(e.Reason(CapAdaHandle), "not offline") {
		t.Errorf("offline: %v %q", e.Has(CapAdaHandle), e.Reason(CapAdaHandle))
	}
}

// ---- polls ----

type fakePolls struct {
	calls int
}

func (f *fakePolls) Source() chain.Source { return "fake koios" }
func (f *fakePolls) PollQuestion(context.Context, chain.TxID) (ports.PollQuestion, error) {
	f.calls++
	return ports.PollQuestion{Lines: []string{"Should the pool raise its margin?"}, Options: [][]string{{"Yes"}, {"No"}}}, nil
}

var pollTx = strings.Repeat("ab", 32)

func withPolls(f *sendFixture, pr ports.PollQuestionReader) {
	f.deps.Config = memConfig(map[string]WorkspaceConfig{f.dir: {Network: "preview", Mode: ModeLight, Koios: &KoiosConfig{}}})
	wire := f.deps.Wire
	f.deps.Wire = func(st ports.Store, o WireOptions) (*Env, error) {
		env, err := wire(st, o)
		if pr != nil {
			env.Polls = pr
		} else {
			env.Absent(CapPollQuestion, "SPO polls are read from the chain: run in light mode")
		}
		return env, err
	}
}

func TestPollShow(t *testing.T) {
	f := newSendFixture(t)
	withPolls(f, &fakePolls{})
	if err := f.run(t, &scriptTerm{t: t}, "poll", "show", pollTx); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	for _, want := range []string{"Should the pool raise its margin?", "  0  Yes", "  1  No", "question hash", "fake koios"} {
		if !strings.Contains(f.out.String(), want) {
			t.Errorf("%q missing:\n%s", want, f.out.String())
		}
	}
	// Offline: refused with the reason, before any question.
	f = newSendFixture(t)
	withPolls(f, nil)
	err := f.run(t, failTerm{t}, "poll", "show", pollTx)
	if err == nil || !strings.Contains(err.Error(), "poll-question") || !strings.Contains(err.Error(), "light mode") {
		t.Errorf("%v", err)
	}
	// A bad hash is refused by the use case.
	f = newSendFixture(t)
	withPolls(f, &fakePolls{})
	if err := f.run(t, &scriptTerm{t: t}, "poll", "show", "xyz"); err == nil || !strings.Contains(err.Error(), "64 hex") {
		t.Errorf("%v", err)
	}
}

func TestPollAnswerAsksConfirmsAndWrites(t *testing.T) {
	f := newSendFixture(t)
	withPolls(f, &fakePolls{})
	out := filepath.Join(t.TempDir(), "ans.cbor")
	term := &scriptTerm{t: t, lines: []string{"1", "y"}}
	if err := f.run(t, term, "poll", "answer", pollTx, "--out", out); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	b, err := os.ReadFile(out)
	if err != nil || len(b) == 0 {
		t.Fatalf("%v %d", err, len(b))
	}
	if term.asked != 2 {
		t.Errorf("asked %d", term.asked)
	}
	// A declined confirmation writes nothing; an existing file is not replaced.
	out2 := filepath.Join(t.TempDir(), "no.cbor")
	if err := f.run(t, &scriptTerm{t: t, lines: []string{""}}, "poll", "answer", pollTx, "--option", "0", "--out", out2); err == nil {
		t.Error("declined answer succeeded")
	}
	if _, err := os.Stat(out2); err == nil {
		t.Error("a declined answer wrote a file")
	}
	if err := f.run(t, &scriptTerm{t: t}, "poll", "answer", pollTx, "--option", "1", "--yes", "--out", out); err == nil {
		t.Error("an existing file was replaced")
	}
	// An option outside the poll is refused.
	if err := f.run(t, &scriptTerm{t: t}, "poll", "answer", pollTx, "--option", "7", "--yes", "--out", out2); err == nil || !strings.Contains(err.Error(), "not one of the poll's options") {
		t.Errorf("%v", err)
	}
	// No terminal and no --option.
	if err := f.run(t, &scriptTerm{t: t}, "poll", "answer", pollTx, "--out", out2); err == nil || !strings.Contains(err.Error(), "--option") {
		t.Errorf("%v", err)
	}
}

func TestPollSubmitQueuesAnAnswerWithTheColdKeyAsRequiredSigner(t *testing.T) {
	f := newSendFixture(t)
	withPolls(f, &fakePolls{})
	// The pool's cold key, as a key file of the upstream layout.
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(0x40 + i)
	}
	vk := ed25519Pub(seed)
	os.WriteFile(filepath.Join(f.dir, "p.node.skey"), []byte(`{"type":"StakePoolSigningKey_ed25519","description":"","cborHex":"5820`+hex.EncodeToString(seed)+`"}`), 0o400)
	os.WriteFile(filepath.Join(f.dir, "p.node.vkey"), []byte(`{"type":"StakePoolVerificationKey_ed25519","description":"","cborHex":"5820`+hex.EncodeToString(vk)+`"}`), 0o644)
	// No answer: refused with the hint.
	err := f.run(t, &scriptTerm{t: t}, "poll", "submit", "w", sendTo, "2000000", "p", "--yes")
	if err == nil || !strings.Contains(err.Error(), "--poll") {
		t.Fatalf("%v", err)
	}
	if len(f.queue.got) != 0 {
		t.Fatal("queued without an answer")
	}
	term := &scriptTerm{t: t}
	if err := f.run(t, term, "poll", "submit", "w", sendTo, "2000000", "p", "--poll", pollTx, "--option", "1", "--yes"); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	if len(f.queue.got) != 1 {
		t.Fatalf("queued %d", len(f.queue.got))
	}
	ws, err := (native.TxViewer{}).Witnesses(f.queue.got[0].Tx.CBOR)
	if err != nil || len(ws) != 2 {
		t.Fatalf("witnesses %d: %v (payer and cold key)", len(ws), err)
	}
	if !strings.Contains(f.out.String(), "Answer for pool p") || !strings.Contains(f.out.String(), "Queued transaction") {
		t.Errorf("%s", f.out.String())
	}
}

func ed25519Pub(seed []byte) []byte {
	return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
}
