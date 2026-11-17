package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/fsstore"
	"github.com/mochipool/workbench/spo/internal/adapters/transferfile"
	"github.com/mochipool/workbench/spo/internal/app/airgap"
	"github.com/mochipool/workbench/spo/internal/app/txconfirm"
	domassets "github.com/mochipool/workbench/spo/internal/domain/assets"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/transfer"
	"github.com/mochipool/workbench/spo/internal/ports"
)

type stubSubmitter struct {
	id  chain.TxID
	err error
}

func (stubSubmitter) Source() chain.Source { return "stub" }
func (s stubSubmitter) Submit(context.Context, []byte) (chain.TxID, error) {
	return s.id, s.err
}

type stubIDs struct{ id chain.TxID }

func (s stubIDs) TransactionID([]byte) (chain.TxID, error) { return s.id, nil }

// After an unknown submission outcome the error names the command that checks
// the transaction, with the id computed from the transaction itself, and says
// not to rebuild it.
//
// spec: SPO-Xconfirm-PRE-005
func TestUnknownSubmitOutcomeNamesTxStatus(t *testing.T) {
	local := chain.TxID{0xab, 0xcd}
	env := &Env{Submitter: stubSubmitter{err: chain.NewOutcomeUnknown("x: unknown")}, TxIDs: stubIDs{local}}
	rec := recordSubmits(env)
	_, err := env.Submitter.Submit(context.Background(), []byte{1})
	if err == nil || !errors.Is(err, chain.ErrSubmitOutcomeUnknown) {
		t.Fatalf("%v", err)
	}
	for _, w := range []string{"spo tx status " + local.String(), "Do not build the transaction again from the same inputs"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("missing %q in %v", w, err)
		}
	}
	if len(rec.submitted()) != 0 {
		t.Error("a submission with an unknown outcome was recorded as accepted")
	}
	// Without a local id calculator the text is the adapter's own.
	env = &Env{Submitter: stubSubmitter{err: chain.NewOutcomeUnknown("x: unknown")}}
	recordSubmits(env)
	if _, err = env.Submitter.Submit(context.Background(), []byte{1}); err == nil || strings.Contains(err.Error(), "spo tx status") {
		t.Errorf("%v", err)
	}
}

// An ordinary refusal is passed through unchanged, and an accepted
// transaction is recorded.
func TestRecorderPassesRefusalsAndRecordsAcceptances(t *testing.T) {
	boom := errors.New("rejected")
	env := &Env{Submitter: stubSubmitter{err: boom}, TxIDs: stubIDs{}}
	recordSubmits(env)
	if _, err := env.Submitter.Submit(context.Background(), []byte{1}); err != boom {
		t.Fatalf("%v", err)
	}
	id := chain.TxID{7}
	env = &Env{Submitter: stubSubmitter{id: id}, TxIDs: stubIDs{id}}
	rec := recordSubmits(env)
	if _, err := env.Submitter.Submit(context.Background(), []byte{9}); err != nil {
		t.Fatal(err)
	}
	if s := rec.submitted(); len(s) != 1 || s[0].ID != id || s[0].CBOR[0] != 9 {
		t.Fatalf("%+v", s)
	}
	if recordSubmits(&Env{}) != nil {
		t.Error("a recorder without a submitter")
	}
}

// Every command that submits a transaction has the wait flags, and a command
// that reads or only builds files does not.
//
// spec: SPO-Xconfirm-IF-005
func TestWaitFlagsOnEverySubmittingCommand(t *testing.T) {
	root := NewRoot(Deps{})
	for _, p := range [][]string{
		{"wallet", "send"}, {"wallet", "send-assets"}, {"wallet", "claim-rewards"}, {"stake", "register"}, {"stake", "delegate"},
		{"stake", "vote-delegate"}, {"stake", "deregister"}, {"stake", "claim-rewards"}, {"pool", "register"}, {"pool", "retire"},
		{"offline", "execute"}, {"poll", "submit"}, {"drep", "register"}, {"drep", "retire"}, {"vote", "cast"}, {"action", "submit"},
	} {
		c := find(root, strings.Join(p, " "))
		if c == nil {
			continue // a command another change renamed or removed is not this test's business
		}
		for _, f := range []string{"wait", "wait-confirmations", "wait-timeout"} {
			if c.Flags().Lookup(f) == nil {
				t.Errorf("%s has no --%s", strings.Join(p, " "), f)
			}
		}
	}
	found := 0
	for _, p := range [][]string{{"wallet", "send"}, {"offline", "execute"}, {"stake", "register"}, {"pool", "register"}} {
		if find(root, strings.Join(p, " ")) != nil {
			found++
		}
	}
	if found != 4 {
		t.Fatalf("the core submitting commands moved: %d of 4 found", found)
	}
	for _, p := range [][]string{{"address"}, {"pool", "opcert", "check"}, {"offline", "info"}, {"tx", "status"}} {
		if c := find(root, strings.Join(p, " ")); c != nil && c.Flags().Lookup("wait") != nil {
			t.Errorf("%s offers --wait but submits nothing", strings.Join(p, " "))
		}
	}
}

// A reason or a source name a provider chose is escaped by the code that
// prints it, whatever the adapter did before.
//
// spec: SPO-Xconfirm-SEC-001
func TestAnswerLinesEscapeProviderText(t *testing.T) {
	hostile := "\x1b]0;pwned\x07\x1b[2J‮"
	lines := answerLines([]chain.ProviderAnswer{
		{Source: chain.Source("koios" + hostile), Reading: chain.Unknown[chain.TxStatus](hostile)},
	})
	if strings.ContainsAny(lines, "\x1b\x07‮") {
		t.Fatalf("a control character was printed raw: %q", lines)
	}
	if !strings.Contains(lines, `\u{1b}`) {
		t.Errorf("the escape is not shown as an escape: %q", lines)
	}
}

// What is waited for is the id computed from the bytes that were sent. An id
// the provider answered that differs is an error, is reported by the wait, and
// is never waited for as if it were the transaction.
//
// spec: SPO-Xconfirm-INV-007
func TestRecorderTiesTheIDToTheBytesSent(t *testing.T) {
	local, theirs := chain.TxID{1}, chain.TxID{2}
	env := &Env{Submitter: stubSubmitter{id: local}, TxIDs: stubIDs{local}}
	rec := recordSubmits(env)
	if _, err := env.Submitter.Submit(context.Background(), []byte{9}); err != nil {
		t.Fatal(err)
	}
	if s := rec.submitted(); len(s) != 1 || s[0].ID != local {
		t.Fatalf("%+v", s)
	}
	env = &Env{Submitter: stubSubmitter{id: theirs}, TxIDs: stubIDs{local}}
	rec = recordSubmits(env)
	_, err := env.Submitter.Submit(context.Background(), []byte{9})
	if err == nil || !strings.Contains(err.Error(), theirs.String()) || !strings.Contains(err.Error(), local.String()) {
		t.Fatalf("%v", err)
	}
	if !errors.Is(err, chain.ErrSubmitOutcomeUnknown) || !strings.Contains(err.Error(), "spo tx status "+local.String()) {
		t.Errorf("an id mismatch is an unknown outcome that names the status command: %v", err)
	}
	if len(rec.submitted()) != 0 || len(rec.unverified()) != 1 {
		t.Errorf("a mismatched id was recorded as the transaction: %+v %v", rec.submitted(), rec.unverified())
	}
	// With no way to compute the id the submission is not waited for, and the wait says why.
	env = &Env{Submitter: stubSubmitter{id: local}}
	rec = recordSubmits(env)
	if _, err := env.Submitter.Submit(context.Background(), []byte{9}); err != nil {
		t.Fatal(err)
	}
	if len(rec.submitted()) != 0 || len(rec.unverified()) != 1 {
		t.Fatalf("%+v %v", rec.submitted(), rec.unverified())
	}
	var out bytes.Buffer
	a := &app{d: Deps{Out: &out}}
	err = a.waitAfterSubmit(context.Background(), env, &chainFlags{waitDepth: 1, waitTimeout: time.Minute}, rec)
	if ExitCode(err) != 1 || strings.Contains(err.Error(), "confirmed") || !strings.Contains(err.Error(), "could not be checked") {
		t.Fatalf("%v", err)
	}
}

type stubViewer struct{ view party.TxView }

func (stubViewer) BodyOf(tx []byte) ([]byte, error)      { return tx, nil }
func (v stubViewer) View([]byte) (party.TxView, error)   { return v.view, nil }
func (stubViewer) AuxOf([]byte) ([]byte, error)          { return nil, nil }
func (stubViewer) ViewAux([]byte) (party.AuxView, error) { return party.AuxView{}, nil }

var _ ports.TxViewer = stubViewer{}

// A transaction with collateral is never given inputs to the node's
// absence proof: one that failed phase 2 is in a block with its inputs unspent.
//
// spec: SPO-Xconfirm-INV-006
func TestRequestForKeepsTransactionsWithCollateralOutOfTheInputsProof(t *testing.T) {
	in := party.ViewInput{TxID: [32]byte{5}, Index: 1}
	ttl := uint64(77)
	plain := &Env{TxViewer: stubViewer{party.TxView{Inputs: []party.ViewInput{in}, TTL: &ttl}}}
	req, known := requestFor(plain, submittedTx{ID: chain.TxID{1}, CBOR: []byte{1}})
	if len(req.Inputs) != 1 || req.Inputs[0].Index != 1 || !known || *req.ValidUntil != 77 {
		t.Fatalf("%+v %v", req, known)
	}
	withCol := &Env{TxViewer: stubViewer{party.TxView{Inputs: []party.ViewInput{in}, CollateralInputs: []party.ViewInput{{TxID: [32]byte{6}}}}}}
	req, _ = requestFor(withCol, submittedTx{ID: chain.TxID{1}, CBOR: []byte{1}})
	if len(req.Inputs) != 0 {
		t.Fatalf("inputs %v were offered for a transaction with collateral", req.Inputs)
	}
}

type fixedStatus struct {
	src string
	r   chain.Reading[chain.TxStatus]
}

func (f fixedStatus) Source() chain.Source { return chain.Source(f.src) }
func (f fixedStatus) TxStatus(context.Context, ports.TxStatusQuery) (chain.Reading[chain.TxStatus], error) {
	return f.r, nil
}

// Every transaction's outcome is reported, and the exit status is the worst.
//
// spec: SPO-Xconfirm-OUT-003
func TestWaitReportsEveryTransactionAndExitsWithTheWorst(t *testing.T) {
	var out bytes.Buffer
	now := time.Unix(1000, 0)
	a := &app{d: Deps{Out: &out, Now: func() time.Time { return now },
		Sleep: func(_ context.Context, d time.Duration) error { now = now.Add(d); return nil }}}
	st := fixedStatus{"p", chain.Unknown[chain.TxStatus]("down")} // every transaction: unknown (22)
	env := &Env{TxWatchers: []ports.TxWatcher{{Status: st}}}
	env.Submitter = stubSubmitter{}
	rec := &submitRecorder{subs: []submittedTx{{ID: chain.TxID{1}}, {ID: chain.TxID{2}}, {ID: chain.TxID{3}}}}
	err := a.waitAfterSubmit(context.Background(), env, &chainFlags{waitDepth: 1, waitTimeout: time.Minute}, rec)
	if ExitCode(err) != ExitWaitUnknown {
		t.Fatalf("%v", err)
	}
	for _, id := range []chain.TxID{{1}, {2}, {3}} {
		if !strings.Contains(out.String()+err.Error(), id.String()) || strings.Count(out.String()+err.Error(), "no provider gave a usable answer") < 3 {
			t.Errorf("transaction %s has no outcome:\n%s\n%v", id, out.String(), err)
		}
	}
	// The ranking: a disagreement is worse than a timeout, a timeout than an expiry.
	if !(waitRank[ExitWaitExpired] < waitRank[ExitWaitTimedOut] && waitRank[ExitWaitTimedOut] < waitRank[ExitWaitUnknown] &&
		waitRank[ExitWaitUnknown] < waitRank[ExitWaitDisagree] && waitRank[ExitWaitDisagree] < waitRank[1] && waitRank[1] < waitRank[ExitWaitCancel]) {
		t.Error("the order of outcomes changed")
	}
}

type silentStatus struct{}

func (silentStatus) Source() chain.Source { return "stub" }
func (silentStatus) TxStatus(context.Context, ports.TxStatusQuery) (chain.Reading[chain.TxStatus], error) {
	return chain.None[chain.TxStatus](), nil
}

// When the wait of `offline execute` ends expired, the expiry is recorded in the
// history of the transfer file as a confirmation is, and a wait that ends any
// other way records nothing (SPO-Xconfirm-PR-022).
//
// spec: SPO-Xconfirm-PR-022
func TestOfflineExecuteRecordsAnExpiredWait(t *testing.T) {
	path := filepath.Join(t.TempDir(), "offlineTransfer.json")
	if err := os.WriteFile(path, []byte(`{"protocol":{"era":"conway","parameters":{"txFeePerByte":44}},"history":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &transferfile.File{Path: path}
	id := chain.TxID{0x31}
	for name, tc := range map[string]struct {
		outcome txconfirm.Outcome
		want    bool
	}{"expired": {txconfirm.OutcomeExpired, true}, "timed out": {txconfirm.OutcomeTimedOut, false}} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(`{"protocol":{"era":"conway","parameters":{"txFeePerByte":44}},"history":[]}`), 0o600); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			a := &app{d: Deps{Out: &out}}
			s := &session{rec: &submitRecorder{}}
			env := &Env{Clock: cliClock{}, Bundle: f, TxWatchers: []ports.TxWatcher{{Status: silentStatus{}}}}
			a.executeSettling(s, env, WireOptions{TransferFile: path}, &chainFlags{}, airgap.ExecuteResult{TxID: id, Submitted: true,
				Entry: transfer.QueuedEntry{AssetPending: `{"txid":"` + id.String() + `"}`}})
			if len(s.rec.onUnsettled) == 0 {
				t.Fatal("no hook for an unsettled wait")
			}
			for _, h := range s.rec.onUnsettled {
				h(context.Background(), id, txconfirm.Result{Outcome: tc.outcome})
			}
			b, _, _ := f.ReadBundle(context.Background())
			oc, _ := b.Outcomes()
			if got := oc[id.String()].Expired; got != tc.want || (len(oc) == 1) != tc.want {
				t.Errorf("%s: outcomes %+v\n%s", name, oc, out.String())
			}
		})
	}
}

// A settling command that could not wait names each new pending record and the
// exact settle command, and says what its exit status 0 means.
//
// spec: SPO-Xconfirm-IF-006
func TestNotWaitedNoticeNamesThePendingRecordAndTheCommand(t *testing.T) {
	st, err := fsstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	put := func(id chain.TxID) {
		p := domassets.Pending{Kind: domassets.PendingPoolRegistration, TxID: id.String(), Pool: "mypool", Epoch: "7", Stamp: "x"}
		b, _ := p.Marshal()
		if err := st.Update(context.Background(), func(w ports.Writer) error { return w.Put(ports.Ref{Name: p.TxID, Kind: ports.PendingUpdate}, b) }); err != nil {
			t.Fatal(err)
		}
	}
	old, fresh := chain.TxID{1}, chain.TxID{2}
	put(old)
	var out bytes.Buffer
	a := &app{d: Deps{Out: &out}}
	s := &session{Store: st}
	before := a.pendingIDs(context.Background(), s, true)
	put(fresh)
	a.printNotWaited(context.Background(), s, before)
	got := out.String()
	for _, w := range []string{"PENDING", "registration record of pool mypool", fresh.String(), "run: spo tx settle", "means submitted or queued, not confirmed"} {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in %q", w, got)
		}
	}
	if strings.Contains(got, old.String()) {
		t.Errorf("an older pending record was named: %q", got)
	}
}
