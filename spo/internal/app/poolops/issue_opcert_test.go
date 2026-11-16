package poolops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/fsstore"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/ports"
)

const (
	coldVKeyHex = "5820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	kesVKeyHex  = "5820a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
)

// fakeIssuer is a signer: it records what it was asked and returns a marker
// instead of a certificate.
type fakeIssuer struct {
	calls []ports.OpCertRequest
	err   error
	hook  func()
}

func (f *fakeIssuer) Profile() custody.Profile {
	return custody.NewProfile("fake").Allow(custody.RolePoolCold, custody.OpIssueOpCert)
}

func (f *fakeIssuer) IssueOpCert(_ context.Context, _ custody.Key[custody.PoolCold], req ports.OpCertRequest) ([]byte, error) {
	f.calls = append(f.calls, req)
	if f.hook != nil {
		f.hook()
	}
	if f.err != nil {
		return nil, f.err
	}
	return []byte("opcert-counter-" + string(rune('0'+req.Counter%10)) + "\n"), nil
}

// directory has a signer for the vault only, like the real build.
type directory struct{ vault ports.Signer }

func (d directory) SignerFor(k custody.KeyRef) (ports.Signer, error) {
	if k.Holder == custody.HolderVault {
		return d.vault, nil
	}
	return nil, errors.New("no hardware signer is configured")
}

type fakeTip struct {
	slot  uint64
	calls int
}

func (f *fakeTip) Source() chain.Source { return "fake" }
func (f *fakeTip) Tip(context.Context) (chain.Tip, error) {
	f.calls++
	return chain.Tip{Slot: f.slot}, nil
}

type fakeGenesis struct{}

func (fakeGenesis) Genesis(context.Context) (chain.Genesis, error) {
	return chain.Genesis{SlotLength: time.Second, SlotsPerKESPeriod: 129600, MaxKESEvolutions: 62, EpochLength: 86400}, nil
}

type fakeCounters struct {
	reading chain.Reading[uint64]
	err     error
}

func (fakeCounters) Source() chain.Source { return "fake" }
func (f fakeCounters) OpCertCounter(context.Context, chain.PoolID) (chain.Reading[uint64], error) {
	return f.reading, f.err
}

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

type issueEnv struct {
	uc     IssueOperationalCertificate
	signer *fakeIssuer
	tip    *fakeTip
	dir    string
}

func put(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o400); err != nil {
		t.Fatal(err)
	}
}

func envelopeOf(typ, cborHex string) string {
	return `{"type":"` + typ + `","description":"","cborHex":"` + cborHex + `"}`
}

// newIssueEnv builds a pool whose KES key 000 waits for its certificate,
// with the cold counter at `counter`, and an offline-style wiring.
func newIssueEnv(t *testing.T, counter uint64, reading chain.Reading[uint64]) issueEnv {
	t.Helper()
	dir := t.TempDir()
	put(t, dir, "mypool.node.vkey", envelopeOf("StakePoolVerificationKey_ed25519", coldVKeyHex))
	put(t, dir, "mypool.node.skey", envelopeOf("StakePoolSigningKey_ed25519", "5820ff"))
	put(t, dir, "mypool.kes.counter", "000\n")
	put(t, dir, "mypool.kes.counter-next", "000\n")
	put(t, dir, "mypool.kes-000.vkey", envelopeOf("KesVerificationKey_ed25519_kes_2^6", kesVKeyHex))
	var vk [32]byte
	for i := range vk {
		vk[i] = byte(i)
	}
	put(t, dir, "mypool.node.counter", string(pool.IssueCounter{Next: counter, ColdVKey: vk}.Envelope()))

	st, err := fsstore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	signer := &fakeIssuer{}
	tip := &fakeTip{slot: 128_000_000}
	return issueEnv{
		uc: IssueOperationalCertificate{
			Store: st, Signers: directory{vault: signer}, Tip: tip, Genesis: fakeGenesis{},
			Counters: fakeCounters{reading: reading}, Clock: fixedClock{time.Date(2026, 11, 16, 8, 57, 1, 0, time.UTC)},
		},
		signer: signer, tip: tip, dir: dir,
	}
}

func u64(n uint64) *uint64 { return &n }

func (e issueEnv) snapshot(t *testing.T) string {
	t.Helper()
	var sb strings.Builder
	entries, _ := os.ReadDir(e.dir)
	for _, en := range entries {
		b, _ := os.ReadFile(filepath.Join(e.dir, en.Name()))
		sb.WriteString(en.Name() + "=" + string(b) + "\n")
	}
	return sb.String()
}

func (e issueEnv) counterFile(t *testing.T) pool.IssueCounter {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.dir, "mypool.node.counter"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := pool.ParseIssueCounter(b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// spec: SPO-04d-IF-001, SPO-04d-IN-001, SPO-04d-IN-002, SPO-04d-IN-003, SPO-04d-IN-004, SPO-04d-IN-005,
// spec: SPO-04d-OUT-001, SPO-04d-OUT-002, SPO-04d-OUT-003, SPO-04d-OUT-004, SPO-04d-INV-001, SPO-04d-INV-002,
// spec: SPO-04d-INV-003, SPO-04d-INV-006, SPO-04d-EXT-002, SPO-04d-EXT-003, SPO-Pfiles-OUT-014, SPO-Pfiles-OUT-015
func TestIssueCommitsEverythingTogether(t *testing.T) {
	e := newIssueEnv(t, 5, chain.Value[uint64](4)) // the chain has seen 4, so 5 is next
	res, err := e.uc.Run(context.Background(), "mypool", IssueOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Verified || res.Counter != 5 || res.KesNumber != 0 || res.KesPeriod != 987 {
		t.Fatalf("result %+v", res)
	}
	// The signer got the public inputs: raw KES key, the counter, the period.
	if len(e.signer.calls) != 1 || e.signer.calls[0].Counter != 5 || e.signer.calls[0].KesPeriod != 987 ||
		len(e.signer.calls[0].KesVKey) != 32 || e.signer.calls[0].KesVKey[0] != 0xa0 {
		t.Fatalf("signer call %+v", e.signer.calls)
	}
	if got, _ := os.ReadFile(filepath.Join(e.dir, "mypool.node-000.opcert")); string(got) != "opcert-counter-5\n" {
		t.Errorf("opcert %q", got)
	}
	if c := e.counterFile(t); c.Next != 6 {
		t.Errorf("counter file holds %d, want 6", c.Next)
	}
	if got, _ := os.ReadFile(filepath.Join(e.dir, "mypool.kes.counter-next")); string(got) != "001\n" {
		t.Errorf("kes.counter-next %q", got)
	}
	if got, _ := os.ReadFile(filepath.Join(e.dir, "mypool.kes.counter")); string(got) != "000\n" {
		t.Errorf("kes.counter changed to %q", got)
	}
	exp, _ := os.ReadFile(filepath.Join(e.dir, "mypool.kes-expire.json"))
	for _, want := range []string{`"latestKESfileindex": "000"`, `"currentKESperiod": "987"`, `"expireKESperiod": "1049"`} {
		if !strings.Contains(string(exp), want) {
			t.Errorf("expire file lacks %s:\n%s", want, exp)
		}
	}
	for _, n := range []string{"mypool.node-000.opcert", "mypool.node.counter", "mypool.kes-expire.json", "mypool.kes.counter-next"} {
		if st, _ := os.Stat(filepath.Join(e.dir, n)); st.Mode().Perm() != 0o400 {
			t.Errorf("%s mode %v", n, st.Mode().Perm())
		}
	}
	// A second run finds the key consumed (current < next).
	if _, err := e.uc.Run(context.Background(), "mypool", IssueOptions{}); !errors.Is(err, pool.ErrNoKesKeyWaiting) {
		t.Errorf("second run: %v", err)
	}
}

// spec: SPO-04d-PRE-002, SPO-04d-PRE-003, SPO-04d-PRE-004, SPO-04d-PRE-005
//
// Every refusal writes nothing and asks nobody: no signer call, no tip read.
func TestIssueRefusals(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(dir string)
		want   error
	}{
		{"no cold key", func(d string) { os.Remove(filepath.Join(d, "mypool.node.skey")) }, ErrNoColdKey},
		{"no cold vkey", func(d string) { os.Remove(filepath.Join(d, "mypool.node.vkey")) }, ErrNoColdVKey},
		{"no kes counter", func(d string) { os.Remove(filepath.Join(d, "mypool.kes.counter")) }, pool.ErrKesCountersMissing},
		{"no kes counter-next", func(d string) { os.Remove(filepath.Join(d, "mypool.kes.counter-next")) }, pool.ErrKesCountersMissing},
		{"counters differ", func(d string) {
			os.Chmod(filepath.Join(d, "mypool.kes.counter-next"), 0o600)
			os.WriteFile(filepath.Join(d, "mypool.kes.counter-next"), []byte("001\n"), 0o600)
		}, pool.ErrNoKesKeyWaiting},
		{"no kes vkey", func(d string) { os.Remove(filepath.Join(d, "mypool.kes-000.vkey")) }, ErrNoKesVKey},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newIssueEnv(t, 0, chain.None[uint64]())
			c.mutate(e.dir)
			before := e.snapshot(t)
			_, err := e.uc.Run(context.Background(), "mypool", IssueOptions{})
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			if len(e.signer.calls) != 0 || e.tip.calls != 0 {
				t.Error("a refused request reached the signer or the chain")
			}
			if e.snapshot(t) != before {
				t.Error("a refusal changed the workspace")
			}
		})
	}
}

// spec: SPO-04d-INV-004
//
// Decisions: INV-004 (software key wins over the hardware file) is kept: it
// is how upstream behaves and the spec records it as intentional. Hardware
// holders are decided by the signer directory, not the use case: with no
// hardware signer configured the plan is refused before the tip, the genesis
// or the chain is read. The hardware confirmation prompt (PR-003) belongs to
// the hardware signer adapter, which does not exist yet.
func TestColdKeyHolderSelection(t *testing.T) {
	// Both files: software wins, the vault signer is used.
	e := newIssueEnv(t, 0, chain.None[uint64]())
	put(t, e.dir, "mypool.node.hwsfile", `{"type":"x","cborHex":"00"}`)
	if _, err := e.uc.Run(context.Background(), "mypool", IssueOptions{}); err != nil {
		t.Fatalf("both files: %v", err)
	}
	// Only the hardware file: refused up front, nothing consulted.
	e = newIssueEnv(t, 0, chain.None[uint64]())
	os.Remove(filepath.Join(e.dir, "mypool.node.skey"))
	put(t, e.dir, "mypool.node.hwsfile", `{"type":"x","cborHex":"00"}`)
	before := e.snapshot(t)
	_, err := e.uc.Run(context.Background(), "mypool", IssueOptions{})
	var unsupported *custody.UnsupportedError
	if !errors.As(err, &unsupported) || !strings.Contains(err.Error(), "no hardware signer is configured") {
		t.Fatalf("hardware only: %v", err)
	}
	if e.tip.calls != 0 || len(e.signer.calls) != 0 || e.snapshot(t) != before {
		t.Error("the plan was not refused before any effect")
	}
}

// spec: SPO-04d-IF-002, SPO-04d-PR-001, SPO-04d-OUT-005
//
// Decision (PR-001): the "use the given counter?" prompt becomes the
// explicit option CounterOverride; passing it is the confirmation. The
// stored counter file is replaced, so after the issue it holds override + 1.
func TestCounterOverride(t *testing.T) {
	e := newIssueEnv(t, 5, chain.Value[uint64](11))
	res, err := e.uc.Run(context.Background(), "mypool", IssueOptions{CounterOverride: u64(12)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Counter != 12 || e.signer.calls[0].Counter != 12 {
		t.Errorf("issued with %d", res.Counter)
	}
	if c := e.counterFile(t); c.Next != 13 {
		t.Errorf("counter file holds %d, want 13", c.Next)
	}
}

// spec: SPO-04d-INV-006, SPO-04d-INV-007, SPO-04d-PRE-007, SPO-04d-PR-001, SPO-04d-OUT-002, SPO-04d-OUT-006
//
// Decisions:
//   - INV-006: the chain requires onChain + 1, or 0 when the chain has none.
//   - INV-007 / PRE-007 / PR-001: upstream deletes the wrong opcert and
//     re-issues with the right counter after a prompt. The port does not
//     re-issue silently: it returns a typed error that carries the required
//     counter, and the caller reruns with CounterOverride. Nothing is
//     written on the mismatch, so there is no wrong opcert to delete and
//     no half-advanced state.
//   - OUT-002 ("counter consumed by a failed run"): upstream's issuing tool
//     advances the cold counter before the chain check, so a discarded
//     opcert still burns a counter value. Here the counter file moves only
//     in the commit, after the check, together with the opcert.
//   - OUT-006: upstream leaves files unlocked when cardano-cli fails; the
//     port writes nothing on any failure, so there is nothing to relock.
func TestCounterMismatchWritesNothingAndSaysWhatIsRequired(t *testing.T) {
	e := newIssueEnv(t, 3, chain.Value[uint64](5)) // the chain wants 6
	before := e.snapshot(t)
	_, err := e.uc.Run(context.Background(), "mypool", IssueOptions{})
	var mm *CounterMismatchError
	if !errors.As(err, &mm) || mm.Issued != 3 || mm.Required != 6 {
		t.Fatalf("err = %v", err)
	}
	if e.snapshot(t) != before {
		t.Error("a mismatch changed the workspace")
	}
	// The caller reruns with the required counter.
	res, err := e.uc.Run(context.Background(), "mypool", IssueOptions{CounterOverride: &mm.Required})
	if err != nil || res.Counter != 6 || !res.Verified {
		t.Fatalf("rerun: %+v %v", res, err)
	}

	// A pool the chain has never seen needs counter 0, not 1.
	e = newIssueEnv(t, 1, chain.None[uint64]())
	if _, err := e.uc.Run(context.Background(), "mypool", IssueOptions{}); !errors.As(err, &mm) || mm.Required != 0 {
		t.Fatalf("none with counter 1: %v", err)
	}
	if _, err := e.uc.Run(context.Background(), "mypool", IssueOptions{CounterOverride: u64(0)}); err != nil {
		t.Fatalf("none with counter 0: %v", err)
	}
}

// spec: SPO-04d-MODE-003, SPO-04d-SEC-003, SPO-04d-MODE-005
//
// Decision (MODE-003, SEC-003): upstream treats a failed or empty Koios
// response as "the pool has made no block" (onChain = -1), which can move
// the cold counter below the on-chain value. Here an answer the provider
// could not give is Unknown, and Unknown is refused unless the caller says
// the chain is not consulted (AllowUnverified, the offline mode). It is
// never read as None. A reader that returns an error is Unknown too.
func TestUnknownChainIsNeverNone(t *testing.T) {
	for name, counters := range map[string]fakeCounters{
		"unknown": {reading: chain.Unknown[uint64]("koios unreachable")},
		"error":   {err: errors.New("connection refused")},
		"zero":    {}, // the zero Reading is Unknown
	} {
		t.Run(name, func(t *testing.T) {
			e := newIssueEnv(t, 0, chain.None[uint64]())
			e.uc.Counters = counters
			before := e.snapshot(t)
			_, err := e.uc.Run(context.Background(), "mypool", IssueOptions{})
			if !errors.Is(err, ErrChainUnverified) {
				t.Fatalf("err = %v", err)
			}
			if e.snapshot(t) != before {
				t.Error("an unverifiable counter changed the workspace")
			}
			// Offline: the caller states that nothing can be checked.
			e.uc.AllowUnverified = true
			res, err := e.uc.Run(context.Background(), "mypool", IssueOptions{})
			if err != nil || res.Verified {
				t.Fatalf("allowed: %+v %v", res, err)
			}
			if e.counterFile(t).Next != 1 {
				t.Error("offline issue did not advance the counter")
			}
		})
	}
}

// spec: SPO-04d-PR-002
//
// Decision: creating a missing counter is a separate use case,
// CreateIssueCounter (CLI: `pool opcert new-counter`), not a prompt inside
// the issue. Issue refuses with ErrNoIssueCounter and creates nothing. A
// counter override on a pool without a file creates it as part of the
// commit, as upstream's new-counter step does.
func TestMissingCounter(t *testing.T) {
	e := newIssueEnv(t, 0, chain.None[uint64]())
	os.Remove(filepath.Join(e.dir, "mypool.node.counter"))
	before := e.snapshot(t)
	if _, err := e.uc.Run(context.Background(), "mypool", IssueOptions{}); !errors.Is(err, ErrNoIssueCounter) {
		t.Fatalf("err = %v", err)
	}
	if e.snapshot(t) != before {
		t.Error("refusal wrote")
	}
	create := CreateIssueCounter{Store: e.uc.Store}
	if err := create.Run(context.Background(), "mypool", 0); err != nil {
		t.Fatal(err)
	}
	if c := e.counterFile(t); c.Next != 0 || c.ColdVKey[31] != 31 {
		t.Errorf("created counter %+v", c)
	}
	if err := create.Run(context.Background(), "mypool", 7); !errors.Is(err, ErrIssueCounterExists) {
		t.Errorf("overwrite: %v", err)
	}
	if _, err := e.uc.Run(context.Background(), "mypool", IssueOptions{}); err != nil {
		t.Fatalf("issue after create: %v", err)
	}

	// Override on a pool with no counter file.
	e = newIssueEnv(t, 0, chain.None[uint64]())
	os.Remove(filepath.Join(e.dir, "mypool.node.counter"))
	if _, err := e.uc.Run(context.Background(), "mypool", IssueOptions{CounterOverride: u64(0)}); err != nil {
		t.Fatal(err)
	}
	if e.counterFile(t).Next != 1 {
		t.Error("counter not created by the override")
	}
}

// spec: SPO-04d-EXT-003, SPO-04d-OUT-006, SPO-04d-INV-008
//
// A failure at the signer writes nothing: kes.counter-next stays at N, the
// counter does not move, no opcert exists.
func TestSignerFailureWritesNothing(t *testing.T) {
	e := newIssueEnv(t, 2, chain.Value[uint64](1))
	e.signer.err = errors.New("key unreadable")
	before := e.snapshot(t)
	if _, err := e.uc.Run(context.Background(), "mypool", IssueOptions{}); err == nil {
		t.Fatal("no error")
	}
	if e.snapshot(t) != before {
		t.Error("a failed issue changed the workspace")
	}
}

// spec: SPO-04d-OUT-002
//
// If the workspace changes while the signer works, the commit refuses
// rather than overwrite.
func TestConcurrentChangeIsAConflict(t *testing.T) {
	e := newIssueEnv(t, 2, chain.Value[uint64](1))
	e.signer.hook = func() {
		p := filepath.Join(e.dir, "mypool.node.counter")
		os.Chmod(p, 0o600)
		var vk [32]byte
		os.WriteFile(p, pool.IssueCounter{Next: 9, ColdVKey: vk}.Envelope(), 0o600)
	}
	if _, err := e.uc.Run(context.Background(), "mypool", IssueOptions{}); !errors.Is(err, ports.ErrConflict) {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "mypool.node-000.opcert")); err == nil {
		t.Error("an opcert was written despite the conflict")
	}
}

// spec: SPO-04d-IN-005
//
// A counter file made for another cold key is refused (cardano-cli refuses
// the same combination when it issues).
func TestCounterOfAnotherKeyIsRefused(t *testing.T) {
	e := newIssueEnv(t, 2, chain.Value[uint64](1))
	p := filepath.Join(e.dir, "mypool.node.counter")
	os.Chmod(p, 0o600)
	os.WriteFile(p, pool.IssueCounter{Next: 2}.Envelope(), 0o600)
	if _, err := e.uc.Run(context.Background(), "mypool", IssueOptions{}); !errors.Is(err, ErrCounterKeyMismatch) {
		t.Fatalf("err = %v", err)
	}
}
