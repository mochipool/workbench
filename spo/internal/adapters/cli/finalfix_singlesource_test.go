package cli

import (
	"context"
	"errors"
	dgov "github.com/mochipool/workbench/spo/internal/domain/governance"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// answersInTurn is a second source whose answers come one per call: agreeing at
// the certificate, silent at the transaction.
type answersInTurn struct {
	name chain.Source
	rs   []chain.Reading[chain.RewardAccount]
	n    int
}

func (a *answersInTurn) Source() chain.Source { return a.name }
func (a *answersInTurn) RewardAccount(context.Context, chain.StakeAddress) (chain.Reading[chain.RewardAccount], error) {
	i := a.n
	if i >= len(a.rs) {
		i = len(a.rs) - 1
	}
	a.n++
	return a.rs[i], nil
}

// queueSeeing is the queue of the rig: when a transaction arrives it asks what
// the audit log holds, so a record made after the queueing is caught.
type queueSeeing struct {
	rec   *recAuditor
	inner *recQueue
	seen  int
}

func (q *queueSeeing) Enqueue(ctx context.Context, t ports.QueuedTx) error {
	q.rec.mu.Lock()
	for _, e := range q.rec.ev {
		if e.Operation == SingleSourceOperation {
			q.seen++
		}
	}
	q.rec.mu.Unlock()
	return q.inner.Enqueue(ctx, t)
}

func withQueueSeeing(f *stakeFix, rec *recAuditor) *queueSeeing {
	q := &queueSeeing{rec: rec, inner: f.queue}
	old := f.deps.Wire
	f.deps.Wire = func(st ports.Store, o WireOptions) (*Env, error) {
		env, err := old(st, o)
		if err == nil {
			env.Queue = q
		}
		return env, err
	}
	return q
}

// Two sources agree at the certificate, the second goes silent at the
// transaction: the transaction's read rests on one source, so the warning is
// shown, one record exists, and it exists before the transaction is queued
// (the use case that reads the account a second time records its own read).
//
// spec: ADR 0006 (single source is written to the audit log before the effect)
func TestStakeDeregisterSecondReadSingleSourceIsRecordedBeforeQueueing(t *testing.T) {
	f := newStakeFix(t)
	rec := &recAuditor{}
	f.deps = rec.deps(f.deps)
	q := withQueueSeeing(f, rec)
	f.newWallet(t)
	f.rewards = &fakeRewards{name: "first", r: registered(0)}
	f.cross = &answersInTurn{name: "second", rs: []chain.Reading[chain.RewardAccount]{registered(0), chain.Unknown[chain.RewardAccount]("HTTP 503")}}
	if err := f.run(t, &scriptTerm{t: t}, "stake", "deregister", "s", "s.payment", "--yes", "--single-source"); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	evs := rec.singles(t, 1)
	if evs[0].Command != "spo stake deregister" || evs[0].Source != "first" {
		t.Errorf("record %+v", evs[0])
	}
	if q.seen != 1 {
		t.Errorf("the audit log held %d records when the transaction was queued, want 1", q.seen)
	}
	mustContain(t, f.out.String(), "ONE source")
	f.queued(t, 1)
}

// Both reads of a deregistration that rest on one source are recorded, one per
// read (the certificate and the transaction), each before its effect; a record
// that cannot be written stops the command with nothing written or queued.
func TestStakeDeregisterOneRecordPerReadAndAFailedRecordStopsIt(t *testing.T) {
	f := newStakeFix(t)
	rec := &recAuditor{}
	f.deps = rec.deps(f.deps)
	q := withQueueSeeing(f, rec)
	f.newWallet(t)
	f.rewards = &fakeRewards{name: "only", r: registered(0)}
	if err := f.run(t, &scriptTerm{t: t}, "stake", "deregister", "s", "s.payment", "--yes", "--single-source"); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	rec.singles(t, 2) // one for the certificate, one for the transaction
	if q.seen != 2 {
		t.Errorf("%d records before the queue, want 2", q.seen)
	}

	g := newStakeFix(t)
	g.deps.WorkspaceAuditor = func(string, ports.Store, string) ports.WorkspaceAuditor { return failingAuditor{} }
	g.newWallet(t)
	g.rewards = &fakeRewards{name: "only", r: registered(0)}
	err := g.run(t, &scriptTerm{t: t}, "stake", "deregister", "s", "s.payment", "--yes", "--single-source")
	if err == nil || !strings.Contains(err.Error(), "could not be recorded") {
		t.Fatalf("%v", err)
	}
	g.queued(t, 0)
	if g.has("s.staking.dereg-cert") {
		t.Error("the certificate was stored although the record failed")
	}
}

type failingAuditor struct{}

func (failingAuditor) Record(context.Context, ports.AuditEvent) error {
	return errors.New("disk full")
}

// flipChain answers one way the first time and another way after.
type flipChain struct {
	c            *chainPool
	first, later chain.PoolInfo
	asked        int
}

func (f *flipChain) Source() chain.Source { return "fake koios" }
func (f *flipChain) PoolInfo(context.Context, chain.PoolID) (chain.Reading[chain.PoolInfo], error) {
	f.asked++
	if f.asked == 1 {
		return chain.Value(f.first), nil
	}
	return chain.Value(f.later), nil
}

// The import reads the chain once: the dry run, the confirmation and the write
// all use the one answer, so what is written is what the operator confirmed
// even if the provider answers differently on a second request.
//
// spec: SPO-0x-SEC-003 (ADR 0006)
func TestPoolImportReadsTheChainOnce(t *testing.T) {
	k := newKeyed(t, true)
	first, _ := k.chain.info.Get()
	later := first
	later.Pledge = "987654321987"
	flip := &flipChain{c: k.chain, first: first, later: later}
	f := newSendFixture(t)
	withPoolImport(f, k, metaFetch{body: k.meta})
	old := f.deps.Wire
	f.deps.Wire = func(st ports.Store, o WireOptions) (*Env, error) {
		env, err := old(st, o)
		env.PoolInfos = flip
		return env, err
	}
	if err := f.runT(t, &recTerm{}, "pool", "import", "--yes", "mypool", k.poolID.Bech32()); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	if flip.asked != 1 {
		t.Errorf("the provider was asked %d times, want 1", flip.asked)
	}
	b, err := os.ReadFile(filepath.Join(f.dir, "mypool.pool.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "987654321987") || !strings.Contains(string(b), first.Pledge) {
		t.Errorf("the descriptor does not hold the confirmed data:\n%s", b)
	}
	mustContain(t, f.out.String(), "ticker", "metadata url", "metadata hash", "vrf key hash", "opcert counter")
}

// byNameParams serves protocol parameters whose cost models are keyed by name,
// the shape a Blockfrost-style provider gives.
type byNameParams struct{ govParams }

func (byNameParams) ProtocolParameters(ctx context.Context) (chain.ProtocolParameters, error) {
	p, _ := govParams{}.ProtocolParameters(ctx)
	p.Raw = []byte(`{"maxTxSize":16384,"cost_models":{"PlutusV3":{"addInteger-cpu-arguments-intercept":100,"addInteger-cpu-arguments-slope":200}}}`)
	return p, nil
}

// With the current cost model not readable as an array, a cost model update is
// refused (the length cannot be checked); with the flag it goes on and the
// summary says the length was not checked.
//
// spec: SPO-25a-IF-022
func TestActionCreateCostModelLengthFailsClosedWhenTheCurrentModelIsNotAnArray(t *testing.T) {
	f := newGovFix(t)
	old := f.deps.Wire
	f.deps.Wire = func(st ports.Store, o WireOptions) (*Env, error) {
		env, err := old(st, o)
		env.Params = byNameParams{}
		return env, err
	}
	if err := os.WriteFile(filepath.Join(f.dir, "cm.json"), []byte(`{"PlutusV3":[100,2,-300]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"action", "create", "parameter-change", stakeAddr(), "--anchor-url", govURL, "--anchor-hash", govHash, "--cost-model-file", filepath.Join(f.dir, "cm.json")}
	out, err := f.cmd(t, nil, args...)
	if !errors.Is(err, dgov.ErrCostModelUnchecked) || !strings.Contains(err.Error(), "--allow-cost-model-length-change") {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(out, "Stored") {
		t.Error("a file was stored")
	}
	out = f.must(t, append(args, "--allow-cost-model-length-change")...)
	mustContain(t, out, "length not checked", "PlutusV3", "Stored")
}
