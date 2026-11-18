package cli

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// recAuditor stands in for the store's audit log and keeps what was recorded.
type recAuditor struct {
	mu sync.Mutex
	ev []ports.AuditEvent
}

func (r *recAuditor) Record(_ context.Context, e ports.AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ev = append(r.ev, e)
	return nil
}

func (r *recAuditor) deps(d Deps) Deps {
	d.WorkspaceAuditor = func(string, ports.NamedStore, string) ports.WorkspaceAuditor { return r }
	return d
}

func (r *recAuditor) singles(t *testing.T, want int) []ports.AuditEvent {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, e := range r.ev {
		if e.Operation == SingleSourceOperation {
			n++
		}
	}
	if n != want {
		t.Fatalf("%d single-source records, want %d: %+v", n, want, r.ev)
	}
	return r.ev
}

// Every stake command that accepts --single-source records the acknowledgement
// when, and only when, the read rested on one source (ADR 0006, F4).
//
// spec: ADR 0006 (single source is written to the audit log)
func TestStakeSingleSourceIsRecorded(t *testing.T) {
	f := newStakeFix(t)
	rec := &recAuditor{}
	f.deps = rec.deps(f.deps)
	f.newWallet(t)
	f.rewards = &fakeRewards{name: "fake rewards", r: registered(0)}

	// Refused without the flag: nothing is recorded.
	if err := f.run(t, &scriptTerm{t: t}, "stake", "deregister", "s", "s.payment", "--yes"); err == nil {
		t.Fatal("accepted a single source without the flag")
	}
	rec.singles(t, 0)

	if err := f.run(t, &scriptTerm{t: t}, "stake", "deregister", "s", "s.payment", "--yes", "--single-source"); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	// One record per accepted read: the certificate's and the transaction's.
	ev := rec.singles(t, 2)[0]
	if ev.Command != "spo stake deregister" || ev.Source != "fake rewards" || !ev.SingleSource || ev.Read == "" {
		t.Errorf("record %+v", ev)
	}

	// The flag given where a second source agrees: no record.
	g := newStakeFix(t)
	rec2 := &recAuditor{}
	g.deps = rec2.deps(g.deps)
	g.newWallet(t)
	g.rewards = &fakeRewards{name: "first", r: registered(0)}
	g.cross = &fakeRewards{name: "second", r: registered(0)}
	if err := g.run(t, &scriptTerm{t: t}, "stake", "deregister", "s", "s.payment", "--yes", "--single-source"); err != nil {
		t.Fatalf("%v\n%s", err, g.out.String())
	}
	rec2.singles(t, 0)

	// Delegation: one source recorded.
	h := newStakeFix(t)
	rec3 := &recAuditor{}
	h.deps = rec3.deps(h.deps)
	h.newWallet(t)
	h.rewards = &fakeRewards{name: "fake rewards", r: registered(0)}
	h.pools = fakePools{r: chain.Value(chain.PoolState{Ticker: "TST"})}
	if err := h.run(t, &scriptTerm{t: t}, "stake", "delegate", "s", poolHex, "--yes", "--single-source"); err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	if ev := rec3.singles(t, 1)[0]; ev.Command != "spo stake delegate" {
		t.Errorf("record %+v", ev)
	}
}

// pool opcert issue: one provider needs --single-source, records it and says
// so in the summary; check and counter are informational and name the source.
//
// spec: ADR 0006 (N7, single source is written to the audit log)
func TestOpcertSingleSourceIsRecordedAndWarned(t *testing.T) {
	var out bytes.Buffer
	dir := t.TempDir()
	seedPool(t, dir)
	cfgs := map[string]WorkspaceConfig{dir: {Network: "preview", Mode: ModeLight, Koios: &KoiosConfig{}}}
	rec := &recAuditor{}
	d := rec.deps(opcertDeps(&out, cfgs, &wired{}))
	if err := runWith(t, d, "-C", dir, "pool", "opcert", "new-counter", "p"); err != nil {
		t.Fatal(err)
	}
	err := runWith(t, d, "-C", dir, "pool", "opcert", "issue", "p")
	if err == nil || !strings.Contains(err.Error(), "--single-source") {
		t.Fatalf("one provider without the flag: %v", err)
	}
	rec.singles(t, 0)
	out.Reset()
	if err := runWith(t, d, "-C", dir, "pool", "opcert", "issue", "p", "--single-source"); err != nil {
		t.Fatal(err)
	}
	ev := rec.singles(t, 1)[0]
	if ev.Command != "spo pool opcert issue" || ev.Source != "fake chain" {
		t.Errorf("record %+v", ev)
	}
	if !strings.Contains(out.String(), "WARNING: the operational certificate counter rests on ONE source (fake chain)") {
		t.Errorf("no warning in the summary:\n%s", out.String())
	}
}
