package poolops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// noopHook accepts every single-source read without recording it, for tests
// that are about something else.
var noopHook ports.SingleSourceHook = func(context.Context, string, string) error { return nil }

// The audit record of an acknowledged single source is made before the pool
// registration is confirmed, signed or submitted; a failing hook stops it; with
// no acknowledgement nothing is recorded; one record per read.
//
// spec: ADR 0006 (single source is written to the audit log before the effect)
func TestPoolRegisterRecordsTheSingleSourceFirst(t *testing.T) {
	setup := func(r *prig, hook ports.SingleSourceHook, policy SourcePolicy) RegisterPool {
		return r.register(false, func(uc *RegisterPool) {
			uc.Pools = &ppools{c: r.calls, src: "koios", r: chain.None[chain.PoolState]()}
			uc.Sources = policy
			uc.OnSingle = hook
		})
	}
	rec := func(r *prig, err error) ports.SingleSourceHook {
		return func(_ context.Context, read, source string) error {
			r.calls.add("single-source " + read + " [" + source + "]")
			return err
		}
	}
	// (a) the record is before any confirmation or submission.
	r := ready(t)
	if _, err := r.run(setup(r, rec(r, nil), SingleSourceAcknowledged)); err != nil {
		t.Fatal(err)
	}
	i := r.calls.index("single-source")
	if i < 0 || r.calls.count("single-source") != 1 || i > r.calls.index("confirm") || i > r.calls.index("submit") {
		t.Errorf("%v", r.calls.l)
	}
	// (b) a failing hook: nothing confirmed, submitted or written.
	r = ready(t)
	_, err := r.run(setup(r, rec(r, errors.New("audit log full")), SingleSourceAcknowledged))
	if err == nil || err.Error() != "audit log full" {
		t.Fatalf("%v", err)
	}
	if r.calls.count("confirm") != 0 || r.calls.count("submit") != 0 || r.calls.count("enqueue") != 0 || !r.exists("mypool.pool.cert") {
		t.Errorf("%v", r.calls.l)
	}
	// A hook that is missing is a misconfiguration, not a silent skip.
	r = ready(t)
	if _, err := r.run(setup(r, nil, SingleSourceAcknowledged)); !errors.Is(err, ports.ErrNoSingleSourceHook) || r.calls.count("submit") != 0 {
		t.Fatalf("%v %v", err, r.calls.l)
	}
	// (c) without the acknowledgement: refused, no record.
	r = ready(t)
	if _, err := r.run(setup(r, rec(r, nil), RequireCorroboration)); !errors.Is(err, ErrSingleSource) || r.calls.count("single-source") != 0 {
		t.Fatalf("%v %v", err, r.calls.l)
	}
}

// pool opcert issue records the acknowledged single source before the signer is
// asked and before any file is written; a failing hook leaves the workspace as
// it was; a mismatch (a refused run) records nothing.
//
// spec: ADR 0006 (single source is written to the audit log before the effect)
func TestOpCertIssueRecordsTheSingleSourceBeforeSigning(t *testing.T) {
	e := newIssueEnv(t, 5, chain.Value(uint64(4)))
	var reads []string
	e.uc.OnSingle = func(_ context.Context, read, source string) error {
		if len(e.signer.calls) != 0 {
			t.Error("the signer was asked before the record")
		}
		if _, err := os.Stat(filepath.Join(e.dir, "mypool.node-000.opcert")); err == nil {
			t.Error("the certificate exists before the record")
		}
		reads = append(reads, read+" ["+source+"]")
		return nil
	}
	if _, err := e.uc.Run(context.Background(), "mypool", IssueOptions{CounterOverride: u64(5)}); err != nil {
		t.Fatal(err)
	}
	if len(reads) != 1 || len(e.signer.calls) != 1 {
		t.Errorf("records %v, signer calls %d", reads, len(e.signer.calls))
	}
	// A failing hook: nothing signed, nothing written.
	f := newIssueEnv(t, 5, chain.Value(uint64(4)))
	before := f.snapshot(t)
	f.uc.OnSingle = func(context.Context, string, string) error { return errors.New("audit log full") }
	if _, err := f.uc.Run(context.Background(), "mypool", IssueOptions{CounterOverride: u64(5)}); err == nil || err.Error() != "audit log full" {
		t.Fatalf("%v", err)
	}
	if len(f.signer.calls) != 0 || f.snapshot(t) != before {
		t.Error("a failed record did not stop the issue")
	}
	// No hook with the acknowledgement: refused before signing.
	g := newIssueEnv(t, 5, chain.Value(uint64(4)))
	g.uc.OnSingle = nil
	if _, err := g.uc.Run(context.Background(), "mypool", IssueOptions{CounterOverride: u64(5)}); !errors.Is(err, ports.ErrNoSingleSourceHook) || len(g.signer.calls) != 0 {
		t.Fatalf("%v", err)
	}
	// A refused run (the counter is wrong) records nothing; neither does a run
	// without the acknowledgement.
	h := newIssueEnv(t, 3, chain.Value(uint64(5)))
	h.uc.OnSingle = func(context.Context, string, string) error { t.Error("recorded a refused run"); return nil }
	if _, err := h.uc.Run(context.Background(), "mypool", IssueOptions{}); err == nil {
		t.Fatal("accepted a wrong counter")
	}
	k := newIssueEnv(t, 5, chain.Value(uint64(4)))
	k.uc.SingleSource = false
	k.uc.OnSingle = func(context.Context, string, string) error { t.Error("recorded without the flag"); return nil }
	if _, err := k.uc.Run(context.Background(), "mypool", IssueOptions{CounterOverride: u64(5)}); !errors.Is(err, ErrOpCertSingleSource) {
		t.Fatalf("%v", err)
	}
}

func (c *pcalls) index(prefix string) int {
	for i, x := range c.l {
		if strings.HasPrefix(x, prefix) {
			return i
		}
	}
	return -1
}
