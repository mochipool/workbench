package stake

import (
	"context"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// recHook writes "single-source <read>" to the rig's call log, so a test can
// compare its position with the signer, the queue and the store; err makes it
// fail.
func (r *rig) recHook(err error) ports.SingleSourceHook {
	return func(_ context.Context, read, source string) error {
		r.l.add("single-source " + read + " [" + source + "]")
		return err
	}
}

// The audit record of an acknowledged single source is made before the
// transaction is signed or queued; one record per accepted read.
//
// spec: ADR 0006 (single source is written to the audit log before the effect)
func TestDeregisterRecordsTheSingleSourceBeforeSigningAndQueueing(t *testing.T) {
	r := newRig(t)
	uc := r.dereg(2_000_000)
	uc.OnSingle = r.recHook(nil)
	res, err := uc.Run(bg, deregReq)
	if err != nil || !res.Queued || !res.SingleSource {
		t.Fatalf("%+v %v", res, err)
	}
	rec := r.l.index("single-source")
	if rec < 0 || r.l.count("single-source") != 1 {
		t.Fatalf("records: %v", r.l.calls)
	}
	if w, q := r.l.index("witness"), r.l.index("enqueue"); rec > w || rec > q {
		t.Errorf("the record (%d) comes after a witness (%d) or the queue (%d): %v", rec, w, q, r.l.calls)
	}
}

// A hook that fails stops the use case with nothing signed, queued or written.
func TestDeregisterHookFailureDoesNothing(t *testing.T) {
	r := newRig(t)
	uc := r.dereg(2_000_000)
	uc.OnSingle = r.recHook(errors.New("audit log full"))
	if _, err := uc.Run(bg, deregReq); err == nil || err.Error() != "audit log full" {
		t.Fatalf("%v", err)
	}
	if r.l.count("witness") != 0 || r.l.count("enqueue") != 0 || r.l.count("submit") != 0 || r.store.writes != 0 {
		t.Errorf("something happened after a failed record: %v", r.l.calls)
	}
}

// Acknowledging a single source with no way to record it is a
// misconfiguration: refused, nothing signed or queued.
func TestSingleSourceWithoutAHookIsRefused(t *testing.T) {
	r := newRig(t)
	uc := r.dereg(2_000_000)
	uc.OnSingle = nil
	if _, err := uc.Run(bg, deregReq); !errors.Is(err, ports.ErrNoSingleSourceHook) {
		t.Fatalf("%v", err)
	}
	if r.l.count("witness") != 0 || r.l.count("enqueue") != 0 {
		t.Errorf("%v", r.l.calls)
	}
	g := newRig(t)
	gen := g.gen08a()
	gen.OnSingle = nil
	if _, err := gen.Run(bg, "w"); !errors.Is(err, ports.ErrNoSingleSourceHook) || g.store.writes != 0 {
		t.Fatalf("%v, %d writes", err, g.store.writes)
	}
}

// Without the acknowledgement no record is made, and two agreeing sources need
// none.
func TestNoRecordWithoutAnAcceptedSingleSource(t *testing.T) {
	r := newRig(t)
	uc := r.dereg(2_000_000)
	uc.Sources = RequireCorroboration
	uc.OnSingle = r.recHook(nil)
	if _, err := uc.Run(bg, deregReq); !errors.Is(err, ErrSingleSource) {
		t.Fatalf("%v", err)
	}
	g := newRig(t)
	uc = g.dereg(2_000_000)
	uc.CrossCheck = &fakeRewards{l: g.l, src: "node", r: registered(nil)}
	uc.OnSingle = g.recHook(nil)
	if res, err := uc.Run(bg, deregReq); err != nil || res.SingleSource {
		t.Fatalf("%+v %v", res, err)
	}
	if r.l.count("single-source") != 0 || g.l.count("single-source") != 0 {
		t.Errorf("a record was made: %v / %v", r.l.calls, g.l.calls)
	}
}

// The certificate generation records before it stores the certificate.
func TestGenerateDeregistrationRecordsBeforeWriting(t *testing.T) {
	r := newRig(t)
	uc := r.gen08a()
	uc.OnSingle = func(ctx context.Context, read, source string) error {
		if r.store.writes != 0 {
			t.Error("the certificate was written before the record")
		}
		return r.recHook(nil)(ctx, read, source)
	}
	if _, err := uc.Run(bg, "w"); err != nil {
		t.Fatal(err)
	}
	if r.l.count("single-source") != 1 || r.store.writes != 1 {
		t.Errorf("%v, %d writes", r.l.calls, r.store.writes)
	}
	g := newRig(t)
	uc = g.gen08a()
	uc.OnSingle = g.recHook(errors.New("no disk"))
	if _, err := uc.Run(bg, "w"); err == nil || g.store.writes != 0 {
		t.Fatalf("%v, %d writes", err, g.store.writes)
	}
}

// The delegation's pool read records before anything is signed or queued, and a
// failing hook stops it.
func TestDelegationRecordsThePoolSingleSourceFirst(t *testing.T) {
	down := &namedPools{src: "blockfrost", r: chain.Unknown[chain.PoolState]("HTTP 503")}
	run := func(hookErr error) *rig {
		r := newRig(t)
		r.rewards.r = registered(nil)
		uc := r.pool()
		uc.Sources = SingleSourceAcknowledged
		uc.OnSingle = r.recHook(hookErr)
		uc.PoolCross = down
		_, err := uc.Run(bg, delegReq)
		if (err != nil) != (hookErr != nil) {
			t.Fatalf("hook error %v, run error %v", hookErr, err)
		}
		return r
	}
	r := run(nil)
	if rec := r.l.index("single-source"); rec < 0 || rec > r.l.index("witness") || rec > r.l.index("enqueue") || r.l.count("single-source") != 1 {
		t.Errorf("%v", r.l.calls)
	}
	r = run(errors.New("no disk"))
	if r.l.count("witness") != 0 || r.l.count("enqueue") != 0 {
		t.Errorf("%v", r.l.calls)
	}
}

// noopHook accepts every single-source read without recording it, for tests
// that are about something else.
var noopHook ports.SingleSourceHook = func(context.Context, string, string) error { return nil }
