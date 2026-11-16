package governance

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// noopHook accepts every single-source read without recording it, for tests
// that are about something else.
var noopHook ports.SingleSourceHook = func(context.Context, string, string) error { return nil }

// drep retire records the acknowledged single source before anything is
// signed or queued; a failing hook stops it; no flag, no record.
//
// spec: ADR 0006 (single source is written to the audit log before the effect)
func TestRetireDRepRecordsTheSingleSourceFirst(t *testing.T) {
	run := func(policy SourcePolicy, hook ports.SingleSourceHook) (*rig, error) {
		r := newRig(t)
		dr := &fakeDReps{src: "koios", l: r.l, r: registeredDRep(123_000_000, "")}
		_, err := RetireDRep{Base: r.base, Certs: r.certs, DReps: dr, Sources: policy, OnSingle: hook}.Run(context.Background(), RetireDRepRequest{DRep: "d", Payer: "w.payment"})
		return r, err
	}
	var r *rig
	rec := func(err error) ports.SingleSourceHook {
		return func(_ context.Context, read, source string) error {
			r.l.add("single-source " + read + " [" + source + "]")
			return err
		}
	}
	idx := func(prefix string) int {
		for i, c := range r.l.calls {
			if strings.HasPrefix(c, prefix) {
				return i
			}
		}
		return -1
	}
	// (a) before any witness or queueing; once.
	r2, err := run(SingleSourceAcknowledged, nil)
	if !errors.Is(err, ports.ErrNoSingleSourceHook) || r2.l.count("witness") != 0 || r2.l.count("enqueue") != 0 {
		t.Fatalf("no hook: %v %v", err, r2.l.calls)
	}
	rr := newRig(t)
	r = rr
	dr := &fakeDReps{src: "koios", l: rr.l, r: registeredDRep(123_000_000, "")}
	if _, err := (RetireDRep{Base: rr.base, Certs: rr.certs, DReps: dr, Sources: SingleSourceAcknowledged, OnSingle: rec(nil)}).Run(context.Background(), RetireDRepRequest{DRep: "d", Payer: "w.payment"}); err != nil {
		t.Fatal(err)
	}
	if i := idx("single-source"); i < 0 || r.l.count("single-source") != 1 || i > idx("witness") || i > idx("enqueue") {
		t.Errorf("%v", r.l.calls)
	}
	// (b) a failing hook: nothing signed, queued or written.
	r = newRig(t)
	dr = &fakeDReps{src: "koios", l: r.l, r: registeredDRep(123_000_000, "")}
	_, err = RetireDRep{Base: r.base, Certs: r.certs, DReps: dr, Sources: SingleSourceAcknowledged, OnSingle: rec(errors.New("audit log full"))}.Run(context.Background(), RetireDRepRequest{DRep: "d", Payer: "w.payment"})
	if err == nil || err.Error() != "audit log full" || r.l.count("witness") != 0 || r.l.count("enqueue") != 0 || r.l.count("put") != 0 {
		t.Fatalf("%v %v", err, r.l.calls)
	}
	// (c) no acknowledgement: refused, no record.
	r = newRig(t)
	dr = &fakeDReps{src: "koios", l: r.l, r: registeredDRep(123_000_000, "")}
	if _, err = (RetireDRep{Base: r.base, Certs: r.certs, DReps: dr, Sources: RequireCorroboration, OnSingle: rec(nil)}).Run(context.Background(), RetireDRepRequest{DRep: "d", Payer: "w.payment"}); !errors.Is(err, ErrSingleSource) || r.l.count("single-source") != 0 {
		t.Fatalf("%v %v", err, r.l.calls)
	}
}
