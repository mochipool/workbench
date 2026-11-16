package wallet

import (
	"context"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/app/handles"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// fakeResolver answers by handle.
type fakeResolver struct {
	answers map[string]handles.Resolved
	errs    map[string]error
	asked   []string
}

func (f *fakeResolver) Resolve(_ context.Context, text string) (handles.Resolved, error) {
	f.asked = append(f.asked, text)
	if err, ok := f.errs[text]; ok {
		return handles.Resolved{}, err
	}
	return f.answers[text], nil
}

func verified(addr string) handles.Resolved {
	return handles.Resolved{Address: chain.Address(addr), Kind: handles.RootClassic, VerifiedBy: "holder utxo"}
}

// An ADA Handle destination, with a resolver wired, is lower-cased, resolved and
// shown as BOTH the handle and the address it resolved to: in the confirmation
// summary, the queue entry and the result. The money goes to the resolved
// address.
//
// spec: SPO-01sendLovelaces-IF-004, SPO-01sendLovelaces-IF-007, SPO-Caddr-IF-001, SPO-Caddr-IF-002, SPO-Caddr-OUT-006
func TestHandleDestinationIsShownAsHandleAndAddress(t *testing.T) {
	r := newRig(t)
	fr := &fakeResolver{answers: map[string]handles.Resolved{"$alice@bob": verified("addr_test_alice")}}
	r.uc.Handles = fr
	res, err := r.uc.Run(context.Background(), SendRequest{Source: "w", Destination: "$Alice@Bob", Amount: "5000000"})
	if err != nil {
		t.Fatal(err)
	}
	if len(fr.asked) != 1 || fr.asked[0] != "$alice@bob" {
		t.Fatalf("the resolver was asked %v", fr.asked)
	}
	if res.Destination != "$alice@bob" || res.Handle == nil || res.Handle.Handle != "$alice@bob" || res.Handle.Address != "addr_test_alice" || res.Handle.VerifiedBy == "" {
		t.Errorf("result: %q %+v", res.Destination, res.Handle)
	}
	if r.conf.got.Destination != "$alice@bob" || r.conf.got.DestAddr != "addr_test_alice" {
		t.Errorf("the operator was shown %q / %q", r.conf.got.Destination, r.conf.got.DestAddr)
	}
	q := r.queue.got[0]
	if q.ToName != "$alice@bob" || q.ToAddr != "addr_test_alice" {
		t.Errorf("queued %q / %q", q.ToName, q.ToAddr)
	}
	// The paid output is the resolved address.
	found := false
	for _, o := range res.Outputs {
		found = found || o.Address == "addr_test_alice"
	}
	if !found {
		t.Errorf("outputs %+v", res.Outputs)
	}
}

// An ambiguous, unfound, unsynced or unverifiable resolution, and an answer
// that says it was not verified, refuse before anything is queried: a wrong
// destination is harmful (ADR 0006).
//
// spec: SPO-01sendLovelaces-IF-007, SPO-Caddr-PRE-006, SPO-Caddr-PRE-008, SPO-Caddr-INV-006, SPO-Caddr-PRE-012, SPO-Caddr-SEC-001
func TestHandleRefusalsHappenBeforeAnythingIsQueried(t *testing.T) {
	cases := map[string]struct {
		fr   *fakeResolver
		want error
	}{
		"ambiguous":          {&fakeResolver{errs: map[string]error{"$a": handles.ErrAmbiguous}}, handles.ErrAmbiguous},
		"not found":          {&fakeResolver{errs: map[string]error{"$a": handles.ErrNotFound}}, handles.ErrNotFound},
		"datum disagrees":    {&fakeResolver{errs: map[string]error{"$a": handles.ErrDatumMismatch}}, handles.ErrDatumMismatch},
		"unverifiable":       {&fakeResolver{errs: map[string]error{"$a": handles.ErrUnverifiable}}, handles.ErrUnverifiable},
		"offline":            {&fakeResolver{errs: map[string]error{"$a": handles.ErrOffline}}, handles.ErrOffline},
		"answer unverified":  {&fakeResolver{answers: map[string]handles.Resolved{"$a": {Address: "addr_test_alice"}}}, ErrHandleUnverified},
		"answer has no addr": {&fakeResolver{answers: map[string]handles.Resolved{"$a": {VerifiedBy: "holder utxo"}}}, ErrHandleUnverified},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.uc.Handles = tc.fr
			_, err := r.uc.Run(context.Background(), SendRequest{Source: "w", Destination: "$a", Amount: "5000000"})
			if !errors.Is(err, tc.want) {
				t.Fatalf("%v, want %v", err, tc.want)
			}
			if r.l.count("utxos") != 0 || r.l.count("tip") != 0 || r.l.count("witness") != 0 || len(r.queue.got) != 0 {
				t.Errorf("a refused handle had effects: %v", r.l.calls)
			}
		})
	}
	t.Run("a handle that resolves to a stake address", func(t *testing.T) {
		r := newRig(t)
		r.uc.Handles = &fakeResolver{answers: map[string]handles.Resolved{"$a": verified("stake_test_abc")}}
		if _, err := r.uc.Run(context.Background(), SendRequest{Source: "w", Destination: "$a", Amount: "5000000"}); !errors.Is(err, ErrBadDestination) {
			t.Errorf("%v", err)
		}
	})
}

// With no resolver wired the refusal is the one it has always been.
//
// spec: SPO-01sendLovelaces-IF-007, SPO-Caddr-PRE-002
func TestHandleWithoutAResolverKeepsTheRefusal(t *testing.T) {
	r := newRig(t)
	if _, err := r.uc.Run(context.Background(), SendRequest{Source: "w", Destination: "$alice", Amount: "5000000"}); !errors.Is(err, ErrAdaHandleUnsupported) {
		t.Errorf("%v", err)
	}
}
