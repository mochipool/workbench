package multisig_test

import (
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// reviewed makes bob hold the request and review it, and returns the approval.
func (s *scene) reviewed() multisig.Approval {
	s.t.Helper()
	s.request()
	s.bobHandles()
	pend, _ := s.B.Signer().Pending(ctx)
	if len(pend) != 1 {
		s.t.Fatalf("pending %d", len(pend))
	}
	rv, err := s.B.Signer().ReviewRequest(ctx, pend[0].ID)
	if err != nil {
		s.t.Fatal(err)
	}
	a, err := rv.Approval()
	if err != nil {
		s.t.Fatal(err)
	}
	return a
}

// nothingSigned asserts that an approval that failed signed and sent nothing,
// and that the request is waiting again.
func (s *scene) nothingSigned() {
	s.t.Helper()
	if s.B.Gate.Count() != 0 {
		s.t.Errorf("the gate was asked %d times: the operator was prompted for a request that went stale", s.B.Gate.Count())
	}
	if items, _ := s.B.Outbox().Pending(ctx); len(items) != 0 {
		s.t.Errorf("an envelope was queued: %+v", items)
	}
	if pend, _ := s.B.Signer().Pending(ctx); len(pend) != 1 {
		s.t.Errorf("the request is not waiting: %d", len(pend))
	}
}

// The scope is checked again when the approval is claimed, against the scope as
// it is then: an operator who narrows the coordinator's scope after the review
// but before the approval signs nothing.
// spec: SPO-Xparty-INV-025, SPO-Xparty-INV-016, SPO-Xparty-INV-010
func TestApproveRechecksTheCurrentScope(t *testing.T) {
	s := newScene(t, sceneOpt{})
	a := s.reviewed()
	s.B.SetScope("coord", party.Scope{KeyRoles: []custody.Role{custody.RoleStake}, Pools: []string{chain.PoolID{0xee}.Bech32()}})
	if _, err := s.B.Signer().Approve(ctx, a); !errors.Is(err, multisig.ErrReviewStale) {
		t.Fatalf("Approve after the scope was narrowed: %v", err)
	}
	s.nothingSigned()
	// Widened again, the same approval goes through: the request itself is unchanged.
	s.B.SetScope("coord", party.Scope{KeyRoles: []custody.Role{custody.RoleStake}, Pools: []string{s.bech}})
	if _, err := s.B.Signer().Approve(ctx, a); err != nil {
		t.Fatalf("Approve with the scope as reviewed: %v", err)
	}
}

// A coordinator revoked after the review no longer has its request signed.
// spec: SPO-Xparty-INV-025, SPO-Xparty-INV-016, SPO-Xparty-INV-005
func TestApproveRechecksTheSenderIsStillACoordinator(t *testing.T) {
	s := newScene(t, sceneOpt{})
	a := s.reviewed()
	s.B.Revoke("coord")
	if _, err := s.B.Signer().Approve(ctx, a); !errors.Is(err, multisig.ErrReviewStale) {
		t.Fatalf("Approve for a revoked coordinator: %v", err)
	}
	if s.B.Gate.Count() != 0 {
		t.Fatal("the gate was asked")
	}
	if items, _ := s.B.Outbox().Pending(ctx); len(items) != 0 {
		t.Fatalf("queued: %+v", items)
	}
}

// A coordinator that keeps sending requests that are refused on arrival
// leaves one security entry per reason, with a counter, not one per message
// (SPO-Xparty-INV-023).
// spec: SPO-Xparty-INV-023
func TestRepeatedRefusalsOfAnAuthenticatedSenderAreCoalesced(t *testing.T) {
	s := newScene(t, sceneOpt{})
	hello, err := s.B.Signer().NewHello(ctx, "coord")
	if err != nil {
		t.Fatal(err)
	}
	if h, _ := s.C.Coordinator().Handle(ctx, ports.FileReceived(hello)); h.Effect != "hello" {
		t.Fatalf("hello: %+v", h)
	}
	for range 50 { // the same message again and again
		if h, err := s.C.Coordinator().Handle(ctx, ports.FileReceived(hello)); err != nil || !h.Refused {
			t.Fatalf("replay: %+v, %v", h, err)
		}
	}
	n, count := 0, 0
	for _, e := range s.C.Events() {
		if e.Kind == "envelope-refused" || e.Kind == "message-refused" {
			n++
			count += e.Count
			if e.LastSeen.IsZero() {
				t.Error("no last-seen time on a coalesced refusal")
			}
		}
	}
	if n != 1 || count != 50 {
		t.Fatalf("%d entries for 50 refusals, counted %d", n, count)
	}
}
