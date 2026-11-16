package multisig_test

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/envelope"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/multiparty/partyrig"
)

// ---- SPO-Xparty-INV-016: no approval without the review ----------------------------

// Approving needs an Approval, and an Approval comes only from a Review that
// ReviewRequest made: its fields are unexported, so a caller cannot build
// one, and a Review built by hand carries no token. The constructor refuses
// all of those.
// spec: SPO-Xparty-INV-016, SPO-Xparty-OUT-006, SPO-Xparty-PR-002
func TestApprovalCannotBeMadeWithoutAReview(t *testing.T) {
	s := newScene(t, sceneOpt{})
	s.request()
	s.bobHandles()
	pend, _ := s.B.Signer().Pending(ctx)
	id := pend[0].ID

	if _, err := (multisig.Review{}).Approval(); err != multisig.ErrNoReview {
		t.Errorf("a zero review gave an approval: %v", err)
	}
	forged := multisig.Review{RequestID: id, BodyHash: [32]byte(s.body.ID), Role: custody.RoleStake}
	if _, err := forged.Approval(); err != multisig.ErrNoReview {
		t.Errorf("a review made by hand gave an approval: %v", err)
	}
	if _, err := s.B.Signer().Approve(ctx, multisig.Approval{}); err != multisig.ErrNoReview {
		t.Errorf("a zero approval was accepted: %v", err)
	}
	// Nothing was signed by any of that.
	if items, _ := s.B.Outbox().Pending(ctx); len(items) != 0 {
		t.Fatal("a response was made")
	}

	rv, err := s.B.Signer().ReviewRequest(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	// A review whose request id or body hash is changed no longer matches its token.
	moved := rv
	moved.RequestID[0] ^= 1
	if _, err := moved.Approval(); err != multisig.ErrNoReview {
		t.Errorf("a review for another request id gave an approval: %v", err)
	}
	moved = rv
	moved.BodyHash[0] ^= 1
	if _, err := moved.Approval(); err != multisig.ErrNoReview {
		t.Errorf("a review for another body hash gave an approval: %v", err)
	}
	// The real one does.
	if _, err := rv.Approval(); err != nil {
		t.Errorf("the review of the request gave no approval: %v", err)
	}
}

// A request that was never reviewed has no review record: ReviewRequest is
// what records it, and Approve checks it.
// spec: SPO-Xparty-INV-016
func TestReviewOfAnUnknownRequestIsRefused(t *testing.T) {
	s := newScene(t, sceneOpt{})
	if _, err := s.B.Signer().ReviewRequest(ctx, party.MessageID{1}); err != multisig.ErrUnknownRequest {
		t.Errorf("err = %v", err)
	}
}

// ---- SPO-Xparty-INV-017 ---------------------------------------------------------------

type countingSigner struct {
	native.VaultSigner
	n *atomic.Int32
}

func (c countingSigner) Witness(ctx context.Context, k custody.KeyRef, b txbuild.TxBody) (txbuild.Witness, error) {
	c.n.Add(1)
	return c.VaultSigner.Witness(ctx, k, b)
}

type countingDir struct{ s countingSigner }

func (d countingDir) SignerFor(custody.KeyRef) (ports.Signer, error) { return d.s, nil }

// An answered request that arrives again by file is answered with the stored
// response and never signed twice; over a network the same id is a replay.
// spec: SPO-Xparty-INV-017, SPO-Xparty-INV-007, SPO-Xparty-OUT-006
func TestAnsweredRequestIsAnsweredAgainFromTheStore(t *testing.T) {
	s := newScene(t, sceneOpt{})
	var n atomic.Int32
	signer := s.B.Signer()
	signer.Signers = countingDir{countingSigner{native.VaultSigner{Vault: s.B.Store}, &n}}
	s.request()
	reqs := s.cb.Take()
	if len(reqs) != 1 {
		t.Fatal(len(reqs))
	}
	if h, err := signer.Handle(ctx, reqs[0], ports.ViaFile); err != nil || h.Effect != "stored" {
		t.Fatalf("first = %+v, %v", h, err)
	}
	pend, _ := signer.Pending(ctx)
	rv, err := signer.ReviewRequest(ctx, pend[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := rv.Approval()
	if _, err := signer.Approve(ctx, a); err != nil {
		t.Fatal(err)
	}
	// Approving again is refused: the request is answered.
	if _, err := signer.Approve(ctx, a); err == nil || !strings.Contains(err.Error(), "not waiting") {
		t.Errorf("second approval: %v", err)
	}
	// The reply file is lost: the coordinator sends the request again.
	s.bobFlush()
	lost := s.bc.Take()
	if len(lost) != 1 {
		t.Fatal(len(lost))
	}
	h, err := signer.Handle(ctx, reqs[0], ports.ViaFile)
	if err != nil || h.Refused || h.Effect != "response-resent" {
		t.Fatalf("again by file = %+v, %v", h, err)
	}
	s.bobFlush()
	again := s.bc.Take()
	if len(again) != 1 || string(again[0]) != string(lost[0]) {
		t.Fatal("the stored response was not the one sent again")
	}
	if n.Load() != 1 {
		t.Errorf("the key signed %d times", n.Load())
	}
	// The re-sent response completes the collection once.
	if h, err := s.C.Coordinator().Handle(ctx, again[0], ports.ViaFile); err != nil || h.Effect != "filled" {
		t.Fatalf("coordinator = %+v, %v", h, err)
	}
	// By network the same id is answered the same way, with the stored
	// response, over the network too (INV-017): never signed again.
	h, err = signer.Handle(ctx, reqs[0], ports.ViaNetwork)
	if err != nil || h.Refused || h.Effect != "response-resent" {
		t.Fatalf("by network = %+v, %v", h, err)
	}
	if n.Load() != 1 {
		t.Errorf("the key signed %d times", n.Load())
	}

}

// ---- SPO-Xparty-INV-011 -----------------------------------------------------------------

// Nothing in the review comes from the purpose text: it appears only in the
// field that says it is the coordinator's claim.
// spec: SPO-Xparty-INV-011, SPO-Xparty-PR-002
func TestPurposeTextIsOnlyAClaim(t *testing.T) {
	s := newScene(t, sceneOpt{})
	const lie = "send 1 ADA to addr_test1qzzzzzzzzzzzzzzz as agreed"
	s.request(func(in *multisig.RequestInput) { in.Purpose = lie })
	s.bobHandles()
	pend, _ := s.B.Signer().Pending(ctx)
	rv, err := s.B.Signer().ReviewRequest(ctx, pend[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if rv.ClaimedPurpose != lie {
		t.Errorf("claimed purpose %q", rv.ClaimedPurpose)
	}
	rv.ClaimedPurpose = ""
	if shown := fmt.Sprintf("%+v", rv); strings.Contains(shown, "zzzz") || strings.Contains(shown, "as agreed") {
		t.Errorf("the purpose text reached the review: %s", shown)
	}
}

// ---- SPO-Xparty-INV-021: Hello ----------------------------------------------------------

// spec: SPO-Xparty-INV-021, SPO-Xparty-INV-010
func TestHello(t *testing.T) {
	s := newScene(t, sceneOpt{})
	if err := s.B.Signer().Hello(ctx, "coord", s.bc); err != nil {
		t.Fatal(err)
	}
	hs := s.coordHandles()
	if len(hs) != 1 || hs[0].Refused || hs[0].Effect != "hello" {
		t.Fatalf("hello = %+v", hs)
	}
	// It lives no more than five minutes.
	long := s.sealFrom(s.B, s.C, party.Hello{}, s.clock.Now(), s.clock.Now().Add(10*time.Minute))
	h, _ := s.C.Coordinator().Handle(ctx, long, ports.ViaNetwork)
	mustRefuse(t, h, party.ErrHelloExpiry.Error())
	// It is not replayable within that time.
	short := s.sealFrom(s.B, s.C, party.Hello{}, s.clock.Now(), s.clock.Now().Add(time.Minute))
	if h, _ := s.C.Coordinator().Handle(ctx, short, ports.ViaNetwork); h.Refused {
		t.Fatalf("first hello refused: %+v", h)
	}
	h, _ = s.C.Coordinator().Handle(ctx, short, ports.ViaNetwork)
	mustRefuse(t, h, envelope.ErrReplayed.Error())
	// Only a signer says hello.
	co := partyrig.New(t, "coonly", s.clock, s.chain)
	s.C.Enroll(co, "coonly", []party.Role{party.RoleCoordinator}, []string{s.bech})
	co.Enroll(s.C, "coord", []party.Role{party.RoleCoordinator}, nil)
	env := s.sealFrom(co, s.C, party.Hello{}, s.clock.Now(), s.clock.Now().Add(time.Minute))
	h, _ = s.C.Coordinator().Handle(ctx, env, ports.ViaNetwork)
	mustRefuse(t, h, party.ErrNotAuthorised.Error())
}

// ---- SPO-Xparty-INV-015, OUT-004: expiry and closing ----------------------------------

// spec: SPO-Xparty-INV-015, SPO-Xparty-OUT-004
func TestSweepAnnouncesExpiryAndTheSignerStopsAnswering(t *testing.T) {
	for _, tipDown := range []bool{false, true} {
		t.Run(fmt.Sprintf("tip down %v", tipDown), func(t *testing.T) {
			s := newScene(t, sceneOpt{})
			s.request()
			s.bobHandles()
			pend, _ := s.B.Signer().Pending(ctx)
			rv, _ := s.B.Signer().ReviewRequest(ctx, pend[0].ID)
			a, _ := rv.Approval()
			// Time passes beyond the ttl slot.
			if tipDown {
				s.chain.Down = true
				s.clock.Advance(600 * time.Second)
			} else {
				s.chain.SetSlot(s.ttl + 1)
			}
			closed, err := s.C.Coordinator().Sweep(ctx)
			if err != nil || len(closed) != 1 {
				t.Fatalf("sweep = %v, %v", closed, err)
			}
			if again, _ := s.C.Coordinator().Sweep(ctx); len(again) != 0 {
				t.Error("a closed collection was closed again")
			}
			if !eventWith(events(s.C), "collection-expired") {
				t.Errorf("log %v", events(s.C))
			}
			// Nothing is accepted for it, and it cannot be requested again.
			if _, err := s.C.Coordinator().RequestSignatures(ctx, multisig.RequestInput{Ref: s.ref}, s.cb.Transport()); err == nil {
				t.Error("requested an expired collection")
			}
			// The notice reaches the signer, who then cannot approve.
			if tipDown {
				s.clock.Advance(0)
			}
			if _, err := s.C.Outbox().Flush(ctx, s.cb.Transport()); err != nil {
				t.Fatal(err)
			}
			if !tipDown { // with the clock advanced the notice has expired with the request
				hs := s.bobHandles()
				if len(hs) != 1 || hs[0].Refused || hs[0].Effect != "closed" {
					t.Fatalf("signer = %+v", hs)
				}
			}
			if _, err := s.B.Signer().Approve(ctx, a); err == nil {
				t.Error("approved a request of an expired collection")
			}
		})
	}
}

// A collection that is gone from its place was discarded.
// spec: SPO-Xparty-OUT-004, SPO-Xparty-INV-015
func TestSweepAnnouncesADiscard(t *testing.T) {
	s := newScene(t, sceneOpt{})
	s.request()
	s.bobHandles()
	if err := s.C.Store.Update(ctx, func(w ports.Writer) error {
		return w.Delete(ports.Ref{Name: s.ref.Name, Kind: ports.MultisigCollection})
	}); err != nil {
		t.Fatal(err)
	}
	if closed, err := s.C.Coordinator().Sweep(ctx); err != nil || len(closed) != 1 {
		t.Fatalf("sweep = %v, %v", closed, err)
	}
	if !eventWith(events(s.C), "collection-discarded") {
		t.Errorf("log %v", events(s.C))
	}
}

// When the last slot is filled the completion callback runs, and a submitted
// transaction is announced to the signers with its id.
// spec: SPO-Xparty-OUT-005, SPO-Xparty-OUT-004
func TestCompletionCallbackAndTheSubmittedNotice(t *testing.T) {
	s := newScene(t, sceneOpt{})
	coord := s.C.Coordinator()
	var called int
	txid := chain.TxID(s.body.ID) // a submission names the transaction that was asked about
	coord.Complete = func(_ context.Context, ref multisig.CollectionRef) (multisig.Completion, error) {
		called++
		if ref != s.ref {
			t.Errorf("ref %+v", ref)
		}
		return multisig.Completion{Submitted: true, TxID: txid}, nil
	}
	s.request()
	s.bobHandles()
	s.bobApproves()
	s.bobFlush()
	env := s.bc.Take()[0]
	h, err := coord.Handle(ctx, env, ports.ViaFile)
	if err != nil || h.Effect != "filled" || !h.Complete || called != 1 {
		t.Fatalf("handled = %+v, %v, called %d", h, err, called)
	}
	items, _ := s.C.Outbox().Pending(ctx)
	if len(items) != 1 || items[0].Type != string(party.TypeCollectionClosed) {
		t.Fatalf("outbox %+v", items)
	}
	if _, err := s.C.Outbox().Flush(ctx, s.cb.Transport()); err != nil {
		t.Fatal(err)
	}
	hs := s.bobHandles()
	if len(hs) != 1 || hs[0].Effect != "closed" {
		t.Fatalf("signer = %+v", hs)
	}
	if !eventWith(events(s.C), "collection-submitted") || !eventWith(events(s.B), "collection-closed") {
		t.Errorf("logs %v %v", events(s.C), events(s.B))
	}
}

// ---- SPO-Xparty-INV-005: revocation ------------------------------------------------------

// spec: SPO-Xparty-INV-005, SPO-Xparty-IF-003, SPO-Xparty-OUT-004
func TestRevocationKeepsVerifiedWitnessesAndUnassignsTheRest(t *testing.T) {
	s := newScene(t, sceneOpt{cold: true})
	s.request(func(in *multisig.RequestInput) {})
	// Only the stake request is answerable: bob holds the cold key too, but
	// the test answers just the first.
	hs := s.bobHandles()
	if len(hs) != 2 {
		t.Fatalf("%d requests", len(hs))
	}
	pend, _ := s.B.Signer().Pending(ctx)
	var stakeReq party.MessageID
	for _, p := range pend {
		if p.Role == custody.RoleStake {
			stakeReq = p.ID
		}
	}
	rv, err := s.B.Signer().ReviewRequest(ctx, stakeReq)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := rv.Approval()
	if _, err := s.B.Signer().Approve(ctx, a); err != nil {
		t.Fatal(err)
	}
	s.bobFlush()
	if hs := s.coordHandles(); len(hs) != 1 || hs[0].Effect != "filled" {
		t.Fatalf("coordinator = %+v", hs)
	}
	// A request still queued for bob goes when the party is revoked.
	s.cb.Down = true
	s.request(func(in *multisig.RequestInput) { in.Renew = true })
	if items, _ := s.C.Outbox().Pending(ctx); len(items) == 0 {
		t.Fatal("nothing is queued for bob")
	}
	s.C.Revoke("bob")
	c := s.collection()
	if !c.Slots[0].Filled() || c.Slots[0].Party != "bob" {
		t.Errorf("the verified witness was not kept: %+v", c.Slots[0])
	}
	if c.Slots[1].Party != "" || c.Slots[1].Filled() {
		t.Errorf("the unfilled slot is not unassigned: %+v", c.Slots[1])
	}
	if items, _ := s.C.Outbox().Pending(ctx); len(items) != 0 {
		t.Errorf("envelopes for the revoked party stay queued: %+v", items)
	}
	if !eventWith(events(s.C), "party-revoked") || !eventWith(events(s.C), "slot-unassigned") {
		t.Errorf("log %v", events(s.C))
	}
	// The cold slot is now reported as unassigned and nothing is sent.
	s.cb.Down = false
	res, err := s.C.Coordinator().RequestSignatures(ctx, multisig.RequestInput{Ref: s.ref}, s.cb.Transport())
	if err != nil || res[0].Status != multisig.SlotFilled || res[1].Status != multisig.SlotRefused {
		t.Fatalf("request = %+v, %v", res, err)
	}
	// Bob's envelopes, even made before, are refused.
	late := s.sealFrom(s.B, s.C, party.Hello{}, s.clock.Now(), s.clock.Now().Add(time.Minute))
	h, _ := s.C.Coordinator().Handle(ctx, late, ports.ViaNetwork)
	mustRefuse(t, h, envelope.ErrSenderRevoked.Error())
}

// ---- the pump -------------------------------------------------------------------------------

// The Pump moves envelopes between the store-backed outboxes and the
// transports until idle, and the result is the same completion.
// spec: SPO-Xparty-SEC-003, SPO-Xparty-SEC-002
func TestPumpRunsTheWorkflowUntilIdle(t *testing.T) {
	s := newScene(t, sceneOpt{kind: ports.ViaNetwork})
	s.request()
	bobPump := multisig.Pump{Outbox: s.B.Outbox(), Send: s.bc.Transport(), Receive: s.cb, Handle: s.B.Signer().Handle, Idle: 30 * time.Millisecond}
	if err := bobPump.Run(ctx); err != nil {
		t.Fatal(err)
	}
	s.bobApproves()
	if err := bobPump.Run(ctx); err != nil {
		t.Fatal(err)
	}
	var seen []multisig.Handled
	coordPump := multisig.Pump{Outbox: s.C.Outbox(), Send: s.cb.Transport(), Receive: s.bc, Handle: s.C.Coordinator().Handle, Idle: 30 * time.Millisecond,
		Handled: func(h multisig.Handled) { seen = append(seen, h) }}
	if err := coordPump.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0].Effect != "filled" || !seen[0].Complete {
		t.Fatalf("pump saw %+v", seen)
	}
	if got := s.collection().State(1000); got != pool.CollectionOpenComplete {
		t.Errorf("state %s", got)
	}
}

// ---- Invite ------------------------------------------------------------------------------------

// An Invite is handed to the wiring, which stores its address as a Secret; it
// is redacted in every format verb.
// spec: SPO-Xparty-SEC-001, SPO-Xparty-INV-010
func TestInviteGoesToTheHookAndIsRedacted(t *testing.T) {
	s := newScene(t, sceneOpt{})
	var got party.Invite
	signer := s.B.Signer()
	signer.OnInvite = func(_ ports.Writer, from party.Party, inv party.Invite) error {
		got = inv
		if from.Name != "coord" {
			t.Errorf("from %s", from.Name)
		}
		return nil
	}
	inv := party.Invite{Address: "tailcat://secret-address-text", Node: coordNode}
	env := s.sealFrom(s.C, s.B, inv, s.clock.Now(), s.clock.Now().Add(time.Hour))
	h, err := signer.Handle(ctx, env, ports.ViaFile)
	if err != nil || h.Effect != "invite" || got.Address != inv.Address {
		t.Fatalf("handled = %+v, %v, got %+v", h, err, got)
	}
	for _, shown := range []string{fmt.Sprint(got), fmt.Sprintf("%v %+v %#v", got, got, got)} {
		if strings.Contains(shown, "secret-address") {
			t.Errorf("the address is shown: %s", shown)
		}
	}
	// A signer without the hook refuses it.
	h, _ = s.B.Signer().Handle(ctx, s.sealFrom(s.C, s.B, inv, s.clock.Now(), s.clock.Now().Add(time.Hour)), ports.ViaFile)
	if !h.Refused {
		t.Errorf("an invite was taken with no hook: %+v", h)
	}
}

// ---- IF-007 ---------------------------------------------------------------------------------------

// A slot filled by the upstream route is marked and stays marked; an
// enveloped response is not. The collection refuses to overwrite either way.
// spec: SPO-Xparty-IF-007, SPO-Xparty-INV-014
func TestUnauthenticatedWitnessCannotBeConfusedWithAnEnvelopedOne(t *testing.T) {
	s := newScene(t, sceneOpt{})
	c := s.collection()
	w := s.witnessOver(s.body.ID)
	filled, err := c.Fill(pool.Fill{Slot: "bob.staking", Witness: w, ExpectVersion: c.Version, Unauthenticated: true}, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !filled.Slots[0].Unauthenticated {
		t.Fatal("an imported witness is not marked")
	}
	// A late response for the slot is acknowledged without effect and does not clear the mark.
	if _, err := filled.Fill(pool.Fill{Slot: "bob.staking", Witness: w, ExpectVersion: filled.Version}, 1000); err == nil {
		t.Error("the collection overwrote a filled slot")
	}
}
