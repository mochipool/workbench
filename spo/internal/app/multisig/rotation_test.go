package multisig_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/envelope"
	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/multiparty/partyrig"
)

// outboxTo is the envelopes of the workspace's outbox addressed to a party.
func outboxOf(t *testing.T, w *partyrig.Workspace) []multisig.OutItem {
	t.Helper()
	items, err := w.Outbox().Pending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return items
}

func partyNamed(t *testing.T, w *partyrig.Workspace, name string) party.Party {
	t.Helper()
	var out party.Party
	if err := w.Store.View(ctx, func(r ports.NamedReader) error {
		p, err := w.Registry.ByName(r, name)
		out = p
		return err
	}); err != nil {
		t.Fatalf("%s has no party %q: %v", w.Name, name, err)
	}
	return out
}

func registry(t *testing.T, w *partyrig.Workspace) []party.Party {
	t.Helper()
	var out []party.Party
	if err := w.Store.View(ctx, func(r ports.NamedReader) error {
		var err error
		out, err = w.Registry.List(r)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// bobRotates has bob rotate his identity and returns the announcement
// addressed to the coordinator.
func (s *scene) bobRotates() (multisig.RotationDone, []byte) {
	s.t.Helper()
	done := s.B.Rotate("bob again")
	var env []byte
	for _, it := range outboxOf(s.t, s.B) {
		if it.Type == string(party.TypeRotation) {
			if it.To == hex.EncodeToString(s.C.Identity.Fingerprint[:]) {
				env = it.Envelope
			}
		}
	}
	if env == nil {
		s.t.Fatalf("no announcement for the coordinator in %+v", outboxOf(s.t, s.B))
	}
	return done, env
}

func (s *scene) coordTyped(fp party.Fingerprint) party.RotationAcceptance {
	return party.RotationAcceptance{Confirmation: fp.String()[:19]}
}

// A rotation: bob replaces his identity, the coordinator receives the
// announcement over a file or a network, and nothing changes in its registry
// until its operator confirms with the first four groups of the new
// fingerprint. Then, in one step, bob's old identity is revoked and the new one
// is active under the same name, and the old identity's envelopes are refused.
//
// spec: SPO-Xparty-IF-008, SPO-Xparty-INV-030, SPO-Xparty-INV-031, SPO-Xparty-INV-032, SPO-Xparty-PR-006
func TestRotationIsPendingUntilTheOperatorConfirms(t *testing.T) {
	for _, via := range []ports.TransportKind{ports.ViaFile, ports.ViaNetwork} {
		t.Run(via.String(), func(t *testing.T) {
			s := newScene(t, sceneOpt{})
			oldFP := s.B.Identity.Fingerprint
			// An envelope bob sealed with his old identity before the rotation.
			staleHello := partyrig.Seal(t, s.B, s.C, party.Hello{}, 4*time.Minute)

			done, env := s.bobRotates()
			if done.Old != oldFP || done.New == oldFP || len(done.Announced) != 1 {
				t.Fatalf("done = %+v", done)
			}
			h, err := s.C.Coordinator().Handle(ctx, partyrig.Received(env, via))
			if err != nil || h.Refused || h.Effect != "rotation-pending" {
				t.Fatalf("handled = %+v, %v", h, err)
			}
			// Nothing changed: bob is the old identity, active, and a pending
			// announcement is listed.
			if p := partyNamed(t, s.C, "bob"); p.Fingerprint != oldFP || !p.Active() {
				t.Fatalf("the registry changed on receipt: %+v", p)
			}
			pend, err := s.C.Node().PendingRotations(ctx)
			if err != nil || len(pend) != 1 || pend[0].Name != "bob" || pend[0].New.Fingerprint() != done.New || pend[0].Old != oldFP {
				t.Fatalf("pending = %+v, %v", pend, err)
			}
			if !eventWith(events(s.C), "rotation-received") {
				t.Error("no event for the announcement")
			}
			// A wrong or empty confirmation changes nothing.
			for _, typed := range []string{"", "aaaa-aaaa-aaaa-aaaa", oldFP.String()[:19]} {
				if _, err := s.C.Node().AcceptRotation(ctx, "bob", party.RotationAcceptance{Confirmation: typed, CarryScope: true}); !errors.Is(err, party.ErrConfirmation) {
					t.Fatalf("confirmation %q: %v", typed, err)
				}
			}
			if p := partyNamed(t, s.C, "bob"); p.Fingerprint != oldFP || !p.Active() {
				t.Fatalf("a refused confirmation changed the registry: %+v", p)
			}
			// Confirmed, scope not carried over.
			res, err := s.C.Node().AcceptRotation(ctx, "bob", s.coordTyped(done.New), s.C.Coordinator().OnRotate)
			if err != nil {
				t.Fatal(err)
			}
			nb := partyNamed(t, s.C, "bob")
			if nb.Fingerprint != done.New || !nb.Active() || !nb.HasRole(party.RoleSigner) || !nb.Scope.Empty() {
				t.Fatalf("the new enrollment: %+v", nb)
			}
			if res.Retired.Active() || res.Retired.Fingerprint != oldFP || res.Retired.Name == "bob" {
				t.Fatalf("the old one: %+v", res.Retired)
			}
			active := 0
			for _, p := range registry(t, s.C) {
				if p.Active() && p.HasRole(party.RoleSigner) && (p.Fingerprint == oldFP || p.Fingerprint == done.New) {
					active++
				}
			}
			if active != 1 {
				t.Errorf("%d of the two identities are active", active)
			}
			// The old identity's envelope, created before, is refused now; the
			// new one's is accepted.
			h, err = s.C.Coordinator().Handle(ctx, partyrig.Received(staleHello, via))
			if err != nil {
				t.Fatal(err)
			}
			mustRefuse(t, h, "sender is revoked")
			h, err = s.C.Coordinator().Handle(ctx, partyrig.Received(partyrig.Seal(t, s.B, s.C, party.Hello{}, 4*time.Minute), via))
			if err != nil || h.Refused || h.Effect != "hello" {
				t.Fatalf("the new identity's hello: %+v, %v", h, err)
			}
			// The announcement is not applied twice: its id is in the replay
			// log, and the statement names an identity that is revoked now.
			h, err = s.C.Coordinator().Handle(ctx, partyrig.Received(env, via))
			if err != nil || !h.Refused {
				t.Fatalf("a replayed announcement: %+v, %v", h, err)
			}
			if !eventWith(events(s.C), "party-rotated") {
				t.Error("no event for the rotation")
			}
			if pend, _ := s.C.Node().PendingRotations(ctx); len(pend) != 0 {
				t.Errorf("pending after accept: %+v", pend)
			}
		})
	}
}

// The scope carries over only when the operator says so, and the roles carry
// over unchanged: a rotation cannot give a party a role it did not have.
//
// spec: SPO-Xparty-PR-006, SPO-Xparty-INV-032
func TestRotationCarriesTheScopeOnlyOnAYes(t *testing.T) {
	s := newScene(t, sceneOpt{})
	// bob rotates; the coordinator's record of bob has a scope for the pool
	_, env := s.bobRotates()
	if _, err := s.C.Coordinator().Handle(ctx, partyrig.Received(env, ports.ViaFile)); err != nil {
		t.Fatal(err)
	}
	pr, err := s.C.Node().RotationOf(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}
	old := partyNamed(t, s.C, "bob")
	if len(old.Scope.Pools) != 1 {
		t.Fatalf("the scene gave bob no scope: %+v", old.Scope)
	}
	if _, err := s.C.Node().AcceptRotation(ctx, "bob", party.RotationAcceptance{Confirmation: pr.New.Fingerprint().String()[:19], CarryScope: true}, s.C.Coordinator().OnRotate); err != nil {
		t.Fatal(err)
	}
	nb := partyNamed(t, s.C, "bob")
	if len(nb.Scope.Pools) != 1 || nb.Scope.Pools[0] != old.Scope.Pools[0] || len(nb.Roles) != 1 || nb.Roles[0] != party.RoleSigner {
		t.Errorf("carried: %+v", nb)
	}
}

// A statement that names an identity that was never enrolled, that is another
// identity than the sender's, that is forged, expired or a replay, changes
// nothing and is recorded.
//
// spec: SPO-Xparty-INV-031, SPO-Xparty-INV-032
func TestRotationStatementsThatAreNotTheSendersOwnAreRefused(t *testing.T) {
	s := newScene(t, sceneOpt{})
	mkPriv := func(seed string) *envelope.Private {
		p, err := envelope.Generate(seed, nil, s.clock.Now(), bytes.NewReader(bytes.Repeat([]byte(seed), 64)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Destroy)
		return p
	}
	stranger, next := mkPriv("s"), mkPriv("n")
	sendAs := func(name string, stmt []byte) multisig.Handled {
		t.Helper()
		env := partyrig.Seal(t, s.B, s.C, party.RotationAnnouncement{Statement: stmt}, time.Hour)
		h, err := s.C.Coordinator().Handle(ctx, partyrig.Received(env, ports.ViaFile))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return h
	}
	// naming an identity never enrolled here, signed by that identity
	stmt, err := envelope.NewRotation(stranger, next, s.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, sendAs("never enrolled", stmt), "another identity than its sender")
	// naming the sender but signed by another key as the old key
	local, err := s.B.Kit.Local(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Destroy()
	forged := forgedStatement(t, s, stranger, next)
	mustRefuse(t, sendAs("old signature by another key", forged), "signature")
	// an expired statement
	oldStmt, err := s.B.Kit.Rotate(ctx, ports.RotateRequest{Now: s.clock.Now().Add(-40 * 24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	oldStmt.Keys.Destroy()
	mustRefuse(t, sendAs("expired", oldStmt.Statement), "expired")
	// nothing is pending, the registry is as it was, every refusal is an event
	if pend, _ := s.C.Node().PendingRotations(ctx); len(pend) != 0 {
		t.Errorf("pending: %+v", pend)
	}
	if p := partyNamed(t, s.C, "bob"); p.Fingerprint != s.B.Identity.Fingerprint || !p.Active() {
		t.Errorf("registry: %+v", p)
	}
	if !eventWith(events(s.C), "refused") {
		t.Error("no refusal event")
	}
}

// forgedStatement is a statement that names bob's identity as the old one but
// whose old signature is made by another key.
func forgedStatement(t *testing.T, s *scene, other, next *envelope.Private) []byte {
	t.Helper()
	// a statement about "other" signed by other, then the old fingerprint in
	// its content replaced by bob's: the old signature no longer covers it
	stmt, err := envelope.NewRotation(other, next, s.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	r, err := envelope.ParseRotation(stmt)
	if err != nil {
		t.Fatal(err)
	}
	bad := bytes.Replace(stmt, r.Old[:], s.B.Identity.Fingerprint[:], 1)
	if bytes.Equal(bad, stmt) {
		t.Fatal("the fingerprint was not found in the statement")
	}
	return bad
}

// An announcement of the same sender replaces its earlier one: one pending per
// sender.
//
// spec: SPO-Xparty-INV-031
func TestOnePendingRotationPerSender(t *testing.T) {
	s := newScene(t, sceneOpt{})
	_, env1 := s.bobRotates()
	if _, err := s.C.Coordinator().Handle(ctx, partyrig.Received(env1, ports.ViaFile)); err != nil {
		t.Fatal(err)
	}
	pend, _ := s.C.Node().PendingRotations(ctx)
	if len(pend) != 1 {
		t.Fatalf("%d pending", len(pend))
	}
	if err := s.C.Node().RejectRotation(ctx, "bob"); err != nil {
		t.Fatal(err)
	}
	if pend, _ := s.C.Node().PendingRotations(ctx); len(pend) != 0 {
		t.Errorf("pending after reject: %+v", pend)
	}
	if err := s.C.Node().RejectRotation(ctx, "bob"); !errors.Is(err, multisig.ErrNoRotation) {
		t.Errorf("rejecting twice: %v", err)
	}
	if p := partyNamed(t, s.C, "bob"); p.Fingerprint != s.B.Identity.Fingerprint && !p.Active() {
		t.Errorf("a rejection changed the enrollment: %+v", p)
	}
}

// In-flight collections are not carried over: when the coordinator accepts bob's
// rotation, the request it had sent to bob's old identity is void, a response
// to it is refused, and a new request goes to the new identity and is answered.
//
// spec: SPO-Xparty-INV-033, SPO-Xparty-PRE-005
func TestInFlightRequestsMustBeRequestedAgainAfterARotation(t *testing.T) {
	s := newScene(t, sceneOpt{})
	if res := s.request(); res[0].Status != multisig.SlotRequested {
		t.Fatalf("request: %+v", res)
	}
	// bob receives and approves it with his OLD identity; the response is sealed
	// by the old identity and not delivered yet.
	s.bobHandles()
	rv := s.bobApproves()
	oldResp := s.B.Outbox()
	var respEnv []byte
	items, _ := oldResp.Pending(ctx)
	for _, it := range items {
		if it.Type == string(party.TypeSigningResponse) {
			respEnv = it.Envelope
		}
	}
	if respEnv == nil {
		t.Fatal("no response queued")
	}
	_, env := s.bobRotates()
	if _, err := s.C.Coordinator().Handle(ctx, partyrig.Received(env, ports.ViaFile)); err != nil {
		t.Fatal(err)
	}
	pr, _ := s.C.Node().RotationOf(ctx, "bob")
	res, err := s.C.Node().AcceptRotation(ctx, "bob", party.RotationAcceptance{Confirmation: pr.New.Fingerprint().String()[:19], CarryScope: true}, s.C.Coordinator().OnRotate)
	if err != nil {
		t.Fatal(err)
	}
	if res.VoidedSlots != 1 {
		t.Fatalf("voided %d slot requests", res.VoidedSlots)
	}
	if !eventWith(events(s.C), "request-voided") {
		t.Error("no event for the void request")
	}
	// the old identity's response (made before) is refused: its sender is revoked
	h, err := s.C.Coordinator().Handle(ctx, partyrig.Received(respEnv, ports.ViaFile))
	if err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, h, "sender is revoked")
	if c := s.collection(); c.Slots[0].Filled() {
		t.Fatal("the slot was filled by the old identity's response")
	}
	// bob has nothing waiting any more
	if pend, _ := s.B.Signer().Pending(ctx); len(pend) != 0 {
		t.Errorf("bob still has pending requests: %+v", pend)
	}
	// the new identity answering the OLD request id is refused as stale: the
	// request was voided
	staleResp := partyrig.Seal(t, s.B, s.C, party.SigningResponse{Collection: s.cid(), Slot: 0, Request: rv.RequestID, Witness: []byte{1}}, time.Hour)
	h, err = s.C.Coordinator().Handle(ctx, partyrig.Received(staleResp, ports.ViaFile))
	if err != nil {
		t.Fatal(err)
	}
	if !h.Refused {
		t.Fatalf("a response to the voided request: %+v", h)
	}
	// request again: goes to the new identity; bob (whose enrollment of the
	// coordinator did not change) answers; the slot fills
	res2 := s.request()
	if res2[0].Status != multisig.SlotRequested {
		t.Fatalf("request again: %+v", res2)
	}
	s.bobHandles()
	s.bobApproves()
	s.bobFlush()
	// bob's outbox also holds his announcement, sealed by the identity that is
	// revoked here now: that one is refused, the answer is not.
	filled, refused := 0, 0
	for _, h := range s.coordHandles() {
		switch {
		case h.Refused:
			refused++
		case h.Effect == "filled":
			filled++
		}
	}
	if filled != 1 || refused != 1 {
		t.Fatalf("filled %d, refused %d", filled, refused)
	}
	if !s.collection().Slots[0].Filled() {
		t.Error("the slot is not filled by the new identity's answer")
	}
}

// The rotating machine: its old keys are gone, requests waiting for it are
// closed with the outcome "rotated" (and refused with that message), everything
// in its outbox is replaced by the announcements, and what it coordinates must
// be requested again.
//
// spec: SPO-Xparty-INV-033, SPO-Xparty-IF-008
func TestRotatingMachineClosesWhatWaitsAndDropsTheOutbox(t *testing.T) {
	s := newScene(t, sceneOpt{})
	s.request()
	s.bobHandles()
	pend, _ := s.B.Signer().Pending(ctx)
	if len(pend) != 1 {
		t.Fatalf("pending %v", pend)
	}
	// an envelope sealed to bob's OLD identity cannot be opened after the rotation
	toOld := partyrig.Seal(t, s.C, s.B, party.Hello{}, time.Minute)
	oldFP := s.B.Identity.Fingerprint
	done := s.B.Rotate("")
	if done.ClosedRequests != 1 {
		t.Fatalf("done = %+v", done)
	}
	if got, _ := s.B.Signer().Pending(ctx); len(got) != 0 {
		t.Errorf("pending after rotation: %+v", got)
	}
	closed, _ := s.B.Signer().Closed(ctx)
	if len(closed) != 1 || closed[0].Outcome != multisig.ClosedRotated {
		t.Fatalf("closed = %+v", closed)
	}
	if _, err := s.B.Signer().ReviewRequest(ctx, pend[0].ID); !errors.Is(err, multisig.ErrRequestClosed) || !strings.Contains(err.Error(), "replaced by a rotation") {
		t.Errorf("review of a request closed by a rotation: %v", err)
	}
	items := outboxOf(t, s.B)
	for _, it := range items {
		if it.Type != string(party.TypeRotation) {
			t.Errorf("a %s survived in the outbox", it.Type)
		}
	}
	if len(items) != 1 {
		t.Errorf("%d items in the outbox, want the one announcement", len(items))
	}
	local, err := s.B.Kit.Local(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Destroy()
	if local.Identity().Fingerprint() == oldFP || local.Identity().Fingerprint() != done.New {
		t.Fatal("the local identity is not the new one")
	}
	if local.Identity().Label != "bob" {
		t.Errorf("an empty label did not keep the old one: %q", local.Identity().Label)
	}
	if _, err := local.Open(toOld, func(party.Fingerprint) (party.Party, bool) { return party.Party{}, false }, s.clock.Now()); err == nil {
		t.Error("an envelope sealed to the old identity opened after the rotation")
	}
	if !eventWith(events(s.B), "identity-rotated") {
		t.Error("no event")
	}
}

// A coordinator that rotates must request again: its outstanding request is gone.
//
// spec: SPO-Xparty-INV-033
func TestCoordinatorRotationVoidsItsOutstandingRequests(t *testing.T) {
	s := newScene(t, sceneOpt{})
	s.request()
	if res := s.request(); res[0].Status == multisig.SlotRequested {
		t.Fatal("a second request without renew was sent")
	}
	done := s.C.Rotate("")
	if done.VoidedSlots != 1 {
		t.Fatalf("done = %+v", done)
	}
	// the coordinator's new identity is unknown to bob until he accepts; the
	// request is made again by the use case (sealed by the new identity to bob's
	// enrolled, unchanged identity)
	if res := s.request(); res[0].Status != multisig.SlotRequested {
		t.Fatalf("after the rotation: %+v", res)
	}
}

// With no usable old identity there is no rotation, and the error says that
// enrolling anew is the way forward.
//
// spec: SPO-Xparty-IF-008
func TestNoRotationWithoutTheOldKey(t *testing.T) {
	s := newScene(t, sceneOpt{})
	if err := s.B.Store.Update(ctx, func(w ports.NamedWriter) error { return w.Delete(ports.NamedRef{Name: "local", Kind: ports.PartyKeys}) }); err != nil {
		t.Fatal(err)
	}
	_, err := s.B.Node().RotateIdentity(ctx, "")
	if !errors.Is(err, multisig.ErrOldKeyUnavailable) || !strings.Contains(err.Error(), "enroll it from scratch") {
		t.Fatalf("rotation without the old key: %v", err)
	}
	if got := s.B.Identity.Fingerprint; partyNamed(t, s.C, "bob").Fingerprint != got {
		t.Error("the identity changed")
	}
}

// What can no longer be confirmed does not stay: an announcement of a sender
// that was revoked is dropped when another announcement arrives, so a revoked
// party cannot fill the list.
//
// spec: SPO-Xparty-INV-031
func TestPendingRotationOfARevokedSenderIsDropped(t *testing.T) {
	s := newScene(t, sceneOpt{})
	_, env := s.bobRotates()
	if _, err := s.C.Coordinator().Handle(ctx, partyrig.Received(env, ports.ViaFile)); err != nil {
		t.Fatal(err)
	}
	if st := s.C.Revoke("bob"); st.Active() {
		t.Fatal("not revoked")
	}
	if pend, _ := s.C.Node().PendingRotations(ctx); len(pend) != 0 {
		t.Fatalf("an announcement of a revoked party is listed: %+v", pend)
	}
	// xavier announces; bob's stale entry is dropped with it
	xenv := func() []byte {
		s.X.Rotate("")
		for _, it := range outboxOf(t, s.X) {
			if it.To == hex.EncodeToString(s.C.Identity.Fingerprint[:]) {
				return it.Envelope
			}
		}
		t.Fatal("no announcement for the coordinator")
		return nil
	}()
	if h, err := s.C.Coordinator().Handle(ctx, partyrig.Received(xenv, ports.ViaFile)); err != nil || h.Refused {
		t.Fatalf("%+v %v", h, err)
	}
	pend, _ := s.C.Node().PendingRotations(ctx)
	if len(pend) != 1 || pend[0].Name != "xav" {
		t.Fatalf("pending = %+v", pend)
	}
}
