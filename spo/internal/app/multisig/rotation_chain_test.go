package multisig_test

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/envelope"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/multiparty/partyrig"
)

// bobRotatesAndCoordAccepts has bob rotate, carries the announcement for the
// coordinator by file and has the coordinator accept it. It returns the new
// fingerprint.
func (s *scene) bobRotatesAndCoordAccepts() party.Fingerprint {
	s.t.Helper()
	done := s.B.Rotate("")
	var env []byte
	for _, it := range outboxOf(s.t, s.B) {
		if it.Type == string(party.TypeRotation) && it.To == hex.EncodeToString(s.C.Identity.Fingerprint[:]) {
			env = it.Envelope
		}
	}
	// handed over: the announcements are delivered, which a further rotation needs
	if _, err := s.B.Outbox().Flush(ctx, s.bc.Transport()); err != nil {
		s.t.Fatal(err)
	}
	s.bc.Take()
	if h, err := s.C.Coordinator().Handle(ctx, partyrig.Received(env, ports.ViaFile)); err != nil || h.Effect != "rotation-pending" {
		s.t.Fatalf("announcement: %+v, %v", h, err)
	}
	if _, err := s.C.Node().AcceptRotation(ctx, "bob", s.coordTyped(done.New)); err != nil {
		s.t.Fatalf("accepting the rotation to %s: %v", done.New, err)
	}
	return done.New
}

// A party with a tailcat node key rotates twice (A to B to C): the revoked
// records of the first rotation keep the node key and do not block the second.
// The coordinator's live allow-list admits exactly the active identity's node
// key, and nothing once that identity is revoked; the node key can then be
// enrolled again under a new name.
//
// spec: SPO-Xparty-INV-032, SPO-Xparty-IF-005, SPO-Xparty-IF-002
func TestAPartyWithANodeKeyCanRotateTwiceAndBeEnrolledAgain(t *testing.T) {
	s := newScene(t, sceneOpt{bobNode: true})
	s.bobRotatesAndCoordAccepts()
	s.bobRotatesAndCoordAccepts()
	keys, err := s.C.Node().AllowList(ctx)
	if err != nil || len(keys) != 1 || keys[0] != bobNodeKey {
		t.Fatalf("allow-list after two rotations: %v, %v", keys, err)
	}
	active := 0
	for _, p := range registry(t, s.C) {
		if p.Identity.Node != nil && *p.Identity.Node == bobNodeKey && p.Active() {
			active++
		}
	}
	if active != 1 {
		t.Fatalf("%d active records hold the node key", active)
	}
	s.C.Revoke("bob")
	if keys, _ := s.C.Node().AllowList(ctx); len(keys) != 0 {
		t.Fatalf("allow-list after the revocation: %v", keys)
	}
	again := partyrig.NewWithNode(t, "bob-again", s.clock, s.chain, &bobNodeKey)
	s.C.Enroll(again, "bob2", []party.Role{party.RoleSigner}, []string{s.bech})
	if keys, _ := s.C.Node().AllowList(ctx); len(keys) != 1 || keys[0] != bobNodeKey {
		t.Fatalf("allow-list after enrolling the node key again: %v", keys)
	}
}

// The node key is not rotated: a statement whose new identity has another node
// key than the sender's enrolled one is refused when it arrives and never stored
// as pending.
//
// spec: SPO-Xparty-INV-030, SPO-Xparty-INV-031
func TestRotationToAnotherNodeKeyIsRefusedAtReceipt(t *testing.T) {
	s := newScene(t, sceneOpt{})
	oldNode, newNode := party.NodeKey{0xd, 1}, party.NodeKey{0xd, 2}
	old, err := envelope.Generate("rogue", &oldNode, s.clock.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Destroy()
	next, err := envelope.Generate("rogue", &newNode, s.clock.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Destroy()
	doc, err := envelope.EncodeDocument(old)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := s.C.Kit.ParseDocument(doc)
	if err != nil {
		t.Fatal(err)
	}
	existing := registry(t, s.C)
	if err := s.C.Store.Update(ctx, func(w ports.Writer) error {
		p, err := party.Enroll(party.Enrollment{Document: parsed, Name: "rogue", Roles: []party.Role{party.RoleSigner}, Confirmation: old.Fingerprint().String()[:19]},
			existing, s.clock.Now())
		if err != nil {
			return err
		}
		return s.C.Registry.Put(w, p)
	}); err != nil {
		t.Fatal(err)
	}
	stmt, err := envelope.NewRotation(old, next, s.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	local, err := s.C.Kit.Local(ctx)
	if err != nil {
		t.Fatal(err)
	}
	to := local.Identity()
	local.Destroy()
	env, _, err := envelope.Seal(old, to, party.RotationAnnouncement{Statement: stmt}, s.clock.Now(), s.clock.Now().Add(time.Hour), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h, err := s.C.Coordinator().Handle(ctx, partyrig.Received(env, ports.ViaFile))
	if err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, h, "node key")
	if pend, _ := s.C.Node().PendingRotations(ctx); len(pend) != 0 {
		t.Fatalf("a statement that changes the node key is pending: %+v", pend)
	}
}
