package multisig_test

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/multiparty/partyrig"
)

// filledAndClosed runs a request to the end: bob answers, the coordinator fills
// the slot, the collection is closed as submitted. It returns bob's response
// envelope, which a transport may deliver again.
func filledAndClosed(t *testing.T) (*scene, []byte, party.CollectionID) {
	t.Helper()
	s := newScene(t, sceneOpt{kind: ports.ViaNetwork, bobNode: true})
	s.connect()
	s.request()
	s.bobHandles()
	s.bobApproves()
	s.bobFlush()
	resp := s.bc.Take()
	if len(resp) != 1 {
		t.Fatalf("%d responses", len(resp))
	}
	h, err := s.C.Coordinator().Handle(ctx, ports.NetworkReceived(resp[0]))
	if err != nil || h.Effect != "filled" {
		t.Fatalf("the response = %+v, %v", h, err)
	}
	cid := s.cid()
	if err := s.C.Coordinator().Close(ctx, s.ref, party.OutcomeSubmitted, [32]byte{}); err != nil {
		t.Fatal(err)
	}
	return s, resp[0], cid
}

// goneCollection removes the collection from the store, as a submission does.
func goneCollection(t *testing.T, s *scene) {
	t.Helper()
	if err := s.C.Store.Update(ctx, func(w ports.NamedWriter) error {
		return w.Delete(ports.NamedRef{Name: s.ref.Name, Kind: ports.MultisigCollection})
	}); err != nil {
		t.Fatal(err)
	}
}

func refusalEntries(w *partyrig.Workspace) (n int, count int) {
	for _, e := range w.Events() {
		if strings.Contains(e.Kind, "refused") {
			n++
			count += max(e.Count, 1)
		}
	}
	return n, count
}

// The same response arriving again after the collection was closed and its
// record is gone, which a re-put that crossed the response makes likely over a
// mailbox, is the signer's own answer: it is acknowledged without a security
// event, and a relay that replays it ten times costs the operator nothing.
//
// spec: SPO-Xparty-INV-041, SPO-Xparty-INV-017
func TestALateDuplicateOfAnAcceptedResponseIsNotARefusal(t *testing.T) {
	s, resp, _ := filledAndClosed(t)
	goneCollection(t, s)
	for i := range 10 {
		h, err := s.C.Coordinator().Handle(ctx, ports.NetworkReceived(resp))
		if err != nil {
			t.Fatal(err)
		}
		if h.Refused || h.Effect != "acknowledged" {
			t.Fatalf("delivery %d = %+v, want acknowledged", i, h)
		}
	}
	if n, c := refusalEntries(s.C); n != 0 || c != 0 {
		t.Fatalf("%d refusal entries (counter %d) for the signer's own late duplicate, want none", n, c)
	}
}

// A late response with an id the coordinator never accepted, from the party
// the slot's request was sealed to, for a closed collection: acknowledged with
// a low-severity event of its own, and its id recorded, so that a replay is an
// ordinary replay and the counter of "not the signer of that slot" is not
// touched.
//
// spec: SPO-Xparty-INV-041, SPO-Xparty-INV-023
func TestALateResponseOfTheRecordedSignerIsRecordedOnce(t *testing.T) {
	s, _, cid := filledAndClosed(t)
	goneCollection(t, s)
	now := s.clock.Now()
	env := s.sealFrom(s.B, s.C, party.SigningResponse{Collection: cid, Slot: 0, Witness: []byte{1}}, now, now.Add(time.Hour))
	h, err := s.C.Coordinator().Handle(ctx, ports.NetworkReceived(env))
	if err != nil {
		t.Fatal(err)
	}
	if h.Refused {
		t.Fatalf("a late response of the recorded signer was refused: %+v", h)
	}
	late := 0
	for _, e := range s.C.Events() {
		if e.Kind == "late-response" {
			late++
		}
	}
	if late != 1 {
		t.Fatalf("%d late-response events, want 1", late)
	}
	for i := range 5 { // the relay replays it
		h, err := s.C.Coordinator().Handle(ctx, ports.NetworkReceived(env))
		if err != nil {
			t.Fatal(err)
		}
		if !h.Refused || !strings.Contains(h.Reason, "already accepted") {
			t.Fatalf("replay %d = %+v, want a plain replay refusal", i, h)
		}
	}
	for _, e := range s.C.Events() {
		if strings.Contains(e.Reason, "not the signer of that slot") {
			t.Fatalf("a replay of a late response was recorded as %q", e.Reason)
		}
	}
}

// A collection that was announced closed while its record is still there: a late
// response with a new id from the recorded signer is recorded as a late response
// (not refused as "collection not open"), and a replay of the same envelope is a
// plain replay.
//
// spec: SPO-Xparty-INV-041
func TestALateResponseForAClosedCollectionWhoseRecordRemainsIsRecordedOnce(t *testing.T) {
	s, _, cid := filledAndClosed(t)
	now := s.clock.Now()
	env := s.sealFrom(s.B, s.C, party.SigningResponse{Collection: cid, Slot: 0, Witness: []byte{1}}, now, now.Add(time.Hour))
	h, err := s.C.Coordinator().Handle(ctx, ports.NetworkReceived(env))
	if err != nil || h.Refused || h.Effect != "late-response" {
		t.Fatalf("late response = %+v, %v, want recorded without refusal", h, err)
	}
	if h, _ := s.C.Coordinator().Handle(ctx, ports.NetworkReceived(env)); !h.Refused || !strings.Contains(h.Reason, "already accepted") {
		t.Fatalf("its replay = %+v, want a plain replay refusal", h)
	}
	if n, _ := refusalEntries(s.C); n != 1 {
		t.Fatalf("%d refusal entries, want the one replay", n)
	}
}

// "Not the signer of that slot" stays where it is true: a sender that is not
// the party the slot's request went to, for a closed collection; and a live
// collection, even when the sender is the party the request was recorded for.
//
// spec: SPO-Xparty-INV-041
func TestNotTheSignerOfThatSlotStaysForOthers(t *testing.T) {
	t.Run("a sender that is not the recorded signer, collection closed", func(t *testing.T) {
		s, _, cid := filledAndClosed(t)
		goneCollection(t, s)
		now := s.clock.Now()
		env := s.sealFrom(s.X, s.C, party.SigningResponse{Collection: cid, Slot: 0, Witness: []byte{1}}, now, now.Add(time.Hour))
		h, err := s.C.Coordinator().Handle(ctx, ports.NetworkReceived(env))
		if err != nil {
			t.Fatal(err)
		}
		mustRefuse(t, h, "not the signer of that slot")
	})
	t.Run("a live collection, sender recorded for the slot but not assigned to it", func(t *testing.T) {
		s := newScene(t, sceneOpt{kind: ports.ViaNetwork, bobNode: true})
		s.connect()
		s.request()
		s.bobHandles()
		// the coordinator's record says the slot's request went to xavier, who is
		// not the signer the collection assigns it to
		ref := ports.NamedRef{Name: "state", Kind: ports.MultisigCoordinator}
		if err := s.C.Store.Update(ctx, func(w ports.NamedWriter) error {
			raw, err := w.Get(ref)
			if err != nil {
				return err
			}
			var st map[string]any
			if err := json.Unmarshal(raw, &st); err != nil {
				return err
			}
			slot := st["collections"].([]any)[0].(map[string]any)["slots"].(map[string]any)["0"].(map[string]any)
			xav := s.fp("xav")
			slot["to"] = hex.EncodeToString(xav[:])
			out, err := json.Marshal(st)
			if err != nil {
				return err
			}
			return w.Put(ref, out)
		}); err != nil {
			t.Fatal(err)
		}
		now := s.clock.Now()
		env := s.sealFrom(s.X, s.C, party.SigningResponse{Collection: s.cid(), Slot: 0, Witness: []byte{1}}, now, now.Add(time.Hour))
		h, err := s.C.Coordinator().Handle(ctx, ports.NetworkReceived(env))
		if err != nil {
			t.Fatal(err)
		}
		mustRefuse(t, h, "not the signer of that slot")
	})
}
