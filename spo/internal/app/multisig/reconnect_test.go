package multisig_test

import (
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/multiparty/partyrig"
)

// connect is one new connection of bob's to the coordinator as the tailcat
// client makes it: a fresh Hello is the first frame, the coordinator admits it
// (SPO-Xparty-INV-018) and handles it, which re-arms bob's unanswered requests.
func (s *scene) connect() multisig.Handled {
	s.t.Helper()
	hello, err := s.B.Signer().NewHello(ctx, "coord")
	if err != nil {
		s.t.Fatal(err)
	}
	if _, err := s.C.Coordinator().Admit(ctx, hello, bobNodeKey); err != nil {
		s.t.Fatalf("the first frame of a connection was refused: %v", err)
	}
	h, err := s.C.Coordinator().Handle(ctx, ports.NetworkReceived(hello))
	if err != nil || h.Effect != "hello" {
		s.t.Fatalf("hello = %+v, %v", h, err)
	}
	return h
}

func (s *scene) coordFlush() int {
	s.t.Helper()
	n, err := s.C.Outbox().Flush(ctx, s.cb.Transport())
	if err != nil {
		s.t.Fatal(err)
	}
	return n
}

// noRefusals asserts that no security event of the workspace records a refused
// envelope or message: a normal reconnect is not an attack.
func noRefusals(t *testing.T, w *partyrig.Workspace) {
	t.Helper()
	for _, e := range w.Events() {
		if strings.Contains(e.Kind, "refused") && e.Kind != "request-refused-by-signer" {
			t.Errorf("%s logged a security event for a normal reconnect: %+v", w.Name, e)
		}
	}
}

// The reviewer's lockout: after a response was accepted, bob's next connection
// opens with a fresh Hello, which Admit takes, and nothing of the response is
// sent again; the coordinator has nothing more to send, and neither side logs
// a refusal.
// spec: SPO-Xparty-INV-017, SPO-Xparty-INV-018
func TestSecondConnectionAfterAnAcceptedResponse(t *testing.T) {
	s := newScene(t, sceneOpt{kind: ports.ViaNetwork, bobNode: true})
	s.connect()
	s.request()
	s.bobHandles()
	s.bobApproves()
	s.bobFlush()
	if hs := s.coordHandles(); len(hs) != 1 || hs[0].Effect != "filled" {
		t.Fatalf("coordinator: %+v", hs)
	}
	for i := range 2 { // two more connections
		if err := s.B.Outbox().Rearm(ctx); err != nil {
			t.Fatal(err)
		}
		if n, err := s.B.Outbox().Flush(ctx, s.bc.Transport()); err != nil || n != 0 {
			t.Fatalf("connection %d: the accepted response was sent again (%d, %v)", i+2, n, err)
		}
		s.connect()
		if n := s.coordFlush(); n != 0 {
			t.Fatalf("connection %d: the coordinator sent %d envelopes for an answered request", i+2, n)
		}
	}
	noRefusals(t, s.C)
	noRefusals(t, s.B)
}

// A response whose write was lost is recovered: the coordinator re-sends the
// same request when the signer connects again, the signer answers it with its
// stored response without signing again, and the coordinator fills the slot.
// spec: SPO-Xparty-INV-017
func TestALostResponseIsRecoveredByTheResentRequest(t *testing.T) {
	s := newScene(t, sceneOpt{kind: ports.ViaNetwork, bobNode: true})
	s.connect()
	s.request()
	first := s.cb.Take()
	if len(first) != 1 {
		t.Fatalf("%d requests sent", len(first))
	}
	if h, _ := s.B.Signer().Handle(ctx, ports.NetworkReceived(first[0])); h.Effect != "stored" {
		t.Fatalf("request: %+v", h)
	}
	s.bobApproves()
	s.bobFlush()
	if lost := s.bc.Take(); len(lost) != 1 { // the connection dropped: the coordinator never sees it
		t.Fatalf("%d responses written", len(lost))
	}
	// Sent once, delivered: not sent again of its own accord.
	if items, _ := s.B.Outbox().Pending(ctx); len(items) != 0 {
		t.Fatalf("the response is still pending after its write succeeded: %+v", items)
	}
	// bob connects again.
	s.connect()
	if n := s.coordFlush(); n != 1 {
		t.Fatalf("the coordinator re-sent %d requests, want 1", n)
	}
	again := s.cb.Take()
	if string(again[0]) != string(first[0]) {
		t.Fatal("the re-sent request is not the same envelope, with the same message id")
	}
	h, err := s.B.Signer().Handle(ctx, ports.NetworkReceived(again[0]))
	if err != nil || h.Effect != "response-resent" {
		t.Fatalf("duplicate = %+v, %v", h, err)
	}
	if s.B.Gate.Count() != 1 {
		t.Fatalf("the key was touched again: gate asked %d times", s.B.Gate.Count())
	}
	s.bobFlush()
	if hs := s.coordHandles(); len(hs) != 1 || hs[0].Effect != "filled" {
		t.Fatalf("coordinator: %+v", hs)
	}
	noRefusals(t, s.C)
	noRefusals(t, s.B)
}

// An unanswered request is sent again on every connection with the same id; a
// signer that has it already, waiting for the operator, takes the duplicate
// with no effect and no security event; and it can still be answered.
// spec: SPO-Xparty-INV-017
func TestAWaitingRequestIsResentOnEveryConnection(t *testing.T) {
	s := newScene(t, sceneOpt{kind: ports.ViaNetwork, bobNode: true})
	s.connect()
	s.request()
	var sent [][]byte
	sent = append(sent, s.cb.Take()...)
	if h, _ := s.B.Signer().Handle(ctx, ports.NetworkReceived(sent[0])); h.Effect != "stored" {
		t.Fatal("not stored")
	}
	before := len(events(s.B))
	for i := range 3 {
		s.connect()
		if n := s.coordFlush(); n != 1 {
			t.Fatalf("connection %d: %d requests re-sent", i+2, n)
		}
		dup := s.cb.Take()
		if string(dup[0]) != string(sent[0]) {
			t.Fatal("not the same request")
		}
		h, err := s.B.Signer().Handle(ctx, ports.NetworkReceived(dup[0]))
		if err != nil || h.Refused || h.Effect != "duplicate" {
			t.Fatalf("duplicate = %+v, %v", h, err)
		}
	}
	if n := len(events(s.B)); n != before {
		t.Fatalf("duplicates of a waiting request wrote %d events", n-before)
	}
	if pend, _ := s.B.Signer().Pending(ctx); len(pend) != 1 {
		t.Fatalf("pending %d", len(pend))
	}
	s.bobApproves()
	s.bobFlush()
	if hs := s.coordHandles(); len(hs) != 1 || hs[0].Effect != "filled" {
		t.Fatalf("coordinator: %+v", hs)
	}
	noRefusals(t, s.B)
}

// Only a SigningRequest is re-sent: a CollectionClosed or an Invite is
// delivered by its write.
// spec: SPO-Xparty-INV-017
func TestOnlyRequestsAreRearmed(t *testing.T) {
	s := newScene(t, sceneOpt{kind: ports.ViaNetwork, bobNode: true})
	s.connect()
	s.request()
	s.bobHandles()
	if err := s.C.Coordinator().Close(ctx, s.ref, party.OutcomeDiscarded, [32]byte{}); err != nil {
		t.Fatal(err)
	}
	items, _ := s.C.Outbox().Pending(ctx)
	types := map[string]int{}
	for _, it := range items {
		types[it.Type]++
	}
	if types[string(party.TypeCollectionClosed)] != 1 {
		t.Fatalf("outbox %v", types)
	}
	s.coordFlush()
	s.cb.Take()
	if err := s.C.Outbox().Rearm(ctx); err != nil {
		t.Fatal(err)
	}
	if n := s.coordFlush(); n != 0 {
		t.Fatalf("%d envelopes sent again after Rearm: a closed announcement is sent once", n)
	}
}
