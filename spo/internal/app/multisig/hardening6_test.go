package multisig_test

import (
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// A duplicate request id is answered from the stored response only over the
// kind of transport the request first arrived on. A request that arrived by
// file and is replayed over a network gets nothing, so a stored response is
// never put on another transport by a duplicate; over the same kind it is
// answered again.
//
// spec: SPO-Xparty-INV-017, SPO-Xparty-INV-024
func TestDuplicateIsAnsweredOnlyOverTheKindItFirstArrivedOn(t *testing.T) {
	s := newScene(t, sceneOpt{})
	s.request()
	reqs := s.cb.Take()
	if len(reqs) != 1 {
		t.Fatalf("%d requests", len(reqs))
	}
	if h, err := s.B.Signer().Handle(ctx, ports.FileReceived(reqs[0])); err != nil || h.Effect != "stored" {
		t.Fatalf("first: %+v %v", h, err)
	}
	s.bobApproves()
	s.bobFlush()
	s.bc.Take()

	// The same envelope replayed over a network: no answer is queued.
	h, err := s.B.Signer().Handle(ctx, ports.NetworkReceived(reqs[0]))
	if err != nil || h.Effect != "duplicate" || h.Refused {
		t.Fatalf("over a network: %+v %v", h, err)
	}
	if items, _ := s.B.Outbox().Pending(ctx); len(items) != 0 {
		t.Fatalf("the stored response was queued for another transport: %+v", items)
	}
	// And the unknown kind is not the file either.
	if h, err := s.B.Signer().Handle(ctx, ports.Received{Envelope: reqs[0]}); err != nil || h.Effect != "duplicate" {
		t.Fatalf("unknown kind: %+v %v", h, err)
	}
	// Over a file it is answered again from the stored response.
	h, err = s.B.Signer().Handle(ctx, ports.FileReceived(reqs[0]))
	if err != nil || h.Effect != "response-resent" {
		t.Fatalf("over a file: %+v %v", h, err)
	}
	if items, _ := s.B.Outbox().Pending(ctx); len(items) != 1 || items[0].Type != string(party.TypeSigningResponse) {
		t.Fatalf("pending %+v", items)
	}
}
