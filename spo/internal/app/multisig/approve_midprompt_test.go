package multisig_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/multiparty/partyrig"
)

// gateFunc is an approval gate that runs a callback while the operator is "at
// the prompt": after the claim, before the signature is stored.
type gateFunc func(ctx context.Context, key custody.KeyRef, hash [32]byte) error

func (g gateFunc) Reauthenticate(ctx context.Context, key custody.KeyRef, hash [32]byte) error {
	return g(ctx, key, hash)
}

// rawOutbox reads the outbox record as stored, without the checks Pending
// makes, so a test sees what an approval queued.
func rawOutbox(t *testing.T, w *partyrig.Workspace) []multisig.OutItem {
	t.Helper()
	var items []multisig.OutItem
	err := w.Store.View(ctx, func(r ports.Reader) error {
		b, err := r.Get(ports.Ref{Name: "all", Kind: ports.MultisigOutbox})
		if errors.Is(err, ports.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		return json.Unmarshal(b, &items)
	})
	if err != nil {
		t.Fatal(err)
	}
	return items
}

// responses is what bob has queued that answers a request.
func responses(t *testing.T, w *partyrig.Workspace) []multisig.OutItem {
	var out []multisig.OutItem
	for _, it := range rawOutbox(t, w) {
		if it.Type == string(party.TypeSigningResponse) || it.Type == string(party.TypeSigningRefusal) {
			out = append(out, it)
		}
	}
	return out
}

// midPrompt reviews bob's request and approves it with a gate that runs during
// the prompt, and returns Approve's error. Nothing may be answered.
func (s *scene) midPrompt(during func()) error {
	s.t.Helper()
	a := s.reviewed()
	sg := s.B.Signer()
	sg.Gate = gateFunc(func(context.Context, custody.KeyRef, [32]byte) error { during(); return nil })
	_, err := sg.Approve(ctx, a)
	return err
}

func (s *scene) nothingAnswered(err error) {
	s.t.Helper()
	if err == nil {
		s.t.Error("Approve succeeded although what it depended on changed while the operator was at the prompt")
	}
	if got := responses(s.t, s.B); len(got) != 0 {
		s.t.Errorf("a response was queued: %+v", got)
	}
	if !s.B.HasEvent("approval-dropped", "") {
		s.t.Errorf("no approval-dropped event: %v", events(s.B))
	}
}

// (a) This machine's own identity is rotated while the operator is at the
// passphrase prompt: the response, sealed with the keys loaded before the
// prompt, is dropped, not queued.
//
// spec: SPO-Xparty-INV-038, SPO-Xparty-INV-025
func TestApproveDropsTheAnswerWhenTheLocalIdentityIsRotatedAtThePrompt(t *testing.T) {
	s := newScene(t, sceneOpt{})
	err := s.midPrompt(func() { s.B.Rotate("") })
	s.nothingAnswered(err)
}

// (b) The coordinator's rotation is accepted at the prompt: its old identity is
// revoked and the envelopes for it dropped, so no response is queued to it.
//
// spec: SPO-Xparty-INV-038, SPO-Xparty-INV-033
func TestApproveDropsTheAnswerWhenTheCoordinatorIsRotatedAtThePrompt(t *testing.T) {
	s := newScene(t, sceneOpt{})
	err := s.midPrompt(func() {
		done := s.C.Rotate("")
		for _, it := range outboxOf(t, s.C) {
			if it.Type == string(party.TypeRotation) && it.To == hex.EncodeToString(s.B.Identity.Fingerprint[:]) {
				if h, err := s.B.Signer().Handle(ctx, partyrig.Received(it.Envelope, ports.ViaFile)); err != nil || h.Effect != "rotation-pending" {
					t.Fatalf("announcement: %+v, %v", h, err)
				}
			}
		}
		if _, err := s.B.Node().AcceptRotation(ctx, "coord", party.RotationAcceptance{Confirmation: done.New.String()[:19]}); err != nil {
			t.Fatal(err)
		}
	})
	s.nothingAnswered(err)
}

// (b') The coordinator is revoked at the prompt, which closes nothing: the
// recipient check alone drops the answer.
//
// spec: SPO-Xparty-INV-038, SPO-Xparty-INV-025
func TestApproveDropsTheAnswerWhenTheCoordinatorIsRevokedAtThePrompt(t *testing.T) {
	s := newScene(t, sceneOpt{})
	err := s.midPrompt(func() { s.B.Revoke("coord") })
	s.nothingAnswered(err)
	if !errors.Is(err, multisig.ErrReviewStale) {
		t.Errorf("err = %v", err)
	}
}

// (c) A CollectionClosed is handled at the prompt: the request is closed, so no
// response is queued.
//
// spec: SPO-Xparty-INV-038, SPO-Xparty-INV-036
func TestApproveDropsTheAnswerWhenTheCollectionIsClosedAtThePrompt(t *testing.T) {
	s := newScene(t, sceneOpt{})
	err := s.midPrompt(func() { s.closeAndDeliver(party.OutcomeDiscarded) })
	s.nothingAnswered(err)
	if !errors.Is(err, multisig.ErrRequestClosed) {
		t.Errorf("err = %v", err)
	}
}

// Backstop: the outbox never lists or hands to a transport an item whose
// recipient is not an active enrolled party or that was sealed by an identity
// other than this machine's current one; each such item is dropped with an
// event. A rotation announcement queued by enqueueRotation, sealed by the
// identity it replaces, is only checked for its recipient; an item that merely
// carries the type Rotation is not exempt.
//
// spec: SPO-Xparty-INV-038
func TestOutboxDropsWhatMustNotLeave(t *testing.T) {
	s := newScene(t, sceneOpt{})
	coord := hex.EncodeToString(s.C.Identity.Fingerprint[:])
	me := hex.EncodeToString(s.B.Identity.Fingerprint[:])
	stranger := hex.EncodeToString(make([]byte, 20))
	item := func(id, to, from, typ string) multisig.OutItem {
		return multisig.OutItem{ID: id + "00000000000000000000000000000000"[len(id):], To: to, From: from, Type: typ, Expires: s.clock.Now().Unix() + 600, Envelope: []byte(id)}
	}
	items := []multisig.OutItem{
		item("aa", coord, me, string(party.TypeSigningResponse)),       // fine
		item("bb", stranger, me, string(party.TypeSigningResponse)),    // recipient is nobody
		item("cc", coord, stranger, string(party.TypeSigningResponse)), // sealed by another identity
		item("dd", coord, "", string(party.TypeSigningResponse)),       // sealing identity unknown
		item("ee", coord, stranger, string(party.TypeRotation)),        // a rotation is sealed by the old identity ...
		item("ff", stranger, stranger, string(party.TypeRotation)),     // ... but still for an enrolled party
		item("gg", coord, stranger, string(party.TypeRotation)),        // a Rotation type alone is no exemption
	}
	items[4].Rotation, items[5].Rotation = true, true // as enqueueRotation marks them
	if err := s.B.Store.Update(ctx, func(w ports.Writer) error {
		b, _ := json.Marshal(items)
		return w.Put(ports.Ref{Name: "all", Kind: ports.MultisigOutbox}, b)
	}); err != nil {
		t.Fatal(err)
	}
	n, err := s.B.Outbox().Flush(ctx, s.bc.Transport())
	if err != nil || n != 2 {
		t.Fatalf("flushed %d, %v", n, err)
	}
	sent := s.bc.Take()
	if len(sent) != 2 || string(sent[0]) != "aa" || string(sent[1]) != "ee" {
		t.Fatalf("sent %q", sent)
	}
	dropped := 0
	for _, e := range s.B.Events() {
		if e.Kind == "outbox-item-dropped" {
			dropped++
		}
	}
	if dropped != 5 {
		t.Errorf("%d drop events: %v", dropped, events(s.B))
	}
	for _, it := range rawOutbox(t, s.B) {
		if it.ID[:2] == "bb" || it.ID[:2] == "cc" || it.ID[:2] == "dd" || it.ID[:2] == "ff" || it.ID[:2] == "gg" {
			t.Errorf("%s is still queued", it.ID[:2])
		}
	}
}
