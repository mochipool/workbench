package multisig_test

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/multiparty/partyrig"
)

// hookKit loads the real local identity and then runs a callback before it
// returns: the world changes between "keys loaded" and "transaction".
type hookKit struct {
	ports.IdentityKit
	after func()
}

func (k hookKit) Local(ctx context.Context) (ports.LocalIdentity, error) {
	l, err := k.IdentityKit.Local(ctx)
	if err == nil && k.after != nil {
		f := k.after
		k.after = nil
		f()
	}
	return l, err
}

// hooked is bob's signer whose first Kit.Local is followed by a rotation of
// bob's identity (done through his own, unhooked, node).
func hooked(s *scene) multisig.Signer {
	sg := s.B.Signer()
	once := false
	sg.Kit = hookKit{IdentityKit: sg.Kit, after: func() {
		if !once {
			once = true
			s.B.Rotate("")
		}
	}}
	return sg
}

// Refuse seals with the keys it loaded; when the identity is rotated before its
// transaction, the refusal is not stored or queued (the request was closed by the
// rotation, which Refuse also checks).
//
// spec: SPO-Xparty-INV-038
func TestRefuseAcrossARotationQueuesNothing(t *testing.T) {
	s := newScene(t, sceneOpt{})
	s.request()
	s.bobHandles()
	pend, _ := s.B.Signer().Pending(ctx)
	if len(pend) != 1 {
		t.Fatal(pend)
	}
	// the hook's Rotate runs while Local is loading, so the fixed Kit is reused
	// by the rotation: give the hook a clean node
	sg := hooked(s)
	_, err := sg.Refuse(ctx, pend[0].ID)
	if err == nil {
		t.Fatal("a refusal sealed by the replaced identity was accepted")
	}
	if got := responses(t, s.B); len(got) != 0 {
		t.Fatalf("queued %+v", got)
	}
}

// A closed request is not refused (as Approve does not approve it).
//
// spec: SPO-Xparty-INV-036, SPO-Xparty-INV-038
func TestRefuseRefusesAClosedRequest(t *testing.T) {
	s := newScene(t, sceneOpt{})
	s.request()
	s.bobHandles()
	pend, _ := s.B.Signer().Pending(ctx)
	s.closeAndDeliver(party.OutcomeDiscarded)
	if _, err := s.B.Signer().Refuse(ctx, pend[0].ID); !errors.Is(err, multisig.ErrRequestClosed) {
		t.Fatalf("refuse of a closed request: %v", err)
	}
	if got := responses(t, s.B); len(got) != 0 {
		t.Fatalf("queued %+v", got)
	}
}

// An answered request is answered again from the stored response when the
// coordinator re-sends it. When the identity is rotated between the signer's load
// of its keys and the transaction, the old identity's response is not queued.
//
// spec: SPO-Xparty-INV-017, SPO-Xparty-INV-038
func TestResendAcrossARotationQueuesNothing(t *testing.T) {
	s := newScene(t, sceneOpt{})
	s.request()
	var reqEnv []byte
	for _, env := range s.cb.Take() {
		reqEnv = env
	}
	if h, err := s.B.Signer().Handle(ctx, partyrig.Received(reqEnv, s.cb.Kind)); err != nil || h.Effect != "stored" {
		t.Fatalf("%+v %v", h, err)
	}
	s.bobApproves()
	s.bobFlush() // delivered: nothing undelivered waits
	_, err := hooked(s).Handle(ctx, partyrig.Received(reqEnv, s.cb.Kind))
	if !errors.Is(err, multisig.ErrIdentityChanged) {
		t.Fatalf("resend across a rotation: %v", err)
	}
	for _, it := range rawOutbox(t, s.B) {
		if it.Type == string(party.TypeSigningResponse) && !it.Delivered {
			t.Fatalf("the old identity's response was queued again: %+v", it)
		}
	}
}

// The only exemption from "sealed by this machine's current identity" is the
// rotation's own announcement, queued by enqueueRotation. The plain enqueue has
// none: an item typed Rotation that another identity sealed is refused like any
// other, and nothing is queued; enqueueRotation takes nothing but Rotation items.
//
// spec: SPO-Xparty-INV-038
func TestEnqueueHasNoRotationExemption(t *testing.T) {
	s := newScene(t, sceneOpt{})
	var stranger party.Fingerprint
	stranger[0] = 7
	coord := hex.EncodeToString(s.C.Identity.Fingerprint[:])
	item := func(typ string) multisig.OutItem {
		return multisig.OutItem{ID: "aa00000000000000000000000000000000", To: coord, Type: typ, Expires: s.clock.Now().Unix() + 600, Envelope: []byte("x")}
	}
	node := s.B.Signer().Node
	for _, typ := range []string{string(party.TypeRotation), string(party.TypeSigningResponse)} {
		err := node.Store.Update(ctx, func(w ports.NamedWriter) error {
			return node.EnqueueForTest(w, s.clock.Now(), stranger, item(typ))
		})
		if !errors.Is(err, multisig.ErrIdentityChanged) {
			t.Errorf("a %s item sealed by another identity: %v", typ, err)
		}
	}
	if len(rawOutbox(t, s.B)) != 0 {
		t.Error("an item was queued")
	}
	if msg := multisig.ErrIdentityChanged.Error(); !strings.Contains(msg, "identity changed while the answer was being prepared") || !strings.Contains(msg, "nothing was sent") {
		t.Errorf("the message does not fit a refused answer: %q", msg)
	}
	// A caller cannot set the announcement mark through the plain enqueue.
	cur := s.B.Identity.Fingerprint
	marked := item(string(party.TypeRotation))
	marked.Rotation = true
	if err := node.Store.Update(ctx, func(w ports.NamedWriter) error {
		return node.EnqueueForTest(w, s.clock.Now(), cur, marked)
	}); err != nil {
		t.Fatal(err)
	}
	if got := rawOutbox(t, s.B); len(got) != 1 || got[0].Rotation {
		t.Errorf("%+v", got)
	}
	// The rotation's own queueing takes only Rotation items, and marks them.
	if err := node.Store.Update(ctx, func(w ports.NamedWriter) error {
		return node.EnqueueRotationForTest(w, s.clock.Now(), stranger, item(string(party.TypeSigningResponse)))
	}); err == nil {
		t.Error("enqueueRotation took an item that is not a rotation announcement")
	}
}
