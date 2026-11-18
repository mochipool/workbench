package multiparty

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/adapters/envelope"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/multiparty/partyrig"
)

// The attacks that need no network. Each is refused with its audit reason and
// leaves the collection as it was.

// requested opens the registration and sends bob's request into a pipe.
func requested(t *testing.T) (*world, *partyrig.Pipe, [][]byte) {
	t.Helper()
	w := newWorld(t, nil)
	w.open()
	pipe := partyrig.NewPipe(ports.ViaFile)
	if _, err := w.C.Coordinator().RequestSignatures(ctx, multisig.RequestInput{Ref: poolRef, Purpose: "register mypool"}, pipe.Transport()); err != nil {
		t.Fatal(err)
	}
	return w, pipe, pipe.Take()
}

func slotIndex(t *testing.T, w *world, name string) int {
	t.Helper()
	for i, s := range w.collection().Slots {
		if s.Name == name {
			return i
		}
	}
	t.Fatalf("no slot %s", name)
	return -1
}

func refused(t *testing.T, h multisig.Handled, err error, reason string) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if !h.Refused || !strings.Contains(h.Reason, reason) {
		t.Fatalf("handled = %+v, want a refusal with %q", h, reason)
	}
	if h.Outward() != nil {
		t.Error("something goes back to the sender")
	}
}

// bobAnswers makes bob review and approve what is in his inbox, returning the
// response envelope.
func bobAnswers(t *testing.T, w *world, reqs [][]byte, via ports.TransportKind) (multisig.Signer, []byte) {
	t.Helper()
	bob := w.bobSigner()
	for _, r := range reqs {
		if h, err := bob.Handle(ctx, partyrig.Received(r, via)); err != nil || h.Refused || h.Effect != "stored" {
			t.Fatalf("bob = %+v, %v", h, err)
		}
	}
	w.reviewAndApprove(bob)
	out := partyrig.NewPipe(via)
	if _, err := w.B.Outbox().Flush(ctx, out.Transport()); err != nil {
		t.Fatal(err)
	}
	got := out.Take()
	if len(got) != 1 {
		t.Fatalf("%d responses", len(got))
	}
	return bob, got[0]
}

// A remote answer made by another key than the one demanded is refused: the slot
// names the key identity it needs, and the answer is verified against it.
//
// spec: SPO-Xparty-INV-010, SPO-Xparty-PRE-002, SPO-Xparty-PRE-005, SPO-Xidentity-SEC-005
func TestAttackResponseFromAnEnrolledPartyThatIsNotTheSlotsSigner(t *testing.T) {
	w, _, _ := requested(t)
	x := partyrig.New(t, "xavier", w.clock, w.chain.Chain)
	x.AddKey(custody.RoleStake, "xavier")
	w.C.Enroll(x, "xavier", []party.Role{party.RoleSigner}, []string{w.bech})
	x.Enroll(w.C, "coordinator", []party.Role{party.RoleCoordinator}, []string{w.bech})
	before := w.snapshot()
	c := w.collection()
	wit := x.SignID(custody.RoleStake, "xavier", c.Body.ID)
	env := partyrig.Seal(t, x, w.C, party.SigningResponse{Collection: multisig.CollectionID(poolRef, c), Slot: party.SlotID(slotIndex(t, w, "bob.staking")),
		Request: party.MessageID{1}, Witness: party.EncodeWitness(wit.VKey, wit.Signature)}, time.Hour)
	h, err := w.C.Coordinator().Handle(ctx, ports.FileReceived(env))
	refused(t, h, err, party.ErrNotAuthorised.Error())
	if w.snapshot() != before {
		t.Error("the collection changed")
	}
	if !w.C.HasEvent("envelope-refused", party.ErrNotAuthorised.Error()) {
		t.Errorf("no audit event: %v", w.C.Events())
	}
}

// A response arriving again is the answer the coordinator already accepted
// (the signer answers a re-sent request with its stored response): it is
// acknowledged, changes nothing and leaves no security event. A replay of
// anything else is refused: the same response id with another slot named is.
// spec: SPO-Xparty-INV-007, SPO-Xparty-PRE-002, SPO-Xparty-INV-017
func TestAttackReplayedResponse(t *testing.T) {
	w, _, reqs := requested(t)
	_, resp := bobAnswers(t, w, reqs, ports.ViaFile)
	coord := w.C.Coordinator()
	if h, err := coord.Handle(ctx, ports.FileReceived(resp)); err != nil || h.Effect != "filled" {
		t.Fatalf("first = %+v, %v", h, err)
	}
	after, events := w.snapshot(), len(w.C.Events())
	h, err := coord.Handle(ctx, ports.FileReceived(resp))
	if err != nil || h.Refused || h.Effect != "acknowledged" {
		t.Fatalf("the accepted answer again = %+v, %v", h, err)
	}
	if w.snapshot() != after || len(w.C.Events()) != events {
		t.Error("the duplicate changed the collection or wrote an event")
	}
}

// spec: SPO-Xparty-INV-020, SPO-Xparty-PRE-006
func TestAttackRequestWhoseBodyHashDoesNotMatchItsBody(t *testing.T) {
	w, _, _ := requested(t)
	before := w.snapshot()
	c := w.collection()
	body, _ := native.TxViewer{}.BodyOf(c.Body.CBOR)
	bad := blake2b.Sum256([]byte("another body"))
	env := partyrig.Seal(t, w.C, w.B, party.SigningRequest{Collection: multisig.CollectionID(poolRef, c), Slot: party.SlotID(slotIndex(t, w, "bob.staking")),
		KeyRole: custody.RoleStake, KeyHash: [28]byte(w.bobHash), Operation: "witness-transaction", TxBody: body, BodyHash: bad, TTLSlot: c.TTL,
		NetworkMagic: partyrig.Magic, Purpose: "register"}, 5*time.Minute)
	bob := w.bobSigner()
	h, err := bob.Handle(ctx, ports.FileReceived(env))
	if err != nil || h.Refused || h.Effect != "refused" || h.Reason != party.RefuseBodyHash.String() {
		t.Fatalf("bob = %+v, %v", h, err)
	}
	if !w.B.HasEvent("request-refused", party.RefuseBodyHash.String()) {
		t.Errorf("no audit event: %v", w.B.Events())
	}
	if pend, _ := bob.Pending(ctx); len(pend) != 0 {
		t.Error("the request waits for a decision")
	}
	// His refusal reaches the coordinator, which records nothing against the
	// slot for a request it never sent.
	back := partyrig.NewPipe(ports.ViaFile)
	w.B.Outbox().Flush(ctx, back.Transport())
	for _, r := range back.Take() {
		h, err := w.C.Coordinator().Handle(ctx, ports.FileReceived(r))
		refused(t, h, err, party.ErrStaleRequest.Error())
	}
	if w.snapshot() != before {
		t.Error("the collection changed")
	}
}

// spec: SPO-Xparty-OUT-002, SPO-Xparty-PRE-002, SPO-Xparty-INV-006
func TestAttackTamperedEnvelope(t *testing.T) {
	w, _, reqs := requested(t)
	before := w.snapshot()
	bad := append([]byte(nil), reqs[0]...)
	bad[len(bad)-20] ^= 0x40
	bob := w.bobSigner()
	h, err := bob.Handle(ctx, ports.FileReceived(bad))
	refused(t, h, err, envelope.ErrDecrypt.Error())
	if h.HasSender {
		t.Error("a sender is recorded for an envelope that did not decrypt")
	}
	if pend, _ := bob.Pending(ctx); len(pend) != 0 {
		t.Error("a tampered request is waiting")
	}
	// And a tampered response at the coordinator.
	_, resp := bobAnswers(t, w, reqs, ports.ViaFile)
	bad = append([]byte(nil), resp...)
	bad[len(bad)/2] ^= 1
	h, err = w.C.Coordinator().Handle(ctx, ports.FileReceived(bad))
	refused(t, h, err, envelope.ErrDecrypt.Error())
	if w.snapshot() != before {
		t.Error("the collection changed")
	}
}

// spec: SPO-Xparty-OUT-003, SPO-Xparty-PRE-002, SPO-Xparty-INV-009
func TestAttackExpiredRequest(t *testing.T) {
	w, _, reqs := requested(t)
	before := w.snapshot()
	w.clock.Advance(30 * time.Hour) // the request lives as long as the TTL slot does: 100000 slots, under 28 hours
	bob := w.bobSigner()
	h, err := bob.Handle(ctx, ports.FileReceived(reqs[0]))
	refused(t, h, err, party.ErrExpired.Error())
	if w.snapshot() != before {
		t.Error("the collection changed")
	}
	if !w.B.HasEvent("envelope-refused", party.ErrExpired.Error()) {
		t.Errorf("no audit event")
	}
}

// spec: SPO-Xparty-INV-005, SPO-Xparty-IF-003
func TestAttackRevokedParty(t *testing.T) {
	w, _, reqs := requested(t)
	_, resp := bobAnswers(t, w, reqs, ports.ViaFile)
	w.C.Revoke("bobparty") // after bob answered, before the answer is imported
	after := w.snapshot()
	h, err := w.C.Coordinator().Handle(ctx, ports.FileReceived(resp))
	refused(t, h, err, envelope.ErrSenderRevoked.Error())
	if h.HasSender {
		t.Error("a revoked sender's fingerprint is a claim, not an authenticated sender: it is not recorded")
	}
	if w.snapshot() != after {
		t.Error("the collection changed")
	}
	if s, _ := w.collection().Slot("bob.staking"); s.Filled() || s.Assigned() {
		t.Errorf("the slot of the revoked party is %+v: want empty and unassigned", s)
	}
	// And it is not requested again.
	res, err := w.C.Coordinator().RequestSignatures(ctx, multisig.RequestInput{Ref: poolRef}, partyrig.NewPipe(ports.ViaFile).Transport())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		if r.Name == "bob.staking" && (r.Status != multisig.SlotRefused || !strings.Contains(r.Err.Error(), "no party")) {
			t.Errorf("bob's slot: %+v", r)
		}
	}
}

type counting struct {
	native.VaultSigner
	n *atomic.Int32
}

func (c counting) Witness(ctx context.Context, k custody.KeyRef, b txbuild.TxBody) (txbuild.Witness, error) {
	c.n.Add(1)
	return c.VaultSigner.Witness(ctx, k, b)
}

type countingDir struct{ s counting }

func (d countingDir) SignerFor(custody.KeyRef) (ports.Signer, error) { return d.s, nil }

// Connected implements ports.SignerDirectory.
func (d countingDir) Connected(k custody.KeyRef) ([]ports.ConnectedSigner, error) {
	return ports.ConnectedVia(d, k)
}

// A signer asked to sign a body with a key of the map it cannot decode refuses
// and never touches its key.
// spec: SPO-Xparty-PRE-006, SPO-Xparty-PR-002
func TestAttackBodyWithAnUnknownCBORKey(t *testing.T) {
	w, _, _ := requested(t)
	before := w.snapshot()
	c := w.collection()
	body, _ := native.TxViewer{}.BodyOf(c.Body.CBOR)
	// A key the signer has no way to display: 99, a value of one byte.
	evil := append([]byte{body[0] + 1}, body[1:]...)
	evil = append(evil, 0x18, 99, 0x01)
	env := partyrig.Seal(t, w.C, w.B, party.SigningRequest{Collection: multisig.CollectionID(poolRef, c), Slot: party.SlotID(slotIndex(t, w, "bob.staking")),
		KeyRole: custody.RoleStake, KeyHash: [28]byte(w.bobHash), Operation: "witness-transaction", TxBody: evil, BodyHash: blake2b.Sum256(evil), TTLSlot: c.TTL,
		NetworkMagic: partyrig.Magic, Purpose: "register"}, 5*time.Minute)
	var n atomic.Int32
	bob := w.bobSigner()
	bob.Signers = countingDir{counting{native.VaultSigner{Vault: w.B.Store.Anchor()}, &n}}
	h, err := bob.Handle(ctx, ports.FileReceived(env))
	if err != nil || h.Refused || h.Effect != "refused" || h.Reason != party.RefuseBodyDecode.String() {
		t.Fatalf("bob = %+v, %v", h, err)
	}
	if !w.B.HasEvent("request-refused", party.RefuseBodyDecode.String()) {
		t.Errorf("no audit event: %v", w.B.Events())
	}
	if pend, _ := bob.Pending(ctx); len(pend) != 0 || n.Load() != 0 {
		t.Errorf("pending %d, signer calls %d", len(pend), n.Load())
	}
	if w.snapshot() != before {
		t.Error("the collection changed")
	}
}
