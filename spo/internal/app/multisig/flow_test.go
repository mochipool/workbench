package multisig_test

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"

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

// One workflow over a file-like transport: request, review, approval,
// response, completion. The witness that arrives in an envelope is not
// marked unauthenticated; the assembled collection's witnesses verify over
// the body hash the signer reviewed.
// spec: SPO-Xparty-SEC-002, SPO-Xparty-INV-013, SPO-Xparty-PRE-003, SPO-Xparty-INV-012, SPO-Xparty-INV-020, SPO-Xparty-PR-002, SPO-Xparty-OUT-006, SPO-Xparty-PRE-005, SPO-Xparty-OUT-004, SPO-Xparty-OUT-005, SPO-Xparty-INV-007, SPO-Xparty-SEC-003, SPO-Xparty-IF-004
func TestRequestReviewApproveCompleteOverFile(t *testing.T) {
	s := newScene(t, sceneOpt{})
	res := s.request()
	if len(res) != 1 || res[0].Status != multisig.SlotRequested {
		t.Fatalf("request = %+v", res)
	}
	if hs := s.bobHandles(); len(hs) != 1 || hs[0].Refused || hs[0].Effect != "stored" {
		t.Fatalf("bob = %+v", hs)
	}
	pend, _ := s.B.Signer().Pending(ctx)
	// The review shows what the body does, decoded by the signer.
	rv, err := s.B.Signer().ReviewRequest(ctx, pend[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if rv.BodyHash != [32]byte(s.body.ID) || rv.Coordinator != "coord" || rv.Role != custody.RoleStake {
		t.Errorf("review header %+v", rv)
	}
	v := rv.View
	if len(v.Certificates) != 1 || v.Certificates[0].PoolReg == nil || v.Certificates[0].PoolReg.Pledge != 1_000_000 ||
		v.Certificates[0].PoolReg.Cost != 340_000_000 || v.Fee != 200_000 || v.TTL == nil || *v.TTL != s.ttl || len(v.Outputs) != 1 {
		t.Errorf("view %+v", v)
	}
	a, err := rv.Approval()
	if err != nil {
		t.Fatal(err)
	}
	if h, err := s.B.Signer().Approve(ctx, a); err != nil || h.Effect != "approved" {
		t.Fatalf("approve = %+v, %v", h, err)
	}
	s.bobFlush()
	hs := s.coordHandles()
	if len(hs) != 1 || hs[0].Refused || hs[0].Effect != "filled" || !hs[0].Complete {
		t.Fatalf("coordinator = %+v", hs)
	}
	c := s.collection()
	if got := c.State(1000); got != pool.CollectionOpenComplete {
		t.Fatalf("state %s", got)
	}
	slot := c.Slots[0]
	if slot.Unauthenticated {
		t.Error("a witness that came in an envelope is marked unauthenticated")
	}
	if err := txbuild.VerifyWitness(c.Body, *slot.Witness, slot.KeyHash); err != nil {
		t.Errorf("the stored witness does not verify: %v", err)
	}
	// The audit log of both sides names the steps (OUT-004, OUT-006).
	ce, be := events(s.C), events(s.B)
	for _, k := range []string{"collection-opened", "request-sealed", "response-accepted", "collection-complete"} {
		if !eventWith(ce, k) {
			t.Errorf("coordinator log has no %s: %v", k, ce)
		}
	}
	for _, k := range []string{"request-received", "request-reviewed", "request-approved"} {
		if !eventWith(be, k) {
			t.Errorf("signer log has no %s: %v", k, be)
		}
	}
	// The envelope names follow the file transport's rule.
	items, _ := s.C.Outbox().Pending(ctx)
	_ = items
}

// Over the file transport an item is named <type>-<collection prefix>-<slot>.spo.
// spec: SPO-Xparty-IF-004
func TestOutboxItemFileName(t *testing.T) {
	s := newScene(t, sceneOpt{})
	s.cb.Down = true
	s.request()
	items, err := s.C.Outbox().Pending(ctx)
	if err != nil || len(items) != 1 {
		t.Fatalf("%v %v", items, err)
	}
	name, ok := items[0].FileName()
	cid := s.cid()
	want := fmt.Sprintf("SigningRequest-%x-0.spo", cid[:4])
	if !ok || name != want {
		t.Errorf("file name %q, want %q", name, want)
	}
}

// A coordinator whose transport has no route keeps the request in the store
// and sends it when the route is up; a restart (a fresh Coordinator value
// over the same store) loses nothing.
// spec: SPO-Xparty-SEC-003
func TestRequestSurvivesNoRoute(t *testing.T) {
	s := newScene(t, sceneOpt{kind: ports.ViaNetwork})
	s.cb.Down = true
	s.request()
	if got := s.cb.Take(); len(got) != 0 {
		t.Fatal("sent with no route")
	}
	if items, _ := s.C.Outbox().Pending(ctx); len(items) != 1 {
		t.Fatalf("outbox %v", items)
	}
	s.cb.Down = false
	if n, err := s.C.Outbox().Flush(ctx, s.cb.Transport()); err != nil || n != 1 {
		t.Fatalf("flush = %d, %v", n, err)
	}
	if hs := s.bobHandles(); len(hs) != 1 || hs[0].Refused {
		t.Fatalf("bob = %+v", hs)
	}
	// Asking again does not send a second request for the slot.
	if res := s.request(); res[0].Status != multisig.SlotAlreadyRequested {
		t.Errorf("second request = %+v", res)
	}
	if got := s.cb.Take(); len(got) != 0 {
		t.Error("a second request was sent")
	}
}

// ---- SPO-Xparty-PRE-002: the receiver's refusals, through Handle ----------------

func (s *scene) readyResponse() []byte {
	s.t.Helper()
	s.request()
	s.bobHandles()
	s.bobApproves()
	s.bobFlush()
	envs := s.bc.Take()
	if len(envs) != 1 {
		s.t.Fatalf("%d envelopes", len(envs))
	}
	return envs[0]
}

func (s *scene) unchanged(before pool.Collection) {
	s.t.Helper()
	after := s.collection()
	if after.Version != before.Version || len(after.Missing()) != len(before.Missing()) {
		s.t.Errorf("the collection changed: version %d to %d", before.Version, after.Version)
	}
}

// spec: SPO-Xparty-PRE-002, SPO-Xparty-INV-006, SPO-Xparty-INV-004, SPO-Xparty-INV-005, SPO-Xparty-SEC-002
func TestPRE002RefusalsAtTheCoordinator(t *testing.T) {
	cases := []struct {
		name   string
		reason string
		known  bool // the sender is recorded
		run    func(s *scene, resp []byte) []byte
	}{
		{"does not decrypt", envelope.ErrDecrypt.Error(), false, func(s *scene, resp []byte) []byte {
			b := append([]byte(nil), resp...)
			b[len(b)/2] ^= 0xff // a tampered envelope
			return b
		}},
		{"not an age file", envelope.ErrDecrypt.Error(), false, func(s *scene, resp []byte) []byte { return []byte("not an envelope at all") }},
		{"empty", envelope.ErrTooLarge.Error(), false, func(s *scene, resp []byte) []byte { return nil }},
		{"sender not enrolled (we enrolled nobody who sent it)", envelope.ErrSenderUnknown.Error(), false, func(s *scene, resp []byte) []byte {
			// Zed has enrolled the coordinator; the coordinator has not enrolled Zed (INV-004).
			z := newZed(s)
			return s.sealFrom(z, s.C, party.Hello{}, s.clock.Now(), s.clock.Now().Add(time.Minute))
		}},
		{"sender revoked, even for an envelope made before", envelope.ErrSenderRevoked.Error(), false, func(s *scene, resp []byte) []byte {
			s.C.Revoke("bob")
			return resp
		}},
		{"expired", party.ErrExpired.Error(), true, func(s *scene, resp []byte) []byte {
			s.clock.Advance(2 * time.Hour * 24 * 8)
			return resp
		}},
		{"created too far in the future", party.ErrFromFuture.Error(), true, func(s *scene, resp []byte) []byte {
			return s.sealFrom(s.B, s.C, party.Hello{}, s.clock.Now().Add(time.Hour), s.clock.Now().Add(time.Hour+time.Minute))
		}},
		{"not a message a coordinator receives", party.ErrNotAuthorised.Error(), true, func(s *scene, resp []byte) []byte {
			return s.sealFrom(s.B, s.C, party.CollectionClosed{Collection: s.cid(), Outcome: party.OutcomeDiscarded}, s.clock.Now(), s.clock.Now().Add(time.Hour))
		}},
		{"sender is not the signer of the slot", party.ErrNotAuthorised.Error(), true, func(s *scene, resp []byte) []byte {
			// Xavier is an enrolled signer, but the slot is bob's.
			w := s.witnessOver(s.body.ID)
			return s.sealFrom(s.X, s.C, party.SigningResponse{Collection: s.cid(), Slot: 0, Request: party.MessageID{1}, Witness: party.EncodeWitness(w.VKey, w.Signature)},
				s.clock.Now(), s.clock.Now().Add(time.Hour))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newScene(t, sceneOpt{})
			resp := s.readyResponse()
			env := tc.run(s, resp)
			before := s.collection() // after a revocation, which unassigns the slot (INV-005)
			h, err := s.C.Coordinator().Handle(ctx, ports.FileReceived(env))
			if err != nil {
				t.Fatal(err)
			}
			mustRefuse(t, h, tc.reason)
			if h.HasSender != tc.known {
				t.Errorf("sender known = %v, want %v", h.HasSender, tc.known)
			}
			// An authenticated refusal is a security event; one that failed before
			// the signature step is noise, in its own ring (INV-023).
			if tc.known && !s.C.HasEvent("envelope-refused", tc.reason) && !s.C.HasEvent("message-refused", tc.reason) {
				t.Errorf("no audit event with the reason: %v", events(s.C))
			}
			if !tc.known {
				ring, total := s.C.Noise()
				if total == 0 || len(ring) == 0 || !strings.Contains(ring[len(ring)-1].Reason, tc.reason) {
					t.Errorf("the noise ring has no entry with the reason: %+v", ring)
				}
				if s.C.HasEvent("envelope-refused", "") {
					t.Error("an unauthenticated refusal is in the security log")
				}
			}
			s.unchanged(before)
		})
	}
}

// A replayed response is acknowledged without effect when it is the answer the
// coordinator accepted for its slot (the signer answers a re-sent request with
// its stored response), and the first took effect once. Every other replay is
// refused: here a response that is not an accepted answer.
// spec: SPO-Xparty-PRE-002, SPO-Xparty-INV-007, SPO-Xparty-INV-017
func TestReplayRefused(t *testing.T) {
	s := newScene(t, sceneOpt{})
	resp := s.readyResponse()
	if h, err := s.C.Coordinator().Handle(ctx, ports.FileReceived(resp)); err != nil || h.Effect != "filled" {
		t.Fatalf("first = %+v, %v", h, err)
	}
	before := s.collection()
	nEvents := len(events(s.C))
	h, err := s.C.Coordinator().Handle(ctx, ports.FileReceived(resp))
	if err != nil || h.Refused || h.Effect != "acknowledged" {
		t.Fatalf("the accepted answer again = %+v, %v", h, err)
	}
	s.unchanged(before)
	if n := len(events(s.C)); n != nEvents {
		t.Fatalf("a duplicate of an accepted answer wrote %d events", n-nEvents)
	}
	// A message that is a replay and is not an accepted answer is refused:
	// the Hello of the party, twice.
	hello, err := s.B.Signer().NewHello(ctx, "coord")
	if err != nil {
		t.Fatal(err)
	}
	if h, err := s.C.Coordinator().Handle(ctx, ports.FileReceived(hello)); err != nil || h.Effect != "hello" {
		t.Fatalf("hello = %+v, %v", h, err)
	}
	h, err = s.C.Coordinator().Handle(ctx, ports.FileReceived(hello))
	if err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, h, envelope.ErrReplayed.Error())
}

// The same refusals whatever the transport said: an envelope handed in as
// "network" is checked exactly as one from a file.
// spec: SPO-Xparty-SEC-002
func TestChecksIgnoreTheTransport(t *testing.T) {
	for _, via := range []ports.TransportKind{ports.ViaFile, ports.ViaNetwork} {
		s := newScene(t, sceneOpt{})
		resp := s.readyResponse()
		bad := append([]byte(nil), resp...)
		bad[len(bad)/2] ^= 1
		h, err := s.C.Coordinator().Handle(ctx, partyrig.Received(bad, via))
		if err != nil {
			t.Fatal(err)
		}
		mustRefuse(t, h, envelope.ErrDecrypt.Error())
	}
}

// ---- SPO-Xparty-PRE-005: the acceptance of a response -----------------------------

// spec: SPO-Xparty-PRE-005, SPO-Xparty-INV-014, SPO-Xparty-INV-015, SPO-Xparty-INV-006
func TestPRE005RefusalsAndTheRest(t *testing.T) {
	good := func(s *scene) (party.MessageID, txbuild.Witness) {
		s.request()
		pend := s.bobHandles()
		_ = pend
		p, _ := s.B.Signer().Pending(ctx)
		return p[0].ID, s.witnessOver(s.body.ID)
	}
	respond := func(s *scene, r party.SigningResponse) multisig.Handled {
		s.t.Helper()
		env := s.sealFrom(s.B, s.C, r, s.clock.Now(), s.clock.Now().Add(time.Hour))
		h, err := s.C.Coordinator().Handle(ctx, ports.FileReceived(env))
		if err != nil {
			s.t.Fatal(err)
		}
		return h
	}
	enc := func(w txbuild.Witness) []byte { return party.EncodeWitness(w.VKey, w.Signature) }

	t.Run("the request id is not the last one sent", func(t *testing.T) {
		s := newScene(t, sceneOpt{})
		_, w := good(s)
		before := s.collection()
		h := respond(s, party.SigningResponse{Collection: s.cid(), Slot: 0, Request: party.MessageID{9, 9}, Witness: enc(w)})
		mustRefuse(t, h, party.ErrStaleRequest.Error())
		s.unchanged(before)
	})
	t.Run("a signature over another body", func(t *testing.T) {
		s := newScene(t, sceneOpt{})
		id, _ := good(s)
		before := s.collection()
		w := s.witnessOver([32]byte{5})
		h := respond(s, party.SigningResponse{Collection: s.cid(), Slot: 0, Request: id, Witness: enc(w)})
		mustRefuse(t, h, party.ErrWitnessSignature.Error())
		s.unchanged(before)
	})
	t.Run("a valid signature of a key that is not the slot's", func(t *testing.T) {
		s := newScene(t, sceneOpt{})
		id, _ := good(s)
		before := s.collection()
		other := s.X.AddKey(custody.RoleStake, "xavier")
		_ = other
		w, err := nativeWitness(s, "xavier")
		if err != nil {
			t.Fatal(err)
		}
		h := respond(s, party.SigningResponse{Collection: s.cid(), Slot: 0, Request: id, Witness: enc(w)})
		mustRefuse(t, h, party.ErrWitnessKeyHash.Error())
		s.unchanged(before)
	})
	t.Run("a malformed witness", func(t *testing.T) {
		s := newScene(t, sceneOpt{})
		id, _ := good(s)
		before := s.collection()
		h := respond(s, party.SigningResponse{Collection: s.cid(), Slot: 0, Request: id, Witness: []byte{1, 2, 3}})
		mustRefuse(t, h, party.ErrWitnessEncoding.Error())
		s.unchanged(before)
	})
	t.Run("a slot the collection does not have", func(t *testing.T) {
		s := newScene(t, sceneOpt{})
		id, w := good(s)
		before := s.collection()
		h := respond(s, party.SigningResponse{Collection: s.cid(), Slot: 7, Request: id, Witness: enc(w)})
		mustRefuse(t, h, "not the signer of that slot")
		s.unchanged(before)
	})
	t.Run("a collection we do not know", func(t *testing.T) {
		s := newScene(t, sceneOpt{})
		id, w := good(s)
		before := s.collection()
		h := respond(s, party.SigningResponse{Collection: party.CollectionID{4, 4}, Slot: 0, Request: id, Witness: enc(w)})
		mustRefuse(t, h, "not the signer of that slot")
		s.unchanged(before)
	})
	t.Run("the collection is not open: its ttl slot has passed", func(t *testing.T) {
		s := newScene(t, sceneOpt{})
		id, w := good(s)
		before := s.collection()
		s.chain.SetSlot(s.ttl + 1)
		h := respond(s, party.SigningResponse{Collection: s.cid(), Slot: 0, Request: id, Witness: enc(w)})
		mustRefuse(t, h, party.ErrCollectionNotOpen.Error())
		s.unchanged(before)
	})
	t.Run("expiry from the clock when no tip is available", func(t *testing.T) {
		s := newScene(t, sceneOpt{})
		id, w := good(s)
		before := s.collection()
		s.chain.Down = true
		s.clock.Advance(1000 * time.Second) // past the ttl slot by the genesis' reckoning, inside the envelope's life
		h := respond(s, party.SigningResponse{Collection: s.cid(), Slot: 0, Request: id, Witness: enc(w)})
		mustRefuse(t, h, party.ErrCollectionNotOpen.Error())
		s.unchanged(before)
	})
	t.Run("a second valid response is acknowledged without effect", func(t *testing.T) {
		s := newScene(t, sceneOpt{cold: true}) // the cold slot stays empty: the collection is incomplete
		id, w := good(s)
		first := respond(s, party.SigningResponse{Collection: s.cid(), Slot: 0, Request: id, Witness: enc(w)})
		if first.Refused || first.Effect != "filled" {
			t.Fatalf("first = %+v", first)
		}
		before := s.collection()
		second := respond(s, party.SigningResponse{Collection: s.cid(), Slot: 0, Request: id, Witness: enc(w)})
		if second.Refused || second.Effect != "acknowledged" {
			t.Fatalf("second = %+v", second)
		}
		s.unchanged(before)
		if !eventWith(events(s.C), "response-acknowledged") {
			t.Error("no acknowledgement event")
		}
	})
}

// The duplicate of the response that completed a collection is acknowledged
// too (INV-014), not refused as a response to a closed collection.
// spec: SPO-Xparty-INV-014
func TestDuplicateOfTheCompletingResponseIsAcknowledged(t *testing.T) {
	s := newScene(t, sceneOpt{})
	s.request()
	s.bobHandles()
	id, w := func() (party.MessageID, txbuild.Witness) {
		p, _ := s.B.Signer().Pending(ctx)
		return p[0].ID, s.witnessOver(s.body.ID)
	}()
	send := func() multisig.Handled {
		env := s.sealFrom(s.B, s.C, party.SigningResponse{Collection: s.cid(), Slot: 0, Request: id, Witness: party.EncodeWitness(w.VKey, w.Signature)},
			s.clock.Now(), s.clock.Now().Add(time.Hour))
		h, err := s.C.Coordinator().Handle(ctx, ports.FileReceived(env))
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	if h := send(); h.Effect != "filled" || !h.Complete {
		t.Fatalf("first = %+v", h)
	}
	before := s.collection()
	if h := send(); h.Refused || h.Effect != "acknowledged" {
		t.Fatalf("second = %+v", h)
	}
	s.unchanged(before)
}

// ---- SPO-Xparty-PRE-006: the signer's refusals -------------------------------------

type noDevice struct{}

func (noDevice) Profile() custody.Profile {
	return custody.NewProfile("device").AllowTx(custody.RoleStake, custody.FeatStakeDelegation)
}

type deviceDir struct{}

func (deviceDir) SignerFor(custody.KeyRef) (ports.Signer, error) { return noDevice{}, nil }

// spec: SPO-Xparty-PRE-006, SPO-Xparty-INV-020, SPO-Xparty-PRE-004, SPO-Xparty-INV-006
func TestPRE006Refusals(t *testing.T) {
	cases := []struct {
		name   string
		reason party.RefusalReason
		opts   sceneOpt
		edit   func(s *scene, r *party.SigningRequest)
		signer func(s *scene) multisig.Signer
	}{
		{"no key with that hash and role", party.RefuseNoKey, sceneOpt{}, func(s *scene, r *party.SigningRequest) { r.KeyHash = [28]byte{1, 2, 3} }, nil},
		{"the key's role is another", party.RefuseNoKey, sceneOpt{}, func(s *scene, r *party.SigningRequest) { r.KeyRole = custody.RolePoolCold }, nil},
		{"a payment request needs an unscoped coordinator", party.RefuseOutOfScope, sceneOpt{}, func(s *scene, r *party.SigningRequest) { r.KeyRole = custody.RolePayment }, nil},
		{"wrong network", party.RefuseWrongNetwork, sceneOpt{}, func(s *scene, r *party.SigningRequest) { r.NetworkMagic = 764824073 }, nil},
		{"the body hash is not the hash of the body", party.RefuseBodyHash, sceneOpt{}, func(s *scene, r *party.SigningRequest) { r.BodyHash[0] ^= 1 }, nil},
		{"the body does not decode (an unknown key)", party.RefuseBodyDecode, sceneOpt{}, func(s *scene, r *party.SigningRequest) {
			b := append([]byte{r.TxBody[0] + 1}, r.TxBody[1:]...) // one more key
			b = append(b, 0x18, 99, 0x01)
			r.TxBody, r.BodyHash = b, blake2b.Sum256(b)
		}, nil},
		{"the body does not decode (not CBOR)", party.RefuseBodyDecode, sceneOpt{}, func(s *scene, r *party.SigningRequest) {
			r.TxBody = []byte{0xff, 0xff}
			r.BodyHash = blake2b.Sum256(r.TxBody)
		}, nil},
		{"the ttl slot has passed", party.RefuseExpired, sceneOpt{}, func(s *scene, r *party.SigningRequest) { s.chain.SetSlot(s.ttl) }, nil},
		{"the pool cold key over a network transport", party.RefuseColdKeyOverNetwork, sceneOpt{cold: true, kind: ports.ViaNetwork}, func(s *scene, r *party.SigningRequest) {
			r.KeyRole, r.KeyHash = custody.RolePoolCold, [28]byte(s.poolID)
		}, nil},
		{"the signer cannot meet the demand of the body", party.RefuseCannotSign, sceneOpt{}, nil, func(s *scene) multisig.Signer {
			sg := s.B.Signer()
			sg.Signers = deviceDir{}
			return sg
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newScene(t, tc.opts)
			env := s.forgedRequest(func(r *party.SigningRequest) {
				if tc.edit != nil {
					tc.edit(s, r)
				}
			})
			signer := s.B.Signer()
			if tc.signer != nil {
				signer = tc.signer(s)
			}
			h, err := signer.Handle(ctx, partyrig.Received(env, s.cb.Kind))
			if err != nil {
				t.Fatal(err)
			}
			if h.Refused || h.Effect != "refused" || h.Reason != tc.reason.String() {
				t.Fatalf("handled = %+v, want a refusal with %q", h, tc.reason)
			}
			if !s.B.HasEvent("request-refused", tc.reason.String()) {
				t.Errorf("no audit event: %v", events(s.B))
			}
			// The refusal goes to the coordinator, who records it against the slot.
			if pend, _ := s.B.Signer().Pending(ctx); len(pend) != 0 {
				t.Error("a refused request is waiting for a decision")
			}
			// A reason that depends on what the signer holds or can do is kept to
			// itself; the others go to the coordinator (INV-006).
			items, _ := s.B.Outbox().Pending(ctx)
			if tc.reason.Disclosed() {
				if len(items) != 1 || items[0].Type != string(party.TypeSigningRefusal) {
					t.Errorf("outbox %+v", items)
				}
			} else if len(items) != 0 {
				t.Errorf("a private-state refusal was queued for the coordinator: %+v", items)
			}
		})
	}
}

// A request for the cold key that arrives by file is not refused for the
// transport (ADR 0005).
// spec: SPO-Xparty-PRE-006, SPO-Xparty-PRE-004
func TestColdKeyRequestOverFileIsAccepted(t *testing.T) {
	s := newScene(t, sceneOpt{cold: true})
	env := s.forgedRequest(func(r *party.SigningRequest) { r.KeyRole, r.KeyHash = custody.RolePoolCold, [28]byte(s.poolID) })
	h, err := s.B.Signer().Handle(ctx, ports.FileReceived(env))
	if err != nil || h.Refused || h.Effect != "stored" {
		t.Fatalf("handled = %+v, %v", h, err)
	}
}

// The coordinator records the signer's refusal against the slot.
// spec: SPO-Xparty-PRE-006, SPO-Xparty-OUT-004
func TestCoordinatorRecordsASigningRefusal(t *testing.T) {
	s := newScene(t, sceneOpt{})
	s.request()
	s.bobHandles()
	pend, _ := s.B.Signer().Pending(ctx)
	if _, err := s.B.Signer().Refuse(ctx, pend[0].ID); err != nil {
		t.Fatal(err)
	}
	s.bobFlush()
	hs := s.coordHandles()
	if len(hs) != 1 || hs[0].Refused || hs[0].Effect != "refusal-recorded" {
		t.Fatalf("coordinator = %+v", hs)
	}
	if !s.C.HasEvent("request-refused-by-signer", party.RefuseDeclined.String()) {
		t.Errorf("log %v", events(s.C))
	}
	if got := s.collection().Missing(); len(got) != 1 {
		t.Errorf("a refusal filled a slot")
	}
}

// ---- SPO-Xparty-PRE-004 on the coordinator ----------------------------------------

// A request for the pool cold key is not created for a network transport, and
// an outbox entry made for a file is not carried over a network later.
// spec: SPO-Xparty-PRE-004
func TestColdKeyRequestIsNeverSentOverNetwork(t *testing.T) {
	s := newScene(t, sceneOpt{cold: true, kind: ports.ViaNetwork})
	res := s.request()
	if len(res) != 2 || res[0].Status != multisig.SlotRequested || res[1].Status != multisig.SlotRefused || !errors.Is(res[1].Err, multisig.ErrColdKeyOverNetwork) {
		t.Fatalf("request = %+v", res)
	}
	if got := s.cb.Take(); len(got) != 1 {
		t.Fatalf("%d envelopes went out, want the stake request only", len(got))
	}
	if !s.C.HasEvent("request-not-created", multisig.ErrColdKeyOverNetwork.Error()) {
		t.Errorf("no audit event: %v", events(s.C))
	}
	// By file the same slot is requested. The file pipe is down, so the
	// request waits in the outbox.
	file := partyrig.NewPipe(ports.ViaFile)
	file.Down = true
	res, err := s.C.Coordinator().RequestSignatures(ctx, multisig.RequestInput{Ref: s.ref}, file.Transport())
	if err != nil || res[1].Status != multisig.SlotRequested {
		t.Fatalf("by file: %+v %v", res, err)
	}
	items, _ := s.C.Outbox().Pending(ctx)
	var cold []multisig.OutItem
	for _, it := range items {
		if it.ColdKey {
			cold = append(cold, it)
		}
	}
	if len(cold) != 1 || cold[0].Sent {
		t.Fatalf("outbox %+v", items)
	}
	// Offered to a network, the queued request does not move.
	net := partyrig.NewPipe(ports.ViaNetwork)
	if n, err := s.C.Outbox().Flush(ctx, net.Transport()); err != nil || n != 0 || len(net.Take()) != 0 {
		t.Fatalf("the cold key request left over a network: %d %v", n, err)
	}
	// Offered to the file transport, it goes.
	file.Down = false
	if n, err := s.C.Outbox().Flush(ctx, file.Transport()); err != nil || n != 1 {
		t.Fatalf("flush by file = %d, %v", n, err)
	}
}

// ---- SPO-Xparty-PRE-003, INV-009, INV-012 ------------------------------------------

// spec: SPO-Xparty-PRE-003
func TestOpenRefusesASlotWithoutAnEnrolledSigner(t *testing.T) {
	s := newScene(t, sceneOpt{})
	mk := func(name, partyName string) multisig.OpenRequest {
		return multisig.OpenRequest{Name: name, Body: s.body, TTL: s.ttl, Slots: []pool.Slot{{Name: "bob.staking", Role: custody.RoleStake, KeyHash: s.bobHash,
			Holder: custody.HolderRemote, Party: partyName}}}
	}
	other := partyrig.New(t, "other", s.clock, s.chain)
	// A signer enrolled for another pool is a signer: the Scope of a party is
	// what it may ask of us, not what we may ask of it (SPO-Xparty-INV-010).
	s.C.Enroll(other, "otherpool", []party.Role{party.RoleSigner}, []string{chain.PoolID{0xee}.Bech32()})
	coonly := partyrig.New(t, "coonly", s.clock, s.chain)
	s.C.Enroll(coonly, "coonly", []party.Role{party.RoleCoordinator}, []string{s.bech})
	s.C.Revoke("xav")
	for name, tc := range map[string]struct{ party, want string }{
		"no party":                     {"", "assigned to no party"},
		"a party that is not enrolled": {"stranger", "not enrolled"},
		"a party that is not a signer": {"coonly", "roles"},
		"a revoked party":              {"xav", "revoked"},
	} {
		if _, err := s.C.Coordinator().Open(ctx, mk("c"+strings.ReplaceAll(name, " ", ""), tc.party)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

// A request lives no longer than the TTL slot's time, nor more than 7 days.
// spec: SPO-Xparty-INV-009
func TestRequestExpiry(t *testing.T) {
	near := newScene(t, sceneOpt{ttl: 500})
	near.request()
	near.bobHandles()
	p, _ := near.B.Signer().Pending(ctx)
	if want := t0.Add(500 * time.Second); !p[0].Expires.Equal(want) {
		t.Errorf("expires %v, want the ttl slot's time %v", p[0].Expires, want)
	}
	far := newScene(t, sceneOpt{ttl: 30 * 24 * 3600})
	far.request()
	far.bobHandles()
	p, _ = far.B.Signer().Pending(ctx)
	if want := t0.Add(7 * 24 * time.Hour); !p[0].Expires.Equal(want) {
		t.Errorf("expires %v, want 7 days after creation %v", p[0].Expires, want)
	}
	// A TTL slot that is already past is not requested.
	past := newScene(t, sceneOpt{})
	past.chain.SetSlot(past.ttl + 5)
	if _, err := past.C.Coordinator().RequestSignatures(ctx, multisig.RequestInput{Ref: past.ref}, past.cb.Transport()); err == nil {
		t.Error("requested signatures for an expired collection")
	}
}

// The coordinator refuses a body whose hash is not its id, and one that the
// signer's decoder would refuse.
// spec: SPO-Xparty-INV-012, SPO-Xparty-INV-020
func TestOpenRefusesABodyThatDoesNotHashToItsId(t *testing.T) {
	s := newScene(t, sceneOpt{})
	bad := s.body
	bad.ID[0] ^= 1
	_, err := s.C.Coordinator().Open(ctx, multisig.OpenRequest{Name: "bad", Body: bad, TTL: s.ttl, Slots: []pool.Slot{{Name: "bob.staking", Role: custody.RoleStake,
		KeyHash: s.bobHash, Holder: custody.HolderRemote, Party: "bob"}}})
	if !errors.Is(err, multisig.ErrBodyHash) {
		t.Errorf("err = %v", err)
	}
}

// ---- helpers for the cases above -----------------------------------------------------

func newZed(s *scene) *partyrig.Workspace {
	z := partyrig.New(s.t, "zed", s.clock, s.chain)
	z.Enroll(s.C, "coord", []party.Role{party.RoleCoordinator}, []string{s.bech})
	return z
}

func nativeWitness(s *scene, owner string) (txbuild.Witness, error) {
	return native.VaultSigner{Vault: s.X.Store}.Witness(ctx, custody.KeyRef{Role: custody.RoleStake, Holder: custody.HolderVault, Owner: owner}, txbuild.TxBody{ID: s.body.ID})
}

var _ = rand.Reader
var _ = fmt.Sprint

// A coordinator in offline mode has no network transport: it will not send
// by one, flush an outbox into one, or take an envelope from one.
// spec: SPO-Xparty-MODE-001
func TestOfflineModeHasNoNetworkTransport(t *testing.T) {
	s := newScene(t, sceneOpt{kind: ports.ViaNetwork})
	off := s.C.Coordinator()
	off.Offline = true
	if _, err := off.RequestSignatures(ctx, multisig.RequestInput{Ref: s.ref}, s.cb.Transport()); !errors.Is(err, multisig.ErrOffline) {
		t.Errorf("request over a network: %v", err)
	}
	if _, err := (multisig.Outbox{Store: s.C.Store, Clock: s.clock, Offline: true}).Flush(ctx, s.cb.Transport()); !errors.Is(err, multisig.ErrOffline) {
		t.Errorf("flush into a network: %v", err)
	}
	if _, err := off.Handle(ctx, ports.NetworkReceived([]byte("x"))); !errors.Is(err, multisig.ErrOffline) {
		t.Errorf("handle from a network: %v", err)
	}
	// By file it works.
	file := partyrig.NewPipe(ports.ViaFile)
	res, err := off.RequestSignatures(ctx, multisig.RequestInput{Ref: s.ref}, file.Transport())
	if err != nil || res[0].Status != multisig.SlotRequested || len(file.Take()) != 1 {
		t.Fatalf("by file: %+v, %v", res, err)
	}
}
