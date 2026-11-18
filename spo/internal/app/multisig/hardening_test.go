package multisig_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/multiparty/partyrig"
)

// ---- the approval gate ----------------------------------------------------------------

// Approve signs only after the gate has authenticated the operator again, with
// the key and the body hash; with no gate it refuses, and a gate that says no
// leaves the request waiting and nothing signed.
// spec: SPO-Xparty-INV-016
func TestApproveNeedsTheGate(t *testing.T) {
	s := newScene(t, sceneOpt{})
	s.request()
	s.bobHandles()
	pend, _ := s.B.Signer().Pending(ctx)
	rv, err := s.B.Signer().ReviewRequest(ctx, pend[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	a, err := rv.Approval()
	if err != nil {
		t.Fatal(err)
	}

	noGate := s.B.Signer()
	noGate.Gate = nil
	if _, err := noGate.Approve(ctx, a); !errors.Is(err, multisig.ErrNoGate) {
		t.Fatalf("no gate: %v", err)
	}
	s.B.Gate.Deny = true
	if _, err := s.B.Signer().Approve(ctx, a); err == nil || s.B.Gate.Count() != 1 {
		t.Fatalf("a gate that says no: %v, asked %d times", err, s.B.Gate.Count())
	}
	if items, _ := s.B.Outbox().Pending(ctx); len(items) != 0 {
		t.Fatal("a response was made without the operator authenticating")
	}
	if pend, _ := s.B.Signer().Pending(ctx); len(pend) != 1 {
		t.Fatal("the request did not go back to waiting")
	}
	s.B.Gate.Deny = false
	if _, err := s.B.Signer().Approve(ctx, a); err != nil {
		t.Fatal(err)
	}
	if got := s.B.Gate.Calls; len(got) != 2 || got[1].Role != custody.RoleStake || got[1].Identity.IsZero() {
		t.Fatalf("the gate was told %+v", got)
	}
}

// ---- M1: an unset transport kind is a network ---------------------------------------

// The coordinator will not create a cold-key request for a transport of no
// stated kind, nor flush one through it, and a transport of no stated kind is
// refused where a kind must be stated.
// spec: SPO-Xparty-PRE-004, SPO-Xparty-INV-024
func TestUnsetTransportKindIsANetworkAtTheCoordinator(t *testing.T) {
	s := newScene(t, sceneOpt{cold: true})
	unset := partyrig.NewPipe(ports.ViaUnknown)
	// With no sender at all (queue only) the cold slot is not created.
	res, err := s.C.Coordinator().RequestSignatures(ctx, multisig.RequestInput{Ref: s.ref}, unset.Transport())
	if err != nil || len(res) != 2 || res[0].Status != multisig.SlotRequested || !errors.Is(res[1].Err, multisig.ErrColdKeyOverNetwork) {
		t.Fatalf("queue only: %+v, %v", res, err)
	}
	if _, err := s.C.Outbox().Flush(ctx, unset.Transport()); !errors.Is(err, multisig.ErrTransportKind) {
		t.Fatalf("flush through a transport of no kind: %v", err)
	}
	if unset.Sent != 0 {
		t.Fatal("something was sent through a transport of no kind")
	}
	// There is no constructor with a kind parameter: a sender is paired with a
	// kind only by FileTransport or NetworkTransport, so no transport of an
	// unstated kind has a sender, and the zero Transport has none.
	if (ports.Transport{}).Kind().Known() || ports.ViaUnknown.IsFile() || ports.NetworkTransport(unset).Kind() != ports.ViaNetwork ||
		ports.FileTransport(unset).Kind() != ports.ViaFile || (ports.Received{}).Via().IsFile() {
		t.Fatal("an unstated kind is a file")
	}
}

// ---- (a)8: what the signer enforces on receipt -----------------------------------------

// The signer refuses on receipt a request that lives longer than its body's TTL
// slot or 7 days, and a body over maxTxSize, before it stores anything.
// spec: SPO-Xparty-INV-008, SPO-Xparty-INV-009
func TestSignerEnforcesExpiryAndSizeOnReceipt(t *testing.T) {
	s := newScene(t, sceneOpt{})
	body := func(r *party.SigningRequest) {}
	long := func(expires time.Duration) []byte {
		req := mustForged(s, body)
		return s.sealFrom(s.C, s.B, req, s.clock.Now(), s.clock.Now().Add(expires))
	}
	// The ttl slot is 500 seconds away: a request that lives 10 minutes outlives it.
	h, err := s.B.Signer().Handle(ctx, ports.FileReceived(long(10*time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, h, party.ErrRequestExpiry.Error())
	h, _ = s.B.Signer().Handle(ctx, ports.FileReceived(long(2*time.Minute)))
	if h.Refused || h.Effect != "stored" {
		t.Fatalf("a request inside its ttl: %+v", h)
	}
	// Over maxTxSize, with the protocol parameter and with the upper bound.
	big := mustForged(s, func(r *party.SigningRequest) {
		r.TxBody = append(r.TxBody, make([]byte, party.DefaultMaxTxSize)...)
	})
	h, _ = s.B.Signer().Handle(ctx, ports.FileReceived(s.sealFrom(s.C, s.B, big, s.clock.Now(), s.clock.Now().Add(2*time.Minute))))
	mustRefuse(t, h, "maxTxSize")
	small := s.B.Signer()
	small.MaxTxSize = 100
	h, _ = small.Handle(ctx, ports.FileReceived(s.sealFrom(s.C, s.B, mustForged(s, body), s.clock.Now(), s.clock.Now().Add(2*time.Minute))))
	mustRefuse(t, h, "maxTxSize")
	// A protocol parameter above the bound does not raise it.
	huge := s.B.Signer()
	huge.MaxTxSize = 1 << 30
	h, _ = huge.Handle(ctx, ports.FileReceived(s.sealFrom(s.C, s.B, big, s.clock.Now(), s.clock.Now().Add(2*time.Minute))))
	mustRefuse(t, h, "maxTxSize")
}

// A request that cannot have its lifetime checked is refused.
// spec: SPO-Xparty-INV-009
func TestRequestWithoutAGenesisIsRefused(t *testing.T) {
	s := newScene(t, sceneOpt{})
	sg := s.B.Signer()
	sg.Chain.Genesis = nil
	sg.Chain.Tip = s.chain // the slot is known; the time of the ttl slot is not
	h, err := sg.Handle(ctx, ports.FileReceived(s.forgedRequest(nil)))
	if err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, h, "lifetime")
}

func mustForged(s *scene, edit func(*party.SigningRequest)) party.SigningRequest {
	var req party.SigningRequest
	s.forgedRequest(func(r *party.SigningRequest) {
		if edit != nil {
			edit(r)
		}
		req = *r
	})
	return req
}

// ---- L3: the invitation ---------------------------------------------------------------------

// The invitation's node key must be the coordinator's enrolled one, and the
// hook runs in the transaction that records the id: a hook that fails leaves
// no replay entry, and the same invitation can be taken afterwards.
// spec: SPO-Xparty-SEC-001, SPO-Xparty-INV-007, SPO-Xparty-IF-006
func TestInviteIsBoundToTheEnrolledNodeKeyAndAtomic(t *testing.T) {
	s := newScene(t, sceneOpt{})
	var stored []string
	fail := true
	sg := s.B.Signer()
	sg.OnInvite = func(w ports.NamedWriter, from party.Party, inv party.Invite) error {
		if fail {
			// Whatever the hook wrote before failing is rolled back with the rest.
			_ = w.Put(ports.NamedRef{Name: "partial", Kind: ports.NodeCounter}, []byte("1"))
			return errors.New("the wiring could not store the secret")
		}
		stored = append(stored, inv.Address)
		return nil
	}
	now := s.clock.Now()
	right := party.Invite{Address: "tailcat://secret", Node: coordNode}
	wrong := party.Invite{Address: "tailcat://secret", Node: party.NodeKey{0x66}}
	h, _ := sg.Handle(ctx, ports.FileReceived(s.sealFrom(s.C, s.B, wrong, now, now.Add(time.Hour))))
	mustRefuse(t, h, "node key")
	if len(stored) != 0 {
		t.Fatal("an invitation for another node key was stored")
	}
	env := s.sealFrom(s.C, s.B, right, now, now.Add(time.Hour))
	if _, err := sg.Handle(ctx, ports.FileReceived(env)); err == nil {
		t.Fatal("a failing hook was not reported")
	}
	fail = false
	h, err := sg.Handle(ctx, ports.FileReceived(env)) // the same envelope: the id was not recorded
	if err != nil || h.Refused || h.Effect != "invite" || len(stored) != 1 {
		t.Fatalf("after the hook worked: %+v, %v", h, err)
	}
	if h, _ = sg.Handle(ctx, ports.FileReceived(env)); !h.Refused {
		t.Fatal("a stored invitation was taken twice")
	}
}

// ---- L4: the end of a collection -----------------------------------------------------------

// A collection whose TTL slot is the tip is expired, as the signer holds it, so
// no response is taken for it.
// spec: SPO-Xparty-INV-015
func TestCollectionExpiresAtTheTTLSlot(t *testing.T) {
	s := newScene(t, sceneOpt{})
	resp := s.readyResponse()
	s.chain.SetSlot(s.ttl) // the tip reaches the ttl slot: the transaction is invalid from here on
	h, err := s.C.Coordinator().Handle(ctx, ports.FileReceived(resp))
	if err != nil || !h.Refused || !strings.Contains(h.Reason, party.ErrCollectionNotOpen.Error()) {
		t.Fatalf("at the ttl slot: %+v, %v", h, err)
	}
	if got := s.collection().Missing(); len(got) != 1 {
		t.Fatalf("the slot was filled: missing %v", got)
	}
}

// A CollectionClosed that names a transaction id that is not the body hash of
// the requests, or a collection nobody asked about, is refused.
// spec: SPO-Xparty-INV-015
func TestCollectionClosedMustNameTheBodyHash(t *testing.T) {
	s := newScene(t, sceneOpt{})
	s.request()
	s.bobHandles()
	now := s.clock.Now()
	closed := func(c party.CollectionID, o party.Outcome, id []byte) multisig.Handled {
		env := s.sealFrom(s.C, s.B, party.CollectionClosed{Collection: c, Outcome: o, TxID: id}, now, now.Add(time.Hour))
		h, err := s.B.Signer().Handle(ctx, ports.FileReceived(env))
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	wrong := chain.TxID{0x42}
	mustRefuse(t, closed(s.cid(), party.OutcomeSubmitted, wrong[:]), "body hash")
	mustRefuse(t, closed(party.CollectionID{9}, party.OutcomeDiscarded, nil), "no request")
	if pend, _ := s.B.Signer().Pending(ctx); len(pend) != 1 {
		t.Fatal("a refused notice closed the request")
	}
	if h := closed(s.cid(), party.OutcomeSubmitted, s.body.ID[:]); h.Refused || h.Effect != "closed" {
		t.Fatalf("the right id: %+v", h)
	}
	if pend, _ := s.B.Signer().Pending(ctx); len(pend) != 0 {
		t.Fatal("the closed request still waits")
	}
}

// ---- L5: a network send is not a delivery ---------------------------------------------------

// Over a network a request stays pending after it was sent, goes out again
// (same id) after a new connection, and stops when the answer it asks for
// arrives. A duplicate request is answered with the stored response, which is
// sent once.
// spec: SPO-Xparty-INV-017, SPO-Xparty-SEC-003
func TestNetworkSendsAreRepeatedUntilAnswered(t *testing.T) {
	s := newScene(t, sceneOpt{kind: ports.ViaNetwork})
	s.request()
	if n := len(s.cb.Take()); n != 1 {
		t.Fatalf("%d sent", n)
	}
	// Sent, not delivered: still pending, and not sent again on the same connection.
	items, _ := s.C.Outbox().Pending(ctx)
	if len(items) != 1 || !items[0].Sent || items[0].Delivered {
		t.Fatalf("outbox %+v", items)
	}
	if n, err := s.C.Outbox().Flush(ctx, s.cb.Transport()); err != nil || n != 0 {
		t.Fatalf("flush on the same connection = %d, %v", n, err)
	}
	// A new connection sends it again.
	if err := s.C.Outbox().Rearm(ctx); err != nil {
		t.Fatal(err)
	}
	if n, err := s.C.Outbox().Flush(ctx, s.cb.Transport()); err != nil || n != 1 {
		t.Fatalf("flush after a reconnect = %d, %v", n, err)
	}
	reqs := s.cb.Take()
	// The signer answers; the duplicate is answered with the stored response, not signed twice.
	if h, _ := s.B.Signer().Handle(ctx, ports.NetworkReceived(reqs[0])); h.Effect != "stored" {
		t.Fatalf("first = %+v", h)
	}
	s.bobApproves()
	h, err := s.B.Signer().Handle(ctx, ports.NetworkReceived(reqs[0]))
	if err != nil || h.Effect != "response-resent" || s.B.Gate.Count() != 1 {
		t.Fatalf("duplicate = %+v, %v, gate %d", h, err, s.B.Gate.Count())
	}
	s.bobFlush()
	if hs := s.coordHandles(); len(hs) != 1 || hs[0].Effect != "filled" {
		t.Fatalf("coordinator = %+v", hs)
	}
	// The answer arrived: the request is done and is not sent again.
	if items, _ := s.C.Outbox().Pending(ctx); len(items) != 0 {
		t.Fatalf("a settled request is still pending: %+v", items)
	}
	// The response was delivered when its write succeeded: it is not sent again.
	if items, _ := s.B.Outbox().Pending(ctx); len(items) != 0 {
		t.Fatalf("the response is still pending: %+v", items)
	}
}

// Over a file the same envelope is delivered once and is done.
// spec: SPO-Xparty-IF-004
func TestFileSendsAreDeliveredOnce(t *testing.T) {
	s := newScene(t, sceneOpt{})
	s.request()
	if items, _ := s.C.Outbox().Pending(ctx); len(items) != 0 {
		t.Fatalf("a written file is still pending: %+v", items)
	}
}

// What a coordinator asks of a signer is limited by the slot assignment and the
// signer's own checks, not by the scope recorded for the signer: that scope is
// what it may ask of us (SPO-Xparty-INV-010, L-d). A signer enrolled with a
// scope that names another pool, or another key role, is still assignable.
// spec: SPO-Xparty-INV-010, SPO-Xparty-PRE-003
func TestCoordinatorDoesNotUseTheSignersScope(t *testing.T) {
	s := newScene(t, sceneOpt{})
	narrow := partyrig.New(t, "narrow", s.clock, s.chain)
	s.C.EnrollScoped(narrow, "payonly", []party.Role{party.RoleSigner}, party.Scope{KeyRoles: []custody.Role{custody.RolePayment}, Pools: []string{s.bech}})
	poolless := partyrig.New(t, "poolless", s.clock, s.chain)
	s.C.EnrollScoped(poolless, "otherpool", []party.Role{party.RoleSigner}, party.Scope{KeyRoles: []custody.Role{custody.RoleStake}, Pools: []string{chain.PoolID{0xee}.Bech32()}})
	for name, partyName := range map[string]string{"a key role it is not asked for": "payonly", "a pool the body does not concern": "otherpool"} {
		req := multisig.OpenRequest{Name: "m" + strings.ReplaceAll(name, " ", ""), Body: s.body, TTL: s.ttl,
			Slots: []pool.Slot{{Name: "bob.staking", Role: custody.RoleStake, KeyHash: s.bobHash, PartyFingerprint: s.fp(partyName)}}}
		if _, err := s.C.Coordinator().Open(ctx, req); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The size limit is on the body and the auxiliary data together: a body and
// auxiliary data that are each within maxTxSize and are not together are
// refused on receipt, and the coordinator does not seal such a request.
// spec: SPO-Xparty-INV-008
func TestSizeLimitCountsAuxiliaryData(t *testing.T) {
	s := newScene(t, sceneOpt{})
	req := mustForged(s, func(r *party.SigningRequest) { r.AuxData = make([]byte, 200) })
	size := len(req.TxBody)
	sg := s.B.Signer()
	sg.MaxTxSize = size + 199 // the body alone is well within it, the body and the aux are one byte over
	h, err := sg.Handle(ctx, ports.FileReceived(s.sealFrom(s.C, s.B, req, s.clock.Now(), s.clock.Now().Add(2*time.Minute))))
	if err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, h, "(200 bytes) together exceed maxTxSize")
	sg.MaxTxSize = size + 200 // exactly at the limit: passes the size check (the body has no aux hash, so it is refused later and elsewhere)
	h, _ = sg.Handle(ctx, ports.FileReceived(s.sealFrom(s.C, s.B, mustForged(s, func(r *party.SigningRequest) { r.AuxData = make([]byte, 200) }), s.clock.Now(), s.clock.Now().Add(2*time.Minute))))
	if h.Refused {
		t.Fatalf("at the limit: %+v", h)
	}
	// The coordinator checks before it seals.
	c := s.C.Coordinator()
	c.MaxTxSize = 10
	if _, err := c.RequestSignatures(ctx, multisig.RequestInput{Ref: s.ref}, s.cb.Transport()); err == nil || !strings.Contains(err.Error(), "maxTxSize") {
		t.Fatalf("a coordinator sealed a request over maxTxSize: %v", err)
	}
}
