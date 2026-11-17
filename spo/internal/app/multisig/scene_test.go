package multisig_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/multiparty/partyrig"
)

var ctx = context.Background()

var t0 = time.Unix(1_800_000_000, 0).UTC()

// coordNode is the coordinator's tailcat node key, published in its identity.
var coordNode = party.NodeKey{0xc0, 1}

// scene is a coordinator, two enrolled signers (bob and xavier) and a
// registration body that bob is asked to sign for his stake key, and, when
// cold is set, for the pool cold key as well.
type scene struct {
	t       *testing.T
	fps     map[string]party.Fingerprint
	clock   *partyrig.Clock
	chain   *partyrig.Chain
	C, B, X *partyrig.Workspace
	poolID  chain.PoolID
	bech    string
	bobHash txbuild.KeyHash
	ref     multisig.CollectionRef
	body    txbuild.TxBody
	ttl     uint64
	cb, bc  *partyrig.Pipe // coordinator to bob, bob to coordinator
}

type sceneOpt struct {
	cold bool
	kind ports.TransportKind
	ttl  uint64 // slots after the tip; 0 means 500
	// bobNode gives bob's identity a tailcat node key, bobNode, which the
	// coordinator has enrolled.
	bobNode bool
}

// bobNodeKey is bob's tailcat node key when sceneOpt.bobNode is set.
var bobNodeKey = party.NodeKey{0xb0, 2}

// fp is the fingerprint of the party the scene enrolled under a name; a name
// no party has gets a fingerprint nobody holds (an unenrolled party).
func (s *scene) fp(name string) party.Fingerprint {
	if name == "" {
		return party.Fingerprint{}
	}
	if fp, ok := s.fps[name]; ok {
		return fp
	}
	for _, p := range registry(s.t, s.C) {
		if p.Name == name {
			return p.Fingerprint
		}
	}
	return party.Fingerprint{0xde, 0xad, byte(len(name))}
}

func newScene(t *testing.T, o sceneOpt) *scene {
	t.Helper()
	if o.kind == 0 {
		o.kind = ports.ViaFile
	}
	if o.ttl == 0 {
		o.ttl = 500
	}
	s := &scene{t: t, clock: partyrig.NewClock(t0)}
	s.chain = partyrig.NewChain(s.clock.Now())
	s.C = partyrig.NewWithNode(t, "coord", s.clock, s.chain, &coordNode)
	if o.bobNode {
		s.B = partyrig.NewWithNode(t, "bob", s.clock, s.chain, &bobNodeKey)
	} else {
		s.B = partyrig.New(t, "bob", s.clock, s.chain)
	}
	s.X = partyrig.New(t, "xavier", s.clock, s.chain)
	s.bobHash = s.B.AddKey(custody.RoleStake, "bob")
	if o.cold {
		s.poolID = chain.PoolID(s.B.AddKey(custody.RolePoolCold, "mypool"))
	} else {
		for i := range s.poolID {
			s.poolID[i] = byte(i + 1)
		}
	}
	s.bech = s.poolID.Bech32()
	s.fps = map[string]party.Fingerprint{}
	s.fps["bob"] = s.C.Enroll(s.B, "bob", []party.Role{party.RoleSigner}, []string{s.bech}).Fingerprint
	s.fps["xav"] = s.C.Enroll(s.X, "xav", []party.Role{party.RoleSigner}, []string{s.bech}).Fingerprint
	s.B.Enroll(s.C, "coord", []party.Role{party.RoleCoordinator}, []string{s.bech})
	s.X.Enroll(s.C, "coord", []party.Role{party.RoleCoordinator}, []string{s.bech})

	cert, err := native.Ledger{}.BuildPoolRegistration(pool.RegistrationSpec{Operator: s.poolID, VrfKeyHash: [32]byte{7}, Pledge: 1_000_000,
		Cost: 340_000_000, Margin: chain.Rational{Num: 1, Den: 100}, RewardAccount: stake.KeyHash(s.bobHash), NetworkID: 0,
		Owners: []stake.KeyHash{stake.KeyHash(s.bobHash)}, Relays: []pool.Relay{{Kind: pool.RelayDNS, Host: "relay.example.org", Port: 3001, HasPort: true}},
		MetaURL: "https://example.org/p.json", MetaHash: [32]byte{9}})
	if err != nil {
		t.Fatal(err)
	}
	s.ttl = 1000 + o.ttl
	s.body = partyrig.Body(t, s.ttl, cert.Attachment(500_000_000))
	slots := []pool.Slot{{Name: "bob.staking", Role: custody.RoleStake, KeyHash: s.bobHash, PartyFingerprint: s.fp("bob")}}
	if o.cold {
		slots = append(slots, pool.Slot{Name: "mypool.node", Role: custody.RolePoolCold, KeyHash: txbuild.KeyHash(s.poolID), PartyFingerprint: s.fp("bob")})
	}
	s.ref, err = s.C.Coordinator().Open(ctx, multisig.OpenRequest{Name: "reg1", Body: s.body, TTL: s.ttl, Slots: slots, Local: txflow.Prepared{}})
	if err != nil {
		t.Fatal(err)
	}
	s.cb, s.bc = partyrig.NewPipe(o.kind), partyrig.NewPipe(o.kind)
	return s
}

func (s *scene) request(opts ...func(*multisig.RequestInput)) []multisig.SlotResult {
	s.t.Helper()
	in := multisig.RequestInput{Ref: s.ref, Purpose: "register the pool"}
	for _, o := range opts {
		o(&in)
	}
	res, err := s.C.Coordinator().RequestSignatures(ctx, in, s.cb.Transport())
	if err != nil {
		s.t.Fatal(err)
	}
	return res
}

// bobHandles gives every envelope waiting for bob to his signer role.
func (s *scene) bobHandles() []multisig.Handled {
	s.t.Helper()
	var out []multisig.Handled
	for _, env := range s.cb.Take() {
		h, err := s.B.Signer().Handle(ctx, partyrig.Received(env, s.cb.Kind))
		if err != nil {
			s.t.Fatal(err)
		}
		out = append(out, h)
	}
	return out
}

// coordHandles gives every envelope waiting for the coordinator to it.
func (s *scene) coordHandles() []multisig.Handled {
	s.t.Helper()
	var out []multisig.Handled
	for _, env := range s.bc.Take() {
		h, err := s.C.Coordinator().Handle(ctx, partyrig.Received(env, s.bc.Kind))
		if err != nil {
			s.t.Fatal(err)
		}
		out = append(out, h)
	}
	return out
}

func (s *scene) bobFlush() {
	s.t.Helper()
	if _, err := s.B.Outbox().Flush(ctx, s.bc.Transport()); err != nil {
		s.t.Fatal(err)
	}
}

// bobApproves reviews and approves the only pending request.
func (s *scene) bobApproves() multisig.Review {
	s.t.Helper()
	pend, err := s.B.Signer().Pending(ctx)
	if err != nil || len(pend) != 1 {
		s.t.Fatalf("pending = %v, %v", pend, err)
	}
	rv, err := s.B.Signer().ReviewRequest(ctx, pend[0].ID)
	if err != nil {
		s.t.Fatal(err)
	}
	a, err := rv.Approval()
	if err != nil {
		s.t.Fatal(err)
	}
	if _, err := s.B.Signer().Approve(ctx, a); err != nil {
		s.t.Fatal(err)
	}
	return rv
}

// collection reads the stored collection.
func (s *scene) collection() pool.Collection {
	s.t.Helper()
	var c pool.Collection
	err := s.C.Store.View(ctx, func(r ports.Reader) error {
		raw, err := r.Get(ports.Ref{Name: s.ref.Name, Kind: ports.MultisigCollection})
		if err != nil {
			return err
		}
		d, err := pool.ParseDescriptor(raw)
		if err != nil {
			return err
		}
		pc, err := d.Collection(native.Ledger{}.TransactionID)
		if err != nil {
			return err
		}
		c = *pc
		return nil
	})
	if err != nil {
		s.t.Fatal(err)
	}
	return c
}

// requestFor builds the request the coordinator would send for slot 0, with
// edits, sealed from the coordinator to bob by the coordinator's real
// identity: what a coordinator that lies would send.
func (s *scene) forgedRequest(edit func(*party.SigningRequest)) []byte {
	s.t.Helper()
	body, err := native.TxViewer{}.BodyOf(s.body.CBOR)
	if err != nil {
		s.t.Fatal(err)
	}
	req := party.SigningRequest{Collection: s.cid(), Slot: 0, KeyRole: custody.RoleStake, KeyHash: [28]byte(s.bobHash),
		Operation: "witness-transaction", TxBody: body, BodyHash: blake2b.Sum256(body), TTLSlot: s.ttl, NetworkMagic: partyrig.Magic, Purpose: "forged"}
	if edit != nil {
		edit(&req)
	}
	return s.sealFrom(s.C, s.B, req, s.clock.Now(), s.clock.Now().Add(2*time.Minute)) // inside the ttl slot's time: INV-009
}

// sealFrom seals a body from one workspace's identity to another's, which
// the sender must have enrolled.
func (s *scene) sealFrom(from, to *partyrig.Workspace, body party.Body, now, expires time.Time) []byte {
	s.t.Helper()
	local, err := from.Kit.Local(ctx)
	if err != nil {
		s.t.Fatal(err)
	}
	defer local.Destroy()
	var rcpt party.Party
	err = from.Store.View(ctx, func(r ports.Reader) error {
		ps, err := from.Registry.List(r)
		for _, p := range ps {
			if p.Fingerprint == to.Identity.Fingerprint {
				rcpt = p
			}
		}
		return err
	})
	if err != nil || rcpt.Name == "" {
		s.t.Fatalf("%s has not enrolled %s: %v", from.Name, to.Name, err)
	}
	env, _, err := local.Seal(rcpt.Identity, body, now, expires)
	if err != nil {
		s.t.Fatal(err)
	}
	return env
}

// witnessOver signs an arbitrary id with a key of bob's vault.
func (s *scene) witnessOver(id [32]byte) txbuild.Witness {
	s.t.Helper()
	return s.B.SignID(custody.RoleStake, "bob", id)
}

// cid is the wire id of the stored collection.
func (s *scene) cid() party.CollectionID { return multisig.CollectionID(s.ref, s.collection()) }

func mustRefuse(t *testing.T, h multisig.Handled, reason string) {
	t.Helper()
	if !h.Refused || !strings.Contains(h.Reason, reason) {
		t.Fatalf("handled = %+v, want a refusal with %q", h, reason)
	}
	if h.Outward() != nil {
		t.Error("something goes back to the sender of a refused envelope")
	}
}

func eventWith(es []string, sub string) bool {
	for _, e := range es {
		if strings.Contains(e, sub) {
			return true
		}
	}
	return false
}

func events(w *partyrig.Workspace) []string {
	var out []string
	for _, e := range w.Events() {
		out = append(out, fmt.Sprintf("%s|%s|%s|%s", e.Kind, e.Reason, e.Peer, e.Detail))
	}
	return out
}
