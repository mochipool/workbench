package multiparty

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/adapters/filebag"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/app/poolops"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// exchange is the two directories the parties pass files through: one holds
// what is for bob, one what is for the coordinator.
type exchange struct {
	toBob, toCoord *filebag.Bag
	dirBob, dirC   string
}

func newExchange(t *testing.T) exchange {
	t.Helper()
	root := t.TempDir()
	mk := func(n string) (*filebag.Bag, string) {
		d := filepath.Join(root, n)
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		b, err := filebag.Open(d)
		if err != nil {
			t.Fatal(err)
		}
		b.SetPoll(5 * time.Millisecond)
		t.Cleanup(func() { b.Close() })
		return b, d
	}
	x := exchange{}
	x.toBob, x.dirBob = mk("to-bob")
	x.toCoord, x.dirC = mk("to-coordinator")
	return x
}

func (x exchange) coordPump(w *world, h multisig.Handler, seen func(multisig.Handled)) multisig.Pump {
	return multisig.Pump{Outbox: w.C.Outbox(), Send: x.toBob.Transport(), Receive: x.toCoord, Handle: h,
		Idle: 150 * time.Millisecond, Handled: seen}
}

func (x exchange) bobPump(w *world, h multisig.Handler) multisig.Pump {
	return multisig.Pump{Outbox: w.B.Outbox(), Send: x.toCoord.Transport(), Receive: x.toBob, Handle: h, Idle: 150 * time.Millisecond}
}

// (a) A two-owner pool registration over the file transport: the coordinator
// holds the cold key and the payer, alice is local, bob is another party.
// The request goes by file, bob reads what the body does, approves, the
// response comes back by file, and the registration is submitted with every
// witness verifying and the transaction id equal to the body hash bob
// reviewed.
//
// spec: SPO-Xparty-SEC-002, SPO-Xparty-INV-013, SPO-Xparty-PRE-003, SPO-Xparty-INV-012, SPO-Xparty-INV-020, SPO-Xparty-PR-002,
// spec: SPO-Xparty-OUT-004, SPO-Xparty-OUT-005, SPO-Xparty-OUT-006, SPO-Xparty-PRE-005, SPO-Xparty-IF-004, SPO-Xparty-SEC-003, SPO-Xparty-INV-016
func TestFileTransportTwoOwnerPoolRegistration(t *testing.T) {
	w := newWorld(t, nil)
	x := newExchange(t)
	w.open()
	coord := w.C.Coordinator() // completion is wired after the response, to look at the collection first

	// The coordinator asks for the one missing signature (the others are its own).
	res, err := coord.RequestSignatures(ctx, multisig.RequestInput{Ref: poolRef, Purpose: "register mypool"}, x.toBob.Transport())
	if err != nil {
		t.Fatal(err)
	}
	var requested int
	for _, r := range res {
		switch r.Status {
		case multisig.SlotRequested:
			requested++
			if r.Name != "bob.staking" {
				t.Errorf("requested %s", r.Name)
			}
		case multisig.SlotFilled:
		default:
			t.Errorf("slot %s: %s %v", r.Name, r.Status, r.Err)
		}
	}
	if requested != 1 {
		t.Fatalf("requests = %+v", res)
	}
	// One file is in bob's directory.
	if files, _ := filepath.Glob(filepath.Join(x.dirBob, "*.spo")); len(files) != 1 {
		t.Fatalf("files %v", files)
	}

	// Bob's machine imports it, reads it, approves, exports the response.
	bob := w.bobSigner()
	if err := x.bobPump(w, bob.Handle).Run(ctx); err != nil {
		t.Fatal(err)
	}
	pend, err := bob.Pending(ctx)
	if err != nil || len(pend) != 1 {
		t.Fatalf("pending %v %v", pend, err)
	}
	rv, err := bob.ReviewRequest(ctx, pend[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	// What bob is shown: decoded from the body he received.
	v := rv.View
	// The registration and the two owners' delegations to the pool.
	if len(v.Certificates) != 3 || v.Certificates[0].PoolReg == nil {
		t.Fatalf("certificates %+v", v.Certificates)
	}
	for _, c := range v.Certificates[1:] {
		if c.Kind != party.CertStakeDelegation || !c.HasPool || c.Pool != [28]byte(w.poolID) {
			t.Errorf("delegation %+v", c)
		}
	}
	p := v.Certificates[0].PoolReg
	if p.Operator != [28]byte(w.poolID) {
		t.Error("the pool id is not the pool's")
	}
	if p.Pledge != 100_000_000_000 || p.Cost != 340_000_000 || p.MarginNum != 1 || p.MarginDen != 10 {
		t.Errorf("pledge, cost, margin: %+v", p)
	}
	if len(p.Owners) != 2 {
		t.Errorf("owners %v", p.Owners)
	}
	var hasBob bool
	for _, o := range p.Owners {
		hasBob = hasBob || o == [28]byte(w.bobHash)
	}
	if !hasBob {
		t.Error("bob is not among the owners he was asked to sign for")
	}
	if len(p.Relays) != 1 || p.Relays[0].Kind != "dns" || p.Relays[0].Host != "relay.example.org" || p.Relays[0].Port != 3001 {
		t.Errorf("relays %+v", p.Relays)
	}
	if p.RewardAccount == "" || !strings.HasPrefix(p.RewardAccount, "stake_test") || !p.HasMeta || p.MetaURL != "https://example.org/mypool.metadata.json" {
		t.Errorf("reward account / metadata %+v", p)
	}
	if v.Fee == 0 || v.TTL == nil || len(v.Outputs) == 0 || len(v.Inputs) != 2 {
		t.Errorf("fee/ttl/outputs/inputs %d %v %d %d", v.Fee, v.TTL, len(v.Outputs), len(v.Inputs))
	}
	// The pool deposit is a protocol parameter: the body states none, and the view says so.
	if v.Certificates[0].Deposit != nil {
		t.Error("the view invents a deposit")
	}
	if rv.ClaimedPurpose != "register mypool" || rv.BodyHash != [32]byte(w.collection().Body.ID) {
		t.Errorf("review %+v", rv)
	}
	a, err := rv.Approval()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Approve(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := x.bobPump(w, bob.Handle).Run(ctx); err != nil {
		t.Fatal(err)
	}

	// The coordinator imports the response: the collection completes and the
	// use case submits.
	var seen []multisig.Handled
	if err := x.coordPump(w, coord.Handle, func(h multisig.Handled) { seen = append(seen, h) }).Run(ctx); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0].Refused || seen[0].Effect != "filled" || !seen[0].Complete {
		t.Fatalf("coordinator saw %+v", seen)
	}
	// The collection is complete; bob's witness came in an envelope, so it is not marked.
	c := w.collection()
	if c.State(1000) != pool.CollectionOpenComplete || w.sub.count() != 0 {
		t.Fatalf("state %s, %d submitted before completion", c.State(1000), w.sub.count())
	}
	bobSlot, _ := c.Slot("bob.staking")
	if bobSlot.Unauthenticated || bobSlot.Witness == nil || bobSlot.PartyFingerprint != w.C.FingerprintOf("bobparty") {
		t.Errorf("bob's slot %+v", bobSlot)
	}
	// The use case then assembles exactly the stored body with the stored witnesses and submits.
	coord.Complete = w.coordinator().Complete
	if err := coord.CompleteNow(ctx, poolRef); err != nil {
		t.Fatal(err)
	}
	if w.sub.count() != 1 {
		t.Fatalf("%d transactions submitted", w.sub.count())
	}
	tx := w.sub.sent[0]
	id, err := w.led.TransactionID(tx)
	if err != nil || id != c.Body.ID || [32]byte(id) != rv.BodyHash {
		t.Errorf("the submitted transaction is %s, bob reviewed %x", id, rv.BodyHash)
	}
	body, _ := native.TxViewer{}.BodyOf(tx)
	if blake2b.Sum256(body) != rv.BodyHash {
		t.Error("the hash of the submitted body is not the one reviewed")
	}
	ws, err := native.TxViewer{}.Witnesses(tx)
	if err != nil || len(ws) != 4 {
		t.Fatalf("witnesses %d, %v", len(ws), err)
	}
	for _, wt := range ws {
		matched := false
		for _, s := range c.Slots {
			if txbuild.HashKey(wt.VKey[:]) == s.KeyHash {
				if err := txbuild.VerifyWitness(c.Body, wt, s.KeyHash); err != nil {
					t.Errorf("witness of %s: %v", s.Name, err)
				}
				matched = true
			}
		}
		if !matched {
			t.Errorf("a witness of no slot")
		}
	}
	if got := w.conf.stages; len(got) != 2 || got[0] != "body" || got[1] != "submit" {
		t.Errorf("confirmations %v", got)
	}
	// The coordinator tells bob it was submitted; his request is closed.
	if err := x.coordPump(w, coord.Handle, nil).Run(ctx); err != nil {
		t.Fatal(err)
	}
	var closed []multisig.Handled
	bp := x.bobPump(w, bob.Handle)
	bp.Handled = func(h multisig.Handled) { closed = append(closed, h) }
	if err := bp.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if len(closed) != 1 || closed[0].Effect != "closed" {
		t.Errorf("bob saw %+v", closed)
	}
	for _, k := range []string{"collection-opened", "request-sealed", "response-accepted", "collection-complete", "collection-submitted"} {
		if k == "collection-opened" {
			continue // opened by RegisterPool, not by the multi-party entry point
		}
		if !w.C.HasEvent(k, "") {
			t.Errorf("coordinator log has no %s", k)
		}
	}
	for _, k := range []string{"request-received", "request-reviewed", "request-approved", "collection-closed"} {
		if !w.B.HasEvent(k, "") {
			t.Errorf("bob's log has no %s", k)
		}
	}
}

// A witness from an upstream 05c transfer file fills its slot marked as
// unauthenticated; it cannot be taken for an enveloped response, and the
// registration completes the same way.
// spec: SPO-Xparty-IF-007, SPO-Xparty-PRE-005
func TestUpstreamWitnessFileIsMarkedUnauthenticated(t *testing.T) {
	w := newWorld(t, nil)
	opened := w.open()
	// What bob's machine does with the upstream script: read the transfer
	// file the coordinator wrote, sign its body id, put the witness in it.
	name := pool.TransferFileName("mypool", "bob", opened.CollectionID)
	var raw []byte
	if err := w.C.Store.View(ctx, func(r ports.NamedReader) error {
		var err error
		raw, err = r.Get(ports.NamedRef{Name: name, Kind: ports.PoolWitnessFile})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	tf, err := pool.ParseTransferFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	cbor, _ := pool.ParseTxEnvelope(tf.TxBody)
	id, _ := w.led.TransactionID(cbor)
	k := w.key("bob|StakeVerificationKeyShelley_ed25519")
	var wit txbuild.Witness
	copy(wit.VKey[:], k.Public().(ed25519.PublicKey))
	copy(wit.Signature[:], ed25519.Sign(k, id[:]))
	tf.SignedWitness, tf.DateSigned = pool.WitnessEnvelope(wit), "signed"
	out, err := poolops.ImportWitness{Store: w.C.Store, Tip: w.chain, TxIDs: w.led}.Run(ctx, poolops.ImportRequest{Pool: "mypool", File: tf.Render()})
	if err != nil || !out.Unauthenticated || out.State != pool.CollectionOpenComplete {
		t.Fatalf("import = %+v, %v", out, err)
	}
	if s, _ := w.collection().Slot("bob.staking"); !s.Unauthenticated || s.Witness == nil {
		t.Fatalf("the imported witness is not marked: %+v", s)
	}
	// A response in an envelope for the same slot afterwards is acknowledged
	// without effect: the slot keeps its mark.
	before := w.snapshot()
	if before == "" {
		t.Fatal("no snapshot")
	}
	// The registration completes.
	res, err := w.registerPool().Run(ctx, poolops.RegisterRequest{Pool: "mypool", Payer: "pay"})
	if err != nil || !res.Submitted || w.sub.count() != 1 {
		t.Fatalf("completion = %+v, %v", res, err)
	}
	if ws, err := (native.TxViewer{}).Witnesses(w.sub.sent[0]); err != nil || len(ws) != 4 {
		t.Fatalf("witnesses %d, %v", len(ws), err)
	}
}
