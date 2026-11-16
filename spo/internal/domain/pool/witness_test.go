package pool

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
)

type signer struct {
	priv ed25519.PrivateKey
}

func newSigner() signer {
	_, p, _ := ed25519.GenerateKey(nil)
	return signer{p}
}

func (s signer) hash() txbuild.KeyHash { return txbuild.HashKey(s.priv.Public().(ed25519.PublicKey)) }

func (s signer) witness(body txbuild.TxBody) txbuild.Witness {
	var w txbuild.Witness
	copy(w.VKey[:], s.priv.Public().(ed25519.PublicKey))
	copy(w.Signature[:], ed25519.Sign(s.priv, body.ID[:]))
	return w
}

type rig struct {
	cold, pay, owner signer
	body             txbuild.TxBody
	c                Collection
}

func newRig(t *testing.T) rig {
	t.Helper()
	r := rig{cold: newSigner(), pay: newSigner(), owner: newSigner()}
	cbor := []byte("a transaction body")
	r.body = txbuild.TxBody{CBOR: cbor, ID: sha256.Sum256(cbor)}
	c, err := OpenCollection(Collection{ID: 1700000000, Type: PoolRegistration, TTL: 1000, PayName: "pay", PayAmount: 505_000_000, PayReturn: 100,
		Body: r.body, Slots: []Slot{
			{Name: "mypool.node", Role: custody.RolePoolCold, KeyHash: r.cold.hash(), Holder: custody.HolderVault},
			{Name: "pay", Role: custody.RolePayment, KeyHash: r.pay.hash(), Holder: custody.HolderVault},
			{Name: "alice.staking", Role: custody.RoleStake, KeyHash: r.owner.hash(), Holder: custody.HolderRemote, Party: "external"},
		}})
	if err != nil {
		t.Fatal(err)
	}
	r.c = c
	return r
}

func (r rig) fill(t *testing.T, c Collection, slot string, s signer, tip uint64) (Collection, error) {
	t.Helper()
	return c.Fill(Fill{Slot: slot, Witness: s.witness(r.body), ExpectVersion: c.Version}, tip)
}

// spec: SPO-05c-INV-001, SPO-05c-INV-003, SPO-05c-INV-005, SPO-05c-OUT-002, SPO-Xparty-PRE-003
func TestOpeningACollection(t *testing.T) {
	r := newRig(t)
	if r.c.Version != 1 || r.c.State(10) != CollectionOpenIncomplete || len(r.c.Missing()) != 3 {
		t.Fatalf("%+v", r.c)
	}
	if got := strings.Join(r.c.Missing(), ","); got != "mypool.node,pay,alice.staking" {
		t.Errorf("slot order %s", got)
	}
	bad := []func(c *Collection){
		func(c *Collection) { c.ID = 0 },
		func(c *Collection) { c.Type = "x" },
		func(c *Collection) { c.Body = txbuild.TxBody{} },
		func(c *Collection) { c.Slots = nil },
		func(c *Collection) { c.Slots = append(c.Slots, c.Slots[0]) },
		func(c *Collection) { w := txbuild.Witness{}; c.Slots[0].Witness = &w },
		func(c *Collection) { c.Slots[1].Name = "" },
	}
	for i, f := range bad {
		c := Collection{ID: 1, Type: PoolRegistration, Body: r.body, Slots: []Slot{{Name: "a"}, {Name: "b"}}}
		f(&c)
		if _, err := OpenCollection(c); !errors.Is(err, ErrBadCollection) {
			t.Errorf("case %d: %v", i, err)
		}
	}
}

// spec: SPO-05d-INV-006, SPO-05d-SEC-003, SPO-Xparty-PRE-005
func TestFillVerifiesBeforeTouchingTheSlot(t *testing.T) {
	r := newRig(t)
	other := newSigner()
	cases := []struct {
		name string
		fill Fill
		want error
	}{
		{"a witness of another key", Fill{Slot: "pay", Witness: other.witness(r.body), ExpectVersion: 1}, txbuild.ErrWitnessKey},
		{"the cold key's witness in the payer's slot", Fill{Slot: "pay", Witness: r.cold.witness(r.body), ExpectVersion: 1}, txbuild.ErrWitnessKey},
		{"a signature over another body", Fill{Slot: "pay", Witness: r.pay.witness(txbuild.TxBody{ID: chain.TxID{9}}), ExpectVersion: 1}, txbuild.ErrWitnessSignature},
		{"a corrupted signature", func() Fill {
			w := r.pay.witness(r.body)
			w.Signature[3] ^= 1
			return Fill{Slot: "pay", Witness: w, ExpectVersion: 1}
		}(), txbuild.ErrWitnessSignature},
		{"an unknown slot", Fill{Slot: "ghost", Witness: r.pay.witness(r.body), ExpectVersion: 1}, ErrUnknownSlot},
		{"a stale version", Fill{Slot: "pay", Witness: r.pay.witness(r.body), ExpectVersion: 7}, ErrVersionConflict},
	}
	for _, c := range cases {
		got, err := r.c.Fill(c.fill, 10)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
		if got.Version != 1 || len(got.Missing()) != 3 {
			t.Errorf("%s: the collection changed", c.name)
		}
	}
	// The input is never mutated: a fill returns a new collection.
	next, err := r.fill(t, r.c, "pay", r.pay, 10)
	if err != nil || next.Version != 2 || len(r.c.Missing()) != 3 || len(next.Missing()) != 2 {
		t.Fatalf("%v %+v", err, next)
	}
}

// spec: SPO-Xparty-INV-014
func TestFillIsACompareAndSet(t *testing.T) {
	r := newRig(t)
	a, err := r.fill(t, r.c, "pay", r.pay, 10)
	if err != nil {
		t.Fatal(err)
	}
	// A second response read from the same version loses.
	if _, err := r.fill(t, r.c, "mypool.node", r.cold, 10); err != nil {
		t.Fatal(err) // it is a different slot on the same base: the base is version 1
	}
	if _, err := r.c.Fill(Fill{Slot: "pay", Witness: r.pay.witness(r.body), ExpectVersion: a.Version - 1}, 10); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Fill(Fill{Slot: "pay", Witness: r.pay.witness(r.body), ExpectVersion: 1}, 10); !errors.Is(err, ErrVersionConflict) {
		t.Errorf("stale: %v", err)
	}
	// The same slot again at the current version: refused unless overwrite is confirmed.
	if _, err := a.Fill(Fill{Slot: "pay", Witness: r.pay.witness(r.body), ExpectVersion: a.Version}, 10); !errors.Is(err, ErrSlotFilled) {
		t.Errorf("filled: %v", err)
	}
	if b, err := a.Fill(Fill{Slot: "pay", Witness: r.pay.witness(r.body), ExpectVersion: a.Version, Overwrite: true}, 10); err != nil || b.Version != 3 {
		t.Errorf("overwrite: %v", err)
	}
}

// spec: SPO-05d-INV-003, SPO-Xparty-INV-015, SPO-05c-INV-008
func TestStatesAndExpiry(t *testing.T) {
	r := newRig(t)
	if r.c.State(1000) != CollectionOpenIncomplete || r.c.State(1001) != CollectionExpired {
		t.Error("the window is open while ttl >= tip: equal is accepted")
	}
	c, _ := r.fill(t, r.c, "mypool.node", r.cold, 10)
	c, _ = r.fill(t, c, "pay", r.pay, 10)
	if c.State(10) != CollectionOpenIncomplete {
		t.Error("one slot is still empty")
	}
	c, err := r.fill(t, c, "alice.staking", r.owner, 10)
	if err != nil || c.State(10) != CollectionOpenComplete {
		t.Fatalf("%v %s", err, c.State(10))
	}
	ws, err := c.Witnesses()
	if err != nil || len(ws) != 3 {
		t.Fatalf("%v", err)
	}
	if _, err := r.c.Witnesses(); err == nil {
		t.Error("witnesses of an incomplete collection")
	}
	// Expired: no response is accepted and nothing assembles.
	if _, err := r.fill(t, r.c, "pay", r.pay, 1001); !errors.Is(err, ErrCollectionNotOpen) {
		t.Errorf("expired: %v", err)
	}
	if c.State(1001) != CollectionExpired {
		t.Error("a complete collection expires too")
	}
	// Submitted and Discarded are terminal and accept no response.
	for _, end := range []CollectionState{CollectionSubmitted, CollectionDiscarded} {
		closed, err := c.Close(end)
		if err != nil || closed.State(10) != end {
			t.Errorf("close %s: %v", end, err)
		}
		if _, err := r.fill(t, closed, "pay", r.pay, 10); !errors.Is(err, ErrCollectionNotOpen) {
			t.Errorf("%s accepted a fill: %v", end, err)
		}
	}
	if _, err := c.Close(CollectionOpenComplete); err == nil {
		t.Error("closed as open")
	}
}

// spec: SPO-05c-OUT-002, SPO-05c-INV-003, SPO-05c-INV-001, SPO-05c-SEC-003
func TestCollectionRoundTripsThroughTheDescriptor(t *testing.T) {
	r := newRig(t)
	c, _ := r.fill(t, r.c, "pay", r.pay, 10)
	c.HardwareWalletIncluded, c.MetadataFiles = true, `"a.json"`
	d := parse(t, goodDescriptor)
	d.SetCollection(c)
	idOf := func(cbor []byte) (chain.TxID, error) { return sha256.Sum256(cbor), nil }
	got, err := parse(t, string(d.Render())).Collection(idOf)
	if err != nil || got == nil {
		t.Fatal(err)
	}
	if got.ID != c.ID || got.Type != c.Type || got.TTL != c.TTL || got.PayName != "pay" || got.PayAmount != 505_000_000 || got.PayReturn != 100 ||
		!got.HardwareWalletIncluded || got.MetadataFiles != `"a.json"` || got.Version != c.Version || got.Body.ID != c.Body.ID || string(got.Body.CBOR) != string(c.Body.CBOR) {
		t.Errorf("%+v", got)
	}
	if len(got.Slots) != 3 || got.Slots[0].Name != "mypool.node" || got.Slots[1].Witness == nil || *got.Slots[1].Witness != *c.Slots[1].Witness ||
		got.Slots[2].Witness != nil || got.Slots[2].Party != "external" || got.Slots[2].KeyHash != r.owner.hash() || got.Slots[2].Role != custody.RoleStake {
		t.Errorf("%+v", got.Slots)
	}
	// The keys of upstream's collection come first, in the order its updates leave them.
	out := string(d.Render())
	prev := -1
	for _, k := range []string{`"id"`, `"type"`, `"ttl"`, `"regPayName"`, `"txBody"`, `"witnesses"`, `"regPayAmount"`, `"regPayReturn"`, `"hardwareWalletIncluded"`, `"metadataFilesList"`} {
		i := strings.Index(out, k)
		if i <= prev {
			t.Errorf("%s out of order in\n%s", k, out)
		}
		prev = i
	}
	// A body hash that does not match the stored body is refused: it is recomputed, not trusted.
	wrong := func([]byte) (chain.TxID, error) { return chain.TxID{1}, nil }
	if _, err := parse(t, string(d.Render())).Collection(wrong); !errors.Is(err, ErrBadCollection) {
		t.Errorf("a mismatched body hash: %v", err)
	}
	// No collection: absent, null, {} and id 0 all mean none (SPO-05d-IN-002).
	for _, v := range []string{"", "null", "{}", `{"id": 0}`} {
		dd := parse(t, goodDescriptor)
		if v != "" {
			dd.doc.set(FieldRegWitness, []byte(v))
		}
		if c, err := dd.Collection(idOf); c != nil || err != nil {
			t.Errorf("%q: %v %v", v, c, err)
		}
	}
	d.ClearCollection()
	if d.Has(FieldRegWitness) {
		t.Error("cleared")
	}
}

// spec: SPO-05c-OUT-003, SPO-Pfiles-OUT-023, SPO-05d-IN-001, SPO-05d-INV-005, SPO-05d-INV-004
func TestTransferFile(t *testing.T) {
	r := newRig(t)
	vk := []byte(`{"type": "StakeVerificationKeyShelley_ed25519", "description": "", "cborHex": "5820aa"}`)
	tf, err := NewTransferFile(r.c, "alice.staking", "mypool", "MYPL", "Tue, 14 Nov 2023 22:13:20 +0000", vk)
	if err != nil {
		t.Fatal(err)
	}
	if tf.Name() != "mypool_alice_1700000000" || TransferFileName("mypool", "mypool.node", 5) != "mypool_mypool.node_5" || TransferFileName("m", "pay", 5) != "m_pay_5" {
		t.Errorf("names %s", tf.Name())
	}
	out := string(tf.Render())
	prev := -1
	for _, k := range []string{`"id": 1700000000`, `"date-created"`, `"ttl": 1000`, `"type": "PoolRegistration"`, `"metadataFilesList"`, `"poolFile": "mypool"`,
		`"poolMetaTicker": "MYPL"`, `"signing-name": "alice.staking"`, `"signing-vkey": {`, `"txBody": {`, `"signedWitness": {}`, `"date-signed": {}`} {
		i := strings.Index(out, k)
		if i <= prev {
			t.Errorf("%s missing or out of order in\n%s", k, out)
		}
		prev = i
	}
	if tf.Signed() {
		t.Error("an unsigned file reads as signed")
	}
	back, err := ParseTransferFile([]byte(out))
	if err != nil || back.ID != tf.ID || back.SigningName != "alice.staking" || back.Signed() {
		t.Fatalf("%+v %v", back, err)
	}
	if err := back.Matches(r.c); err != nil {
		t.Errorf("a file of the collection: %v", err)
	}
	// Signed in place: the witness and the date.
	back.SignedWitness = WitnessEnvelope(r.owner.witness(r.body))
	back.DateSigned = "now"
	signed, err := ParseTransferFile(back.Render())
	if err != nil || !signed.Signed() || signed.DateSigned != "now" {
		t.Fatalf("%v", err)
	}
	w, err := ParseWitnessEnvelope(signed.SignedWitness)
	if err != nil || w != r.owner.witness(r.body) {
		t.Errorf("the witness does not survive the file: %v", err)
	}
	// What does not belong to the collection.
	mism := []func(*TransferFile){
		func(f *TransferFile) { f.ID++ },
		func(f *TransferFile) { f.Type = PoolReRegistration },
		func(f *TransferFile) { f.TxBody = []byte(`{"type":"Tx ConwayEra","description":"","cborHex":"00"}`) },
		func(f *TransferFile) { f.SigningName = "ghost.staking" },
	}
	for i, m := range mism {
		f := signed
		m(&f)
		if err := f.Matches(r.c); err == nil {
			t.Errorf("mismatch %d accepted", i)
		}
	}
	if _, err := NewTransferFile(r.c, "ghost", "mypool", "T", "d", vk); !errors.Is(err, ErrUnknownSlot) {
		t.Errorf("%v", err)
	}
	if _, err := ParseTransferFile([]byte(`{"id": 0}`)); err == nil {
		t.Error("id 0")
	}
}

func TestWitnessEnvelopeIsCardanoCLIs(t *testing.T) {
	r := newRig(t)
	w := r.pay.witness(r.body)
	env := string(WitnessEnvelope(w))
	if !strings.Contains(env, `"type": "TxWitness ConwayEra"`) || !strings.Contains(env, `"description": "Key Witness ShelleyEra"`) || !strings.Contains(env, `"cborHex": "825820`) {
		t.Errorf("%s", env)
	}
	for _, bad := range []string{"", "{}", `{"type":"TxWitness ConwayEra","description":"","cborHex":"00"}`,
		`{"type":"Certificate","description":"","cborHex":"825820` + strings.Repeat("00", 32) + `5840` + strings.Repeat("00", 64) + `"}`} {
		if _, err := ParseWitnessEnvelope([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
