package envelope

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"os"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

var t0 = time.Unix(1_800_000_000, 0).UTC()

func det(seed byte) *rand.ChaCha8 {
	var s [32]byte
	s[0] = seed
	return rand.NewChaCha8(s)
}

func newID(t *testing.T, seed byte, label string) *Private {
	t.Helper()
	p, err := Generate(label, nil, t0, det(seed))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Destroy)
	return p
}

func enrolled(p *Private, name string, roles ...party.Role) party.Party {
	id := p.Identity()
	return party.Party{Identity: id, Fingerprint: id.Fingerprint(), Name: name, Roles: roles,
		Scope: party.Scope{Pools: []string{"pool1"}}, State: party.StateActive, EnrolledAt: t0}
}

func lookupOf(ps ...party.Party) LookupFunc {
	return func(fp party.Fingerprint) (party.Party, bool) {
		for _, p := range ps {
			if p.Fingerprint == fp {
				return p, true
			}
		}
		return party.Party{}, false
	}
}

func sampleRequest() party.SigningRequest {
	return party.SigningRequest{
		Collection: party.CollectionID{1, 2, 3}, Slot: 2, KeyRole: "payment",
		KeyHash: [28]byte{9}, Operation: "witness", TxBody: []byte{0xa0}, BodyHash: [32]byte{7},
		TTLSlot: 1000, NetworkMagic: 764824073, Purpose: "register pool",
	}
}

func never(party.MessageID) (bool, error) { return false, nil }

func authorise(p party.Party, t party.Type, _ party.Body) error {
	return party.Authorise(p, t, party.Concern{})
}

// craft encrypts an arbitrary plaintext to recipient, for building envelopes
// that Seal would never produce.
func craft(t *testing.T, to party.Identity, plain []byte) []byte {
	t.Helper()
	r, err := ageRecipient(to.X25519)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	w, _ := age.Encrypt(&out, r)
	w.Write(plain)
	w.Close()
	return out.Bytes()
}

type payloadSpec struct {
	version   uint
	typ       string
	sender    party.Fingerprint
	recipient party.Fingerprint
	id        party.MessageID
	created   time.Time
	expires   time.Time
	body      []byte
}

func (s payloadSpec) bytes(t *testing.T) []byte {
	t.Helper()
	b, err := marshal(payloadWire{Version: s.version, Type: s.typ, Sender: s.sender[:], Recipient: s.recipient[:],
		ID: s.id[:], Created: s.created.Unix(), Expires: s.expires.Unix(), Body: s.body})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func goodSpec(t *testing.T, from, to *Private) payloadSpec {
	body, _ := encodeBody(sampleRequest())
	return payloadSpec{version: Version, typ: "SigningRequest", sender: from.Fingerprint(), recipient: to.Fingerprint(),
		id: party.MessageID{5}, created: t0, expires: t0.Add(time.Hour), body: body}
}

// sealed signs payload with signer and encrypts to the recipient.
func sealed(t *testing.T, signer *Private, to party.Identity, payload []byte) []byte {
	t.Helper()
	sig, err := signer.sign(signedBytes(payload))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := marshal(plaintextWire{Payload: payload, Signature: sig[:]})
	if err != nil {
		t.Fatal(err)
	}
	return craft(t, to, plain)
}

// spec: SPO-Xparty-OUT-002, SPO-Xparty-OUT-003, SPO-Xparty-INV-006
func TestRoundTrip(t *testing.T) {
	a, b := newID(t, 1, "a"), newID(t, 2, "b")
	exp := t0.Add(time.Hour)
	env, id, err := Seal(a, b.Identity(), sampleRequest(), t0, exp, det(9))
	if err != nil {
		t.Fatal(err)
	}
	o, err := Open(b, env, lookupOf(enrolled(a, "a", party.RoleCoordinator)), t0)
	if err != nil {
		t.Fatal(err)
	}
	if o.ID() != id || o.Type() != party.TypeSigningRequest || o.Sender().Name != "a" || !o.Expires().Equal(exp) || !o.Created().Equal(t0) {
		t.Fatalf("opened = %+v", o)
	}
	body, err := o.Admit(never, authorise)
	if err != nil {
		t.Fatal(err)
	}
	if got := body.(party.SigningRequest); got.Purpose != "register pool" || got.Slot != 2 || got.TTLSlot != 1000 {
		t.Fatalf("body = %+v", got)
	}
	// The ciphertext is randomised.
	env2, _, _ := Seal(a, b.Identity(), sampleRequest(), t0, exp, det(9))
	if bytes.Equal(env, env2) {
		t.Fatal("two seals of one message are identical")
	}
}

// spec: SPO-Xparty-OUT-002
func TestAllMessageTypesRoundTrip(t *testing.T) {
	a, b := newID(t, 1, "a"), newID(t, 2, "b")
	bodies := []party.Body{
		sampleRequest(),
		party.SigningResponse{Collection: party.CollectionID{1}, Slot: 1, Request: party.MessageID{2}, Witness: []byte{0x82, 0x40, 0x40}},
		party.SigningRefusal{Collection: party.CollectionID{1}, Slot: 1, Request: party.MessageID{2}, Reason: party.RefuseDeclined},
		party.CollectionClosed{Collection: party.CollectionID{1}, Outcome: party.OutcomeSubmitted, TxID: bytes.Repeat([]byte{4}, 32)},
		party.CollectionClosed{Collection: party.CollectionID{1}, Outcome: party.OutcomeDiscarded},
		party.Invite{Address: "tcAbC", Node: party.NodeKey{3}},
		party.Bundle{Snapshot: []byte{1}, Transactions: [][]byte{{2}}, Attachments: []party.Attachment{{Name: "x.json", Data: []byte{3}}}},
		party.Bundle{},
	}
	for _, in := range bodies {
		env, _, err := Seal(a, b.Identity(), in, t0, t0.Add(time.Minute), det(1))
		if err != nil {
			t.Fatalf("%s: seal: %v", in.Type(), err)
		}
		o, err := Open(b, env, lookupOf(enrolled(a, "a")), t0)
		if err != nil {
			t.Fatalf("%s: open: %v", in.Type(), err)
		}
		out, err := o.Admit(never, func(party.Party, party.Type, party.Body) error { return nil })
		if err != nil {
			t.Fatalf("%s: admit: %v", in.Type(), err)
		}
		re1, _ := encodeBody(in)
		re2, _ := encodeBody(out)
		if !bytes.Equal(re1, re2) {
			t.Fatalf("%s: body changed in transit", in.Type())
		}
	}
}

// The age recipient and identity we build from raw keys are the same key.
func TestAgeKeyConsistency(t *testing.T) {
	a := newID(t, 1, "a")
	id, err := a.ageIdentity()
	if err != nil {
		t.Fatal(err)
	}
	r, err := ageRecipient(a.Identity().X25519)
	if err != nil {
		t.Fatal(err)
	}
	if id.Recipient().String() != r.String() {
		t.Fatal("age identity and recipient built from raw keys disagree")
	}
}

// spec: SPO-Xparty-PRE-002
func TestRefusalOrder(t *testing.T) {
	a, b, c := newID(t, 1, "a"), newID(t, 2, "b"), newID(t, 3, "c")
	known := lookupOf(enrolled(a, "a", party.RoleCoordinator))
	now := t0.Add(time.Minute)
	good := goodSpec(t, a, b)

	revoked := enrolled(a, "a", party.RoleCoordinator)
	revoked.State = party.StateRevoked

	tamper := func(env party.Identity, p payloadSpec, signer *Private) []byte {
		return sealed(t, signer, env, p.bytes(t))
	}
	badSig := func() []byte {
		p := good.bytes(t)
		sig, _ := a.sign(signedBytes(p))
		sig[0] ^= 1
		plain, _ := marshal(plaintextWire{Payload: p, Signature: sig[:]})
		return craft(t, b.Identity(), plain)
	}()
	v2 := good
	v2.version = 2
	other := good
	other.recipient = c.Fingerprint()
	expired := good
	expired.expires = t0
	future := good
	future.created = now.Add(11 * time.Minute)
	future.expires = future.created.Add(time.Hour)
	// Two defects: unknown sender and a bad signature; the earlier step wins.
	unknownBadSig := func() []byte {
		spec := good
		spec.sender = c.Fingerprint()
		return sealed(t, a, b.Identity(), spec.bytes(t)) // signed by a, claims c
	}()
	// Two defects: wrong recipient and expired.
	wrongAndExpired := other
	wrongAndExpired.expires = t0

	plainGarbage := craft(t, b.Identity(), []byte("not cbor"))
	trailing := func() []byte {
		p := good.bytes(t)
		sig, _ := a.sign(signedBytes(p))
		plain, _ := marshal(plaintextWire{Payload: p, Signature: sig[:]})
		return craft(t, b.Identity(), append(plain, 0))
	}()

	tests := []struct {
		name   string
		env    []byte
		lookup LookupFunc
		want   error
	}{
		{"too large", make([]byte, party.MaxEnvelopeBytes+1), known, ErrTooLarge},
		{"empty", nil, known, ErrTooLarge},
		{"not decryptable", craft(t, c.Identity(), []byte{}), known, ErrDecrypt},
		{"plaintext not CBOR", plainGarbage, known, ErrMalformed},
		{"trailing bytes", trailing, known, ErrMalformed},
		{"unknown version", tamper(b.Identity(), v2, a), known, ErrVersion},
		{"unknown sender", tamper(b.Identity(), good, a), lookupOf(), ErrSenderUnknown},
		{"revoked sender", tamper(b.Identity(), good, a), lookupOf(revoked), ErrSenderRevoked},
		{"bad signature", badSig, known, ErrSignature},
		{"signed by another key", tamper(b.Identity(), good, c), known, ErrSignature},
		{"other recipient", tamper(b.Identity(), other, a), known, ErrNotRecipient},
		{"expired", tamper(b.Identity(), expired, a), known, ErrExpired},
		{"from the future", tamper(b.Identity(), future, a), known, ErrFromFuture},
		{"unknown sender before signature", unknownBadSig, known, ErrSenderUnknown},
		{"recipient before expiry", tamper(b.Identity(), wrongAndExpired, a), known, ErrNotRecipient},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o, err := Open(b, tc.env, tc.lookup, now)
			if o != nil || !errors.Is(err, tc.want) {
				t.Fatalf("Open = %v, %v; want %v", o, err, tc.want)
			}
			if got := Outward(err); got != nil {
				t.Fatalf("Outward = %q, want nothing", got)
			}
		})
	}
}

// A refusal records the sender only once the sender is established.
// spec: SPO-Xparty-INV-006
func TestAuditSender(t *testing.T) {
	a, b := newID(t, 1, "a"), newID(t, 2, "b")
	good := goodSpec(t, a, b)
	envUnknown := sealed(t, a, b.Identity(), good.bytes(t))
	_, err := Open(b, envUnknown, lookupOf(), t0)
	if _, _, known := Audit(err); known {
		t.Fatal("sender recorded before it was established")
	}
	expired := good
	expired.expires = t0.Add(-time.Hour)
	_, err = Open(b, sealed(t, a, b.Identity(), expired.bytes(t)), lookupOf(enrolled(a, "a")), t0)
	reason, sender, known := Audit(err)
	if !known || sender != a.Fingerprint() || !strings.Contains(reason, "expired") {
		t.Fatalf("Audit = %q, %v, %v", reason, sender, known)
	}
}

// spec: SPO-Xparty-INV-008
func TestSizeLimit(t *testing.T) {
	a, b := newID(t, 1, "a"), newID(t, 2, "b")
	big := party.Bundle{Snapshot: make([]byte, party.MaxEnvelopeBytes)}
	if _, _, err := Seal(a, b.Identity(), big, t0, t0.Add(time.Hour), det(1)); err == nil {
		t.Fatal("sealed an oversize bundle")
	}
	// Just under the limit works end to end.
	ok := party.Bundle{Snapshot: make([]byte, party.MaxEnvelopeBytes-4096)}
	env, _, err := Seal(a, b.Identity(), ok, t0, t0.Add(time.Hour), det(1))
	if err != nil {
		t.Fatal(err)
	}
	if len(env) > party.MaxEnvelopeBytes {
		t.Fatal("envelope over the limit")
	}
	if _, err := Open(b, env, lookupOf(enrolled(a, "a")), t0); err != nil {
		t.Fatal(err)
	}
}

// spec: SPO-Xparty-PRE-002, SPO-Xparty-INV-007, SPO-Xparty-INV-010
func TestAdmitOrder(t *testing.T) {
	a, b := newID(t, 1, "a"), newID(t, 2, "b")
	// a is a signer only: not authorised to send a SigningRequest.
	env, _, _ := Seal(a, b.Identity(), sampleRequest(), t0, t0.Add(time.Hour), det(1))
	o, err := Open(b, env, lookupOf(enrolled(a, "a", party.RoleSigner)), t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.Admit(never, authorise); !errors.Is(err, party.ErrNotAuthorised) {
		t.Fatalf("Admit = %v, want not authorised", err)
	}
	// Replay is checked before authorisation: a replayed and unauthorised
	// message is a replay.
	seen := func(party.MessageID) (bool, error) { return true, nil }
	if _, err := o.Admit(seen, authorise); !errors.Is(err, ErrReplayed) {
		t.Fatalf("Admit = %v, want replayed", err)
	}
	// A failing store is not a refusal.
	boom := errors.New("store down")
	if _, err := o.Admit(func(party.MessageID) (bool, error) { return false, boom }, authorise); !errors.Is(err, boom) {
		t.Fatalf("Admit = %v", err)
	}
	// A body that does not validate is refused after the replay check.
	spec := goodSpec(t, a, b)
	spec.typ = "Bogus"
	o2, err := Open(b, sealed(t, a, b.Identity(), spec.bytes(t)), lookupOf(enrolled(a, "a", party.RoleCoordinator)), t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o2.Admit(never, authorise); !errors.Is(err, ErrUnknownType) {
		t.Fatalf("Admit = %v, want unknown type", err)
	}
}

// spec: SPO-Xparty-INV-003, SPO-Xparty-PRE-001
func TestDocument(t *testing.T) {
	node := party.NodeKey{7}
	p, err := Generate("alice's laptop", &node, t0, det(1))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Destroy()
	b, err := EncodeDocument(p)
	if err != nil {
		t.Fatal(err)
	}
	d, err := ParseDocument(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Verify(); err != nil {
		t.Fatal(err)
	}
	if d.Identity.Label != "alice's laptop" || d.Identity.Node == nil || *d.Identity.Node != node || d.Identity.Fingerprint() != p.Fingerprint() {
		t.Fatalf("identity = %+v", d.Identity)
	}
	// Tampering with the content breaks the signature.
	var w documentWire
	if err := unmarshal(b, &w); err != nil {
		t.Fatal(err)
	}
	w.Content[len(w.Content)-1] ^= 1
	b2, _ := marshal(w)
	if d2, err := ParseDocument(b2); err == nil && d2.Verify() == nil {
		t.Fatal("tampered document verified")
	}
	// A document signed by another key does not verify as the claimed one.
	q, _ := Generate("mallory", nil, t0, det(2))
	defer q.Destroy()
	w2 := documentWire{Content: w.Content}
	w2.Content[len(w2.Content)-1] ^= 1 // restore
	sig, _ := q.sign(party.DocumentMessage(w2.Content))
	w2.Signature = sig[:]
	b3, _ := marshal(w2)
	d3, err := ParseDocument(b3)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(d3.Verify(), party.ErrDocumentSignature) {
		t.Fatal("document signed by another key verified")
	}
	// Strictness.
	for name, bad := range map[string][]byte{
		"trailing":  append(append([]byte{}, b...), 0),
		"empty":     nil,
		"truncated": b[:len(b)-1],
	} {
		if _, err := ParseDocument(bad); err == nil {
			t.Fatalf("%s: parsed", name)
		}
	}
	// Unknown version, wrong key length, wrong array length.
	for name, wire := range map[string]any{
		"version":  identityWire{Version: 2, Label: "x", Ed25519: bytes.Repeat([]byte{1}, 32), X25519: bytes.Repeat([]byte{1}, 32), Created: 1},
		"keylen":   identityWire{Version: 1, Label: "x", Ed25519: []byte{1}, X25519: bytes.Repeat([]byte{1}, 32), Created: 1},
		"label":    identityWire{Version: 1, Label: "x\x1b[2J", Ed25519: bytes.Repeat([]byte{1}, 32), X25519: bytes.Repeat([]byte{1}, 32), Created: 1},
		"fiveitem": []any{1, "x", []byte{}, []byte{}, nil},
	} {
		content, _ := marshal(wire)
		doc, _ := marshal(documentWire{Content: content, Signature: make([]byte, 64)})
		if _, err := ParseDocument(doc); err == nil {
			t.Fatalf("%s: parsed", name)
		}
	}
}

func TestNewPrivateChecksKeys(t *testing.T) {
	a, b := newID(t, 1, "a"), newID(t, 2, "b")
	var raw [KeysLen]byte
	a.keys.Use(func(k []byte) error { copy(raw[:], k); return nil })
	again, err := newPrivateFromBytes(raw[:], a.Identity())
	if err != nil {
		t.Fatal(err)
	}
	again.Destroy()
	if _, err := newPrivateFromBytes(raw[:], b.Identity()); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("err = %v", err)
	}
}

func TestWitness(t *testing.T) {
	var vk [32]byte
	var sig [64]byte
	vk[0], sig[0] = 1, 2
	b, err := EncodeWitness(vk, sig)
	if err != nil {
		t.Fatal(err)
	}
	gv, gs, err := DecodeWitness(b)
	if err != nil || gv != vk || gs != sig {
		t.Fatal(gv, gs, err)
	}
	for name, bad := range map[string][]byte{"trailing": append(append([]byte{}, b...), 0), "short": b[:10], "empty": nil} {
		if _, _, err := DecodeWitness(bad); err == nil {
			t.Fatalf("%s decoded", name)
		}
	}
	short, _ := marshal(witnessWire{Key: vk[:31], Sig: sig[:]})
	if _, _, err := DecodeWitness(short); err == nil {
		t.Fatal("31-byte key decoded")
	}
}

type vectors struct {
	FingerprintA string `json:"fingerprint_a"`
	DocumentA    string `json:"document_a"`
	MessageID    string `json:"message_id"`
	Payload      string `json:"payload"`
	Signature    string `json:"signature"`
	Plaintext    string `json:"plaintext"`
}

// Fixed inputs, fixed outputs. The age ciphertext is random, so the vector
// is the plaintext and the signature; the encryption is round-tripped above.
// spec: SPO-Xparty-INV-002, SPO-Xparty-INV-003, SPO-Xparty-OUT-002, SPO-Xparty-OUT-003
func TestVectors(t *testing.T) {
	node := party.NodeKey{0x11}
	a, err := Generate("alice", &node, t0, det(1))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Destroy()
	b := newID(t, 2, "bob")
	doc, err := EncodeDocument(a)
	if err != nil {
		t.Fatal(err)
	}
	var id party.MessageID
	det(9).Read(id[:])
	payload, sig, plain, err := buildPlaintext(a, b.Fingerprint(), sampleRequest(), id, t0, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	got := vectors{a.Fingerprint().String(), hex.EncodeToString(doc), hex.EncodeToString(id[:]),
		hex.EncodeToString(payload), hex.EncodeToString(sig[:]), hex.EncodeToString(plain)}
	const path = "testdata/vectors.json"
	if os.Getenv("UPDATE_VECTORS") == "1" {
		out, _ := json.MarshalIndent(got, "", "  ")
		if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var want vectors
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("vectors differ:\n got %+v\nwant %+v", got, want)
	}
	// The committed signature verifies with a plain Ed25519 implementation.
	pub := a.Identity().Ed25519
	pl, _ := hex.DecodeString(want.Payload)
	sg, _ := hex.DecodeString(want.Signature)
	if !ed25519.Verify(pub[:], append([]byte("spo/envelope/v1"), pl...), sg) {
		t.Fatal("committed signature does not verify")
	}
	// And the committed document parses and verifies.
	db, _ := hex.DecodeString(want.DocumentA)
	d, err := ParseDocument(db)
	if err != nil || d.Verify() != nil || d.Identity.Fingerprint().String() != want.FingerprintA {
		t.Fatal("committed document", err)
	}
}

func newPrivateFromBytes(raw []byte, id party.Identity) (*Private, error) {
	keys, err := secret.Fill(len(raw), func(b []byte) error { copy(b, raw); return nil })
	if err != nil {
		return nil, err
	}
	return NewPrivate(keys, id)
}
