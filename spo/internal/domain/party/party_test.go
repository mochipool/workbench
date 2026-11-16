package party

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"
)

var t0 = time.Unix(1_800_000_000, 0).UTC()

type keyset struct {
	priv ed25519.PrivateKey
	id   Identity
}

func mk(seed byte, label string) keyset {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	id := Identity{Label: label, Created: t0}
	copy(id.Ed25519[:], priv[32:])
	id.X25519 = X25519Public{seed, 1}
	return keyset{priv, id}
}

// doc builds a document the way adapters/envelope does, with the content a
// stand-in byte string: Verify only covers the signature over Content.
func (k keyset) doc(content string) Document {
	d := Document{Identity: k.id, Content: []byte(content)}
	copy(d.Signature[:], ed25519.Sign(k.priv, DocumentMessage(d.Content)))
	return d
}

func typed(fp Fingerprint) string { return fp.String()[:19] } // four groups: "xxxx-xxxx-xxxx-xxxx"

// spec: SPO-Xparty-INV-002
func TestFingerprint(t *testing.T) {
	k := mk(1, "a")
	fp := k.id.Fingerprint()
	// Reference computation, independent of FingerprintOf.
	h, _ := blake2b.New256(nil)
	h.Write([]byte("spo/party/v1"))
	h.Write(k.id.Ed25519[:])
	h.Write(k.id.X25519[:])
	if !bytes.Equal(fp[:], h.Sum(nil)[:20]) {
		t.Fatal("fingerprint is not the first 20 bytes of the hash")
	}
	s := fp.String()
	if len(s) != 8*4+7 || strings.Count(s, "-") != 7 || s != strings.ToLower(s) {
		t.Fatalf("display %q", s)
	}
	back, err := ParseFingerprint(s)
	if err != nil || back != fp {
		t.Fatalf("parse = %v, %v", back, err)
	}
	if back, err = ParseFingerprint(strings.ToUpper(strings.ReplaceAll(s, "-", " "))); err != nil || back != fp {
		t.Fatalf("parse with spaces and capitals = %v, %v", back, err)
	}
	for _, bad := range []string{"", s[:len(s)-1], s + "a", strings.Replace(s, s[:1], "1", 1)} {
		if _, err := ParseFingerprint(bad); err == nil {
			t.Fatalf("parsed %q", bad)
		}
	}
	// Changing either key changes the fingerprint; the order is fixed.
	other := k.id
	other.X25519[0]++
	if other.Fingerprint() == fp {
		t.Fatal("x25519 key not covered")
	}
	if FingerprintOf(Ed25519Public(k.id.X25519), X25519Public(k.id.Ed25519)) == fp {
		t.Fatal("order not covered")
	}
}

// spec: SPO-Xparty-PR-001
func TestConfirmPrefix(t *testing.T) {
	fp := mk(1, "a").id.Fingerprint()
	s := fp.String()
	for _, ok := range []string{s[:19], strings.ToUpper(s[:19]), strings.ReplaceAll(s[:19], "-", ""), " " + s[:19]} {
		if !ConfirmPrefix(fp, ok) {
			t.Fatalf("refused %q", ok)
		}
	}
	for _, bad := range []string{"", s[:4], s[:9], s[:14], s[:18], s, "aaaa-aaaa-aaaa-aaaa", s[:18] + "x"} {
		if ConfirmPrefix(fp, bad) {
			t.Fatalf("accepted %q", bad)
		}
	}
}

// spec: SPO-Xparty-PRE-001, SPO-Xparty-PR-001, SPO-Xparty-IF-002, SPO-Xparty-OUT-001
func TestEnroll(t *testing.T) {
	k := mk(1, "alice")
	good := Enrollment{Document: k.doc("c"), Name: "alice", Roles: []Role{RoleSigner, RoleCoordinator}, Pools: []string{"pool1"}, Confirmation: typed(k.id.Fingerprint())}
	p, err := Enroll(good, nil, t0)
	if err != nil {
		t.Fatal(err)
	}
	if p.State != StateActive || p.Fingerprint != k.id.Fingerprint() || p.Roles[0] != RoleCoordinator || !p.EnrolledAt.Equal(t0) {
		t.Fatalf("party = %+v", p)
	}

	bad := good
	bad.Document.Signature[0] ^= 1
	if _, err := Enroll(bad, nil, t0); !errors.Is(err, ErrDocumentSignature) {
		t.Fatalf("bad signature: %v", err)
	}
	// A document whose signature is by another key than it contains.
	m := mk(2, "mallory")
	forged := good
	copy(forged.Document.Signature[:], ed25519.Sign(m.priv, DocumentMessage(forged.Document.Content)))
	if _, err := Enroll(forged, nil, t0); !errors.Is(err, ErrDocumentSignature) {
		t.Fatalf("forged: %v", err)
	}
	// The signature is checked before the confirmation.
	both := bad
	both.Confirmation = ""
	if _, err := Enroll(both, nil, t0); !errors.Is(err, ErrDocumentSignature) {
		t.Fatalf("order: %v", err)
	}
	for name, c := range map[string]string{"empty": "", "wrong": "aaaa-aaaa", "one group": typed(k.id.Fingerprint())[:4], "full": k.id.Fingerprint().String()} {
		e := good
		e.Confirmation = c
		if _, err := Enroll(e, nil, t0); !errors.Is(err, ErrConfirmation) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for name, mut := range map[string]func(*Enrollment){
		"no roles":     func(e *Enrollment) { e.Roles = nil },
		"unknown role": func(e *Enrollment) { e.Roles = []Role{"root"} },
		"dup role":     func(e *Enrollment) { e.Roles = []Role{RoleSigner, RoleSigner} },
		"bad name":     func(e *Enrollment) { e.Name = "../x" },
		"empty name":   func(e *Enrollment) { e.Name = "" },
		"bad pool":     func(e *Enrollment) { e.Pools = []string{"a b"} },
	} {
		e := good
		mut(&e)
		if _, err := Enroll(e, nil, t0); !errors.Is(err, ErrInvalidEnrollment) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := Enroll(good, []Party{p}, t0); !errors.Is(err, ErrAlreadyEnrolled) {
		t.Fatalf("duplicate identity: %v", err)
	}
	k2 := mk(3, "bob")
	e2 := Enrollment{Document: k2.doc("c"), Name: "alice", Roles: []Role{RoleSigner}, Confirmation: typed(k2.id.Fingerprint())}
	if _, err := Enroll(e2, []Party{p}, t0); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("duplicate name: %v", err)
	}
	// An identity with a hostile label is refused.
	k3 := mk(4, "x\x1b]0;pwn\a")
	e3 := Enrollment{Document: k3.doc("c"), Name: "eve", Roles: []Role{RoleSigner}, Confirmation: typed(k3.id.Fingerprint())}
	if _, err := Enroll(e3, nil, t0); !errors.Is(err, ErrIdentity) {
		t.Fatalf("label: %v", err)
	}
}

// spec: SPO-Xparty-INV-005, SPO-Xparty-IF-003
func TestRevoke(t *testing.T) {
	k := mk(1, "a")
	p, _ := Enroll(Enrollment{Document: k.doc("c"), Name: "a", Roles: []Role{RoleCoordinator}, Confirmation: typed(k.id.Fingerprint())}, nil, t0)
	r, err := Revoke(p)
	if err != nil || r.Active() || p.State != StateActive {
		t.Fatal(r, err)
	}
	if _, err := Revoke(r); !errors.Is(err, ErrAlreadyRevoked) {
		t.Fatal(err)
	}
	if err := Authorise(r, TypeSigningRequest, Concern{}); !errors.Is(err, ErrNotAuthorised) {
		t.Fatalf("revoked party authorised: %v", err)
	}
}

// spec: SPO-Xparty-INV-010
func TestAuthorise(t *testing.T) {
	mkp := func(seed byte, roles []Role, pools ...string) Party {
		id := mk(seed, "p").id
		return Party{Identity: id, Fingerprint: id.Fingerprint(), Roles: roles, Pools: pools, State: StateActive}
	}
	coord := mkp(1, []Role{RoleCoordinator}, "poolA")
	signer := mkp(2, []Role{RoleSigner})
	machine := mkp(3, []Role{RoleMachine})
	other := mkp(4, []Role{RoleSigner})
	slot := Concern{SlotSigner: signer.Fingerprint, HasSlotSigner: true}
	tests := []struct {
		name   string
		p      Party
		t      Type
		c      Concern
		permit bool
	}{
		{"coordinator request for own pool", coord, TypeSigningRequest, Concern{Pool: "poolA"}, true},
		{"coordinator request for other pool", coord, TypeSigningRequest, Concern{Pool: "poolB"}, false},
		{"coordinator request with no pool", coord, TypeSigningRequest, Concern{}, true},
		{"coordinator closed", coord, TypeCollectionClosed, Concern{Pool: "poolA"}, true},
		{"coordinator closed other pool", coord, TypeCollectionClosed, Concern{Pool: "poolB"}, false},
		{"coordinator invite", coord, TypeInvite, Concern{}, true},
		{"signer request", signer, TypeSigningRequest, Concern{Pool: "poolA"}, false},
		{"machine invite", machine, TypeInvite, Concern{}, false},
		{"signer response for its slot", signer, TypeSigningResponse, slot, true},
		{"signer refusal for its slot", signer, TypeSigningRefusal, slot, true},
		{"signer response for another's slot", other, TypeSigningResponse, slot, false},
		{"signer response, slot unknown", signer, TypeSigningResponse, Concern{}, false},
		{"coordinator response", coord, TypeSigningResponse, Concern{SlotSigner: coord.Fingerprint, HasSlotSigner: true}, false},
		{"machine bundle", machine, TypeBundle, Concern{}, true},
		{"signer bundle", signer, TypeBundle, Concern{}, false},
		{"coordinator bundle", coord, TypeBundle, Concern{}, false},
		{"unknown type", coord, Type("X"), Concern{}, false},
	}
	for _, tc := range tests {
		err := Authorise(tc.p, tc.t, tc.c)
		if (err == nil) != tc.permit || (err != nil && !errors.Is(err, ErrNotAuthorised)) {
			t.Errorf("%s: err = %v, want permit=%v", tc.name, err, tc.permit)
		}
	}
}

// spec: SPO-Xparty-PRE-005
func TestVerifyWitness(t *testing.T) {
	k := mk(1, "w")
	var vk [32]byte
	copy(vk[:], k.priv[32:])
	body := blake2b.Sum256([]byte("body"))
	var sig [64]byte
	copy(sig[:], ed25519.Sign(k.priv, body[:]))
	kh := keyHash(vk)
	if err := VerifyWitness(body, vk, sig, kh); err != nil {
		t.Fatal(err)
	}
	// Valid signature by another key, with that key's own hash: the slot's
	// key hash differs.
	o := mk(2, "o")
	var ovk [32]byte
	copy(ovk[:], o.priv[32:])
	var osig [64]byte
	copy(osig[:], ed25519.Sign(o.priv, body[:]))
	if err := VerifyWitness(body, ovk, osig, kh); !errors.Is(err, ErrWitnessKeyHash) {
		t.Fatalf("other key: %v", err)
	}
	// Right key hash, signature over another body.
	other := blake2b.Sum256([]byte("other"))
	if err := VerifyWitness(other, vk, sig, kh); !errors.Is(err, ErrWitnessSignature) {
		t.Fatalf("other body: %v", err)
	}
	// Right key hash, corrupted signature.
	bad := sig
	bad[10] ^= 1
	if err := VerifyWitness(body, vk, bad, kh); !errors.Is(err, ErrWitnessSignature) {
		t.Fatalf("bad signature: %v", err)
	}
	// Right key, wrong key hash by one bit.
	wrong := kh
	wrong[0] ^= 1
	if err := VerifyWitness(body, vk, sig, wrong); !errors.Is(err, ErrWitnessKeyHash) {
		t.Fatalf("wrong hash: %v", err)
	}
	// Zero values never verify.
	if err := VerifyWitness(body, [32]byte{}, [64]byte{}, [28]byte{}); err == nil {
		t.Fatal("zero witness verified")
	}
}

// spec: SPO-Xparty-PRE-005, SPO-Xparty-INV-014
func TestAcceptResponse(t *testing.T) {
	k := mk(1, "w")
	var vk [32]byte
	copy(vk[:], k.priv[32:])
	body := blake2b.Sum256([]byte("body"))
	var sig [64]byte
	copy(sig[:], ed25519.Sign(k.priv, body[:]))
	signer := Fingerprint{1}
	slot := SlotState{Collection: CollectionID{1}, Slot: 3, CollectionOpen: true, AssignedSigner: signer,
		LastRequest: MessageID{9}, BodyHash: body, KeyHash: keyHash(vk)}
	resp := SigningResponse{Collection: CollectionID{1}, Slot: 3, Request: MessageID{9}}
	if err := AcceptResponse(slot, signer, resp, vk, sig); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		mut  func(*SlotState, *Fingerprint, *SigningResponse, *[64]byte)
		want error
	}{
		{"collection closed", func(s *SlotState, _ *Fingerprint, _ *SigningResponse, _ *[64]byte) { s.CollectionOpen = false }, ErrCollectionNotOpen},
		{"slot filled", func(s *SlotState, _ *Fingerprint, _ *SigningResponse, _ *[64]byte) { s.Filled = true }, ErrSlotFilled},
		{"wrong sender", func(_ *SlotState, f *Fingerprint, _ *SigningResponse, _ *[64]byte) { f[0] = 2 }, ErrWrongSender},
		{"old request", func(_ *SlotState, _ *Fingerprint, r *SigningResponse, _ *[64]byte) { r.Request = MessageID{8} }, ErrStaleRequest},
		{"other slot", func(_ *SlotState, _ *Fingerprint, r *SigningResponse, _ *[64]byte) { r.Slot = 4 }, ErrWrongSlot},
		{"other collection", func(_ *SlotState, _ *Fingerprint, r *SigningResponse, _ *[64]byte) { r.Collection = CollectionID{2} }, ErrWrongSlot},
		{"bad signature", func(_ *SlotState, _ *Fingerprint, _ *SigningResponse, g *[64]byte) { g[0] ^= 1 }, ErrWitnessSignature},
		{"wrong key hash", func(s *SlotState, _ *Fingerprint, _ *SigningResponse, _ *[64]byte) { s.KeyHash[0] ^= 1 }, ErrWitnessKeyHash},
	}
	for _, tc := range tests {
		s, f, r, g := slot, signer, resp, sig
		tc.mut(&s, &f, &r, &g)
		if err := AcceptResponse(s, f, r, vk, g); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
}

// spec: SPO-Xparty-PRE-006
func TestRefuseRequest(t *testing.T) {
	txb := []byte{0xa0, 1, 2}
	req := SigningRequest{KeyRole: "payment", TxBody: txb, BodyHash: blake2b.Sum256(txb), TTLSlot: 1000, NetworkMagic: 42}
	facts := RequestFacts{HoldsKey: true, WorkspaceMagic: 42, CurrentSlot: 10}
	if r, refuse := RefuseRequestEarly(req, facts); refuse {
		t.Fatalf("refused: %d", r)
	}
	if r, refuse := RefuseRequestLate(req, facts); refuse {
		t.Fatalf("refused late: %d", r)
	}
	early := []struct {
		name string
		mut  func(*SigningRequest, *RequestFacts)
		want RefusalReason
	}{
		{"no key", func(_ *SigningRequest, f *RequestFacts) { f.HoldsKey = false }, RefuseNoKey},
		{"wrong network", func(r *SigningRequest, _ *RequestFacts) { r.NetworkMagic = 1 }, RefuseWrongNetwork},
		{"body hash", func(r *SigningRequest, _ *RequestFacts) { r.TxBody = []byte{0xa0, 1, 3} }, RefuseBodyHash},
		{"no key before network", func(r *SigningRequest, f *RequestFacts) { f.HoldsKey = false; r.NetworkMagic = 1 }, RefuseNoKey},
	}
	for _, tc := range early {
		r, f := req, facts
		tc.mut(&r, &f)
		if got, refuse := RefuseRequestEarly(r, f); !refuse || got != tc.want {
			t.Errorf("%s: %d, %v", tc.name, got, refuse)
		}
	}
	late := []struct {
		name string
		mut  func(*SigningRequest, *RequestFacts)
		want RefusalReason
	}{
		{"ttl passed", func(_ *SigningRequest, f *RequestFacts) { f.CurrentSlot = 1000 }, RefuseExpired},
		{"cold key over network", func(r *SigningRequest, f *RequestFacts) { r.KeyRole = "pool-cold"; f.OverNetwork = true }, RefuseColdKeyOverNetwork},
	}
	for _, tc := range late {
		r, f := req, facts
		tc.mut(&r, &f)
		if got, refuse := RefuseRequestLate(r, f); !refuse || got != tc.want {
			t.Errorf("%s: %d, %v", tc.name, got, refuse)
		}
	}
	// A cold key by file is allowed.
	cold := req
	cold.KeyRole = "pool-cold"
	if _, refuse := RefuseRequestLate(cold, facts); refuse {
		t.Fatal("cold key over file refused")
	}
}

// spec: SPO-Xparty-PRE-002, SPO-Xparty-INV-009
func TestWindows(t *testing.T) {
	exp := t0.Add(time.Hour)
	for name, tc := range map[string]struct {
		created, expires, now time.Time
		want                  error
	}{
		"ok":                {t0, exp, t0, nil},
		"expires now":       {t0, exp, exp, nil},
		"expired":           {t0, exp, exp.Add(time.Second), ErrExpired},
		"skew edge":         {t0.Add(ClockSkew), exp, t0, nil},
		"future":            {t0.Add(ClockSkew + time.Second), exp, t0, ErrFromFuture},
		"backwards":         {t0.Add(time.Minute), t0, t0, ErrWindow},
		"too long":          {t0, t0.Add(MaxLifetime + time.Second), t0, ErrWindow},
		"expired and early": {t0.Add(time.Hour), t0, t0.Add(time.Minute), ErrExpired},
	} {
		if err := CheckWindow(tc.created, tc.expires, tc.now); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	ttl := t0.Add(24 * time.Hour)
	for name, tc := range map[string]struct {
		expires time.Time
		want    error
	}{
		"before ttl":      {ttl.Add(-time.Second), nil},
		"at ttl":          {ttl, nil},
		"after ttl":       {ttl.Add(time.Second), ErrRequestExpiry},
		"seven days":      {t0.Add(MaxRequestLifetime), nil},
		"over seven days": {t0.Add(MaxRequestLifetime + time.Second), ErrRequestExpiry},
	} {
		far := t0.Add(30 * 24 * time.Hour)
		got := CheckRequestExpiry(t0, tc.expires, far) // ttl far away: only the 7-day cap applies
		if name == "before ttl" || name == "at ttl" || name == "after ttl" {
			got = CheckRequestExpiry(t0, tc.expires, ttl)
		}
		if !errors.Is(got, tc.want) {
			t.Errorf("%s: %v", name, got)
		}
	}
}

// spec: SPO-Xparty-INV-008
func TestBodyValidation(t *testing.T) {
	good := SigningRequest{KeyRole: "payment", Operation: "witness", TxBody: []byte{1}, TTLSlot: 1, Purpose: "p"}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	bads := map[string]Body{
		"role":       func() Body { m := good; m.KeyRole = "root"; return m }(),
		"operation":  func() Body { m := good; m.Operation = ""; return m }(),
		"empty body": func() Body { m := good; m.TxBody = nil; return m }(),
		"huge body":  func() Body { m := good; m.TxBody = make([]byte, MaxEnvelopeBytes+1); return m }(),
		"purpose":    func() Body { m := good; m.Purpose = strings.Repeat("x", MaxPurposeBytes+1); return m }(),
		"escape":     func() Body { m := good; m.Purpose = "a\x1b[31m"; return m }(),
		"ttl":        func() Body { m := good; m.TTLSlot = 0; return m }(),
		"witness":    SigningResponse{},
		"reason":     SigningRefusal{Reason: 0},
		"reason2":    SigningRefusal{Reason: 99},
		"outcome":    CollectionClosed{Outcome: "x"},
		"no txid":    CollectionClosed{Outcome: OutcomeSubmitted},
		"txid":       CollectionClosed{Outcome: OutcomeExpired, TxID: make([]byte, 32)},
		"invite":     Invite{},
		"invite key": Invite{Address: "tc"},
		"attach":     Bundle{Attachments: []Attachment{{Name: "../x"}}},
		"attach dup": Bundle{Attachments: []Attachment{{Name: "a"}, {Name: "a"}}},
		"attach dot": Bundle{Attachments: []Attachment{{Name: "a..b"}}},
		"bundle big": Bundle{Snapshot: make([]byte, MaxEnvelopeBytes+1)},
	}
	for name, b := range bads {
		if err := b.Validate(); !errors.Is(err, ErrInvalidBody) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := good.CheckTxSize(0); err == nil {
		t.Fatal("maxTxSize not enforced")
	}
	if err := good.CheckTxSize(16384); err != nil {
		t.Fatal(err)
	}
	if s := (Invite{Address: "tcSECRET", Node: NodeKey{1}}).String(); strings.Contains(s, "SECRET") {
		t.Fatal("invite leaks its address")
	}
}

// spec: SPO-Xparty-IF-004
func TestFileName(t *testing.T) {
	got := FileName(TypeSigningRequest, CollectionID{0xde, 0xad, 0xbe, 0xef, 1}, 2)
	if got != "SigningRequest-deadbeef-2.spo" {
		t.Fatal(got)
	}
}
