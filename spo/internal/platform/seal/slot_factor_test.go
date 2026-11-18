package seal

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// Vectors. They were computed by a second implementation, in Python
// (hashlib, hmac and a hand-written CBOR encoder; no Go code, no CBOR library):
//
//	nonce = 0x11 * 16, slot id = 0x22 * 16, format version = 2
//	recovery key hash = SHA-256("recovery-public-key")
//	fido2 factor: kind 3, id = 0xaa * 32, credential id = bytes 1..48,
//	              rp id = "spo." + hex(nonce), hmac salt = 0x33 * 32,
//	              touch probe result = 1 (enforced),
//	              output = 0x44 * 32
//	passphrase factor: kind 1, id = 0x01 * 16, Argon2id 65536 KiB / 3 / 1,
//	              salt = 0x77 * 16, output = 0x55 * 32
//	cold sub-key: version 2, identity = 0x66 * 28, factor output = 0x44 * 32
//
// slot key  = HKDF-SHA-256(IKM = for each output: be32(len) || output, salt =
//
//	nonce, info = CBOR ["spo/slot-key", version, slot id, kind,
//	[[factor kind, factor id], ...]])
//
// commit    = HMAC-SHA-256(slot key, "spo-workbench/seal/v1/slot-commit")
// ad        = CBOR ["spo/slot-ad", version, nonce, slot id, kind,
//
//	[[factor kind, factor id, params], ...], recovery key hash, commit]
const (
	vecRecoveryHash = "77126485148c9a2ab5672d9ae560db53ea3707237268f67958d53808be810b4d"

	vecFIDOKey    = "f81b841f7a37f95455f213972244e98d90d943fdba63709aef5b9b5481b2cf83"
	vecFIDOCommit = "b9a286d69728c76d4249bfa7e071ccf227b7650f92ffce0f987a201e037c022e"
	vecFIDOAD     = "886b73706f2f736c6f742d616402501111111111111111111111111111111150222222222222222222222222222222226a6669646f322d686d61638183035820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8458300102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30782473706f2e31313131313131313131313131313131313131313131313131313131313131315820333333333333333333333333333333333333333333333333333333333333333301582077126485148c9a2ab5672d9ae560db53ea3707237268f67958d53808be810b4d5820b9a286d69728c76d4249bfa7e071ccf227b7650f92ffce0f987a201e037c022e"

	vecCompKey    = "d980cdc143d26b8df0d157f39771fdf7643555b9ef6a7e8e49b267b4c0637e9f"
	vecCompCommit = "82fb9cee78cdd1d69fe493a22d25acaa2aa3bae520a75d06ca3e345a4df097eb"
	vecCompAD     = "886b73706f2f736c6f742d6164025011111111111111111111111111111111502222222222222222222222222222222269636f6d706f73697465828301500101010101010101010101010101010185686172676f6e3269641a000100000301507777777777777777777777777777777783035820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8458300102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30782473706f2e31313131313131313131313131313131313131313131313131313131313131315820333333333333333333333333333333333333333333333333333333333333333301582077126485148c9a2ab5672d9ae560db53ea3707237268f67958d53808be810b4d582082fb9cee78cdd1d69fe493a22d25acaa2aa3bae520a75d06ca3e345a4df097eb"

	// cold sub-key of a composite: outputs 0x55*32 then 0x44*32 (passphrase, fido2)
	// IKM = be32(32) || 0x55*32 || be32(32) || 0x44*32, same salt and info
	vecColdComposite = "6c0a1753e436175f9eb945233bda9376d9bc5a3841f005f57637aa970f65d2b4"

	vecColdSubKey = "e65d8505699c3825ed1e5e292603b08277c03c15283509ef7dafac1fae486914"
)

func rep(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }

func fidoParams() FactorParams {
	cred := make([]byte, 48)
	for i := range cred {
		cred[i] = byte(i + 1)
	}
	return FactorParams{Kind: FactorFIDO2, ID: rep(0xaa, 32), CredentialID: cred,
		RPID: "spo." + hex.EncodeToString(rep(0x11, 16)), HMACSalt: rep(0x33, 32), Touch: 1}
}

func passParams() FactorParams {
	return FactorParams{Kind: FactorPassphrase, ID: rep(0x01, 16), KDF: MinKDF(), KDFSalt: rep(0x77, 16)}
}

func fidoSpec() SlotSpec {
	rh, _ := hex.DecodeString(vecRecoveryHash)
	return SlotSpec{FormatVersion: 2, GenesisNonce: rep(0x11, 16), SlotID: rep(0x22, 16), Kind: SlotFIDO2HMAC,
		Factors: []FactorParams{fidoParams()}, RecoveryPubKeyHash: rh}
}

func compSpec() SlotSpec {
	s := fidoSpec()
	s.Kind = SlotComposite
	s.Factors = []FactorParams{passParams(), fidoParams()}
	return s
}

func outs(bs ...[]byte) []*secret.Buffer {
	o := make([]*secret.Buffer, len(bs))
	for i, b := range bs {
		o[i] = secret.Take(append([]byte(nil), b...))
	}
	return o
}

func destroy(o []*secret.Buffer) {
	for _, b := range o {
		b.Destroy()
	}
}

func keyHex(t *testing.T, k *secret.Buffer, err error) string {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	defer k.Destroy()
	var h string
	_ = k.Use(func(b []byte) error { h = hex.EncodeToString(b); return nil })
	return h
}

func TestRecoveryPubKeyHashVector(t *testing.T) {
	if got := hex.EncodeToString(RecoveryPubKeyHash([]byte("recovery-public-key"))); got != vecRecoveryHash {
		t.Fatalf("got %s", got)
	}
}

// spec: SPO-Xunlock-OUT-001, SPO-Xunlock-OUT-002
func TestSlotKeyAndAssociatedDataVectors(t *testing.T) {
	for _, c := range []struct {
		name            string
		spec            SlotSpec
		out             [][]byte
		key, commit, ad string
	}{
		{"fido2-hmac", fidoSpec(), [][]byte{rep(0x44, 32)}, vecFIDOKey, vecFIDOCommit, vecFIDOAD},
		{"composite", compSpec(), [][]byte{rep(0x55, 32), rep(0x44, 32)}, vecCompKey, vecCompCommit, vecCompAD},
	} {
		t.Run(c.name, func(t *testing.T) {
			o := outs(c.out...)
			defer destroy(o)
			k, err := c.spec.DeriveKey(o)
			if got := keyHex(t, k, err); got != c.key {
				t.Fatalf("slot key %s", got)
			}
			kb, _ := hex.DecodeString(c.key)
			if got := hex.EncodeToString(slotCommit(kb)); got != c.commit {
				t.Fatalf("commit %s", got)
			}
			cm, _ := hex.DecodeString(c.commit)
			ad, err := c.spec.AD(cm)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(ad); got != c.ad {
				t.Fatalf("associated data\n got %s\nwant %s", got, c.ad)
			}
		})
	}
}

// spec: SPO-Xunlock-OUT-003
func TestColdSubKeyVector(t *testing.T) {
	out := outs(rep(0x44, 32))
	defer destroy(out)
	k, err := DeriveColdSubKey(out[0], rep(0x11, 16), 2, rep(0x66, 28))
	if got := keyHex(t, k, err); got != vecColdSubKey {
		t.Fatalf("got %s", got)
	}
	// The sub-key is keyed on every input it names.
	same := func(o *secret.Buffer, nonce []byte, v uint32, id []byte) bool {
		k2, err := DeriveColdSubKey(o, nonce, v, id)
		return keyHex(t, k2, err) == vecColdSubKey
	}
	other := outs(rep(0x45, 32))
	defer destroy(other)
	flipped := rep(0x66, 28)
	flipped[27] ^= 1
	for name, ok := range map[string]bool{
		"another factor output":  same(other[0], rep(0x11, 16), 2, rep(0x66, 28)),
		"another genesis nonce":  same(out[0], rep(0x12, 16), 2, rep(0x66, 28)),
		"another format version": same(out[0], rep(0x11, 16), 3, rep(0x66, 28)),
		"another identity":       same(out[0], rep(0x11, 16), 2, flipped),
		"identity of 32 bytes":   same(out[0], rep(0x11, 16), 2, rep(0x66, 32)),
	} {
		if ok {
			t.Errorf("%s gives the same sub-key", name)
		}
	}
	if _, err := DeriveColdSubKey(out[0], rep(0x11, 16), 2, rep(0x66, 27)); !errors.Is(err, ErrFormat) {
		t.Fatalf("an identity of 27 bytes: %v", err)
	}
	short := outs(rep(1, 31))
	defer destroy(short)
	if _, err := DeriveColdSubKey(short[0], rep(0x11, 16), 2, rep(0x66, 28)); !errors.Is(err, ErrFormat) {
		t.Fatalf("a 31-byte factor output: %v", err)
	}
}

// spec: SPO-Xunlock-INV-001, SPO-Xunlock-IN-003
func TestSlotKeySeparation(t *testing.T) {
	base := func(mut func(*SlotSpec), o ...[]byte) string {
		s := compSpec()
		if mut != nil {
			mut(&s)
		}
		if len(o) == 0 {
			o = [][]byte{rep(0x55, 32), rep(0x44, 32)}
		}
		b := outs(o...)
		defer destroy(b)
		k, err := s.DeriveKey(b)
		return keyHex(t, k, err)
	}
	want := base(nil)
	if want != vecCompKey {
		t.Fatal("the base case is not the vector")
	}
	a, b := rep(0x55, 32), rep(0x44, 32)
	moved1 := append(append([]byte(nil), a[:31]...), b[0])
	moved2 := append([]byte{a[31]}, b[1:]...)
	for name, got := range map[string]string{
		"outputs swapped":                 base(nil, b, a),
		"a byte moved between neighbours": base(nil, moved1, moved2),
		"another slot id":                 base(func(s *SlotSpec) { s.SlotID = rep(0x23, 16) }),
		"another genesis nonce":           base(func(s *SlotSpec) { s.GenesisNonce = rep(0x12, 16) }),
		"another format version":          base(func(s *SlotSpec) { s.FormatVersion = 3 }),
		"another factor id":               base(func(s *SlotSpec) { s.Factors[1].ID = rep(0xab, 32) }),
		"another factor kind (backend)": base(func(s *SlotSpec) {
			s.Factors[1] = FactorParams{Kind: FactorBackend, ID: rep(0xaa, 32), BackendKeyRef: "k"}
		}),
		"another first output":  base(nil, rep(0x56, 32), b),
		"another second output": base(nil, a, rep(0x45, 32)),
	} {
		if got == want {
			t.Errorf("%s: the slot key does not change", name)
		}
	}
	// The recovery key hash is bound by the associated data, not the key: the
	// slot opens under the same key but not under the changed associated data.
	master, _ := NewMasterKey()
	defer master.Destroy()
	o := outs(a, b)
	defer destroy(o)
	slot, err := NewFactorSlot(compSpec(), o, master)
	if err != nil {
		t.Fatal(err)
	}
	m, err := slot.Unwrap(o)
	if err != nil {
		t.Fatal(err)
	}
	m.Destroy()
	for name, mut := range map[string]func(*SlotSpec){
		"recovery key hash":  func(s *SlotSpec) { s.RecoveryPubKeyHash = rep(9, 32) },
		"hmac-secret salt":   func(s *SlotSpec) { s.Factors[1].HMACSalt = rep(0x34, 32) },
		"touch probe result": func(s *SlotSpec) { s.Factors[1].Touch = 2 }, // spec: SPO-Xunlock-SEC-004
		"credential id":      func(s *SlotSpec) { s.Factors[1].CredentialID = rep(1, 48) },
		"relying-party id":   func(s *SlotSpec) { s.Factors[1].RPID = "spo.other" },
		"argon2id salt":      func(s *SlotSpec) { s.Factors[0].KDFSalt = rep(0x78, 16) },
		"argon2id passes":    func(s *SlotSpec) { s.Factors[0].KDF.Passes = 4 },
	} {
		bad := slot
		bad.Spec = compSpec()
		mut(&bad.Spec)
		if _, err := bad.Unwrap(o); !errors.Is(err, ErrAuth) {
			t.Errorf("%s: a changed value still opens the slot (%v)", name, err)
		}
	}
	// The wrong outputs and a changed commitment give ErrAuth too.
	wrong := outs(a, rep(0x46, 32))
	defer destroy(wrong)
	if _, err := slot.Unwrap(wrong); !errors.Is(err, ErrAuth) {
		t.Fatalf("a wrong factor output: %v", err)
	}
	bad := slot
	bad.Commit = append([]byte(nil), slot.Commit...)
	bad.Commit[0] ^= 1
	if _, err := bad.Unwrap(o); !errors.Is(err, ErrAuth) {
		t.Fatalf("a changed commitment: %v", err)
	}
}

// spec: SPO-Xunlock-IN-003, SPO-Xunlock-INV-001
func TestFactorOutputsAreExactlyKeySizeAndOrdered(t *testing.T) {
	// The length prefix is a constant for 32-byte outputs, so outputs of 31 and 33
	// bytes (the same concatenation as two 32-byte ones) are refused, not framed.
	a, b := rep(0x55, 32), rep(0x44, 32)
	o := outs(a[:31], append([]byte{a[31]}, b...))
	defer destroy(o)
	if _, err := compSpec().DeriveKey(o); !errors.Is(err, ErrFormat) {
		t.Fatalf("outputs of 31 and 33 bytes: %v", err)
	}
	// The derivation keeps the order it is given: the same outputs under the
	// reversed factor list are another key. SlotSpec refuses that list.
	refs := []FactorRef{{FactorPassphrase, rep(0x01, 16)}, {FactorFIDO2, rep(0xaa, 32)}}
	rev := []FactorRef{refs[1], refs[0]}
	p := outs(a, b)
	defer destroy(p)
	q := outs(b, a)
	defer destroy(q)
	k1, e1 := deriveSlotKey(2, rep(0x11, 16), rep(0x22, 16), SlotComposite, refs, p)
	k2, e2 := deriveSlotKey(2, rep(0x11, 16), rep(0x22, 16), SlotComposite, rev, q)
	if keyHex(t, k1, e1) == keyHex(t, k2, e2) {
		t.Fatal("a reordered factor list gives the same key")
	}
	s := compSpec()
	s.Factors[0], s.Factors[1] = s.Factors[1], s.Factors[0]
	if _, err := s.DeriveKey(q); !errors.Is(err, ErrFormat) {
		t.Fatalf("factors not in canonical order: %v", err)
	}
	// SortFactors restores the canonical order.
	SortFactors(s.Factors)
	if err := s.validate(); err != nil {
		t.Fatal(err)
	}
	// A repeated factor is refused.
	s.Factors = []FactorParams{passParams(), passParams()}
	if _, err := s.DeriveKey(p); !errors.Is(err, ErrFormat) {
		t.Fatalf("a repeated factor: %v", err)
	}
}

// spec: SPO-Xunlock-PRE-016
func TestSlotSpecRefusesWhatDoesNotFitItsKind(t *testing.T) {
	for name, mut := range map[string]func(*SlotSpec){
		"fido2-hmac with two factors":    func(s *SlotSpec) { s.Factors = []FactorParams{passParams(), fidoParams()} },
		"fido2-hmac over a passphrase":   func(s *SlotSpec) { s.Factors = []FactorParams{passParams()} },
		"composite with one factor":      func(s *SlotSpec) { s.Kind = SlotComposite },
		"unknown kind":                   func(s *SlotSpec) { s.Kind = "device" },
		"a short genesis nonce":          func(s *SlotSpec) { s.GenesisNonce = rep(1, 15) },
		"a short slot id":                func(s *SlotSpec) { s.SlotID = rep(1, 15) },
		"a 31-byte recovery key hash":    func(s *SlotSpec) { s.RecoveryPubKeyHash = rep(1, 31) },
		"a 31-byte hmac salt":            func(s *SlotSpec) { s.Factors[0].HMACSalt = rep(1, 31) },
		"no credential id":               func(s *SlotSpec) { s.Factors[0].CredentialID = nil },
		"no relying-party id":            func(s *SlotSpec) { s.Factors[0].RPID = "" },
		"an empty factor id":             func(s *SlotSpec) { s.Factors[0].ID = nil },
		"passphrase parameters on fido2": func(s *SlotSpec) { s.Factors[0].KDFSalt = rep(1, 16) },
		"a backend reference on fido2":   func(s *SlotSpec) { s.Factors[0].BackendKeyRef = "k" },
		"an unknown factor kind":         func(s *SlotSpec) { s.Factors[0].Kind = 9 },
	} {
		s := fidoSpec()
		mut(&s)
		o := outs(rep(1, 32), rep(2, 32))
		if _, err := s.DeriveKey(o[:len(s.Factors)]); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: got %v", name, err)
		}
		destroy(o)
	}
	weak := compSpec()
	weak.Factors[0].KDF = KDFParams{MemoryKiB: 8, Passes: 1, Lanes: 1}
	withProductionFloor(t)
	if err := weak.validate(); !errors.Is(err, ErrWeakKDF) {
		t.Fatalf("a weak Argon2id factor: %v", err)
	}
}

// spec: SPO-Xunlock-OUT-002
func TestFactorSlotRoundTripAndPassphraseFactor(t *testing.T) {
	master, _ := NewMasterKey()
	defer master.Destroy()
	pw := secret.Take([]byte("correct horse"))
	defer pw.Destroy()
	salt := rep(0x77, 16)
	po, err := PassphraseFactorOutput(pw, salt, smallKDF)
	if err != nil {
		t.Fatal(err)
	}
	fo := outs(rep(0x44, 32))
	defer destroy(fo)
	spec := compSpec()
	spec.Factors[0].KDF = smallKDF
	slot, err := NewFactorSlot(spec, []*secret.Buffer{po, fo[0]}, master)
	if err != nil {
		t.Fatal(err)
	}
	got, err := slot.Unwrap([]*secret.Buffer{po, fo[0]})
	if err != nil {
		t.Fatal(err)
	}
	var same bool
	_ = got.Use(func(a []byte) error {
		return master.Use(func(b []byte) error { same = bytes.Equal(a, b); return nil })
	})
	if !same {
		t.Fatal("another master key")
	}
	// A different passphrase is a different factor output.
	wrongPW := secret.Take([]byte("correct horse!"))
	defer wrongPW.Destroy()
	wo, _ := PassphraseFactorOutput(wrongPW, salt, smallKDF)
	if _, err := slot.Unwrap([]*secret.Buffer{wo, fo[0]}); !errors.Is(err, ErrAuth) {
		t.Fatalf("a wrong passphrase factor: %v", err)
	}
	if _, err := PassphraseFactorOutput(pw, rep(1, 15), smallKDF); !errors.Is(err, ErrFormat) {
		t.Fatalf("a short salt: %v", err)
	}
}

// The passphrase and recovery derivations do not go through the derivation of
// this file; the committed vectors of ADR 0003 still hold byte for byte. (The
// two tests run here under this requirement's name; they also run on their own.)
//
// spec: SPO-Xunlock-INV-002
func TestOlderSlotKindsAreUnchanged(t *testing.T) {
	t.Run("regenerated vectors equal the committed file", TestVectors)
	t.Run("committed slots open", TestCommittedVectorsOpen)
}

// spec: SPO-Xunlock-OUT-007
func TestColdSubKeyCompositeVector(t *testing.T) {
	refs := []FactorRef{{FactorPassphrase, rep(0x01, 16)}, {FactorFIDO2, rep(0xaa, 32)}}
	o := outs(rep(0x55, 32), rep(0x44, 32))
	defer destroy(o)
	k, err := DeriveColdSubKeyComposite(refs, o, rep(0x11, 16), 2, rep(0x66, 28))
	if got := keyHex(t, k, err); got != vecColdComposite {
		t.Fatalf("got %s", got)
	}
	// Each input is keyed: order, a factor output, the nonce, the identity.
	rev := outs(rep(0x44, 32), rep(0x55, 32))
	defer destroy(rev)
	other := outs(rep(0x55, 32), rep(0x45, 32))
	defer destroy(other)
	flipped := rep(0x66, 28)
	flipped[0] ^= 1
	for name, f := range map[string]func() (*secret.Buffer, error){
		"outputs swapped": func() (*secret.Buffer, error) {
			return DeriveColdSubKeyComposite(refs, rev, rep(0x11, 16), 2, rep(0x66, 28))
		},
		"another output": func() (*secret.Buffer, error) {
			return DeriveColdSubKeyComposite(refs, other, rep(0x11, 16), 2, rep(0x66, 28))
		},
		"another nonce": func() (*secret.Buffer, error) {
			return DeriveColdSubKeyComposite(refs, o, rep(0x12, 16), 2, rep(0x66, 28))
		},
		"another identity": func() (*secret.Buffer, error) { return DeriveColdSubKeyComposite(refs, o, rep(0x11, 16), 2, flipped) },
		"another version": func() (*secret.Buffer, error) {
			return DeriveColdSubKeyComposite(refs, o, rep(0x11, 16), 3, rep(0x66, 28))
		},
	} {
		k, err := f()
		if keyHex(t, k, err) == vecColdComposite {
			t.Errorf("%s gives the same sub-key", name)
		}
	}
	// A single factor is not a composite, and the list must be canonical.
	if _, err := DeriveColdSubKeyComposite(refs[:1], o[:1], rep(0x11, 16), 2, rep(0x66, 28)); !errors.Is(err, ErrFormat) {
		t.Fatalf("one factor: %v", err)
	}
	if _, err := DeriveColdSubKeyComposite([]FactorRef{refs[1], refs[0]}, o, rep(0x11, 16), 2, rep(0x66, 28)); !errors.Is(err, ErrFormat) {
		t.Fatalf("not canonical: %v", err)
	}
}

// A strict workspace has no recovery key: its slots bind an empty hash and
// still open (domain/unlock requires the value to be absent everywhere).
//
// spec: SPO-Xunlock-OUT-002
func TestSlotWithNoRecoveryKeyHashOpens(t *testing.T) {
	s := fidoSpec()
	s.RecoveryPubKeyHash = nil
	master, _ := NewMasterKey()
	defer master.Destroy()
	o := outs(rep(0x44, 32))
	defer destroy(o)
	slot, err := NewFactorSlot(s, o, master)
	if err != nil {
		t.Fatal(err)
	}
	m, err := slot.Unwrap(o)
	if err != nil {
		t.Fatal(err)
	}
	m.Destroy()
	withHash := slot
	withHash.Spec.RecoveryPubKeyHash = rep(9, 32)
	if _, err := withHash.Unwrap(o); !errors.Is(err, ErrAuth) {
		t.Fatalf("a hash added to a slot that had none: %v", err)
	}
}

// The policy is bound in the associated data of a slot of store format 3 (both
// the factor kinds and the passphrase and recovery kinds): a slot opens only
// under the policy it was made under.
//
// spec: SPO-Xunlock-OUT-011
func TestSlotPolicyIsBoundInAssociatedData(t *testing.T) {
	master, _ := NewMasterKey()
	defer master.Destroy()
	o := outs(rep(0x44, 32))
	defer destroy(o)
	s := fidoSpec()
	s.Policy = "hardware"
	slot, err := NewFactorSlot(s, o, master)
	if err != nil {
		t.Fatal(err)
	}
	if m, err := slot.Unwrap(o); err != nil {
		t.Fatal(err)
	} else {
		m.Destroy()
	}
	for _, other := range []string{"standard", "strict", ""} {
		changed := slot
		changed.Spec.Policy = other
		if _, err := changed.Unwrap(o); !errors.Is(err, ErrAuth) {
			t.Errorf("policy %q: %v", other, err)
		}
	}
	ws, id := rep(1, IDSize), rep(2, IDSize)
	pw := secret.Take([]byte("pw"))
	ps, err := NewBoundPassphraseSlot(ws, id, master, pw, MinKDF(), SlotBinding{Policy: "standard", RecoveryPubKeyHash: rep(9, 32)})
	if err != nil {
		t.Fatal(err)
	}
	if m, err := ps.Unwrap(ws, secret.Take([]byte("pw"))); err != nil {
		t.Fatal(err)
	} else {
		m.Destroy()
	}
	for name, b := range map[string]*SlotBinding{
		"another policy": {Policy: "hardware", RecoveryPubKeyHash: rep(9, 32)},
		"another hash":   {Policy: "standard", RecoveryPubKeyHash: rep(8, 32)},
		"no hash":        {Policy: "standard"},
		"legacy":         nil,
	} {
		c := ps
		c.Binding = b
		if _, err := c.Unwrap(ws, secret.Take([]byte("pw"))); !errors.Is(err, ErrAuth) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
