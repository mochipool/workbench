package custody

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
)

type vkp struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newKP(seed byte) vkp {
	pub, priv, _ := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{seed}, 64)))
	return vkp{pub, priv}
}

func (k vkp) id(t *testing.T) identity.Ref {
	t.Helper()
	r, err := identity.KeyHashOf(k.pub)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (k vkp) arr() (a [32]byte) { copy(a[:], k.pub); return }

func sig64(b []byte) (a [64]byte) { copy(a[:], b); return }

// spec: SPO-Xidentity-SEC-001
func TestTxWitnessVerifier(t *testing.T) {
	signer, other := newKP(1), newKP(2)
	body := []byte{0xa1, 0x02, 0x1a, 0x00, 0x0f, 0x42, 0x40}
	tx := append([]byte{0x84}, body...)
	tx = append(tx, 0xa0, 0xf5, 0xf6)
	txid, err := identity.TxIDOfTx(tx)
	if err != nil {
		t.Fatal(err)
	}
	var id [32]byte
	copy(id[:], txid.Hash())
	good := sig64(ed25519.Sign(signer.priv, id[:]))

	if err := VerifyTxWitness(id, signer.arr(), good, signer.id(t)); err != nil {
		t.Fatal(err)
	}
	if err := VerifyTxWitnessOverTx(tx, &id, signer.arr(), good, signer.id(t)); err != nil {
		t.Fatal(err)
	}
	if err := VerifyTxWitnessOverTx(tx, nil, signer.arr(), good, signer.id(t)); err != nil {
		t.Fatal(err)
	}

	// A valid signature of a key that is not the demanded identity.
	if err := VerifyTxWitness(id, other.arr(), sig64(ed25519.Sign(other.priv, id[:])), signer.id(t)); !errors.Is(err, ErrWitnessKey) {
		t.Errorf("wrong key: %v", err)
	}
	// The right key with a signature over another id.
	var wrong [32]byte
	wrong[0] = 1
	if err := VerifyTxWitness(wrong, signer.arr(), good, signer.id(t)); !errors.Is(err, ErrWitnessSignature) {
		t.Errorf("other body: %v", err)
	}
	bad := good
	bad[5] ^= 1
	if err := VerifyTxWitness(id, signer.arr(), bad, signer.id(t)); !errors.Is(err, ErrWitnessSignature) {
		t.Errorf("corrupt: %v", err)
	}
	// A demanded identity of another kind is refused, never compared by bytes.
	asVRF, _ := identity.NewRef(identity.KindVRFKeyHash, bytes.Repeat([]byte{1}, 32))
	if err := VerifyTxWitness(id, signer.arr(), good, asVRF); !errors.Is(err, identity.ErrBadKind) {
		t.Errorf("wrong kind: %v", err)
	}
	if err := VerifyTxWitness(id, signer.arr(), good, identity.Ref{}); err == nil {
		t.Error("zero identity demanded")
	}
	// The claimed id must hash from the body bytes.
	lie := id
	lie[0] ^= 1
	if err := VerifyTxWitnessOverTx(tx, &lie, signer.arr(), sig64(ed25519.Sign(signer.priv, lie[:])), signer.id(t)); !errors.Is(err, ErrTxIDMismatch) || errors.Is(err, ErrWitnessSignature) {
		t.Errorf("a transaction id that does not hash from the body bytes: %v", err)
	}
	// The signature-only half.
	if err := VerifyTxSignature(id, signer.arr(), good); err != nil {
		t.Error(err)
	}
	if err := VerifyTxSignature(wrong, signer.arr(), good); !errors.Is(err, ErrWitnessSignature) {
		t.Error(err)
	}
}

// spec: SPO-Xidentity-SEC-002
func TestOpCertVerifier(t *testing.T) {
	cold, other := newKP(3), newKP(4)
	kes := bytes.Repeat([]byte{7}, 32)
	sign := func(k vkp, kes []byte, counter, period uint64) OpCert {
		m := append([]byte(nil), kes...)
		m = binary.BigEndian.AppendUint64(m, counter)
		m = binary.BigEndian.AppendUint64(m, period)
		oc := OpCert{Counter: counter, KesPeriod: period, ColdVKey: k.arr(), Signature: sig64(ed25519.Sign(k.priv, m))}
		copy(oc.KesVKey[:], kes)
		return oc
	}
	ask := &OpCertAsk{KesVKey: kes, Counter: 5, KesPeriod: 400}
	if err := VerifyOpCert(sign(cold, kes, 5, 400), ask, cold.id(t)); err != nil {
		t.Fatal(err)
	}
	if err := VerifyOpCert(sign(cold, kes, 5, 400), nil, cold.id(t)); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		oc   OpCert
		want error
	}{
		"another counter":  {sign(cold, kes, 6, 400), ErrOpCertField},
		"another period":   {sign(cold, kes, 5, 401), ErrOpCertField},
		"another KES key":  {sign(cold, bytes.Repeat([]byte{8}, 32), 5, 400), ErrOpCertField},
		"another cold key": {sign(other, kes, 5, 400), ErrOpCertKey},
		"a bad signature": {func() OpCert {
			o := sign(cold, kes, 5, 400)
			o.Signature[0] ^= 1
			return o
		}(), ErrOpCertSignature},
		"a signature over other fields": {func() OpCert {
			o := sign(cold, kes, 5, 400)
			o.Signature = sign(cold, kes, 5, 399).Signature
			return o
		}(), ErrOpCertSignature},
	} {
		if err := VerifyOpCert(c.oc, ask, cold.id(t)); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := VerifyOpCert(sign(cold, kes, 5, 400), ask, identity.Ref{}); err == nil {
		t.Error("zero identity demanded")
	}
}

// spec: SPO-Xidentity-SEC-003
func TestCip36Verifier(t *testing.T) {
	stake, other := newKP(5), newKP(6)
	reg := cose.Cip36{Address: append([]byte{0x00}, bytes.Repeat([]byte{1}, 56)...), Nonce: 9, Delegations: []cose.Delegation{{Weight: 1}}}
	reg.StakePub = stake.arr()
	h := reg.SigningHash()
	md := reg.Metadata(ed25519.Sign(stake.priv, h[:]))
	got, err := VerifyCip36(md, stake.id(t))
	if err != nil || got.Nonce != 9 {
		t.Fatalf("%v %+v", err, got)
	}
	if _, err := VerifyCip36(md, other.id(t)); !errors.Is(err, ErrMessageKey) {
		t.Errorf("another stake key demanded: %v", err)
	}
	tampered := bytes.Replace(md, []byte{0x09}, []byte{0x0a}, 1)
	if _, err := VerifyCip36(tampered, stake.id(t)); err == nil {
		t.Error("a tampered registration verified")
	}
	if _, err := VerifyCip36(md[:20], stake.id(t)); err == nil {
		t.Error("garbage verified")
	}
	// A witness by a key other than the one the registration names.
	forged := reg
	md2 := forged.Metadata(ed25519.Sign(other.priv, h[:]))
	if _, err := VerifyCip36(md2, stake.id(t)); err == nil {
		t.Error("a registration signed by another key verified")
	}
}

// spec: SPO-Xidentity-SEC-003
func TestCip88Verifier(t *testing.T) {
	cold, other := newKP(7), newKP(8)
	calidus := newKP(9)
	reg := cose.Cip88{Nonce: 3}
	pid := cose.Blake2b224(cold.pub)
	copy(reg.PoolID[:], pid[:])
	copy(reg.CalidusPub[:], calidus.pub)
	sig := ed25519.Sign(cold.priv, reg.ToBeSigned())
	md := reg.Metadata(cold.pub, sig)
	got, err := VerifyCip88(md, cold.id(t))
	if err != nil || got != reg {
		t.Fatalf("%v %+v", err, got)
	}
	if _, err := VerifyCip88(md, other.id(t)); !errors.Is(err, ErrMessageKey) {
		t.Errorf("another pool demanded: %v", err)
	}
	badSig := bytes.Clone(md)
	badSig[len(badSig)-1] ^= 1
	if _, err := VerifyCip88(badSig, cold.id(t)); err == nil {
		t.Error("a corrupted signature verified")
	}
}

// spec: SPO-Xidentity-SEC-003
func TestMessageVerifier(t *testing.T) {
	k, other := newKP(10), newKP(11)
	addr := cose.Blake2b224(k.pub)
	s := cose.Sign1{Protected: cose.ProtectedHeader(addr[:]), Payload: []byte("hello")}
	s.Signature = ed25519.Sign(k.priv, cose.SigStructure(s.Protected, s.Payload))
	enc, key := s.Encode(), cose.EncodeKey(k.pub)
	if _, err := VerifyMessage(enc, key, nil, true, k.id(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyMessage(enc, key, []byte("hello"), true, k.id(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyMessage(enc, key, nil, true, other.id(t)); !errors.Is(err, ErrMessageKey) {
		t.Errorf("another key demanded: %v", err)
	}
	if _, err := VerifyMessage(enc, cose.EncodeKey(other.pub), nil, false, k.id(t)); err == nil {
		t.Error("a message verified under another key")
	}
	if _, err := VerifyMessage(enc, key, []byte("other"), true, k.id(t)); err == nil {
		t.Error("data that is not the payload verified")
	}
}

// spec: SPO-Xidentity-SEC-001
func TestRegistryAttestationVerifier(t *testing.T) {
	k, other := newKP(12), newKP(13)
	msg := [32]byte{1, 2, 3}
	sig := sig64(ed25519.Sign(k.priv, msg[:]))
	if err := VerifyRegistryAttestation(msg, k.arr(), sig, k.id(t)); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRegistryAttestation(msg, other.arr(), sig64(ed25519.Sign(other.priv, msg[:])), k.id(t)); !errors.Is(err, ErrMessageKey) {
		t.Errorf("another key: %v", err)
	}
	if err := VerifyRegistryAttestation([32]byte{9}, k.arr(), sig, k.id(t)); !errors.Is(err, ErrRegistrySig) {
		t.Errorf("another message: %v", err)
	}
}

// The three callers of the transaction witness check hold no verification of
// their own: none of their sources calls ed25519.
//
// spec: SPO-Xidentity-SEC-001
func TestNoSecondTransactionWitnessVerifier(t *testing.T) {
	for _, dir := range []string{"../pool", "../party", "../txbuild"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			n := e.Name()
			if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
				continue
			}
			b, _ := os.ReadFile(dir + "/" + n)
			if strings.Contains(string(b), "ed25519.Verify") && n != "rotation.go" && n != "identity.go" {
				t.Errorf("%s/%s verifies a signature itself", dir, n)
			}
		}
	}
}

// A text signature is accepted only for the demanded Calidus key.
//
// spec: SPO-Xidentity-SEC-006
func TestVerifyText(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	var vk [32]byte
	copy(vk[:], pub)
	var sig [64]byte
	copy(sig[:], ed25519.Sign(priv, []byte("hello")))
	want, _ := identity.CalidusKeyHashOf(vk[:])
	if err := VerifyText([]byte("hello"), vk, sig, want); err != nil {
		t.Fatal(err)
	}
	if err := VerifyText([]byte("other"), vk, sig, want); !errors.Is(err, ErrTextSignature) {
		t.Errorf("another text: %v", err)
	}
	other, _ := identity.CalidusKeyHashOf(make([]byte, 32))
	if err := VerifyText([]byte("hello"), vk, sig, other); !errors.Is(err, ErrMessageKey) {
		t.Errorf("another key: %v", err)
	}
	if err := VerifyText([]byte("hello"), vk, sig, identity.Ref{}); err == nil {
		t.Error("no identity demanded")
	}
}
