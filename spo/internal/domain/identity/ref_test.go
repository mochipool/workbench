package identity_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
)

func vk(seed byte) []byte {
	pub, _, _ := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{seed}, 64)))
	return pub
}

func b224(parts ...[]byte) []byte {
	h, _ := blake2b.New(28, nil)
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func b256(parts ...[]byte) []byte {
	h, _ := blake2b.New256(nil)
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func must(t *testing.T) func(identity.Ref, error) identity.Ref {
	t.Helper()
	return func(r identity.Ref, err error) identity.Ref {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
}

// spec: SPO-Xidentity-INV-001, SPO-Xidentity-IN-001
func TestReferencesAreTyped(t *testing.T) {
	h := bytes.Repeat([]byte{7}, 32)
	a, err := identity.NewRef(identity.KindVRFKeyHash, h)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := identity.NewRef(identity.KindFileHash, h)
	if a == b || a.Compare(b) == 0 {
		t.Error("equal hash bytes of two kinds must be two identities")
	}
	if err := a.Require(identity.KindFileHash); !errors.Is(err, identity.ErrBadKind) {
		t.Errorf("Require: %v", err)
	}
	if err := a.Require(identity.KindVRFKeyHash); err != nil {
		t.Error(err)
	}
	if (identity.Ref{}).Is(identity.Kind(0)) || !(identity.Ref{}).IsZero() {
		t.Error("the zero reference is not an identity")
	}
	if a.Compare(a) != 0 || a.Compare(b) == b.Compare(a) {
		t.Error("Compare must be a total order")
	}
	// Text form round-trips for every kind.
	for _, k := range identity.Kinds() {
		r, err := identity.NewRef(k, bytes.Repeat([]byte{0xab}, k.Size()))
		if err != nil {
			t.Fatal(err)
		}
		back, err := identity.ParseRef(r.String())
		if err != nil || back != r {
			t.Errorf("%s: %v %v", k, back, err)
		}
		if !strings.HasPrefix(r.String(), k.String()+":") {
			t.Errorf("text form %q", r)
		}
	}
	for _, bad := range []string{"", "nokind", "key-hash:zz", "key-hash:abcd", "vrf-key-hash:" + strings.ToUpper(hex.EncodeToString(bytes.Repeat([]byte{0xab}, 32))), "nonsense:" + hex.EncodeToString(h), "key-hash"} {
		if _, err := identity.ParseRef(bad); !errors.Is(err, identity.ErrBadRef) {
			t.Errorf("ParseRef(%q): %v", bad, err)
		}
	}
}

// spec: SPO-Xidentity-INV-010, SPO-Xidentity-IN-001
func TestBinaryForm(t *testing.T) {
	for _, k := range identity.Kinds() {
		r, _ := identity.NewRef(k, bytes.Repeat([]byte{0x11}, k.Size()))
		b, err := r.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if int(b[0]) != 1+k.Size() || len(b) != 2+k.Size() || b[1] != byte(k) {
			t.Errorf("%s: % x", k, b)
		}
		back, err := identity.UnmarshalRef(b)
		if err != nil || back != r {
			t.Errorf("%s: %v", k, err)
		}
		// A reader skips one reference and gets the rest.
		_, rest, err := identity.ReadBinary(append(b, 0xee, 0xff))
		if err != nil || !bytes.Equal(rest, []byte{0xee, 0xff}) {
			t.Errorf("rest %x %v", rest, err)
		}
		if _, err := identity.UnmarshalRef(append(b, 0)); err == nil {
			t.Error("trailing byte accepted")
		}
		if _, err := identity.UnmarshalRef(b[:len(b)-1]); err == nil {
			t.Error("truncated accepted")
		}
		wrong := append([]byte(nil), b...)
		wrong[0]--
		if _, err := identity.UnmarshalRef(wrong); err == nil {
			t.Error("a length byte that disagrees with the kind was accepted")
		}
	}
	if _, err := (identity.Ref{}).MarshalBinary(); err == nil {
		t.Error("zero reference has no binary form")
	}
	if _, _, err := identity.ReadBinary([]byte{3, 99, 1, 2}); err == nil {
		t.Error("unknown kind code accepted")
	}
}

// spec: SPO-Xidentity-INV-002, SPO-Xidentity-IN-002
func TestKeyHashAgreesWithTheLedgerCredentialCode(t *testing.T) {
	key := vk(1)
	id := must(t)(identity.KeyHashOf(key))
	if id.Kind() != identity.KindKeyHash || !bytes.Equal(id.Hash(), b224(key)) {
		t.Fatal("not Blake2b-224 of the key")
	}
	th := txbuild.HashKey(key)
	if !bytes.Equal(id.Hash(), th[:]) {
		t.Error("differs from txbuild.HashKey")
	}
	pid, _ := chain.PoolIDOf(key)
	if !bytes.Equal(id.Hash(), pid[:]) {
		t.Error("differs from the pool id")
	}
	for _, n := range []int{0, 31, 33, 64} {
		if _, err := identity.KeyHashOf(make([]byte, n)); !errors.Is(err, identity.ErrBadKey) {
			t.Errorf("%d bytes: %v", n, err)
		}
	}
}

// spec: SPO-Xidentity-INV-004, SPO-Xidentity-IN-002
func TestVRFKeyHashAgreesWithPoolRegistration(t *testing.T) {
	key := bytes.Repeat([]byte{9}, 32)
	id := must(t)(identity.VRFKeyHashOf(key))
	want := pool.VrfHash(key)
	if id.Kind() != identity.KindVRFKeyHash || !bytes.Equal(id.Hash(), want[:]) {
		t.Error("differs from pool.VrfHash")
	}
	if _, err := identity.VRFKeyHashOf(key[:31]); !errors.Is(err, identity.ErrBadKey) {
		t.Error(err)
	}
}

// spec: SPO-Xidentity-INV-005, SPO-Xidentity-IN-002
func TestProjectRuleKeys(t *testing.T) {
	key := vk(2)
	kes := must(t)(identity.KESKeyHashOf(key))
	cat := must(t)(identity.CatalystKeyHashOf(key))
	cal := must(t)(identity.CalidusKeyHashOf(key))
	if !bytes.Equal(kes.Hash(), b256(key)) || !bytes.Equal(cat.Hash(), b256(key)) || !bytes.Equal(cal.Hash(), b224(key)) {
		t.Fatal("wrong hash")
	}
	if kes == cat || kes.Kind() == cat.Kind() {
		t.Error("one key in two roles of different kind must have different typed identities")
	}
	if !bytes.Equal(cal.Hash(), cose.CalidusIDBytes(key)[1:]) {
		t.Error("differs from the hash a Calidus id carries")
	}
	for _, n := range []int{48, 96} {
		b := bytes.Repeat([]byte{3}, n)
		if r := must(t)(identity.BLSKeyHashOf(b)); !bytes.Equal(r.Hash(), b256(b)) {
			t.Errorf("BLS %d", n)
		}
	}
	for _, f := range []func([]byte) (identity.Ref, error){identity.KESKeyHashOf, identity.CatalystKeyHashOf, identity.CalidusKeyHashOf, identity.BLSKeyHashOf} {
		if _, err := f(make([]byte, 5)); !errors.Is(err, identity.ErrBadKey) {
			t.Error(err)
		}
	}
}

// spec: SPO-Xidentity-INV-001
func TestPartyFingerprintWrapsTheADR0005Value(t *testing.T) {
	var ed party.Ed25519Public
	var x party.X25519Public
	copy(ed[:], vk(3))
	x[0] = 5
	fp := party.FingerprintOf(ed, x)
	id := must(t)(identity.PartyFingerprintOf(fp[:]))
	if id.Kind() != identity.KindPartyFingerprint || !bytes.Equal(id.Hash(), fp[:]) {
		t.Error("the fingerprint is carried unchanged")
	}
	if _, err := identity.PartyFingerprintOf(fp[:19]); err == nil {
		t.Error("short fingerprint accepted")
	}
}

// spec: SPO-Xidentity-INV-006
func TestExactBytesRowsKeepTheIdentityOfTheirInput(t *testing.T) {
	// A transaction body in a non-canonical encoding: an indefinite-length map
	// with an unsorted key order and a long-form integer head.
	body := []byte{0xbf, 0x02, 0x1a, 0x00, 0x00, 0x00, 0x05, 0x00, 0x81, 0x82, 0x58, 0x20}
	body = append(body, bytes.Repeat([]byte{1}, 32)...)
	body = append(body, 0x00, 0xff)
	if _, err := identity.DecodeCanonical(body); err == nil {
		t.Fatal("the body is meant to be non-canonical")
	}
	id := identity.TxIDOf(body)
	if id.Kind() != identity.KindTxID || !bytes.Equal(id.Hash(), b256(body)) {
		t.Error("the transaction id is not the hash of the input bytes")
	}
	// The same body inside a whole transaction keeps the identity of its bytes.
	tx := append([]byte{0x84}, body...)
	tx = append(tx, 0xa0, 0xf5, 0xf6)
	if got := must(t)(identity.TxIDOfTx(tx)); got != id {
		t.Errorf("TxIDOfTx %s, want %s", got, id)
	}
	tx = append([]byte{0x9f}, body...)
	tx = append(tx, 0xa0, 0xf5, 0xf6, 0xff)
	if got := must(t)(identity.TxIDOfTx(tx)); got != id {
		t.Errorf("TxIDOfTx (indefinite array) %s, want %s", got, id)
	}
	if got := must(t)(identity.TxIDOfTx(body)); got != id {
		t.Error("a bare body map is its own body")
	}
	for _, bad := range [][]byte{nil, {0x01}, {0x84}, {0x81, 0x01}} {
		if _, err := identity.TxIDOfTx(bad); err == nil {
			t.Errorf("% x accepted", bad)
		}
	}

	// A metadata file with other key order and whitespace than a re-serialisation.
	file := []byte("{\n  \"ticker\" : \"ABC\",\n\t\"name\":\"A\"  }\n")
	f := identity.FileHashOf(file)
	if f.Kind() != identity.KindFileHash || !bytes.Equal(f.Hash(), b256(file)) {
		t.Error("file identity is not the hash of the file bytes")
	}
	if f == identity.FileHashOf([]byte(`{"name":"A","ticker":"ABC"}`)) {
		t.Error("a re-serialised file must have another identity")
	}

	// A certificate with indefinite-length items, in a text envelope.
	cert := []byte{0x9f, 0x01, 0x9f, 0x02, 0xff, 0xff}
	env := []byte(`{"type":"CertificateConway","description":"x","cborHex":"` + hex.EncodeToString(cert) + `"}`)
	pr := must(t)(identity.PayloadHashOfEnvelope(env))
	if pr != identity.PayloadHashOf(cert) || !bytes.Equal(pr.Hash(), b256(cert)) {
		t.Error("payload identity is not the hash of the decoded cborHex bytes")
	}
	other := []byte(`{"cborHex":"` + hex.EncodeToString(cert) + `","description":"changed","type":"Other"}`)
	if must(t)(identity.PayloadHashOfEnvelope(other)) != pr {
		t.Error("the wrapper must not be part of the identity")
	}
	for _, bad := range []string{`{}`, `not json`, `{"cborHex":"zz"}`} {
		if _, err := identity.PayloadHashOfEnvelope([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := identity.DecodeCanonical(cert); err == nil {
		t.Error("indefinite-length certificate must not pass the canonical check")
	}

	if e := identity.EnvelopeHashOf([]byte("sealed")); e.Kind() != identity.KindEnvelopeHash || !bytes.Equal(e.Hash(), b256([]byte("sealed"))) {
		t.Error("envelope identity")
	}
	if identity.FileHashOf(file) == identity.PayloadHashOf(file) {
		t.Error("the same bytes under two kinds are two identities")
	}
}

// Every verification key shape a store holds gives its key hash over the first
// 32 bytes: plain and extended (BIP32) forms alike. The vector is the extended
// key of the parity fixtures' derivation: the hash is that of the public half.
//
// spec: SPO-Xidentity-INV-002
func TestPublicKeyOfCborHexHandlesPlainAndExtendedKeys(t *testing.T) {
	pub := bytes.Repeat([]byte{0x11}, 32)
	chainCode := bytes.Repeat([]byte{0x22}, 32)
	want, _ := identity.KeyHashOf(pub)
	for name, hexs := range map[string]string{
		"payment":                "5820" + hex.EncodeToString(pub),
		"stake":                  "5820" + hex.EncodeToString(pub),
		"pool cold":              "5820" + hex.EncodeToString(pub),
		"drep":                   "5820" + hex.EncodeToString(pub),
		"committee cold and hot": "5820" + hex.EncodeToString(pub),
		"policy":                 "5820" + hex.EncodeToString(pub),
		"calidus and voting":     "5820" + hex.EncodeToString(pub),
		"extended (bip32), any":  "5840" + hex.EncodeToString(append(append([]byte{}, pub...), chainCode...)),
	} {
		got, err := identity.PublicKeyOfCborHex(hexs)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if id, _ := identity.KeyHashOf(got); id != want {
			t.Errorf("%s: key hash %s, want %s", name, id, want)
		}
	}
	for _, bad := range []string{"", "zz", "5820aa", "5840" + hex.EncodeToString(pub), "5830" + hex.EncodeToString(append(pub, chainCode[:16]...))} {
		if _, err := identity.PublicKeyOfCborHex(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
