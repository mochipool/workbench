package layout_test

// These tests join the pure layout to the sealed envelope of platform/seal:
// the objects a store would write, opened again, and the ways they can be
// damaged. A test file may import the platform; the package itself may not.

import (
	"bytes"
	"crypto/ecdh"
	"math"
	"math/rand"
	"os/exec"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/layout"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

var (
	wsID  = pat(0x20, 16)
	epoch = pat(0xf0, 16)
)

func testKeys(t testing.TB) *seal.Keys {
	t.Helper()
	k, err := seal.DeriveKeys(secret.Take(pat(0x10, 32)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Destroy)
	return k
}

func metaFor(kind, class string, id byte) seal.RecordMeta {
	return seal.RecordMeta{WorkspaceID: wsID, RecordID: pat(id, 16), Kind: kind, Anchor: append([]byte{0}, pat(0x40, 28)...), Num: 7, Class: class, Version: 3, Format: seal.RecordFormat}
}

func toInner(r seal.SealedRecord) layout.Inner {
	return layout.Inner{Nonce: r.Nonce, WrappedKey: r.WrappedKey, Owner: r.Owner, Ciphertext: r.Ciphertext}
}

func fromInner(in layout.Inner) seal.SealedRecord {
	return seal.SealedRecord{Nonce: in.Nonce, WrappedKey: in.WrappedKey, Owner: in.Owner, Ciphertext: in.Ciphertext}
}

func recordOf(m seal.RecordMeta, class string, r seal.SealedRecord) layout.Record {
	return layout.Record{Kind: m.Kind, Class: class, ID: m.RecordID, Anchor: m.Anchor, Num: m.Num, Version: m.Version, RecordFormat: m.Format, UpdatedAt: 1700000000, Inner: toInner(r)}
}

func hotSecret(t testing.TB, k *seal.Keys, n int) (seal.RecordMeta, seal.SealedRecord) {
	t.Helper()
	m := metaFor("node.skey", seal.ClassSecret, 0xa0)
	r, err := k.SealSecret(m, secret.Take(pat(1, n)))
	if err != nil {
		t.Fatal(err)
	}
	return m, r
}

type coldBuild struct {
	hdr      seal.ColdHeader
	prev     bool
	left     bool
	recovery bool
}

func sealCold(t testing.TB, k *seal.Keys, n int, c coldBuild) (seal.RecordMeta, seal.SealedRecord, *secret.Buffer) {
	t.Helper()
	m := metaFor("node.skey", seal.ClassSecretCold, 0xb0)
	ident := pat(0x60, 28)
	sub, err := seal.DeriveColdSubKey(secret.Take(pat(0x70, 32)), wsID, uint32(seal.StoreFormat), ident)
	if err != nil {
		t.Fatal(err)
	}
	cs := seal.ColdSeal{Sub: sub, Header: c.hdr, Left: c.left}
	if c.prev {
		cs.Prev, err = seal.DeriveColdSubKey(secret.Take(pat(0x71, 32)), wsID, uint32(seal.StoreFormat), ident)
		if err != nil {
			t.Fatal(err)
		}
	}
	if c.recovery {
		priv, err := ecdh.X25519().NewPrivateKey(pat(0x80, 32))
		if err != nil {
			t.Fatal(err)
		}
		cs.Recovery = &seal.ColdRecovery{Pub: priv.PublicKey().Bytes(), Identity: ident}
	}
	r, err := k.SealSecretCold(m, secret.Take(pat(1, n)), cs)
	if err != nil {
		t.Fatal(err)
	}
	return m, r, sub
}

func fido2Header(cred int, prev bool, fallbacks uint64) seal.ColdHeader {
	h := seal.ColdHeader{Kind: seal.ColdFIDO2, Credential: pat(0xc0, cred), Salt: pat(0xc1, 32), Next: pat(0xc2, 32), Fallbacks: fallbacks}
	if prev {
		h.Prev = pat(0xc3, 32)
	}
	return h
}

func passphraseHeader() seal.ColdHeader {
	return seal.ColdHeader{Kind: seal.ColdPassphrase, KDF: seal.KDFParams{MemoryKiB: 64 * 1024, Passes: 3, Lanes: 1}, Salt: pat(0xc0, 16)}
}

func sealRecordObject(t testing.TB, k *seal.Keys, rec layout.Record) []byte {
	t.Helper()
	body, err := layout.EncodeBody(rec)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := k.SealObject(epoch, wsID, body)
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

// W is measured from the largest cold-role blob the code can produce: a
// FIDO2 header with a credential id of the CTAP maximum (1024 bytes), a
// present previous wrap, the left mark, the outer wrap and the HPKE recovery
// wrap, and the largest fallback counter.
// spec: SPO-Xlayout-OUT-007
func TestWrappedKeyWidthCoversTheWorstColdBlob(t *testing.T) {
	k := testKeys(t)
	_, worst, _ := sealCold(t, k, 64, coldBuild{hdr: fido2Header(1024, true, math.MaxUint64), prev: true, left: true, recovery: true})
	n := len(worst.WrappedKey)
	t.Logf("worst-case cold wrapped-key blob: %d bytes; W = %d", n, layout.WrappedKeyMax)
	if n > layout.WrappedKeyMax {
		t.Fatalf("a legal cold blob of %d bytes exceeds W = %d", n, layout.WrappedKeyMax)
	}
	if layout.WrappedKeyMax != 1536 {
		t.Fatalf("W is the measured size rounded up to 1536; it is %d", layout.WrappedKeyMax)
	}
	if layout.WrappedKeyMax-n >= 256 {
		t.Fatalf("W (%d) is not the measured size (%d) rounded up to a multiple of 256", layout.WrappedKeyMax, n)
	}
	// 1024 is the largest legal credential id: one more is refused by the seal.
	m := metaFor("node.skey", seal.ClassSecretCold, 0xb0)
	sub, _ := seal.DeriveColdSubKey(secret.Take(pat(0x70, 32)), wsID, uint32(seal.StoreFormat), pat(0x60, 28))
	if _, err := k.SealSecretCold(m, secret.Take(pat(1, 64)), seal.ColdSeal{Sub: sub, Header: fido2Header(1025, false, 0)}); err == nil {
		t.Fatal("a 1025-byte credential id was sealed: the worst case above is not the worst case")
	}
	// the other cold forms are smaller
	for name, c := range map[string]coldBuild{
		"passphrase":                 {hdr: passphraseHeader()},
		"passphrase, recovery":       {hdr: passphraseHeader(), recovery: true},
		"fido2, no previous":         {hdr: fido2Header(1024, false, math.MaxUint64), recovery: true},
		"fido2, previous, no left":   {hdr: fido2Header(1024, true, math.MaxUint64), prev: true, recovery: true},
		"fido2, previous, left only": {hdr: fido2Header(1024, true, 0), prev: true, left: true},
	} {
		_, r, _ := sealCold(t, k, 64, c)
		if len(r.WrappedKey) > n {
			t.Errorf("%s: %d bytes is larger than the worst case %d", name, len(r.WrappedKey), n)
		}
	}
	// A hot record's blob is 72 bytes.
	_, hot := hotSecret(t, k, 64)
	if len(hot.WrappedKey) != 72 {
		t.Fatalf("a hot wrapped key is %d bytes", len(hot.WrappedKey))
	}
}

// A hot Secret record and the two cold-role forms of equal payload size are
// stored in objects of the same size, at several payload sizes.
// spec: SPO-Xlayout-INV-004
func TestStoredHotAndColdObjectsShareABucket(t *testing.T) {
	k := testKeys(t)
	for _, n := range []int{1, 64, 252, 253, 1000, 3000} {
		m, hot := hotSecret(t, k, n)
		want := len(sealRecordObject(t, k, recordOf(m, "secret", hot)))
		for name, c := range map[string]coldBuild{
			"passphrase": {hdr: passphraseHeader()},
			"fido2":      {hdr: fido2Header(1024, true, 3), prev: true, left: true, recovery: true},
		} {
			cm, cr, _ := sealCold(t, k, n, c)
			got := len(sealRecordObject(t, k, recordOf(cm, "secret", cr)))
			if got != want {
				t.Errorf("payload %d, %s: stored %d bytes, hot %d", n, name, got, want)
			}
		}
	}
}

// Opening the envelope yields the record's inner fields; the master-derived
// keys do not open a cold-role record's payload. This pins the guarantee of
// ADR 0011 against a later simplification of the exporter.
// spec: SPO-Xlayout-SEC-003
func TestColdRolePayloadIsNotOpenableWithMasterDerivedKeysAlone(t *testing.T) {
	k := testKeys(t)
	cm, cr, sub := sealCold(t, k, 64, coldBuild{hdr: fido2Header(16, true, 2), prev: true, left: true})
	stored := sealRecordObject(t, k, recordOf(cm, "secret", cr))
	body, err := k.OpenObject(stored, wsID, epoch)
	if err != nil {
		t.Fatal(err)
	}
	o, err := layout.DecodeBody(body, rule)
	if err != nil {
		t.Fatal(err)
	}
	got := fromInner(o.(layout.Record).Inner)
	if !bytes.Equal(got.WrappedKey, cr.WrappedKey) || !bytes.Equal(got.Ciphertext, cr.Ciphertext) || !bytes.Equal(got.Owner, cr.Owner) || !bytes.Equal(got.Nonce, cr.Nonce) {
		t.Fatal("the envelope did not yield the inner fields")
	}
	if !seal.IsColdSealed(got) {
		t.Fatal("the cold form was lost")
	}
	// K_obj and the record-wrapping key are all the master gives; they open no payload.
	hm := cm
	hm.Class = seal.ClassSecret
	if b, err := k.OpenSecret(hm, got); err == nil {
		b.Destroy()
		t.Fatal("the master-derived keys opened a cold-role payload")
	}
	if b, err := k.OpenSecret(cm, got); err == nil {
		b.Destroy()
		t.Fatal("the master-derived keys opened a cold-role payload as the cold class")
	}
	oc, err := k.OpenColdOuter(cm, got) // the outer layer opens with the master-derived key
	if err != nil {
		t.Fatal(err)
	}
	wrong, _ := seal.DeriveColdSubKey(secret.Take(pat(0x99, 32)), wsID, uint32(seal.StoreFormat), pat(0x60, 28))
	if b, err := oc.OpenSecret(wrong); err == nil {
		b.Destroy()
		t.Fatal("a wrong sub-key opened the payload")
	}
	b, err := oc.OpenSecret(sub)
	if err != nil {
		t.Fatalf("the cold sub-key does not open the record that came out of the envelope: %v", err)
	}
	b.Destroy()
}

// The server sees a bucket size and nothing else of the record: no kind, id or
// anchor in the stored bytes.
// spec: SPO-Xlayout-SEC-004
func TestStoredObjectShowsNoPlaintextOfTheRecord(t *testing.T) {
	k := testKeys(t)
	m, r := hotSecret(t, k, 64)
	stored := sealRecordObject(t, k, recordOf(m, "secret", r))
	for name, needle := range map[string][]byte{"kind": []byte(m.Kind), "record id": m.RecordID, "anchor": m.Anchor, "class": []byte("secret"), "owner blob": r.Owner[:24], "nonce": r.Nonce, "wrapped key": r.WrappedKey[:24]} {
		if bytes.Contains(stored, needle) {
			t.Errorf("the stored object contains the %s in the clear", name)
		}
	}
	h, err := layout.ParseHeader(stored)
	if err != nil || h.Format != layout.FormatSealed || !bytes.Equal(h.Epoch, epoch) {
		t.Fatal("header")
	}
}

// Every single-bit flip of a stored sealed object makes OpenObject or the
// decoder fail.
// spec: SPO-Xlayout-SEC-001
func TestEveryBitFlipIsRefused(t *testing.T) {
	k := testKeys(t)
	m, r := hotSecret(t, k, 64)
	stored := sealRecordObject(t, k, recordOf(m, "secret", r))
	if len(stored) != 4096 {
		t.Fatalf("%d", len(stored))
	}
	check := func(stored []byte, bit int) {
		c := append([]byte(nil), stored...)
		c[bit/8] ^= 1 << (bit % 8)
		body, err := k.OpenObject(c, wsID, epoch)
		if err != nil {
			return
		}
		if _, err := layout.DecodeBody(body, rule); err != nil {
			return
		}
		t.Fatalf("bit %d flipped: the object was accepted", bit)
	}
	for bit := 0; bit < len(stored)*8; bit++ {
		check(stored, bit)
	}
	// A large object: the header, the nonce, the tag and a bounded sample.
	big := bigObject(t, k, 1<<20)
	rng := rand.New(rand.NewSource(1))
	for bit := 0; bit < 60*8; bit++ {
		check(big, bit)
		check(big, (len(big)-60)*8+bit)
	}
	for i := 0; i < 3000; i++ {
		check(big, rng.Intn(len(big)*8))
	}
	// and truncation at every length, for the small object
	for n := 0; n < len(stored); n++ {
		if _, err := k.OpenObject(stored[:n], wsID, epoch); err == nil {
			t.Fatalf("truncated to %d bytes: opened", n)
		}
	}
	if _, err := k.OpenObject(append(append([]byte(nil), stored...), 0), wsID, epoch); err == nil {
		t.Fatal("trailing byte")
	}
}

func bigObject(t testing.TB, k *seal.Keys, payload int) []byte {
	t.Helper()
	m, r := hotSecret(t, k, payload)
	return sealRecordObject(t, k, recordOf(m, "secret", r))
}

// The largest bucket seals; one byte more is refused with the size, never
// chunked.
// spec: SPO-Xlayout-OUT-003, SPO-Xlayout-PRE-003
func TestLargestObjectAndOneByteOver(t *testing.T) {
	k := testKeys(t)
	cbor := make([]byte, 4<<20-61)
	body, err := layout.FrameBody(cbor)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := k.SealObject(epoch, wsID, body)
	if err != nil || len(stored) != 4<<20 {
		t.Fatalf("%d %v", len(stored), err)
	}
	if _, err := layout.FrameBody(make([]byte, 4<<20-60)); err == nil {
		t.Fatal("one byte over the largest bucket was framed")
	}
}

// A header epoch that differs from the epoch in the associated data is
// refused.
// spec: SPO-Xlayout-PRE-004
func TestHeaderEpochMustMatch(t *testing.T) {
	k := testKeys(t)
	m, r := hotSecret(t, k, 64)
	stored := sealRecordObject(t, k, recordOf(m, "secret", r))
	if _, err := k.OpenObject(stored, wsID, pat(0xf1, 16)); err == nil {
		t.Fatal("opened under another expected epoch")
	}
	c := append([]byte(nil), stored...)
	copy(c[1:17], pat(0xf1, 16)) // header rewritten: the AD epoch is the header's, so it fails to authenticate
	if _, err := k.OpenObject(c, wsID, pat(0xf1, 16)); err == nil {
		t.Fatal("a rewritten header epoch opened")
	}
}

// The layout and the envelope are separate packages that must agree on sizes
// and bytes; nothing but this test joins them.
// spec: SPO-Xlayout-OUT-002, SPO-Xlayout-OUT-003, SPO-Xlayout-OUT-010
func TestLayoutAgreesWithTheEnvelope(t *testing.T) {
	if layout.HeaderSize != seal.ObjectHeaderSize || layout.SealedOverhead != seal.ObjectOverhead || layout.EpochSize != seal.EpochSize ||
		layout.NonceSize != seal.NonceSize || layout.MinBucket != seal.ObjectMinBucket || layout.BucketCount != seal.ObjectBucketCount ||
		layout.FormatSealed != seal.ObjectFormatSealed || layout.FormatSlots != seal.ObjectFormatSlots || layout.FormatChunked != seal.ObjectFormatChunked {
		t.Fatal("a constant differs between layout and seal")
	}
	a, b := layout.Buckets(), seal.ObjectBuckets()
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("bucket %d: %d and %d", i, a[i], b[i])
		}
	}
	pub := pat(0x90, 32)
	so := samplePolicySlots("standard")
	so.Meta.RecoveryPub, so.Meta.RecoveryPubHash = pub, seal.RecoveryPubKeyHash(pub)
	if _, err := layout.EncodeSlotsObject(so.Meta.KeyEpoch, so); err != nil {
		t.Fatalf("the recovery key hash rule differs from seal's: %v", err)
	}
	// a stored object's header is read the same way by both
	k := testKeys(t)
	m, r := hotSecret(t, k, 64)
	stored := sealRecordObject(t, k, recordOf(m, "secret", r))
	f, e, err := seal.ObjectHeader(stored)
	h, err2 := layout.ParseHeader(stored)
	if err != nil || err2 != nil || f != h.Format || !bytes.Equal(e, h.Epoch) {
		t.Fatal("the headers are read differently")
	}
}

// The independent check of the vectors, when a Python interpreter is present.
// spec: SPO-Xlayout-OUT-013
func TestVectorsAgreeWithTheIndependentCheck(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("no python3: run testdata/check_vectors.py where one is available")
	}
	out, err := exec.Command(py, "-I", "testdata/check_vectors.py", "--fast").CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
}
