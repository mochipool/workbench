package seal

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

func objKeys(t *testing.T) *Keys {
	t.Helper()
	k, err := DeriveKeys(secret.Take(pattern(0x10, 32)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Destroy)
	return k
}

// spec: SPO-Xlayout-OUT-003
func TestObjectBucketsAreFourKiBTimesPowersOfTwo(t *testing.T) {
	b := ObjectBuckets()
	if len(b) != ObjectBucketCount {
		t.Fatalf("%d buckets, want %d", len(b), ObjectBucketCount)
	}
	for i, n := range b {
		if n != 4096<<i {
			t.Fatalf("bucket %d is %d, want %d", i, n, 4096<<i)
		}
	}
	if b[len(b)-1] != 4<<20 {
		t.Fatalf("largest bucket %d, want 4 MiB", b[len(b)-1])
	}
}

// spec: SPO-Xlayout-OUT-004, SPO-Xlayout-SEC-001
func TestObjectRoundTripAndHeader(t *testing.T) {
	k := objKeys(t)
	epoch, genesis := pattern(0xf0, EpochSize), pattern(0x20, IDSize)
	for _, n := range ObjectBuckets()[:3] {
		body := pattern(1, n-ObjectOverhead)
		stored, err := k.SealObject(epoch, genesis, body)
		if err != nil {
			t.Fatalf("bucket %d: %v", n, err)
		}
		if len(stored) != n {
			t.Fatalf("stored length %d, want %d", len(stored), n)
		}
		f, e, err := ObjectHeader(stored)
		if err != nil || f != ObjectFormatSealed || !bytes.Equal(e, epoch) {
			t.Fatalf("header %x %x %v", f, e, err)
		}
		got, err := k.OpenObject(stored, genesis, epoch)
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("open: %v", err)
		}
	}
}

// spec: SPO-Xlayout-SEC-001, SPO-Xlayout-PRE-004
func TestObjectOpenRefusals(t *testing.T) {
	k := objKeys(t)
	epoch, genesis := pattern(0xf0, EpochSize), pattern(0x20, IDSize)
	stored, err := k.SealObject(epoch, genesis, make([]byte, 4096-ObjectOverhead))
	if err != nil {
		t.Fatal(err)
	}
	other := objKeys(t)
	_ = other
	flip := func(i int) []byte { c := append([]byte(nil), stored...); c[i] ^= 1; return c }
	cases := map[string][]byte{
		"unknown format byte": append([]byte{0x7f}, stored[1:]...),
		"slots format byte":   append([]byte{ObjectFormatSlots}, stored[1:]...),
		"chunked format byte": append([]byte{ObjectFormatChunked}, stored[1:]...),
		"epoch bit":           flip(5),
		"nonce bit":           flip(20),
		"tag bit":             flip(len(stored) - 1),
		"trailing byte":       append(append([]byte(nil), stored...), 0),
		"empty":               nil,
	}
	for name, c := range cases {
		if _, err := k.OpenObject(c, genesis, epoch); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
	if _, err := k.OpenObject(stored, pattern(0x21, IDSize), epoch); !errors.Is(err, ErrAuth) {
		t.Errorf("another genesis nonce: %v", err)
	}
	if _, err := k.OpenObject(stored, genesis, pattern(0xf1, EpochSize)); err == nil {
		t.Error("a header epoch that is not the expected epoch opened")
	}
	for n := 0; n < len(stored); n++ {
		if _, err := k.OpenObject(stored[:n], genesis, epoch); err == nil {
			t.Fatalf("truncated to %d bytes: opened", n)
		}
	}
}

// spec: SPO-Xlayout-PRE-003
func TestObjectSealRefusesAWrongBodyLength(t *testing.T) {
	k := objKeys(t)
	epoch, genesis := pattern(0xf0, EpochSize), pattern(0x20, IDSize)
	for _, n := range []int{0, 1, 4096 - ObjectOverhead - 1, 4096 - ObjectOverhead + 1, 4<<20 - ObjectOverhead + 1} {
		if _, err := k.SealObject(epoch, genesis, make([]byte, n)); err == nil {
			t.Errorf("body of %d bytes sealed", n)
		}
	}
}

// The object key and the nonce key are purpose keys of their own: HKDF-Expand
// of the INDEX key under the pinned labels, equal to an independent
// computation and equal to neither the wrapping key nor the index key nor each
// other. The index key is used only as an HMAC-SHA256 key whose messages start
// with the 8-byte big-endian length of a namespace (first byte 0x00), so the
// expand input (label || 0x01) never collides with another use of it.
// spec: SPO-Xlayout-SEC-002
func TestObjectKeysAreExpandedFromTheIndexKey(t *testing.T) {
	k := objKeys(t)
	var idx, w []byte
	k.Index.k.Use(func(x []byte) error { idx = append([]byte(nil), x...); return nil })
	k.wrap.Use(func(x []byte) error { w = append([]byte(nil), x...); return nil })
	if labelObject != "spo/object-envelope/1" || labelObjectNonce != "spo/object-nonce/1" {
		t.Fatal("the labels are pinned")
	}
	seen := [][]byte{idx, w}
	for _, label := range []string{labelObject, labelObjectNonce} {
		b, err := hkdfExpandKey(k.Index.k, label)
		if err != nil {
			t.Fatal(err)
		}
		var got []byte
		b.Use(func(x []byte) error { got = append([]byte(nil), x...); return nil })
		want, err := hkdf.Expand(sha256.New, idx, label, 32)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s: not HKDF-Expand(index key, label): %v", label, err)
		}
		for _, s := range seen {
			if bytes.Equal(got, s) {
				t.Fatalf("%s: equals another key", label)
			}
		}
		seen = append(seen, got)
	}
	// Every message the index key authenticates starts with a length whose
	// first byte is 0 and a label does not: the inputs cannot coincide.
	msg := lp(lp(nil, []byte("record-ref/v2")), []byte("x"))
	if msg[0] != 0 || labelObject[0] == 0 || labelObjectNonce[0] == 0 {
		t.Fatal("the index key's messages and the expand labels are not prefix-disjoint")
	}
}

// The nonce is synthetic: HMAC-SHA256(K_nonce, AD || body)[:24]. The same body
// under the same keys, epoch and genesis nonce gives identical stored bytes
// and so the same name; different bodies give different nonces; opening does
// not recompute the nonce, so an object sealed under any nonce opens.
// spec: SPO-Xlayout-OUT-004, SPO-Xlayout-INV-006
func TestObjectNonceIsSynthetic(t *testing.T) {
	k := objKeys(t)
	epoch, genesis := pattern(0xf0, EpochSize), pattern(0x20, IDSize)
	body := pattern(1, 4096-ObjectOverhead)
	a, err := k.SealObject(epoch, genesis, body)
	if err != nil {
		t.Fatal(err)
	}
	b, err := k.SealObject(epoch, genesis, body)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("sealing the same body twice gave different bytes")
	}
	nk, err := hkdfExpandKey(k.Index.k, labelObjectNonce)
	if err != nil {
		t.Fatal(err)
	}
	ad, _ := objectAD(epoch, genesis)
	var want []byte
	nk.Use(func(key []byte) error {
		m := hmac.New(sha256.New, key)
		m.Write(ad)
		m.Write(body)
		want = m.Sum(nil)[:NonceSize]
		return nil
	})
	if !bytes.Equal(a[ObjectHeaderSize:ObjectHeaderSize+NonceSize], want) {
		t.Fatal("the nonce is not HMAC-SHA256(K_nonce, AD || body)[:24]")
	}
	body2 := append([]byte(nil), body...)
	body2[len(body2)-1] ^= 1
	c, _ := k.SealObject(epoch, genesis, body2)
	if bytes.Equal(a[ObjectHeaderSize:ObjectHeaderSize+NonceSize], c[ObjectHeaderSize:ObjectHeaderSize+NonceSize]) {
		t.Fatal("two bodies share a nonce")
	}
	d, _ := k.SealObject(pattern(0xf1, EpochSize), genesis, body)
	if bytes.Equal(a[ObjectHeaderSize:ObjectHeaderSize+NonceSize], d[ObjectHeaderSize:ObjectHeaderSize+NonceSize]) {
		t.Fatal("two epochs share a nonce")
	}
	// Opening accepts any nonce: seal under a random one by hand.
	obj, err := hkdfExpandKey(k.Index.k, labelObject)
	if err != nil {
		t.Fatal(err)
	}
	nonce := pattern(0x55, NonceSize)
	var ct []byte
	obj.Use(func(key []byte) error { ct, err = aeadSeal(key, nonce, body, ad); return err })
	hand := append(append(append([]byte{ObjectFormatSealed}, epoch...), nonce...), ct...)
	if got, err := k.OpenObject(hand, genesis, epoch); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("an object under another nonce did not open: %v", err)
	}
}

// The keys are derived once per sealer (two locked buffers: K_obj and K_nonce)
// and destroyed on Close, on the error paths and by the one-shot methods: the
// locked-buffer count is back where it was whenever they return.
// spec: SPO-Xlayout-SEC-005
func TestObjectSealerHoldsTwoBuffersUntilClosed(t *testing.T) {
	k := objKeys(t)
	epoch, genesis := pattern(0xf0, EpochSize), pattern(0x20, IDSize)
	body := make([]byte, 4096-ObjectOverhead)
	base := secret.Budget().Live
	o, err := k.ObjectSealer()
	if err != nil {
		t.Fatal(err)
	}
	if got := secret.Budget().Live - base; got != 2 {
		t.Fatalf("a sealer holds %d buffers, want 2", got)
	}
	var stored []byte
	for i := 0; i < 20; i++ { // many objects, no further derivation
		stored, err = o.Seal(epoch, genesis, body)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := o.Open(stored, genesis, epoch); err != nil {
			t.Fatal(err)
		}
		if got := secret.Budget().Live - base; got != 2 {
			t.Fatalf("after %d objects the sealer holds %d buffers", i+1, got)
		}
	}
	o.Close()
	o.Close()
	if got := secret.Budget().Live; got != base {
		t.Fatalf("Close left %d buffers", got-base)
	}
	if _, err := o.Seal(epoch, genesis, body); !errors.Is(err, ErrSealerClosed) {
		t.Fatalf("a closed sealer sealed: %v", err)
	}
	if _, err := o.Open(stored, genesis, epoch); !errors.Is(err, ErrSealerClosed) {
		t.Fatalf("a closed sealer opened: %v", err)
	}
	if _, err := k.SealObject(epoch, genesis, body); err != nil {
		t.Fatal(err)
	}
	if _, err := k.OpenObject(stored, genesis, epoch); err != nil {
		t.Fatal(err)
	}
	k.SealObject(epoch, genesis, body[:5])
	k.SealObject(epoch[:3], genesis, body)
	k.OpenObject(stored[:100], genesis, epoch)
	k.OpenObject(stored, pattern(1, IDSize), epoch)
	k.OpenObject(stored, genesis, pattern(9, EpochSize))
	if got := secret.Budget().Live; got != base {
		t.Fatalf("the one-shot methods left %d buffers", got-base)
	}
}

// An ordinary unlock holds no key that only the layout needs: deriving the keys
// locks exactly the three buffers it locked before the object envelope.
// spec: SPO-Xlayout-SEC-005
func TestDeriveKeysLocksThreeBuffers(t *testing.T) {
	m := secret.Take(pattern(0x10, 32))
	defer m.Destroy()
	before := secret.Budget().Live
	k, err := DeriveKeys(m)
	if err != nil {
		t.Fatal(err)
	}
	if got := secret.Budget().Live - before; got != 3 {
		t.Fatalf("DeriveKeys holds %d locked buffers, want 3 (record wrapping, index, audit)", got)
	}
	k.Destroy()
	if got := secret.Budget().Live; got != before {
		t.Fatalf("Destroy left %d buffers", got-before)
	}
}
