package identity_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"runtime"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/identity"
)

// spec: SPO-Xidentity-INV-007
func TestContentHashIsOverTheTagValueArray(t *testing.T) {
	value := []any{"x", uint64(1), []byte{1, 2}}
	got := must(t)(identity.ContentOf(identity.TagPendingRecord, value))
	// [tag, value] written by hand: array(2), text(tag), the value.
	tag := "spo/obj/v1/pending-record"
	want := []byte{0x82, 0x78, byte(len(tag))}
	want = append(want, tag...)
	want = append(want, 0x83, 0x61, 'x', 0x01, 0x42, 1, 2)
	if got.Kind() != identity.KindPendingRecord || !bytes.Equal(got.Hash(), b256(want)) {
		t.Errorf("content hash is not Blake2b-256 of %x", want)
	}
	other := must(t)(identity.ContentOf(identity.TagAuditEvent, value))
	if other == got {
		t.Error("equal values of two kinds must have two identities")
	}
	// Encoded input gives the same identity as the value, and only when canonical.
	enc, _ := identity.EncodeCanonical(value)
	if via := must(t)(identity.ContentOfEncoded(identity.TagPendingRecord, enc)); via != got {
		t.Error("ContentOfEncoded differs from ContentOf")
	}
	if _, err := identity.ContentOfEncoded(identity.TagPendingRecord, []byte{0x9f, 0x01, 0xff}); !errors.Is(err, identity.ErrNotCanonical) {
		t.Errorf("non-canonical value hashed: %v", err)
	}
	// Map key order does not change the identity.
	a := must(t)(identity.ContentOf(identity.TagPendingRecord, identity.Map{{K: "a", V: 1}, {K: "b", V: 2}}))
	b := must(t)(identity.ContentOf(identity.TagPendingRecord, identity.Map{{K: "b", V: 2}, {K: "a", V: 1}}))
	if a != b {
		t.Error("map order changed the identity")
	}
}

// spec: SPO-Xidentity-INV-008, SPO-Xidentity-PRE-001
func TestTagRegistryBindsOneKindToOneTag(t *testing.T) {
	if _, err := identity.ContentOf("spo/obj/v1/unknown", "x"); err == nil {
		t.Error("an unregistered tag was accepted")
	}
	// A JSON-mapped kind has one valid tag, the one with the mapping version.
	if string(identity.TagPoolDescriptor) != "spo/obj/v1/pool-descriptor/map1" {
		t.Errorf("pool descriptor tag %q", identity.TagPoolDescriptor)
	}
	if _, err := identity.ContentOf("spo/obj/v1/pool-descriptor", "x"); err == nil {
		t.Error("the bare tag of a JSON-mapped kind gives a second identity to one descriptor")
	}
	seenKind := map[identity.Kind]identity.Tag{}
	seen := map[identity.Ref]identity.Tag{}
	for _, tg := range identity.Tags() {
		k, ok := tg.Kind()
		if !ok || !k.Valid() || k.Size() != 32 {
			t.Fatalf("%s: kind %v", tg, k)
		}
		if p, dup := seenKind[k]; dup {
			t.Errorf("%s and %s share kind %s", tg, p, k)
		}
		seenKind[k] = tg
		if back, ok := identity.TagOf(k); !ok || back != tg {
			t.Errorf("TagOf(%s) = %q", k, back)
		}
		r := must(t)(identity.ContentOf(tg, ""))
		if r.Kind() != k {
			t.Errorf("%s: the reference has kind %s, the tag binds %s", tg, r.Kind(), k)
		}
		if p, dup := seen[r]; dup {
			t.Errorf("%s and %s give one identity", tg, p)
		}
		seen[r] = tg
	}
	if _, ok := identity.TagOf(identity.KindKeyHash); ok {
		t.Error("a key kind has no tag")
	}
	a := must(t)(identity.ContentOf(identity.TagAuditEvent, "x"))
	b := must(t)(identity.ContentOf(identity.TagPendingRecord, "x"))
	if a == b || a.Kind() == b.Kind() {
		t.Error("equal values of two object kinds must be two typed identities")
	}
}

// The value at the decoder's maximum depth can be hashed with the wrapper.
//
// spec: SPO-Xidentity-INV-009
func TestObjectAtMaximumDepthIsHashable(t *testing.T) {
	deepest := func(levels int) []byte {
		b := bytes.Repeat([]byte{0x81}, levels)
		return append(b, 0x00)
	}
	ok := deepest(64) // 65 nested items: the decoder's limit
	if _, err := identity.DecodeCanonical(ok); err != nil {
		t.Fatalf("limit: %v", err)
	}
	if _, err := identity.ContentOfEncoded(identity.TagPendingRecord, ok); err != nil {
		t.Errorf("an object the decoder accepts cannot be hashed: %v", err)
	}
	if _, err := identity.DecodeCanonical(deepest(65)); err == nil {
		t.Error("one level past the limit was accepted")
	}
}

// A head that claims a huge count must not make the decoder allocate before it
// has read the items.
//
// spec: SPO-Xidentity-INV-009
func TestDecoderAllocationIsBoundedByTheInput(t *testing.T) {
	const zeros = 1 << 20
	var in []byte
	for i := 0; i < 64; i++ {
		in = append(in, 0x9a, 0x00, 0x10, 0x00, 0x00) // array of 2^20 items
	}
	in = append(in, make([]byte, zeros)...)
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	_, err := identity.DecodeCanonical(in)
	runtime.ReadMemStats(&m1)
	if err == nil {
		t.Fatal("a truncated nest was accepted")
	}
	if got := m1.TotalAlloc - m0.TotalAlloc; got > 128*uint64(len(in)) {
		t.Errorf("decoding %d bytes allocated %d bytes", len(in), got)
	}
	// Maps: each entry is at least two bytes.
	m := append([]byte{0xba, 0x00, 0x10, 0x00, 0x00}, make([]byte, zeros)...)
	if _, err := identity.DecodeCanonical(m); err == nil {
		t.Error("a map claiming 2^20 entries in 2^20 bytes was accepted")
	}
}

// spec: SPO-Xidentity-INV-009
func TestCanonicalCheck(t *testing.T) {
	good := []any{
		nil, true, false, uint64(0), uint64(23), uint64(24), uint64(255), uint64(256), uint64(65535), uint64(65536),
		uint64(1 << 32), uint64(1<<64 - 1), int64(-1), int64(-24), int64(-25), int64(-1 << 63), "", "héllo", []byte{}, []byte{1},
		[]any{}, []any{uint64(1), []any{"a"}}, identity.Map{{K: "a", V: uint64(1)}, {K: "bb", V: nil}},
	}
	for _, v := range good {
		enc, err := identity.EncodeCanonical(v)
		if err != nil {
			t.Fatalf("%v: %v", v, err)
		}
		dec, err := identity.DecodeCanonical(enc)
		if err != nil {
			t.Fatalf("%x: %v", enc, err)
		}
		again, _ := identity.EncodeCanonical(dec)
		if !bytes.Equal(again, enc) {
			t.Errorf("%x does not round-trip", enc)
		}
	}
	// RFC 8949 test vectors for the shortest heads.
	vec := map[string]any{"00": 0, "17": 23, "1818": 24, "1903e8": 1000, "1a000f4240": 1000000, "20": -1, "3903e7": -1000, "6161": "a", "80": []any{}}
	for hx, v := range vec {
		enc, _ := identity.EncodeCanonical(v)
		if hex.EncodeToString(enc) != hx {
			t.Errorf("%v: %x, want %s", v, enc, hx)
		}
	}
	// Map keys sort by encoded bytes: shorter first, then lexicographic.
	enc, _ := identity.EncodeCanonical(identity.Map{{K: "b", V: 0}, {K: "aa", V: 0}, {K: "a", V: 0}})
	if hex.EncodeToString(enc) != "a3616100616200626161"+"00" {
		t.Errorf("map order %x", enc)
	}

	bad := map[string]string{
		"long head":        "1800",   // 0 in two bytes
		"long head 2":      "190017", // 23 in three bytes
		"indefinite array": "9fff",   // [_ ]
		"indefinite bytes": "5fff",   //
		"indefinite map":   "bfff",   //
		"unsorted map":     "a2616200616100",
		"duplicate key":    "a2616100616100",
		"trailing":         "0000",
		"truncated array":  "8201",
		"truncated string": "6361",
		"empty":            "",
	}
	for name, hx := range bad {
		raw, _ := hex.DecodeString(hx)
		if _, err := identity.DecodeCanonical(raw); !errors.Is(err, identity.ErrNotCanonical) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, hx := range map[string]string{"float": "f90000", "tag": "c001", "undefined": "f7", "bad utf8": "62c328"} {
		raw, _ := hex.DecodeString(hx)
		if _, err := identity.DecodeCanonical(raw); !errors.Is(err, identity.ErrUnsupported) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := identity.EncodeCanonical(identity.Map{{K: "a", V: 1}, {K: "a", V: 2}}); err == nil {
		t.Error("duplicate map key encoded")
	}
	if _, err := identity.EncodeCanonical(struct{}{}); !errors.Is(err, identity.ErrUnsupported) {
		t.Error("a type outside the model encoded")
	}
	deep := []byte(bytes.Repeat([]byte{0x81}, 200))
	deep = append(deep, 0x00)
	if _, err := identity.DecodeCanonical(deep); err == nil {
		t.Error("200 levels of nesting accepted")
	}
}

// spec: SPO-Xidentity-INV-011, SPO-Xidentity-PRE-003
func TestFixedAnchors(t *testing.T) {
	ownerless := must(t)(identity.OwnerlessAnchor(identity.TagWorkspaceSettings))
	if ownerless != must(t)(identity.ContentOf(identity.TagWorkspaceSettings, "")) {
		t.Error("the ownerless anchor is the content hash of [tag, \"\"]")
	}
	if ownerless == must(t)(identity.OwnerlessAnchor(identity.TagProviderToken)) {
		t.Error("two ownerless kinds share an anchor")
	}
	l1 := must(t)(identity.LabelAnchor(identity.OwnerWallet, "alice"))
	if l1 != must(t)(identity.ContentOf(identity.TagLabel, []any{"wallet", "alice"})) {
		t.Error("label anchor is the content hash of [tag, [kind, name]]")
	}
	if l1 == must(t)(identity.LabelAnchor(identity.OwnerPool, "alice")) || l1 == must(t)(identity.LabelAnchor(identity.OwnerWallet, "bob")) {
		t.Error("label anchors must differ by owner kind and name")
	}
	if _, err := identity.LabelAnchor("nothing", "x"); err == nil {
		t.Error("unknown kind of owner")
	}

	pay := must(t)(identity.KeyHashOf(vk(10)))
	stake := must(t)(identity.KeyHashOf(vk(11)))
	if got := must(t)(identity.WalletAnchor(pay, stake)); got != pay {
		t.Error("a wallet with a payment key is anchored by it")
	}
	if got := must(t)(identity.WalletAnchor(pay, identity.Ref{})); got != pay {
		t.Error("payment only")
	}
	if got := must(t)(identity.WalletAnchor(identity.Ref{}, stake)); got != stake {
		t.Error("a stake-only wallet is anchored by its stake key")
	}
	if _, err := identity.WalletAnchor(identity.Ref{}, identity.Ref{}); err == nil {
		t.Error("a wallet with no key has no anchor")
	}
	script := identity.NativeScriptHashOf([]byte{0x82, 0x00, 0x00})
	if _, err := identity.WalletAnchor(script, identity.Ref{}); !errors.Is(err, identity.ErrBadKind) {
		t.Error("wallet anchor of a script hash")
	}
	if got := must(t)(identity.PoolAnchor(pay)); got != pay {
		t.Error("pool anchor")
	}
	if got := must(t)(identity.DRepAnchor(pay)); got != pay {
		t.Error("drep anchor")
	}
	if got := must(t)(identity.CommitteeAnchor(pay)); got != pay {
		t.Error("committee anchor")
	}
	if got := must(t)(identity.PolicyAnchor(script)); got != script {
		t.Error("policy anchor")
	}
	for _, f := range []func(identity.Ref) (identity.Ref, error){identity.PoolAnchor, identity.DRepAnchor, identity.CommitteeAnchor} {
		if _, err := f(script); !errors.Is(err, identity.ErrBadKind) {
			t.Error("anchor of the wrong kind accepted")
		}
	}
	if _, err := identity.PolicyAnchor(pay); !errors.Is(err, identity.ErrBadKind) {
		t.Error("policy anchored by a key hash")
	}
	if _, err := identity.PoolAnchor(identity.Ref{}); err == nil {
		t.Error("zero anchor accepted")
	}
}

// The vector comes from the native adapter's own computation (PolicyID of an
// "all" script with a sig and a before), so the identity is pinned to what the
// policy code produced, not to this package's formula.
//
// spec: SPO-Xidentity-INV-003
func TestNativeScriptHashFixedVector(t *testing.T) {
	script, _ := hex.DecodeString("8201828200581cabababababababababababababababababababababababababababab82051903e8")
	id := identity.NativeScriptHashOf(script)
	if id.String() != "script-hash:3a7491aed45141733e612dfaa8a741122b2c5fbf017e7cca8d77d891" {
		t.Errorf("%s", id)
	}
}
