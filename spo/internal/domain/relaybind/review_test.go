package relaybind_test

// Tests of the package review of ADR 0014 work package 1 (findings 1 to 10).
// Every test cites the spec ids it covers.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"sort"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
)

func mustHexS(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func idSlice(a [32]byte) []byte { return a[:] }

func sortedNames(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// smallOrderEncodings are the eight small-order points of Curve25519 in
// Edwards form, and the encodings that set the sign bit of x = 0 (which are not
// canonical): ten encodings of five y values.
func smallOrderEncodings() map[string][]byte {
	return map[string][]byte{
		"identity (y=1)":          mustHexS("0100000000000000000000000000000000000000000000000000000000000000"),
		"identity, sign bit set":  mustHexS("0100000000000000000000000000000000000000000000000000000000000080"),
		"order 2 (y=-1)":          mustHexS("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
		"order 2, sign bit set":   mustHexS("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
		"order 4 (y=0)":           mustHexS("0000000000000000000000000000000000000000000000000000000000000000"),
		"order 4 (y=0), sign set": mustHexS("0000000000000000000000000000000000000000000000000000000000000080"),
		"order 8, y1":             mustHexS("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
		"order 8, y1, sign set":   mustHexS("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
		"order 8, y2":             mustHexS("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
		"order 8, y2, sign set":   mustHexS("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
	}
}

// nonCanonicalEncodings are the encodings with y = p + i (i = 0 to 18, the
// only ones below 2^255), with and without the sign bit. Several decode to
// small-order points, others to ordinary ones; all are refused.
func nonCanonicalEncodings() map[string][]byte {
	out := map[string][]byte{}
	for i := 0; i <= 18; i++ {
		e := bytes.Repeat([]byte{0xff}, 32)
		e[0] = byte(0xed + i)
		e[31] = 0x7f
		out[fmt.Sprintf("y = p+%d", i)] = bytes.Clone(e)
		e[31] = 0xff
		out[fmt.Sprintf("y = p+%d, sign bit set", i)] = bytes.Clone(e)
	}
	return out
}

// --- an independent Ed25519 signer with a chosen nonce (math/big) ------------

var (
	edP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	edQ = func() *big.Int {
		q, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
		return q.Add(q, new(big.Int).Lsh(big.NewInt(1), 252))
	}()
	edD = func() *big.Int {
		d := new(big.Int).Mul(big.NewInt(-121665), new(big.Int).ModInverse(big.NewInt(121666), edP))
		return d.Mod(d, edP)
	}()
)

type edPoint struct{ x, y *big.Int }

func edMul(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Mul(a, b), edP) }
func edInv(a *big.Int) *big.Int    { return new(big.Int).ModInverse(a, edP) }

func edAdd(a, b edPoint) edPoint {
	x1y2, x2y1, y1y2, x1x2 := edMul(a.x, b.y), edMul(b.x, a.y), edMul(a.y, b.y), edMul(a.x, b.x)
	dxy := edMul(edD, edMul(x1x2, y1y2))
	x3 := edMul(new(big.Int).Add(x1y2, x2y1), edInv(new(big.Int).Mod(new(big.Int).Add(big.NewInt(1), dxy), edP)))
	y3 := edMul(new(big.Int).Add(y1y2, x1x2), edInv(new(big.Int).Mod(new(big.Int).Sub(big.NewInt(1), dxy), edP)))
	return edPoint{x3, y3}
}

func edBase() edPoint {
	y := edMul(big.NewInt(4), edInv(big.NewInt(5)))
	y2 := edMul(y, y)
	x2 := edMul(new(big.Int).Mod(new(big.Int).Sub(y2, big.NewInt(1)), edP), edInv(new(big.Int).Mod(new(big.Int).Add(edMul(edD, y2), big.NewInt(1)), edP)))
	x := new(big.Int).Exp(x2, new(big.Int).Div(new(big.Int).Add(edP, big.NewInt(3)), big.NewInt(8)), edP)
	if edMul(x, x).Cmp(x2) != 0 {
		sqrtM1 := new(big.Int).Exp(big.NewInt(2), new(big.Int).Div(new(big.Int).Sub(edP, big.NewInt(1)), big.NewInt(4)), edP)
		x = edMul(x, sqrtM1)
	}
	if x.Bit(0) != 0 {
		x = new(big.Int).Sub(edP, x)
	}
	return edPoint{x, y}
}

func edMulBase(s *big.Int) edPoint {
	r := edPoint{big.NewInt(0), big.NewInt(1)}
	b := edBase()
	for i := s.BitLen() - 1; i >= 0; i-- {
		r = edAdd(r, r)
		if s.Bit(i) == 1 {
			r = edAdd(r, b)
		}
	}
	return r
}

func leToInt(b []byte) *big.Int {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(r)
}

func intToLE32(x *big.Int) []byte {
	b := x.FillBytes(make([]byte, 32))
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

func edEncode(p edPoint) []byte {
	b := intToLE32(p.y)
	b[31] |= byte(p.x.Bit(0)) << 7
	return b
}

// signWithNonce is RFC 8032 signing in which the nonce hash also takes extra.
// With extra empty it is the standard deterministic signature; with extra set
// it is another valid signature over the same message by the same key.
func signWithNonce(seed, msg, extra []byte) []byte {
	h := sha512.Sum512(seed)
	s := bytes.Clone(h[:32])
	s[0] &= 248
	s[31] &= 127
	s[31] |= 64
	a := leToInt(s)
	A := edEncode(edMulBase(a))
	rh := sha512.New()
	rh.Write(h[32:])
	rh.Write(extra)
	rh.Write(msg)
	r := leToInt(rh.Sum(nil))
	r.Mod(r, edQ)
	R := edEncode(edMulBase(r))
	kh := sha512.New()
	kh.Write(R)
	kh.Write(A)
	kh.Write(msg)
	k := leToInt(kh.Sum(nil))
	k.Mod(k, edQ)
	S := new(big.Int).Add(r, new(big.Int).Mul(k, a))
	S.Mod(S, edQ)
	return append(R, intToLE32(S)...)
}

// --- finding 4: small-order and non-canonical verification keys ---------------

// spec: SPO-Xrelaybind-SEC-008
func TestSmallOrderAndNonCanonicalKeysAreRefusedByParseCOSEKey(t *testing.T) {
	encs := map[string][]byte{}
	for k, v := range smallOrderEncodings() {
		encs[k] = v
	}
	for k, v := range nonCanonicalEncodings() {
		encs[k] = v
	}
	if len(encs) != 10+38 {
		t.Fatalf("%d encodings", len(encs))
	}
	for name, enc := range encs {
		if _, err := relaybind.ParseCOSEKey(cose.EncodeKey(enc)); !errors.Is(err, relaybind.ErrWeakKey) {
			t.Errorf("%s: ParseCOSEKey(%x) = %v, want ErrWeakKey", name, enc, err)
		}
	}
	// Ordinary keys pass: no false positive over 300 fresh keys.
	for i := 0; i < 300; i++ {
		pub := ed25519.NewKeyFromSeed(bs(32, byte(i))).Public().(ed25519.PublicKey)
		if i > 255 {
			pub = ed25519.NewKeyFromSeed(append(bs(31, byte(i)), 9)).Public().(ed25519.PublicKey)
		}
		if _, err := relaybind.ParseCOSEKey(cose.EncodeKey(pub)); err != nil {
			t.Fatalf("an ordinary key was refused: %v", err)
		}
	}
	if _, err := relaybind.ParseCOSEKey(cose.EncodeKey(testPub[:])); err != nil {
		t.Fatal(err)
	}
}

// The identity point as the verification key: R = identity, S = 0 verifies for
// every message under Go's ed25519, so the statement "verified" without any
// signer. VerifyBinding, VerifyRevoke and VerifyDeviceRevoke refuse the key
// before they verify, whatever the signature.
//
// spec: SPO-Xrelaybind-SEC-008
func TestSmallOrderKeyCannotForgeAStatement(t *testing.T) {
	id := smallOrderEncodings()["identity (y=1)"]
	var vk [32]byte
	copy(vk[:], id)
	k := cose.Blake2b224(id)
	prot := protectedWith(k[:])
	payload := goodPayload(t)
	forged := make([]byte, 64)
	forged[0] = 1 // R = the identity point, S = 0
	if !ed25519.Verify(id, cose.SigStructure(prot, payload), forged) {
		t.Fatal("setup: the forged signature does not verify under Go's ed25519; the attack of the review is not reproduced")
	}
	st := mustStatement(t, assemble(bstr(prot), unprotOK, bstr(payload), bstr(forged)))
	if _, err := relaybind.VerifyBinding(st, vk, testDev, nowT, pol()); !errors.Is(err, relaybind.ErrWeakKey) {
		t.Errorf("VerifyBinding under the identity key: %v, want ErrWeakKey", err)
	}
	rv, _ := relaybind.Revoke{All: true, NotBefore: nowT}.Render()
	rst := mustStatement(t, assemble(bstr(prot), unprotOK, bstr(rv), bstr(forged)))
	if !ed25519.Verify(id, cose.SigStructure(prot, rv), forged) {
		t.Fatal("setup: the forged revoke signature does not verify")
	}
	if _, err := relaybind.VerifyRevoke(rst, vk, nowT, pol()); !errors.Is(err, relaybind.ErrWeakKey) {
		t.Errorf("VerifyRevoke under the identity key: %v, want ErrWeakKey", err)
	}
	var x party.X25519Public
	var sig [64]byte
	copy(sig[:], forged)
	devMsg, _ := relaybind.DeviceRevokeBytes(party.FingerprintOf(party.Ed25519Public(vk), x), nowT)
	if !ed25519.Verify(id, devMsg, forged) {
		t.Fatal("setup: the forged device revoke does not verify")
	}
	if _, err := verifyDevRevoke(party.Ed25519Public(vk), x, nowT, sig, nowT, relaybind.SkewSeconds); !errors.Is(err, relaybind.ErrWeakKey) {
		t.Errorf("VerifyDeviceRevoke under the identity key: %v, want ErrWeakKey", err)
	}
	// Every encoding is refused by the verifier itself, before the signature
	// check (the signature here is not even valid).
	encs := map[string][]byte{}
	for n, e := range smallOrderEncodings() {
		encs[n] = e
	}
	for n, e := range nonCanonicalEncodings() {
		encs[n] = e
	}
	for name, enc := range encs {
		var v [32]byte
		copy(v[:], enc)
		h := cose.Blake2b224(enc)
		s := mustStatement(t, assemble(bstr(protectedWith(h[:])), unprotOK, bstr(payload), bstr(make([]byte, 64))))
		if _, err := relaybind.VerifyBinding(s, v, testDev, nowT, pol()); !errors.Is(err, relaybind.ErrWeakKey) {
			t.Errorf("%s: VerifyBinding %v, want ErrWeakKey", name, err)
		}
		if _, err := relaybind.VerifyRevoke(s, v, nowT, pol()); !errors.Is(err, relaybind.ErrWeakKey) {
			t.Errorf("%s: VerifyRevoke %v, want ErrWeakKey", name, err)
		}
	}
}

// Two valid signatures by one key over one statement: Ed25519 signatures are
// unforgeable by a non-holder but not unique. FullHash (signature included)
// differs; StatementID (wallet key hash and payload) is the same, and is what
// a registry de-duplicates by.
//
// spec: SPO-Xrelaybind-SEC-003, SPO-Xrelaybind-OUT-006, SPO-Xrelaybind-OUT-013
func TestTwoSignaturesOverOneStatement(t *testing.T) {
	payload := goodPayload(t)
	prot := protectedWith(testK[:])
	ss := cose.SigStructure(prot, payload)
	std := signWithNonce(testPriv.Seed(), ss, nil)
	if !bytes.Equal(std, ed25519.Sign(testPriv, ss)) {
		t.Fatal("setup: the test signer does not reproduce RFC 8032 signing")
	}
	other := signWithNonce(testPriv.Seed(), ss, []byte("another nonce"))
	if bytes.Equal(std, other) {
		t.Fatal("setup: the nonce did not change the signature")
	}
	build := func(sig []byte) relaybind.VerifiedBinding {
		in := assemble(bstr(prot), unprotOK, bstr(payload), bstr(sig))
		vb, err := relaybind.VerifyBinding(mustStatement(t, in), testPub, testDev, nowT, pol())
		if err != nil {
			t.Fatalf("a valid signature does not verify: %v", err)
		}
		return vb
	}
	a, b := build(std), build(other)
	if a.FullHash() == b.FullHash() {
		t.Error("two different signatures have one full hash: it would be a commitment to the statement only")
	}
	if a.StatementID() != b.StatementID() {
		t.Error("two signatures over one statement have different statement identities: the registry would count them twice")
	}
	if a.StatementID() == a.FullHash() {
		t.Error("the statement identity is the full hash")
	}
	// The identity is the wallet key hash and the payload, nothing else: another
	// address form or key order of the same key and payload is the same statement;
	// another payload or another signer is not.
	baseAddr := cat([]byte{0x01}, testK[:], bs(28, 0x70))
	swapped := cat(head(5, 2), tstr("address"), bstr(testK[:]), kAlg, vAlg)
	for name, p := range map[string][]byte{"base address form": protectedWith(baseAddr), "other key order": swapped} {
		sig := signWithNonce(testPriv.Seed(), cose.SigStructure(p, payload), nil)
		vb, err := relaybind.VerifyBinding(mustStatement(t, assemble(bstr(p), unprotOK, bstr(payload), bstr(sig))), testPub, testDev, nowT, pol())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if vb.StatementID() != a.StatementID() {
			t.Errorf("%s: the statement identity depends on header bytes", name)
		}
		if vb.FullHash() == a.FullHash() {
			t.Errorf("%s: the full hash does not depend on header bytes", name)
		}
	}
	ids := map[[32]byte]string{a.StatementID(): "good"}
	add := func(name string, vb relaybind.VerifiedBinding) {
		if prev, dup := ids[vb.StatementID()]; dup {
			t.Errorf("%s has the statement identity of %s", name, prev)
		}
		ids[vb.StatementID()] = name
	}
	later := []byte(bindingText(testDev, fmt.Sprint(fromT+1), fmt.Sprint(untilT)))
	vb2, err := relaybind.VerifyBinding(mustStatement(t, signed(testK[:], later)), testPub, testDev, nowT, pol())
	if err != nil {
		t.Fatal(err)
	}
	add("another payload", vb2)
	k2 := cose.Blake2b224(otherPub[:])
	vb3, err := relaybind.VerifyBinding(mustStatement(t, signedWith(otherPriv, protectedWith(k2[:]), payload)), otherPub, testDev, nowT, pol())
	if err != nil {
		t.Fatal(err)
	}
	add("another signer, same payload", vb3)
	// A revoke has an identity too, and a binding and a revoke never share one.
	rv, _ := relaybind.Revoke{Device: testDev, NotBefore: nowT}.Render()
	vr, err := relaybind.VerifyRevoke(mustStatement(t, signed(testK[:], rv)), testPub, nowT, pol())
	if err != nil {
		t.Fatal(err)
	}
	if _, dup := ids[vr.StatementID()]; dup || vr.StatementID() == vr.FullHash() {
		t.Error("the revoke identity collides")
	}
	vr2, err := relaybind.VerifyRevoke(mustStatement(t, assemble(bstr(prot), unprotOK, bstr(rv), bstr(signWithNonce(testPriv.Seed(), cose.SigStructure(prot, rv), []byte("n"))))), testPub, nowT, pol())
	if err != nil || vr2.StatementID() != vr.StatementID() || vr2.FullHash() == vr.FullHash() {
		t.Errorf("two signatures over one revoke: %v", err)
	}
}

// --- finding 1 and 2: invalidation and the three tombstone scopes -------------

func bindingFrom(t testing.TB, dev party.Fingerprint, from int64, now int64) relaybind.VerifiedBinding {
	t.Helper()
	in := signed(testK[:], []byte(bindingText(dev, fmt.Sprint(from), fmt.Sprint(from+relaybind.DefaultLifetimeSeconds))))
	vb, err := relaybind.VerifyBinding(mustStatement(t, in), testPub, dev, now, pol())
	if err != nil {
		t.Fatalf("binding from %d: %v", from, err)
	}
	return vb
}

// "Forget this device", then a later re-login with from = not-before + 1: the
// client's own re-sent revoke, or anyone replaying the revoke bytes (a revoke
// names no relay), must not delete the newer binding. Recording the tombstone
// is always done; the relay deletes a binding, closes sessions and purges mail
// only when Invalidated says so.
//
// spec: SPO-Xrelaybind-OUT-012
func TestAReplayedRevokeDoesNotInvalidateANewerBinding(t *testing.T) {
	nb := nowT
	old := bindingFrom(t, testDev, fromT, nowT)
	tomb := relaybind.NoTombstones()

	// The first revoke is recorded and invalidates the binding that existed.
	tomb = tomb.Merge(relaybind.ScopePair, nb)
	if !relaybind.Invalidated(old.Binding(), tomb) {
		t.Fatal("a revoke at not-before >= from did not invalidate the stored binding")
	}
	if err := relaybind.Admit(old, tomb, nowT, pol()); !errors.Is(err, relaybind.ErrRevoked) {
		t.Fatalf("the old binding is admitted again after the revoke: %v", err)
	}

	// The device logs in again: from = not-before + 1 (ChooseFrom).
	from2, err := relaybind.ChooseFrom(nb+5, nb)
	if err != nil || from2 != nb+1 {
		t.Fatalf("ChooseFrom: %d, %v", from2, err)
	}
	fresh := bindingFrom(t, testDev, from2, nb+5)
	if err := relaybind.Admit(fresh, tomb, nb+5, pol()); err != nil {
		t.Fatalf("the re-login binding is refused: %v", err)
	}

	// The same revoke arrives again (the client re-sends it on every connection,
	// or somebody replays it): the tombstone is merged (it stays at the maximum)
	// and the new binding is NOT invalidated.
	for _, replay := range []struct {
		name  string
		scope relaybind.Scope
		nb    int64
	}{
		{"the same pair revoke", relaybind.ScopePair, nb},
		{"an older pair revoke", relaybind.ScopePair, nb - 1000},
		{"the same all-devices revoke", relaybind.ScopeAll, nb},
		{"the same device-signed revoke", relaybind.ScopeDevice, nb},
		{"a revoke at the largest not-before below from", relaybind.ScopePair, from2 - 1},
	} {
		merged := tomb.Merge(replay.scope, replay.nb)
		if relaybind.Invalidated(fresh.Binding(), merged) {
			t.Errorf("%s: the replay invalidates the newer binding (it would wipe it and its mail)", replay.name)
		}
		if merged.Merge(replay.scope, replay.nb) != merged || relaybind.MergeTombstone(tomb.Pair, nb-1000) != tomb.Pair {
			t.Errorf("%s: the tombstone is not idempotent or was lowered", replay.name)
		}
	}
	if m := tomb.Merge(relaybind.ScopePair, nb-1000); m != tomb {
		t.Errorf("an older revoke lowered the tombstone: %+v", m)
	}

	// A revoke made after the re-login (not-before >= from2) does invalidate it.
	for _, scope := range []relaybind.Scope{relaybind.ScopePair, relaybind.ScopeAll, relaybind.ScopeDevice} {
		if !relaybind.Invalidated(fresh.Binding(), tomb.Merge(scope, from2)) {
			t.Errorf("scope %d: a revoke at not-before == from does not invalidate", scope)
		}
	}
	// An unknown scope merges nothing.
	if tomb.Merge(0, math.MaxInt64) != tomb || tomb.Merge(99, math.MaxInt64) != tomb {
		t.Error("an unknown scope changed the tombstones")
	}
}

// Each scope's revoke lands in its own table and nowhere else, keeps the maximum,
// and leaves the other two alone.
//
// spec: SPO-Xrelaybind-OUT-010, SPO-Xrelaybind-OUT-014
func TestMergePutsEachScopeInItsOwnField(t *testing.T) {
	no := relaybind.NoTombstone
	n := relaybind.NoTombstones()
	for _, c := range []struct {
		scope relaybind.Scope
		want  relaybind.Tombstones
	}{
		{relaybind.ScopePair, relaybind.Tombstones{Pair: 5, All: no, Device: no}},
		{relaybind.ScopeAll, relaybind.Tombstones{Pair: no, All: 5, Device: no}},
		{relaybind.ScopeDevice, relaybind.Tombstones{Pair: no, All: no, Device: 5}},
	} {
		got := n.Merge(c.scope, 5)
		if got != c.want {
			t.Errorf("scope %d: %+v, want %+v", c.scope, got, c.want)
		}
		if again := got.Merge(c.scope, 3).Merge(c.scope, 9).Merge(c.scope, 7); again.Pair < got.Pair || again.All < got.All || again.Device < got.Device {
			t.Errorf("scope %d: lowered: %+v", c.scope, again)
		}
	}
	both := n.Merge(relaybind.ScopePair, 4).Merge(relaybind.ScopeAll, 8).Merge(relaybind.ScopeDevice, 6)
	if both != (relaybind.Tombstones{Pair: 4, All: 8, Device: 6}) {
		t.Errorf("three scopes: %+v", both)
	}
}

// Admission takes all three tombstone scopes, each of which blocks on its own,
// one second at a time.
//
// spec: SPO-Xrelaybind-OUT-012, SPO-Xrelaybind-OUT-014
func TestAdmitTakesAllThreeTombstoneScopes(t *testing.T) {
	vb := bindingFrom(t, testDev, fromT, nowT)
	no := relaybind.NoTombstone
	for _, c := range []struct {
		name string
		t    relaybind.Tombstones
	}{
		{"pair", relaybind.Tombstones{Pair: fromT, All: no, Device: no}},
		{"all", relaybind.Tombstones{Pair: no, All: fromT, Device: no}},
		{"device only", relaybind.Tombstones{Pair: no, All: no, Device: fromT}},
		{"pair later", relaybind.Tombstones{Pair: fromT + 99, All: no, Device: no}},
		{"all later", relaybind.Tombstones{Pair: no, All: fromT + 99, Device: no}},
		{"device only later", relaybind.Tombstones{Pair: no, All: no, Device: fromT + 99}},
	} {
		if err := relaybind.Admit(vb, c.t, nowT, pol()); !errors.Is(err, relaybind.ErrRevoked) {
			t.Errorf("%s tombstone at from: %v, want ErrRevoked", c.name, err)
		}
	}
	for _, c := range []struct {
		name string
		t    relaybind.Tombstones
	}{
		{"none", relaybind.NoTombstones()},
		{"pair one earlier", relaybind.Tombstones{Pair: fromT - 1, All: no, Device: no}},
		{"all one earlier", relaybind.Tombstones{Pair: no, All: fromT - 1, Device: no}},
		{"device only one earlier", relaybind.Tombstones{Pair: no, All: no, Device: fromT - 1}},
		{"all three one earlier", relaybind.Tombstones{Pair: fromT - 1, All: fromT - 1, Device: fromT - 1}},
	} {
		if err := relaybind.Admit(vb, c.t, nowT, pol()); err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// A device-signed revoke carries no wallet key. Arriving where the device is
// not bound (so there is no K to store it under) it is recorded under the
// device alone, and then an old binding of that device by ANY key is refused;
// a newer one is admitted.
//
// spec: SPO-Xrelaybind-OUT-014
func TestDeviceOnlyTombstoneRefusesOldBindingsOfAnyKey(t *testing.T) {
	nb := nowT
	tomb := relaybind.NoTombstones().Merge(relaybind.ScopeDevice, nb)
	oldByK := bindingFrom(t, testDev, fromT, nowT)
	if err := relaybind.Admit(oldByK, tomb, nowT, pol()); !errors.Is(err, relaybind.ErrRevoked) {
		t.Errorf("the device's old binding is admitted after its device-signed revoke: %v", err)
	}
	// The same device under another wallet key.
	k2 := cose.Blake2b224(otherPub[:])
	in := signedWith(otherPriv, protectedWith(k2[:]), []byte(bindingText(testDev, fmt.Sprint(fromT), fmt.Sprint(fromT+relaybind.DefaultLifetimeSeconds))))
	vb2, err := relaybind.VerifyBinding(mustStatement(t, in), otherPub, testDev, nowT, pol())
	if err != nil {
		t.Fatal(err)
	}
	if err := relaybind.Admit(vb2, tomb, nowT, pol()); !errors.Is(err, relaybind.ErrRevoked) {
		t.Errorf("the device under another key is admitted: %v", err)
	}
	if relaybind.Invalidated(oldByK.Binding(), relaybind.NoTombstones()) {
		t.Error("no tombstone invalidates")
	}
	newer := bindingFrom(t, testDev, nb+1, nb+1)
	if err := relaybind.Admit(newer, tomb, nb+1, pol()); err != nil {
		t.Errorf("a binding after the revoke is refused: %v", err)
	}
	// The relay looks the device-only table up by the binding's own device, so
	// another device has no device-only tombstone and is unaffected.
	other := bindingFrom(t, fpOf(0x77), fromT, nowT)
	if err := relaybind.Admit(other, relaybind.NoTombstones(), nowT, pol()); err != nil {
		t.Errorf("another device is refused: %v", err)
	}
	// The scope of a verified wallet-signed revoke.
	rd, _ := relaybind.Revoke{Device: testDev, NotBefore: nowT}.Render()
	ra, _ := relaybind.Revoke{All: true, NotBefore: nowT}.Render()
	vrd, err := relaybind.VerifyRevoke(mustStatement(t, signed(testK[:], rd)), testPub, nowT, pol())
	if err != nil || vrd.Scope() != relaybind.ScopePair {
		t.Errorf("revoke of one device: scope %d, %v", vrd.Scope(), err)
	}
	vra, err := relaybind.VerifyRevoke(mustStatement(t, signed(testK[:], ra)), testPub, nowT, pol())
	if err != nil || vra.Scope() != relaybind.ScopeAll {
		t.Errorf("revoke of all: scope %d, %v", vra.Scope(), err)
	}
}

// --- finding 3: the tombstone expiry against until ---------------------------

// The proof of concept of the review: from = not-before and until = not-before
// + the maximum lifetime. At now == until the binding still verifies, so its
// tombstone must still be kept; one second later the binding is expired and
// the tombstone may go. Never "binding verifies" and "tombstone expired" at
// once, at any second around the edge.
//
// spec: SPO-Xrelaybind-OUT-010
func TestTombstoneIsKeptWhileTheBindingItBlocksStillVerifies(t *testing.T) {
	nb := fromT
	until := nb + relaybind.MaxLifetimeSeconds
	in := signed(testK[:], []byte(bindingText(testDev, fmt.Sprint(nb), fmt.Sprint(until))))
	tomb := relaybind.NoTombstones().Merge(relaybind.ScopePair, nb)
	for now := until - 3; now <= until+3; now++ {
		vb, err := verifyBinding(t, in, testDev, now, pol())
		verifies := err == nil
		if !verifies && !errors.Is(err, relaybind.ErrExpired) {
			t.Fatalf("now %d: %v", now, err)
		}
		if verifies && relaybind.TombstoneExpired(nb, now) {
			t.Errorf("now %d (until %d): the binding verifies and its tombstone is expired: the revoked binding would be accepted again", now, until)
		}
		if verifies {
			if err := relaybind.Admit(vb, tomb, now, pol()); !errors.Is(err, relaybind.ErrRevoked) {
				t.Errorf("now %d: Admit %v, want ErrRevoked", now, err)
			}
		}
	}
	if relaybind.TombstoneExpired(nb, until) || !relaybind.TombstoneExpired(nb, until+1) {
		t.Errorf("expiry edge: at until %v, at until+1 %v, want false and true",
			relaybind.TombstoneExpired(nb, until), relaybind.TombstoneExpired(nb, until+1))
	}
	// A tightened maximum lifetime keeps its tombstones no longer than the ADR's
	// (the tombstone's life is the ADR maximum; a tighter relay may drop earlier
	// only by its own choice, never later than this).
	if relaybind.TombstoneExpired(nb, nb) {
		t.Error("a fresh tombstone is expired")
	}
}

// --- finding 5: which part of the address matched is exposed; callers display K

// spec: SPO-Xrelaybind-PRE-014
func TestAddressPartNames(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range []relaybind.AddressPart{relaybind.PartKeyHash, relaybind.PartEnterprise, relaybind.PartReward, relaybind.PartBasePayment} {
		s := p.String()
		if s == "unknown" || seen[s] {
			t.Errorf("part %d is named %q", p, s)
		}
		seen[s] = true
	}
	if relaybind.AddressPart(0).String() != "unknown" || relaybind.AddressPart(200).String() != "unknown" {
		t.Error("an invalid part has a name")
	}
}

// --- finding 6: a binding is never accepted before it is valid ----------------

// A phished binding dated years ahead cannot be presented, registered or held:
// VerifyBinding refuses a from beyond now + skew, Admit refuses it again at
// registration time, and a tightened skew moves the edge.
//
// spec: SPO-Xrelaybind-SEC-009
func TestABindingIsNeverAcceptedBeforeItIsValid(t *testing.T) {
	skew := relaybind.SkewSeconds
	mk := func(from int64) []byte {
		return signed(testK[:], []byte(bindingText(testDev, fmt.Sprint(from), fmt.Sprint(from+relaybind.DefaultLifetimeSeconds))))
	}
	// Edge at the default skew: from == now + skew is valid; one second more is not.
	if _, err := verifyBinding(t, mk(nowT+skew), testDev, nowT, pol()); err != nil {
		t.Errorf("from == now + skew: %v", err)
	}
	if _, err := verifyBinding(t, mk(nowT+skew+1), testDev, nowT, pol()); !errors.Is(err, relaybind.ErrNotYetValid) {
		t.Errorf("from == now + skew + 1: %v, want ErrNotYetValid", err)
	}
	// Years ahead.
	for _, years := range []int64{1, 5, 100} {
		if _, err := verifyBinding(t, mk(nowT+years*365*86400), testDev, nowT, pol()); !errors.Is(err, relaybind.ErrNotYetValid) {
			t.Errorf("%d years ahead: %v, want ErrNotYetValid", years, err)
		}
	}
	// A tightened skew.
	zero := relaybind.Policy{Skew: 0, MaxLifetime: relaybind.MaxLifetimeSeconds}
	if _, err := verifyBinding(t, mk(nowT), testDev, nowT, zero); err != nil {
		t.Errorf("skew 0, from == now: %v", err)
	}
	if _, err := verifyBinding(t, mk(nowT+1), testDev, nowT, zero); !errors.Is(err, relaybind.ErrNotYetValid) {
		t.Errorf("skew 0, from == now + 1: %v", err)
	}
	// Admit repeats the window at its own time: a binding verified later is
	// refused if it is held to an earlier time, and one held past until is dead.
	vb, err := verifyBinding(t, mk(nowT+skew), testDev, nowT, pol())
	if err != nil {
		t.Fatal(err)
	}
	if err := relaybind.Admit(vb, relaybind.NoTombstones(), nowT, pol()); err != nil {
		t.Errorf("Admit at the verification time: %v", err)
	}
	if err := relaybind.Admit(vb, relaybind.NoTombstones(), nowT-1, pol()); !errors.Is(err, relaybind.ErrNotYetValid) {
		t.Errorf("Admit one second before: %v, want ErrNotYetValid", err)
	}
	if err := relaybind.Admit(vb, relaybind.NoTombstones(), nowT+skew, zero); err != nil {
		t.Errorf("Admit at from, skew 0: %v", err)
	}
	if err := relaybind.Admit(vb, relaybind.NoTombstones(), nowT+skew-1, zero); !errors.Is(err, relaybind.ErrNotYetValid) {
		t.Errorf("Admit one second before from, skew 0: %v", err)
	}
	until := vb.Binding().Until
	if err := relaybind.Admit(vb, relaybind.NoTombstones(), until, pol()); err != nil {
		t.Errorf("Admit at until: %v", err)
	}
	if err := relaybind.Admit(vb, relaybind.NoTombstones(), until+1, pol()); !errors.Is(err, relaybind.ErrExpired) {
		t.Errorf("Admit at until + 1: %v, want ErrExpired", err)
	}
	// The registry-load path: a stored binding is re-verified at load time with
	// the same function, so one that was valid when stored is valid or expired,
	// never "not yet valid" for a later now.
	if _, err := verifyBinding(t, mk(nowT+skew), testDev, nowT+3600, pol()); err != nil {
		t.Errorf("reverified later: %v", err)
	}
}

// --- finding 7: allocation, depth and simple values ---------------------------

func unprotectedMap(pairs int, dupAt int) []byte {
	out := head(5, uint64(pairs))
	for i := 0; i < pairs; i++ {
		k := uint64(i)
		if i == dupAt {
			k = 0
		}
		out = append(out, head(0, k)...)
		out = append(out, 0x00)
	}
	return out
}

// The input of the review: 512 bytes whose unprotected header claims 233
// pairs allocated about 6.3 KB per parse (a key list preallocated from the
// claim). The bound is under 1 KiB per parse, for that input and for maps that
// really have many pairs.
//
// spec: SPO-Xrelaybind-SEC-005
func TestClaimedMapPairsAllocateNothing(t *testing.T) {
	prefix := cat(head(4, 4), bstr(protectedWith(testK[:])))
	claim := cat(prefix, []byte{0xb8, 233})
	claim = append(claim, make([]byte, 512-len(claim))...)
	good := cat(prefix, unprotectedMap(100, -1), bstr(goodPayload(t)), bstr(make([]byte, 64)))
	dup := cat(prefix, unprotectedMap(100, 99), bstr(goodPayload(t)), bstr(make([]byte, 64)))
	// 160 distinct keys: the largest map that fits the 512 bytes.
	big := cat(prefix, unprotectedMap(160, -1))
	for name, in := range map[string]struct {
		b    []byte
		want error
	}{
		"512 bytes claiming 233 pairs": {claim, relaybind.ErrDuplicateKey},
		"100 distinct pairs":           {good, relaybind.ErrUnprotected},
		"a duplicate in the 100th":     {dup, relaybind.ErrDuplicateKey},
		"160 distinct pairs":           {big, relaybind.ErrUnprotected},
	} {
		if len(in.b) > relaybind.MaxSign1Bytes {
			t.Fatalf("%s: setup: %d bytes", name, len(in.b))
		}
		if _, err := relaybind.ParseStatement(in.b); !errors.Is(err, in.want) {
			t.Fatalf("%s: %v, want %v", name, err, in.want)
		}
		n := allocated(func() {
			for i := 0; i < 100; i++ {
				relaybind.ParseStatement(in.b)
			}
		})
		if per := n / 100; per > 1024 {
			t.Errorf("%s: %d bytes allocated per parse, want under 1024", name, per)
		}
	}
	if len(claim) != 512 {
		t.Errorf("the claiming input is %d bytes, not 512", len(claim))
	}
}

// A duplicate key is still found at every level, with no stored key list: in
// the first and last position of a long map, and in a map nested in a value.
//
// spec: SPO-Xrelaybind-PRE-005
func TestDuplicateKeysAreFoundWithoutAKeyList(t *testing.T) {
	prefix := cat(head(4, 4), bstr(protectedWith(testK[:])))
	tail := cat(bstr(goodPayload(t)), bstr(make([]byte, 64)))
	nested := cat(head(5, 1), tstr("hashed"), head(5, 2), head(0, 1), head(0, 0), head(0, 1), head(0, 0))
	nestedKeyDup := cat(head(5, 2), tstr("a"), cat(head(5, 2), tstr("x"), cFalse, tstr("y"), cFalse), tstr("a"), cFalse)
	// Equal map keys that are maps themselves, then arrays.
	mapKey := cat(head(5, 2), cat(head(5, 1), head(0, 1), head(0, 2)), head(0, 0), cat(head(5, 1), head(0, 1), head(0, 2)), head(0, 1))
	arrKey := cat(head(5, 2), cat(head(4, 2), head(0, 1), head(0, 2)), head(0, 0), cat(head(4, 2), head(0, 1), head(0, 2)), head(0, 1))
	diffArrKey := cat(head(5, 2), cat(head(4, 2), head(0, 1), head(0, 2)), head(0, 0), cat(head(4, 2), head(0, 1), head(0, 3)), head(0, 1))
	for name, c := range map[string]struct {
		u    []byte
		want error
	}{
		"the second key repeats the first":   {unprotectedMap(2, 1), relaybind.ErrDuplicateKey},
		"the last of 100 repeats the first":  {unprotectedMap(100, 99), relaybind.ErrDuplicateKey},
		"the middle of 50 repeats the first": {unprotectedMap(50, 25), relaybind.ErrDuplicateKey},
		"a duplicate in a nested map":        {nested, relaybind.ErrDuplicateKey},
		"a nested map before a repeated key": {nestedKeyDup, relaybind.ErrDuplicateKey},
		"map keys that are equal maps":       {mapKey, relaybind.ErrDuplicateKey},
		"array keys that are equal":          {arrKey, relaybind.ErrDuplicateKey},
		"array keys that differ":             {diffArrKey, relaybind.ErrUnprotected},
		"distinct keys":                      {unprotectedMap(30, -1), relaybind.ErrUnprotected},
	} {
		_, err := relaybind.ParseStatement(cat(prefix, c.u, tail))
		if !errors.Is(err, relaybind.ErrBadEncoding) || !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want ErrBadEncoding wrapping %v", name, err, c.want)
		}
	}
}

// The skip depth limit: a value nested exactly at the limit in a skipped
// position is read (and the header is then refused as not the one allowed
// form); one level deeper is refused by the depth limit.
//
// spec: SPO-Xrelaybind-PRE-008
func TestSkippedValueAtTheDepthLimit(t *testing.T) {
	prefix := cat(head(4, 4), bstr(protectedWith(testK[:])))
	tail := cat(bstr(goodPayload(t)), bstr(make([]byte, 64)))
	nest := func(arrays int) []byte { // arrays nested arrays holding the integer 0
		var out []byte
		for i := 0; i < arrays; i++ {
			out = append(out, head(4, 1)...)
		}
		return append(out, 0x00)
	}
	nestMaps := func(maps int) []byte { // maps nested maps {1: {1: ... 0}}
		var out []byte
		for i := 0; i < maps; i++ {
			out = append(out, head(5, 1)...)
			out = append(out, 0x01)
		}
		return append(out, 0x00)
	}
	for name, c := range map[string]struct {
		u    []byte
		want error
	}{
		// The unprotected item is depth 0; its leaf may be at depth 4.
		"4 nested arrays: the leaf is at depth 4":     {nest(4), relaybind.ErrUnprotected},
		"5 nested arrays: the leaf is at depth 5":     {nest(5), relaybind.ErrShape},
		"a map value 3 arrays deep (leaf at depth 4)": {cat(head(5, 1), tstr("hashed"), nest(3)), relaybind.ErrUnprotected},
		"a map value 4 arrays deep (leaf at depth 5)": {cat(head(5, 1), tstr("hashed"), nest(4)), relaybind.ErrShape},
		"a map key 3 arrays deep (leaf at depth 4)":   {cat(head(5, 1), nest(3), cFalse), relaybind.ErrUnprotected},
		"a map key 4 arrays deep (leaf at depth 5)":   {cat(head(5, 1), nest(4), cFalse), relaybind.ErrShape},
		"4 nested maps: the leaf is at depth 4":       {nestMaps(4), relaybind.ErrUnprotected},
		"5 nested maps: the leaf is at depth 5":       {nestMaps(5), relaybind.ErrShape},
	} {
		_, err := relaybind.ParseStatement(cat(prefix, c.u, tail))
		if !errors.Is(err, relaybind.ErrBadEncoding) || !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want ErrBadEncoding wrapping %v", name, err, c.want)
		}
	}
}

// Simple values (false, true, null, undefined) written in the two-byte form
// 0xf8 nn, and the float forms, are refused wherever they stand: a head with
// an argument byte is never shortest for a simple value.
//
// spec: SPO-Xrelaybind-PRE-002
func TestSimpleValuesInNonShortestForm(t *testing.T) {
	prot := protectedWith(testK[:])
	pOK, plOK, sOK := bstr(prot), bstr(goodPayload(t)), bstr(make([]byte, 64))
	forms := map[string][]byte{
		"false as 0xf8 0x14":     {0xf8, 0x14},
		"true as 0xf8 0x15":      {0xf8, 0x15},
		"null as 0xf8 0x16":      {0xf8, 0x16},
		"undefined":              {0xf7},
		"undefined as 0xf8 0x17": {0xf8, 0x17},
		"simple 0xf8 0x20":       {0xf8, 0x20},
		"half float":             {0xf9, 0x00, 0x00},
		"single float":           {0xfa, 0, 0, 0, 0},
		"double float":           {0xfb, 0, 0, 0, 0, 0, 0, 0, 0},
		"break":                  {0xff},
		"simple 0xe0":            {0xe0},
		"simple 0xf3 (19)":       {0xf3},
	}
	for name, f := range forms {
		// As the value of "hashed".
		u := cat(head(5, 1), tstr("hashed"), f)
		if _, err := relaybind.ParseStatement(cat(head(4, 4), pOK, u, plOK, sOK)); !errors.Is(err, relaybind.ErrBadEncoding) {
			t.Errorf("%s as the hashed value: %v", name, err)
		}
		// As the whole unprotected header and as the payload position.
		if _, err := relaybind.ParseStatement(cat(head(4, 4), pOK, f, plOK, sOK)); !errors.Is(err, relaybind.ErrBadEncoding) {
			t.Errorf("%s as the unprotected header: %v", name, err)
		}
		if _, err := relaybind.ParseStatement(cat(head(4, 4), pOK, unprotOK, f, sOK)); !errors.Is(err, relaybind.ErrBadEncoding) {
			t.Errorf("%s as the payload: %v", name, err)
		}
		// As the algorithm of the protected header.
		pm := bstr(cat(head(5, 2), kAlg, f, tstr("address"), bstr(testK[:])))
		if _, err := relaybind.ParseStatement(cat(head(4, 4), pm, unprotOK, plOK, sOK)); !errors.Is(err, relaybind.ErrBadEncoding) {
			t.Errorf("%s as the algorithm: %v", name, err)
		}
	}
	// The two-byte forms are named: ErrShape, not a pass.
	if _, err := relaybind.ParseStatement(cat(head(4, 4), pOK, cat(head(5, 1), tstr("hashed"), []byte{0xf8, 0x14}), plOK, sOK)); !errors.Is(err, relaybind.ErrShape) {
		t.Errorf("false as 0xf8 0x14: %v, want ErrShape", err)
	}
	if _, err := relaybind.ParseStatement(cat(head(4, 4), pOK, unprotOK, []byte{0xf8, 0x16}, sOK)); !errors.Is(err, relaybind.ErrShape) {
		t.Errorf("null as 0xf8 0x16 in the payload position: %v, want ErrShape", err)
	}
	// The one-byte forms of false remain the accepted unprotected header.
	if _, err := relaybind.ParseStatement(goodSign1(t)); err != nil {
		t.Fatal(err)
	}
}

// --- finding 9: the API cannot be misused -------------------------------------

// The verified types have only unexported fields, so no other package can
// build one with a composite literal (keyed, which names a field, or unkeyed,
// which needs them all) or set a field: it does not compile. Only the verify
// functions make a value whose Admit succeeds, and Admit refuses the zero
// value. The assertion is by reflection over the fields.
//
// spec: SPO-Xrelaybind-SEC-010
func TestVerifiedTypesCannotBeBuiltOutsideThePackage(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeOf(relaybind.VerifiedBinding{}), reflect.TypeOf(relaybind.VerifiedRevoke{})} {
		if typ.NumField() == 0 {
			t.Errorf("%s has no field: an empty literal would be a 'valid' value", typ)
		}
		for i := 0; i < typ.NumField(); i++ {
			if f := typ.Field(i); f.IsExported() {
				t.Errorf("%s.%s is exported: another package can build or change a verified value", typ, f.Name)
			}
		}
	}
	// Admit refuses what no verification produced.
	if err := relaybind.Admit(relaybind.VerifiedBinding{}, relaybind.NoTombstones(), nowT, pol()); !errors.Is(err, relaybind.ErrUnverified) {
		t.Errorf("Admit of the zero VerifiedBinding: %v, want ErrUnverified", err)
	}
	// ... before it looks at the policy.
	if err := relaybind.Admit(relaybind.VerifiedBinding{}, relaybind.NoTombstones(), nowT, relaybind.Policy{}); !errors.Is(err, relaybind.ErrUnverified) {
		t.Errorf("Admit of the zero VerifiedBinding with a bad policy: %v, want ErrUnverified", err)
	}
	// The accessors of a zero value are zero, not a panic.
	var z relaybind.VerifiedBinding
	if z.Key() != (relaybind.KeyHash{}) || z.Binding() != (relaybind.Binding{}) || z.AddressPart() != 0 {
		t.Error("a zero VerifiedBinding is not zero")
	}
}

// Admit refuses a policy outside the ADR's, and in the order: verified, policy,
// window, tombstones.
//
// spec: SPO-Xrelaybind-SEC-010, SPO-Xrelaybind-SEC-007
func TestAdmitClausesAndOrder(t *testing.T) {
	vb := bindingFrom(t, testDev, fromT, nowT)
	until := vb.Binding().Until
	if err := relaybind.Admit(vb, relaybind.NoTombstones(), nowT, relaybind.Policy{}); !errors.Is(err, relaybind.ErrRange) {
		t.Errorf("a zero Policy: %v, want ErrRange", err)
	}
	if err := relaybind.Admit(vb, relaybind.NoTombstones(), nowT, relaybind.Policy{Skew: relaybind.SkewSeconds + 1, MaxLifetime: relaybind.MaxLifetimeSeconds}); !errors.Is(err, relaybind.ErrRange) {
		t.Errorf("a raised skew: %v, want ErrRange", err)
	}
	// Not yet valid and revoked: the window comes first. Expired and revoked: expired.
	rev := relaybind.Tombstones{Pair: fromT, All: relaybind.NoTombstone, Device: relaybind.NoTombstone}
	if err := relaybind.Admit(vb, rev, fromT-relaybind.SkewSeconds-1, pol()); !errors.Is(err, relaybind.ErrNotYetValid) {
		t.Errorf("early and revoked: %v", err)
	}
	if err := relaybind.Admit(vb, rev, until+1, pol()); !errors.Is(err, relaybind.ErrExpired) {
		t.Errorf("expired and revoked: %v", err)
	}
	if err := relaybind.Admit(vb, rev, nowT, pol()); !errors.Is(err, relaybind.ErrRevoked) {
		t.Errorf("revoked: %v", err)
	}
	// The sentinels are distinct.
	all := []error{relaybind.ErrRevoked, relaybind.ErrUnverified, relaybind.ErrNotYetValid, relaybind.ErrExpired, relaybind.ErrRange}
	for i, a := range all {
		for j, b := range all {
			if i != j && errors.Is(a, b) {
				t.Errorf("%v is %v", a, b)
			}
		}
	}
}

// A relay that tightened its maximum lifetime answers a longer (but ADR-valid)
// binding with a distinct class, which is also ErrLifetime; a binding outside
// the ADR's bounds is plain ErrLifetime.
//
// spec: SPO-Xrelaybind-SEC-011
func TestTightenedLifetimeIsADistinctClass(t *testing.T) {
	in := goodSign1(t) // 90 days
	tight := relaybind.Policy{Skew: relaybind.SkewSeconds, MaxLifetime: 30 * 24 * 3600}
	_, err := verifyBinding(t, in, testDev, nowT, tight)
	if !errors.Is(err, relaybind.ErrLifetimePolicy) || !errors.Is(err, relaybind.ErrLifetime) {
		t.Errorf("90 days under a 30-day maximum: %v, want ErrLifetimePolicy and ErrLifetime", err)
	}
	if _, err := verifyBinding(t, in, testDev, nowT, pol()); err != nil {
		t.Errorf("under the default policy: %v", err)
	}
	// Exactly the relay's maximum passes; one second more is the class.
	mk := func(d int64) []byte {
		return signed(testK[:], []byte(bindingText(testDev, fmt.Sprint(fromT), fmt.Sprint(fromT+d))))
	}
	if _, err := verifyBinding(t, mk(tight.MaxLifetime), testDev, nowT, tight); err != nil {
		t.Errorf("exactly the maximum: %v", err)
	}
	if _, err := verifyBinding(t, mk(tight.MaxLifetime+1), testDev, nowT, tight); !errors.Is(err, relaybind.ErrLifetimePolicy) {
		t.Errorf("one second over the maximum: %v", err)
	}
	// Outside the ADR's bounds, whatever the policy: plain ErrLifetime, not the class.
	for name, d := range map[string]int64{"over 180 days": relaybind.MaxLifetimeSeconds + 1, "under 1 hour": relaybind.MinLifetimeSeconds - 1} {
		_, err := verifyBinding(t, mk(d), testDev, nowT, tight)
		if !errors.Is(err, relaybind.ErrLifetime) || errors.Is(err, relaybind.ErrLifetimePolicy) {
			t.Errorf("%s: %v, want ErrLifetime and not ErrLifetimePolicy", name, err)
		}
	}
	// The default policy never gives the class (its maximum is the ADR's).
	if _, err := verifyBinding(t, mk(relaybind.MaxLifetimeSeconds+1), testDev, nowT, pol()); errors.Is(err, relaybind.ErrLifetimePolicy) {
		t.Errorf("the default policy gave the tightened-policy class: %v", err)
	}
}

// VerifyDeviceRevoke takes a Policy, validated like the others.
//
// spec: SPO-Xrelaybind-SEC-007, SPO-Xrelaybind-OUT-004
func TestVerifyDeviceRevokeTakesAPolicy(t *testing.T) {
	ed := party.Ed25519Public(testPub)
	var x party.X25519Public
	copy(x[:], bs(32, 0x50))
	dev := party.FingerprintOf(ed, x)
	msg, _ := relaybind.DeviceRevokeBytes(dev, nowT)
	var sig [64]byte
	copy(sig[:], signRaw(msg))
	if got, err := relaybind.VerifyDeviceRevoke(ed, x, nowT, sig, nowT, pol()); err != nil || got != dev {
		t.Fatalf("default policy: %v", err)
	}
	for name, p := range map[string]relaybind.Policy{
		"zero":            {},
		"raised skew":     {Skew: relaybind.SkewSeconds + 1, MaxLifetime: relaybind.MaxLifetimeSeconds},
		"raised lifetime": {Skew: 0, MaxLifetime: relaybind.MaxLifetimeSeconds + 1},
		"low lifetime":    {Skew: 0, MaxLifetime: relaybind.MinLifetimeSeconds - 1},
	} {
		if _, err := relaybind.VerifyDeviceRevoke(ed, x, nowT, sig, nowT, p); !errors.Is(err, relaybind.ErrRange) {
			t.Errorf("%s: %v, want ErrRange", name, err)
		}
	}
	// The policy's skew is the one used.
	msg2, _ := relaybind.DeviceRevokeBytes(dev, nowT+100)
	copy(sig[:], signRaw(msg2))
	if _, err := relaybind.VerifyDeviceRevoke(ed, x, nowT+100, sig, nowT, relaybind.Policy{Skew: 100, MaxLifetime: relaybind.MaxLifetimeSeconds}); err != nil {
		t.Errorf("not-before at now + skew: %v", err)
	}
	if _, err := relaybind.VerifyDeviceRevoke(ed, x, nowT+100, sig, nowT, relaybind.Policy{Skew: 99, MaxLifetime: relaybind.MaxLifetimeSeconds}); !errors.Is(err, relaybind.ErrRevokeFuture) {
		t.Errorf("not-before at now + skew + 1: %v", err)
	}
}

// --- finding 10: the client waiting rule -------------------------------------

// spec: SPO-Xrelaybind-OUT-015
func TestPlanFromWaitsExactlyWhenTheRelayWouldRefuse(t *testing.T) {
	skew := relaybind.SkewSeconds
	no := relaybind.NoTombstone
	for _, c := range []struct {
		name       string
		now, last  int64
		skew       int64
		from, wait int64
	}{
		{"no tombstone", 1000, no, skew, 940, 0},
		{"old tombstone", 1000, 500, skew, 940, 0},
		{"tombstone at now", 1000, 1000, skew, 1001, 0},
		{"last + 1 - skew == now: no wait", 1000, 1000 + skew - 1, skew, 1000 + skew, 0},
		{"last + 1 - skew == now + 1: wait one", 1000, 1000 + skew, skew, 1001 + skew, 1},
		{"revoker's clock ahead by the full skew", 1000, 1000 + skew, skew, 1001 + skew, 1},
		{"tombstone ahead by skew + 5", 1000, 1000 + skew + 5, skew, 1001 + skew + 5, 6},
		{"skew 0, tombstone at now", 1000, 1000, 0, 1001, 1},
		{"skew 0, tombstone before now", 1000, 999, 0, 1000, 0},
		{"skew 100, tombstone now + 100", 1000, 1100, 100, 1101, 1},
		{"skew 100, tombstone now + 99", 1000, 1099, 100, 1100, 0},
		{"now below 60 clamps from at zero", 10, no, skew, 0, 0},
	} {
		from, wait, err := relaybind.PlanFrom(c.now, c.last, c.skew)
		if err != nil || from != c.from || wait != c.wait {
			t.Errorf("%s: PlanFrom(%d, %d, %d) = %d, %d, %v; want %d, %d", c.name, c.now, c.last, c.skew, from, wait, err, c.from, c.wait)
		}
		// from is ChooseFrom's.
		if cf, _ := relaybind.ChooseFrom(c.now, c.last); cf != from {
			t.Errorf("%s: PlanFrom's from %d is not ChooseFrom's %d", c.name, from, cf)
		}
	}
	// The rule against the relay, second by second: at now + wait the relay
	// accepts the binding; one second earlier it refuses (when there is a wait).
	for last := int64(1000 - 5); last <= 1000+skew+7; last++ {
		now := int64(1000)
		from, wait, err := relaybind.PlanFrom(now, last, skew)
		if err != nil {
			t.Fatal(err)
		}
		in := signed(testK[:], []byte(bindingText(testDev, fmt.Sprint(from), fmt.Sprint(from+relaybind.DefaultLifetimeSeconds))))
		vb, err := relaybind.VerifyBinding(mustStatement(t, in), testPub, testDev, now+wait, pol())
		if err != nil {
			t.Fatalf("last %d: at now + wait %d the relay refuses: %v", last, wait, err)
		}
		if err := relaybind.Admit(vb, relaybind.Tombstones{Pair: last, All: no, Device: no}, now+wait, pol()); err != nil {
			t.Fatalf("last %d: admission after the wait: %v", last, err)
		}
		if wait > 0 {
			if _, err := relaybind.VerifyBinding(mustStatement(t, in), testPub, testDev, now+wait-1, pol()); !errors.Is(err, relaybind.ErrNotYetValid) {
				t.Errorf("last %d: one second before the wait ends the relay accepts: %v", last, err)
			}
		}
	}
	for name, c := range map[string]struct{ now, last, skew int64 }{
		"negative skew":   {1000, no, -1},
		"raised skew":     {1000, no, skew + 1},
		"huge skew":       {1000, no, math.MaxInt64},
		"negative now":    {-1, no, skew},
		"now over max":    {relaybind.MaxTime + 1, no, skew},
		"tombstone range": {1000, -2, skew},
	} {
		if _, _, err := relaybind.PlanFrom(c.now, c.last, c.skew); !errors.Is(err, relaybind.ErrRange) {
			t.Errorf("%s: %v, want ErrRange", name, err)
		}
	}
}
