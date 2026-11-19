package relaybind_test

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
)

func pol() relaybind.Policy { return relaybind.DefaultPolicy() }

func verifyBinding(t testing.TB, in []byte, dev party.Fingerprint, now int64, p relaybind.Policy) (relaybind.VerifiedBinding, error) {
	t.Helper()
	return relaybind.VerifyBinding(mustStatement(t, in), testPub, dev, now, p)
}

// spec: SPO-Xrelaybind-SEC-001
func TestVerifyBindingAccepts(t *testing.T) {
	in := goodSign1(t)
	v, err := verifyBinding(t, in, testDev, nowT, pol())
	if err != nil {
		t.Fatal(err)
	}
	if v.Key() != testK || v.Binding() != goodBinding() || v.AddressPart() != relaybind.PartKeyHash {
		t.Errorf("got key %x binding %+v part %v", v.Key(), v.Binding(), v.AddressPart())
	}
	if v.FullHash() != mustStatement(t, in).FullHash() {
		t.Error("the verified hash is not the statement's full hash")
	}
}

// Each failure has its own sentinel, in the order of ADR 0014: signature, key,
// payload, device, window.
//
// spec: SPO-Xrelaybind-SEC-001
func TestVerifyBindingFailures(t *testing.T) {
	k := testK[:]
	payload := goodPayload(t)
	kOther := relaybind.KeyHash(cose.Blake2b224(otherPub[:]))
	revoke, _ := relaybind.Revoke{All: true, NotBefore: nowT}.Render()
	mk := func(from, until int64) []byte {
		return signed(k, []byte(bindingText(testDev, fmt.Sprint(from), fmt.Sprint(until))))
	}
	cases := []struct {
		name string
		in   []byte
		dev  party.Fingerprint
		now  int64
		want error
	}{
		{"signed by another key", signedWith(otherPriv, protectedWith(k), payload), testDev, nowT, relaybind.ErrBadSignature},
		{"signature of other bytes", assemble(bstr(protectedWith(k)), unprotOK, bstr(payload), bstr(signRaw(payload))), testDev, nowT, relaybind.ErrBadSignature},
		{"address of another key", signed(kOther[:], payload), testDev, nowT, relaybind.ErrWrongKey},
		{"address not containing K", signed(append([]byte{0x61}, kOther[:]...), payload), testDev, nowT, relaybind.ErrWrongKey},
		{"Byron address", signed(append([]byte{0x82}, bs(56, 0)...), payload), testDev, nowT, relaybind.ErrAddressForm},
		{"upper-case payload", signed(k, bytes.ToUpper(payload)), testDev, nowT, relaybind.ErrPayloadNotCanonical},
		{"a revoke payload", signed(k, revoke), testDev, nowT, relaybind.ErrPayloadNotCanonical},
		{"empty payload", signed(k, nil), testDev, nowT, relaybind.ErrPayloadNotCanonical},
		{"another device presented", goodSign1(t), fpOf(0x31), nowT, relaybind.ErrDeviceMismatch},
		{"not yet valid by a second", goodSign1(t), testDev, fromT - relaybind.SkewSeconds - 1, relaybind.ErrNotYetValid},
		{"expired by a second", goodSign1(t), testDev, untilT + 1, relaybind.ErrExpired},
		{"lifetime one second short", mk(fromT, fromT+relaybind.MinLifetimeSeconds-1), testDev, nowT, relaybind.ErrLifetime},
		{"lifetime one second long", mk(fromT, fromT+relaybind.MaxLifetimeSeconds+1), testDev, nowT, relaybind.ErrLifetime},
		{"until before from", mk(fromT, fromT-1), testDev, nowT, relaybind.ErrLifetime},
		{"until over MaxTime", mk(relaybind.MaxTime-5, relaybind.MaxTime+1), testDev, nowT, relaybind.ErrPayloadNotCanonical},
	}
	for _, c := range cases {
		_, err := verifyBinding(t, c.in, c.dev, c.now, pol())
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
			continue
		}
		// Distinct: no failure is another failure's sentinel.
		for _, other := range []error{relaybind.ErrBadSignature, relaybind.ErrWrongKey, relaybind.ErrPayloadNotCanonical,
			relaybind.ErrDeviceMismatch, relaybind.ErrNotYetValid, relaybind.ErrExpired, relaybind.ErrLifetime, relaybind.ErrBadEncoding} {
			if other != c.want && errors.Is(err, other) {
				t.Errorf("%s: %v is also %v", c.name, err, other)
			}
		}
	}
	// Order: a statement with a bad signature AND a wrong address is a bad signature;
	// a wrong address AND a bad payload is a wrong key; a bad payload AND another
	// device is a bad payload; another device AND an expired window is a mismatch.
	if _, err := verifyBinding(t, signedWith(otherPriv, protectedWith(kOther[:]), payload), testDev, nowT, pol()); !errors.Is(err, relaybind.ErrBadSignature) {
		t.Errorf("signature before key: %v", err)
	}
	if _, err := verifyBinding(t, signed(kOther[:], bytes.ToUpper(payload)), testDev, nowT, pol()); !errors.Is(err, relaybind.ErrWrongKey) {
		t.Errorf("key before payload: %v", err)
	}
	if _, err := verifyBinding(t, signed(k, bytes.ToUpper(payload)), fpOf(0x31), nowT, pol()); !errors.Is(err, relaybind.ErrPayloadNotCanonical) {
		t.Errorf("payload before device: %v", err)
	}
	if _, err := verifyBinding(t, goodSign1(t), fpOf(0x31), untilT+99, pol()); !errors.Is(err, relaybind.ErrDeviceMismatch) {
		t.Errorf("device before window: %v", err)
	}
	if _, err := verifyBinding(t, mk(fromT, fromT+5), testDev, untilT+99, pol()); !errors.Is(err, relaybind.ErrLifetime) {
		t.Errorf("lifetime before window: %v", err)
	}
	if _, err := verifyBinding(t, mk(fromT, fromT+5), fpOf(0x31), nowT, pol()); !errors.Is(err, relaybind.ErrDeviceMismatch) {
		t.Errorf("device before lifetime: %v", err)
	}
	// A device mismatch is also a mismatch for the all-zero fingerprint.
	if _, err := verifyBinding(t, goodSign1(t), party.Fingerprint{}, nowT, pol()); !errors.Is(err, relaybind.ErrDeviceMismatch) {
		t.Errorf("zero device: %v", err)
	}
}

// The window is from - skew <= now <= until, to the second.
//
// spec: SPO-Xrelaybind-SEC-001, SPO-Xrelaybind-SEC-004
func TestVerifyBindingWindowEdges(t *testing.T) {
	in := goodSign1(t)
	skew := relaybind.SkewSeconds
	for _, c := range []struct {
		name string
		now  int64
		want error
	}{
		{"from - skew - 1", fromT - skew - 1, relaybind.ErrNotYetValid},
		{"from - skew", fromT - skew, nil},
		{"from", fromT, nil},
		{"until - 1", untilT - 1, nil},
		{"until", untilT, nil},
		{"until + 1", untilT + 1, relaybind.ErrExpired},
		{"MaxInt64", math.MaxInt64, relaybind.ErrExpired},
		{"MinInt64", math.MinInt64, relaybind.ErrNotYetValid},
		{"zero", 0, relaybind.ErrNotYetValid},
		{"negative", -1, relaybind.ErrNotYetValid},
	} {
		_, err := verifyBinding(t, in, testDev, c.now, pol())
		if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	// From zero: from - skew is negative and does not wrap.
	zero := signed(testK[:], []byte(bindingText(testDev, "0", fmt.Sprint(relaybind.MinLifetimeSeconds))))
	for now, want := range map[int64]error{math.MinInt64: relaybind.ErrNotYetValid, -skew - 1: relaybind.ErrNotYetValid, -skew: nil, 0: nil} {
		_, err := verifyBinding(t, zero, testDev, now, pol())
		if want == nil && err != nil || want != nil && !errors.Is(err, want) {
			t.Errorf("from 0, now %d: %v, want %v", now, err, want)
		}
	}
	// Until at MaxTime, now at MaxInt64: no overflow either way.
	top := signed(testK[:], []byte(bindingText(testDev, fmt.Sprint(relaybind.MaxTime-relaybind.MinLifetimeSeconds), fmt.Sprint(relaybind.MaxTime))))
	if _, err := verifyBinding(t, top, testDev, relaybind.MaxTime, pol()); err != nil {
		t.Errorf("now = MaxTime: %v", err)
	}
	if _, err := verifyBinding(t, top, testDev, math.MaxInt64, pol()); !errors.Is(err, relaybind.ErrExpired) {
		t.Errorf("now = MaxInt64: %v", err)
	}
}

// A relay may tighten the skew and the maximum lifetime, never raise them.
//
// spec: SPO-Xrelaybind-SEC-007
func TestPolicyOnlyTightens(t *testing.T) {
	in := goodSign1(t) // a 90-day binding
	tight := relaybind.Policy{Skew: 0, MaxLifetime: 30 * 24 * 3600}
	if _, err := verifyBinding(t, in, testDev, nowT, tight); !errors.Is(err, relaybind.ErrLifetime) {
		t.Errorf("90 days under a 30-day maximum: %v", err)
	}
	ok := relaybind.Policy{Skew: 0, MaxLifetime: 90 * 24 * 3600}
	if _, err := verifyBinding(t, in, testDev, nowT, ok); err != nil {
		t.Errorf("90 days under a 90-day maximum: %v", err)
	}
	if _, err := verifyBinding(t, in, testDev, fromT-1, ok); !errors.Is(err, relaybind.ErrNotYetValid) {
		t.Errorf("skew 0, one second early: %v", err)
	}
	if _, err := verifyBinding(t, in, testDev, fromT, ok); err != nil {
		t.Errorf("skew 0, at from: %v", err)
	}
	for name, p := range map[string]relaybind.Policy{
		"skew raised":        {Skew: relaybind.SkewSeconds + 1, MaxLifetime: relaybind.MaxLifetimeSeconds},
		"negative skew":      {Skew: -1, MaxLifetime: relaybind.MaxLifetimeSeconds},
		"lifetime raised":    {Skew: 0, MaxLifetime: relaybind.MaxLifetimeSeconds + 1},
		"lifetime below min": {Skew: 0, MaxLifetime: relaybind.MinLifetimeSeconds - 1},
		"zero value":         {},
		"huge skew":          {Skew: math.MaxInt64, MaxLifetime: relaybind.MaxLifetimeSeconds},
		"huge lifetime":      {Skew: 0, MaxLifetime: math.MaxInt64},
		"negative lifetime":  {Skew: 0, MaxLifetime: math.MinInt64},
	} {
		if err := p.Validate(); !errors.Is(err, relaybind.ErrRange) {
			t.Errorf("%s: Validate %v, want ErrRange", name, err)
		}
		if _, err := verifyBinding(t, in, testDev, nowT, p); !errors.Is(err, relaybind.ErrRange) {
			t.Errorf("%s: VerifyBinding %v, want ErrRange", name, err)
		}
		if _, err := relaybind.VerifyRevoke(mustStatement(t, in), testPub, nowT, p); !errors.Is(err, relaybind.ErrRange) {
			t.Errorf("%s: VerifyRevoke %v, want ErrRange", name, err)
		}
	}
	for _, p := range []relaybind.Policy{pol(),
		{Skew: 0, MaxLifetime: relaybind.MinLifetimeSeconds},
		{Skew: relaybind.SkewSeconds, MaxLifetime: relaybind.MaxLifetimeSeconds}} {
		if err := p.Validate(); err != nil {
			t.Errorf("%+v: %v", p, err)
		}
	}
	if relaybind.DefaultLifetimeSeconds != 90*86400 {
		t.Errorf("the default lifetime is %d seconds, the ADR says 90 days", relaybind.DefaultLifetimeSeconds)
	}
	d := pol()
	if d.Skew != 300 || d.MaxLifetime != 180*86400 {
		t.Errorf("DefaultPolicy %+v is not 5 minutes and 180 days", d)
	}
}

// The address forms of the protected header, exactly: the 28-byte key hash; an
// enterprise or reward address of 29 bytes with a KEY-hash credential equal to
// K; a base address of 57 bytes whose key-hash PAYMENT credential equals K
// (types 0, 2); K as only the stake part is refused. Network id 0 or 1.
// Nothing else. The verified result says which part matched.
//
// spec: SPO-Xrelaybind-PRE-014
func TestProtectedAddressForms(t *testing.T) {
	k := testK[:]
	other := bs(28, 0x80)
	hdr := func(b byte) []byte { return []byte{b} }
	type want struct {
		parse error // the strict parser refuses (ErrBadEncoding wrapping this)
		err   error // VerifyBinding refuses with this
		part  relaybind.AddressPart
	}
	ok := func(p relaybind.AddressPart) want { return want{part: p} }
	cases := []struct {
		name string
		addr []byte
		want want
	}{
		// Accepted.
		{"28-byte key hash", k, ok(relaybind.PartKeyHash)},
		{"enterprise address, mainnet", cat(hdr(0x61), k), ok(relaybind.PartEnterprise)},
		{"enterprise address, testnet", cat(hdr(0x60), k), ok(relaybind.PartEnterprise)},
		{"reward address, mainnet", cat(hdr(0xe1), k), ok(relaybind.PartReward)},
		{"reward address, testnet", cat(hdr(0xe0), k), ok(relaybind.PartReward)},
		{"base, K payment (key, key)", cat(hdr(0x01), k, other), ok(relaybind.PartBasePayment)},
		{"base, K in both slots is the payment part", cat(hdr(0x00), k, k), ok(relaybind.PartBasePayment)},
		{"base (key, script), K payment", cat(hdr(0x21), k, other), ok(relaybind.PartBasePayment)},
		// K as only the stake part of a base address is not a match: a wallet
		// signing for a base address signs with the payment key, and one signing
		// with the stake key presents the reward address.
		{"base, K only as the stake part (key, key)", cat(hdr(0x01), other, k), want{err: relaybind.ErrWrongKey}},
		{"base, K only as the stake part, testnet", cat(hdr(0x00), other, k), want{err: relaybind.ErrWrongKey}},
		{"base (script, key), K as the stake part", cat(hdr(0x11), other, k), want{err: relaybind.ErrAddressForm}},
		// A well-formed address that does not name K.
		{"another key hash", bs(28, 1), want{err: relaybind.ErrWrongKey}},
		{"enterprise address of another key", cat(hdr(0x61), other), want{err: relaybind.ErrWrongKey}},
		{"reward address of another key", cat(hdr(0xe1), other), want{err: relaybind.ErrWrongKey}},
		{"base address without K", cat(hdr(0x01), other, other), want{err: relaybind.ErrWrongKey}},
		{"K shifted by one byte in a base address", cat(hdr(0x01), []byte{0}, k[:27], other), want{err: relaybind.ErrWrongKey}},
		{"(script, key) base with K in the SCRIPT payment slot", cat(hdr(0x11), k, other), want{err: relaybind.ErrAddressForm}},
		{"(key, script) base with K in the SCRIPT stake slot", cat(hdr(0x21), other, k), want{err: relaybind.ErrWrongKey}},
		// Forms that are not accepted.
		{"script enterprise address with K", cat(hdr(0x71), k), want{err: relaybind.ErrAddressForm}},
		{"script reward address with K", cat(hdr(0xf1), k), want{err: relaybind.ErrAddressForm}},
		{"(script, script) base with K", cat(hdr(0x31), k, other), want{err: relaybind.ErrAddressForm}},
		{"pointer header on 29 bytes", cat(hdr(0x41), k), want{err: relaybind.ErrAddressForm}},
		{"pointer header on 57 bytes", cat(hdr(0x41), k, other), want{err: relaybind.ErrAddressForm}},
		{"enterprise header on 57 bytes", cat(hdr(0x61), other, k), want{err: relaybind.ErrAddressForm}},
		{"Byron type 8 on 29 bytes", cat(hdr(0x81), k), want{err: relaybind.ErrAddressForm}},
		{"Byron type 8 on 57 bytes", cat(hdr(0x82), k, other), want{err: relaybind.ErrAddressForm}},
		{"reserved type 9", cat(hdr(0x91), k), want{err: relaybind.ErrAddressForm}},
		{"reserved type 13", cat(hdr(0xd1), k), want{err: relaybind.ErrAddressForm}},
		{"enterprise network id 2", cat(hdr(0x62), k), want{err: relaybind.ErrAddressForm}},
		{"enterprise network id 15", cat(hdr(0x6f), k), want{err: relaybind.ErrAddressForm}},
		{"reward network id 2", cat(hdr(0xe2), k), want{err: relaybind.ErrAddressForm}},
		{"base network id 2", cat(hdr(0x02), k, other), want{err: relaybind.ErrAddressForm}},
		{"base network id 15", cat(hdr(0x0f), k, other), want{err: relaybind.ErrAddressForm}},
		// Wrong lengths: the strict parser refuses them.
		{"enterprise address with a trailing byte (30)", cat(hdr(0x61), k, []byte{0xff}), want{parse: relaybind.ErrAddress}},
		{"truncated base address with K (39 bytes)", cat(hdr(0x01), k, bs(10, 1)), want{parse: relaybind.ErrAddress}},
		{"base address one byte short (56)", cat(hdr(0x01), k, other[:27]), want{parse: relaybind.ErrAddress}},
		{"base address with trailing bytes (58)", cat(hdr(0x01), k, other, []byte{1}), want{parse: relaybind.ErrAddress}},
		{"base address with trailing bytes (60)", cat(hdr(0x01), k, other, []byte{1, 2, 3}), want{parse: relaybind.ErrAddress}},
		{"64-byte address", bs(64, 1), want{parse: relaybind.ErrAddress}},
		{"27-byte address", k[:27], want{parse: relaybind.ErrAddress}},
	}
	for _, c := range cases {
		st, err := relaybind.ParseStatement(signed(c.addr, goodPayload(t)))
		if c.want.parse != nil {
			if !errors.Is(err, relaybind.ErrBadEncoding) || !errors.Is(err, c.want.parse) {
				t.Errorf("%s: parse %v, want ErrBadEncoding wrapping %v", c.name, err, c.want.parse)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: parse: %v", c.name, err)
			continue
		}
		v, err := relaybind.VerifyBinding(st, testPub, testDev, nowT, pol())
		switch {
		case c.want.err == nil && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.want.err == nil && (v.Key() != testK || v.AddressPart() != c.want.part):
			t.Errorf("%s: key %x part %v, want K and %v", c.name, v.Key(), v.AddressPart(), c.want.part)
		case c.want.err != nil && !errors.Is(err, c.want.err):
			t.Errorf("%s: %v, want %v", c.name, err, c.want.err)
		case c.want.err == relaybind.ErrAddressForm && errors.Is(err, relaybind.ErrWrongKey),
			c.want.err == relaybind.ErrWrongKey && errors.Is(err, relaybind.ErrAddressForm):
			t.Errorf("%s: %v is both kinds", c.name, err)
		}
	}
	// The same rules for a revoke: the part is reported there too.
	rv, _ := relaybind.Revoke{All: true, NotBefore: nowT}.Render()
	vr, err := relaybind.VerifyRevoke(mustStatement(t, signed(cat(hdr(0xe1), k), rv)), testPub, nowT, pol())
	if err != nil || vr.AddressPart() != relaybind.PartReward {
		t.Errorf("revoke by a reward-address statement: part %v, %v", vr.AddressPart(), err)
	}
	if _, err := relaybind.VerifyRevoke(mustStatement(t, signed(cat(hdr(0x71), k), rv)), testPub, nowT, pol()); !errors.Is(err, relaybind.ErrAddressForm) {
		t.Errorf("revoke with a script enterprise address: %v", err)
	}
	// The verification key must hash to K: the address alone is never the identity.
	v, err := verifyBinding(t, signed(cat(hdr(0x01), k, other), goodPayload(t)), testDev, nowT, pol())
	if err != nil || v.Key() != testK {
		t.Errorf("the result key is %x (%v), want the hash of the verification key", v.Key(), err)
	}
}

func revokeOf(t testing.TB, r relaybind.Revoke) []byte {
	t.Helper()
	p, err := r.Render()
	if err != nil {
		t.Fatal(err)
	}
	return signed(testK[:], p)
}

// spec: SPO-Xrelaybind-SEC-001, SPO-Xrelaybind-OUT-003
func TestVerifyRevoke(t *testing.T) {
	skew := relaybind.SkewSeconds
	for _, r := range []relaybind.Revoke{
		{Device: testDev, NotBefore: nowT},
		{All: true, NotBefore: nowT},
		{All: true, NotBefore: 0},
		{All: true, NotBefore: nowT + skew},
	} {
		in := revokeOf(t, r)
		v, err := relaybind.VerifyRevoke(mustStatement(t, in), testPub, nowT, pol())
		if err != nil || v.Key() != testK || v.Revoke() != r || v.FullHash() != mustStatement(t, in).FullHash() {
			t.Errorf("%+v: %+v, %v", r, v, err)
		}
	}
	vr := func(in []byte, vk [32]byte, now int64) error {
		_, err := relaybind.VerifyRevoke(mustStatement(t, in), vk, now, pol())
		return err
	}
	good := revokeOf(t, relaybind.Revoke{All: true, NotBefore: nowT})
	if err := vr(revokeOf(t, relaybind.Revoke{All: true, NotBefore: nowT + skew + 1}), testPub, nowT); !errors.Is(err, relaybind.ErrRevokeFuture) {
		t.Errorf("not-before one second past the skew: %v", err)
	}
	if err := vr(revokeOf(t, relaybind.Revoke{All: true, NotBefore: nowT}), testPub, nowT-skew-1); !errors.Is(err, relaybind.ErrRevokeFuture) {
		t.Errorf("relay time before not-before - skew: %v", err)
	}
	if err := vr(good, testPub, math.MinInt64); !errors.Is(err, relaybind.ErrRevokeFuture) {
		t.Errorf("now MinInt64: %v", err)
	}
	if err := vr(good, testPub, math.MaxInt64); err != nil {
		t.Errorf("now MaxInt64: %v", err)
	}
	// A wallet-signed revoke does not expire: an old not-before is fine.
	if err := vr(revokeOf(t, relaybind.Revoke{All: true, NotBefore: 1}), testPub, nowT); err != nil {
		t.Errorf("old not-before: %v", err)
	}
	if err := vr(good, otherPub, nowT); !errors.Is(err, relaybind.ErrBadSignature) {
		t.Errorf("another verification key: %v", err)
	}
	kOther := relaybind.KeyHash(cose.Blake2b224(otherPub[:]))
	rv, _ := relaybind.Revoke{All: true, NotBefore: nowT}.Render()
	if err := vr(signed(kOther[:], rv), testPub, nowT); !errors.Is(err, relaybind.ErrWrongKey) {
		t.Errorf("address of another key: %v", err)
	}
	// A binding is not a revoke, and a revoke is not a binding.
	if err := vr(goodSign1(t), testPub, nowT); !errors.Is(err, relaybind.ErrPayloadNotCanonical) {
		t.Errorf("a binding verified as a revoke: %v", err)
	}
	if _, err := verifyBinding(t, good, testDev, nowT, pol()); !errors.Is(err, relaybind.ErrPayloadNotCanonical) {
		t.Errorf("a revoke verified as a binding: %v", err)
	}
	if err := vr(signed(testK[:], bytes.ToUpper(rv)), testPub, nowT); !errors.Is(err, relaybind.ErrPayloadNotCanonical) {
		t.Errorf("upper-case revoke: %v", err)
	}
}

// A statement that verifies as one kind cannot be reused as the other, nor as a
// device-signed revoke, nor does it start like anything the device key signs.
//
// spec: SPO-Xrelaybind-SEC-006
func TestStatementsAreSeparatedFromEachOther(t *testing.T) {
	binding := goodPayload(t)
	revoke, _ := relaybind.Revoke{Device: testDev, NotBefore: nowT}.Render()
	devRevoke, _ := relaybind.DeviceRevokeBytes(testDev, nowT)
	if binding[0] != 's' || revoke[0] != 's' || devRevoke[0] != 0x83 {
		t.Fatalf("first bytes %#x %#x %#x", binding[0], revoke[0], devRevoke[0])
	}
	if !relaybind.IsReserved(binding) || !relaybind.IsReserved(revoke) {
		t.Error("a statement payload is not reserved for the generic message path")
	}
	// The Sig_structure of a statement is a CBOR array starting 0x84 "Signature1";
	// a device-revoke is an array of 3 and a transaction hash is 32 bytes.
	ss := cose.SigStructure(protectedWith(testK[:]), binding)
	if ss[0] != 0x84 || len(ss) <= 32 {
		t.Errorf("Sig_structure starts %#x and is %d bytes", ss[0], len(ss))
	}
}
