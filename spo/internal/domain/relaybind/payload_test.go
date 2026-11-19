package relaybind_test

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
)

// The package's MaxTime is the mailbox domain's. A pure package cannot import
// it, so the test pins the two together.
//
// spec: SPO-Xrelaybind-PRE-016
func TestMaxTimeIsTheMailboxMaxTime(t *testing.T) {
	if relaybind.MaxTime != mailbox.MaxTime {
		t.Fatalf("MaxTime %d, mailbox.MaxTime %d", relaybind.MaxTime, int64(mailbox.MaxTime))
	}
	if relaybind.SkewSeconds != mailbox.ClockSkewWarningSeconds {
		t.Fatalf("skew %d, want %d", relaybind.SkewSeconds, mailbox.ClockSkewWarningSeconds)
	}
}

// spec: SPO-Xrelaybind-OUT-001
func TestBindingRenderIsTheADRLine(t *testing.T) {
	b := relaybind.Binding{Device: fpOf(0), From: 1700000000, Until: 1707776000}
	got, err := b.Render()
	if err != nil {
		t.Fatal(err)
	}
	want := "spo-relay-binding-v1 device 000102030405060708090a0b0c0d0e0f10111213 from 1700000000 until 1707776000"
	if string(got) != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	if len(got) != 101 {
		t.Fatalf("length %d, the ADR says 101 with 10-digit times", len(got))
	}
}

// spec: SPO-Xrelaybind-OUT-001, SPO-Xrelaybind-OUT-002
func TestBindingRoundTrip(t *testing.T) {
	maxFrom := relaybind.MaxTime - relaybind.MinLifetimeSeconds
	for name, b := range map[string]relaybind.Binding{
		"typical":          goodBinding(),
		"from zero":        {Device: fpOf(1), From: 0, Until: relaybind.MinLifetimeSeconds},
		"shortest":         {Device: fpOf(2), From: 100, Until: 100 + relaybind.MinLifetimeSeconds},
		"longest":          {Device: fpOf(3), From: 100, Until: 100 + relaybind.MaxLifetimeSeconds},
		"until at MaxTime": {Device: fpOf(4), From: maxFrom, Until: relaybind.MaxTime},
		"all zero device":  {Device: party.Fingerprint{}, From: 5, Until: 5 + 7200},
	} {
		p, err := b.Render()
		if err != nil {
			t.Errorf("%s: Render: %v", name, err)
			continue
		}
		if len(p) > relaybind.MaxPayloadBytes {
			t.Errorf("%s: %d bytes, over the bound", name, len(p))
		}
		got, err := relaybind.ParseBinding(p)
		if err != nil || got != b {
			t.Errorf("%s: ParseBinding(%q) = %+v, %v", name, p, got, err)
		}
	}
}

func replace(s, old, new string) string { return strings.Replace(s, old, new, 1) }

// spec: SPO-Xrelaybind-PRE-015
func TestParseBindingRefusesNearMisses(t *testing.T) {
	good := string(goodPayload(t))
	dev := fmt.Sprintf("%x", testDev[:])
	cases := map[string]string{
		"empty":                   "",
		"upper-case label":        replace(good, "spo-relay", "Spo-relay"),
		"label v2":                replace(good, "binding-v1", "binding-v2"),
		"upper-case word":         replace(good, " device ", " Device "),
		"upper-case hex":          replace(good, dev, strings.ToUpper(dev)),
		"one upper-case hex":      replace(good, "3a3b", "3A3b"),
		"39 hex digits":           replace(good, dev, dev[:39]),
		"41 hex digits":           replace(good, dev, dev+"0"),
		"non-hex digit":           replace(good, dev, "g"+dev[1:]),
		"leading space":           " " + good,
		"trailing space":          good + " ",
		"double space":            replace(good, " from ", "  from "),
		"double space 2":          replace(good, "binding-v1 device", "binding-v1  device"),
		"tab for space":           replace(good, " from ", "\tfrom "),
		"line feed at the end":    good + "\n",
		"line feed inside":        replace(good, " from ", "\nfrom "),
		"carriage return":         good + "\r",
		"NUL byte":                good + "\x00",
		"non-ASCII":               replace(good, " from ", " fröm "),
		"fields swapped":          fmt.Sprintf("spo-relay-binding-v1 device %s until %d from %d", dev, untilT, fromT),
		"missing until":           fmt.Sprintf("spo-relay-binding-v1 device %s from %d", dev, fromT),
		"extra field":             good + " extra 1",
		"missing label":           replace(good, "spo-relay-binding-v1 ", ""),
		"leading zero":            bindingText(testDev, "0"+fmt.Sprint(fromT), fmt.Sprint(untilT)),
		"zero with a zero":        bindingText(testDev, "00", fmt.Sprint(untilT)),
		"leading zero on until":   bindingText(testDev, fmt.Sprint(fromT), "0"+fmt.Sprint(untilT)),
		"plus sign":               bindingText(testDev, "+"+fmt.Sprint(fromT), fmt.Sprint(untilT)),
		"minus sign":              bindingText(testDev, "-1", fmt.Sprint(untilT)),
		"hex number":              bindingText(testDev, "0x10", fmt.Sprint(untilT)),
		"exponent":                bindingText(testDev, "1e9", fmt.Sprint(untilT)),
		"decimal point":           bindingText(testDev, "1800000000.0", fmt.Sprint(untilT)),
		"empty number":            bindingText(testDev, "", fmt.Sprint(untilT)),
		"13 digits":               bindingText(testDev, fmt.Sprint(fromT), "1000000000000"),
		"fullwidth digit":         bindingText(testDev, "１"+fmt.Sprint(fromT)[1:], fmt.Sprint(untilT)),
		"until above MaxTime":     bindingText(testDev, fmt.Sprint(fromT), "253402300800"),
		"overflowing number":      bindingText(testDev, fmt.Sprint(fromT), "99999999999999999999"),
		"121 bytes":               good + strings.Repeat(" ", 121-len(good)),
		"121 bytes with 0 digits": bindingText(testDev, fmt.Sprint(fromT), fmt.Sprint(untilT)) + strings.Repeat("0", 121-len(good)),
	}
	for name, s := range cases {
		_, err := relaybind.ParseBinding([]byte(s))
		if !errors.Is(err, relaybind.ErrPayloadNotCanonical) {
			t.Errorf("%s: %q: error %v, want ErrPayloadNotCanonical", name, s, err)
		}
	}
	if _, err := relaybind.ParseBinding(nil); !errors.Is(err, relaybind.ErrPayloadNotCanonical) {
		t.Errorf("nil: %v", err)
	}
}

// Whatever one byte changed in a valid binding does, the result is refused or
// it is the canonical rendering of what it parses to: nothing in between.
//
// spec: SPO-Xrelaybind-OUT-002, SPO-Xrelaybind-INV-002
func TestParseBindingAcceptsOnlyCanonicalRenderings(t *testing.T) {
	good := goodPayload(t)
	for i := range good {
		for _, c := range []byte{' ', '0', '1', 'a', 'A', 'f', '\n', '+', '-', 'x', 0, 0xff} {
			m := bytes.Clone(good)
			if m[i] == c {
				continue
			}
			m[i] = c
			b, err := relaybind.ParseBinding(m)
			if err != nil {
				continue
			}
			again, rerr := b.Render()
			if rerr != nil || !bytes.Equal(again, m) {
				t.Fatalf("byte %d := %#x: accepted %q but it re-renders to %q (%v)", i, c, m, again, rerr)
			}
		}
	}
}

// spec: SPO-Xrelaybind-PRE-016
func TestBindingWindowAndLifetimeBounds(t *testing.T) {
	const min, max = relaybind.MinLifetimeSeconds, relaybind.MaxLifetimeSeconds
	line := func(from, until int64) []byte {
		return []byte(bindingText(testDev, fmt.Sprint(from), fmt.Sprint(until)))
	}
	for name, c := range map[string]struct {
		from, until int64
		want        error
	}{
		"minimum lifetime":        {1000, 1000 + min, nil},
		"one second short":        {1000, 1000 + min - 1, relaybind.ErrLifetime},
		"zero lifetime":           {1000, 1000, relaybind.ErrLifetime},
		"until before from":       {1000, 999, relaybind.ErrLifetime},
		"maximum lifetime":        {1000, 1000 + max, nil},
		"one second over maximum": {1000, 1000 + max + 1, relaybind.ErrLifetime},
		"from zero":               {0, min, nil},
		"until at MaxTime":        {relaybind.MaxTime - min, relaybind.MaxTime, nil},
		"until over MaxTime":      {relaybind.MaxTime - min + 1, relaybind.MaxTime + 1, relaybind.ErrPayloadNotCanonical},
	} {
		_, err := relaybind.ParseBinding(line(c.from, c.until))
		if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: from %d until %d: %v, want %v", name, c.from, c.until, err, c.want)
		}
		b := relaybind.Binding{Device: testDev, From: c.from, Until: c.until}
		_, rerr := b.Render()
		if (rerr == nil) != (c.want == nil) {
			t.Errorf("%s: Render %v, ParseBinding %v: they must agree", name, rerr, err)
		}
	}
	for name, b := range map[string]relaybind.Binding{
		"negative from":      {Device: testDev, From: -1, Until: min},
		"negative until":     {Device: testDev, From: 0, Until: -5},
		"MaxInt64 until":     {Device: testDev, From: 0, Until: math.MaxInt64},
		"MinInt64 from":      {Device: testDev, From: math.MinInt64, Until: 5000},
		"overflowing spread": {Device: testDev, From: math.MinInt64, Until: math.MaxInt64},
	} {
		if _, err := b.Render(); err == nil {
			t.Errorf("%s: Render accepted %+v", name, b)
		}
	}
}

// spec: SPO-Xrelaybind-OUT-003
func TestRevokeRenderAndRoundTrip(t *testing.T) {
	one := relaybind.Revoke{Device: fpOf(0), NotBefore: 1700000000}
	got, err := one.Render()
	if err != nil {
		t.Fatal(err)
	}
	if want := "spo-relay-revoke-v1 device 000102030405060708090a0b0c0d0e0f10111213 not-before 1700000000"; string(got) != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if len(got) != 89 {
		t.Fatalf("length %d, the ADR says 89 with a 10-digit time", len(got))
	}
	all := relaybind.Revoke{All: true, NotBefore: 1700000000}
	got, err = all.Render()
	if err != nil || string(got) != "spo-relay-revoke-v1 device all not-before 1700000000" {
		t.Fatalf("all: %q, %v", got, err)
	}
	for _, r := range []relaybind.Revoke{one, all,
		{All: true, NotBefore: 0},
		{Device: fpOf(9), NotBefore: relaybind.MaxTime},
	} {
		p, err := r.Render()
		if err != nil {
			t.Fatalf("%+v: %v", r, err)
		}
		back, err := relaybind.ParseRevoke(p)
		if err != nil || back != r {
			t.Errorf("%+v: round trip %+v, %v", r, back, err)
		}
	}
	for name, r := range map[string]relaybind.Revoke{
		"all with a device":   {All: true, Device: fpOf(1), NotBefore: 5},
		"negative not-before": {Device: fpOf(1), NotBefore: -1},
		"over MaxTime":        {Device: fpOf(1), NotBefore: relaybind.MaxTime + 1},
	} {
		if _, err := r.Render(); err == nil {
			t.Errorf("%s: Render accepted %+v", name, r)
		}
	}
}

// spec: SPO-Xrelaybind-PRE-017
func TestParseRevokeRefusesNearMisses(t *testing.T) {
	dev := fmt.Sprintf("%x", testDev[:])
	good := "spo-relay-revoke-v1 device " + dev + " not-before 1800000000"
	cases := map[string]string{
		"empty":              "",
		"binding label":      replace(good, "revoke", "binding"),
		"label v2":           replace(good, "revoke-v1", "revoke-v2"),
		"upper-case ALL":     "spo-relay-revoke-v1 device ALL not-before 5",
		"mixed-case All":     "spo-relay-revoke-v1 device All not-before 5",
		"all with spaces":    "spo-relay-revoke-v1 device all  not-before 5",
		"all and hex":        "spo-relay-revoke-v1 device all" + dev + " not-before 5",
		"upper-case hex":     replace(good, dev, strings.ToUpper(dev)),
		"39 hex":             replace(good, dev, dev[:39]),
		"41 hex":             replace(good, dev, dev+"a"),
		"leading space":      " " + good,
		"trailing space":     good + " ",
		"line feed":          good + "\n",
		"double space":       replace(good, " not-before", "  not-before"),
		"leading zero":       replace(good, "1800000000", "01800000000"),
		"zero with a zero":   "spo-relay-revoke-v1 device all not-before 00",
		"plus":               replace(good, "1800000000", "+1800000000"),
		"minus":              replace(good, "1800000000", "-1"),
		"empty time":         "spo-relay-revoke-v1 device all not-before ",
		"over MaxTime":       "spo-relay-revoke-v1 device all not-before 253402300800",
		"13 digits":          "spo-relay-revoke-v1 device all not-before 1000000000000",
		"missing not-before": "spo-relay-revoke-v1 device all",
		"not_before":         "spo-relay-revoke-v1 device all not_before 5",
		"extra field":        good + " x 1",
		"binding payload":    string(goodPayload(t)),
		"121 bytes":          good + strings.Repeat(" ", 121-len(good)),
	}
	for name, s := range cases {
		_, err := relaybind.ParseRevoke([]byte(s))
		if !errors.Is(err, relaybind.ErrPayloadNotCanonical) {
			t.Errorf("%s: %q: %v, want ErrPayloadNotCanonical", name, s, err)
		}
	}
	if _, err := relaybind.ParseBinding([]byte(good)); !errors.Is(err, relaybind.ErrPayloadNotCanonical) {
		t.Errorf("a revoke payload parsed as a binding: %v", err)
	}
	// "0" is a valid not-before; "all" and a device are both accepted.
	for _, s := range []string{"spo-relay-revoke-v1 device all not-before 0", good} {
		if _, err := relaybind.ParseRevoke([]byte(s)); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
}

// spec: SPO-Xrelaybind-OUT-003, SPO-Xrelaybind-INV-002
func TestParseRevokeAcceptsOnlyCanonicalRenderings(t *testing.T) {
	for _, base := range []string{
		"spo-relay-revoke-v1 device all not-before 1800000000",
		"spo-relay-revoke-v1 device " + fmt.Sprintf("%x", testDev[:]) + " not-before 7",
	} {
		good := []byte(base)
		for i := range good {
			for _, c := range []byte{' ', '0', '1', 'a', 'A', 'l', 'L', '\n', '+', '-', 0, 0xff} {
				m := bytes.Clone(good)
				if m[i] == c {
					continue
				}
				m[i] = c
				r, err := relaybind.ParseRevoke(m)
				if err != nil {
					continue
				}
				again, rerr := r.Render()
				if rerr != nil || !bytes.Equal(again, m) {
					t.Fatalf("%q byte %d := %#x: accepted but re-renders to %q (%v)", base, i, c, again, rerr)
				}
			}
		}
	}
}

// The bytes a device signs to revoke itself (ADR 0014 decision 7): a
// canonical CBOR array with the label inside, built by hand here.
//
// spec: SPO-Xrelaybind-OUT-004
func TestDeviceRevokeBytes(t *testing.T) {
	dev := fpOf(0x10)
	got, err := relaybind.DeviceRevokeBytes(dev, 1800000000)
	if err != nil {
		t.Fatal(err)
	}
	want := cat(head(4, 3), tstr("spo/relay-revoke-device/v1"), bstr(dev[:]), head(0, 1800000000))
	mustEqualBytes(t, "bytes", got, want)
	if got[0] != 0x83 {
		t.Errorf("first byte %#x; a CBOR array of 3 starts 0x83, which no ASCII payload does", got[0])
	}
	for name, f := range map[string]func() ([]byte, error){
		"another device": func() ([]byte, error) { return relaybind.DeviceRevokeBytes(fpOf(0x11), 1800000000) },
		"another time":   func() ([]byte, error) { return relaybind.DeviceRevokeBytes(dev, 1800000001) },
	} {
		other, err := f()
		if err != nil || bytes.Equal(other, got) {
			t.Errorf("%s: bytes did not change (%v)", name, err)
		}
	}
	for _, nb := range []int64{-1, relaybind.MaxTime + 1, math.MinInt64, math.MaxInt64} {
		if _, err := relaybind.DeviceRevokeBytes(dev, nb); !errors.Is(err, relaybind.ErrRange) {
			t.Errorf("not-before %d: %v, want ErrRange", nb, err)
		}
	}
	if _, err := relaybind.DeviceRevokeBytes(dev, 0); err != nil {
		t.Errorf("not-before 0: %v", err)
	}
	if _, err := relaybind.DeviceRevokeBytes(dev, relaybind.MaxTime); err != nil {
		t.Errorf("not-before MaxTime: %v", err)
	}
}

// spec: SPO-Xrelaybind-OUT-004, SPO-Xrelaybind-SEC-001
func TestVerifyDeviceRevoke(t *testing.T) {
	var ed party.Ed25519Public = party.Ed25519Public(testPub)
	var x party.X25519Public
	copy(x[:], bs(32, 0x50))
	dev := party.FingerprintOf(ed, x)
	const nb = nowT - 10
	msg, err := relaybind.DeviceRevokeBytes(dev, nb)
	if err != nil {
		t.Fatal(err)
	}
	var sig [64]byte
	copy(sig[:], signRaw(msg))
	skew := relaybind.SkewSeconds

	got, err := verifyDevRevoke(ed, x, nb, sig, nowT, skew)
	if err != nil || got != dev {
		t.Fatalf("good revoke: %x, %v", got, err)
	}
	// VerifyDeviceRevoke returns the verified type: the device and the not-before
	// signed; a refusal returns the zero value, which says it was not verified
	// (SPO-Xmailbox-SEC-062)
	v, err := relaybind.VerifyDeviceRevoke(ed, x, nb, sig, nowT, relaybind.DefaultPolicy())
	if err != nil || v.IsZero() || v.Device() != dev || v.NotBefore() != nb {
		t.Fatalf("verified device revoke: %+v, %v", v, err)
	}
	if bad, err := relaybind.VerifyDeviceRevoke(ed, x, nb+1, sig, nowT, relaybind.DefaultPolicy()); err == nil || !bad.IsZero() {
		t.Fatalf("a refused revoke returned %+v, %v", bad, err)
	}
	if !(relaybind.VerifiedDeviceRevoke{}).IsZero() {
		t.Fatal("the zero VerifiedDeviceRevoke is not zero")
	}
	// The relay recomputes the fingerprint from the two keys; another X25519
	// key is another device and the signature no longer fits.
	x2 := x
	x2[0] ^= 1
	if _, err := verifyDevRevoke(ed, x2, nb, sig, nowT, skew); !errors.Is(err, relaybind.ErrBadSignature) {
		t.Errorf("another x25519 key: %v", err)
	}
	ed2 := party.Ed25519Public(otherPub)
	if _, err := verifyDevRevoke(ed2, x, nb, sig, nowT, skew); !errors.Is(err, relaybind.ErrBadSignature) {
		t.Errorf("another ed25519 key: %v", err)
	}
	if _, err := verifyDevRevoke(ed, x, nb+1, sig, nowT, skew); !errors.Is(err, relaybind.ErrBadSignature) {
		t.Errorf("another not-before: %v", err)
	}
	for i := 0; i < 64*8; i++ {
		s := sig
		s[i/8] ^= 1 << (i % 8)
		if _, err := verifyDevRevoke(ed, x, nb, s, nowT, skew); err == nil {
			t.Fatalf("signature bit %d flipped and still verifies", i)
		}
	}
	// A signature under another label does not verify as a device revoke.
	other := signRaw(append([]byte("spo/mailbox-auth/v2"), msg...))
	copy(sig[:], other)
	if _, err := verifyDevRevoke(ed, x, nb, sig, nowT, skew); err == nil {
		t.Error("a signature over other bytes verified")
	}
	// not-before: at relay time plus skew passes, one second more does not.
	for _, c := range []struct {
		nb   int64
		want error
	}{{nowT + skew, nil}, {nowT + skew + 1, relaybind.ErrRevokeFuture}, {0, nil}, {-1, relaybind.ErrRange}, {relaybind.MaxTime + 1, relaybind.ErrRange}} {
		m, _ := relaybind.DeviceRevokeBytes(dev, c.nb)
		if c.nb < 0 || c.nb > relaybind.MaxTime {
			m = []byte("x")
		}
		copy(sig[:], signRaw(m))
		_, err := verifyDevRevoke(ed, x, c.nb, sig, nowT, skew)
		if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("not-before %d: %v, want %v", c.nb, err, c.want)
		}
	}
	// Policy: skew outside 0 to SkewSeconds is refused; 0 is the tightest.
	m, _ := relaybind.DeviceRevokeBytes(dev, nowT+1)
	copy(sig[:], signRaw(m))
	if _, err := verifyDevRevoke(ed, x, nowT+1, sig, nowT, 0); !errors.Is(err, relaybind.ErrRevokeFuture) {
		t.Errorf("skew 0: %v", err)
	}
	for _, s := range []int64{-1, skew + 1, math.MaxInt64, math.MinInt64} {
		if _, err := verifyDevRevoke(ed, x, nb, sig, nowT, s); !errors.Is(err, relaybind.ErrRange) {
			t.Errorf("skew %d: %v, want ErrRange", s, err)
		}
	}
	// Relay times at the ends of int64 do not overflow.
	m, _ = relaybind.DeviceRevokeBytes(dev, relaybind.MaxTime)
	copy(sig[:], signRaw(m))
	for _, now := range []int64{math.MaxInt64, math.MinInt64} {
		_, err := verifyDevRevoke(ed, x, relaybind.MaxTime, sig, now, skew)
		if now == math.MaxInt64 && err != nil {
			t.Errorf("now MaxInt64: %v", err)
		}
		if now == math.MinInt64 && !errors.Is(err, relaybind.ErrRevokeFuture) {
			t.Errorf("now MinInt64: %v", err)
		}
	}
}
