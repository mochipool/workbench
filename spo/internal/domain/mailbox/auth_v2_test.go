package mailbox_test

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
)

func paramsV2() mailbox.AuthV2Params {
	return mailbox.AuthV2Params{
		RelayKey:      nk(10),
		ClientNodeKey: nk(20),
		Nonce:         nonce(30),
		RelayTime:     1700000000,
		Fingerprint:   fp(40),
		BindingHash:   hash(50),
		SendersHash:   hash(60),
	}
}

// By hand: a 9-array, the 19-character label as a text string, the version 2,
// the byte strings and the time, in the order of ADR 0014 decision 7.
func wantAuthBytesV2(p mailbox.AuthV2Params) []byte {
	b := []byte{0x89, 0x60 + 19}
	b = append(b, "spo/mailbox-auth/v2"...)
	b = append(b, 2)
	b = append(b, bstr(p.RelayKey[:])...)
	b = append(b, bstr(p.ClientNodeKey[:])...)
	b = append(b, bstr(p.Nonce[:])...)
	b = append(b, 0x1a, 0x65, 0x53, 0xf1, 0x00) // 1700000000
	b = append(b, bstr(p.Fingerprint[:])...)
	b = append(b, bstr(p.BindingHash[:])...)
	b = append(b, bstr(p.SendersHash[:])...)
	return b
}

// spec: SPO-Xmailbox-OUT-053
func TestAuthBytesV2AreTheLabelledArray(t *testing.T) {
	p := paramsV2()
	got, err := mailbox.AuthBytesV2(p)
	if err != nil {
		t.Fatal(err)
	}
	if want := wantAuthBytesV2(p); !bytes.Equal(got, want) {
		t.Fatalf("got  %x\nwant %x", got, want)
	}
	if got[0] != 0x89 || !bytes.HasPrefix(got[1:], append([]byte{0x73}, mailbox.AuthLabelV2...)) {
		t.Error("the label is not the first element of the array")
	}
	if mailbox.AuthLabelV2 != "spo/mailbox-auth/v2" || mailbox.AuthLabel != "spo/mailbox-auth/v1" {
		t.Errorf("labels %q %q", mailbox.AuthLabelV2, mailbox.AuthLabel)
	}
}

// Every field is covered: changing any one changes the bytes, and so does
// swapping any two fields of one type.
//
// spec: SPO-Xmailbox-SEC-039
func TestEveryAuthV2FieldChangesTheBytes(t *testing.T) {
	base, _ := mailbox.AuthBytesV2(paramsV2())
	muts := map[string]func(*mailbox.AuthV2Params){
		"relay key":               func(p *mailbox.AuthV2Params) { p.RelayKey[31] ^= 1 },
		"client key":              func(p *mailbox.AuthV2Params) { p.ClientNodeKey[0] ^= 1 },
		"nonce":                   func(p *mailbox.AuthV2Params) { p.Nonce[17] ^= 1 },
		"time":                    func(p *mailbox.AuthV2Params) { p.RelayTime++ },
		"fingerprint":             func(p *mailbox.AuthV2Params) { p.Fingerprint[19] ^= 1 },
		"binding hash":            func(p *mailbox.AuthV2Params) { p.BindingHash[31] ^= 1 },
		"binding hash first byte": func(p *mailbox.AuthV2Params) { p.BindingHash[0] ^= 1 },
		"senders hash":            func(p *mailbox.AuthV2Params) { p.SendersHash[0] ^= 1 },
		"senders hash last byte":  func(p *mailbox.AuthV2Params) { p.SendersHash[31] ^= 1 },
	}
	for name, mut := range muts {
		p := paramsV2()
		mut(&p)
		got, err := mailbox.AuthBytesV2(p)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if bytes.Equal(got, base) {
			t.Errorf("%s does not change the signed bytes", name)
		}
	}
	p := paramsV2()
	p.RelayKey, p.ClientNodeKey = p.ClientNodeKey, p.RelayKey
	if got, _ := mailbox.AuthBytesV2(p); bytes.Equal(got, base) {
		t.Error("swapped node keys give the same bytes")
	}
	p = paramsV2()
	p.BindingHash, p.SendersHash = p.SendersHash, p.BindingHash
	if got, _ := mailbox.AuthBytesV2(p); bytes.Equal(got, base) {
		t.Error("swapped hashes give the same bytes")
	}
	// Dropping a field (a zero value) changes the bytes too.
	for name, mut := range map[string]func(*mailbox.AuthV2Params){
		"zero binding hash": func(p *mailbox.AuthV2Params) { p.BindingHash = [32]byte{} },
		"zero senders hash": func(p *mailbox.AuthV2Params) { p.SendersHash = [32]byte{} },
		"zero fingerprint":  func(p *mailbox.AuthV2Params) { p.Fingerprint = party.Fingerprint{} },
	} {
		p := paramsV2()
		mut(&p)
		if got, _ := mailbox.AuthBytesV2(p); bytes.Equal(got, base) {
			t.Errorf("%s gives the same bytes", name)
		}
	}
}

// spec: SPO-Xmailbox-PRE-030
func TestAuthBytesV2RefuseOutOfRangeInputs(t *testing.T) {
	for name, mut := range map[string]func(*mailbox.AuthV2Params){
		"negative time":  func(p *mailbox.AuthV2Params) { p.RelayTime = -1 },
		"min int64 time": func(p *mailbox.AuthV2Params) { p.RelayTime = -1 << 63 },
		"time max+1":     func(p *mailbox.AuthV2Params) { p.RelayTime = mailbox.MaxTime + 1 },
		"max int64 time": func(p *mailbox.AuthV2Params) { p.RelayTime = 1<<63 - 1 },
	} {
		p := paramsV2()
		mut(&p)
		if _, err := mailbox.AuthBytesV2(p); !errors.Is(err, mailbox.ErrRange) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, mut := range map[string]func(*mailbox.AuthV2Params){
		"time 0":   func(p *mailbox.AuthV2Params) { p.RelayTime = 0 },
		"time max": func(p *mailbox.AuthV2Params) { p.RelayTime = mailbox.MaxTime },
	} {
		p := paramsV2()
		mut(&p)
		if _, err := mailbox.AuthBytesV2(p); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The separation of SEC-001, extended: the version 1 array has 7 elements and
// the label v1; the version 2 array has 9 and the label v2; the device revoke
// is an array of 3 under its own label; every other message the device key
// signs starts with an ASCII byte. No label is a prefix or a part of another
// message's bytes, and no two messages have the same first element.
//
// spec: SPO-Xmailbox-SEC-038
func TestAuthBytesV2AreSeparatedFromEverythingTheDeviceKeySigns(t *testing.T) {
	v2, err := mailbox.AuthBytesV2(paramsV2())
	if err != nil {
		t.Fatal(err)
	}
	v1p := params()
	v1, err := mailbox.AuthBytes(v1p)
	if err != nil {
		t.Fatal(err)
	}
	rev, err := relaybind.DeviceRevokeBytes(fp(40), 1700000000)
	if err != nil {
		t.Fatal(err)
	}
	if v1[0] != 0x87 || v2[0] != 0x89 || rev[0] != 0x83 {
		t.Fatalf("array heads: v1 0x%02x, v2 0x%02x, device revoke 0x%02x", v1[0], v2[0], rev[0])
	}
	labelOf := func(b []byte) string { // the text string after the array head
		n := int(b[1] - 0x60)
		if b[1] < 0x60 || b[1] > 0x77 {
			n = int(b[2])
			return string(b[3 : 3+n])
		}
		return string(b[2 : 2+n])
	}
	labels := map[string]string{
		"mailbox auth v1":   labelOf(v1),
		"mailbox auth v2":   labelOf(v2),
		"device revoke":     labelOf(rev),
		"envelope":          "spo/envelope/v1",
		"identity document": party.DocumentDomain,
		"rotation, old key": party.RotationOldDomain,
		"rotation, new key": party.RotationNewDomain,
	}
	if labels["mailbox auth v1"] != mailbox.AuthLabel || labels["mailbox auth v2"] != mailbox.AuthLabelV2 || labels["device revoke"] != relaybind.DeviceRevokeLabel {
		t.Fatalf("labels %v", labels)
	}
	seen := map[string]string{}
	for what, l := range labels {
		if prev, dup := seen[l]; dup {
			t.Errorf("%s and %s share the label %q", what, prev, l)
		}
		seen[l] = what
	}
	// Each array's bytes start with its head and its own label and carry no
	// other label.
	arrays := map[string][]byte{"mailbox auth v1": v1, "mailbox auth v2": v2, "device revoke": rev}
	for name, b := range arrays {
		for what, l := range labels {
			has := bytes.Contains(b, []byte(l))
			if what == name && !has || what != name && has {
				t.Errorf("%s: contains the label of %s: %v", name, what, has)
			}
		}
	}
	// The ASCII-label messages start with a byte below 0x80; the arrays start
	// with 0x80 or more, and the three arrays start differently.
	for what, l := range labels {
		if what == "mailbox auth v1" || what == "mailbox auth v2" || what == "device revoke" {
			continue
		}
		if l == "" || l[0] >= 0x80 {
			t.Errorf("%s: label %q does not start with an ASCII byte", what, l)
		}
		for name, b := range arrays {
			if bytes.HasPrefix(b, []byte(l)) {
				t.Errorf("%s starts with the label of %s", name, what)
			}
		}
	}
	if v1[0] == v2[0] || v1[0] == rev[0] || v2[0] == rev[0] {
		t.Error("two arrays start with the same head")
	}
	// The same fields under the other label and head are other bytes: a v1
	// array built over the v2 values is not the v2 array.
	if bytes.Equal(v1, v2) || bytes.HasPrefix(v2, v1) || bytes.HasPrefix(v1, v2) {
		t.Error("the v1 and v2 auth bytes are not separate")
	}
	// The relaybind statement payloads are ASCII and reserved: no auth array
	// can be one.
	for _, b := range arrays {
		if relaybind.IsReserved(b) {
			t.Error("an array is a reserved payload")
		}
	}
}

func deviceKeyPair(seed byte) (ed25519.PrivateKey, mailbox.DeviceKeys) {
	priv, pub := keypair(seed)
	var x party.X25519Public
	copy(x[:], bs(32, seed+100))
	return priv, mailbox.DeviceKeys{Ed25519: pub, X25519: x}
}

func signV2(t *testing.T, priv ed25519.PrivateKey, p mailbox.AuthV2Params) (s [64]byte) {
	t.Helper()
	b, err := mailbox.AuthBytesV2(p)
	if err != nil {
		t.Fatal(err)
	}
	copy(s[:], ed25519.Sign(priv, b))
	return
}

// goodV2 is a device, the parameters of its authentication over the tunnel as
// its node key, and a genuine signature.
func goodV2(t *testing.T) (ed25519.PrivateKey, mailbox.DeviceKeys, mailbox.AuthV2Params, [64]byte) {
	priv, keys := deviceKeyPair(1)
	p := paramsV2()
	p.Fingerprint = keys.Fingerprint()
	return priv, keys, p, signV2(t, priv, p)
}

// Each comparison VerifyAuthV2 enforces is refused with its own error, and
// every one of them is also an ErrAuth. The signature in each case is genuine,
// so only the named check can be what refuses.
//
// spec: SPO-Xmailbox-SEC-037
func TestVerifyAuthV2BindsTheDevice(t *testing.T) {
	priv, keys, p, s := goodV2(t)
	peer := p.ClientNodeKey
	if err := mailbox.VerifyAuthV2(keys, peer, s, p); err != nil {
		t.Fatalf("a good authentication: %v", err)
	}
	// The claimed fingerprint is not that of the presented keys.
	q := p
	q.Fingerprint = fp(77)
	if err := mailbox.VerifyAuthV2(keys, peer, signV2(t, priv, q), q); !errors.Is(err, mailbox.ErrAuthFingerprint) || !errors.Is(err, mailbox.ErrAuth) {
		t.Errorf("another fingerprint: %v", err)
	}
	// The fingerprint follows both presented keys.
	k2 := keys
	k2.X25519[0] ^= 1
	if err := mailbox.VerifyAuthV2(k2, peer, s, p); !errors.Is(err, mailbox.ErrAuthFingerprint) {
		t.Errorf("another x25519 key: %v", err)
	}
	// A device that presents another Ed25519 key, whose own fingerprint it
	// claims and signs for, is that other device: it authenticates as it, and
	// the claim for the first fingerprint is refused.
	otherPriv, otherKeys := deviceKeyPair(2)
	if err := mailbox.VerifyAuthV2(otherKeys, peer, signV2(t, otherPriv, p), p); !errors.Is(err, mailbox.ErrAuthFingerprint) {
		t.Errorf("another device claiming this fingerprint: %v", err)
	}
	// The tunnel peer is not the node key the client claims.
	if err := mailbox.VerifyAuthV2(keys, nk(99), s, p); !errors.Is(err, mailbox.ErrAuthTunnelKey) || !errors.Is(err, mailbox.ErrAuth) {
		t.Errorf("another tunnel peer: %v", err)
	}
	// There is no check against an identity's node key: a client whose node key
	// is not the one in any document authenticates, because the relay has no
	// document. The version 1 reason does not exist in version 2.
	q = p
	q.ClientNodeKey = nk(98)
	if err := mailbox.VerifyAuthV2(keys, q.ClientNodeKey, signV2(t, priv, q), q); err != nil {
		t.Errorf("a client at another node key: %v", err)
	}
	if errors.Is(mailbox.ErrAuthIdentityNode, mailbox.ErrAuth) {
		t.Log("(the version 1 reasons are still defined)")
	}
	// The reasons are different errors.
	reasons := []error{mailbox.ErrAuthFingerprint, mailbox.ErrAuthTunnelKey, mailbox.ErrAuthWeakKey}
	for i, a := range reasons {
		for j, b := range reasons {
			if (i == j) != (a == b) {
				t.Errorf("reasons %d and %d", i, j)
			}
		}
	}
}

// The order of the checks: the key, then the fingerprint, then the tunnel peer,
// then the signature.
//
// spec: SPO-Xmailbox-SEC-037
func TestVerifyAuthV2Order(t *testing.T) {
	priv, keys, p, _ := goodV2(t)
	// A wrong fingerprint and a wrong peer: the fingerprint is named.
	q := p
	q.Fingerprint = fp(77)
	if err := mailbox.VerifyAuthV2(keys, nk(99), signV2(t, priv, q), q); !errors.Is(err, mailbox.ErrAuthFingerprint) || errors.Is(err, mailbox.ErrAuthTunnelKey) {
		t.Errorf("fingerprint and peer both wrong: %v", err)
	}
	// A wrong peer and a bad signature: the peer is named.
	var bad [64]byte
	if err := mailbox.VerifyAuthV2(keys, nk(99), bad, p); !errors.Is(err, mailbox.ErrAuthTunnelKey) {
		t.Errorf("peer and signature both wrong: %v", err)
	}
	// Out of range parameters are ErrRange, after the three comparisons.
	q = p
	q.RelayTime = -1
	if err := mailbox.VerifyAuthV2(keys, p.ClientNodeKey, bad, q); !errors.Is(err, mailbox.ErrRange) || errors.Is(err, mailbox.ErrAuth) {
		t.Errorf("a negative time: %v", err)
	}
	if err := mailbox.VerifyAuthV2(keys, nk(99), bad, q); !errors.Is(err, mailbox.ErrAuthTunnelKey) {
		t.Errorf("a negative time and a wrong peer: %v", err)
	}
	// A weak key is named before the fingerprint.
	weak := keys
	weak.Ed25519 = party.Ed25519Public{1}
	q = p
	q.Fingerprint = weak.Fingerprint()
	var universal [64]byte
	universal[0] = 1 // R = the identity point, S = 0
	if err := mailbox.VerifyAuthV2(weak, p.ClientNodeKey, universal, q); !errors.Is(err, mailbox.ErrAuthWeakKey) || !errors.Is(err, mailbox.ErrAuth) {
		t.Errorf("the identity point as the key: %v", err)
	}
	if err := mailbox.VerifyAuthV2(weak, nk(99), universal, p); !errors.Is(err, mailbox.ErrAuthWeakKey) {
		t.Errorf("a weak key with a wrong fingerprint: %v", err)
	}
}

// A device key that is a small-order point or not canonical makes a signature
// that holds for every message: it is refused. The identity point, its order-2
// and order-4 companions, a non-canonical y, and the sign-bit form.
//
// spec: SPO-Xmailbox-SEC-041
func TestVerifyAuthV2RefusesWeakDeviceKeys(t *testing.T) {
	weakKeys := map[string]party.Ed25519Public{
		"identity":        {1},
		"zero":            {},
		"order 2 (p-1)":   {0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
		"identity, sign":  {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80},
		"y = p":           {0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
		"y = 2^255-1":     {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
		"order 8 a":       {0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a},
		"order 8 b":       {0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05},
		"order 8 a, sign": {0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0xfa},
	}
	for name, k := range weakKeys {
		keys := mailbox.DeviceKeys{Ed25519: k, X25519: xk(6)}
		p := paramsV2()
		p.Fingerprint = keys.Fingerprint()
		var s [64]byte
		s[0] = 1
		if err := mailbox.VerifyAuthV2(keys, p.ClientNodeKey, s, p); !errors.Is(err, mailbox.ErrAuthWeakKey) || !errors.Is(err, mailbox.ErrAuth) {
			t.Errorf("%s: %v", name, err)
		}
		// The rule is the one relaybind applies to the same key (the two
		// packages do not import each other, so this pins them together).
		if _, err := relaybind.VerifyDeviceRevoke(k, xk(6), 5, s, 10, relaybind.DefaultPolicy()); !errors.Is(err, relaybind.ErrWeakKey) {
			t.Errorf("%s: relaybind: %v", name, err)
		}
	}
	// A key that is not weak is not refused as weak: the weakest of the
	// ordinary ones, y = 2 and y = p - 2.
	_, keys, p, s := goodV2(t)
	if err := mailbox.VerifyAuthV2(keys, p.ClientNodeKey, s, p); err != nil {
		t.Errorf("a good key: %v", err)
	}
	for name, k := range map[string]party.Ed25519Public{
		"y just below p, byte 1 low":  {0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
		"y just below p, byte 30 low": {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x7f},
		"y with byte 31 below 0x7f":   {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7e},
		"y = 2":                       {2},
		"y = p-2":                     {0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	} {
		kk := mailbox.DeviceKeys{Ed25519: k, X25519: xk(6)}
		q := paramsV2()
		q.Fingerprint = kk.Fingerprint()
		var sg [64]byte
		if err := mailbox.VerifyAuthV2(kk, q.ClientNodeKey, sg, q); errors.Is(err, mailbox.ErrAuthWeakKey) {
			t.Errorf("%s is refused as weak: %v", name, err)
		}
		if _, err := relaybind.VerifyDeviceRevoke(k, xk(6), 5, sg, 10, relaybind.DefaultPolicy()); errors.Is(err, relaybind.ErrWeakKey) {
			t.Errorf("%s: relaybind refuses it as weak: %v", name, err)
		}
	}
}

// The key is the device's: a signature by another key over the right bytes is
// refused as ErrAuth alone, and so is every bit of a signature and every
// changed field, including the two commitments.
//
// spec: SPO-Xmailbox-SEC-037, SPO-Xmailbox-SEC-039
func TestVerifyAuthV2ChecksTheSignature(t *testing.T) {
	priv, keys, p, s := goodV2(t)
	peer := p.ClientNodeKey
	plain := func(err error) bool {
		return errors.Is(err, mailbox.ErrAuth) && !errors.Is(err, mailbox.ErrAuthFingerprint) &&
			!errors.Is(err, mailbox.ErrAuthTunnelKey) && !errors.Is(err, mailbox.ErrAuthWeakKey) && !errors.Is(err, mailbox.ErrRange)
	}
	otherPriv, _ := keypair(2)
	if err := mailbox.VerifyAuthV2(keys, peer, signV2(t, otherPriv, p), p); !plain(err) {
		t.Errorf("another key: %v", err)
	}
	for i := 0; i < 64; i++ {
		c := s
		c[i] ^= 0x80
		if err := mailbox.VerifyAuthV2(keys, peer, c, p); !plain(err) {
			t.Fatalf("signature byte %d flipped: %v", i, err)
		}
	}
	for name, mut := range map[string]func(*mailbox.AuthV2Params){
		"relay key":    func(q *mailbox.AuthV2Params) { q.RelayKey[0] ^= 1 },
		"nonce":        func(q *mailbox.AuthV2Params) { q.Nonce[0] ^= 1 },
		"time":         func(q *mailbox.AuthV2Params) { q.RelayTime++ },
		"binding hash": func(q *mailbox.AuthV2Params) { q.BindingHash[7] ^= 1 },
		"senders hash": func(q *mailbox.AuthV2Params) { q.SendersHash[7] ^= 1 },
	} {
		q := p
		mut(&q)
		if err := mailbox.VerifyAuthV2(keys, peer, s, q); !plain(err) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A signature over the same fields under another label does not verify.
	good, _ := mailbox.AuthBytesV2(p)
	other := append([]byte{0x89, 0x60 + 19}, "spo/mailbox-auth/v3"...)
	other = append(other, good[2+19:]...)
	var s2 [64]byte
	copy(s2[:], ed25519.Sign(priv, other))
	if err := mailbox.VerifyAuthV2(keys, peer, s2, p); !plain(err) {
		t.Errorf("another label: %v", err)
	}
	// A time outside the range is ErrRange.
	q := p
	q.RelayTime = mailbox.MaxTime + 1
	if err := mailbox.VerifyAuthV2(keys, peer, s, q); !errors.Is(err, mailbox.ErrRange) {
		t.Errorf("relay time above the bound: %v", err)
	}
}

// What protects against a downgrade from 2 to 1. The version is inside the
// signed bytes of both versions, under different labels and array lengths, so
// a signature made for one is no signature for the other: an attacker who
// rewrites the offered versions or the Auth frame cannot make both sides
// complete a version 1 session unless the client itself signs version 1 bytes,
// and a client signs version 1 bytes only if it chose version 1. Rewriting the
// Challenge's range is the one thing that makes a client without a floor
// choose version 1; a client with a floor refuses.
//
// spec: SPO-Xmailbox-SEC-036
func TestDowngradeNeedsTheClientsOwnSignatureOverVersion1(t *testing.T) {
	priv, id, p1 := listed(1)
	keys := mailbox.DeviceKeys{Ed25519: id.Ed25519, X25519: id.X25519}
	p2 := paramsV2()
	p2.ClientNodeKey = p1.ClientNodeKey
	p2.RelayKey = p1.RelayKey
	p2.Nonce = p1.Nonce
	p2.RelayTime = p1.RelayTime
	p2.Fingerprint = p1.Fingerprint
	peer := p1.ClientNodeKey

	// 1. The client signs version 2. The attacker turns the Auth into a
	// version 1 Auth carrying the same signature: version 1 verification
	// refuses it, and so does a signature over the version 1 bytes presented as
	// version 2.
	s2 := signV2(t, priv, p2)
	if err := mailbox.VerifyAuthV2(keys, peer, s2, p2); err != nil {
		t.Fatalf("version 2: %v", err)
	}
	if err := mailbox.VerifyAuth(id, peer, s2, p1); !errors.Is(err, mailbox.ErrAuth) {
		t.Errorf("a version 2 signature as a version 1 signature: %v", err)
	}
	s1 := sign(t, priv, p1)
	if err := mailbox.VerifyAuth(id, peer, s1, p1); err != nil {
		t.Fatalf("version 1: %v", err)
	}
	if err := mailbox.VerifyAuthV2(keys, peer, s1, p2); !errors.Is(err, mailbox.ErrAuth) {
		t.Errorf("a version 1 signature as a version 2 signature: %v", err)
	}
	// Even the version 1 array that says version 2 is not the version 2 array.
	pv := p1
	pv.Version = 2
	if err := mailbox.VerifyAuthV2(keys, peer, sign(t, priv, pv), p2); !errors.Is(err, mailbox.ErrAuth) {
		t.Errorf("a version 1 array with version 2: %v", err)
	}
	// 2. The Auth frame cannot be rewritten into the other version's: the
	// shapes differ, so a version 2 Auth with its version field set to 1 is not
	// a version 1 Auth.
	a2 := mustEncodeV(t, 2, mailbox.AuthV2{Fingerprint: p2.Fingerprint, Signature: s2, Keys: keys, Sign1: bs(10, 1), Key: bs(10, 2)})
	rewritten := cbor(t, 1, 1, fpb(40), s2[:], []any{keys.Ed25519[:], keys.X25519[:], bs(10, 1), bs(10, 2)}, []any{})
	if bytes.Equal(a2, rewritten) {
		t.Fatal("test bug")
	}
	for _, st := range []mailbox.Stage{mailbox.StageUnversioned, mailbox.StageV1, mailbox.StageV2PreAuth} {
		if m, err := mailbox.DecodeFromClientIn(st, rewritten); err == nil {
			t.Errorf("a version 1 Auth with a version 2 body decoded at %v as %T", st, m)
		}
	}
	// 3. The relay's Challenge range is not signed in either version. A client
	// that supports both and is shown 1..1 chooses version 1 and signs it. A
	// client that speaks version 2 only refuses. This is the whole of the
	// protection against a rewrite of the Challenge: the tunnel authenticates
	// the relay, so only the relay can make it, a version 1 signature obtained
	// that way binds that relay's key (the signed array holds the relay key the
	// client pinned) and verifies nowhere else, and clients speak version 2 only.
	both := mailbox.BothVersions
	if v, err := both.Choose(1, 1); err != nil || v != 1 {
		t.Fatalf("a client of both versions: %d, %v", v, err)
	}
	if _, err := mailbox.V2.Choose(1, 1); !errors.Is(err, mailbox.ErrVersion) {
		t.Errorf("a client of version 2: %v", err)
	}
	// The version 1 signature binds the relay key: against another relay's key
	// it does not verify.
	other := p1
	other.RelayKey = nk(77)
	if err := mailbox.VerifyAuth(id, peer, s1, other); !errors.Is(err, mailbox.ErrAuth) {
		t.Errorf("a version 1 signature at another relay: %v", err)
	}
	// The relay that offered only 2 refuses a version 1 Auth at the decoder.
	st, err := mailbox.StageForOffer(mailbox.V2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mailbox.DecodeFromClientIn(st, mustEncodeV(t, 1, mailbox.Auth{Version: 1, Fingerprint: p1.Fingerprint, Signature: s1})); !errors.Is(err, mailbox.ErrVersion) {
		t.Errorf("a version 1 Auth at a relay that offers only 2: %v", err)
	}
}

// The commitments: a real binding and a real list go through the relay's whole
// pure path, and the device signature fails if the binding or the senders
// change. The binding hash is relaybind's FullHash of the canonical statement,
// signature included, so a second valid signature over the same statement is
// another hash.
//
// spec: SPO-Xmailbox-SEC-039, SPO-Xmailbox-OUT-053
func TestAuthV2CommitsToTheBindingAndTheSenders(t *testing.T) {
	devPriv, keys := deviceKeyPair(1)
	device := keys.Fingerprint()
	walletPriv := ed25519.NewKeyFromSeed(bs(32, 7))
	walletPub := [32]byte(walletPriv.Public().(ed25519.PublicKey))
	const now = int64(1800000000)
	payload, err := relaybind.Binding{Device: device, From: now - 60, Until: now - 60 + 90*86400}.Render()
	if err != nil {
		t.Fatal(err)
	}
	sign1 := realSign1(t, walletPriv, walletPub, payload, false)
	st, err := relaybind.ParseStatement(sign1)
	if err != nil {
		t.Fatal(err)
	}
	vb, err := relaybind.VerifyBinding(st, walletPub, device, now, relaybind.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	senders, err := mailbox.CanonicalSenders([]mailbox.WalletKey{wk(30), wk(10), wk(20)})
	if err != nil {
		t.Fatal(err)
	}
	sh, err := mailbox.SendersHash(senders)
	if err != nil {
		t.Fatal(err)
	}
	p := paramsV2()
	p.Fingerprint = device
	p.BindingHash = vb.FullHash()
	p.SendersHash = sh
	frame := mailbox.AuthV2{Fingerprint: device, Signature: signV2(t, devPriv, p), Keys: keys, Sign1: sign1, Key: realKey(walletPub), Senders: senders}
	b := mustEncodeV(t, 2, frame)

	// The relay: decode, recompute both commitments from what was presented,
	// verify the binding with the computed device, then the device signature.
	m, err := mailbox.DecodeFromClientIn(mailbox.StageV2PreAuth, b)
	if err != nil {
		t.Fatal(err)
	}
	a := m.(mailbox.AuthV2)
	relayCheck := func(a mailbox.AuthV2) error {
		st, err := relaybind.ParseStatement(a.Sign1)
		if err != nil {
			return err
		}
		vk, err := relaybind.ParseCOSEKey(a.Key)
		if err != nil {
			return err
		}
		vb, err := relaybind.VerifyBinding(st, vk, a.Keys.Fingerprint(), now, relaybind.DefaultPolicy())
		if err != nil {
			return err
		}
		sh, err := mailbox.SendersHash(a.Senders)
		if err != nil {
			return err
		}
		q := paramsV2()
		q.Fingerprint = a.Fingerprint
		q.BindingHash = vb.FullHash()
		q.SendersHash = sh
		return mailbox.VerifyAuthV2(a.Keys, q.ClientNodeKey, a.Signature, q)
	}
	if err := relayCheck(a); err != nil {
		t.Fatalf("the genuine authentication: %v", err)
	}
	// The same statement under a second valid signature of the wallet key (a
	// different nonce, here the same message with a different protected-header
	// key order) has another full hash: the device signature no longer fits it.
	swapped := realSign1(t, walletPriv, walletPub, payload, true)
	if st2, err := relaybind.ParseStatement(swapped); err == nil {
		if st2.FullHash() == st.FullHash() {
			t.Fatal("test bug: the two statements have one full hash")
		}
		b2 := a
		b2.Sign1 = swapped
		if err := relayCheck(b2); !errors.Is(err, mailbox.ErrAuth) || errors.Is(err, mailbox.ErrAuthFingerprint) {
			t.Errorf("another encoding of the same binding: %v", err)
		}
	} else {
		t.Fatalf("the test's second statement does not parse: %v", err)
	}
	// A changed expected-sender list.
	for name, mut := range map[string]func(*mailbox.AuthV2){
		"a sender added":   func(c *mailbox.AuthV2) { c.Senders = append(append([]mailbox.WalletKey{}, c.Senders...), wk(40)) },
		"a sender dropped": func(c *mailbox.AuthV2) { c.Senders = append([]mailbox.WalletKey{}, c.Senders[1:]...) },
		"a sender changed": func(c *mailbox.AuthV2) {
			c.Senders = append([]mailbox.WalletKey{}, c.Senders...)
			c.Senders[2][5] ^= 1
		},
		"all dropped": func(c *mailbox.AuthV2) { c.Senders = nil },
	} {
		c := a
		mut(&c)
		if err := relayCheck(c); !errors.Is(err, mailbox.ErrAuth) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A device that is not the one in the binding.
	c := a
	c.Keys.X25519[0] ^= 1
	c.Fingerprint = c.Keys.Fingerprint()
	if err := relayCheck(c); !errors.Is(err, relaybind.ErrDeviceMismatch) {
		t.Errorf("another device: %v", err)
	}
}
