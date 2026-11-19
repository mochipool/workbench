package relaybind_test

import (
	"bytes"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
)

// Seeds are small: the engine minimises every interesting input, and the
// package bounds every input at 512 bytes anyway. Inputs over fuzzCap are skipped.
const fuzzCap = 600

// Whatever ParseStatement accepts is its own canonical encoding, its hash is
// that of the canonical bytes, and verifying it never panics.
//
// spec: SPO-Xrelaybind-INV-002
func FuzzParseStatement(f *testing.F) {
	good := goodSign1(f)
	f.Add(good)
	f.Add(good[:len(good)/2])
	f.Add([]byte{})
	f.Add([]byte{0x84, 0x40, 0xa0, 0x40, 0x40})
	f.Add(cat([]byte{0xd2}, good))
	f.Add(cat(head(4, 4), bstr(protectedWith(testK[:])), head(0, 0), bstr(goodPayload(f)), bstr(make([]byte, 64))))
	f.Add([]byte{0x9f, 0xff})
	f.Add([]byte{0x84, 0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzCap {
			t.Skip()
		}
		st, err := relaybind.ParseStatement(data)
		if err != nil {
			return
		}
		if !bytes.Equal(st.Canonical(), data) {
			t.Fatalf("accepted %x, canonical form %x", data, st.Canonical())
		}
		if st.FullHash() != cose.Blake2b256(data) {
			t.Fatalf("hash of %x", data)
		}
		again, err := relaybind.ParseStatement(st.Canonical())
		if err != nil || again.FullHash() != st.FullHash() {
			t.Fatalf("canonical form of %x does not parse back: %v", data, err)
		}
		// A statement that parsed can be verified without a panic, whatever it says.
		relaybind.VerifyBinding(st, testPub, testDev, nowT, relaybind.DefaultPolicy())
		relaybind.VerifyRevoke(st, testPub, nowT, relaybind.DefaultPolicy())
	})
}

// spec: SPO-Xrelaybind-INV-002
func FuzzParseBinding(f *testing.F) {
	f.Add(goodPayload(f))
	f.Add([]byte("spo-relay-binding-v1 device 0000000000000000000000000000000000000000 from 0 until 3600"))
	f.Add([]byte(""))
	f.Add([]byte("spo-relay-binding-v1 device  from  until "))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzCap {
			t.Skip()
		}
		b, err := relaybind.ParseBinding(data)
		if err != nil {
			return
		}
		again, err := b.Render()
		if err != nil || !bytes.Equal(again, data) {
			t.Fatalf("accepted %q, renders %q (%v)", data, again, err)
		}
		if len(data) > relaybind.MaxPayloadBytes {
			t.Fatalf("accepted %d bytes", len(data))
		}
	})
}

// spec: SPO-Xrelaybind-INV-002
func FuzzParseRevoke(f *testing.F) {
	f.Add([]byte("spo-relay-revoke-v1 device all not-before 0"))
	f.Add([]byte("spo-relay-revoke-v1 device 000102030405060708090a0b0c0d0e0f10111213 not-before 1800000000"))
	f.Add([]byte("spo-relay-revoke-v1 device ALL not-before 1"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzCap {
			t.Skip()
		}
		r, err := relaybind.ParseRevoke(data)
		if err != nil {
			return
		}
		again, err := r.Render()
		if err != nil || !bytes.Equal(again, data) {
			t.Fatalf("accepted %q, renders %q (%v)", data, again, err)
		}
	})
}

// spec: SPO-Xrelaybind-INV-002
func FuzzParseCOSEKey(f *testing.F) {
	f.Add(cose.EncodeKey(testPub[:]))
	f.Add([]byte{})
	f.Add([]byte{0xa4, 0x01, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzCap {
			t.Skip()
		}
		k, err := relaybind.ParseCOSEKey(data)
		if err != nil {
			return
		}
		if !bytes.Equal(cose.EncodeKey(k[:]), data) {
			t.Fatalf("accepted %x, which is not the canonical key encoding", data)
		}
		// An accepted key is none of the ten small-order encodings and has y < p.
		for name, e := range smallOrderEncodings() {
			a, b := bytes.Clone(k[:]), bytes.Clone(e)
			a[31] &^= 0x80
			b[31] &^= 0x80
			if bytes.Equal(a, b) {
				t.Fatalf("accepted the small-order key %s: %x", name, k)
			}
		}
		if k[31]&0x7f == 0x7f && k[0] >= 0xed && bytes.Equal(k[1:31], bytes.Repeat([]byte{0xff}, 30)) {
			t.Fatalf("accepted the non-canonical key %x (y >= p)", k)
		}
	})
}

// Whatever address bytes a statement carries, a binding that verifies has one
// of the accepted forms, with K where the reported part says.
//
// spec: SPO-Xrelaybind-INV-002, SPO-Xrelaybind-PRE-014
func FuzzProtectedAddress(f *testing.F) {
	k := testK[:]
	f.Add(k)
	f.Add(append([]byte{0x61}, k...))
	f.Add(append([]byte{0xe1}, k...))
	f.Add(append(append([]byte{0x01}, k...), bs(28, 0x40)...))
	f.Add(append(append([]byte{0x01}, bs(28, 0x40)...), k...))
	f.Add(append([]byte{0x71}, k...))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, addr []byte) {
		if len(addr) > 80 {
			t.Skip()
		}
		st, err := relaybind.ParseStatement(signed(addr, goodPayload(t)))
		if err != nil {
			return
		}
		vb, err := relaybind.VerifyBinding(st, testPub, testDev, nowT, relaybind.DefaultPolicy())
		if err != nil {
			return
		}
		if vb.Key() != testK {
			t.Fatalf("key %x", vb.Key())
		}
		typ, net := addr[0]>>4, addr[0]&0x0f
		switch vb.AddressPart() {
		case relaybind.PartKeyHash:
			if !bytes.Equal(addr, k) {
				t.Fatalf("key-hash form with %x", addr)
			}
		case relaybind.PartEnterprise, relaybind.PartReward:
			want := byte(6)
			if vb.AddressPart() == relaybind.PartReward {
				want = 14
			}
			if len(addr) != 29 || typ != want || net > 1 || !bytes.Equal(addr[1:], k) {
				t.Fatalf("%v accepted for %x", vb.AddressPart(), addr)
			}
		case relaybind.PartBasePayment:
			if len(addr) != 57 || (typ != 0 && typ != 2) || net > 1 || !bytes.Equal(addr[1:29], k) {
				t.Fatalf("base-payment accepted for %x", addr)
			}
		default:
			t.Fatalf("part %v", vb.AddressPart())
		}
	})
}

// A device-signed revoke never panics, and what verifies is bound to its keys.
//
// spec: SPO-Xrelaybind-INV-002
func FuzzVerifyDeviceRevoke(f *testing.F) {
	f.Add(bs(32, 1), bs(32, 2), int64(1800000000), bs(64, 3), int64(1800000000), int64(300))
	f.Add([]byte{}, []byte{}, int64(-1), []byte{}, int64(0), int64(-1))
	f.Fuzz(func(t *testing.T, ed, x []byte, nb int64, sig []byte, now, skew int64) {
		var e party.Ed25519Public
		var xx party.X25519Public
		var s [64]byte
		copy(e[:], ed)
		copy(xx[:], x)
		copy(s[:], sig)
		fp, err := verifyDevRevoke(e, xx, nb, s, now, skew)
		if err == nil && fp != party.FingerprintOf(e, xx) {
			t.Fatalf("verified for %x but the keys give another fingerprint", fp)
		}
	})
}
