package mailbox_test

import (
	"crypto/ed25519"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/cose"
)

// A minimal CBOR writer for the test's COSE_Sign1, independent of the
// package's.
func chead(major byte, n int) []byte {
	m := major << 5
	switch {
	case n < 24:
		return []byte{m | byte(n)}
	case n < 256:
		return []byte{m | 24, byte(n)}
	}
	return []byte{m | 25, byte(n >> 8), byte(n)}
}

func cbstr(b []byte) []byte { return append(chead(2, len(b)), b...) }
func ctstr(s string) []byte { return append(chead(3, len(s)), s...) }

// realSign1 is a CIP-8 COSE_Sign1 the way the software signing path writes it:
// protected header {1: -8, "address": K}, unprotected {"hashed": false}, the
// payload embedded. swapOrder writes the two protected keys in the other order:
// the same statement, another encoding, another valid signature.
func realSign1(t testing.TB, priv ed25519.PrivateKey, pub [32]byte, payload []byte, swapOrder bool) []byte {
	t.Helper()
	k := cose.Blake2b224(pub[:])
	alg := append(chead(0, 1), chead(1, 7)...)
	addr := append(ctstr("address"), cbstr(k[:])...)
	protected := chead(5, 2)
	if swapOrder {
		protected = append(append(protected, addr...), alg...)
	} else {
		protected = append(append(protected, alg...), addr...)
	}
	sig := ed25519.Sign(priv, cose.SigStructure(protected, payload))
	unprot := append(append(chead(5, 1), ctstr("hashed")...), 0xf4)
	out := chead(4, 4)
	out = append(out, cbstr(protected)...)
	out = append(out, unprot...)
	out = append(out, cbstr(payload)...)
	return append(out, cbstr(sig)...)
}

func realKey(pub [32]byte) []byte { return cose.EncodeKey(pub[:]) }
