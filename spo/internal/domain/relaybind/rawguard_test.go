package relaybind_test

import (
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
)

// The predicate of the raw-signing routes: every array head of COSE with every
// context string is refused, written out here by hand (not derived from the
// code's table), so a context string or a head dropped from the code fails here.
//
// spec: SPO-Xrelaybind-SEC-018
func TestLooksLikeSignedStatementInputRefusesEveryCOSEContext(t *testing.T) {
	contexts := []struct {
		name string
		head byte // the CBOR text head: 0x60 + length
	}{
		{"Signature1", 0x6a},
		{"Signature", 0x69},
		{"CounterSignature", 0x70},
		{"CounterSignature0", 0x71},
		{"CounterSignatureV2", 0x72},
	}
	heads := []byte{0x84, 0x85, 0x9f}
	for _, h := range heads {
		for _, c := range contexts {
			in := append([]byte{h, c.head}, c.name...)
			if !relaybind.LooksLikeSignedStatementInput(in) {
				t.Errorf("head %#x context %q: not recognised", h, c.name)
			}
			// followed by anything
			if !relaybind.LooksLikeSignedStatementInput(append(in, 0x40, 0x40, 0x58, 0x20)) {
				t.Errorf("head %#x context %q with a tail: not recognised", h, c.name)
			}
			// a prefix of the prefix is not the structure
			// the text head carries the length, so a cut-short string is no other context's prefix
			if relaybind.LooksLikeSignedStatementInput(in[:len(in)-1]) {
				t.Errorf("head %#x context %q cut short: recognised", h, c.name)
			}
		}
	}
}

// The reserved prefixes, each part.
//
// spec: SPO-Xrelaybind-SEC-018
func TestLooksLikeSignedStatementInputRefusesTheReservedPrefixes(t *testing.T) {
	for _, in := range []string{"spo-", "spo/", "spo-relay-binding-v1 device 00", "spo/mailbox-auth/v2", "spo-anything"} {
		if !relaybind.LooksLikeSignedStatementInput([]byte(in)) {
			t.Errorf("%q: not recognised", in)
		}
	}
}

// The Sig_structure the relay verifies, for a real binding and a real revoke, is
// recognised: this is the input of the attack on the Calidus `sign`.
//
// spec: SPO-Xrelaybind-SEC-018
func TestLooksLikeSignedStatementInputRecognisesRealSigStructures(t *testing.T) {
	var k [28]byte
	for _, payload := range [][]byte{[]byte("spo-relay-binding-v1 device 00 from 0 until 3600"), []byte("anything at all"), nil} {
		for _, addr := range [][]byte{k[:], make([]byte, 29), make([]byte, 57)} {
			ss := cose.SigStructure(cose.ProtectedHeader(addr), cose.PayloadFor(payload, false))
			if !relaybind.LooksLikeSignedStatementInput(ss) {
				t.Errorf("a Sig_structure of %d-byte address and payload %q is not recognised", len(addr), payload)
			}
		}
	}
}

// Ordinary text and near misses are not refused, so the Calidus `sign` still
// signs what upstream signs.
//
// spec: SPO-Xrelaybind-SEC-018
func TestLooksLikeSignedStatementInputLeavesOrdinaryDataAlone(t *testing.T) {
	for _, in := range [][]byte{
		nil, {}, []byte("hello pool"), []byte("Signature1"), []byte("spo"), []byte("Spo-x"), []byte(" spo-x"), []byte("xspo-"), []byte("sp"),
		{0x84}, {0x84, 0x6a}, {0x84, 0x6a, 'S'}, // a head with no string
		append([]byte{0x84, 0x69}, "Signature"[:8]...), // a context cut short
		append([]byte{0x83, 0x6a}, "Signature1"...),    // an array of 3 is no Sig_structure
		append([]byte{0x84, 0x6a}, "Signature2"...),    // another string
		append([]byte{0x84, 0x6b}, "Signature1x"...),   // a longer string
		append([]byte{0x80, 0x6a}, "Signature1"...),
		append([]byte{0x86, 0x6a}, "Signature1"...),
		{0xf0, 0x9f, 0x98, 0x80}, // valid UTF-8, an emoji
	} {
		if relaybind.LooksLikeSignedStatementInput(in) {
			t.Errorf("%x (%q) is refused", in, in)
		}
	}
}

// It allocates nothing, so a hostile input costs nothing to refuse or accept.
//
// spec: SPO-Xrelaybind-SEC-018
func TestLooksLikeSignedStatementInputAllocatesNothing(t *testing.T) {
	in := make([]byte, 1<<16)
	if n := testing.AllocsPerRun(100, func() { relaybind.LooksLikeSignedStatementInput(in) }); n != 0 {
		t.Errorf("%v allocations", n)
	}
}

// Why the raw routes of 32-byte digests need no guard: the signing input of a
// statement the relay accepts is always longer than a digest, and begins as the
// predicate says. (The shortest protected header holds the 28-byte key hash.)
//
// spec: SPO-Xrelaybind-SEC-018
func TestASigStructureIsLongerThanADigest(t *testing.T) {
	var k [28]byte
	ss := cose.SigStructure(cose.ProtectedHeader(k[:]), cose.PayloadFor([]byte("spo-relay-binding-v1 device 00 from 0 until 3600"), false))
	if len(ss) <= 32 {
		t.Fatalf("a Sig_structure is %d bytes", len(ss))
	}
	if !relaybind.LooksLikeSignedStatementInput(ss) {
		t.Error("not recognised")
	}
}

// The error is its own sentinel, distinct from the reserved-prefix error of the
// generic message path.
//
// spec: SPO-Xrelaybind-SEC-018
func TestRawStatementInputIsItsOwnError(t *testing.T) {
	if errors.Is(relaybind.ErrRawStatementInput, relaybind.ErrReservedPayload) || errors.Is(relaybind.ErrReservedPayload, relaybind.ErrRawStatementInput) {
		t.Error("the two refusals are one error")
	}
}
