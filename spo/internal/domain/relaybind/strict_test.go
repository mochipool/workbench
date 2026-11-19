package relaybind_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
)

// The software signing path (VaultSignatures.SignMessage) writes this very
// encoding with cose.Sign1.Encode; the strict parser accepts it untouched and
// the canonical form is the same bytes.
//
// spec: SPO-Xrelaybind-OUT-005, SPO-Xrelaybind-OUT-006
func TestStrictParserAcceptsWhatTheSoftwarePathWrites(t *testing.T) {
	payload := goodPayload(t)
	prot := cose.ProtectedHeader(testK[:])
	mustEqualBytes(t, "hand-built protected header", prot, protectedWith(testK[:]))
	sig := signRaw(cose.SigStructure(prot, cose.PayloadFor(payload, false)))
	project := cose.Sign1{Protected: prot, Hashed: false, Payload: payload, Signature: sig}.Encode()
	mustEqualBytes(t, "hand-built sign1", goodSign1(t), project)

	st := mustStatement(t, project)
	mustEqualBytes(t, "Canonical", st.Canonical(), project)
	mustEqualBytes(t, "Payload", st.Payload(), payload)
	mustEqualBytes(t, "Protected", st.Protected(), prot)
	mustEqualBytes(t, "Address", st.Address(), testK[:])
	if got := st.Signature(); !bytes.Equal(got[:], sig) {
		t.Errorf("Signature %x want %x", got, sig)
	}
	// The strict COSE_Key: exactly what cose.EncodeKey writes.
	key, err := relaybind.ParseCOSEKey(cose.EncodeKey(testPub[:]))
	if err != nil || key != testPub {
		t.Errorf("ParseCOSEKey: %x, %v", key, err)
	}
}

// Forms the strict parser accepts because the protected bytes are signed:
// either key order of the protected map, and a raw Shelley address.
//
// spec: SPO-Xrelaybind-PRE-014
func TestStrictParserAcceptedProtectedForms(t *testing.T) {
	payload := goodPayload(t)
	base := append(append([]byte{0x01}, testK[:]...), bs(28, 0x60)...)
	swapped := cat(head(5, 2), tstr("address"), bstr(testK[:]), kAlg, vAlg)
	for name, prot := range map[string][]byte{
		"28-byte key hash":  protectedWith(testK[:]),
		"base address":      protectedWith(base),
		"address key first": swapped,
		"29-byte address":   protectedWith(bs(29, 1)),
	} {
		if _, err := relaybind.ParseStatement(signedWith(testPriv, prot, payload)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

type refusal struct {
	name   string
	input  []byte
	reason error
}

func refusals(t testing.TB) []refusal {
	good := goodSign1(t)
	payload := goodPayload(t)
	sig := signRaw([]byte("x"))
	prot := protectedWith(testK[:])
	unprot := unprotOK
	k := testK[:]
	a := func(p, u, pl, s []byte) []byte { return assemble(p, u, pl, s) }
	pOK, plOK, sOK := bstr(prot), bstr(payload), bstr(sig)

	// A protected map with chosen content.
	pm := func(parts ...[]byte) []byte { return bstr(cat(parts...)) }
	var rs []refusal
	add := func(name string, reason error, in []byte) { rs = append(rs, refusal{name, in, reason}) }

	// Non-shortest heads, one per head of the structure.
	add("array head one byte wide", relaybind.ErrNotShortest, cat(wide(4, 4, 1), good[1:]))
	add("protected length two bytes wide", relaybind.ErrNotShortest, a(cat(wide(2, uint64(len(prot)), 2), prot), unprot, plOK, sOK))
	add("payload length one byte wide", relaybind.ErrNotShortest, a(pOK, unprot, cat(wide(2, 5, 1), payload[:5]), sOK))
	add("signature length two bytes wide", relaybind.ErrNotShortest, a(pOK, unprot, plOK, cat(wide(2, 64, 2), sig)))
	add("unprotected map head one byte wide", relaybind.ErrNotShortest, a(pOK, cat(wide(5, 1, 1), tstr("hashed"), cFalse), plOK, sOK))
	add("unprotected key length one byte wide", relaybind.ErrNotShortest, a(pOK, cat(head(5, 1), wide(3, 6, 1), []byte("hashed"), cFalse), plOK, sOK))
	add("protected map head one byte wide", relaybind.ErrNotShortest, a(pm(wide(5, 2, 1), kAlg, vAlg, tstr("address"), bstr(k)), unprot, plOK, sOK))
	add("protected key 1 one byte wide", relaybind.ErrNotShortest, a(pm(head(5, 2), wide(0, 1, 1), vAlg, tstr("address"), bstr(k)), unprot, plOK, sOK))
	add("protected algorithm one byte wide", relaybind.ErrNotShortest, a(pm(head(5, 2), kAlg, wide(1, 7, 1), tstr("address"), bstr(k)), unprot, plOK, sOK))
	add("protected address key length one byte wide", relaybind.ErrNotShortest, a(pm(head(5, 2), kAlg, vAlg, wide(3, 7, 1), []byte("address"), bstr(k)), unprot, plOK, sOK))
	add("address length two bytes wide", relaybind.ErrNotShortest, a(pm(head(5, 2), kAlg, vAlg, tstr("address"), wide(2, 28, 2), k), unprot, plOK, sOK))
	add("array head eight bytes wide", relaybind.ErrNotShortest, cat(wide(4, 4, 8), good[1:]))
	// The boundary of each width: the largest value that has a shorter form.
	add("23 in a one-byte argument", relaybind.ErrNotShortest, a(pOK, unprot, cat(wide(2, 23, 1), make([]byte, 23)), sOK))
	add("255 in a two-byte argument", relaybind.ErrNotShortest, a(pOK, unprot, wide(2, 255, 2), sOK))
	add("65535 in a four-byte argument", relaybind.ErrNotShortest, a(pOK, unprot, wide(2, 65535, 4), sOK))
	add("2^32-1 in an eight-byte argument", relaybind.ErrNotShortest, a(pOK, unprot, wide(2, 1<<32-1, 8), sOK))

	// Indefinite lengths.
	add("indefinite outer array", relaybind.ErrIndefinite, cat([]byte{0x9f}, good[1:], []byte{0xff}))
	add("indefinite protected", relaybind.ErrIndefinite, a([]byte{0x5f, 0x40, 0xff}, unprot, plOK, sOK))
	add("indefinite unprotected map", relaybind.ErrIndefinite, a(pOK, cat([]byte{0xbf}, tstr("hashed"), cFalse, []byte{0xff}), plOK, sOK))
	add("indefinite payload", relaybind.ErrIndefinite, a(pOK, unprot, []byte{0x5f, 0x41, 'a', 0xff}, sOK))
	add("indefinite signature", relaybind.ErrIndefinite, a(pOK, unprot, plOK, []byte{0x5f, 0x40, 0xff}))
	add("indefinite protected map", relaybind.ErrIndefinite, a(pm([]byte{0xbf}, kAlg, vAlg, []byte{0xff}), unprot, plOK, sOK))

	// Tags: the project's Sign1.Encode writes none, so the tag-18 form is refused too.
	add("tag 18 over the array", relaybind.ErrTagged, cat([]byte{0xd2}, good))
	add("tag 1 over the array", relaybind.ErrTagged, cat([]byte{0xc1}, good))
	add("tag on the payload", relaybind.ErrTagged, a(pOK, unprot, cat([]byte{0xc1}, plOK), sOK))
	add("tag on the signature", relaybind.ErrTagged, a(pOK, unprot, plOK, cat([]byte{0xc1}, sOK)))
	add("tag on the unprotected map", relaybind.ErrTagged, a(pOK, cat([]byte{0xc1}, unprot), plOK, sOK))
	add("tag on the protected bytes", relaybind.ErrTagged, a(cat([]byte{0xc1}, pOK), unprot, plOK, sOK))
	add("tag inside the protected header", relaybind.ErrTagged, a(bstr(cat([]byte{0xc1}, prot)), unprot, plOK, sOK))
	add("tagged value in the protected header", relaybind.ErrTagged, a(pm(head(5, 2), kAlg, vAlg, tstr("address"), []byte{0xc1}, bstr(k)), unprot, plOK, sOK))

	// Duplicate map keys.
	add("duplicate algorithm", relaybind.ErrDuplicateKey, a(pm(head(5, 3), kAlg, vAlg, kAlg, vAlg, tstr("address"), bstr(k)), unprot, plOK, sOK))
	add("duplicate address", relaybind.ErrDuplicateKey, a(pm(head(5, 3), kAlg, vAlg, tstr("address"), bstr(k), tstr("address"), bstr(bs(28, 9))), unprot, plOK, sOK))
	add("duplicate in the unprotected map", relaybind.ErrDuplicateKey, a(pOK, cat(head(5, 2), tstr("hashed"), cFalse, tstr("hashed"), cFalse), plOK, sOK))
	add("duplicate with another value", relaybind.ErrDuplicateKey, a(pOK, cat(head(5, 2), tstr("hashed"), cFalse, tstr("hashed"), cTrue), plOK, sOK))

	// Protected keys.
	add("integer key 2", relaybind.ErrProtectedKey, a(pm(head(5, 3), kAlg, vAlg, tstr("address"), bstr(k), head(0, 2), head(0, 0)), unprot, plOK, sOK))
	add("kid text key", relaybind.ErrProtectedKey, a(pm(head(5, 3), kAlg, vAlg, tstr("address"), bstr(k), tstr("kid"), head(0, 0)), unprot, plOK, sOK))
	add("negative key", relaybind.ErrProtectedKey, a(pm(head(5, 3), kAlg, vAlg, tstr("address"), bstr(k), head(1, 0), head(0, 0)), unprot, plOK, sOK))
	add("upper-case Address", relaybind.ErrProtectedKey, a(pm(head(5, 2), kAlg, vAlg, tstr("Address"), bstr(k)), unprot, plOK, sOK))
	add("byte string key", relaybind.ErrProtectedKey, a(pm(head(5, 3), kAlg, vAlg, tstr("address"), bstr(k), bstr(nil), head(0, 0)), unprot, plOK, sOK))
	add("hashed in the protected header", relaybind.ErrHashedInProtected, a(pm(head(5, 3), kAlg, vAlg, tstr("address"), bstr(k), tstr("hashed"), cFalse), unprot, plOK, sOK))
	add("hashed true in the protected header", relaybind.ErrHashedInProtected, a(pm(head(5, 3), kAlg, vAlg, tstr("address"), bstr(k), tstr("hashed"), cTrue), unprot, plOK, sOK))
	add("hashed replaces nothing", relaybind.ErrHashedInProtected, a(pm(head(5, 3), tstr("hashed"), cFalse, kAlg, vAlg, tstr("address"), bstr(k)), unprot, plOK, sOK))

	// Algorithm and address.
	add("algorithm -7", relaybind.ErrAlgorithm, a(pm(head(5, 2), kAlg, head(1, 6), tstr("address"), bstr(k)), unprot, plOK, sOK))
	add("algorithm 8", relaybind.ErrAlgorithm, a(pm(head(5, 2), kAlg, head(0, 8), tstr("address"), bstr(k)), unprot, plOK, sOK))
	add("algorithm as text", relaybind.ErrAlgorithm, a(pm(head(5, 2), kAlg, tstr("EdDSA"), tstr("address"), bstr(k)), unprot, plOK, sOK))
	add("algorithm missing", relaybind.ErrAlgorithm, a(pm(head(5, 1), tstr("address"), bstr(k)), unprot, plOK, sOK))
	add("address missing", relaybind.ErrAddress, a(pm(head(5, 1), kAlg, vAlg), unprot, plOK, sOK))
	add("empty protected map", relaybind.ErrAlgorithm, a(pm(head(5, 0)), unprot, plOK, sOK))
	add("address as text", relaybind.ErrAddress, a(pm(head(5, 2), kAlg, vAlg, tstr("address"), tstr("addr")), unprot, plOK, sOK))
	add("address as a 28-character text", relaybind.ErrAddress, a(pm(head(5, 2), kAlg, vAlg, tstr("address"), tstr("abcdefghijklmnopqrstuvwxyz01")), unprot, plOK, sOK))
	add("address of 27 bytes", relaybind.ErrAddress, a(pm(head(5, 2), kAlg, vAlg, tstr("address"), bstr(k[:27])), unprot, plOK, sOK))
	add("address of 0 bytes", relaybind.ErrAddress, a(pm(head(5, 2), kAlg, vAlg, tstr("address"), bstr(nil)), unprot, plOK, sOK))
	add("address of 65 bytes", relaybind.ErrAddress, a(pm(head(5, 2), kAlg, vAlg, tstr("address"), bstr(bs(65, 1))), unprot, plOK, sOK))
	add("address claiming 2^32 bytes", relaybind.ErrAddress, a(pm(head(5, 2), kAlg, vAlg, tstr("address"), []byte{0x5a, 0xff, 0xff, 0xff, 0xff}), unprot, plOK, sOK))
	add("protected header not a map", relaybind.ErrShape, a(bstr(head(4, 0)), unprot, plOK, sOK))
	add("protected header empty", relaybind.ErrShape, a(bstr(nil), unprot, plOK, sOK))
	add("trailing bytes in the protected header", relaybind.ErrTrailing, a(bstr(cat(prot, []byte{0})), unprot, plOK, sOK))
	add("protected header over 128 bytes", relaybind.ErrTooLarge, a(bstr(bs(129, 0)), unprot, plOK, sOK))

	// Unprotected header: exactly {"hashed": false}.
	for name, u := range map[string][]byte{
		"integer 0":           head(0, 0),
		"integer 1":           head(0, 1),
		"empty map":           head(5, 0),
		"hashed true":         cat(head(5, 1), tstr("hashed"), cTrue),
		"hashed 0":            cat(head(5, 1), tstr("hashed"), head(0, 0)),
		"hashed null":         cat(head(5, 1), tstr("hashed"), cNull),
		"upper-case Hashed":   cat(head(5, 1), tstr("Hashed"), cFalse),
		"another key":         cat(head(5, 1), tstr("hash"), cFalse),
		"integer key":         cat(head(5, 1), head(0, 1), cFalse),
		"extra pair":          cat(head(5, 2), tstr("hashed"), cFalse, tstr("x"), cFalse),
		"null":                cNull,
		"false":               cFalse,
		"byte string":         bstr([]byte("hashed")),
		"text":                tstr("hashed"),
		"array":               cat(head(4, 1), cFalse),
		"nested map in value": cat(head(5, 1), tstr("hashed"), head(5, 0)),
	} {
		add("unprotected "+name, relaybind.ErrUnprotected, a(pOK, u, plOK, sOK))
	}

	// Nesting in the unprotected header is bounded while it is skipped.
	add("unprotected nested six deep", relaybind.ErrShape, a(pOK, cat(head(4, 1), head(4, 1), head(4, 1), head(4, 1), head(4, 1), head(4, 1), head(0, 0)), plOK, sOK))

	// Payload and signature.
	add("payload detached", relaybind.ErrDetached, a(pOK, unprot, cNull, sOK))
	add("payload 121 bytes", relaybind.ErrPayloadSize, a(pOK, unprot, bstr(bs(121, 1)), sOK))
	add("payload claiming 2^32 bytes", relaybind.ErrPayloadSize, a(pOK, unprot, []byte{0x5a, 0xff, 0xff, 0xff, 0xff}, sOK))
	add("payload claiming 2^64-1 bytes", relaybind.ErrPayloadSize, a(pOK, unprot, []byte{0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, sOK))
	add("payload as text", relaybind.ErrShape, a(pOK, unprot, tstr("abc"), sOK))
	add("payload as integer", relaybind.ErrShape, a(pOK, unprot, head(0, 5), sOK))
	add("signature 63 bytes", relaybind.ErrSignatureSize, a(pOK, unprot, plOK, bstr(sig[:63])))
	add("signature 65 bytes", relaybind.ErrSignatureSize, a(pOK, unprot, plOK, bstr(append(bytes.Clone(sig), 0))))
	add("signature empty", relaybind.ErrSignatureSize, a(pOK, unprot, plOK, bstr(nil)))
	add("signature claiming 2^32 bytes", relaybind.ErrSignatureSize, a(pOK, unprot, plOK, []byte{0x5a, 0xff, 0xff, 0xff, 0xff}))
	add("signature as text", relaybind.ErrShape, a(pOK, unprot, plOK, tstr("abc")))

	// Shape, trailing bytes, sizes, UTF-8.
	add("array of 3", relaybind.ErrShape, cat(head(4, 3), pOK, unprot, plOK))
	add("array of 5", relaybind.ErrShape, cat(head(4, 5), pOK, unprot, plOK, sOK, head(0, 0)))
	add("map instead of an array", relaybind.ErrShape, cat(head(5, 0)))
	add("empty input", relaybind.ErrShape, nil)
	add("protected as text", relaybind.ErrShape, a(tstr("x"), unprot, plOK, sOK))
	add("trailing byte", relaybind.ErrTrailing, append(bytes.Clone(good), 0))
	add("two statements", relaybind.ErrTrailing, cat(good, good))
	add("513 bytes", relaybind.ErrTooLarge, append(bytes.Clone(good), make([]byte, 513-len(good))...))
	add("protected key not UTF-8", relaybind.ErrNotUTF8, a(pm(head(5, 2), kAlg, vAlg, head(3, 7), []byte{0xff, 'd', 'd', 'r', 'e', 's', 's'}, bstr(k)), unprot, plOK, sOK))
	add("unprotected key not UTF-8", relaybind.ErrNotUTF8, a(pOK, cat(head(5, 1), head(3, 6), []byte{0xff, 'a', 's', 'h', 'e', 'd'}, cFalse), plOK, sOK))
	return rs
}

// Each strictness rule of ADR 0014 decision 3 has a test that names it: the
// input is refused, as an encoding error, with that rule's reason.
//
// spec: SPO-Xrelaybind-PRE-002, SPO-Xrelaybind-PRE-003, SPO-Xrelaybind-PRE-004, SPO-Xrelaybind-PRE-005, SPO-Xrelaybind-PRE-006, SPO-Xrelaybind-PRE-007, SPO-Xrelaybind-PRE-008, SPO-Xrelaybind-PRE-009, SPO-Xrelaybind-PRE-010, SPO-Xrelaybind-PRE-011, SPO-Xrelaybind-PRE-012, SPO-Xrelaybind-PRE-013, SPO-Xrelaybind-PRE-014
func TestStrictParserRefusesEachRule(t *testing.T) {
	for _, r := range refusals(t) {
		_, err := relaybind.ParseStatement(r.input)
		if !errors.Is(err, relaybind.ErrBadEncoding) || !errors.Is(err, r.reason) {
			t.Errorf("%s: error %v, want ErrBadEncoding wrapping %v", r.name, err, r.reason)
		}
	}
}

// The lenient parser of domain/cose is not changed and still accepts several of
// these, which is why the relay has its own.
//
// spec: SPO-Xrelaybind-INV-003
func TestTheLenientParserStillAcceptsWhatTheStrictOneRefuses(t *testing.T) {
	payload := goodPayload(t)
	prot := protectedWith(testK[:])
	sig := signRaw([]byte("x"))
	pOK, plOK, sOK := bstr(prot), bstr(payload), bstr(sig)
	lenient := map[string][]byte{
		"non-shortest array head":  cat(wide(4, 4, 1), pOK, unprotOK, plOK, sOK),
		"bare integer unprotected": assemble(pOK, head(0, 0), plOK, sOK),
		"extra protected key": assemble(bstr(cat(head(5, 3), kAlg, vAlg, tstr("address"), bstr(testK[:]), tstr("kid"), head(0, 0))),
			unprotOK, plOK, sOK),
		"hashed in protected": assemble(bstr(cat(head(5, 3), kAlg, vAlg, tstr("address"), bstr(testK[:]), tstr("hashed"), cFalse)),
			unprotOK, plOK, sOK),
		"duplicate address": assemble(bstr(cat(head(5, 3), kAlg, vAlg, tstr("address"), bstr(testK[:]), tstr("address"), bstr(bs(28, 3)))),
			unprotOK, plOK, sOK),
	}
	for name, in := range lenient {
		if _, err := cose.ParseSign1(in); err != nil {
			t.Errorf("%s: the lenient parser refused it: %v (it must stay lenient)", name, err)
		}
		if _, err := relaybind.ParseStatement(in); err == nil {
			t.Errorf("%s: the strict parser accepted it", name)
		}
	}
}

// A size bound is checked before the parse and before any allocation: inputs
// that claim huge lengths cost almost nothing.
//
// spec: SPO-Xrelaybind-PRE-001, SPO-Xrelaybind-SEC-005
func TestStrictParserBoundsAreCheckedBeforeAllocation(t *testing.T) {
	good := goodSign1(t)
	hostile := [][]byte{
		cat(head(4, 4), []byte{0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}),
		cat(head(4, 4), bstr(protectedWith(testK[:])), []byte{0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}),
		cat(head(4, 4), bstr(protectedWith(testK[:])), unprotOK, []byte{0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}),
		cat(head(4, 4), bstr(protectedWith(testK[:])), unprotOK, bstr(goodPayload(t)), []byte{0x5a, 0xff, 0xff, 0xff, 0xff}),
		cat(head(4, 4), bstr(protectedWith(testK[:])), []byte{0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}),
		make([]byte, relaybind.MaxSign1Bytes+1),
		make([]byte, 1<<16),
	}
	n := allocated(func() {
		for i := 0; i < 100; i++ {
			for _, h := range hostile {
				if _, err := relaybind.ParseStatement(h); err == nil {
					t.Error("a hostile input was accepted")
				}
			}
		}
	})
	if limit := uint64(100 * len(hostile) * 1024); n > limit {
		t.Errorf("%d bytes allocated for %d hostile parses, want under %d", n, 100*len(hostile), limit)
	}
	// Exactly at the bound is read (and fails on content); one over is refused by size alone.
	atBound := append(bytes.Clone(good), make([]byte, relaybind.MaxSign1Bytes-len(good))...)
	if _, err := relaybind.ParseStatement(atBound); errors.Is(err, relaybind.ErrTooLarge) {
		t.Errorf("512 bytes refused as too large: %v", err)
	}
	if _, err := relaybind.ParseStatement(append(atBound, 0)); !errors.Is(err, relaybind.ErrTooLarge) {
		t.Errorf("513 bytes: %v", err)
	}
	// The payload bound: 120 bytes pass the parse, 121 do not.
	p120 := bytes.Repeat([]byte("a"), relaybind.MaxPayloadBytes)
	if _, err := relaybind.ParseStatement(signed(testK[:], p120)); err != nil {
		t.Errorf("120-byte payload: %v", err)
	}
	if _, err := relaybind.ParseStatement(signed(testK[:], append(p120, 'a'))); !errors.Is(err, relaybind.ErrPayloadSize) {
		t.Errorf("121-byte payload: %v", err)
	}
	// A payload line over its bound is refused before it is split.
	big := bytes.Repeat([]byte("a "), 1<<19)
	if n := allocated(func() {
		relaybind.ParseBinding(big)
		relaybind.ParseRevoke(big)
	}); n > 2048 {
		t.Errorf("a 1 MiB payload line allocated %d bytes", n)
	}
	// The COSE_Key bound.
	if _, err := relaybind.ParseCOSEKey(make([]byte, 1<<20)); err == nil {
		t.Error("a megabyte COSE_Key was accepted")
	}
	// 129 bytes of what the decoder would build items for (a map of 64 pairs of
	// small integers, the last cut short) are refused by length first.
	many := head(5, 64)
	for i := 0; i < 63; i++ {
		many = append(many, 0x01, 0x01)
	}
	many = append(many, 0x01) // 129 bytes; the 64th pair is cut short
	var kerr error
	kn := allocated(func() { _, kerr = relaybind.ParseCOSEKey(many) })
	if len(many) != relaybind.MaxKeyBytes+1 || !errors.Is(kerr, relaybind.ErrTooLarge) || kn > 1024 {
		t.Errorf("%d-byte COSE_Key: %v, %d bytes allocated", len(many), kerr, kn)
	}
}

// spec: SPO-Xrelaybind-OUT-007, SPO-Xrelaybind-PRE-001
func TestParseCOSEKeyIsStrict(t *testing.T) {
	good := cose.EncodeKey(testPub[:])
	if _, err := relaybind.ParseCOSEKey(good); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"empty":            nil,
		"trailing byte":    append(bytes.Clone(good), 0),
		"truncated":        good[:len(good)-1],
		"129 bytes":        append(bytes.Clone(good), make([]byte, relaybind.MaxKeyBytes+1-len(good))...),
		"extra pair":       append(append([]byte{good[0] + 1}, good[1:]...), 0x04, 0x00),
		"keys reordered":   cat(head(5, 4), head(0, 3), head(1, 7), head(0, 1), head(0, 1), head(1, 0), head(0, 6), head(1, 1), bstr(testPub[:])),
		"non-shortest map": cat(wide(5, 4, 1), good[1:]),
		"key of 31 bytes":  cat(good[:len(good)-34], bstr(testPub[:31])),
		"wrong curve":      bytes.Replace(good, []byte{0x20, 0x06}, []byte{0x20, 0x07}, 1),
		"wrong algorithm":  bytes.Replace(good, []byte{0x03, 0x27}, []byte{0x03, 0x26}, 1),
	}
	for name, in := range cases {
		if _, err := relaybind.ParseCOSEKey(in); err == nil {
			t.Errorf("%s: accepted %x", name, in)
		}
	}
}
