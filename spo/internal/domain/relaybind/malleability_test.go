package relaybind_test

import (
	"bytes"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
)

// For a valid statement, no single bit flip, byte deletion, byte insertion or
// truncation verifies.
//
// spec: SPO-Xrelaybind-SEC-002
func TestNothingMutatedVerifies(t *testing.T) {
	good := goodSign1(t)
	if err := verifiesAsBinding(good); err != nil {
		t.Fatalf("the unmutated statement does not verify: %v", err)
	}
	for i := 0; i < len(good)*8; i++ {
		m := bytes.Clone(good)
		m[i/8] ^= 1 << (i % 8)
		if err := verifiesAsBinding(m); err == nil {
			t.Fatalf("bit %d flipped and the statement still verifies: %x", i, m)
		}
	}
	for i := range good {
		del := append(bytes.Clone(good[:i]), good[i+1:]...)
		if err := verifiesAsBinding(del); err == nil {
			t.Fatalf("byte %d deleted and the statement still verifies", i)
		}
		for _, c := range []byte{0x00, 0x20, 0xf4, 0xff} {
			ins := append(append(bytes.Clone(good[:i]), c), good[i:]...)
			if err := verifiesAsBinding(ins); err == nil {
				t.Fatalf("byte %#x inserted at %d and the statement still verifies", c, i)
			}
		}
		if err := verifiesAsBinding(good[:i]); err == nil {
			t.Fatalf("truncated to %d bytes and the statement still verifies", i)
		}
	}
}

// The structured mutations of the brief, each applied to a valid statement:
// every one is refused (the unprotected header is the only unsigned part, and
// the ADR refuses every variant of it).
//
// spec: SPO-Xrelaybind-SEC-002, SPO-Xrelaybind-PRE-002, SPO-Xrelaybind-PRE-005, SPO-Xrelaybind-PRE-006, SPO-Xrelaybind-PRE-007, SPO-Xrelaybind-PRE-008, SPO-Xrelaybind-PRE-011
func TestStructuredMutationsAreRefused(t *testing.T) {
	payload := goodPayload(t)
	prot := protectedWith(testK[:])
	sigStruct := func(p, pl []byte) []byte { return signRaw(cose.SigStructure(p, pl)) }
	sig := sigStruct(prot, payload)
	pOK, plOK, sOK := bstr(prot), bstr(payload), bstr(sig)
	k := testK[:]

	// Mutations that keep the signature valid, so only the encoding rules
	// stand between them and acceptance.
	reorderedProt := cat(head(5, 2), tstr("address"), bstr(k), kAlg, vAlg) // other key order: signed as it is
	dupProt := cat(head(5, 3), kAlg, vAlg, tstr("address"), bstr(k), tstr("address"), bstr(k))
	hashedProt := cat(head(5, 3), kAlg, vAlg, tstr("address"), bstr(k), tstr("hashed"), cFalse)
	extraProt := cat(head(5, 3), kAlg, vAlg, tstr("address"), bstr(k), tstr("kid"), head(0, 0))
	sameKeyProt := cat(head(5, 2), kAlg, vAlg, tstr("address"), bstr(k))
	withProt := func(p []byte) []byte { // properly signed over the mutated protected header
		return assemble(bstr(p), unprotOK, plOK, bstr(sigStruct(p, payload)))
	}
	cases := map[string][]byte{
		"non-shortest array head":           cat(wide(4, 4, 1), pOK, unprotOK, plOK, sOK),
		"non-shortest protected length":     assemble(cat(wide(2, uint64(len(prot)), 2), prot), unprotOK, plOK, sOK),
		"non-shortest payload length":       assemble(pOK, unprotOK, cat(wide(2, uint64(len(payload)), 2), payload), sOK),
		"non-shortest signature length":     assemble(pOK, unprotOK, plOK, cat(wide(2, 64, 2), sig)),
		"duplicated unprotected key":        assemble(pOK, cat(head(5, 2), tstr("hashed"), cFalse, tstr("hashed"), cFalse), plOK, sOK),
		"duplicated protected key":          withProt(dupProt),
		"hashed moved to the protected":     withProt(hashedProt),
		"hashed in both":                    assemble(bstr(hashedProt), unprotOK, plOK, bstr(sigStruct(hashedProt, payload))),
		"extra protected key":               withProt(extraProt),
		"integer unprotected 0":             assemble(pOK, head(0, 0), plOK, sOK),
		"integer unprotected 1":             assemble(pOK, head(0, 1), plOK, sOK),
		"hashed true":                       assemble(pOK, cat(head(5, 1), tstr("hashed"), cTrue), plOK, sOK),
		"empty unprotected":                 assemble(pOK, head(5, 0), plOK, sOK),
		"tag 18 added":                      cat([]byte{0xd2}, goodSign1(t)),
		"trailing byte":                     append(goodSign1(t), 0),
		"payload upper-cased":               signed(k, bytes.ToUpper(payload)),
		"payload with an extra space":       signed(k, bytes.Replace(payload, []byte(" from"), []byte("  from"), 1)),
		"payload with a leading zero":       signed(k, bytes.Replace(payload, []byte(" from 1"), []byte(" from 01"), 1)),
		"payload with a trailing line feed": signed(k, append(bytes.Clone(payload), '\n')),
		"payload for another device":        signed(k, []byte(bindingText(fpOf(0x77), "1799999940", "1807775940"))),
	}
	for name, in := range cases {
		if err := verifiesAsBinding(in); err == nil {
			t.Errorf("%s: verifies", name)
		}
	}
	// Documented acceptance, not a mutation: the other key order is the signer's own
	// choice and is signed, so it is accepted and has its own hash.
	other := withProt(reorderedProt)
	if err := verifiesAsBinding(other); err != nil {
		t.Errorf("the protected header with the keys the other way round: %v", err)
	} else if mustStatement(t, other).FullHash() == mustStatement(t, goodSign1(t)).FullHash() {
		t.Error("different protected bytes gave the same hash")
	}
	if !bytes.Equal(withProt(sameKeyProt), goodSign1(t)) {
		t.Error("the helper does not rebuild the good statement")
	}
}

// Canonical() is the relay's own encoding; Hash() is Blake2b-256 of it. For
// every accepted input the canonical bytes equal the input (the strict parser
// admits one encoding), and different statements have different hashes.
//
// spec: SPO-Xrelaybind-OUT-006, SPO-Xrelaybind-SEC-003
func TestCanonicalAndHash(t *testing.T) {
	good := goodSign1(t)
	st := mustStatement(t, good)
	sg := st.Signature()
	hand := cat(head(4, 4), bstr(protectedWith(testK[:])), unprotOK, bstr(goodPayload(t)), bstr(sg[:]))
	mustEqualBytes(t, "Canonical against a hand encoding", st.Canonical(), hand)
	mustEqualBytes(t, "Canonical against the input", st.Canonical(), good)
	if got, want := st.FullHash(), cose.Blake2b256(st.Canonical()); got != want {
		t.Errorf("Hash %x, Blake2b-256 of Canonical %x", got, want)
	}
	// The unprotected header of the canonical form is exactly {"hashed": false}.
	if !bytes.Contains(st.Canonical(), unprotOK) {
		t.Error("Canonical does not carry the one allowed unprotected header")
	}
	// Re-parsing the canonical bytes gives the same statement and the same hash.
	again := mustStatement(t, st.Canonical())
	if again.FullHash() != st.FullHash() || !bytes.Equal(again.Canonical(), st.Canonical()) {
		t.Error("Canonical is not a fixed point of parse and re-encode")
	}
	// Different statements, different hashes: every part that is signed or
	// signature changes the hash.
	seen := map[[32]byte]string{st.FullHash(): "good"}
	add := func(name string, b []byte) {
		h := mustStatement(t, b).FullHash()
		if prev, dup := seen[h]; dup {
			t.Errorf("%s has the same hash as %s", name, prev)
		}
		seen[h] = name
	}
	add("other payload", signed(testK[:], []byte(bindingText(testDev, "1799999941", "1807775940"))))
	add("other device", signed(testK[:], []byte(bindingText(fpOf(1), "1799999940", "1807775940"))))
	base := append([]byte{0x01}, testK[:]...)
	base = append(base, bs(28, 0x40)...)
	add("raw address form", signed(base, goodPayload(t)))
	add("other signer", signedWith(otherPriv, protectedWith(testK[:]), goodPayload(t)))
	flipSig := bytes.Clone(good)
	flipSig[len(flipSig)-1] ^= 1
	add("one signature bit", flipSig)
	// The hash depends on nothing outside the statement: parsing twice gives the same.
	if mustStatement(t, good).FullHash() != st.FullHash() {
		t.Error("Hash is not deterministic")
	}
	// Every accepted input is its own canonical form.
	for _, in := range [][]byte{good, signed(base, goodPayload(t)), signedWith(otherPriv, protectedWith(testK[:]), goodPayload(t))} {
		if s, err := relaybind.ParseStatement(in); err != nil || !bytes.Equal(s.Canonical(), in) {
			t.Errorf("an accepted input is not its own canonical form: %v", err)
		}
	}
}

// The accessors return copies: changing them cannot change the statement.
//
// spec: SPO-Xrelaybind-OUT-006
func TestStatementIsImmutable(t *testing.T) {
	in := goodSign1(t)
	st := mustStatement(t, in)
	want := st.FullHash()
	// The caller's buffer: protected header, payload and signature regions.
	for _, i := range []int{3, 40, len(in) - 70, len(in) - 1} {
		in[i] ^= 0xff
	}
	st.Payload()[0] ^= 0xff
	st.Protected()[0] ^= 0xff
	st.Address()[0] ^= 0xff
	st.Canonical()[0] ^= 0xff
	if st.FullHash() != want {
		t.Error("the statement changed through its accessors or its input buffer")
	}
	if !bytes.Equal(st.Address(), testK[:]) || !bytes.Equal(st.Payload(), goodPayload(t)) ||
		!bytes.Equal(st.Protected(), protectedWith(testK[:])) {
		t.Error("an accessor returned a view of the statement's own bytes")
	}
}
