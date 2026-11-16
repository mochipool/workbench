package native

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// spec: SPO-Pparam-EXT-001, SPO-Pparam-IF-012, SPO-Pparam-SEC-001
func TestCIP83RoundTripAndFormat(t *testing.T) {
	lines := []string{"hello", `a "quoted" \ line <x>`, "wörld", strings.Repeat("é", 32)}
	got, err := CIP83{Rand: bytes.NewReader([]byte("12345678"))}.EncryptMessages(lines, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range got {
		if len(l) > 64 || strings.ContainsAny(l, " \n") {
			t.Errorf("a message line of %d characters: %q", len(l), l)
		}
	}
	if !strings.HasPrefix(got[0], "U2FsdGVkX1") { // base64 of "Salted__"
		t.Errorf("the openssl salted header is missing: %q", got[0])
	}
	back, err := DecryptMessages(got, nil)
	if err != nil || strings.Join(back, "\x00") != strings.Join(lines, "\x00") {
		t.Errorf("%q %v", back, err)
	}
	pass := secret.Take([]byte("  spaced  "))
	defer pass.Destroy()
	enc, err := CIP83{}.EncryptMessages(lines, pass)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptMessages(enc, nil); !errors.Is(err, ErrDecrypt) {
		t.Errorf("the default passphrase read a message made with another: %v", err)
	}
	if back, err := DecryptMessages(enc, pass); err != nil || len(back) != len(lines) {
		t.Errorf("%q %v", back, err)
	}
	// the plaintext is jq's compact form, with DEL escaped and no HTML escaping
	if got := string(jqCompact([]string{"<a&b>\x7f é\t"})); got != "[\"<a&b>\\u007f é\\t\"]" {
		t.Errorf("%q", got)
	}
	for _, bad := range [][]string{nil, {"!!!"}, {"U2FsdGVkX1" + strings.Repeat("A", 40)}} {
		if _, err := DecryptMessages(bad, nil); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// spec: SPO-Pparam-IF-016, SPO-Pparam-OUT-001
func TestAuxDataComposition(t *testing.T) {
	f := func(name, js string) txbuild.MetadataFile {
		return txbuild.MetadataFile{Name: name, Format: txbuild.MetadataJSON, Data: []byte(js)}
	}
	aux, err := composeAuxData([]txbuild.MetadataFile{f("b.json", `{"721":{"a":1}}`), f("a.json", `{"5":"x"}`)}, []string{"hi"}, "")
	if err != nil {
		t.Fatal(err)
	}
	// tag 259, {0: {5: "x", 674: {"msg": ["hi"]}, 721: {"a": 1}}}
	if want := "d90103a100a3056178" + "1902a2a1636d73678162" + "6869" + "1902d1a1616101"; hex.EncodeToString(aux) != want {
		t.Errorf("%x\nwant %s", aux, want)
	}
	if a, err := composeAuxData(nil, nil, ""); a != nil || err != nil {
		t.Errorf("no metadata: %x %v", a, err)
	}
	if _, err := composeAuxData([]txbuild.MetadataFile{f("a.json", `{"674":1}`)}, []string{"x"}, ""); !errors.Is(err, ErrDuplicateLabel) {
		t.Errorf("the message label twice: %v", err)
	}
	if _, err := composeAuxData([]txbuild.MetadataFile{{Name: "x", Format: "yaml"}}, nil, ""); !errors.Is(err, ErrMetadata) {
		t.Errorf("an unknown format: %v", err)
	}
	enc, err := composeAuxData(nil, []string{"x"}, "basic")
	if err != nil || !bytes.Contains(enc, []byte("\x63enc\x65basic")) {
		t.Errorf("%x %v", enc, err)
	}
	if _, err := composeAuxData(nil, []string{strings.Repeat("a", 65)}, ""); !errors.Is(err, ErrMetadata) {
		t.Errorf("a line over 64 bytes: %v", err)
	}
}

// spec: SPO-10-EXT-004, SPO-11a-EXT-001
func TestNativeScripts(t *testing.T) {
	h := strings.Repeat("ab", 28)
	led := Ledger{}
	id1, err := led.PolicyID([]byte(`{"type":"sig","keyHash":"` + h + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	// a script's id does not depend on how its JSON is written
	id2, _ := led.PolicyID([]byte(`{ "keyHash": "` + h + `", "type": "sig" }` + "\n"))
	if id1 != id2 {
		t.Error("whitespace and key order changed the id")
	}
	for _, bad := range []string{``, `[]`, `{"type":"sig"}`, `{"type":"sig","keyHash":"zz"}`, `{"type":"nope"}`, `{"type":"all"}`, `{"type":"before","slot":"x"}`, `{"type":"before","slot":-1}`, `{"type":"atLeast","scripts":[]}`} {
		if _, err := led.PolicyID([]byte(bad)); !errors.Is(err, ErrScript) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	// the witness set orders scripts by hash, and a script given twice is one script
	a, b := []byte(`{"type":"sig","keyHash":"`+h+`"}`), []byte(`{"type":"before","slot":5}`)
	s1, err := mintScriptSet([][]byte{a, b, a})
	if err != nil {
		t.Fatal(err)
	}
	s2, _ := mintScriptSet([][]byte{b, a})
	if !bytes.Equal(s1, s2) || s1[0] != 0xd9 || s1[3] != 0x82 {
		t.Errorf("%x %x", s1, s2)
	}
}

// spec: SPO-11a-EXT-001, SPO-11b-EXT-001
func TestMintFieldEncoding(t *testing.T) {
	id := func(p byte, n string) chain.AssetID { return chain.AssetID{Policy: [28]byte{p}, Name: []byte(n)} }
	b, err := encodeMint([]txbuild.MintEntry{{Asset: id(2, "b"), Quantity: -5}, {Asset: id(1, "z"), Quantity: 1 << 40}, {Asset: id(1, ""), Quantity: 3}, {Asset: id(2, "b"), Quantity: -1}})
	if err != nil {
		t.Fatal(err)
	}
	// {p1: {"": 3, "z": 2^40}, p2: {"b": -6}}
	if !bytes.HasPrefix(b, []byte{0xa2, 0x58, 0x1c, 1}) || !bytes.Contains(b, []byte{0x40, 0x03, 0x41, 'z', 0x1b, 0, 0, 1, 0, 0, 0, 0, 0}) || !bytes.HasSuffix(b, []byte{0x41, 'b', 0x25}) {
		t.Errorf("%x", b)
	}
	if _, err := encodeMint([]txbuild.MintEntry{{Asset: id(1, "a"), Quantity: 5}, {Asset: id(1, "a"), Quantity: -5}}); err == nil {
		t.Error("a mint that adds up to zero")
	}
}
