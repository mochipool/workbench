package keyfile

import (
	"errors"
	"strings"
	"testing"
)

const cbor = "5820f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f80"

func plain(desc string) []byte {
	return AppendPlainEnvelope(nil, "PaymentSigningKeyShelley_ed25519", desc, []byte(cbor), len(cbor), "    ")
}

func encrypted(encr string) []byte {
	return EncryptedEnvelope("PaymentSigningKeyShelley_ed25519", "Payment Signing Key", []byte(encr))
}

var goodEncr = strings.Repeat("8c", 40)

// spec: SPO-Pfiles-OUT-003, SPO-Pfiles-OUT-004, SPO-Ckey-IN-001, SPO-Ckey-OUT-003, SPO-01protectKey-IN-001
func TestClassifyForms(t *testing.T) {
	hw := []byte(`{"type": "PaymentHWSigningFileShelley_ed25519", "description": "Payment Hardware Signing File", "path": ["1852H","1815H","0H","0","0"], "cborXPubKeyHex": "5840aa"}`)
	cases := []struct {
		name string
		in   []byte
		form Form
		err  error
	}{
		{"plain", plain("Payment Signing Key"), FormPlain, nil},
		{"plain whose description says Encrypted", plain("Encrypted note"), FormPlain, nil}, // upstream would loop on prompts
		{"encrypted", encrypted(goodEncr), FormEncrypted, nil},
		{"hardware", hw, FormHardware, nil},
		{"not json", []byte("5820abcd"), FormMalformed, ErrMalformed},
		{"empty", nil, FormMalformed, ErrMalformed},
		{"trailing garbage", append(plain("x"), []byte("garbage")...), FormMalformed, ErrMalformed},
		{"verification key", []byte(`{"type":"PaymentVerificationKeyShelley_ed25519","description":"","cborHex":"5820aa"}`), FormMalformed, ErrMalformed},
		{"non-hex cborHex", []byte(`{"type":"PaymentSigningKeyShelley_ed25519","description":"","cborHex":"58zz"}`), FormMalformed, ErrMalformed},
		{"encrypted without hex", []byte(`{"type":"PaymentSigningKeyShelley_ed25519","description":"Encrypted x","encrHex":"nothex"}`), FormMalformed, ErrMalformedEncrypted},
		{"encrypted too short", encrypted("8c0d04"), FormMalformed, ErrMalformedEncrypted},
		{"encrypted empty", encrypted(""), FormMalformed, ErrMalformedEncrypted},
		{"encrypted without the prefix", []byte(`{"type":"PaymentSigningKeyShelley_ed25519","description":"Payment","encrHex":"` + goodEncr + `"}`), FormMalformed, ErrMalformedEncrypted},
		{"encrypted and plain at once", []byte(`{"type":"PaymentSigningKeyShelley_ed25519","description":"Encrypted x","encrHex":"` + goodEncr + `","cborHex":"5820aa"}`), FormMalformed, ErrMalformedEncrypted},
		{"encrypted, truncated json", encrypted(goodEncr)[:len(encrypted(goodEncr))-6], FormMalformed, ErrMalformedEncrypted},
	}
	for _, c := range cases {
		info, err := Classify(c.in)
		if info.Form != c.form || !errors.Is(err, c.err) && !(c.err == nil && err == nil) {
			t.Errorf("%s: got %v / %v, want %v / %v", c.name, info.Form, err, c.form, c.err)
		}
	}
	// a truncated encrypted file is reported as damaged encrypted data (H8)
	if _, err := Classify(encrypted(goodEncr)[:len(encrypted(goodEncr))-6]); !errors.Is(err, ErrMalformedEncrypted) {
		t.Errorf("a truncated encrypted file must be ErrMalformedEncrypted, got %v", err)
	}
}

// spec: SPO-Ckey-PRE-003, SPO-Ckey-PRE-006, SPO-Ckey-PRE-010
func TestParseEncryptedFailsFast(t *testing.T) {
	good, err := ParseEncrypted(encrypted(goodEncr))
	if err != nil || good.Type != "PaymentSigningKeyShelley_ed25519" || good.Description != "Encrypted Payment Signing Key" || string(good.EncrHex) != goodEncr {
		t.Fatalf("good envelope: %+v %v", good, err)
	}
	for name, in := range map[string]string{
		"missing type":        `{"description":"Encrypted x","encrHex":"` + goodEncr + `"}`,
		"missing description": `{"type":"PaymentSigningKeyShelley_ed25519","encrHex":"` + goodEncr + `"}`,
		"missing encrHex":     `{"type":"PaymentSigningKeyShelley_ed25519","description":"Encrypted x"}`,
		"type is not a key":   `{"type":"Payment","description":"Encrypted x","encrHex":"` + goodEncr + `"}`,
		"encrHex null":        `{"type":"PaymentSigningKeyShelley_ed25519","description":"Encrypted x","encrHex":null}`,
		"odd length hex":      `{"type":"PaymentSigningKeyShelley_ed25519","description":"Encrypted x","encrHex":"` + goodEncr + `a"}`,
		"array":               `[]`,
		"garbage":             `not json`,
	} {
		if _, err := ParseEncrypted([]byte(in)); !errors.Is(err, ErrMalformedEncrypted) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

// spec: SPO-Ckey-OUT-001, SPO-Ckey-OUT-002, SPO-01protectKey-OUT-001
func TestEnvelopeFormats(t *testing.T) {
	got := string(encrypted(goodEncr))
	want := "{\n  \"type\": \"PaymentSigningKeyShelley_ed25519\",\n  \"description\": \"Encrypted Payment Signing Key\",\n  \"encrHex\": \"" + goodEncr + "\"\n}\n"
	if got != want {
		t.Errorf("encrypted envelope:\n%s\nwant\n%s", got, want)
	}
	if d := PlainDescription("Encrypted Payment Signing Key"); d != "Payment Signing Key" {
		t.Errorf("plain description %q", d)
	}
	// every occurrence is removed, as upstream's decrypt does
	if d := PlainDescription("Encrypted a Encrypted b"); d != "a b" {
		t.Errorf("plain description %q", d)
	}
	p := string(AppendPlainEnvelope(nil, "T", "D <&>", []byte("5820aa"), 6, "  "))
	if p != "{\n  \"type\": \"T\",\n  \"description\": \"D <&>\",\n  \"cborHex\": \"5820aa\"\n}\n" {
		t.Errorf("plain envelope %q", p)
	}
	if PlainEnvelopeLen("T", "D <&>", 6, "  ") != len(p) {
		t.Error("PlainEnvelopeLen differs from the envelope")
	}
	pl, n, err := ParsePlain(plain("Payment Signing Key"))
	if err != nil || pl.Type != "PaymentSigningKeyShelley_ed25519" || n != len(cbor) {
		t.Errorf("ParsePlain: %+v %d %v", pl, n, err)
	}
	span, err := CborHexSpan(plain("x"))
	if err != nil || string(span) != cbor {
		t.Errorf("CborHexSpan: %q %v", span, err)
	}
}

// spec: SPO-Ckey-INV-001, SPO-Ckey-IF-001
func TestStrongPassword(t *testing.T) {
	for pw, want := range map[string]bool{
		"Abcdefgh1!":         true,
		"Abcdefgh1 ":         true,  // a space is special
		"Abcdefg1é":          false, // nine characters: é is one special character, but length 9
		"Abcdefgh1é":         true,  // non-ASCII counts as special
		"abcdefgh1!":         false, // no upper case
		"ABCDEFGH1!":         false, // no lower case
		"Abcdefghi!":         false, // no digit
		"Abcdefghi1":         false, // no special
		"Abcdef1!":           false, // too short
		"":                   false,
		`AbC\def-12345`:      true,
		"Trailing space 1A ": true,
	} {
		if got := IsStrongPassword([]byte(pw)); got != want {
			t.Errorf("%q: got %v, want %v", pw, got, want)
		}
	}
}

// spec: SPO-Cui-IF-003, SPO-Cui-SEC-001
func TestUpstreamReadMangling(t *testing.T) {
	for typed, want := range map[string]string{
		`ab\cd`:          "abcd",   // a backslash is consumed as an escape
		`ab\\cd`:         `ab\cd`,  // an escaped backslash survives
		`abc\`:           "abc",    // a trailing backslash is dropped
		"abc\\\ndef":     "abcdef", // backslash-newline joins the lines
		"plain-Passw0rd": "plain-Passw0rd",
		"trailing ":      "trailing ", // IFS is empty: no trimming
		"  leading":      "  leading",
		`\a\b\c`:         "abc",
		"":               "",
	} {
		if got := string(UpstreamRead([]byte(typed))); got != want {
			t.Errorf("%q: got %q, want %q", typed, got, want)
		}
	}
}

// spec: SPO-Cui-IF-003, SPO-Ckey-EXT-002
func TestPasswordCandidates(t *testing.T) {
	c := PasswordCandidates([]byte(`ab\cd`))
	if len(c) != 2 || string(c[0]) != `ab\cd` || string(c[1]) != "abcd" {
		t.Errorf("candidates for a backslash password: %q", c)
	}
	c = PasswordCandidates([]byte("Plain-Passw0rd"))
	if len(c) != 1 || string(c[0]) != "Plain-Passw0rd" {
		t.Errorf("a password without a backslash has one candidate: %q", c)
	}
	in := []byte(`x\y`)
	c = PasswordCandidates(in)
	c[0][0] = '!'
	if in[0] != 'x' {
		t.Error("a candidate aliases the typed password")
	}
}
