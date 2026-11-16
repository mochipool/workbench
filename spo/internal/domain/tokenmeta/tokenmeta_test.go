package tokenmeta

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// spec: SPO-12b-INV-001, SPO-12a-SEC-001, SPO-12a-SEC-002
// The attestations of real entries of the public registry verify with the
// public keys they carry. This is the oracle of the construction.
func TestRealEntriesVerify(t *testing.T) {
	for _, name := range []string{"hosky_mapping.json", "policy_v1_unlimited_mapping.json", "policy_v2_timelocked_mapping.json"} {
		t.Run(name, func(t *testing.T) {
			e, err := ParseEntry(readFixture(t, name))
			if err != nil {
				t.Fatal(err)
			}
			v := e.Verify()
			if !v.OK {
				t.Fatalf("not verified: %+v", v)
			}
			for _, p := range v.Properties {
				if p.Valid != 1 || p.Invalid != 0 {
					t.Errorf("%s: %+v", p.Property, p)
				}
			}
			if e.Policy != "" && (!v.PolicyChecked || !v.PolicyIDMatches) {
				t.Errorf("policy not checked against the subject: %+v", v)
			}
		})
	}
}

// spec: SPO-12b-INV-001
func TestTamperedEntryFails(t *testing.T) {
	e, err := ParseEntry(readFixture(t, "policy_v2_timelocked_mapping.json"))
	if err != nil {
		t.Fatal(err)
	}
	a := e.Props[PropName]
	a.Value = Text(a.Value.Text() + "x")
	e.Props[PropName] = a
	v := e.Verify()
	if v.OK {
		t.Fatal("a changed name verified")
	}
	a = e.Props[PropName]
	a.Value = Text(strings.TrimSuffix(a.Value.Text(), "x"))
	a.Sequence++
	e.Props[PropName] = a
	if e.Verify().OK {
		t.Fatal("a changed sequence number verified")
	}
}

// spec: SPO-12a-OUT-004
// The file the registry takes is rendered as its own files are: parsing and
// rendering a real entry gives the same bytes.
func TestJSONMatchesRegistryFiles(t *testing.T) {
	for _, name := range []string{"hosky_mapping.json", "policy_v2_timelocked_mapping.json", "policy_v1_unlimited_mapping.json"} {
		b := readFixture(t, name)
		e, err := ParseEntry(b)
		if err != nil {
			t.Fatal(err)
		}
		got := e.JSON()
		if !bytes.Equal(bytes.TrimRight(got, "\n"), bytes.TrimRight(b, "\n")) {
			t.Errorf("%s: rendered file differs from the registry's", name)
		}
	}
}

// The `policy` property rebuilt from its script is the registry's: the
// encoder, the tag rule and the id agree with real entries.
func TestPolicyValueMatchesRegistry(t *testing.T) {
	cases := []struct{ fixture, script string }{
		{"policy_v1_unlimited_mapping.json", `{"type":"all","scripts":[{"type":"sig","keyHash":"cfd863012153a158e298ee31fb75160455af6e61914702b9a0ab0426"}]}`},
		{"policy_v2_timelocked_mapping.json", `{"type":"all","scripts":[{"type":"before","slot":%d},{"type":"sig","keyHash":"39a1df51147b6de6689a4727846962fb6540c3a3c7859a1a79b9420f"}]}`},
	}
	for _, c := range cases {
		e, err := ParseEntry(readFixture(t, c.fixture))
		if err != nil {
			t.Fatal(err)
		}
		script := c.script
		if strings.Contains(script, "%d") {
			script = fmt.Sprintf(script, 0x05987c3a)
		}
		val, id, err := PolicyValue([]byte(script))
		if err != nil {
			t.Fatal(err)
		}
		if val != e.Policy {
			t.Errorf("%s: policy value\n got %s\nwant %s", c.fixture, val, e.Policy)
		}
		if hex.EncodeToString(id[:]) != e.Subject[:56] {
			t.Errorf("%s: id %x is not the subject's", c.fixture, id)
		}
	}
}

func testSigner(seed byte) (SignFunc, ed25519.PublicKey) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	return func(_ context.Context, msgs [][32]byte) ([]Attestation, error) {
		var out []Attestation
		for _, m := range msgs {
			var a Attestation
			copy(a.PublicKey[:], priv.Public().(ed25519.PublicKey))
			copy(a.Signature[:], ed25519.Sign(priv, m[:]))
			out = append(out, a)
		}
		return out, nil
	}, priv.Public().(ed25519.PublicKey)
}

func policyFor(pub ed25519.PublicKey, expiry uint64) (script []byte, subject string) {
	kh := blake224(pub)
	if expiry == 0 {
		script = []byte(fmt.Sprintf(`{"type":"sig","keyHash":"%x"}`, kh))
	} else {
		script = []byte(fmt.Sprintf(`{"type":"all","scripts":[{"type":"before","slot":%d},{"type":"sig","keyHash":"%x"}]}`, expiry, kh))
	}
	c, _, _ := ScriptCBOR(script)
	id := PolicyID(c)
	return script, hex.EncodeToString(id[:]) + hex.EncodeToString([]byte("TOKEN"))
}

var pngBytes = append([]byte(pngMagic), bytes.Repeat([]byte{1}, 40)...)

// spec: SPO-12a-EXT-001, SPO-12a-EXT-002, SPO-12a-EXT-003, SPO-12a-EXT-004
// Build signs every property at the new sequence number, the entry verifies
// as the registry would verify it, and survives the file round trip.
func TestBuildSignsAndVerifies(t *testing.T) {
	sign, pub := testSigner(7)
	script, subject := policyFor(pub, 5000)
	f := Fields{Name: "Token", Description: "A token", Ticker: "TKN", URL: "https://example.org", Decimals: "6", Logo: pngBytes}
	e, err := Build(context.Background(), subject, script, f, 3, sign)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Props) != 6 {
		t.Fatalf("properties: %d", len(e.Props))
	}
	for p, a := range e.Props {
		if a.Sequence != 3 || len(a.Signatures) != 1 {
			t.Errorf("%s: %+v", p, a)
		}
	}
	if !e.Verify().OK {
		t.Fatalf("built entry does not verify: %+v", e.Verify())
	}
	back, err := ParseEntry(e.JSON())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back.JSON(), e.JSON()) || !back.Verify().OK {
		t.Fatal("the rendered file does not read back to the same entry")
	}
	if !strings.HasPrefix(e.Policy, "8201") {
		t.Errorf("a time-locked policy has tag 1: %s", e.Policy)
	}
	// An unlimited policy has tag 0 and optional properties may be absent.
	script0, subject0 := policyFor(pub, 0)
	e0, err := Build(context.Background(), subject0, script0, Fields{Name: "T", Description: "d"}, 1, sign)
	if err != nil || len(e0.Props) != 2 || !strings.HasPrefix(e0.Policy, "8200") || !e0.Verify().OK {
		t.Fatalf("minimal entry: %v %+v", err, e0.Props)
	}
}

// spec: SPO-12a-EXT-003
func TestBuildRefusesWrongSigner(t *testing.T) {
	sign, pub := testSigner(7)
	script, subject := policyFor(pub, 0)
	f := Fields{Name: "T", Description: "d"}
	liar := func(ctx context.Context, m [][32]byte) ([]Attestation, error) {
		a, err := sign(ctx, m)
		a[0].Signature[0] ^= 1
		return a, err
	}
	if _, err := Build(context.Background(), subject, script, f, 1, liar); err == nil {
		t.Error("a bad signature went into the entry")
	}
	short := func(ctx context.Context, m [][32]byte) ([]Attestation, error) { return nil, nil }
	if _, err := Build(context.Background(), subject, script, f, 1, short); err == nil {
		t.Error("a missing attestation went into the entry")
	}
	// The script must be the subject's policy.
	_, other := policyFor(ed25519.PublicKey(bytes.Repeat([]byte{9}, 32)), 0)
	if _, err := Build(context.Background(), other, script, f, 1, sign); err == nil {
		t.Error("a script that does not hash to the policy id was signed")
	}
}

// A policy that the signing keys do not satisfy is not OK (CIP-26).
func TestVerifyPolicyNotSatisfied(t *testing.T) {
	sign, pub := testSigner(7)
	script, subject := policyFor(pub, 0)
	e, err := Build(context.Background(), subject, script, Fields{Name: "T", Description: "d"}, 1, sign)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := testSigner(8)
	msgs := [][32]byte{Message(subject, PropName, e.Props[PropName].Value, 1)}
	at, _ := other(context.Background(), msgs)
	a := e.Props[PropName]
	a.Signatures = at
	e.Props[PropName] = a
	v := e.Verify()
	if v.OK {
		t.Fatalf("an entry signed by a key outside the policy verified: %+v", v)
	}
}

// spec: SPO-12a-PRE-001, SPO-12a-PRE-002, SPO-12a-PRE-003, SPO-12a-PRE-004, SPO-12a-PRE-005, SPO-12a-PRE-006
func TestFieldLimits(t *testing.T) {
	ok := Fields{Name: "N", Description: "D"}
	tests := []struct {
		name string
		f    func(Fields) Fields
		ok   bool
	}{
		{"min", func(f Fields) Fields { return f }, true},
		{"name empty", func(f Fields) Fields { f.Name = ""; return f }, false},                                  // PRE-001
		{"name 50", func(f Fields) Fields { f.Name = strings.Repeat("é", 50); return f }, true},                 // characters, not bytes
		{"name 51", func(f Fields) Fields { f.Name = strings.Repeat("a", 51); return f }, false},                // PRE-001
		{"description empty", func(f Fields) Fields { f.Description = ""; return f }, false},                    // PRE-002
		{"description 500", func(f Fields) Fields { f.Description = strings.Repeat("é", 500); return f }, true}, // PRE-002
		{"description 501", func(f Fields) Fields { f.Description = strings.Repeat("a", 501); return f }, false},
		{"ticker 1", func(f Fields) Fields { f.Ticker = "A"; return f }, false}, // PRE-003
		{"ticker 2", func(f Fields) Fields { f.Ticker = "AB"; return f }, true},
		{"ticker 9", func(f Fields) Fields { f.Ticker = "ABCDEFGHI"; return f }, true},
		{"ticker 10", func(f Fields) Fields { f.Ticker = "ABCDEFGHIJ"; return f }, false},
		{"url https", func(f Fields) Fields { f.URL = "https://a.b"; return f }, true}, // PRE-004
		{"url http", func(f Fields) Fields { f.URL = "http://a.b"; return f }, false},
		{"url embedded https (upstream accepts, anchored here)", func(f Fields) Fields { f.URL = "x https://a.b"; return f }, false},
		{"url 250", func(f Fields) Fields { f.URL = "https://" + strings.Repeat("a", 242); return f }, true},
		{"url 251", func(f Fields) Fields { f.URL = "https://" + strings.Repeat("a", 243); return f }, false},
		{"decimals 0", func(f Fields) Fields { f.Decimals = "0"; return f }, true}, // PRE-005
		{"decimals 19", func(f Fields) Fields { f.Decimals = "19"; return f }, true},
		{"decimals 20 (upstream accepts to 255, CIP-26 stops at 19)", func(f Fields) Fields { f.Decimals = "20"; return f }, false},
		{"decimals 256", func(f Fields) Fields { f.Decimals = "256"; return f }, false},
		{"decimals text", func(f Fields) Fields { f.Decimals = "six"; return f }, false},
		{"decimals negative", func(f Fields) Fields { f.Decimals = "-1"; return f }, false},
		{"logo png", func(f Fields) Fields { f.Logo = pngBytes; return f }, true}, // PRE-006
		{"logo not png", func(f Fields) Fields { f.Logo = []byte("GIF89a....."); return f }, false},
		{"logo 64 KB", func(f Fields) Fields { f.Logo = append([]byte(pngMagic), make([]byte, MaxLogoBytes-8)...); return f }, true},
		{"logo over 64 KB", func(f Fields) Fields { f.Logo = append([]byte(pngMagic), make([]byte, MaxLogoBytes-7)...); return f }, false},
	}
	for _, c := range tests {
		err := c.f(ok).Validate()
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v", c.name, err)
		}
	}
}

func TestParseEntryStrict(t *testing.T) {
	sub := strings.Repeat("ab", 28)
	good := `{"subject":"` + sub + `","name":{"sequenceNumber":0,"value":"x","signatures":[]}}`
	if _, err := ParseEntry([]byte(good)); err != nil {
		t.Fatal(err)
	}
	bads := map[string]string{
		"duplicate":    `{"subject":"` + sub + `","subject":"` + sub + `"}`,
		"seq text":     `{"subject":"` + sub + `","name":{"sequenceNumber":"0","value":"x"}}`,
		"seq negative": `{"subject":"` + sub + `","name":{"sequenceNumber":-1,"value":"x"}}`,
		"seq float":    `{"subject":"` + sub + `","name":{"sequenceNumber":1.5,"value":"x"}}`,
		"value type":   `{"subject":"` + sub + `","name":{"sequenceNumber":0,"value":5}}`,
		"decimals":     `{"subject":"` + sub + `","decimals":{"sequenceNumber":0,"value":"6"}}`,
		"short sig":    `{"subject":"` + sub + `","name":{"sequenceNumber":0,"value":"x","signatures":[{"signature":"00","publicKey":"00"}]}}`,
		"member":       `{"subject":"` + sub + `","name":{"sequenceNumber":0,"value":"x","extra":1}}`,
		"subject":      `{"subject":"zz","name":{"sequenceNumber":0,"value":"x"}}`,
		"trailing":     good + `{}`,
		"not object":   `[]`,
	}
	for n, b := range bads {
		if _, err := ParseEntry([]byte(b)); err == nil {
			t.Errorf("%s: accepted", n)
		}
	}
	e, err := ParseEntry([]byte(`{"additionalProperties":{},"subject":"` + sub + `"}`))
	if err != nil || len(e.Other) != 1 {
		t.Errorf("server members: %v %v", err, e.Other)
	}
}
