package assets

import (
	"encoding/hex"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

func policy(t *testing.T, h string) (p [28]byte) {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 28 {
		t.Fatalf("policy %q: %v", h, err)
	}
	copy(p[:], b)
	return p
}

// CIP-14 test vectors: bech32 `asset` of the 20-byte blake2b of policy id and name.
//
// spec: SPO-Cconv-OUT-013
func TestFingerprintIsCIP14(t *testing.T) {
	p := policy(t, "7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373")
	for _, c := range []struct {
		name []byte
		want string
	}{
		{nil, "asset1rjklcrnsdzqp65wjgrg55sy9723kw09mlgvlc3"},
		{[]byte("PATATE"), "asset13n25uv0yaf5kus35fm2k86cqy60z58d9xmde92"},
	} {
		if got := Fingerprint(chain.AssetID{Policy: p, Name: c.name}); got != c.want {
			t.Errorf("fingerprint of %q = %s, want %s", c.name, got, c.want)
		}
	}
}

// The text form of an asset name is its bytes in hex, lower case, on one
// line; a `{hex}` name is the raw bytes, non-printable ones included, NUL too.
//
// spec: SPO-Cconv-OUT-014, SPO-Cconv-OUT-015
func TestAssetNameTextAndHexForms(t *testing.T) {
	n, err := ParseName("Token7")
	if err != nil || hex.EncodeToString(n.Bytes) != "546f6b656e37" {
		t.Fatalf("text name: %x %v", n.Bytes, err)
	}
	n, err = ParseName("{00ff10}")
	if err != nil || hex.EncodeToString(n.Bytes) != "00ff10" || !n.HexTyped {
		t.Fatalf("hex name keeps raw bytes: %x %v", n.Bytes, err)
	}
}

// The display form of a name is its text only when every byte is a letter or
// a digit; a NUL byte, a space or a byte above 127 keeps the hex. Upstream
// prefixes the readable text with a dot (the empty name prints `.`): the dot
// is the display's join between policy and name and is not part of the name,
// so the port returns the text alone and the empty name is the empty text.
//
// spec: SPO-Cconv-OUT-016
func TestDisplayNameIsTextOnlyWhenEveryByteIsAlphanumeric(t *testing.T) {
	for _, c := range []struct {
		in   []byte
		want string
	}{
		{[]byte("Token7"), "Token7"},
		{nil, ""},
		{[]byte{0x00, 'a'}, "0061"},
		{[]byte("a b"), "612062"},
		{[]byte{0xc3, 0xa9}, "c3a9"},
	} {
		if got := DisplayName(c.in); got != c.want {
			t.Errorf("DisplayName(%x) = %q, want %q", c.in, got, c.want)
		}
	}
}
