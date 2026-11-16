package chain

import (
	"encoding/hex"
	"strings"
	"testing"
)

// BIP-173 valid strings: they must decode and re-encode unchanged.
func TestBech32ValidVectors(t *testing.T) {
	for _, s := range []string{
		"A12UEL5L",
		"a12uel5l",
		"an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
		"abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
		"11" + strings.Repeat("q", 82) + "c8247j",
		"split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
	} {
		hrp, data, err := Bech32Decode(s)
		if err != nil {
			t.Errorf("%q: %v", s, err)
			continue
		}
		got, err := Bech32Encode(hrp, data)
		if err != nil || got != strings.ToLower(s) {
			t.Errorf("%q: re-encoded to %q (%v)", s, got, err)
		}
	}
}

// BIP-173 invalid strings.
func TestBech32InvalidVectors(t *testing.T) {
	for _, s := range []string{
		"\x201nwldj5",
		"pzry9x0s0muk",
		"1pzry9x0s0muk",
		"x1b4n0q5v",
		"li1dgmt3",
		"de1lg7wt\xff",
		"A1G7SGD8",
		"10a06t8",
		"1qzzfhee",
		"A12uEL5L", // mixed case
	} {
		if _, _, err := Bech32Decode(s); err == nil {
			t.Errorf("%q decoded but must not", s)
		}
	}
}

func TestPoolIDRoundTrip(t *testing.T) {
	// Real preview pool, recorded from Koios.
	const s = "pool16h8ugt8k0a4kxa5g6x062zjrgfjc7cehpw0ze8374axlul76932"
	p, err := ParsePoolBech32(s)
	if err != nil {
		t.Fatal(err)
	}
	if p.Bech32() != s {
		t.Fatalf("got %s", p.Bech32())
	}
	want := "d5cfc42cf67f6b637688d19fa50a4342658f63370b9e2c9e3eaf4dfe"
	if hex.EncodeToString(p[:]) != want {
		t.Fatal("hex form differs from Koios pool_id_hex")
	}
	if _, err := ParsePoolBech32("addr1qqqqqqqq"); err == nil {
		t.Fatal("accepted a non-pool string")
	}
}
