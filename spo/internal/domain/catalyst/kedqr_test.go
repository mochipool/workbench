package catalyst

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// The vector was computed with an independent implementation of the algorithm
// the toolbox source states (Python hashlib.pbkdf2_hmac and PyCryptodome's
// ChaCha20_Poly1305), not with this package: PIN 1 2 3 4 as the bytes 1,2,3,4,
// salt 00..0f, nonce 64..6f, key bytes 00..3f. The toolbox itself publishes no
// known-answer vector, so this does NOT show that the mobile app accepts it.
const (
	vecKDFKey  = "b6174001af8bc102b9d8e588099c415132c3c0bc7ad79f1fb17d0c8f81d17a6c"
	vecPayload = "01000102030405060708090a0b0c0d0e0f6465666768696a6b6c6d6e6fda6cf38a6d4b47df2b250777a067c1ee9e4af75fb198a996349f71256fc8455bc2391fcee820ffa6c5bb702dcb26cb819baf1848add77cb1a6643b9c412e7cc7c8b29a87c24e15460d9a50c16a08e668"
)

func seqKey() []byte {
	k := make([]byte, 64)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

// fixedRandom yields the salt 00..0f then the nonce 64..6f.
func fixedRandom() *bytes.Reader {
	b := make([]byte, 0, 28)
	for i := 0; i < 16; i++ {
		b = append(b, byte(i))
	}
	for i := 0; i < 12; i++ {
		b = append(b, byte(100+i))
	}
	return bytes.NewReader(b)
}

// spec: SPO-09a-EXT-005, SPO-09a-PRE-009
func TestPINIsDigitValuesNotASCII(t *testing.T) {
	p, err := ParsePIN([]byte("1234"))
	if err != nil || p != (PIN{1, 2, 3, 4}) {
		t.Fatalf("%v %v", p, err)
	}
	for _, bad := range []string{"", "123", "12345", "12a4", " 123", "-123", "１２３４"} {
		if _, err := ParsePIN([]byte(bad)); !errors.Is(err, ErrBadPIN) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// spec: SPO-09a-EXT-005
func TestEncodeMatchesIndependentVector(t *testing.T) {
	got, err := Encode(seqKey(), PIN{1, 2, 3, 4}, fixedRandom())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != vecPayload {
		t.Errorf("payload\n got  %s\n want %s", got, vecPayload)
	}
	if len(got) != 218 || strings.ToLower(string(got)) != string(got) {
		t.Errorf("layout: %d characters", len(got))
	}
	key, _ := deriveKey(PIN{1, 2, 3, 4}, mustHex(t, vecPayload)[1:17])
	if hex.EncodeToString(key) != vecKDFKey {
		t.Errorf("PBKDF2 key %x", key)
	}
}

// spec: SPO-09a-EXT-005
func TestDecodeRoundTripAndRefusals(t *testing.T) {
	plain, err := Decode([]byte(vecPayload), PIN{1, 2, 3, 4})
	if err != nil || !bytes.Equal(plain, seqKey()) {
		t.Fatalf("%x %v", plain, err)
	}
	if _, err := Decode([]byte(vecPayload), PIN{1, 2, 3, 5}); !errors.Is(err, ErrWrongPIN) {
		t.Errorf("wrong pin: %v", err)
	}
	raw := mustHex(t, vecPayload)
	raw[40] ^= 1
	if _, err := Decode([]byte(hex.EncodeToString(raw)), PIN{1, 2, 3, 4}); !errors.Is(err, ErrWrongPIN) {
		t.Errorf("altered: %v", err)
	}
	raw = mustHex(t, vecPayload)
	raw[0] = 2
	if _, err := Decode([]byte(hex.EncodeToString(raw)), PIN{1, 2, 3, 4}); !errors.Is(err, ErrUnknownProto) {
		t.Errorf("version: %v", err)
	}
	for _, bad := range []string{"", "zz", vecPayload[:60], vecPayload[:len(vecPayload)-2]} {
		if _, err := Decode([]byte(bad), PIN{1, 2, 3, 4}); !errors.Is(err, ErrBadPayload) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if _, err := Encode(make([]byte, 63), PIN{}, fixedRandom()); !errors.Is(err, ErrBadKey) {
		t.Errorf("short key: %v", err)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
