package native

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"
)

type blsEnv struct{ Type, Description, CborHex string }

// The envelopes are those of `cardano-cli dijkstra node key-gen-BLS` 11.2.3.0
// (compared with a run of the pinned cli in the parity test): the cli's type
// strings including their "Mininimal" typo, a 96-byte verification key and a
// 32-byte signing key as CBOR byte strings, four-space indent, trailing
// newline, and a fresh pair on every call.
//
// spec: SPO-04f-EXT-001
func TestGenerateBLSEnvelopes(t *testing.T) {
	a, err := KeyGen{}.GenerateBLS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var v, s blsEnv
	if err := json.Unmarshal(a.VKey, &v); err != nil {
		t.Fatal(err)
	}
	if err := a.SKey.Use(func(b []byte) error { return json.Unmarshal(b, &s) }); err != nil {
		t.Fatal(err)
	}
	if v.Type != blsVKeyType || v.Description != "BLS12-381 verification key" || len(v.CborHex) != 196 || v.CborHex[:4] != "5860" {
		t.Errorf("verification key %+v", v)
	}
	if s.Type != blsSKeyType || s.Description != "BLS12-381 signing key" || len(s.CborHex) != 68 || s.CborHex[:4] != "5820" {
		t.Errorf("signing key %+v", s)
	}
	if _, err := hex.DecodeString(v.CborHex); err != nil {
		t.Error(err)
	}
	if a.VKey[len(a.VKey)-1] != '\n' {
		t.Error("no trailing newline")
	}
	b, _ := KeyGen{}.GenerateBLS(context.Background())
	if string(a.VKey) == string(b.VKey) {
		t.Error("two generations gave the same key")
	}
	a.SKey.Destroy()
	b.SKey.Destroy()
}
