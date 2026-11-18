package fido2cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// Flags of the authenticator data (WebAuthn level 2, section 6.1).
const (
	flagUP = 1 << 0
	flagUV = 1 << 2
	flagAT = 1 << 6
	flagED = 1 << 7
)

var dec = func() cbor.DecMode {
	m, err := cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF, MaxNestedLevels: 8, MaxArrayElements: 64, MaxMapPairs: 64}.DecMode()
	if err != nil {
		panic(err)
	}
	return m
}()

func malformed(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ports.ErrFactorMalformed, fmt.Sprintf(format, a...))
}

func decodeB64(s string) ([]byte, error) {
	return base64.StdEncoding.Strict().DecodeString(s)
}

// decodeAuthData reads a base64 line holding the CBOR byte string that the tools
// print around the raw authenticator data, and returns the raw data.
//
// spec: SPO-Xunlock-EXT-005
func decodeAuthData(line string) ([]byte, error) {
	b, err := decodeB64(line)
	if err != nil {
		return nil, malformed("authenticator data is not base64")
	}
	var raw []byte
	rest, err := dec.UnmarshalFirst(b, &raw)
	if err != nil || len(rest) != 0 {
		return nil, malformed("authenticator data is not one CBOR byte string")
	}
	return raw, nil
}

// header checks the 37 fixed bytes and the relying-party hash.
func header(ad []byte, rpID string) (flags byte, rest []byte, err error) {
	if len(ad) < 37 {
		return 0, nil, malformed("authenticator data is too short")
	}
	h := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(ad[:32], h[:]) {
		return 0, nil, malformed("the authenticator data is for another relying party")
	}
	return ad[32], ad[37:], nil
}

// assertFlags returns the flags byte of an assertion's authenticator data.
func assertFlags(ad []byte, rpID string) (byte, error) {
	f, rest, err := header(ad, rpID)
	if err != nil {
		return 0, err
	}
	if f&flagAT != 0 {
		return 0, malformed("an assertion carries attested credential data")
	}
	if f&flagED != 0 {
		var ext map[string]cbor.RawMessage
		r, err := dec.UnmarshalFirst(rest, &ext)
		if err != nil || len(r) != 0 {
			return 0, malformed("extension data")
		}
	} else if len(rest) != 0 {
		return 0, malformed("trailing bytes after the authenticator data")
	}
	return f, nil
}

type credAuthData struct {
	flags       byte
	credID      []byte
	credProtect int
	hmacSecret  bool
	// x and y are the coordinates of the ES256 public key (COSE, RFC 9053).
	x, y []byte
}

// parseCOSEES256 reads an ES256 COSE key: kty 2 (EC2), alg -7, crv 1 (P-256) and
// the two 32-byte coordinates.
func parseCOSEES256(raw cbor.RawMessage) (x, y []byte, err error) {
	var m map[int]any
	if err := dec.Unmarshal(raw, &m); err != nil {
		return nil, nil, malformed("credential public key is not a COSE map")
	}
	num := func(k int) (int64, bool) {
		switch v := m[k].(type) {
		case int64:
			return v, true
		case uint64:
			return int64(v), true
		}
		return 0, false
	}
	if kty, ok := num(1); !ok || kty != 2 {
		return nil, nil, malformed("credential public key is not an EC2 key")
	}
	if alg, ok := num(3); !ok || alg != -7 {
		return nil, nil, malformed("credential public key is not ES256")
	}
	if crv, ok := num(-1); !ok || crv != 1 {
		return nil, nil, malformed("credential public key is not on P-256")
	}
	x, _ = m[-2].([]byte)
	y, _ = m[-3].([]byte)
	if len(x) != 32 || len(y) != 32 {
		return nil, nil, malformed("credential public key coordinates are not 32 bytes")
	}
	return x, y, nil
}

// signAuthData reads the authenticator data of a signing assertion: exactly the
// 37 fixed bytes (relying-party hash, flags, counter), with no attested
// credential data and no extension output, so that what the authenticator
// signed is the data shown and an SSH signature can be rebuilt from it.
func signAuthData(ad []byte, rpID string) (flags byte, counter uint32, err error) {
	f, _, err := header(ad, rpID)
	if err != nil {
		return 0, 0, err
	}
	if len(ad) != 37 || f&(flagAT|flagED) != 0 {
		return 0, 0, malformed("a signing assertion carries more than the 37 fixed bytes")
	}
	return f, binary.BigEndian.Uint32(ad[33:37]), nil
}

// parseCredAuthData reads the authenticator data of a makeCredential: the
// attested credential data, then the extension map with credProtect and
// hmac-secret.
func parseCredAuthData(ad []byte, rpID string) (credAuthData, error) {
	f, rest, err := header(ad, rpID)
	if err != nil {
		return credAuthData{}, err
	}
	if f&flagAT == 0 {
		return credAuthData{}, malformed("no attested credential data")
	}
	if len(rest) < 18 {
		return credAuthData{}, malformed("attested credential data is too short")
	}
	n := int(binary.BigEndian.Uint16(rest[16:18]))
	rest = rest[18:]
	if n == 0 || len(rest) < n {
		return credAuthData{}, malformed("credential id length")
	}
	out := credAuthData{flags: f, credID: append([]byte(nil), rest[:n]...)}
	rest = rest[n:]
	var key cbor.RawMessage // the COSE public key: one item
	if rest, err = dec.UnmarshalFirst(rest, &key); err != nil {
		return credAuthData{}, malformed("credential public key")
	}
	// An unlock credential's key is never used, so a key that is not ES256 only
	// leaves x and y empty; EnrolSigner refuses an empty key.
	out.x, out.y, _ = parseCOSEES256(key)
	if f&flagED == 0 {
		if len(rest) != 0 {
			return credAuthData{}, malformed("trailing bytes after the credential data")
		}
		return out, nil
	}
	var ext map[string]any
	if rest, err = dec.UnmarshalFirst(rest, &ext); err != nil || len(rest) != 0 {
		return credAuthData{}, malformed("extension data")
	}
	if v, ok := ext["hmac-secret"].(bool); ok {
		out.hmacSecret = v
	}
	switch v := ext["credProtect"].(type) {
	case uint64:
		out.credProtect = int(v)
	case int64:
		out.credProtect = int(v)
	}
	return out, nil
}
