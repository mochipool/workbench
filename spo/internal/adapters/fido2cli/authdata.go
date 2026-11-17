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
	var key cbor.RawMessage // the COSE public key: one item, skipped
	if rest, err = dec.UnmarshalFirst(rest, &key); err != nil {
		return credAuthData{}, malformed("credential public key")
	}
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
