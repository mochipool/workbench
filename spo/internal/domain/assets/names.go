// Package assets is the native-assets context: asset names and references,
// the selections of a send, minting policies and the asset record. It is
// pure; files, keys and the chain are the use cases' and adapters'.
package assets

import (
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// MaxAssetNameBytes is the ledger's limit on an asset name.
const MaxAssetNameBytes = 32

// Errors of asset names and references.
var (
	// ErrBadAssetName: a name that is neither alphanumeric ASCII nor `{hex}`
	// (SPO-11a-IF-003), or is over 32 bytes (SPO-11a-PRE-001).
	ErrBadAssetName = errors.New("invalid asset name")
	// ErrBadAssetRef: a `<policy>.<asset>` reference of the wrong shape
	// (SPO-11a-IF-002).
	ErrBadAssetRef = errors.New("invalid asset reference")
	// ErrBadAmount: a mint or burn amount that is not a positive integer
	// within the ledger's signed 64-bit range (SPO-11a-PRE-002).
	ErrBadAmount = errors.New("invalid amount")
)

var (
	hexPairsRE = regexp.MustCompile(`^([0-9a-fA-F]{2})+$`)
	alnumRE    = regexp.MustCompile(`^[0-9A-Za-z]*$`)
)

// Name is an asset name as typed: its bytes and whether it was given as
// `{hex}`.
type Name struct {
	Bytes []byte
	// HexTyped is true for a `{hex}` name: the record's hexname holds the hex
	// only then (SPO-11a-INV-005).
	HexTyped bool
}

// ParseName reads an asset name: alphanumeric ASCII only, converted to its
// bytes, or `{<hex>}` with one or more full pairs, used as the raw name. The
// result is at most 32 bytes. The empty name is a valid name.
//
// spec: SPO-11a-IF-003, SPO-11a-PRE-001, SPO-11b-IF-003
func ParseName(s string) (Name, error) {
	if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") && len(s) > 2 {
		h := s[1 : len(s)-1]
		if !hexPairsRE.MatchString(h) {
			return Name{}, fmt.Errorf("%w: %q: a {hex} name needs full hex pairs", ErrBadAssetName, s)
		}
		b, _ := hex.DecodeString(h)
		if len(b) > MaxAssetNameBytes {
			return Name{}, fmt.Errorf("%w: %q is %d bytes, the maximum is %d", ErrBadAssetName, s, len(b), MaxAssetNameBytes)
		}
		return Name{Bytes: b, HexTyped: true}, nil
	}
	if !alnumRE.MatchString(s) {
		return Name{}, fmt.Errorf("%w: %q should only contain alphanumeric characters; use {8ac33ed5...} for a binary name", ErrBadAssetName, s)
	}
	if len(s) > MaxAssetNameBytes {
		return Name{}, fmt.Errorf("%w: %q is %d bytes, the maximum is %d", ErrBadAssetName, s, len(s), MaxAssetNameBytes)
	}
	return Name{Bytes: []byte(s)}, nil
}

// Ref is a `<policy>.<asset>` reference as `11a` and `11b` take it.
type Ref struct {
	Policy string // the policy name
	Asset  string // the asset name as typed
}

// ParseRef splits a mint or burn reference. A trailing `.asset` is dropped;
// the rest must have exactly one dot (upstream cuts at the first dot for the
// policy and the last for the asset name, and with no dot uses the one text
// for both, so `mypolicy` mints an asset `mypolicy` under policy `mypolicy`:
// a quirk the port refuses).
//
// spec: SPO-11a-IF-001, SPO-11a-IF-002, SPO-11b-IF-002
func ParseRef(s string) (Ref, error) {
	s = strings.TrimSuffix(s, ".asset")
	if strings.Count(s, ".") != 1 {
		return Ref{}, fmt.Errorf("%w: %q must be <policy>.<asset> with exactly one dot", ErrBadAssetRef, s)
	}
	p, a, _ := strings.Cut(s, ".")
	if p == "" {
		return Ref{}, fmt.Errorf("%w: %q has no policy name", ErrBadAssetRef, s)
	}
	return Ref{Policy: p, Asset: a}, nil
}

// RecordName is the store name of an asset record: `<policy>.<asset>` as the
// name was typed. A `{hex}` name keeps no braces (a store name is a plain
// label, hazard H7) and reads `hex-<hex>`; an alphanumeric name never
// contains a dash, so the two cannot collide. One name serves every work mode
// (SPO-11b-OUT-002: upstream's offline burn used the hex form of an ASCII
// name and so started a second record).
//
// spec: SPO-11b-OUT-002, SPO-11a-INV-005
func RecordName(policy, asset string) string {
	if strings.HasPrefix(asset, "{") && strings.HasSuffix(asset, "}") {
		asset = "hex-" + strings.ToLower(asset[1:len(asset)-1])
	}
	return policy + "." + asset
}

// ParseMintAmount reads the amount of a mint or burn: a positive decimal
// integer, at most the ledger's signed 64-bit maximum.
//
// spec: SPO-11a-PRE-002, SPO-11b-IF-003
func ParseMintAmount(s string) (int64, error) {
	if s == "" || strings.Trim(s, "0123456789") != "" {
		return 0, fmt.Errorf("%w: %q must be a positive whole number", ErrBadAmount, s)
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, fmt.Errorf("%w: %q has leading zeros", ErrBadAmount, s)
	}
	var n int64
	for _, c := range s {
		d := int64(c - '0')
		if n > (1<<63-1-d)/10 {
			return 0, fmt.Errorf("%w: %q is above the ledger's maximum of %d", ErrBadAmount, s, int64(1<<63-1))
		}
		n = n*10 + d
	}
	if n < 1 {
		return 0, fmt.Errorf("%w: the amount must be a positive number", ErrBadAmount)
	}
	return n, nil
}

// DisplayName is the readable form of an asset name (SPO-Cconv-OUT-016): the
// text when every byte is an ASCII letter or digit, else the hex. The empty
// name is the empty text.
//
// spec: SPO-Cconv-OUT-016
func DisplayName(name []byte) string {
	for _, c := range name {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return hex.EncodeToString(name)
		}
	}
	return string(name)
}

// Subject is the policy id followed by the hex name (the token registry's
// subject).
func Subject(a chain.AssetID) string {
	return hex.EncodeToString(a.Policy[:]) + hex.EncodeToString(a.Name)
}

// Fingerprint is the CIP-14 fingerprint of an asset (SPO-Cconv-OUT-013).
func Fingerprint(a chain.AssetID) string { return chain.AssetFingerprint(a) }
