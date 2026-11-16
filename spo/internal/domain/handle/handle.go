// Package handle is the pure side of ADA Handles: the name formats, the
// policy ids, the asset-name labels and the reading of the address a virtual
// sub-handle's datum states. Looking a handle up is the use case's
// (app/handles).
package handle

import (
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// Asset-name labels of the handle standard.
const (
	// LabelCIP68 (222, `000de140`) prefixes the asset name of a CIP-68
	// handle: a root handle or an on-chain sub-handle.
	LabelCIP68 = "000de140"
	// LabelVirtual (`00000000`) prefixes a virtual sub-handle, which has no
	// UTxO of its own: the Handle API's minting UTxO holds its datum.
	LabelVirtual = "00000000"
)

// Policy ids (SPO-Cconf-INV-006 endpoint table, SPO-Caddr-INV-009).
const (
	PolicyCurrent = "f0ff48bbb7bbe9d59a40f1ce90e9e9d0ff5002ec48f232b49ca0fb9a"
	PolicyLegacy  = "8d18d786e92776c824607fd8e193ec535c79dc61ea2405ddf3b09fe3"
)

// Policy parses a policy id.
func Policy(h string) ([28]byte, error) {
	var p [28]byte
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 28 {
		return p, fmt.Errorf("%q is not a 56-digit policy id", h)
	}
	copy(p[:], b)
	return p, nil
}

// ErrFormat: a string that is neither a root nor a sub-handle.
var ErrFormat = errors.New("not an ADA Handle: want $name or $sub@name, parts of 1 to 15 of a-z 0-9 _ . -")

var (
	rootRE = regexp.MustCompile(`^\$[a-z0-9_.-]{1,15}$`)
	subRE  = regexp.MustCompile(`^\$[a-z0-9_.-]{1,15}@[a-z0-9_.-]{1,15}$`)
)

// Handle is a parsed handle name.
type Handle struct {
	// Name is the lowercased name without the `$`: `name` or `sub@name`.
	Name string
	// Sub is true for `sub@name`.
	Sub bool
}

// Parse lowercases the text and accepts the root form `$name` and the
// sub-handle form `$sub@name` (SPO-Caddr-IF-001, SPO-Caddr-PRE-004).
func Parse(s string) (Handle, error) {
	s = strings.ToLower(s)
	switch {
	case rootRE.MatchString(s):
		return Handle{Name: s[1:]}, nil
	case subRE.MatchString(s):
		return Handle{Name: s[1:], Sub: true}, nil
	}
	return Handle{}, fmt.Errorf("%w: %q", ErrFormat, s)
}

// NameHex is the hex of the name's bytes: the asset name of a classic
// (CIP-25) root handle.
func (h Handle) NameHex() string { return hex.EncodeToString([]byte(h.Name)) }

const (
	datumKeyHex    = "7265736f6c7665645f616464726573736573" // "resolved_addresses"
	datumAdaKeyHex = "436164615839"                         // key "ada", then a 57-byte string header
	baseAddrBytes  = 57
)

// ErrDatum: the datum states no address this reader can find.
var ErrDatum = errors.New("the datum has no readable resolved_addresses.ada base address")

// DatumAddress reads the address a virtual sub-handle's datum states: after
// the key `resolved_addresses` (its last occurrence), the key `ada` and a
// 57-byte string header, then 57 bytes, which are bech32-encoded with the
// prefix `addr` on mainnet and `addr_test` otherwise (SPO-Caddr-INV-007,
// SPO-Caddr-INV-008). Only base addresses, 57 bytes, can be read this way.
// Upstream takes the last occurrence of the `ada` marker as well, anywhere in
// the datum; the port takes the first one after the key, which is the entry
// of that map and cannot be a byte string elsewhere in the document.
func DatumAddress(datumHex string, mainnet bool) (string, error) {
	d := strings.ToLower(datumHex)
	// Aligned search: a match on an odd offset is not a byte boundary.
	last := -1
	for i := 0; i+len(datumKeyHex) <= len(d); i += 2 {
		if d[i:i+len(datumKeyHex)] == datumKeyHex {
			last = i
		}
	}
	if last < 0 {
		return "", ErrDatum
	}
	rest := last + len(datumKeyHex)
	for i := rest; i+len(datumAdaKeyHex)+2*baseAddrBytes <= len(d); i += 2 {
		if d[i:i+len(datumAdaKeyHex)] != datumAdaKeyHex {
			continue
		}
		raw, err := hex.DecodeString(d[i+len(datumAdaKeyHex) : i+len(datumAdaKeyHex)+2*baseAddrBytes])
		if err != nil {
			return "", ErrDatum
		}
		hrp := "addr_test"
		if mainnet {
			hrp = "addr"
		}
		return chain.Bech32Encode(hrp, raw)
	}
	return "", ErrDatum
}
