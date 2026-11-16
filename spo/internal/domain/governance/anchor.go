// Package governance is the governance bounded context of the Conway era
// (spec/upstream/scripts/21a to 25b): DReps, constitutional committee
// members, votes and governance actions, with the rules that decide who may
// vote on what and how a vote is tallied. The package is pure. Certificates,
// vote files, action files and their CBOR are produced by the ledger adapter
// (ports/governance.go); nothing here encodes or decodes them.
package governance

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// Anchor is the metadata anchor of a certificate, a vote or a proposal: the
// URL of a CIP-100 document and the blake2b-256 hash of its bytes. The zero
// value is "no anchor".
type Anchor struct {
	URL  string
	Hash [32]byte
}

// IsZero reports that there is no anchor.
func (a Anchor) IsZero() bool { return a.URL == "" }

// HashHex is the hash in lower-case hex.
func (a Anchor) HashHex() string { return hex.EncodeToString(a.Hash[:]) }

// MaxAnchorURL is the longest anchor URL the ledger accepts (128 bytes).
const MaxAnchorURL = 128

// Refusals of anchor words.
var (
	// ErrAnchorURL: a URL that does not start with https:// or ipfs://, or is too long.
	ErrAnchorURL = errors.New("the anchor URL must start with https:// or ipfs:// and be at most 128 characters")
	// ErrAnchorHash: a hash that is not 64 hex digits.
	ErrAnchorHash = errors.New("the anchor hash must be 64 hexadecimal digits")
	// ErrAnchorPair: a url without a hash, or a hash without a url.
	ErrAnchorPair = errors.New("an anchor needs both the URL and the data hash")
)

// HashDocument is the anchor data hash of a document: the blake2b-256 digest
// of its raw bytes, never of a re-serialisation.
//
// spec: SPO-21b-EXT-003, SPO-24a-INV-002, SPO-25a-EXT-002
func HashDocument(doc []byte) [32]byte { return blake2b.Sum256(doc) }

// ParseAnchorURL trims and checks an anchor URL: https:// or ipfs:// prefix
// (upstream tests for the scheme anywhere in the text, so `ftp://x/https://y`
// passes there; this port requires the prefix) and at most 128 characters.
//
// spec: SPO-Pparam-IF-025, SPO-24a-IF-004, SPO-25a-IF-005
func ParseAnchorURL(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) > MaxAnchorURL || !(strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "ipfs://")) || len(s) == len("https://") {
		return "", fmt.Errorf("%w: %q", ErrAnchorURL, s)
	}
	return s, nil
}

// ParseHash32 trims, lower-cases and decodes a 64-digit hash.
//
// spec: SPO-Pparam-IF-026, SPO-24a-IF-004, SPO-25a-IF-006
func ParseHash32(s string) ([32]byte, error) {
	var out [32]byte
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) != 64 {
		return out, fmt.Errorf("%w: %q", ErrAnchorHash, s)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("%w: %q", ErrAnchorHash, s)
	}
	copy(out[:], b)
	return out, nil
}

// ParseAnchorWords checks the `url:` and `hash:` words of an anchor. Both
// empty is no anchor; one without the other is refused.
//
// spec: SPO-21b-PRE-006, SPO-23e-PRE-003, SPO-24a-PRE-002, SPO-25a-PRE-005, SPO-25a-PRE-006
func ParseAnchorWords(url, hash string) (Anchor, error) {
	if url == "" && hash == "" {
		return Anchor{}, nil
	}
	if url == "" || hash == "" {
		return Anchor{}, ErrAnchorPair
	}
	u, err := ParseAnchorURL(url)
	if err != nil {
		return Anchor{}, err
	}
	h, err := ParseHash32(hash)
	if err != nil {
		return Anchor{}, err
	}
	return Anchor{URL: u, Hash: h}, nil
}

// FetchURL is the URL an anchor document is downloaded from: an ipfs://<path>
// URL is read through the gateway (`https://ipfs.io/ipfs/` by default); the
// ipfs:// URL itself stays in the certificate.
//
// spec: SPO-21b-EXT-002, SPO-21c-EXT-003, SPO-24a-EXT-001, SPO-25a-EXT-001
func FetchURL(anchorURL, gateway string) string {
	if p, ok := strings.CutPrefix(anchorURL, "ipfs://"); ok {
		if gateway == "" {
			gateway = "https://ipfs.io/ipfs/"
		}
		return strings.TrimSuffix(gateway, "/") + "/" + strings.TrimPrefix(p, "/")
	}
	return anchorURL
}
