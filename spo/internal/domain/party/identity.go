// Package party is the multi-party bounded context: who the other parties
// are, what they may ask of us, and the messages exchanged (spec
// spec/extensions/Xparty.md, ADR 0005).
//
// It holds types and rules only. It performs no I/O, holds no private key
// and has no serialisation: the canonical CBOR of identity documents,
// payloads and bodies lives in adapters/envelope, which builds the values
// defined here. Hashing and Ed25519 verification are the only cryptography.
package party

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/blake2b"
)

// Domain strings keep a signature or hash made for one purpose from being
// valid for another.
const (
	// FingerprintDomain prefixes the hash that makes a fingerprint
	// (SPO-Xparty-INV-002).
	FingerprintDomain = "spo/party/v1"
	// DocumentDomain prefixes the bytes signed in an identity document
	// (SPO-Xparty-INV-003). The spec does not name this string; it is ours.
	DocumentDomain = "spo/identity/v1"
	// DocumentVersion is the identity document version.
	DocumentVersion = 1
)

// Key types, raw 32-byte values.
type (
	Ed25519Public [32]byte
	X25519Public  [32]byte
	// NodeKey is a tailcat (WireGuard) node public key.
	NodeKey [32]byte
)

// Fingerprint identifies an identity (SPO-Xparty-INV-002).
type Fingerprint [20]byte

// FingerprintOf is the first 20 bytes of BLAKE2b-256 over FingerprintDomain,
// the Ed25519 public key and the X25519 public key, in that order.
func FingerprintOf(ed Ed25519Public, x X25519Public) Fingerprint {
	h, _ := blake2b.New256(nil) // only fails for a key longer than 64 bytes
	h.Write([]byte(FingerprintDomain))
	h.Write(ed[:])
	h.Write(x[:])
	var fp Fingerprint
	copy(fp[:], h.Sum(nil))
	return fp
}

var fpEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

const (
	// GroupLen is the characters per displayed group.
	GroupLen = 4
	// Groups is the groups per displayed fingerprint.
	Groups = 8
	// ConfirmGroups is the groups the operator types (SPO-Xparty-PR-001).
	ConfirmGroups = 4
)

// compact is the 32 lower-case base32 characters of the fingerprint.
func (f Fingerprint) compact() string { return strings.ToLower(fpEnc.EncodeToString(f[:])) }

// String shows the fingerprint as 8 groups of 4 lower-case base32
// characters separated by '-': 20 bytes are 160 bits, 32 characters
// (SPO-Xparty-INV-002).
func (f Fingerprint) String() string {
	c := f.compact()
	parts := make([]string, 0, Groups)
	for i := 0; i < len(c); i += GroupLen {
		parts = append(parts, c[i:i+GroupLen])
	}
	return strings.Join(parts, "-")
}

// ErrFingerprint is returned for text that is not a fingerprint.
var ErrFingerprint = errors.New("party: not a fingerprint")

// normalise drops the separators a person types and folds case.
func normalise(s string) string {
	return strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(s))
}

// ParseFingerprint reads the text form back. Separators and case are free.
func ParseFingerprint(s string) (Fingerprint, error) {
	var fp Fingerprint
	n := normalise(s)
	if len(n) != 32 {
		return fp, fmt.Errorf("%w: want 32 base32 characters", ErrFingerprint)
	}
	b, err := fpEnc.DecodeString(strings.ToUpper(n))
	if err != nil || len(b) != len(fp) {
		return fp, fmt.Errorf("%w: bad base32", ErrFingerprint)
	}
	copy(fp[:], b)
	if fp.compact() != n { // reject non-canonical trailing bits
		return Fingerprint{}, fmt.Errorf("%w: bad base32", ErrFingerprint)
	}
	return fp, nil
}

// Tail is the last Groups-ConfirmGroups groups: the only part of a fingerprint
// the enrollment display shows (SPO-Xparty-PR-001). The first ConfirmGroups
// groups are typed by the operator, read out by the other party, and never
// shown here.
func (f Fingerprint) Tail() string {
	c := f.compact()[ConfirmGroups*GroupLen:]
	parts := make([]string, 0, Groups-ConfirmGroups)
	for i := 0; i < len(c); i += GroupLen {
		parts = append(parts, c[i:i+GroupLen])
	}
	return strings.Join(parts, "-")
}

// ConfirmPrefix reports whether typed is the first ConfirmGroups groups of
// the fingerprint (SPO-Xparty-PR-001). Anything but exactly those characters
// is a mismatch; the comparison takes the same time wherever they differ.
func ConfirmPrefix(fp Fingerprint, typed string) bool {
	want := fp.compact()[:ConfirmGroups*GroupLen]
	got := normalise(typed)
	if len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// MaxLabelBytes bounds a label.
const MaxLabelBytes = 64

// Identity is the public part of a party identity (SPO-Xparty-INV-001,
// INV-003). The label is chosen by its owner and is not trusted: it is for
// display and carries no control characters.
type Identity struct {
	Label   string
	Ed25519 Ed25519Public
	X25519  X25519Public
	Node    *NodeKey // tailcat node public key, nil when the party has none
	Created time.Time
}

// Fingerprint of the identity.
func (i Identity) Fingerprint() Fingerprint { return FingerprintOf(i.Ed25519, i.X25519) }

// ErrIdentity is returned for an identity that breaks a rule.
var ErrIdentity = errors.New("party: invalid identity")

// cleanText reports whether s is valid UTF-8 without control or format
// characters (terminal escape sequences, bidi overrides).
func cleanText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func zero32(b [32]byte) bool { return b == [32]byte{} }

// Validate checks the identity's fields.
func (i Identity) Validate() error {
	switch {
	case len(i.Label) > MaxLabelBytes || !cleanText(i.Label):
		return fmt.Errorf("%w: label", ErrIdentity)
	case zero32(i.Ed25519), zero32(i.X25519):
		return fmt.Errorf("%w: zero public key", ErrIdentity)
	case i.Node != nil && zero32(*i.Node):
		return fmt.Errorf("%w: zero node key", ErrIdentity)
	case i.Created.IsZero() || i.Created.Unix() < 0:
		return fmt.Errorf("%w: created", ErrIdentity)
	}
	return nil
}

// Document is an identity and its signature (SPO-Xparty-INV-003).
//
// Content is the canonical CBOR of the identity, exactly the bytes that were
// signed; adapters/envelope builds a Document from a file and is the only
// producer, so Identity always is the decoding of Content. Signature is
// Ed25519 over DocumentDomain followed by Content, under Identity.Ed25519.
type Document struct {
	Identity  Identity
	Content   []byte
	Signature [64]byte
}

// ErrDocumentSignature is SPO-Xparty-PRE-001.
var ErrDocumentSignature = errors.New("party: identity document signature does not verify")

// DocumentMessage is the byte string a document signature covers.
func DocumentMessage(content []byte) []byte {
	return append([]byte(DocumentDomain), content...)
}

// Verify checks the signature under the key the document itself contains
// (SPO-Xparty-PRE-001). It proves possession of the private key, not who
// holds it: that is what the fingerprint confirmation is for.
func (d Document) Verify() error {
	if len(d.Content) == 0 {
		return fmt.Errorf("%w: empty content", ErrDocumentSignature)
	}
	if !ed25519.Verify(ed25519.PublicKey(d.Identity.Ed25519[:]), DocumentMessage(d.Content), d.Signature[:]) {
		return ErrDocumentSignature
	}
	return nil
}
