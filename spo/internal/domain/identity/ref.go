// Package identity is the object identity of ADR 0010: every object has an
// identity that is a hash, and every reference between objects is a typed
// pair (kind, hash), never a bare hash.
//
// A Ref is built only by the constructors below, one per row of the table in
// ADR 0010 decision 1; each applies exactly the hash and the encoding that
// row states. Rows the ADR marks "unconfirmed" are marked again at their
// constructor: no primary source (ledger specification, CIP text) was
// consulted for them, and a test only proves agreement with the code that
// already exists in this repository.
//
// The package has no storage and knows no operator names.
package identity

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// Kind says what a hash identifies. Its numeric code is part of the binary
// form (Ref.MarshalBinary) and never changes.
type Kind uint8

// The kinds, one per row of ADR 0010 decision 1.
const (
	// KindKeyHash is Blake2b-224 of a 32-byte Ed25519 verification key: the
	// ledger's credential hash. Payment, stake, pool cold (the pool id), DRep,
	// committee cold and hot, and a policy verification key.
	KindKeyHash Kind = 1
	// KindScriptHash is Blake2b-224 of 0x00 and a native script's CBOR: the
	// policy id.
	KindScriptHash Kind = 2
	// KindVRFKeyHash is Blake2b-256 of a 32-byte VRF verification key.
	KindVRFKeyHash Kind = 3
	// KindKESKeyHash is Blake2b-256 of a 32-byte KES verification key (project
	// rule: the ledger defines no hash of it). The KES number is not part of it.
	KindKESKeyHash Kind = 4
	// KindBLSKeyHash is Blake2b-256 of a raw BLS verification key (project rule).
	KindBLSKeyHash Kind = 5
	// KindCatalystKeyHash is Blake2b-256 of a 32-byte Catalyst voting key
	// (project rule).
	KindCatalystKeyHash Kind = 6
	// KindCalidusKeyHash is Blake2b-224 of a 32-byte Calidus key.
	KindCalidusKeyHash Kind = 7
	// KindTxID is Blake2b-256 of the transaction body bytes as built or received.
	KindTxID Kind = 8
	// KindFileHash is Blake2b-256 of the exact bytes of a metadata or anchor file.
	KindFileHash Kind = 9
	// KindPayloadHash is Blake2b-256 of the CBOR bytes a text envelope carries.
	KindPayloadHash Kind = 10
	// KindEnvelopeHash is Blake2b-256 of a sealed party envelope as sent or received.
	KindEnvelopeHash Kind = 11
	// KindPartyFingerprint is the 20-byte party fingerprint of ADR 0005.
	KindPartyFingerprint Kind = 13

	// The content-hash kinds: one per kind of object spo defines, bound
	// one-to-one to its tag (see the registry in content.go), so a reference
	// names the table a resolver consults. The hash of each is Blake2b-256
	// over [tag, value] (ContentOf).

	// KindPoolDescriptor is a pool descriptor, mapped from JSON.
	KindPoolDescriptor Kind = 12
	// KindWitnessCollection is a witness collection.
	KindWitnessCollection Kind = 14
	// KindPendingRecord is a pending record.
	KindPendingRecord Kind = 15
	// KindPartyIdentityDoc is a party identity document.
	KindPartyIdentityDoc Kind = 16
	// KindAuditEvent is an audit event.
	KindAuditEvent Kind = 17
	// KindOwnerManifest is an owner manifest.
	KindOwnerManifest Kind = 18
	// KindRoleHistory is a role-history value.
	KindRoleHistory Kind = 19
	// KindLabel is a label anchor (the anchor of a label record).
	KindLabel Kind = 20
	// KindOwnerRecord is the anchor-bound owner record.
	KindOwnerRecord Kind = 21
	// KindWorkspaceSettings is the fixed anchor of the workspace settings.
	KindWorkspaceSettings Kind = 22
	// KindProviderToken is the fixed anchor of provider tokens.
	KindProviderToken Kind = 23
)

// Kind codes are part of the binary form and of every stored reference. A
// code is never reused or renumbered; a new kind takes the next free code.
// The codes are 1-11 (key and exact-bytes rows, in the order of ADR 0010's
// table), 12 (pool descriptor), 13 (party fingerprint), 14-23 (the other
// content kinds above).

type kindInfo struct {
	name string
	size int
}

var kinds = map[Kind]kindInfo{
	KindKeyHash:           {"key-hash", 28},
	KindScriptHash:        {"script-hash", 28},
	KindVRFKeyHash:        {"vrf-key-hash", 32},
	KindKESKeyHash:        {"kes-key-hash", 32},
	KindBLSKeyHash:        {"bls-key-hash", 32},
	KindCatalystKeyHash:   {"catalyst-key-hash", 32},
	KindCalidusKeyHash:    {"calidus-key-hash", 28},
	KindTxID:              {"tx-id", 32},
	KindFileHash:          {"file-hash", 32},
	KindPayloadHash:       {"payload-hash", 32},
	KindEnvelopeHash:      {"envelope-hash", 32},
	KindPartyFingerprint:  {"party-fingerprint", 20},
	KindPoolDescriptor:    {"pool-descriptor", 32},
	KindWitnessCollection: {"witness-collection", 32},
	KindPendingRecord:     {"pending-record", 32},
	KindPartyIdentityDoc:  {"party-identity-document", 32},
	KindAuditEvent:        {"audit-event", 32},
	KindOwnerManifest:     {"owner-manifest", 32},
	KindRoleHistory:       {"role-history", 32},
	KindLabel:             {"label", 32},
	KindOwnerRecord:       {"owner-record", 32},
	KindWorkspaceSettings: {"workspace-settings", 32},
	KindProviderToken:     {"provider-token", 32},
}

// Kinds lists every kind in code order.
func Kinds() []Kind {
	out := make([]Kind, 0, len(kinds))
	for k := Kind(1); k < 255; k++ {
		if _, ok := kinds[k]; ok {
			out = append(out, k)
		}
	}
	return out
}

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool { _, ok := kinds[k]; return ok }

// String is the kind's name, as used in the text form.
func (k Kind) String() string {
	if i, ok := kinds[k]; ok {
		return i.name
	}
	return fmt.Sprintf("kind-%d", uint8(k))
}

// Size is the length in bytes of a hash of the kind, or 0 for an unknown kind.
func (k Kind) Size() int { return kinds[k].size }

// Errors of this package.
var (
	ErrBadRef  = errors.New("identity: malformed reference")
	ErrBadKind = errors.New("identity: the reference has another kind than required")
	ErrBadKey  = errors.New("identity: the verification key has the wrong length")
)

// Ref is a typed identity: a kind and the hash of that kind. The zero Ref is
// not a valid identity. Refs are comparable with ==.
type Ref struct {
	kind Kind
	n    uint8
	h    [32]byte
}

// NewRef builds a Ref from a kind and a hash of that kind's length. Use it to
// read a stored or received identity; use a constructor to derive one.
func NewRef(kind Kind, hash []byte) (Ref, error) {
	if !kind.Valid() {
		return Ref{}, fmt.Errorf("%w: unknown kind %d", ErrBadRef, uint8(kind))
	}
	if len(hash) != kind.Size() {
		return Ref{}, fmt.Errorf("%w: a %s is %d bytes, not %d", ErrBadRef, kind, kind.Size(), len(hash))
	}
	r := Ref{kind: kind, n: uint8(len(hash))}
	copy(r.h[:], hash)
	return r, nil
}

// IsZero reports whether r is the zero value.
func (r Ref) IsZero() bool { return r == Ref{} }

// Kind returns the kind.
func (r Ref) Kind() Kind { return r.kind }

// Hash returns a copy of the hash.
func (r Ref) Hash() []byte { return append([]byte(nil), r.h[:r.n]...) }

// Is reports whether r has kind k.
func (r Ref) Is(k Kind) bool { return r.kind == k && !r.IsZero() }

// Require returns ErrBadKind unless r has kind k.
func (r Ref) Require(k Kind) error {
	if !r.Is(k) {
		return fmt.Errorf("%w: wanted %s, got %s", ErrBadKind, k, r.kind)
	}
	return nil
}

// Compare orders references by kind code, then hash bytes.
func (r Ref) Compare(o Ref) int {
	if r.kind != o.kind {
		if r.kind < o.kind {
			return -1
		}
		return 1
	}
	return bytes.Compare(r.h[:r.n], o.h[:o.n])
}

// String is the text form, "<kind>:<hex hash>". It is for display and
// parsing; it is not a storage key.
func (r Ref) String() string {
	if r.IsZero() {
		return "none"
	}
	return r.kind.String() + ":" + hex.EncodeToString(r.h[:r.n])
}

// ParseRef reads the text form of String.
func ParseRef(s string) (Ref, error) {
	name, hx, ok := strings.Cut(s, ":")
	if !ok {
		return Ref{}, fmt.Errorf("%w: no kind in %q", ErrBadRef, s)
	}
	for k, i := range kinds {
		if i.name != name {
			continue
		}
		raw, err := hex.DecodeString(hx)
		if err != nil || hx != strings.ToLower(hx) {
			return Ref{}, fmt.Errorf("%w: hash is not lowercase hexadecimal", ErrBadRef)
		}
		return NewRef(k, raw)
	}
	return Ref{}, fmt.Errorf("%w: unknown kind %q", ErrBadRef, name)
}

// MarshalBinary is the fixed-length binary form: one length byte (the number
// of bytes that follow), the kind code, then the hash. The length is fixed
// per kind (1+size), so a reader that knows the kind can check it; the prefix
// lets a reader skip a reference it does not know (ADR 0011, sub-key info).
func (r Ref) MarshalBinary() ([]byte, error) {
	if r.IsZero() {
		return nil, fmt.Errorf("%w: the zero reference", ErrBadRef)
	}
	return append([]byte{r.n + 1, byte(r.kind)}, r.h[:r.n]...), nil
}

// ReadBinary reads one reference from the front of b and returns the rest.
func ReadBinary(b []byte) (Ref, []byte, error) {
	if len(b) < 2 {
		return Ref{}, nil, fmt.Errorf("%w: too short", ErrBadRef)
	}
	n := int(b[0])
	if n < 1 || len(b) < 1+n {
		return Ref{}, nil, fmt.Errorf("%w: length byte %d", ErrBadRef, n)
	}
	r, err := NewRef(Kind(b[1]), b[2:1+n])
	if err != nil {
		return Ref{}, nil, err
	}
	return r, b[1+n:], nil
}

// UnmarshalRef reads exactly one reference in the binary form.
func UnmarshalRef(b []byte) (Ref, error) {
	r, rest, err := ReadBinary(b)
	if err != nil {
		return Ref{}, err
	}
	if len(rest) != 0 {
		return Ref{}, fmt.Errorf("%w: trailing bytes", ErrBadRef)
	}
	return r, nil
}

func blake224(parts ...[]byte) []byte {
	h, _ := blake2b.New(28, nil)
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func blake256(parts ...[]byte) []byte {
	h, _ := blake2b.New256(nil)
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func vkey(vk []byte, want int) error {
	if len(vk) != want {
		return fmt.Errorf("%w: %d bytes, want %d", ErrBadKey, len(vk), want)
	}
	return nil
}

func mustRef(k Kind, h []byte) Ref {
	r, err := NewRef(k, h)
	if err != nil {
		panic(err) // a constructor produced the wrong length: a bug here
	}
	return r
}

// KeyHashOf is the identity of a payment, stake, pool cold, DRep, committee
// cold or hot, or policy key: Blake2b-224 of the 32-byte Ed25519
// verification key, the ledger's credential hash. It agrees with
// txbuild.HashKey and with the pool id of chain.PoolIDOf (tests).
//
// CIP-0129 adds a header byte before the hash in the bech32 form of a DRep
// and committee id only; that byte is not part of the identity. The status of
// CIP-0129 is unconfirmed (ADR 0010).
func KeyHashOf(vk []byte) (Ref, error) {
	if err := vkey(vk, 32); err != nil {
		return Ref{}, err
	}
	return mustRef(KindKeyHash, blake224(vk)), nil
}

// NativeScriptHashOf is the policy id of a native script: Blake2b-224 of the
// tag byte 0x00 and the script CBOR as given.
//
// UNCONFIRMED against the ledger specification (ADR 0010); it agrees with
// native.scriptHash, which is what the policy code computes today.
func NativeScriptHashOf(scriptCBOR []byte) Ref {
	return mustRef(KindScriptHash, blake224([]byte{0x00}, scriptCBOR))
}

// VRFKeyHashOf is the VRF key hash of a pool registration certificate:
// Blake2b-256 of the 32-byte VRF verification key.
//
// UNCONFIRMED against the ledger specification (ADR 0010); it agrees with
// pool.VrfHash.
func VRFKeyHashOf(vk []byte) (Ref, error) {
	if err := vkey(vk, 32); err != nil {
		return Ref{}, err
	}
	return mustRef(KindVRFKeyHash, blake256(vk)), nil
}

// KESKeyHashOf is the identity of a KES verification key, by project rule
// Blake2b-256 of the 32 raw bytes (the ledger has no credential hash of it).
// The key's number is a property of the key, not part of its identity.
//
// UNCONFIRMED against the ledger specification (ADR 0010).
func KESKeyHashOf(vk []byte) (Ref, error) {
	if err := vkey(vk, 32); err != nil {
		return Ref{}, err
	}
	return mustRef(KindKESKeyHash, blake256(vk)), nil
}

// BLSKeyHashOf is the identity of a BLS verification key, by project rule
// Blake2b-256 of the raw bytes. A compressed BLS12-381 key is 48 bytes (G1)
// or 96 bytes (G2); other lengths are refused.
//
// UNCONFIRMED against any CIP or ledger text (ADR 0010).
func BLSKeyHashOf(vk []byte) (Ref, error) {
	if len(vk) != 48 && len(vk) != 96 {
		return Ref{}, fmt.Errorf("%w: %d bytes, want 48 or 96", ErrBadKey, len(vk))
	}
	return mustRef(KindBLSKeyHash, blake256(vk)), nil
}

// CatalystKeyHashOf is the identity of a Catalyst voting key (CIP-36), by
// project rule Blake2b-256 of the 32 raw bytes.
//
// UNCONFIRMED against CIP-36 (ADR 0010).
func CatalystKeyHashOf(vk []byte) (Ref, error) {
	if err := vkey(vk, 32); err != nil {
		return Ref{}, err
	}
	return mustRef(KindCatalystKeyHash, blake256(vk)), nil
}

// CalidusKeyHashOf is the identity of a Calidus key: Blake2b-224 of the 32
// raw bytes, the hash a Calidus id carries after its header byte. It agrees
// with cose.CalidusIDBytes (test).
//
// UNCONFIRMED against CIP-88 and CIP-151 (ADR 0010).
func CalidusKeyHashOf(vk []byte) (Ref, error) {
	if err := vkey(vk, 32); err != nil {
		return Ref{}, err
	}
	return mustRef(KindCalidusKeyHash, blake224(vk)), nil
}

// TxIDOf is the transaction id: Blake2b-256 of the transaction body CBOR
// exactly as built or received. The body is never re-encoded, and this is
// exempt from the canonical check: a body in a non-canonical encoding keeps
// the identity of its bytes.
func TxIDOf(bodyCBOR []byte) Ref { return mustRef(KindTxID, blake256(bodyCBOR)) }

// FileHashOf is the identity of a metadata file (pool metadata, extended
// metadata, a governance anchor document): Blake2b-256 of the exact bytes,
// with no domain tag. It equals the on-chain metadata or anchor hash. The
// bytes are never parsed and re-serialised; exempt from the canonical check.
func FileHashOf(raw []byte) Ref { return mustRef(KindFileHash, blake256(raw)) }

// PayloadHashOf is the identity of a certificate, vote, governance action or
// witness in text-envelope form: Blake2b-256 of the bytes the cborHex field
// decodes to, exactly as given. The wrapper (type, description) is not part
// of it. Exempt from the canonical check.
func PayloadHashOf(cbor []byte) Ref { return mustRef(KindPayloadHash, blake256(cbor)) }

// PayloadHashOfEnvelope reads a cardano-cli text envelope (JSON) and returns
// the PayloadHashOf its cborHex field decodes to.
func PayloadHashOfEnvelope(envelopeJSON []byte) (Ref, error) {
	var e struct {
		CborHex *string `json:"cborHex"`
	}
	if err := json.Unmarshal(envelopeJSON, &e); err != nil || e.CborHex == nil {
		return Ref{}, fmt.Errorf("%w: not a text envelope with a cborHex", ErrBadRef)
	}
	raw, err := hex.DecodeString(*e.CborHex)
	if err != nil {
		return Ref{}, fmt.Errorf("%w: cborHex is not hexadecimal", ErrBadRef)
	}
	return PayloadHashOf(raw), nil
}

// EnvelopeHashOf is the identity of a party envelope (ADR 0005): Blake2b-256
// of the sealed bytes as sent or received. Exempt from the canonical check.
func EnvelopeHashOf(sealed []byte) Ref { return mustRef(KindEnvelopeHash, blake256(sealed)) }

// PartyFingerprintOf wraps the 20-byte party fingerprint of ADR 0005, which
// that record defines and which is unchanged here (party.FingerprintOf).
func PartyFingerprintOf(fp []byte) (Ref, error) { return NewRef(KindPartyFingerprint, fp) }

// PublicKeyOfCborHex is the one place that reads the 32-byte public key of a
// verification key text envelope's cborHex, for every key type a store can
// hold: the plain forms (`5820` and 32 bytes: payment, stake, pool cold, DRep,
// committee cold and hot, policy, Calidus, CIP-36 voting) and the extended
// BIP32 forms (`...ExtendedVerificationKey..._bip32`: `5840` and 64 bytes, the
// 32-byte public key followed by the 32-byte chain code, which every
// mnemonic-derived and hardware wallet has). The chain code is no part of the
// key: the credential hash is over the first 32 bytes, as cardano-cli computes
// it. The type name is not consulted, only the shape.
func PublicKeyOfCborHex(cborHex string) ([]byte, error) {
	raw, err := hex.DecodeString(cborHex)
	if err != nil {
		return nil, fmt.Errorf("%w: cborHex is not hexadecimal", ErrBadKey)
	}
	switch {
	case len(raw) == 34 && raw[0] == 0x58 && raw[1] == 0x20:
		return raw[2:], nil
	case len(raw) == 66 && raw[0] == 0x58 && raw[1] == 0x40:
		return raw[2:34], nil
	}
	return nil, fmt.Errorf("%w: not a 32-byte key or a 64-byte extended key", ErrBadKey)
}
