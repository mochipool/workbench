package seal

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"

	"golang.org/x/crypto/argon2"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// Slots of the kinds fido2-hmac and composite, and the cold-role sub-key
// (ADR 0011, decisions 3 and 6). This file is pure: it reads no file and talks
// to no device. A slot of the kinds passphrase and recovery is in slot.go and
// is not touched by anything here.
//
// The slot key of the two new kinds is
//
//	IKM  = for each factor output in order: uint32_be(len) || output
//	salt = genesis nonce (IDSize bytes)
//	info = canonical CBOR of ["spo/slot-key", format version, slot id, slot kind,
//	                          [[factor kind, factor id], ...] in the same order]
//	key  = HKDF-SHA-256(IKM, salt, info), 32 bytes (RFC 5869)
//
// Every output is exactly KeySize bytes, so the length prefix is a constant
// 0x00000020 and a shifted byte changes the key; it stays because the rule is
// stated for any length and a later factor may differ.
//
// The associated data of the slot's wrapped master key is the canonical CBOR of
//
//	["spo/slot-ad", format version, genesis nonce, slot id, slot kind,
//	 [factor entry, ...], hash of the recovery public key, commitment]
//
// where a factor entry is [kind, id, params] and params is
//
//	passphrase: ["argon2id", memory KiB, passes, lanes, salt]
//	fido2:      [credential id, relying-party id, hmac-secret salt]
//	backend:    [key reference]
//	recovery:   []
//
// The commitment is slotCommit of the slot key, exactly as for the older kinds,
// and is compared before the AEAD.

// Slot kinds of ADR 0011 decision 3 that this file derives for.
const (
	SlotFIDO2HMAC = "fido2-hmac"
	SlotComposite = "composite"
)

// FactorKind is the code of a factor kind. Factors are ordered by (kind code,
// id) and the codes are in the associated data, so they are format.
type FactorKind uint64

const (
	FactorPassphrase FactorKind = 1 // the Argon2id output of a typed passphrase
	FactorRecovery   FactorKind = 2 // the 32 bytes of the recovery key
	FactorFIDO2      FactorKind = 3 // an hmac-secret output
	FactorBackend    FactorKind = 4 // the unwrapped secret B of a Vault or KMS backend
)

const (
	labelSlotKeyInfo = "spo/slot-key"
	labelSlotAD      = "spo/slot-ad"
	labelColdSubKey  = "cold-subkey"

	maxFactorID     = 64
	maxCredentialID = 1024 // CTAP 2.1 allows credential ids up to 1023 bytes
	maxRPID         = 255
	maxBackendRef   = 512
	maxFactors      = 8
)

// FactorParams is one factor of a slot: its kind, id and the parameters that
// are bound in the slot's associated data. Only the fields of its kind are
// read; the others must be empty.
type FactorParams struct {
	Kind FactorKind
	ID   []byte

	// FactorPassphrase.
	KDF     KDFParams
	KDFSalt []byte // SaltSize bytes

	// FactorFIDO2.
	CredentialID []byte
	RPID         string
	HMACSalt     []byte // KeySize bytes, drawn at enrolment

	// FactorBackend: the Vault or KMS key reference.
	BackendKeyRef string
}

// FactorRef is the (kind, id) pair that orders a factor and enters the key
// derivation.
type FactorRef struct {
	Kind FactorKind
	ID   []byte
}

// Ref returns the factor's (kind, id).
func (f FactorParams) Ref() FactorRef { return FactorRef{f.Kind, f.ID} }

func lessRef(a, b FactorRef) bool {
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	return bytes.Compare(a.ID, b.ID) < 0
}

// SortFactors puts factors in the canonical order (kind code, then id bytes,
// ascending). The caller builds a slot from the sorted list and stores that
// order; the functions below refuse any other.
func SortFactors(f []FactorParams) {
	sort.SliceStable(f, func(i, j int) bool { return lessRef(f[i].Ref(), f[j].Ref()) })
}

func (f FactorParams) validate() error {
	if len(f.ID) == 0 || len(f.ID) > maxFactorID {
		return fmt.Errorf("%w: factor id length", ErrFormat)
	}
	only := func(ok bool) error {
		if !ok {
			return fmt.Errorf("%w: parameters of another factor kind", ErrFormat)
		}
		return nil
	}
	noPass := f.KDF == (KDFParams{}) && len(f.KDFSalt) == 0
	noFIDO := len(f.CredentialID) == 0 && f.RPID == "" && len(f.HMACSalt) == 0
	switch f.Kind {
	case FactorPassphrase:
		if err := only(noFIDO && f.BackendKeyRef == ""); err != nil {
			return err
		}
		if err := f.KDF.validate(); err != nil {
			return err
		}
		if len(f.KDFSalt) != SaltSize {
			return fmt.Errorf("%w: passphrase factor salt", ErrFormat)
		}
	case FactorRecovery:
		return only(noPass && noFIDO && f.BackendKeyRef == "")
	case FactorFIDO2:
		if err := only(noPass && f.BackendKeyRef == ""); err != nil {
			return err
		}
		if len(f.CredentialID) == 0 || len(f.CredentialID) > maxCredentialID ||
			f.RPID == "" || len(f.RPID) > maxRPID || len(f.HMACSalt) != KeySize {
			return fmt.Errorf("%w: fido2 factor parameters", ErrFormat)
		}
	case FactorBackend:
		if err := only(noPass && noFIDO); err != nil {
			return err
		}
		if f.BackendKeyRef == "" || len(f.BackendKeyRef) > maxBackendRef {
			return fmt.Errorf("%w: backend key reference", ErrFormat)
		}
	default:
		return fmt.Errorf("%w: factor kind %d", ErrFormat, f.Kind)
	}
	return nil
}

func (f FactorParams) entry() []any {
	var params []any
	switch f.Kind {
	case FactorPassphrase:
		params = []any{AlgKDF, uint64(f.KDF.MemoryKiB), uint64(f.KDF.Passes), uint64(f.KDF.Lanes), f.KDFSalt}
	case FactorFIDO2:
		params = []any{f.CredentialID, f.RPID, f.HMACSalt}
	case FactorBackend:
		params = []any{f.BackendKeyRef}
	default:
		params = []any{}
	}
	return []any{uint64(f.Kind), f.ID, params}
}

// SlotSpec is everything of a fido2-hmac or composite slot that its associated
// data binds, except the commitment.
type SlotSpec struct {
	// FormatVersion is the store format version in force when the slot is made.
	// It is a parameter, not FormatVersion of this package, because the format
	// version of the new kinds is the store's to raise.
	FormatVersion uint64
	GenesisNonce  []byte // IDSize bytes
	SlotID        []byte // IDSize bytes
	Kind          string // SlotFIDO2HMAC or SlotComposite
	// Factors are in the canonical order (SortFactors), strictly ascending.
	Factors []FactorParams
	// RecoveryPubKeyHash binds the recovery public key (decision 6): MACSize
	// bytes, or empty in every slot of a strict workspace, which has no recovery
	// key (domain/unlock enforces which).
	RecoveryPubKeyHash []byte
}

// RecoveryPubKeyHash is the value bound in every slot for a recovery public
// key: SHA-256 of its encoding.
func RecoveryPubKeyHash(pub []byte) []byte {
	h := sha256.Sum256(pub)
	return h[:]
}

func (s SlotSpec) validate() error {
	if n := len(s.RecoveryPubKeyHash); len(s.GenesisNonce) != IDSize || len(s.SlotID) != IDSize || (n != 0 && n != MACSize) {
		return fmt.Errorf("%w: genesis nonce, slot id or recovery key hash length", ErrFormat)
	}
	switch s.Kind {
	case SlotFIDO2HMAC:
		if len(s.Factors) != 1 || s.Factors[0].Kind != FactorFIDO2 {
			return fmt.Errorf("%w: a %s slot has exactly one fido2 factor", ErrFormat, s.Kind)
		}
	case SlotComposite:
		if len(s.Factors) < 2 {
			return fmt.Errorf("%w: a composite slot has at least two factors", ErrFormat)
		}
	default:
		return fmt.Errorf("%w: slot kind %q", ErrFormat, s.Kind)
	}
	if len(s.Factors) > maxFactors {
		return fmt.Errorf("%w: too many factors", ErrFormat)
	}
	for i, f := range s.Factors {
		if err := f.validate(); err != nil {
			return err
		}
		if i > 0 && !lessRef(s.Factors[i-1].Ref(), f.Ref()) {
			return fmt.Errorf("%w: factors are not in canonical order or repeat", ErrFormat)
		}
	}
	return nil
}

// AD returns the associated data of the slot with the given commitment.
func (s SlotSpec) AD(commit []byte) ([]byte, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if len(commit) != MACSize {
		return nil, fmt.Errorf("%w: slot commitment", ErrFormat)
	}
	entries := make([]any, len(s.Factors))
	for i, f := range s.Factors {
		entries[i] = f.entry()
	}
	return EncodeCanonical([]any{labelSlotAD, s.FormatVersion, s.GenesisNonce, s.SlotID, s.Kind, entries, s.RecoveryPubKeyHash, commit})
}

// DeriveKey derives the slot key from the factor outputs, given in the order
// of s.Factors. Each must be exactly KeySize bytes.
func (s SlotSpec) DeriveKey(outputs []*secret.Buffer) (*secret.Buffer, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	refs := make([]FactorRef, len(s.Factors))
	for i, f := range s.Factors {
		refs[i] = f.Ref()
	}
	return deriveSlotKey(s.FormatVersion, s.GenesisNonce, s.SlotID, s.Kind, refs, outputs)
}

// deriveSlotKey is the derivation of decision 3. It keeps the order it is
// given and does not check it (SlotSpec.validate does), so the tests can show
// that a different order is a different key.
func deriveSlotKey(version uint64, genesisNonce, slotID []byte, kind string, refs []FactorRef, outputs []*secret.Buffer) (*secret.Buffer, error) {
	if len(refs) == 0 || len(refs) != len(outputs) || len(genesisNonce) != IDSize {
		return nil, fmt.Errorf("%w: factor list", ErrFormat)
	}
	list := make([]any, len(refs))
	for i, r := range refs {
		list[i] = []any{uint64(r.Kind), r.ID}
	}
	info, err := EncodeCanonical([]any{labelSlotKeyInfo, version, slotID, kind, list})
	if err != nil {
		return nil, err
	}
	ikm, err := secret.Fill(len(outputs)*(4+KeySize), func(dst []byte) error {
		off := 0
		for _, o := range outputs {
			if o.Len() != KeySize {
				return fmt.Errorf("%w: a factor output must be %d bytes", ErrFormat, KeySize)
			}
			binary.BigEndian.PutUint32(dst[off:], uint32(KeySize))
			off += 4
			if err := o.Use(func(b []byte) error { copy(dst[off:], b); return nil }); err != nil {
				return err
			}
			off += KeySize
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	defer ikm.Destroy()
	var k []byte
	if err := ikm.Use(func(b []byte) error {
		var herr error
		k, herr = hkdf.Key(sha256.New, b, genesisNonce, string(info), KeySize)
		return herr
	}); err != nil {
		return nil, err
	}
	return secret.TryTake(k) // wipes k
}

// FactorSlot is a fido2-hmac or composite slot: the master key wrapped under
// the slot key.
type FactorSlot struct {
	Spec    SlotSpec
	Commit  []byte // MACSize bytes
	Nonce   []byte // NonceSize bytes
	Wrapped []byte // KeySize + tag bytes
}

// NewFactorSlot wraps master under the key derived from outputs (the order of
// spec.Factors). Randomness is read once: the nonce.
func NewFactorSlot(spec SlotSpec, outputs []*secret.Buffer, master *secret.Buffer) (FactorSlot, error) {
	return defaultSealer.newFactorSlot(spec, outputs, master)
}

func (s sealer) newFactorSlot(spec SlotSpec, outputs []*secret.Buffer, master *secret.Buffer) (FactorSlot, error) {
	sk, err := spec.DeriveKey(outputs)
	if err != nil {
		return FactorSlot{}, err
	}
	defer sk.Destroy()
	nonce, err := readBytes(s.rand, NonceSize)
	if err != nil {
		return FactorSlot{}, err
	}
	fs := FactorSlot{Spec: spec, Nonce: nonce}
	err = sk.Use(func(k []byte) error {
		fs.Commit = slotCommit(k)
		ad, err := spec.AD(fs.Commit)
		if err != nil {
			return err
		}
		return master.Use(func(m []byte) error {
			if len(m) != KeySize {
				return ErrFormat
			}
			w, err := aeadSeal(k, nonce, m, ad)
			fs.Wrapped = w
			return err
		})
	})
	if err != nil {
		return FactorSlot{}, err
	}
	return fs, nil
}

// Unwrap recovers the master key from the factor outputs. A wrong output, a
// changed parameter (another salt, credential id, recovery key hash, factor
// order) and a modified slot all give ErrAuth; the commitment is compared
// before the AEAD, as for the older kinds.
func (fs FactorSlot) Unwrap(outputs []*secret.Buffer) (*secret.Buffer, error) {
	if len(fs.Nonce) != NonceSize || len(fs.Wrapped) != KeySize+tagSize {
		return nil, ErrFormat
	}
	sk, err := fs.Spec.DeriveKey(outputs)
	if err != nil {
		return nil, err
	}
	defer sk.Destroy()
	var got []byte
	if err := sk.Use(func(k []byte) error { got = slotCommit(k); return nil }); err != nil {
		return nil, err
	}
	if !hmac.Equal(got, fs.Commit) {
		return nil, ErrAuth
	}
	ad, err := fs.Spec.AD(fs.Commit)
	if err != nil {
		return nil, err
	}
	return openToBuffer(sk, fs.Nonce, fs.Wrapped, ad)
}

// PassphraseFactorOutput is the output of a passphrase factor: Argon2id over
// the typed bytes with the factor's own salt and parameters (the same function
// as a passphrase slot's key, ADR 0003). The parameters are checked against the
// floors and ceilings first.
func PassphraseFactorOutput(passphrase *secret.Buffer, salt []byte, p KDFParams) (*secret.Buffer, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	if len(salt) != SaltSize || passphrase.Len() == 0 {
		return nil, fmt.Errorf("%w: passphrase factor", ErrFormat)
	}
	var k []byte
	if err := passphrase.Use(func(pw []byte) error {
		k = argon2.IDKey(pw, salt, p.Passes, p.MemoryKiB, p.Lanes, KeySize)
		return nil
	}); err != nil {
		return nil, err
	}
	return secret.TryTake(k)
}

// DeriveColdSubKey is the sub-key of a cold-role record (decision 6):
//
//	sub-key = HKDF-SHA-256(IKM = factor output, salt = genesis nonce,
//	                       info = uint32_be(format version) || "cold-subkey" ||
//	                              len(identity) as one byte || identity)
//
// The factor output is KeySize bytes (an hmac-secret output, a backend-unwrapped
// secret, or the Argon2id output of the sub-key passphrase). The record identity
// is the Blake2b-224 or Blake2b-256 hash of ADR 0010, taken as bytes.
func DeriveColdSubKey(factorOutput *secret.Buffer, genesisNonce []byte, formatVersion uint32, recordIdentity []byte) (*secret.Buffer, error) {
	if factorOutput.Len() != KeySize || len(genesisNonce) != IDSize {
		return nil, fmt.Errorf("%w: sub-key input lengths", ErrFormat)
	}
	if n := len(recordIdentity); n != 28 && n != 32 {
		return nil, fmt.Errorf("%w: a record identity is 28 or 32 bytes", ErrFormat)
	}
	info := binary.BigEndian.AppendUint32(nil, formatVersion)
	info = append(info, labelColdSubKey...)
	info = append(info, byte(len(recordIdentity)))
	info = append(info, recordIdentity...)
	var k []byte
	if err := factorOutput.Use(func(b []byte) error {
		var herr error
		k, herr = hkdf.Key(sha256.New, b, genesisNonce, string(info), KeySize)
		return herr
	}); err != nil {
		return nil, err
	}
	return secret.TryTake(k)
}

// DeriveColdSubKeyComposite is the sub-key of a cold-role record under a Vault
// or KMS composite (decision 6, third bullet): the IKM is the ordered factor
// outputs, each as uint32_be(len) || output, the order and framing of decision 3,
// so a backend operator alone and a stolen client alone both derive nothing.
// Salt and info are those of DeriveColdSubKey. refs must be in canonical order
// and distinct, with at least two factors, as in a composite slot.
func DeriveColdSubKeyComposite(refs []FactorRef, outputs []*secret.Buffer, genesisNonce []byte, formatVersion uint32, recordIdentity []byte) (*secret.Buffer, error) {
	if len(refs) < 2 || len(refs) != len(outputs) || len(refs) > maxFactors || len(genesisNonce) != IDSize {
		return nil, fmt.Errorf("%w: sub-key factor list", ErrFormat)
	}
	for i, r := range refs {
		if len(r.ID) == 0 || len(r.ID) > maxFactorID || (i > 0 && !lessRef(refs[i-1], r)) {
			return nil, fmt.Errorf("%w: factors are not in canonical order or repeat", ErrFormat)
		}
	}
	if n := len(recordIdentity); n != 28 && n != 32 {
		return nil, fmt.Errorf("%w: a record identity is 28 or 32 bytes", ErrFormat)
	}
	ikm, err := frameOutputs(outputs)
	if err != nil {
		return nil, err
	}
	defer ikm.Destroy()
	var k []byte
	if err := ikm.Use(func(b []byte) error {
		var herr error
		k, herr = hkdf.Key(sha256.New, b, genesisNonce, coldInfo(formatVersion, recordIdentity), KeySize)
		return herr
	}); err != nil {
		return nil, err
	}
	return secret.TryTake(k)
}

func coldInfo(formatVersion uint32, recordIdentity []byte) string {
	info := binary.BigEndian.AppendUint32(nil, formatVersion)
	info = append(info, labelColdSubKey...)
	info = append(info, byte(len(recordIdentity)))
	return string(append(info, recordIdentity...))
}

// frameOutputs builds the IKM of decision 3 in guarded memory.
func frameOutputs(outputs []*secret.Buffer) (*secret.Buffer, error) {
	return secret.Fill(len(outputs)*(4+KeySize), func(dst []byte) error {
		off := 0
		for _, o := range outputs {
			if o.Len() != KeySize {
				return fmt.Errorf("%w: a factor output must be %d bytes", ErrFormat, KeySize)
			}
			binary.BigEndian.PutUint32(dst[off:], uint32(KeySize))
			off += 4
			if err := o.Use(func(b []byte) error { copy(dst[off:], b); return nil }); err != nil {
				return err
			}
			off += KeySize
		}
		return nil
	})
}
