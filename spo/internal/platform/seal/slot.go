package seal

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

var defaultSealer = sealer{rand: rand.Reader}

// Slot kinds.
const (
	SlotPassphrase = "passphrase"
	SlotRecovery   = "recovery"
)

// KDFParams are the Argon2id parameters of a passphrase slot. They are stored
// with the slot and bound into its associated data.
type KDFParams struct {
	MemoryKiB uint32
	Passes    uint32
	Lanes     uint8
}

// DefaultKDF is what a new passphrase slot uses (ADR 0003): 256 MiB, 3 passes,
// 4 lanes.
func DefaultKDF() KDFParams { return KDFParams{MemoryKiB: 256 * 1024, Passes: 3, Lanes: 4} }

// MinKDF is the weakest parameter set the binary accepts when opening a slot,
// so a modified file cannot weaken the passphrase hash: 64 MiB, 3 passes, 1
// lane. (The ADR names no lane floor beyond "at least 1".)
func MinKDF() KDFParams { return KDFParams{MemoryKiB: 64 * 1024, Passes: 3, Lanes: 1} }

// kdfFloor is the enforced minimum. Only a _test.go file in this package
// assigns it, so non-test code cannot lower it.
var kdfFloor = MinKDF()

// Upper bounds, so a modified file cannot make us allocate without limit.
const (
	maxKDFMemoryKiB = 4 * 1024 * 1024 // 4 GiB
	maxKDFPasses    = 64
	maxKDFLanes     = 64
)

// ErrWeakKDF is returned for Argon2id parameters outside the accepted range.
var ErrWeakKDF = errors.New("seal: key-derivation parameters outside the accepted range")

func (p KDFParams) validate() error {
	if p.MemoryKiB < kdfFloor.MemoryKiB || p.Passes < kdfFloor.Passes || p.Lanes < kdfFloor.Lanes || p.Lanes < 1 ||
		p.MemoryKiB > maxKDFMemoryKiB || p.Passes > maxKDFPasses || p.Lanes > maxKDFLanes ||
		p.MemoryKiB < 8*uint32(p.Lanes) {
		return fmt.Errorf("%w: %d KiB, %d passes, %d lanes", ErrWeakKDF, p.MemoryKiB, p.Passes, p.Lanes)
	}
	return nil
}

// Slot is one wrapped copy of the master key.
//
//	ID       16 random bytes
//	Kind     SlotPassphrase or SlotRecovery
//	KDF      Argon2id parameters (passphrase slots only)
//	Salt     16 random bytes (passphrase slots only)
//	Nonce    24 random bytes
//	Wrapped  XChaCha20-Poly1305(master key) = 48 bytes
//
// The slot key is Argon2id(passphrase, Salt, KDF) for a passphrase slot and
// HKDF-SHA256(recovery key, info = labelRecoverySlot) for a recovery slot.
// Associated data is the canonical CBOR of
//
//	[format version, workspace id, slot id, slot kind, kdf]
//
// where kdf is ["argon2id", memory KiB, passes, lanes, salt] for a passphrase
// slot and ["hkdf-sha256", info label] for a recovery slot.
type Slot struct {
	ID      []byte
	Kind    string
	KDF     KDFParams
	Salt    []byte
	Nonce   []byte
	Wrapped []byte
}

func (s Slot) ad(workspaceID []byte) ([]byte, error) {
	if len(workspaceID) != IDSize || len(s.ID) != IDSize {
		return nil, fmt.Errorf("%w: ids must be %d bytes", ErrFormat, IDSize)
	}
	var kdf []any
	switch s.Kind {
	case SlotPassphrase:
		if len(s.Salt) != SaltSize {
			return nil, ErrFormat
		}
		kdf = []any{AlgKDF, uint64(s.KDF.MemoryKiB), uint64(s.KDF.Passes), uint64(s.KDF.Lanes), s.Salt}
	case SlotRecovery:
		kdf = []any{AlgHKDF, labelRecoverySlot}
	default:
		return nil, fmt.Errorf("%w: slot kind %q", ErrFormat, s.Kind)
	}
	return EncodeCanonical([]any{FormatVersion, workspaceID, s.ID, s.Kind, kdf})
}

// slotKey derives the slot's wrapping key from the credential.
func (s Slot) slotKey(cred *secret.Buffer) (*secret.Buffer, error) {
	switch s.Kind {
	case SlotPassphrase:
		if err := s.KDF.validate(); err != nil {
			return nil, err
		}
		if len(s.Salt) != SaltSize {
			return nil, ErrFormat
		}
		var out *secret.Buffer
		err := cred.Use(func(pw []byte) error {
			k := argon2.IDKey(pw, s.Salt, s.KDF.Passes, s.KDF.MemoryKiB, s.KDF.Lanes, KeySize)
			out = secret.Take(k) // wipes k
			return nil
		})
		return out, err
	case SlotRecovery:
		if cred.Len() != KeySize {
			return nil, fmt.Errorf("%w: recovery key must be %d bytes", ErrFormat, KeySize)
		}
		return hkdfKey(cred, labelRecoverySlot)
	}
	return nil, fmt.Errorf("%w: slot kind %q", ErrFormat, s.Kind)
}

// Unwrap recovers the master key using the passphrase (passphrase slot) or the
// raw 32-byte recovery key (recovery slot). A wrong credential and a modified
// slot both give ErrAuth; weak stored KDF parameters give ErrWeakKDF before any
// work is done.
func (s Slot) Unwrap(workspaceID []byte, cred *secret.Buffer) (*secret.Buffer, error) {
	if len(s.Nonce) != NonceSize || len(s.Wrapped) != KeySize+tagSize {
		return nil, ErrFormat
	}
	ad, err := s.ad(workspaceID)
	if err != nil {
		return nil, err
	}
	sk, err := s.slotKey(cred)
	if err != nil {
		return nil, err
	}
	defer sk.Destroy()
	return openToBuffer(sk, s.Nonce, s.Wrapped, ad)
}

// NewPassphraseSlot wraps master under a key derived from passphrase.
// Randomness is read in this order (pinned by the vectors): salt, nonce.
func NewPassphraseSlot(workspaceID, slotID []byte, master, passphrase *secret.Buffer, p KDFParams) (Slot, error) {
	return defaultSealer.newPassphraseSlot(workspaceID, slotID, master, passphrase, p)
}

func (s sealer) newPassphraseSlot(workspaceID, slotID []byte, master, passphrase *secret.Buffer, p KDFParams) (Slot, error) {
	if err := p.validate(); err != nil {
		return Slot{}, err
	}
	if passphrase.Len() == 0 {
		return Slot{}, fmt.Errorf("%w: empty passphrase", ErrFormat)
	}
	salt, err := readBytes(s.rand, SaltSize)
	if err != nil {
		return Slot{}, err
	}
	nonce, err := readBytes(s.rand, NonceSize)
	if err != nil {
		return Slot{}, err
	}
	slot := Slot{ID: slotID, Kind: SlotPassphrase, KDF: p, Salt: salt, Nonce: nonce}
	return slot, s.wrap(&slot, workspaceID, master, passphrase)
}

// NewRecoverySlot generates a 32-byte recovery key and wraps master under it.
// The recovery key is returned raw; show it once with EncodeRecoveryKey.
// Randomness is read in this order: recovery key, nonce.
func NewRecoverySlot(workspaceID, slotID []byte, master *secret.Buffer) (Slot, *secret.Buffer, error) {
	return defaultSealer.newRecoverySlot(workspaceID, slotID, master)
}

func (s sealer) newRecoverySlot(workspaceID, slotID []byte, master *secret.Buffer) (Slot, *secret.Buffer, error) {
	rk, err := readSecret(s.rand, KeySize)
	if err != nil {
		return Slot{}, nil, err
	}
	nonce, err := readBytes(s.rand, NonceSize)
	if err != nil {
		rk.Destroy()
		return Slot{}, nil, err
	}
	slot := Slot{ID: slotID, Kind: SlotRecovery, Nonce: nonce}
	if err := s.wrap(&slot, workspaceID, master, rk); err != nil {
		rk.Destroy()
		return Slot{}, nil, err
	}
	return slot, rk, nil
}

// wrap fills slot.Wrapped. slot.Nonce, Kind, ID (and KDF, Salt) are set.
func (s sealer) wrap(slot *Slot, workspaceID []byte, master, cred *secret.Buffer) error {
	ad, err := slot.ad(workspaceID)
	if err != nil {
		return err
	}
	sk, err := slot.slotKey(cred)
	if err != nil {
		return err
	}
	defer sk.Destroy()
	return sk.Use(func(k []byte) error {
		return master.Use(func(m []byte) error {
			if len(m) != KeySize {
				return ErrFormat
			}
			w, err := aeadSeal(k, slot.Nonce, m, ad)
			slot.Wrapped = w
			return err
		})
	})
}

// NewID returns IDSize random bytes (workspace, slot and record ids).
func NewID() ([]byte, error) { return readBytes(rand.Reader, IDSize) }
