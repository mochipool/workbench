package envelope

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/btcsuite/btcd/btcutil/bech32"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// KeysLen is the size of the private key record: the Ed25519 seed (32 bytes)
// then the X25519 scalar (32 bytes).
const KeysLen = 64

// Private is a local party identity: its public part and its private keys.
type Private struct {
	keys *secret.Buffer // KeysLen bytes: Ed25519 seed || X25519 scalar
	id   party.Identity
}

// Generate makes a new identity, reading 64 random bytes from rand straight
// into guarded memory. node is the tailcat node public key to publish, or nil.
func Generate(label string, node *party.NodeKey, created time.Time, rand io.Reader) (*Private, error) {
	keys, err := secret.Fill(KeysLen, func(b []byte) error {
		_, err := io.ReadFull(rand, b)
		return err
	})
	if err != nil {
		return nil, err
	}
	var id party.Identity
	err = keys.Use(func(b []byte) error {
		var derr error
		id.Ed25519, id.X25519, derr = derivePublic(b)
		return derr
	})
	if err != nil {
		keys.Destroy()
		return nil, err
	}
	id.Label, id.Node, id.Created = label, node, created.UTC().Truncate(time.Second)
	if err := id.Validate(); err != nil {
		keys.Destroy()
		return nil, err
	}
	return &Private{keys: keys, id: id}, nil
}

// ErrKeyMismatch: the stored private keys are not those of the identity.
var ErrKeyMismatch = errors.New("envelope: private keys do not match the identity")

// NewPrivate wraps stored private keys with their public identity, and
// refuses when the keys do not derive the identity's public keys. It takes
// ownership of keys.
func NewPrivate(keys *secret.Buffer, id party.Identity) (*Private, error) {
	if keys.Len() != KeysLen {
		keys.Destroy()
		return nil, fmt.Errorf("%w: key record is %d bytes", ErrKeyMismatch, keys.Len())
	}
	var ed party.Ed25519Public
	var x party.X25519Public
	err := keys.Use(func(b []byte) error {
		var derr error
		ed, x, derr = derivePublic(b)
		return derr
	})
	if err != nil {
		keys.Destroy()
		return nil, err
	}
	if ed != id.Ed25519 || x != id.X25519 {
		keys.Destroy()
		return nil, ErrKeyMismatch
	}
	return &Private{keys: keys, id: id}, nil
}

// derivePublic computes the two public keys from the 64 private bytes. The
// expanded Ed25519 key is wiped; crypto/ecdh keeps a copy of the scalar in an
// ordinary heap value that we cannot wipe.
func derivePublic(b []byte) (ed party.Ed25519Public, x party.X25519Public, err error) {
	priv := ed25519.NewKeyFromSeed(b[:32])
	copy(ed[:], priv[32:])
	clear(priv)
	k, err := ecdh.X25519().NewPrivateKey(b[32:KeysLen])
	if err != nil {
		return ed, x, err
	}
	copy(x[:], k.PublicKey().Bytes())
	return ed, x, nil
}

// Identity is the public identity.
func (p *Private) Identity() party.Identity { return p.id }

// Fingerprint of the identity.
func (p *Private) Fingerprint() party.Fingerprint { return p.id.Fingerprint() }

// Keys returns the private key buffer so the caller can store it with
// Writer.PutSecret. The Private keeps ownership: do not destroy it.
func (p *Private) Keys() *secret.Buffer { return p.keys }

// Destroy wipes the private keys.
func (p *Private) Destroy() { p.keys.Destroy() }

// sign signs msg with the Ed25519 key. The expanded key is a copy in ordinary
// memory for the duration of the call and is wiped after.
func (p *Private) sign(msg []byte) (sig [64]byte, err error) {
	err = p.keys.Use(func(b []byte) error {
		priv := ed25519.NewKeyFromSeed(b[:32])
		copy(sig[:], ed25519.Sign(priv, msg))
		clear(priv)
		return nil
	})
	return sig, err
}

// ageIdentity builds the age identity from the X25519 scalar. age offers no
// constructor from raw bytes, only from its bech32 text, so the scalar goes
// through a Go string and into age's own struct. Both are ordinary heap
// memory that cannot be wiped, and live until the garbage collector reclaims
// them. The Private is built, used and dropped per Open to keep that short.
func (p *Private) ageIdentity() (*age.X25519Identity, error) {
	var id *age.X25519Identity
	err := p.keys.Use(func(b []byte) error {
		s, err := bech32.EncodeFromBase256("age-secret-key-", b[32:KeysLen])
		if err != nil {
			return err
		}
		id, err = age.ParseX25519Identity(strings.ToUpper(s))
		return err
	})
	return id, err
}

// ageRecipient builds the age recipient for a public X25519 key.
func ageRecipient(x party.X25519Public) (*age.X25519Recipient, error) {
	s, err := bech32.EncodeFromBase256("age", x[:])
	if err != nil {
		return nil, err
	}
	return age.ParseX25519Recipient(s)
}

// equalFP compares fingerprints in constant time.
func equalFP(a, b party.Fingerprint) bool { return subtle.ConstantTimeCompare(a[:], b[:]) == 1 }
