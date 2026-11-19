package stream

import (
	"crypto/rand"
	"errors"
	"strings"

	"go4.org/mem"
	"tailscale.com/types/key"

	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// clearPriv overwrites a node private key: the dialer's copy at Close.
func clearPriv(k *key.NodePrivate) { *k = key.NodePrivate{} }

// KeyLen is the size of a node private key and of a pre-shared key.
const KeyLen = 32

// SecretReader hands the bytes of a secret to use, which must not keep them. A
// platform/secret Buffer's Use method is one, so the wiring passes `buf.Use`
// and this package never imports the secret buffers: the relay binary must not
// link them (ADR 0013 decision 1, SPO-Xmailbox-SEC-009). tailcat itself keeps
// ordinary heap copies of the node key and the pre-shared key that cannot be
// wiped; this is only about how the keys reach it.
type SecretReader func(use func(raw []byte) error) error

// SecretBytes is a SecretReader over a copy of b. The copy is not wiped.
func SecretBytes(b []byte) SecretReader {
	c := append([]byte(nil), b...)
	return func(use func([]byte) error) error { return use(c) }
}

// KeyBytes is a SecretReader over a 32-byte key.
func KeyBytes(k [KeyLen]byte) SecretReader { return SecretBytes(k[:]) }

// RandomKey returns a random 32-byte key, for a node private key or a
// pre-shared key. The caller stores it.
func RandomKey() ([KeyLen]byte, error) {
	var k [KeyLen]byte
	_, err := rand.Read(k[:])
	return k, err
}

var errKeyLen = errors.New("tailcat stream: a node key and a pre-shared key are 32 bytes")

// read32 copies a 32-byte secret out of r into an array the caller owns.
func read32(r SecretReader) (k [KeyLen]byte, err error) {
	if r == nil {
		return k, errors.New("tailcat stream: a key is required")
	}
	err = r(func(raw []byte) error {
		if len(raw) != KeyLen {
			return errKeyLen
		}
		copy(k[:], raw)
		return nil
	})
	return k, err
}

func nodePrivate(r SecretReader) (key.NodePrivate, error) {
	raw, err := read32(r)
	defer clear(raw[:]) // the key.NodePrivate below holds its own copy
	if err != nil {
		return key.NodePrivate{}, err
	}
	return key.NodePrivateFromRaw32(mem.B(raw[:])), nil
}

// PublicKey is the node public key for a node private key: what an access
// list names and a peer pins.
func PublicKey(r SecretReader) (party.NodeKey, error) {
	k, err := nodePrivate(r)
	if err != nil {
		return party.NodeKey{}, err
	}
	return party.NodeKey(k.Public().Raw32()), nil
}

func nodePublic(k party.NodeKey) key.NodePublic {
	return key.NodePublicFromRaw32(mem.B(k[:]))
}

// parsePeer reads a node key from tailcat's TAILCAT_PEER_KEY="nodekey:<hex>".
func parsePeer(s string) (party.NodeKey, bool) {
	s, ok := strings.CutPrefix(s, "TAILCAT_PEER_KEY=")
	if !ok {
		return party.NodeKey{}, false
	}
	var k key.NodePublic
	if k.UnmarshalText([]byte(s)) != nil || k.IsZero() {
		return party.NodeKey{}, false
	}
	return party.NodeKey(k.Raw32()), true
}
