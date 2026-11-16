package tailcat

import (
	"errors"
	"strings"

	"go4.org/mem"
	"tailscale.com/types/key"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// KeyLen is the size of a node private key and of a pre-shared key.
const KeyLen = 32

// NewKey returns a random 32-byte key in guarded memory, for a node private
// key or a pre-shared key. The caller stores it as a Secret record.
func NewKey() (*secret.Buffer, error) { return secret.TryNew(KeyLen) }

// nodePrivate builds tailcat's private key type from the buffer. tailcat
// keeps its keys in ordinary heap memory (types/key, wireguard-go): this copy
// cannot be wiped and lives as long as the server or client.
func nodePrivate(b *secret.Buffer) (key.NodePrivate, error) {
	var k key.NodePrivate
	if b.Len() != KeyLen {
		return k, errors.New("tailcat: a node key is 32 bytes")
	}
	err := b.Use(func(raw []byte) error { k = key.NodePrivateFromRaw32(mem.B(raw)); return nil })
	return k, err
}

// PublicKey is the node public key for a node private key buffer, to publish
// in the identity document (SPO-Xparty-INV-003).
func PublicKey(b *secret.Buffer) (party.NodeKey, error) {
	k, err := nodePrivate(b)
	if err != nil {
		return party.NodeKey{}, err
	}
	return party.NodeKey(k.Public().Raw32()), nil
}

func nodePublic(k party.NodeKey) key.NodePublic {
	return key.NodePublicFromRaw32(mem.B(k[:]))
}

// parsePeer reads a node key from TAILCAT_PEER_KEY's "nodekey:<hex>".
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
