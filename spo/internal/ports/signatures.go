package ports

import (
	"context"
	"fmt"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
)

// Message, Catalyst and pool-key registration signing (ADR 0008). Each is a
// narrow capability of a Signer; a signer implements only those its profile
// claims, and CheckSignatureSigner enforces that.

// The artefact kinds of the Calidus key and the voting key (CalidusVKey,
// VotingSKey, VoteRegistration, CalidusRegistration, CatalystQRCode, ...) are
// declared in workspace.go; the registration files are named `<pool>_<ts>`
// and `<stake>_<ts>` (SPO-Pfiles-OUT-035, SPO-Pfiles-OUT-036).

// ---- key derivation -----------------------------------------------------------------

// CalidusKeyDeriver derives the Calidus pool key pair (CIP-151) from a
// mnemonic. cardano-signer's `keygen --path calidus` derives along
// 1852H/1815H/<account>H/0/<index>, the payment path (observed: the key for
// the public test phrase equals its payment key 0/0). Upstream has no
// random-seed path, so there is no CalidusKeyGenerator: every Calidus key
// comes from a mnemonic, fresh or given. The mnemonic is the normalised
// phrase; the deriver does not keep it.
type CalidusKeyDeriver interface {
	DeriveCalidus(ctx context.Context, mnemonic *Secret, account, index uint32) (KeyPair, error)
}

// VotingKeyDeriver derives the Catalyst (CIP-36) voting key pair along
// 1694H/1815H/<account>H/0/<index> and gives its bech32 `cvote_vk` public key
// text (the content of `.voting.pkey`, without the newline).
type VotingKeyDeriver interface {
	DeriveVoting(ctx context.Context, mnemonic *Secret, account, index uint32) (KeyPair, string, error)
}

// ---- signing ----------------------------------------------------------------------

// MessageRequest asks for a CIP-8 message signature. Address is the raw
// address the message is signed for (it goes into the protected header and
// must belong to the key); Hashed signs the blake2b-224 hash of Payload.
type MessageRequest struct {
	Key     custody.KeyRef
	Address []byte
	Payload []byte
	Hashed  bool
}

// SignedMessage is the COSE_Sign1 and COSE_Key of a CIP-8 signature, as the
// bytes (the CIP-30 `signData` result is their hex).
type SignedMessage struct {
	Sign1 []byte
	Key   []byte
}

// MessageSigner signs CIP-8 messages with a payment or stake key.
type MessageSigner interface {
	Signer
	SignMessage(ctx context.Context, req MessageRequest) (SignedMessage, error)
}

// MessageVerifier verifies CIP-8 messages. It needs no key, but a hardware
// wallet's message is checked by the same adapter that made it, so it is a
// capability of a signer.
type MessageVerifier interface {
	Signer
	VerifyMessage(ctx context.Context, sign1, key, external []byte, checkAddress bool) (cose.Verified, error)
}

// Registration is a signed registration: the metadata CBOR (the content of a
// `.cbor` metadata file for the send transaction) and its JSON form.
type Registration struct {
	CBOR []byte
	JSON string
}

// Cip36Signer signs a Catalyst registration with a stake key. The signer
// checks that the key is the registration's stake key.
type Cip36Signer interface {
	Signer
	SignCip36(ctx context.Context, key custody.Key[custody.Stake], reg cose.Cip36) (Registration, error)
}

// Cip88Signer signs a Calidus registration with the pool cold key. The signer
// checks that the key's hash is the registration's pool id.
type Cip88Signer interface {
	Signer
	SignCip88(ctx context.Context, key custody.Key[custody.PoolCold], reg cose.Cip88) (Registration, error)
}

// CheckSignatureSigner is the CheckSigner of these capabilities: a signer
// whose profile claims one must implement its interface.
func CheckSignatureSigner(s Signer) error {
	p := s.Profile()
	claims := map[custody.Operation]bool{}
	for _, role := range custody.Roles() {
		for _, op := range p.Operations(role) {
			claims[op] = true
		}
	}
	if claims[custody.OpSignMessage] {
		if _, ok := s.(MessageSigner); !ok {
			return fmt.Errorf("signer %q claims %s but does not implement MessageSigner", p.Name(), custody.OpSignMessage)
		}
	}
	if claims[custody.OpSignCip36] {
		if _, ok := s.(Cip36Signer); !ok {
			return fmt.Errorf("signer %q claims %s but does not implement Cip36Signer", p.Name(), custody.OpSignCip36)
		}
	}
	if claims[custody.OpSignCip88] {
		if _, ok := s.(Cip88Signer); !ok {
			return fmt.Errorf("signer %q claims %s but does not implement Cip88Signer", p.Name(), custody.OpSignCip88)
		}
	}
	if claims[custody.OpSignText] {
		if _, ok := s.(TextSigner); !ok {
			return fmt.Errorf("signer %q claims %s but does not implement TextSigner", p.Name(), custody.OpSignText)
		}
	}
	return nil
}

// ---- reading Calidus registrations ----------------------------------------------------

// CalidusFilter selects registrations: by Calidus public key (hex), Calidus
// id (bech32) or pool id (bech32). All empty lists every registered pool's.
type CalidusFilter struct {
	PubKeyHex string
	IDBech    string
	PoolBech  string
}

// CalidusEntry is one registration as a provider reports it
// (SPO-15-OUT-005).
type CalidusEntry struct {
	BlockTime time.Time // zero when the provider gave none
	PoolBech  string
	IDBech    string
	PubKeyHex string
	Nonce     uint64
	HasNonce  bool
	Epoch     uint64
	HasEpoch  bool
	TxHash    string
}

// CalidusKeyReader reads the Calidus keys registered on chain for registered
// pools, oldest first. No entry is an empty answer, not an error
// (SPO-15-PRE-007 port note); a provider that fails returns an error.
type CalidusKeyReader interface {
	ChainSource
	CalidusKeys(ctx context.Context, f CalidusFilter) ([]CalidusEntry, error)
}
