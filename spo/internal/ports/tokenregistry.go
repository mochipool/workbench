package ports

import (
	"context"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/tokenmeta"
)

// RegistryAttestation is an ed25519 signature and the public key that made it.
type RegistryAttestation struct {
	PublicKey [32]byte
	Signature [64]byte
}

// RegistrySigner signs the messages of a token-registry entry (CIP-26) with a
// minting-policy key. The signer opens the key itself and releases nothing
// but signatures. It is a capability of a signer whose profile claims
// custody.OpSignRegistryEntry for the policy role.
type RegistrySigner interface {
	Signer
	SignRegistryMessages(ctx context.Context, key custody.Key[custody.Policy], msgs [][32]byte) ([]RegistryAttestation, error)
}

// CheckRegistrySigner is the CheckSigner of this capability.
func CheckRegistrySigner(s Signer) error {
	p := s.Profile()
	for _, role := range custody.Roles() {
		for _, op := range p.Operations(role) {
			if op == custody.OpSignRegistryEntry {
				if _, ok := s.(RegistrySigner); !ok {
					return fmt.Errorf("signer %q claims %s but does not implement RegistrySigner", p.Name(), op)
				}
			}
		}
	}
	return nil
}

// Errors of the registry reader.
var (
	// ErrTokenNotFound: the registry has no entry for the subject (HTTP 404, or
	// an empty answer to a subject it does not know).
	ErrTokenNotFound = errors.New("the token registry has no entry for this subject")
	// ErrRegistryAnswer: the registry answered, but not with an entry this
	// program reads (not JSON, a wrong shape, over the size limit, another
	// subject, an HTTP status other than 200 and 404).
	ErrRegistryAnswer = errors.New("the token registry's answer is not a usable entry")
)

// TokenRegistryReader reads what a token-registry server serves for a subject
// (CIP-26: GET <server>/<subject>). A server that cannot be reached returns an
// error that is neither ErrTokenNotFound nor ErrRegistryAnswer, so "not found"
// and "unreachable" stay apart (SPO-12b port notes).
type TokenRegistryReader interface {
	// Registry names the server, for the operator and the audit log.
	Registry() string
	TokenMetadata(ctx context.Context, subject string) (tokenmeta.Entry, error)
}

// LogoFileReader reads the PNG file a record's `metaLogoPNG` names. The path
// is the operator's, outside the store (upstream reads it from the working
// directory), so the adapter that implements it is the file system's.
type LogoFileReader interface {
	ReadLogoFile(path string) ([]byte, error)
}
