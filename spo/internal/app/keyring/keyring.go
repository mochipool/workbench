// Package keyring is the one place where a use case turns today's operator
// name for a key's owner into the key's identity (ADR 0010).
//
// The store is still keyed by name, so Resolve reads the stored verification
// key of (name, role) and applies the identity constructor of the role. A use
// case calls it once, at its edge, and works with key references afterwards.
// A later change replaces the name by labels over anchors: it re-implements
// Resolve and the use cases do not change.
package keyring

import (
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ErrUnresolved means the name has no verification key for the role.
var ErrUnresolved = ports.ErrNoVerificationKey

// Resolve returns the key reference of the role's key stored under the name.
// It refuses when the name has no verification key for the role.
func Resolve(r ports.NamedReader, role custody.Role, name string) (custody.KeyRef, error) {
	kinds, ok := ports.KeyKindsOf(role)
	if !ok {
		return custody.KeyRef{}, fmt.Errorf("a %s key has no stored form to resolve", role)
	}
	raw, err := r.Get(ports.NamedRef{Name: name, Kind: kinds.VKey})
	if errors.Is(err, ports.ErrNotFound) {
		return custody.KeyRef{}, fmt.Errorf("%w: the %s key of %q (%s)", ErrUnresolved, role, name, kinds.VKey)
	}
	if err != nil {
		return custody.KeyRef{}, err
	}
	id, err := ports.IdentityOfVKey(role, raw)
	if err != nil {
		return custody.KeyRef{}, fmt.Errorf("the %s key of %q: %w", role, name, err)
	}
	return custody.KeyRef{Role: role, Identity: id}, nil
}

// ResolveHeld is Resolve for a key this workspace must be able to sign with:
// held is false when neither a signing key nor a hardware signing file is
// stored under the name (the caller states its own refusal). Which signer
// answers for the key is decided later by the signer directory; nothing here
// says whether the key is in the vault or on a device.
func ResolveHeld(r ports.NamedReader, role custody.Role, name string) (key custody.KeyRef, held bool, err error) {
	kinds, ok := ports.KeyKindsOf(role)
	if !ok {
		return custody.KeyRef{}, false, fmt.Errorf("a %s key has no stored form to resolve", role)
	}
	if kinds.Hws != "" {
		if held, err = r.Exists(ports.NamedRef{Name: name, Kind: kinds.Hws}); err != nil {
			return custody.KeyRef{}, false, err
		}
	}
	if !held {
		if held, err = r.Exists(ports.NamedRef{Name: name, Kind: kinds.SKey}); err != nil {
			return custody.KeyRef{}, false, err
		}
	}
	if !held {
		return custody.KeyRef{}, false, nil
	}
	key, err = Resolve(r, role, name)
	return key, err == nil, err
}

// Held is ResolveHeld with the refusal of a use case: when neither a signing
// key nor a hardware signing file is stored it returns noKey, wrapped with the
// reference of the missing signing key.
func Held(r ports.NamedReader, role custody.Role, name string, noKey error) (custody.KeyRef, error) {
	key, held, err := ResolveHeld(r, role, name)
	if err != nil {
		return custody.KeyRef{}, err
	}
	if !held {
		kinds, _ := ports.KeyKindsOf(role)
		return custody.KeyRef{}, fmt.Errorf("%w: %s", noKey, ports.NamedRef{Name: name, Kind: kinds.SKey})
	}
	return key, nil
}
