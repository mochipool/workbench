package vaultkms

import (
	"fmt"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// Options are the client-side settings of both backends.
type Options struct {
	Vault VaultOptions
	KMS   KMSOptions
}

// Open returns the backend a reference names, with the client-side options.
// The caller has checked the reference against the local configuration (a
// slot's stored reference is only a claim); the options say how to
// authenticate, which CA to trust, and whether plain http to loopback or a
// private KMS or STS endpoint is allowed, which a reference alone never is.
func Open(ref ports.BackendRef, o Options) (ports.KeyWrapBackend, error) {
	switch ref.Kind {
	case ports.BackendVaultTransit:
		return NewVault(ref, o.Vault)
	case ports.BackendAWSKMS:
		return NewKMS(ref, o.KMS)
	}
	return nil, fmt.Errorf("%w: unknown backend kind %q", ports.ErrBackendConfig, ref.Kind)
}
