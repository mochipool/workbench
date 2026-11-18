//go:build !linux

package nodefiles

import (
	"context"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// IdentityCredential is the name of the systemd credential with the identity.
const IdentityCredential = "spo-node-age-identity"

// DeliverConfig is one start-up delivery.
type DeliverConfig struct {
	From, To, CredentialsDir string
	Derive                   ports.HotVKeyDeriver
}

// Deliver always refuses on this platform.
func (Writer) Deliver(context.Context, DeliverConfig) ([]string, error) { return nil, errLinuxOnly }
