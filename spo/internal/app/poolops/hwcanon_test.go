package poolops

import (
	"context"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// idCanon is a hardware canonicalizer for a body that is already canonical: a
// pool registration with a hardware slot needs one wired even when the slot is
// signed later (txflow.ErrNoCanonicalizer), because the body is fixed now.
type idCanon struct{}

func (idCanon) Profile() custody.Profile { return custody.NewProfile("test canonicalizer") }
func (idCanon) Canonicalize(_ context.Context, b txbuild.TxBody, _ ports.HardwareTxOptions) (txbuild.TxBody, bool, error) {
	return b, false, nil
}
