package ports

import (
	"context"
	"errors"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
)

// Hardware wallet capabilities beyond the generic signer ports (ADR 0008).
// They exist because a device has needs a vault does not: the transaction
// body must be in the encoding the device accepts, a witness may carry
// declarations about the change outputs, and the device can be asked for a
// policy id. A use case that does not care types against the generic ports; a
// hardware signer implements these as well.

// ErrNoHardwareSigner means a key is held on a hardware wallet and no hardware
// signer is configured: the pinned cardano-hw-cli is missing from the release
// set or no session factory was wired. The message names what is missing.
var ErrNoHardwareSigner = errors.New("no hardware signer is configured: it needs the release set's cardano-hw-cli and a connected, unlocked device with the Cardano app open")

// HardwareCanonicalizer brings a transaction body to the form a hardware
// wallet accepts (CIP-21 canonical ordering and definite lengths; spec:
// SPO-Ctx-EXT-001, SPO-Ptx-EXT-005). The new body has a different id, so a use
// case calls Canonicalize BEFORE the body is fixed, shown to the operator or
// put in a collection (SPO-Xparty-INV-012), and signs only the result: a
// TxWitnesser witnesses the body it is given and refuses one that is not
// canonical.
type HardwareCanonicalizer interface {
	Signer
	// Canonicalize returns the body in hardware form and whether it changed.
	// The id is recomputed for a changed body. The Unrestricted option of
	// SPO-Ctx-IF-001 is the caller's explicit choice.
	Canonicalize(ctx context.Context, body txbuild.TxBody, opt HardwareTxOptions) (txbuild.TxBody, bool, error)
}

// HardwareTxOptions are what a device needs to know about one transaction.
type HardwareTxOptions struct {
	// Unrestricted allows `--allow-unrestricted-mode` (SPO-21b-PR-001): the
	// device signs a transaction with a certificate or vote it does not own.
	// Never implied; a use case sets it only after the operator agreed, and
	// puts custody.FeatUnrestricted in the Demand.
	Unrestricted bool
	// ChangeKeys are keys whose hardware signing files are declared as
	// `--change-output-key-file`, so the device recognises the change output
	// (SPO-Ptx-INV-009, SPO-01sendLovelaces-EXT-002).
	ChangeKeys []custody.KeyRef
}

// HardwareWitnesser is a TxWitnesser that takes the options of a device.
// Witness is WitnessWith with no options.
type HardwareWitnesser interface {
	TxWitnesser
	WitnessWith(ctx context.Context, key custody.KeyRef, body txbuild.TxBody, opt HardwareTxOptions) (txbuild.Witness, error)
}

// HardwarePolicyIDer asks the device for the id of a native policy script
// (SPO-10-EXT-005): the device shows the script's expiry slot. The script is
// the cardano-cli native script JSON.
type HardwarePolicyIDer interface {
	Signer
	PolicyID(ctx context.Context, key custody.Key[custody.Policy], script []byte) (string, error)
}

// ErrNotHardwareCanonical is returned by a hardware witness for a body that
// is not in hardware form. Canonical holds the bytes the tool proposes (the
// body's CBOR), so the caller can show what would change; the caller's way out
// is HardwareCanonicalizer.Canonicalize before the body is fixed, never to
// sign the changed body in place.
type ErrNotHardwareCanonical struct{ Canonical []byte }

func (e *ErrNotHardwareCanonical) Error() string {
	return "the transaction body is not in the canonical form a hardware wallet accepts (it would change under `cardano-hw-cli transaction transform`); canonicalise the body before it is fixed and shown"
}
