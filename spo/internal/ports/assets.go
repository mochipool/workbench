package ports

import (
	"context"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// The policy and asset artefacts (ports.PolicyVKey, PolicySKey, PolicyHwsFile,
// PolicyScript, PolicyID and AssetFile, SPO-Pfiles-OUT-031 to OUT-033) are
// declared with the other artefact families in workspace.go.

// AssetPending is an update of an asset record that waits for the confirmed
// submission of a queued mint or burn (hazard H9); the Name is the
// transaction id in hex. Not secret. See assets.Pending.
const AssetPending Kind = "asset-pending"

func init() { kinds[AssetPending] = kindInfo{} }

// PolicyIDCalculator gives the policy id of a native script: the blake2b-224
// hash of the script's CBOR with the native-script tag (what
// `cardano-cli transaction policyid` prints). The script is the JSON of a
// `.policy.script` file.
type PolicyIDCalculator interface {
	PolicyID(scriptJSON []byte) ([28]byte, error)
}

// PostSubmitHook is told when a transaction that was queued for a later
// submission has been confirmed submitted. The mint and burn use cases update
// the asset record at that moment and not when the transaction is queued
// (hazard H9, SPO-11a-MODE-002): what to apply travels with the queue entry
// (assets.PendingUpdates) and the executor of the queue calls the hook after
// a successful submit.
type PostSubmitHook interface {
	OnSubmitted(ctx context.Context, txid chain.TxID) error
}
