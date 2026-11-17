package ports

import (
	"context"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// The policy and asset artefacts (ports.PolicyVKey, PolicySKey, PolicyHwsFile,
// PolicyScript, PolicyID and AssetFile, SPO-Pfiles-OUT-031 to OUT-033) are
// declared with the other artefact families in workspace.go.

// AssetPending is the first version's pending update of an asset record (hazard
// H9); the Name is the transaction id in hex. It is only read now: a workspace
// written by that version still settles, and nothing writes the kind. Not
// secret. See assets.Pending.
const AssetPending Kind = "asset-pending"

// PendingUpdate is an update of a local record (an asset record, or a pool's
// registration or retirement record) that waits for its transaction to be
// confirmed in a block; the Name is the transaction id in hex. Not secret. See
// assets.Pending and spec/extensions/Xconfirm.md.
const PendingUpdate Kind = "pending-update"

func init() {
	kinds[AssetPending] = kindInfo{}
	kinds[PendingUpdate] = kindInfo{}
}

// PolicyIDCalculator gives the policy id of a native script: the blake2b-224
// hash of the script's CBOR with the native-script tag (what
// `cardano-cli transaction policyid` prints). The script is the JSON of a
// `.policy.script` file.
type PolicyIDCalculator interface {
	PolicyID(scriptJSON []byte) ([28]byte, error)
}

// ConfirmedUpdateHook is told, by the command that runs `offline execute`, that
// a transaction whose queue entry carried an update (the `spoAssetPending`
// field) is confirmed in a block. update is that field's JSON. The hook
// applies the update when this workspace holds the pending record or the
// record the update names, and does nothing otherwise: the online machine
// usually holds neither. Confirmation also travels back to the offline machine
// in the history of the transfer file (assets.SettleFromBundle).
type ConfirmedUpdateHook interface {
	OnConfirmedUpdate(ctx context.Context, txid chain.TxID, update string) error
}
