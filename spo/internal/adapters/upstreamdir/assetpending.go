package upstreamdir

import "github.com/mochipool/workbench/spo/internal/ports"

// A pending update is kept as `<txid>.pending` until the transaction it
// belongs to is confirmed (hazard H9). The first version kept asset updates as
// `<txid>.asset-pending`; those files are still read.
func init() {
	layout[ports.PendingUpdate] = func(r ports.Ref) string { return r.Name + ".pending" }
	layout[ports.AssetPending] = func(r ports.Ref) string { return r.Name + ".asset-pending" }
}
