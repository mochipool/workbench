package fsstore

import "github.com/mochipool/workbench/spo/internal/ports"

// The pending asset update is kept as `<txid>.asset-pending` until the
// transaction it belongs to is confirmed submitted (hazard H9).
func init() {
	layout[ports.AssetPending] = func(r ports.Ref) string { return r.Name + ".asset-pending" }
}
