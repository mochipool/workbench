package layoutexport

import (
	"crypto/sha256"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/layout"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// slotsOf is the slots object content of a snapshot: the meta row (without the
// transient cleanup_pending) and every keyslots row, with NULL kept apart from
// an empty value. The recovery public key hash is SHA-256 of the key.
func slotsOf(s *ports.Snapshot) (layout.SlotsObject, error) {
	m := s.Meta
	if m.FormatVersion < 0 {
		return layout.SlotsObject{}, fmt.Errorf("the store format %d is not one this layout carries", m.FormatVersion)
	}
	so := layout.SlotsObject{Meta: layout.Meta{
		WorkspaceID: m.WorkspaceID, StoreFormat: uint64(m.FormatVersion), Policy: m.Policy, KeyEpoch: m.KeyEpoch,
		EpochMAC: m.EpochMAC, CreatedAt: m.CreatedAt, RecoveryPub: m.RecoveryPub,
	}}
	if m.RecoveryPub != nil {
		h := sha256.Sum256(m.RecoveryPub)
		so.Meta.RecoveryPubHash = h[:]
	}
	for _, r := range s.Slots {
		so.Slots = append(so.Slots, layout.Slot{
			ID: r.ID, Kind: r.Kind, KDFMemoryKiB: r.KDFMemoryKiB, KDFPasses: r.KDFPasses, KDFLanes: r.KDFLanes,
			Salt: r.Salt, KeyCommit: r.KeyCommit, Nonce: r.Nonce, WrappedKey: r.WrappedKey, Bound: r.Bound,
			RecHash: r.RecHash, Factors: r.Factors,
		})
	}
	return so, nil
}
