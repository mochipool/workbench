package sqlitestore

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/layout"
	"github.com/mochipool/workbench/spo/internal/domain/unlock"
)

// layoutSlotsOf reads the meta row and the keyslots table of the file at path
// into the layout's slots object, with plain SQL.
func layoutSlotsOf(t *testing.T, path string) (layout.SlotsObject, []byte) {
	t.Helper()
	var so layout.SlotsObject
	err := withReadOnly(path, func(db *sql.DB) error {
		m := &so.Meta
		var format int64
		var recPub []byte
		if err := db.QueryRow(`SELECT workspace_id, format_version, created_at, key_epoch, epoch_mac, policy, recovery_pub FROM meta WHERE id = 1`).
			Scan(&m.WorkspaceID, &format, &m.CreatedAt, &m.KeyEpoch, &m.EpochMAC, &m.Policy, &recPub); err != nil {
			return err
		}
		m.StoreFormat = uint64(format)
		if recPub != nil {
			h := sha256.Sum256(recPub)
			m.RecoveryPub, m.RecoveryPubHash = recPub, h[:]
		}
		rows, err := db.Query(`SELECT id, kind, kdf_memory_kib, kdf_passes, kdf_lanes, salt, key_commit, nonce, wrapped_key, bound, rec_hash, factors FROM keyslots ORDER BY id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s layout.Slot
			var mem, passes, lanes sql.NullInt64
			var salt, recHash, factors any // NULL is nil; an empty blob is a non-nil empty slice
			if err := rows.Scan(&s.ID, &s.Kind, &mem, &passes, &lanes, &salt, &s.KeyCommit, &s.Nonce, &s.WrappedKey, &s.Bound, &recHash, &factors); err != nil {
				return err
			}
			s.Salt, s.RecHash, s.Factors = blobOrNull(salt), blobOrNull(recHash), blobOrNull(factors)
			for _, c := range []struct {
				n   sql.NullInt64
				dst **int64
			}{{mem, &s.KDFMemoryKiB}, {passes, &s.KDFPasses}, {lanes, &s.KDFLanes}} {
				if c.n.Valid {
					v := c.n.Int64
					*c.dst = &v
				}
			}
			so.Slots = append(so.Slots, s)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	facts, err := InspectBackupFacts(path)
	if err != nil {
		t.Fatal(err)
	}
	return so, facts.SlotTable
}

// The layout's slot-set hash and slots object against real workspaces of every
// policy: standard, and hardware and strict made with the fake authenticator.
// The layout reimplements the rule because it may not import this package.
//
// spec: SPO-Xlayout-OUT-010, SPO-Xlayout-OUT-011
func TestLayoutSlotSetHashAgreesWithTheStoreForEveryPolicy(t *testing.T) {
	paths := map[unlock.Policy]string{}
	_, std, _ := scratch(t)
	paths[unlock.Standard] = std
	paths[unlock.Hardware], _, _, _ = standardThenRotated(t, unlock.Hardware)
	paths[unlock.Strict], _, _, _ = standardThenRotated(t, unlock.Strict)
	for pol, path := range paths {
		so, want := layoutSlotsOf(t, path)
		if so.Meta.Policy != string(pol) {
			t.Fatalf("%s: the file says policy %s", pol, so.Meta.Policy)
		}
		got, err := layout.SlotSetHash(so.Meta.Policy, so.Slots)
		if err != nil {
			t.Fatalf("%s: %v", pol, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: the layout's slot-set hash %x is not the store's %x", pol, got, want)
		}
		stored, err := layout.EncodeSlotsObject(so.Meta.KeyEpoch, so)
		if err != nil {
			t.Fatalf("%s: %v", pol, err)
		}
		epoch, back, err := layout.ParseSlotsObject(stored)
		if err != nil || !bytes.Equal(epoch, so.Meta.KeyEpoch) {
			t.Fatalf("%s: %v", pol, err)
		}
		if again, err := layout.SlotSetHash(back.Meta.Policy, back.Slots); err != nil || !bytes.Equal(again, want) {
			t.Fatalf("%s: the parsed slots object hashes differently: %v", pol, err)
		}
		t.Logf("%s: %d slots, slots object %d bytes, hash agrees", pol, len(so.Slots), len(stored))
	}
}

// blobOrNull keeps SQL NULL (nil) apart from an empty blob (non-nil, empty).
func blobOrNull(v any) []byte {
	b, ok := v.([]byte)
	if !ok {
		return nil
	}
	return append([]byte{}, b...)
}
