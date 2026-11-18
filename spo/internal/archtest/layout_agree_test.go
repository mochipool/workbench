package archtest

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/mochipool/workbench/spo/internal/adapters/sqlitestore"
	"github.com/mochipool/workbench/spo/internal/domain/layout"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// The slot-set hash of domain/layout is reimplemented from the documented
// rule, because the layout may not import the store. This test lives here
// because only a test outside both layers may import both: it makes a real
// workspace, reads its keyslots and meta rows with plain SQL, builds the slots
// object from them, and requires the layout's hash to equal the value the
// store itself records (what a backup checkpoint calls the slot table hash).
// It also requires the slots object to round-trip with those rows.
//
// spec: SPO-Xlayout-OUT-010, SPO-Xlayout-OUT-011
func TestLayoutSlotSetHashAgreesWithTheStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ws.spo")
	rk, err := sqlitestore.Init(path, secret.Take([]byte("correct horse battery staple")))
	if err != nil {
		t.Fatal(err)
	}
	rk.Destroy()
	facts, err := sqlitestore.InspectBackupFacts(path)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var m layout.Meta
	var format int64
	var recPub []byte
	if err := db.QueryRow(`SELECT workspace_id, format_version, created_at, key_epoch, epoch_mac, policy, recovery_pub FROM meta WHERE id = 1`).
		Scan(&m.WorkspaceID, &format, &m.CreatedAt, &m.KeyEpoch, &m.EpochMAC, &m.Policy, &recPub); err != nil {
		t.Fatal(err)
	}
	m.StoreFormat = uint64(format)
	if recPub != nil {
		m.RecoveryPub = recPub
		m.RecoveryPubHash = layoutSHA256(recPub)
	}
	rows, err := db.Query(`SELECT id, kind, kdf_memory_kib, kdf_passes, kdf_lanes, salt, key_commit, nonce, wrapped_key, bound, rec_hash, factors FROM keyslots ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var slots []layout.Slot
	for rows.Next() {
		var s layout.Slot
		var mem, passes, lanes sql.NullInt64
		var salt, recHash, factors any // NULL is nil; an empty blob is a non-nil empty slice
		if err := rows.Scan(&s.ID, &s.Kind, &mem, &passes, &lanes, &salt, &s.KeyCommit, &s.Nonce, &s.WrappedKey, &s.Bound, &recHash, &factors); err != nil {
			t.Fatal(err)
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
		slots = append(slots, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(slots) < 2 {
		t.Fatalf("%d slots", len(slots))
	}
	got, err := layout.SlotSetHash(m.Policy, slots)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, facts.SlotTable) {
		t.Fatalf("the layout's slot-set hash %x is not the store's %x", got, facts.SlotTable)
	}
	stored, err := layout.EncodeSlotsObject(m.KeyEpoch, layout.SlotsObject{Meta: m, Slots: slots})
	if err != nil {
		t.Fatal(err)
	}
	epoch, back, err := layout.ParseSlotsObject(stored)
	if err != nil || !bytes.Equal(epoch, m.KeyEpoch) {
		t.Fatal(err)
	}
	again, err := layout.SlotSetHash(back.Meta.Policy, back.Slots)
	if err != nil || !bytes.Equal(again, facts.SlotTable) {
		t.Fatalf("the hash of the parsed slots object is not the store's: %v", err)
	}
}

func layoutSHA256(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

// blobOrNull keeps SQL NULL (nil) apart from an empty blob (non-nil, empty).
func blobOrNull(v any) []byte {
	b, ok := v.([]byte)
	if !ok {
		return nil
	}
	return append([]byte{}, b...)
}

// The layout mirrors two constants of the store because it may not import the
// platform: the record encoding a record body must carry, and the store format a
// slots object carries.
//
// spec: SPO-Xlayout-PRE-012, SPO-Xlayout-OUT-010
func TestLayoutMirrorsTheStoreConstants(t *testing.T) {
	if layout.RecordFormat != seal.RecordFormat || layout.StoreFormat != seal.StoreFormat {
		t.Fatalf("layout record format %d / store format %d, seal %d / %d", layout.RecordFormat, layout.StoreFormat, seal.RecordFormat, seal.StoreFormat)
	}
}
