package sqlitestore

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// EXPORT MATERIAL (ADR 0012 stage 3, work package 3; spec/extensions/Xlayout.md).
//
// TakeExport is ReadSnapshot that also hands back what the layout exporter needs
// the workspace keys for, taken from the same verified private copy under the
// one presentation of the credential: an object sealer (K_obj and K_nonce, held
// in guarded memory until Close), the anchor and number of every record (read
// from its owner blob, which is authenticated against the workspace, the record
// id and the kind; the lookup tag is recomputed from them and must equal the
// row's), and the checkpoint key record when there is one. No record payload is
// decrypted and no cold-role factor is asked for.

// ExportMaterial is what TakeExport returns. The caller closes Sealer.
type ExportMaterial struct {
	Snapshot ports.Snapshot
	Facts    SnapshotFacts
	// Refs[i] belongs to Snapshot.Records[i].
	Refs   []ports.RecordRef
	Sealer ports.ObjectSealer
	// CheckpointKey is the checkpoint key record as stored (a public key, a
	// credential id and dates); nil when the workspace has none.
	CheckpointKey []byte
}

type exportSealer struct {
	s     *seal.ObjectSealer
	epoch []byte
	ws    []byte
}

func (e *exportSealer) Epoch() []byte       { return append([]byte(nil), e.epoch...) }
func (e *exportSealer) WorkspaceID() []byte { return append([]byte(nil), e.ws...) }
func (e *exportSealer) Seal(body []byte) ([]byte, error) {
	return e.s.Seal(e.epoch, e.ws, body)
}
func (e *exportSealer) Close() { e.s.Close() }

// exportRefHook lets a test change a recomputed lookup tag.
var exportRefHook func(tag *[]byte)

// TakeExport reads the verified snapshot of the workspace file at path and the
// material of ExportMaterial. See ReadSnapshot for what is verified and refused.
func TakeExport(ctx context.Context, path string, c SnapshotCredential) (*ExportMaterial, error) {
	var out ExportMaterial
	var ids [][]byte
	then := func(s *Store) (err error) {
		sealer, err := s.keys.ObjectSealer()
		if err != nil {
			return err
		}
		defer func() {
			// the sealer is destroyed on an error and on a panic (which goes on)
			if r := recover(); r != nil {
				sealer.Close()
				panic(r)
			}
			if err != nil {
				sealer.Close()
			}
		}()
		out.Sealer = &exportSealer{s: sealer, epoch: append([]byte(nil), s.epoch...), ws: append([]byte(nil), s.ws...)}
		rows, qerr := s.db.QueryContext(ctx, `SELECT id, lookup_tag, kind, owner_sealed FROM records ORDER BY id`)
		if qerr != nil {
			return qerr
		}
		defer rows.Close()
		for rows.Next() {
			var id, tag, owner []byte
			var kind string
			if err := rows.Scan(&id, &tag, &kind, &owner); err != nil {
				return err
			}
			k := ports.Kind(kind)
			if !k.Known() {
				return fmt.Errorf("a record has the kind %q, which this version does not know; it cannot be exported", kind)
			}
			anchor, num, err := s.keys.OpenOwnerRef(s.ws, id, kind, seal.SealedRecord{Owner: owner})
			if err != nil {
				return fmt.Errorf("the owner blob of a %s record does not open: %w", kind, err)
			}
			ref, err := identity.UnmarshalRef(anchor)
			if err != nil {
				return fmt.Errorf("the owner blob of a %s record names no valid anchor: %w", kind, err)
			}
			want, err := tagFor(s.keys, ref, kind, int(num))
			if err != nil {
				return err
			}
			if exportRefHook != nil {
				exportRefHook(&want)
			}
			if !bytes.Equal(want, tag) {
				return fmt.Errorf("the lookup tag of a %s record is not the one its owner blob gives: the workspace is inconsistent and is not exported", kind)
			}
			out.Refs = append(out.Refs, ports.RecordRef{Anchor: anchor, Num: num, Class: classOf(k)})
			ids = append(ids, id)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		raw, err := readCheckpointKey(ctx, s)
		if err != nil {
			return fmt.Errorf("reading the checkpoint key record: %w", err)
		}
		out.CheckpointKey = raw
		return nil
	}
	snap, facts, err := readSnapshot(ctx, path, c, then)
	if err != nil {
		if out.Sealer != nil {
			out.Sealer.Close()
		}
		return nil, err
	}
	if len(ids) != len(snap.Records) {
		out.Sealer.Close()
		return nil, errors.New("sqlitestore: the records changed between the two reads of the verified copy")
	}
	for i := range ids {
		if !bytes.Equal(ids[i], snap.Records[i].ID) {
			out.Sealer.Close()
			return nil, errors.New("sqlitestore: the records changed between the two reads of the verified copy")
		}
	}
	out.Snapshot, out.Facts = snap, facts
	return &out, nil
}
