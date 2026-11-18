package sqlitestore

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/unlock"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// THE LAYOUT READER'S SIDE OF THE STORE (ADR 0012 stage 3; spec/extensions/Xlayout.md,
// "The verifier and the importer").
//
// A layout carries the slot table and the meta row in its plaintext slots object.
// These functions turn that table into what the reader needs without a SQLite
// file of the workspace: the store's own policy check on it, an unlock through the
// store's own unlock path, and a verified scratch file. No key byte leaves this
// package: the opener holds the keys and offers only the operations the reader
// needs (the envelope of an object, the owner blob of a record, the lookup tag,
// the epoch MAC), and no operation opens a record payload, so a cold-role record
// stays as unopenable here as it is to anyone who holds the workspace keys.

// tableOfSnapshot parses the slot table of a snapshot's meta and slots as a file
// reader parses the keyslots rows (buildTSlot). The meta must be of the current
// store format.
func tableOfSnapshot(meta ports.SnapshotMeta, slots []ports.SnapshotSlot) (*table, error) {
	if meta.FormatVersion != int64(seal.StoreFormat) {
		return nil, fmt.Errorf("sqlitestore: store format %d is not the current store format (%d)", meta.FormatVersion, seal.StoreFormat)
	}
	t := &table{ws: meta.WorkspaceID, format: uint64(meta.FormatVersion), policy: unlock.Policy(meta.Policy)}
	for _, r := range slots {
		s := seal.Slot{ID: r.ID, Kind: r.Kind, Salt: r.Salt, Commit: r.KeyCommit, Nonce: r.Nonce, Wrapped: r.WrappedKey}
		var mem, passes, lanes int64
		if r.KDFMemoryKiB != nil {
			mem = *r.KDFMemoryKiB
		}
		if r.KDFPasses != nil {
			passes = *r.KDFPasses
		}
		if r.KDFLanes != nil {
			lanes = *r.KDFLanes
		}
		s.KDF = seal.KDFParams{MemoryKiB: uint32(mem), Passes: uint32(passes), Lanes: uint8(lanes)}
		if mem < 0 || mem > 1<<32-1 || passes < 0 || passes > 1<<32-1 || lanes < 0 || lanes > 255 {
			s.KDF = seal.KDFParams{} // out of range values wrap: zero is refused as weak
		}
		ts, err := buildTSlot(t, meta.WorkspaceID, s, r.Bound == 1, r.RecHash, r.Factors)
		if err != nil {
			return nil, err
		}
		t.slots = append(t.slots, ts)
	}
	return t, nil
}

// CheckLayoutSlotTable runs the store's unlock-policy check (domain/unlock) on
// the slot table of a layout, as every open of a workspace does before any
// factor is asked for. It needs no secret. A table that breaks its policy is
// ErrPolicyViolated.
func CheckLayoutSlotTable(meta ports.SnapshotMeta, slots []ports.SnapshotSlot) error {
	t, err := tableOfSnapshot(meta, slots)
	if err != nil {
		return err
	}
	return checkLayoutTable(t)
}

// checkLayoutTable is the policy check of the table and the check that no FIDO2
// factor names an RP id but the workspace's own ("spo." and the workspace id in
// hex, as every enrolment writes it). The authenticator is asked with the
// credential id and RP id a slot names, so a table of a layout must not choose
// them.
func checkLayoutTable(t *table) error {
	if err := t.check(); err != nil {
		return err
	}
	want := "spo." + hex.EncodeToString(t.ws)
	for _, ts := range t.slots {
		for _, f := range ts.fs.Spec.Factors {
			if f.Kind == seal.FactorFIDO2 && f.RPID != want {
				return fmt.Errorf("%w: a FIDO2 factor names the RP id %q, not this workspace's %q", ErrPolicyViolated, f.RPID, want)
			}
		}
	}
	return nil
}

type layoutOpener struct {
	keys   *seal.Keys
	sealer *seal.ObjectSealer
	epoch  []byte
	ws     []byte
}

var _ ports.ObjectOpener = (*layoutOpener)(nil)

func (o *layoutOpener) Epoch() []byte       { return append([]byte(nil), o.epoch...) }
func (o *layoutOpener) WorkspaceID() []byte { return append([]byte(nil), o.ws...) }
func (o *layoutOpener) EpochMACValid(ws, epoch, mac []byte) (bool, error) {
	return o.keys.Audit.CheckEpoch(ws, epoch, mac)
}
func (o *layoutOpener) Open(stored []byte) ([]byte, error) {
	return o.sealer.Open(stored, o.ws, o.epoch)
}
func (o *layoutOpener) OwnerRef(id []byte, kind string, owner []byte) ([]byte, uint64, error) {
	return o.keys.OpenOwnerRef(o.ws, id, kind, seal.SealedRecord{Owner: owner})
}
func (o *layoutOpener) LookupTag(anchor []byte, kind string, num uint64) ([]byte, error) {
	ref, err := identity.UnmarshalRef(anchor)
	if err != nil {
		return nil, err
	}
	return tagFor(o.keys, ref, kind, int(num))
}
func (o *layoutOpener) Close() {
	o.sealer.Close()
	o.keys.Destroy()
}

// OpenLayoutKeys unlocks the slot table of a layout through c, the way an open of
// the workspace would: the policy check first (before any authenticator is
// asked), then the slots of the credential's kind, then the check that the key
// belongs to the key epoch of meta (its epoch MAC). A hardware or strict table
// opens only through factors. The master key is destroyed as soon as the keys are
// derived. The caller closes the opener.
func OpenLayoutKeys(ctx context.Context, meta ports.SnapshotMeta, slots []ports.SnapshotSlot, c SnapshotCredential) (ports.ObjectOpener, error) {
	return openLayoutKeys(ctx, meta, slots, c, nil)
}

// openLayoutKeys is OpenLayoutKeys; with keep set, a copy of the master key is
// handed back in *keep (the caller destroys it).
func openLayoutKeys(ctx context.Context, meta ports.SnapshotMeta, slots []ports.SnapshotSlot, c SnapshotCredential, keep **secret.Buffer) (ports.ObjectOpener, error) {
	t, err := tableOfSnapshot(meta, slots)
	if err != nil {
		return nil, err
	}
	if err := checkLayoutTable(t); err != nil {
		return nil, err
	}
	if len(meta.WorkspaceID) != seal.IDSize || len(meta.KeyEpoch) != seal.EpochSize || len(meta.EpochMAC) != seal.MACSize {
		return nil, errors.New("sqlitestore: the meta of the slots object has a bad workspace id or key epoch")
	}
	cred, done, err := c.resolve()
	if err != nil {
		return nil, err
	}
	defer done()
	m := metaRow{ws: meta.WorkspaceID, format: int(meta.FormatVersion), epoch: meta.KeyEpoch, epochMAC: meta.EpochMAC}
	master, _, _, err := unlockTable(ctx, t, cred, func(mk *secret.Buffer) (bool, error) { return epochMatches(m, mk) })
	if err != nil {
		return nil, err
	}
	defer master.Destroy()
	if keep != nil {
		cp, cerr := copySecret(master)
		if cerr != nil {
			return nil, cerr
		}
		*keep = cp
	}
	keys, err := seal.DeriveKeys(master)
	if err != nil {
		if keep != nil {
			(*keep).Destroy()
		}
		return nil, err
	}
	sealer, err := keys.ObjectSealer()
	if err != nil {
		keys.Destroy()
		if keep != nil {
			(*keep).Destroy()
		}
		return nil, err
	}
	return &layoutOpener{keys: keys, sealer: sealer, epoch: append([]byte(nil), meta.KeyEpoch...), ws: append([]byte(nil), meta.WorkspaceID...)}, nil
}

// WriteLayoutFile builds the verified scratch store file of an import: a NEW
// file at path from the snapshot rebuilt from a layout, through c. It is
// WriteSnapshotFile (the schema allow-list, the full verification of the audit
// chain, the record hashes and the policy, and a read-back) with the schema
// version of this binary, which the layout does not carry. It never replaces
// anything.
func WriteLayoutFile(ctx context.Context, path string, snap ports.Snapshot, c SnapshotCredential) error {
	snap.Meta.SchemaVersion = int64(len(migrations))
	return WriteSnapshotFile(ctx, path, snap, c)
}

// ErrLayoutReadOnly is what every write on a handle opened from a sealed layout
// returns (ADR 0012 stage 3, the owner decision on its scope: the SQLite file is
// the only writable store). ErrLayoutColdRecord is what opening a cold-role record
// on such a handle returns: a read-only open cannot rotate the per-use salt, so
// each open would show the authenticator the same salt, and no cold factor is ever
// asked for.
var (
	ErrLayoutReadOnly   = errors.New("this is a sealed layout opened read-only; convert it into a workspace to change it: spo store convert --from-layout DIR --pin PIN")
	ErrLayoutColdRecord = errors.New("this is a sealed layout opened read-only, and a cold-role record is never opened from it (a read-only open cannot rotate the per-use salt of its cold factor); convert the layout into a workspace to use the key: spo store convert --from-layout DIR --pin PIN")
)

// LayoutUnlock holds the master key one unlock of a layout's slot table derived,
// so that the scratch file of a read-only open and the open itself need no second
// presentation of the credential. The master key is checked against the key epoch
// of the slots object before it is kept (the unlock does that), and the scratch
// file is built from the same slot table, so nothing the credential proves is
// skipped; what is not repeated is only the presentation. It is guarded memory and
// Close destroys it.
type LayoutUnlock struct {
	master *secret.Buffer
}

// UnlockLayout is OpenLayoutKeys that also keeps the master key for WriteFile and
// OpenReadOnly. The caller closes both the opener and the LayoutUnlock.
func UnlockLayout(ctx context.Context, meta ports.SnapshotMeta, slots []ports.SnapshotSlot, c SnapshotCredential) (ports.ObjectOpener, *LayoutUnlock, error) {
	var kept *secret.Buffer
	op, err := openLayoutKeys(ctx, meta, slots, c, &kept)
	if err != nil {
		return nil, nil, err
	}
	return op, &LayoutUnlock{master: kept}, nil
}

// WriteFile is WriteLayoutFile through the kept master key: the file is verified
// by the store's own verification, and the audit chain, the record hashes and the
// policy are checked as ever.
func (u *LayoutUnlock) WriteFile(ctx context.Context, path string, snap ports.Snapshot) error {
	if u == nil || u.master == nil {
		return errors.New("sqlitestore: the layout unlock is closed")
	}
	return WriteLayoutFile(ctx, path, snap, SnapshotCredential{master: u.master})
}

// OpenReadOnly opens the scratch file written by WriteFile as a read-only handle
// of a sealed layout: every write fails with ErrLayoutReadOnly and a cold-role
// record with ErrLayoutColdRecord. The handle has no cold source, so no factor can
// be asked for through it.
func (u *LayoutUnlock) OpenReadOnly(path string) (*Store, error) {
	if u == nil || u.master == nil {
		return nil, errors.New("sqlitestore: the layout unlock is closed")
	}
	st, err := open(path, credential{kind: credMaster, buf: u.master}, true, OpenOptions{})
	if err != nil {
		return nil, err
	}
	st.layoutRO = true
	return st, nil
}

// Close destroys the kept master key. It is safe to call twice.
func (u *LayoutUnlock) Close() {
	if u != nil && u.master != nil {
		u.master.Destroy()
		u.master = nil
	}
}
