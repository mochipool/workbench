package layoutread

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"sync/atomic"

	"github.com/mochipool/workbench/spo/internal/domain/layout"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Workers bounds the objects fetched at once. With a bucket of at most 4 MiB,
// the objects in flight hold at most Workers times that (plus what each opens
// to), whatever the size of the layout.
const Workers = 8

// MaxStoredBytes bounds the bytes of objects one unlocked pass reads (the
// largest layout this reader accepts: 500,000 audit rows of 4 KiB is 2 GiB).
var MaxStoredBytes int64 = 4 << 30

// MaxFieldBytes bounds the bytes of the fields of the rows the pass holds: the
// snapshot limit, counted as the rows are read, not only when the snapshot is
// validated at the end.
var MaxFieldBytes int64 = ports.SnapshotMaxBytes

// Unlocked is what the unlocked pass rebuilt and checked.
type Unlocked struct {
	// Snapshot is the workspace's rows rebuilt from the objects. The schema
	// version is the writer's to set.
	Snapshot ports.Snapshot
	Records  int
	Audit    int
	// Objects and Bytes are what the pass fetched: every object the head names but
	// the slots object.
	Objects int
	Bytes   int64
	Notices []string
}

// UnlockedInput is what the unlocked pass needs.
type UnlockedInput struct {
	Reader ports.ObjectReader
	Locked *Locked
	// Keys unlocks the slot table with the credential the caller holds.
	Keys ports.LayoutKeyOpener
}

func classRule(kind string) (string, bool) {
	k := ports.Kind(kind)
	if !k.Known() {
		return "", false
	}
	if k.Secret() {
		return layout.ClassSecret, true
	}
	return layout.ClassSensitive, true
}

type pass struct {
	in    UnlockedInput
	op    ports.ObjectOpener
	head  layout.Head
	bytes atomic.Int64
	field atomic.Int64
	objs  atomic.Int64
}

// CheckUnlocked is the unlocked pass. It opens the manifest and every object the
// head names with the keys of the slot table, checks the invariants of the
// layout on them (SPO-Xlayout-INV-007 to INV-011 and INV-017), and rebuilds the
// snapshot. It never opens a record payload. It does not check the audit chain:
// the store does, when the snapshot is written to a file.
func CheckUnlocked(ctx context.Context, in UnlockedInput) (*Unlocked, error) {
	lr := in.Locked
	if in.Reader == nil || in.Keys == nil || lr == nil {
		return nil, errors.New("layoutread: the reader, the locked result or the keys are missing")
	}
	meta, slots := SnapshotOf(lr.Slots)
	op, err := in.Keys.OpenLayoutKeys(ctx, meta, slots)
	if err != nil {
		return nil, fmt.Errorf("unlocking the slot table of the layout: %w", err)
	}
	defer op.Close()
	p := &pass{in: in, op: op, head: lr.Used.Head}
	if !bytes.Equal(op.Epoch(), p.head.Epoch) || !bytes.Equal(op.WorkspaceID(), lr.Pin.WorkspaceID) {
		return nil, fmt.Errorf("%w: the keys are of another key epoch or workspace than the head's", ErrSlots)
	}
	// SPO-Xlayout-INV-017
	if ok, err := op.EpochMACValid(meta.WorkspaceID, meta.KeyEpoch, meta.EpochMAC); err != nil || !ok {
		return nil, fmt.Errorf("%w: the epoch MAC of the slots object does not verify under the keys the credential opened (it was edited, or it is not the MAC of this workspace's key epoch)", ErrSlots)
	}
	root, err := p.root(lr.ManifestStored)
	if err != nil {
		return nil, err
	}
	rp, ap, err := p.pages(ctx, root)
	if err != nil {
		return nil, err
	}
	if err := layout.VerifyManifest(root, rp, ap); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrManifest, err)
	}
	snap := ports.Snapshot{Meta: meta, Slots: slots}
	if snap.Records, err = p.records(ctx, rp); err != nil {
		return nil, err
	}
	if snap.Audit, err = p.audit(ctx, ap); err != nil {
		return nil, err
	}
	if err := p.finish(root, lr.Slots, &snap); err != nil {
		return nil, err
	}
	if err := snap.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSnapshot, err)
	}
	// the head this check settled on is still the head
	again, err := readAll(ctx, in.Reader, layout.HeadPath(p.head.Sequence), layout.MaxHeadSize)
	if err != nil || !bytes.Equal(again, lr.Used.Note) {
		return nil, fmt.Errorf("%w: %s is not what it was when the check began", ErrChanged, layout.HeadPath(p.head.Sequence))
	}
	return &Unlocked{Snapshot: snap, Records: len(snap.Records), Audit: len(snap.Audit), Objects: int(p.objs.Load()) + 1, Bytes: p.bytes.Load() + int64(len(lr.ManifestStored))}, nil
}

// countFields adds the bytes of one row's fields to the pass's running total and
// refuses when it passes the bound, before the row is copied.
func (p *pass) countFields(n int) error {
	if t := p.field.Add(int64(n)); t > MaxFieldBytes {
		return fmt.Errorf("%w: the fields of the rows are more than %d bytes", ErrLimit, MaxFieldBytes)
	}
	return nil
}

// fetch reads an object by hash and opens and decodes it, counting its bytes.
func (p *pass) fetch(ctx context.Context, hash []byte, what string) (layout.Object, error) {
	stored, err := fetchObject(ctx, p.in.Reader, hash, what)
	if err != nil {
		return nil, err
	}
	if n := p.bytes.Add(int64(len(stored))); n > MaxStoredBytes {
		return nil, fmt.Errorf("%w: the objects read so far are more than %d bytes", ErrLimit, MaxStoredBytes)
	}
	p.objs.Add(1)
	return p.decode(stored, what)
}

func (p *pass) decode(stored []byte, what string) (layout.Object, error) {
	body, err := p.op.Open(stored)
	if err != nil {
		return nil, fmt.Errorf("%w: %s does not open under the keys of the workspace (%v)", ErrObject, what, err)
	}
	o, err := layout.DecodeBody(body, classRule)
	if err != nil {
		return nil, fmt.Errorf("%w: %s opened but is not a well-formed object (%v)", ErrObject, what, err)
	}
	return o, nil
}

// root opens the manifest root and checks it against the head.
func (p *pass) root(stored []byte) (layout.Root, error) {
	o, err := p.decode(stored, "the manifest root")
	if err != nil {
		return layout.Root{}, err
	}
	r, ok := o.(layout.Root)
	if !ok {
		return r, fmt.Errorf("%w: the object the head names as its manifest is not a manifest root", ErrManifest)
	}
	h := p.head
	if r.Parent.Seq != h.Sequence || !bytes.Equal(r.Parent.PreviousHead, h.Previous) {
		return r, fmt.Errorf("%w: the manifest root was made for head %d after %x, not for head %d after %x: it belongs to another export of this workspace", ErrManifest, r.Parent.Seq, r.Parent.PreviousHead, h.Sequence, h.Previous)
	}
	if !bytes.Equal(r.Slots, h.Slots) {
		return r, fmt.Errorf("%w: the manifest root names another slots object than the head does", ErrManifest)
	}
	if r.AuditSeq != h.AuditSeq || !bytes.Equal(r.AuditMAC, h.AuditMAC) {
		return r, fmt.Errorf("%w: the audit head of the manifest root (sequence %d) is not the audit head of the head note (sequence %d)", ErrManifest, r.AuditSeq, h.AuditSeq)
	}
	maxRP := (ports.SnapshotMaxRecords + layout.MaxRecordsPerPage - 1) / layout.MaxRecordsPerPage
	maxAP := (ports.SnapshotMaxAudit + layout.AuditPageSize - 1) / layout.AuditPageSize
	if r.Records > ports.SnapshotMaxRecords || r.Audits > ports.SnapshotMaxAudit || len(r.RecordPages) > maxRP || len(r.AuditPages) > maxAP {
		return r, fmt.Errorf("%w: the manifest names %d records, %d audit rows and %d+%d pages; this reader accepts at most %d records, %d audit rows and %d+%d pages", ErrLimit,
			r.Records, r.Audits, len(r.RecordPages), len(r.AuditPages), ports.SnapshotMaxRecords, ports.SnapshotMaxAudit, maxRP, maxAP)
	}
	return r, nil
}

// pages fetches and opens the pages the root names.
func (p *pass) pages(ctx context.Context, root layout.Root) ([]layout.RecordPage, []layout.AuditPage, error) {
	rp := make([]layout.RecordPage, len(root.RecordPages))
	ap := make([]layout.AuditPage, len(root.AuditPages))
	err := parallel(ctx, len(rp)+len(ap), func(ctx context.Context, i int) error {
		if i < len(rp) {
			o, err := p.fetch(ctx, root.RecordPages[i], fmt.Sprintf("record page %d", i))
			if err != nil {
				return err
			}
			pg, ok := o.(layout.RecordPage)
			if !ok {
				return fmt.Errorf("%w: the object named as record page %d is not a record page", ErrManifest, i)
			}
			rp[i] = pg
			return nil
		}
		j := i - len(rp)
		o, err := p.fetch(ctx, root.AuditPages[j], fmt.Sprintf("audit page %d", j))
		if err != nil {
			return err
		}
		pg, ok := o.(layout.AuditPage)
		if !ok {
			return fmt.Errorf("%w: the object named as audit page %d is not an audit page", ErrManifest, j)
		}
		ap[j] = pg
		return nil
	})
	return rp, ap, err
}

func (p *pass) records(ctx context.Context, rp []layout.RecordPage) ([]ports.SnapshotRecord, error) {
	var entries []layout.RecordEntry
	for _, pg := range rp {
		entries = append(entries, pg.Entries...)
	}
	if len(entries) == 0 {
		return nil, nil // a snapshot of a file with no record has no slice, not an empty one
	}
	out := make([]ports.SnapshotRecord, len(entries))
	err := parallel(ctx, len(entries), func(ctx context.Context, i int) error {
		e := entries[i]
		name := fmt.Sprintf("the object of record %x", e.ID)
		o, err := p.fetch(ctx, e.Hash, name)
		if err != nil {
			return err
		}
		rec, ok := o.(layout.Record)
		if !ok {
			return fmt.Errorf("%w: %s is not a record", ErrObject, name)
		}
		// SPO-Xlayout-INV-007
		if !bytes.Equal(rec.ID, e.ID) {
			return fmt.Errorf("%w: the manifest lists the object %x for record %x, but it is the object of record %x", ErrRecord, e.Hash[:8], e.ID, rec.ID)
		}
		if rec.Version != e.Version || rec.Version > math.MaxInt64 {
			return fmt.Errorf("%w: the manifest lists version %d of record %x, but the object holds version %d", ErrRecord, e.Version, e.ID, rec.Version)
		}
		// SPO-Xlayout-INV-010: the anchor and number are those of the owner blob, which
		// only the workspace keys open; the lookup tag is recomputed from them
		anchor, num, err := p.op.OwnerRef(rec.ID, rec.Kind, rec.Inner.Owner)
		if err != nil {
			return fmt.Errorf("%w: the owner blob of record %x (a %s) does not open: %v", ErrRecord, rec.ID, rec.Kind, err)
		}
		if !bytes.Equal(anchor, rec.Anchor) || num != rec.Num {
			return fmt.Errorf("%w: the anchor or number in the body of record %x (a %s) is not what its owner blob says", ErrRecord, rec.ID, rec.Kind)
		}
		tag, err := p.op.LookupTag(rec.Anchor, rec.Kind, rec.Num)
		if err != nil {
			return fmt.Errorf("%w: the lookup tag of record %x (a %s) cannot be made: %v", ErrRecord, rec.ID, rec.Kind, err)
		}
		if err := p.countFields(len(rec.ID) + len(tag) + len(rec.Kind) + len(rec.Inner.Nonce) + len(rec.Inner.WrappedKey) + len(rec.Inner.Owner) + len(rec.Inner.Ciphertext)); err != nil {
			return err
		}
		out[i] = ports.SnapshotRecord{
			ID: append([]byte{}, rec.ID...), LookupTag: tag, Kind: rec.Kind, Version: int64(rec.Version),
			Nonce: append([]byte{}, rec.Inner.Nonce...), WrappedKey: append([]byte{}, rec.Inner.WrappedKey...),
			OwnerSealed: append([]byte{}, rec.Inner.Owner...), Ciphertext: append([]byte{}, rec.Inner.Ciphertext...), UpdatedAt: rec.UpdatedAt,
		}
		return nil
	})
	return out, err
}

func (p *pass) audit(ctx context.Context, ap []layout.AuditPage) ([]ports.SnapshotAudit, error) {
	var entries []layout.AuditEntry
	for _, pg := range ap {
		entries = append(entries, pg.Entries...)
	}
	out := make([]ports.SnapshotAudit, len(entries))
	err := parallel(ctx, len(entries), func(ctx context.Context, i int) error {
		e := entries[i]
		name := fmt.Sprintf("the object of audit row %d", e.Seq)
		o, err := p.fetch(ctx, e.Hash, name)
		if err != nil {
			return err
		}
		a, ok := o.(layout.Audit)
		if !ok {
			return fmt.Errorf("%w: %s is not an audit row", ErrObject, name)
		}
		// SPO-Xlayout-INV-008
		if uint64(a.Seq) != e.Seq {
			return fmt.Errorf("%w: the manifest lists the object %x for audit row %d, but it is the object of audit row %d (the sequence number differs)", ErrAudit, e.Hash[:8], e.Seq, a.Seq)
		}
		if err := p.countFields(len(a.Kind) + len(a.Event) + len(a.Touched) + len(a.SlotSet) + len(a.MAC) + len(a.PrevMAC)); err != nil {
			return err
		}
		out[i] = ports.SnapshotAudit{Seq: a.Seq, At: a.At, Kind: a.Kind, Event: append([]byte{}, a.Event...), Touched: append([]byte{}, a.Touched...),
			SlotSet: append([]byte{}, a.SlotSet...), MAC: append([]byte{}, a.MAC...), PrevMAC: append([]byte{}, a.PrevMAC...)}
		return nil
	})
	return out, err
}

// finish checks what needs all the rows: the last audit row against the root
// (INV-009) and the slots object against the newest slot-table row (INV-011).
func (p *pass) finish(root layout.Root, so layout.SlotsObject, snap *ports.Snapshot) error {
	if n := len(snap.Audit); n > 0 {
		last := snap.Audit[n-1]
		if !bytes.Equal(last.MAC, root.AuditMAC) {
			return fmt.Errorf("%w: the last audit row (sequence %d) has a MAC that is not the audit head MAC of the manifest root (sequence %d)", ErrAudit, last.Seq, root.AuditSeq)
		}
	}
	want, err := layout.SlotSetHash(so.Meta.Policy, so.Slots)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSlots, err)
	}
	for i := len(snap.Audit) - 1; i >= 0; i-- {
		if k := snap.Audit[i].Kind; k == "slots" || k == "rollover" {
			if !bytes.Equal(snap.Audit[i].SlotSet, want) {
				return fmt.Errorf("%w: the slot table of the slots object does not hash to the slot-set hash the newest slot-table audit row (sequence %d) recorded", ErrSlots, snap.Audit[i].Seq)
			}
			return nil
		}
	}
	return fmt.Errorf("%w: the audit chain has no slot-table row (kind slots or rollover) to check the slot table against", ErrSlots)
}

// parallel runs fn for 0..n-1 on at most Workers goroutines and returns the first
// error, after which no new work starts.
func parallel(ctx context.Context, n int, fn func(ctx context.Context, i int) error) error {
	if n == 0 {
		return nil
	}
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan int)
	var wg sync.WaitGroup
	var once sync.Once
	var first error
	for w := 0; w < min(Workers, n); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				if cctx.Err() != nil {
					continue
				}
				if err := fn(cctx, i); err != nil {
					once.Do(func() { first = err; cancel() })
				}
			}
		}()
	}
loop:
	for i := 0; i < n; i++ {
		select {
		case jobs <- i:
		case <-cctx.Done():
			break loop
		}
	}
	close(jobs)
	wg.Wait()
	if first != nil {
		return first
	}
	return ctx.Err()
}
