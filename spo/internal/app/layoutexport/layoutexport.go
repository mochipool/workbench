// Package layoutexport is the use case of ADR 0012 stage 3, work package 3:
// write a workspace into a directory as sealed, padded, content-named objects
// (spec/extensions/Xlayout.md). It reaches the directory, the single-writer lock,
// the keys and the local pin only through ports, and it never sees a key byte:
// the objects are sealed by a ports.ObjectSealer made by the store adapter from
// the unlocked workspace.
//
// ORDER. Objects first, manifest next, head last. The slots object, every
// record and audit object, the manifest pages and the manifest root are put
// (create-if-absent) and each is read back before the next step; only then is
// the head note put, so a head never names an object that is missing. A kill at
// any point leaves the newest valid head, if there is one, fully satisfiable:
// nothing this run puts is referenced by an older head, and a run that stopped
// early is completed by running it again (the objects it put have the same
// names, because the nonce of the envelope is synthetic, so they are found and
// not put again).
//
// RECORDS ARE CARRIED, NOT OPENED. A record's four sealed fields go from the
// snapshot into the body byte for byte. The exporter never opens, rebuilds or
// re-seals an inner record, and a cold-role record is not opened at all.
package layoutexport

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/backupsink"
	"github.com/mochipool/workbench/spo/internal/domain/checkpoint"
	"github.com/mochipool/workbench/spo/internal/domain/layout"
	"github.com/mochipool/workbench/spo/internal/domain/sshsig"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Dir is a layout directory as the wiring hands it to the use case: the object
// ports it honours, the single-writer lock and the pin.
type Dir struct {
	Writer ports.ObjectWriter
	Reader ports.ObjectReader
	Lister ports.ObjectLister
	Locker ports.LayoutLocker
	Pins   ports.LayoutPins
}

// Material is what unlocking the workspace yields for an export. The
// snapshot is consumed: Run clears each row once its object is put, so that the
// workspace is not held twice.
type Material struct {
	Snapshot ports.Snapshot
	// Refs has one entry per record of the snapshot, in the same order.
	Refs   []ports.RecordRef
	Sealer ports.ObjectSealer
	// Notices are what verifying the workspace reported; Run hands them back.
	Notices []string
	// Signing signs the head note with the checkpoint key; nil when no key is
	// enrolled or the operator chose --no-checkpoint.
	Signing *backupsink.Signing
	// KeyRecord is the enrolled checkpoint key whether or not this run signs
	// with it; nil when none is enrolled. Signatures found in the directory are
	// verified against it.
	KeyRecord *checkpoint.KeyRecord
	// Close releases what the material holds (the sealer's keys).
	Close func()
}

// Input is what Run needs.
type Input struct {
	Dir Dir
	// WorkspaceID is the genesis nonce of the workspace, read from the workspace
	// file without a key. The layout is checked against it before anything is
	// asked of the operator.
	WorkspaceID []byte
	// Unlock unlocks the workspace the normal way for its policy and takes the
	// verified raw snapshot. It is called once, after every check that needs no
	// secret has passed.
	Unlock func(ctx context.Context) (Material, error)
	Now    func() time.Time
	// AdoptLayout is the operator's statement that an existing layout this machine
	// has no pin for is trusted.
	AdoptLayout bool
	// Notify, when set, is told of what the run trusts (an adopted layout) at the
	// moment it decides to, before any pin is recorded.
	Notify func(string)
}

// Observed is what someone who can read the directory sees.
type Observed struct {
	// Objects is the number of objects the head names (the slots object, the
	// records, the audit rows, the manifest pages and the root).
	Objects int
	// Buckets maps a stored size to the number of objects of that size.
	Buckets map[int]int
	// SlotsObjectBytes is the size of the plaintext slots object.
	SlotsObjectBytes int
	// Heads is the number of head notes in the directory after the run.
	Heads int
}

// Result says what a run did.
type Result struct {
	Notices []string
	// ObjectsWritten and ObjectsReused count the objects this run put and the
	// objects it found already there under the same name and size.
	ObjectsWritten int
	ObjectsReused  int
	BytesWritten   int64
	// UpToDate is true when nothing changed since the newest head: no head was
	// written.
	UpToDate     bool
	HeadWritten  bool
	HeadSequence uint64
	HeadHash     []byte
	// Signed is true when the head of this result has a signature in the
	// directory (put by this run or found).
	Signed bool
	// SignedNow is true when this run put the signature.
	SignedNow bool
	// KeyHash is the checkpoint key hash the head names; nil for none.
	KeyHash []byte
	// Fresh is true when the directory had no head before.
	Fresh bool
	// Adopted is true when an existing layout without a pin was trusted on the
	// operator's statement (--adopt-layout); AdoptedByKey when every head of it
	// verified against the enrolled checkpoint key.
	Adopted      bool
	AdoptedByKey bool
	// Pin is <workspace id>:layout:<sequence>:<head hash>.
	Pin string
	// LongPin is the long-lived pin of the checkpoint key; empty when unsigned.
	LongPin  string
	Observed Observed
}

// StageError is an error with one sentence about the state of the directory.
type StageError struct {
	Err  error
	Note string
}

func (e *StageError) Error() string {
	return trimStop(e.Err.Error()) + ". " + e.Note
}
func (e *StageError) Unwrap() error { return e.Err }

func trimStop(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '.' || s[len(s)-1] == ' ' || s[len(s)-1] == '\n') {
		s = s[:len(s)-1]
	}
	return s
}

const (
	noteNothing = "Nothing was written to the layout directory and the workspace is unchanged; once the cause is fixed the command can be run again."
	noteObjects = "Objects may have been written but no head was; the newest valid head of the directory, if there is one, is still complete. The command can be run again: objects already there are found, not written again."
	noteHead    = "The head was written and read back, but the pin file beside the workspace was not updated; run the command again to update it."
	noteSig     = "The head is in the directory but its signature is not; run the command again (it asks for the signature without writing anything else)."
	// noteBlocked is for a directory that cannot be exported to as it is: running
	// the command again does not help.
	noteBlocked = "Nothing in the directory was changed, and this tool never overwrites or deletes anything in a layout. This directory cannot be used for this export as it is: export to a fresh directory."
)

func stage(err error, note string) error {
	if err == nil {
		return nil
	}
	return &StageError{Err: err, Note: note}
}

// Sentinel refusals.
var (
	ErrOtherWorkspace = errors.New("the directory holds a layout of another workspace; this tool writes only to an empty directory or to a layout of this workspace")
	ErrNotALayout     = errors.New("the directory is not empty and is not a layout; use an empty or new directory")
	ErrRolledBack     = errors.New("the directory is behind the pin of this machine: the layout was rolled back or replaced (if you removed or replaced the directory on purpose, move the pin file beside the workspace file away and run the command again)")
	ErrAhead          = errors.New("the newest head of the directory records a newer audit state than this workspace has. Either the workspace file is older than what was exported (restored from an older backup), or the directory holds a head that this machine cannot vouch for; this tool does not decide which")
	// ErrWrongContent is returned when a file under an object name does not hash to
	// that name.
	ErrWrongContent = errors.New("the directory holds wrong content under the name of an object")
)

// MaxSequence bounds the head sequence numbers this tool accepts: far below
// 64 bits, so nothing can wrap.
const MaxSequence = 1 << 32

var errTooLarge = errors.New("the object is larger than expected")

const lockName = ".spo-export.lock"

var (
	headRE   = regexp.MustCompile(`^heads/([0-9]{20})(\.sig)?$`)
	objectRE = regexp.MustCompile(`^objects/([0-9a-f]{2})/([0-9a-f]{64})$`)
)

// maxSigBytes bounds a signature object read back.
const maxSigBytes = 16 << 10

// state is what the directory holds before the run.
type state struct {
	existing map[string]int64 // object name -> size
	sigs     map[uint64]bool  // sequence -> a signature file exists
	// chain is the heads this run relies on, oldest first: from the pinned head (or
	// from sequence 1 when this machine has no pin) to the newest. Empty for a
	// directory with no head.
	chain []*headInfo
	// pinned is true when the chain starts at the head this machine pinned.
	pinned bool
	notes  []string
	// headCount is the number of head notes (not signatures).
	headCount int
}

func (st *state) newest() *headInfo {
	if len(st.chain) == 0 {
		return nil
	}
	return st.chain[len(st.chain)-1]
}

type headInfo struct {
	head layout.Head
	note []byte
	hash []byte
}

// Run exports the workspace. See the package comment for the order.
func Run(ctx context.Context, in Input) (res Result, err error) {
	if in.Dir.Writer == nil || in.Dir.Reader == nil || in.Dir.Lister == nil || in.Dir.Locker == nil || in.Dir.Pins == nil {
		return res, errors.New("layoutexport: the directory is missing a port")
	}
	if len(in.WorkspaceID) != layout.EpochSize {
		return res, errors.New("layoutexport: the workspace id is not 16 bytes")
	}
	if in.Now == nil {
		in.Now = time.Now
	}
	lock, err := in.Dir.Locker.Lock(ctx)
	if err != nil {
		return res, stage(err, noteNothing)
	}
	defer lock.Release()

	// 1. every check that needs no secret
	pin, pinFound, err := in.Dir.Pins.Load()
	if err != nil {
		return res, stage(err, noteNothing)
	}
	st, err := inspect(ctx, in, pin, pinFound)
	if err != nil {
		var se *StageError
		if errors.As(err, &se) {
			return res, err
		}
		return res, stage(err, noteBlocked)
	}

	// 2. unlock and take the snapshot
	if in.Unlock == nil {
		return res, errors.New("layoutexport: no way to unlock")
	}
	m, err := in.Unlock(ctx)
	if err != nil {
		return res, err
	}
	if m.Close != nil {
		defer m.Close()
	} else if m.Sealer != nil {
		defer m.Sealer.Close()
	}
	res.Notices = append(res.Notices, st.notes...)
	res.Notices = append(res.Notices, m.Notices...)
	e := &exporter{in: in, st: st, m: &m, lock: lock, res: &res, written: map[string]bool{}}
	if err := e.run(ctx); err != nil {
		return res, err
	}
	return res, nil
}

// inspect lists the directory and checks what needs no secret: that it is empty
// or a layout of this workspace, that its heads form an unbroken chain from the
// pinned one (or from the first), that the pinned head is the one this machine
// recorded, and that the newest head's manifest and slots objects are there and
// hash to their names. It reads no key.
func inspect(ctx context.Context, in Input, pin ports.LayoutPin, pinFound bool) (*state, error) {
	entries, err := in.Dir.Lister.List(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("the directory could not be listed: %w", err)
	}
	st := &state{existing: map[string]int64{}, sigs: map[uint64]bool{}}
	notes := map[uint64]bool{}
	var seqs []uint64
	for _, en := range entries {
		switch {
		case en.Name == lockName:
		case objectRE.MatchString(en.Name):
			st.existing[en.Name[len("objects/xx/"):]] = en.Size
		case headRE.MatchString(en.Name):
			m := headRE.FindStringSubmatch(en.Name)
			seq, perr := strconv.ParseUint(m[1], 10, 64)
			if perr != nil || seq > MaxSequence || seq == 0 {
				return nil, fmt.Errorf("heads/%s is not a head sequence number this tool accepts (out of range)", m[1])
			}
			if m[2] == ".sig" {
				st.sigs[seq] = true
				continue
			}
			notes[seq] = true
			seqs = append(seqs, seq)
			st.headCount++
		default:
			return nil, ErrNotALayout
		}
	}
	for seq := range st.sigs {
		if !notes[seq] {
			return nil, fmt.Errorf("%s.sig is in the directory without its head: a signature that no head of this tool's made; the name is taken and this tool never deletes or replaces it", layout.HeadPath(seq))
		}
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	if len(seqs) == 0 {
		if pinFound {
			return nil, ErrRolledBack
		}
		if len(st.existing) > 0 {
			if err := checkUnfinished(ctx, in, st); err != nil {
				return nil, err
			}
		}
		return st, nil
	}
	if pinFound && (seqs[len(seqs)-1] < pin.Sequence || !notes[pin.Sequence]) {
		return nil, ErrRolledBack
	}
	start := uint64(1)
	if pinFound {
		start = pin.Sequence
	}
	var prev *headInfo
	for _, seq := range seqs {
		if seq < start {
			continue
		}
		if prev == nil && seq != start {
			return nil, brokenChain(seq, "the head before it is missing")
		}
		if prev != nil && seq != prev.head.Sequence+1 {
			return nil, brokenChain(seq, "the head before it is missing")
		}
		hi, herr := readHead(ctx, in.Dir.Reader, seq)
		if herr != nil {
			return nil, brokenChain(seq, "it is not a valid head ("+herr.Error()+")")
		}
		if !bytes.Equal(hi.head.Workspace, in.WorkspaceID) {
			return nil, ErrOtherWorkspace
		}
		switch {
		case prev == nil && pinFound:
			if !bytes.Equal(hi.hash, pin.HeadHash) {
				return nil, fmt.Errorf("%w: heads/%020d is not the head this machine pinned; the directory was replaced or rolled back (if you did that on purpose, move the pin file beside the workspace file away)", ErrRolledBack, seq)
			}
		case prev == nil:
			// the first head of a chain with no pin is sequence 1 (checked above), and
			// ParseHead refuses a first head with a previous hash and any other head
			// without one
		case !bytes.Equal(hi.head.Previous, prev.hash):
			return nil, brokenChain(seq, "its previous hash is not the hash of the head before it")
		}
		st.chain = append(st.chain, hi)
		prev = hi
	}
	st.pinned = pinFound
	// the newest head names a manifest and a slots object: they must be there and
	// be what their names say
	nh := st.newest()
	for what, h := range map[string][]byte{"manifest": nh.head.Manifest, "slots object": nh.head.Slots} {
		name := hex.EncodeToString(h)
		p, _ := layout.ObjectPath(name)
		b, rerr := readAll(ctx, in.Dir.Reader, p, int64(layout.MaxBucket))
		switch {
		case errors.Is(rerr, ports.ErrObjectNotFound):
			return nil, fmt.Errorf("the newest head (%s) names a %s, object %s, that is not in the directory", layout.HeadPath(nh.head.Sequence), what, name)
		case rerr != nil && !errors.Is(rerr, errTooLarge):
			return nil, fmt.Errorf("the newest head names a %s that could not be read: %w", what, rerr)
		case rerr != nil || layout.ObjectName(b) != name:
			return nil, fmt.Errorf("the newest head (%s) names a %s, object %s, but the directory holds wrong content under that name", layout.HeadPath(nh.head.Sequence), what, name)
		}
	}
	return st, nil
}

func brokenChain(seq uint64, why string) error {
	return fmt.Errorf("%s does not continue this machine's chain: %s. The directory holds heads that this machine did not write or cannot verify, and this tool will not chain onto them: export to a fresh directory", layout.HeadPath(seq), why)
}

// checkUnfinished accepts a directory with objects and no head only when its
// slots objects (plaintext) all name this workspace and there is at least one:
// an export that was stopped after it began.
func checkUnfinished(ctx context.Context, in Input, st *state) error {
	names := make([]string, 0, len(st.existing))
	for n := range st.existing {
		names = append(names, n)
	}
	sort.Strings(names)
	slots := 0
	for _, n := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		p, _ := layout.ObjectPath(n)
		rc, err := in.Dir.Reader.Get(ctx, p)
		if err != nil {
			return fmt.Errorf("an object in the directory could not be read: %w", err)
		}
		var first [1]byte
		_, rerr := io.ReadFull(rc, first[:])
		rc.Close()
		if rerr != nil {
			return ErrNotALayout
		}
		if first[0] != layout.FormatSlots {
			continue
		}
		b, err := readAll(ctx, in.Dir.Reader, p, int64(layout.MaxBucket))
		if err != nil {
			return err
		}
		_, so, err := layout.ParseSlotsObject(b)
		if err != nil || !bytes.Equal(so.Meta.WorkspaceID, in.WorkspaceID) {
			return ErrOtherWorkspace
		}
		slots++
	}
	if slots == 0 {
		return ErrNotALayout
	}
	return nil
}

func readHead(ctx context.Context, r ports.ObjectReader, seq uint64) (*headInfo, error) {
	b, err := readAll(ctx, r, layout.HeadPath(seq), layout.MaxHeadSize)
	if err != nil {
		return nil, err
	}
	h, err := layout.ParseHead(b)
	if err != nil {
		return nil, err
	}
	if h.Sequence != seq {
		return nil, fmt.Errorf("the note says sequence %d under the name of sequence %d", h.Sequence, seq)
	}
	return &headInfo{head: h, note: b, hash: layout.HeadHash(b)}, nil
}

func readAll(ctx context.Context, r ports.ObjectReader, name string, max int64) ([]byte, error) {
	rc, err := r.Get(ports.WithExpectedSize(ctx, max), name)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(&ctxReader{ctx, rc}, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%w (more than %d bytes)", errTooLarge, max)
	}
	return b, nil
}

type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// exporter holds one run.
type exporter struct {
	in      Input
	st      *state
	m       *Material
	lock    ports.LayoutLock
	res     *Result
	written map[string]bool
	obs     Observed
	// completeSig is set when the newest head is the unsigned head of an interrupted
	// export that this run may complete; chainVerified when a key is enrolled and
	// every head the new head builds on verified against it.
	completeSig   bool
	chainVerified bool
}

func (e *exporter) check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return e.lock.Check()
}

// put puts one stored object (create-if-absent), reading it back when it was
// written, and returns its hash.
func (e *exporter) put(ctx context.Context, stored []byte) ([]byte, error) {
	name := layout.ObjectName(stored)
	hash := layout.ObjectHash(stored)
	e.obs.Objects++
	if e.obs.Buckets == nil {
		e.obs.Buckets = map[int]int{}
	}
	e.obs.Buckets[len(stored)]++
	if e.written[name] {
		return hash, nil
	}
	e.written[name] = true
	if size, ok := e.st.existing[name]; ok {
		// an object that is there is read and hashed, not believed: every object a
		// head will name has been verified in this run
		if size != int64(len(stored)) {
			return nil, wrongContent(name)
		}
		got, rerr := readAll(ctx, e.in.Dir.Reader, objPath(name), int64(len(stored)))
		switch {
		case rerr == nil:
			if layout.ObjectName(got) != name {
				return nil, wrongContent(name)
			}
			e.res.ObjectsReused++
			return hash, nil
		case errors.Is(rerr, errTooLarge):
			return nil, wrongContent(name)
		case errors.Is(rerr, ports.ErrObjectNotFound):
			// gone since the listing: it is put below
		default:
			return nil, fmt.Errorf("object %s could not be read: %w", name, rerr)
		}
	}
	// before every put: the context, and that the directory is still the one that
	// was locked (a replaced directory stops the run before another byte is put)
	if err := e.check(ctx); err != nil {
		return nil, err
	}
	path, err := layout.ObjectPath(name)
	if err != nil {
		return nil, err
	}
	if err := e.in.Dir.Writer.Put(ctx, path, bytes.NewReader(stored), int64(len(stored))); err != nil {
		if errors.Is(err, ports.ErrObjectExists) {
			return nil, wrongContent(name)
		}
		return nil, fmt.Errorf("putting object %s: %w", name, err)
	}
	if err := e.readBack(ctx, path, stored); err != nil {
		return nil, fmt.Errorf("object %s: %w", name, err)
	}
	e.res.ObjectsWritten++
	e.res.BytesWritten += int64(len(stored))
	return hash, nil
}

func objPath(name string) string { p, _ := layout.ObjectPath(name); return p }

// wrongContent is the refusal for a file that is under an object's name and does
// not hash to it.
func wrongContent(name string) error {
	return stage(fmt.Errorf("%w: object %s is there but its bytes are not the object this export builds (the file is damaged, truncated, longer than it should be, or was replaced); this tool will not overwrite or delete it", ErrWrongContent, name), noteBlocked)
}

func (e *exporter) readBack(ctx context.Context, path string, want []byte) error {
	got, err := readAll(ctx, e.in.Dir.Reader, path, int64(len(want)))
	if err != nil {
		return fmt.Errorf("read back failed: %w", err)
	}
	if len(got) != len(want) || !bytes.Equal(layout.ObjectHash(got), layout.ObjectHash(want)) {
		return errors.New("the bytes read back are not the bytes that were put")
	}
	return nil
}

// seal frames, seals and puts one object of the layout.
func (e *exporter) seal(ctx context.Context, o layout.Object, describe string) ([]byte, error) {
	body, err := layout.EncodeBody(o)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", describe, err)
	}
	stored, err := e.m.Sealer.Seal(body)
	if err != nil {
		return nil, fmt.Errorf("%s: sealing: %w", describe, err)
	}
	return e.put(ctx, stored)
}

func (e *exporter) run(ctx context.Context) (err error) {
	snap := &e.m.Snapshot
	defer func() {
		if err != nil {
			if !errors.As(err, new(*StageError)) {
				err = stage(err, noteObjects)
			}
		}
	}()
	if err := snap.Validate(); err != nil {
		return stage(err, noteNothing)
	}
	meta := &snap.Meta
	if !bytes.Equal(meta.WorkspaceID, e.in.WorkspaceID) || !bytes.Equal(e.m.Sealer.WorkspaceID(), meta.WorkspaceID) {
		return stage(errors.New("the workspace id of the unlocked workspace is not the one the command started with"), noteNothing)
	}
	if !bytes.Equal(e.m.Sealer.Epoch(), meta.KeyEpoch) {
		return stage(errors.New("the key epoch of the sealer is not the key epoch of the snapshot: the workspace changed while it was being read; run the command again"), noteNothing)
	}
	if len(e.m.Refs) != len(snap.Records) {
		return stage(errors.New("the record references do not match the records of the snapshot"), noteNothing)
	}
	so, err := slotsOf(snap)
	if err != nil {
		return stage(err, noteNothing)
	}
	slotsStored, err := layout.EncodeSlotsObject(meta.KeyEpoch, so)
	if err != nil {
		return stage(err, noteNothing)
	}
	// INV-011 on the write side: the slots object's slot-set hash is the one the
	// newest slot-table audit row recorded. A workspace always has a genesis
	// slot-table row (init and every slot change write one); one that has none is
	// inconsistent and is not exported.
	want, err := layout.SlotSetHash(so.Meta.Policy, so.Slots)
	if err != nil {
		return stage(err, noteNothing)
	}
	foundRow := false
	for i := len(snap.Audit) - 1; i >= 0; i-- {
		if k := snap.Audit[i].Kind; k == "slots" || k == "rollover" {
			foundRow = true
			if !bytes.Equal(snap.Audit[i].SlotSet, want) {
				return stage(errors.New("the slot table does not hash to the slot-set hash of the newest slots or rollover audit row; the workspace is inconsistent and is not exported"), noteNothing)
			}
			break
		}
	}
	if !foundRow {
		return stage(errors.New("the workspace has no genesis slot-table row (an audit row of kind slots or rollover) to check its slot table against; it is inconsistent and is not exported"), noteNothing)
	}
	var auditSeq uint64
	auditMAC := make([]byte, layout.HashSize)
	if n := len(snap.Audit); n > 0 {
		auditSeq, auditMAC = uint64(snap.Audit[n-1].Seq), append([]byte(nil), snap.Audit[n-1].MAC...)
	}
	if err := e.verifyTrust(ctx); err != nil {
		return err
	}
	if err := e.checkHistory(snap, so, auditSeq); err != nil {
		return err
	}
	e.res.Fresh = e.st.newest() == nil
	if err := e.check(ctx); err != nil {
		return stage(err, noteNothing)
	}

	// the slots object first: it is plaintext and names the workspace, so a
	// directory that holds objects is always recognisable as this workspace's
	slotsHash, err := e.put(ctx, slotsStored)
	if err != nil {
		return err
	}
	e.obs.SlotsObjectBytes = len(slotsStored)

	// records
	entries := make([]layout.RecordEntry, 0, len(snap.Records))
	for i := range snap.Records {
		r := &snap.Records[i]
		ref := e.m.Refs[i]
		if r.Version < 1 {
			return stage(fmt.Errorf("a %s record has version %d", r.Kind, r.Version), noteNothing)
		}
		rec := layout.Record{
			Kind: r.Kind, Class: ref.Class, ID: r.ID, Anchor: ref.Anchor, Num: ref.Num,
			Version: uint64(r.Version), RecordFormat: layout.RecordFormat, UpdatedAt: r.UpdatedAt,
			Inner: layout.Inner{Nonce: r.Nonce, WrappedKey: r.WrappedKey, Owner: r.OwnerSealed, Ciphertext: r.Ciphertext},
		}
		h, err := e.seal(ctx, rec, fmt.Sprintf("a %s record of class %s", r.Kind, ref.Class))
		if err != nil {
			return err
		}
		entries = append(entries, layout.RecordEntry{ID: append([]byte(nil), r.ID...), Version: uint64(r.Version), Hash: h})
		*r = ports.SnapshotRecord{}
		e.m.Refs[i] = ports.RecordRef{}
	}
	// audit rows
	aentries := make([]layout.AuditEntry, 0, len(snap.Audit))
	for i := range snap.Audit {
		a := &snap.Audit[i]
		row := layout.Audit{Seq: a.Seq, At: a.At, Kind: a.Kind, Event: a.Event, Touched: a.Touched, SlotSet: a.SlotSet, MAC: a.MAC, PrevMAC: a.PrevMAC}
		h, err := e.seal(ctx, row, fmt.Sprintf("audit row %d", a.Seq))
		if err != nil {
			return err
		}
		aentries = append(aentries, layout.AuditEntry{Seq: uint64(a.Seq), Hash: h})
		*a = ports.SnapshotAudit{}
	}
	// pages
	rpages, err := layout.PageRecords(entries)
	if err != nil {
		return err
	}
	apages, err := layout.PageAudit(aentries)
	if err != nil {
		return err
	}
	if err := e.check(ctx); err != nil {
		return err
	}
	rhashes := make([][]byte, len(rpages))
	for i, p := range rpages {
		if rhashes[i], err = e.seal(ctx, p, fmt.Sprintf("record page %d", i)); err != nil {
			return err
		}
	}
	ahashes := make([][]byte, len(apages))
	for i, p := range apages {
		if ahashes[i], err = e.seal(ctx, p, fmt.Sprintf("audit page %d", i)); err != nil {
			return err
		}
	}
	root := func(seq uint64, prev []byte) layout.Root {
		return layout.Root{RecordPages: rhashes, AuditPages: ahashes, Slots: slotsHash, AuditSeq: auditSeq, AuditMAC: auditMAC,
			Records: uint64(len(entries)), Audits: uint64(len(aentries)),
			Parent: layout.Parent{Format: layout.ParentFormat, Seq: seq, PreviousHead: prev}}
	}
	// INV-007..009 on the write side: the root and the pages agree
	nextSeq, prevHash := uint64(1), make([]byte, layout.HashSize)
	if nh := e.st.newest(); nh != nil {
		if nh.head.Sequence+1 > MaxSequence {
			return stage(fmt.Errorf("the head sequence number %d is at the limit this tool accepts", nh.head.Sequence), noteBlocked)
		}
		nextSeq, prevHash = nh.head.Sequence+1, nh.hash
	}
	if err := layout.VerifyManifest(root(nextSeq, prevHash), rpages, apages); err != nil {
		return stage(fmt.Errorf("the manifest built from the snapshot does not verify: %w", err), noteObjects)
	}

	// Is anything new? The root names its own head's sequence number and the
	// hash of the head before it, so it is compared as it would be for the newest
	// head.
	var manifestHash []byte
	if nh := e.st.newest(); nh != nil {
		cand, err := e.sealRoot(root(nh.head.Sequence, nh.head.Previous))
		if err != nil {
			return err
		}
		if bytes.Equal(cand, nh.head.Manifest) && bytes.Equal(slotsHash, nh.head.Slots) {
			if _, err := e.putRoot(ctx, root(nh.head.Sequence, nh.head.Previous)); err != nil {
				return err
			}
			return e.upToDate(ctx, so, auditSeq, auditMAC)
		}
	}
	if e.completeSig {
		return stage(fmt.Errorf("%s was written by an interrupted export and has no signature, but the workspace has changed since: this run would write a new head after it, and a head that was never signed cannot be built on. Export to a fresh directory", layout.HeadPath(e.st.newest().head.Sequence)), noteBlocked)
	}
	manifestHash, err = e.putRoot(ctx, root(nextSeq, prevHash))
	if err != nil {
		return err
	}
	return e.writeHead(ctx, so, nextSeq, prevHash, manifestHash, slotsHash, auditSeq, auditMAC)
}

func (e *exporter) sealRoot(r layout.Root) ([]byte, error) {
	body, err := layout.EncodeBody(r)
	if err != nil {
		return nil, err
	}
	stored, err := e.m.Sealer.Seal(body)
	if err != nil {
		return nil, err
	}
	return layout.ObjectHash(stored), nil
}

func (e *exporter) putRoot(ctx context.Context, r layout.Root) ([]byte, error) {
	return e.seal(ctx, r, "the manifest root")
}

// upToDate is the end of a run that found nothing new. It writes no head. When
// the operator wants a signature and the newest head has none, it signs that
// head, but only a note that this run would have encoded itself from the verified
// snapshot (every field the same but the time); nothing else is put.
func (e *exporter) upToDate(ctx context.Context, so layout.SlotsObject, auditSeq uint64, auditMAC []byte) error {
	nh := e.st.newest()
	e.res.UpToDate = true
	e.res.HeadSequence, e.res.HeadHash = nh.head.Sequence, nh.hash
	signed, serr := e.sigStatus(ctx, nh)
	e.res.Signed = signed
	if signed && e.m.KeyRecord != nil {
		e.res.KeyHash = e.m.KeyRecord.Hash()
	}
	if sg := e.m.Signing; sg != nil && !signed {
		if serr != nil {
			return stage(fmt.Errorf("%s.sig is in the directory but does not verify (%v); this tool never replaces it", layout.HeadPath(nh.head.Sequence), serr), noteBlocked)
		}
		if !e.wouldBeThisHead(nh, so, auditSeq, auditMAC) {
			return stage(errors.New("the newest head in the directory has no signature and differs from the workspace (a field other than its time is not what this export would write); it is not signed"), noteBlocked)
		}
		if err := e.check(ctx); err != nil {
			return stage(err, noteSig)
		}
		armored, err := sg.Sign(ctx, layout.NamespaceHead, nh.note)
		if err != nil {
			return stage(fmt.Errorf("the newest head has no signature and signing it failed: %w", err), noteSig)
		}
		if err := e.putSig(ctx, nh.head.Sequence, armored); err != nil {
			return stage(err, noteSig)
		}
		e.res.Signed, e.res.SignedNow = true, true
		e.res.KeyHash = sg.Record.Hash()
	} else if serr != nil {
		e.res.Notices = append(e.res.Notices, fmt.Sprintf("%s.sig is in the directory but does not verify (%v): it is not counted as a signature", layout.HeadPath(nh.head.Sequence), serr))
	}
	return e.finish(ctx, nh.head.Sequence, nh.hash)
}

// wouldBeThisHead reports whether this run, for the workspace as it is, would
// encode the existing head's note but for its time.
func (e *exporter) wouldBeThisHead(nh *headInfo, so layout.SlotsObject, auditSeq uint64, auditMAC []byte) bool {
	want := nh.head
	want.Workspace, want.Slots, want.Manifest = e.in.WorkspaceID, nh.head.Slots, nh.head.Manifest
	want.AuditSeq, want.AuditMAC, want.RecoveryKey, want.Epoch = auditSeq, auditMAC, so.Meta.RecoveryPubHash, e.m.Snapshot.Meta.KeyEpoch
	cks := [][]byte{nil, e.m.Signing.Record.Hash()}
	if e.completeSig {
		cks = cks[1:] // an interrupted export wrote the key's hash
	}
	for _, ck := range cks {
		want.CheckpointKey = ck
		if note, err := want.Encode(); err == nil && bytes.Equal(note, nh.note) {
			return true
		}
	}
	return false
}

// sigStatus reports whether heads/<seq>.sig exists and verifies against the
// enrolled checkpoint key. With no key enrolled nothing can be verified: not
// signed, no error. A signature file that does not verify is an error value and
// is never counted.
func (e *exporter) sigStatus(ctx context.Context, h *headInfo) (bool, error) {
	if !e.st.sigs[h.head.Sequence] {
		return false, nil
	}
	if e.m.KeyRecord == nil {
		return false, errors.New("no checkpoint key is enrolled to verify it with")
	}
	b, err := readAll(ctx, e.in.Dir.Reader, layout.HeadPath(h.head.Sequence)+".sig", maxSigBytes)
	if err != nil {
		return false, err
	}
	blob, err := sshsig.Dearmor(b)
	if err != nil {
		return false, err
	}
	if _, err := sshsig.Verify(blob, h.note, layout.NamespaceHead, e.m.KeyRecord.Hash(), checkpoint.Application); err != nil {
		return false, err
	}
	return true, nil
}

// clockTolerance is how far in the future the time of a head may be.
const clockTolerance = 5 * time.Minute

// verifyTrust decides, once the workspace is unlocked and its checkpoint key is
// known, whether the heads this run would chain onto can be believed.
//
// With a checkpoint key enrolled the key is the only authority: every head the
// new head would build on (those above the pin, or all of them when this machine
// has no pin) must carry a signature that verifies, and --adopt-layout does not
// override a head that does not. The one exception is the completion of an
// interrupted export (see completable). With no key, a layout this machine has no
// pin for is trusted only on the operator's statement (--adopt-layout).
func (e *exporter) verifyTrust(ctx context.Context) error {
	if len(e.st.chain) == 0 {
		return nil
	}
	key := e.m.KeyRecord
	nh := e.st.newest()
	check := e.st.chain
	if e.st.pinned {
		check = check[1:]
	}
	when := nh.head.Time.UTC().Format("2006-01-02T15:04:05Z")
	var firstBad *headInfo
	var badWhy error
	if key != nil {
		for _, h := range check {
			ok, err := e.sigStatus(ctx, h)
			if !ok {
				if err == nil {
					err = errors.New("it has no signature")
				}
				firstBad, badWhy = h, err
				break
			}
		}
	}
	completing := false
	if firstBad != nil && e.completable(firstBad, badWhy) {
		e.completeSig = true
		completing, firstBad = true, nil
	}
	e.chainVerified = key != nil && firstBad == nil && !completing
	switch {
	case key != nil && firstBad != nil && e.st.pinned:
		return stage(fmt.Errorf("%s does not verify against this workspace's checkpoint key (%v): the directory holds heads that this machine did not write or cannot verify, and this tool will not chain onto them. Export to a fresh directory", layout.HeadPath(firstBad.head.Sequence), badWhy), noteBlocked)
	case key != nil && firstBad != nil:
		// the key is enrolled and a head does not verify: the flag does not override it
		return stage(fmt.Errorf("this machine has no pin for this layout and %s does not verify against the workspace's checkpoint key (%v): the layout was not made with this key, or not by this machine, and a checkpoint key is never overridden. Export to a fresh directory", layout.HeadPath(firstBad.head.Sequence), badWhy), noteBlocked)
	case e.st.pinned:
		return nil
	case key != nil:
		e.res.AdoptedByKey = true
		e.say(fmt.Sprintf("this machine had no pin for this layout; every one of its %d heads carries a signature that verifies against the workspace's checkpoint key, so it was trusted and the pin will be recorded", len(check)))
	case e.in.AdoptLayout:
		e.res.Adopted = true
		e.say(fmt.Sprintf("this machine had no pin for this layout; it is trusted because --adopt-layout was given: head %d (audit sequence %d, hash %x, written %s) is taken as written by this machine and the pin will be recorded", nh.head.Sequence, nh.head.AuditSeq, nh.hash, when))
	default:
		return stage(fmt.Errorf("this machine has no pin for this layout (the pin file lives beside the workspace file; it is missing, or this layout was made elsewhere) and the workspace has no checkpoint key to verify its heads with. Trusting an existing layout is your decision: give --adopt-layout to say it is yours (newest head: sequence %d, audit sequence %d, hash %x, written %s), or export to a fresh directory", nh.head.Sequence, nh.head.AuditSeq, nh.hash, when), noteBlocked)
	}
	return nil
}

// say reports what the run trusts, at the moment it decides: to Notify when set
// (before any pin is recorded), else in the result.
func (e *exporter) say(msg string) {
	if e.in.Notify != nil {
		e.in.Notify(msg)
		return
	}
	e.res.Notices = append(e.res.Notices, msg)
}

// completable reports whether head h, which does not verify, is the unsigned
// newest head of an export that was interrupted between putting the head and
// putting its signature, which this run may complete. All of these hold: a
// checkpoint key is enrolled and this run signs; there is a pin; h is the only
// head above the pin, it is the newest and at the pin's sequence plus one; there
// is no signature file for it at all; its checkpoint-key field is the enrolled
// key's hash; its time is not before the pinned head's and not more than
// clockTolerance in the future. Run() then also requires that the run would
// otherwise be "already up to date" and that the note is what this run would
// encode from the verified workspace but for its time.
func (e *exporter) completable(h *headInfo, why error) bool {
	key := e.m.KeyRecord
	c := e.st.chain
	if key == nil || e.m.Signing == nil || !e.st.pinned || len(c) != 2 || c[1] != h || e.st.sigs[h.head.Sequence] {
		return false
	}
	if h.head.Sequence != c[0].head.Sequence+1 || !bytes.Equal(h.head.CheckpointKey, key.Hash()) {
		return false
	}
	t := h.head.Time
	return !t.Before(c[0].head.Time) && !t.After(e.in.Now().Add(clockTolerance))
}

// checkHistory checks every head of the chain against the workspace: audit
// sequences do not go down along the chain and none is above the workspace's, the
// head's audit MAC is the workspace's audit row MAC at that sequence (zeros for
// sequence 0), and, for a head at or after the newest rollover row (before it the
// epoch and the recovery key of earlier times are not in the snapshot), the epoch
// and the recovery-key field are the current ones. A head that fails is refused
// by name.
func (e *exporter) checkHistory(snap *ports.Snapshot, so layout.SlotsObject, auditSeq uint64) error {
	if len(e.st.chain) == 0 {
		return nil
	}
	macAt := make(map[uint64][]byte, len(snap.Audit))
	var lastRollover uint64
	for _, a := range snap.Audit {
		macAt[uint64(a.Seq)] = a.MAC
		if a.Kind == "rollover" {
			lastRollover = uint64(a.Seq)
		}
	}
	var prev uint64
	for _, h := range e.st.chain {
		name := layout.HeadPath(h.head.Sequence)
		hs := h.head.AuditSeq
		if hs > auditSeq {
			if e.chainVerified {
				return stage(fmt.Errorf("%s (signed by this workspace's checkpoint key) records audit sequence %d, which is ahead of this workspace's %d: the workspace file is older than what was exported (for example restored from an older backup). Nothing was written; use a fresh directory if you want a layout of this older state", name, hs, auditSeq), noteBlocked)
			}
			return stage(fmt.Errorf("%w (%s: audit sequence %d; this workspace: %d)", ErrAhead, name, hs, auditSeq), noteBlocked)
		}
		if hs < prev {
			return stage(fmt.Errorf("%s records audit sequence %d, below the head before it (%d): it is not this workspace's history", name, hs, prev), noteBlocked)
		}
		prev = hs
		want := make([]byte, layout.HashSize)
		if hs > 0 {
			var ok bool
			if want, ok = macAt[hs]; !ok {
				return stage(fmt.Errorf("%s records audit sequence %d, which this workspace has no row for: the layout and the workspace are not the same workspace history", name, hs), noteBlocked)
			}
		}
		if !bytes.Equal(h.head.AuditMAC, want) {
			return stage(fmt.Errorf("%s records audit sequence %d with MAC %x, but this workspace's MAC at that sequence is %x: the layout and the workspace are not the same workspace history (they diverged, or this workspace was restored from a diverged backup)", name, hs, h.head.AuditMAC, want), noteBlocked)
		}
		if lastRollover == 0 || hs >= lastRollover {
			if !bytes.Equal(h.head.Epoch, e.m.Snapshot.Meta.KeyEpoch) || !bytes.Equal(h.head.RecoveryKey, so.Meta.RecoveryPubHash) {
				return stage(fmt.Errorf("%s names a key epoch or recovery key that is not this workspace's, although the workspace has not rotated since: the layout and the workspace are not the same workspace history", name), noteBlocked)
			}
		}
	}
	return nil
}

func (e *exporter) putSig(ctx context.Context, seq uint64, armored []byte) error {
	name := layout.HeadPath(seq) + ".sig"
	if err := e.in.Dir.Writer.Put(ctx, name, bytes.NewReader(armored), int64(len(armored))); err != nil {
		return fmt.Errorf("putting the signature: %w", err)
	}
	got, err := readAll(ctx, e.in.Dir.Reader, name, maxSigBytes)
	if err != nil || !bytes.Equal(got, armored) {
		return errors.New("the signature read back is not the one that was put")
	}
	return nil
}

func (e *exporter) writeHead(ctx context.Context, so layout.SlotsObject, seq uint64, prev, manifest, slots []byte, auditSeq uint64, auditMAC []byte) error {
	if err := e.check(ctx); err != nil {
		return err
	}
	h := layout.Head{
		Workspace: e.in.WorkspaceID, Sequence: seq, Previous: prev, Manifest: manifest, Slots: slots,
		AuditSeq: auditSeq, AuditMAC: auditMAC, RecoveryKey: so.Meta.RecoveryPubHash, Epoch: e.m.Snapshot.Meta.KeyEpoch,
		Time: e.in.Now().UTC().Truncate(time.Second),
	}
	if e.m.Signing != nil {
		h.CheckpointKey = e.m.Signing.Record.Hash()
	}
	note, err := h.Encode()
	if err != nil {
		return err
	}
	// the signature is made before the head is put: a failure to sign leaves no head
	var armored []byte
	if sg := e.m.Signing; sg != nil {
		if armored, err = sg.Sign(ctx, layout.NamespaceHead, note); err != nil {
			return stage(fmt.Errorf("the objects are in the directory but the head could not be signed: %w", err),
				"Objects written, no head written; the newest valid head of the directory, if there is one, is still complete. Run the command again: it does not put the objects again.")
		}
	}
	if err := e.check(ctx); err != nil {
		return stage(err, noteObjects)
	}
	path := layout.HeadPath(seq)
	if err := e.in.Dir.Writer.Put(ctx, path, bytes.NewReader(note), int64(len(note))); err != nil {
		if errors.Is(err, ports.ErrObjectExists) {
			return stage(fmt.Errorf("%s is already in the directory with other content (it appeared during this run); nothing was overwritten", path), noteBlocked)
		}
		return stage(fmt.Errorf("putting the head: %w", err), noteObjects)
	}
	got, err := readAll(ctx, e.in.Dir.Reader, path, layout.MaxHeadSize)
	if err != nil || !bytes.Equal(got, note) {
		return stage(errors.New("the head read back is not the one that was put"), noteObjects)
	}
	e.res.HeadWritten = true
	e.res.HeadSequence, e.res.HeadHash = seq, layout.HeadHash(note)
	e.st.headCount++
	if armored != nil {
		if err := e.putSig(ctx, seq, armored); err != nil {
			e.res.Signed = false
			return stage(err, noteSig)
		}
		e.res.Signed, e.res.SignedNow = true, true
		e.res.KeyHash = e.m.Signing.Record.Hash()
	}
	return e.finish(ctx, seq, e.res.HeadHash)
}

// finish advances the pin and fills in the result.
func (e *exporter) finish(ctx context.Context, seq uint64, hash []byte) error {
	if err := e.in.Dir.Pins.Advance(ports.LayoutPin{Sequence: seq, HeadHash: hash}); err != nil {
		return stage(fmt.Errorf("the pin could not be recorded: %w", err), noteHead)
	}
	ws := hex.EncodeToString(e.in.WorkspaceID)
	e.res.Pin = fmt.Sprintf("%s:layout:%d:%s", ws, seq, hex.EncodeToString(hash))
	if e.res.Signed && e.res.KeyHash != nil {
		e.res.LongPin = checkpoint.LongPin{WorkspaceID: e.in.WorkspaceID, KeyHash: e.res.KeyHash}.String()
	}
	e.obs.Heads = e.st.headCount
	e.res.Observed = e.obs
	return nil
}
