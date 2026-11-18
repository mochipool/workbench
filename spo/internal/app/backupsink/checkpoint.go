package backupsink

// ADR 0012 stage 2: the signed checkpoint. A checkpoint is a small object that
// sits beside a backup (`<name without .spo>.checkpoint`) and says, under the
// signature of the workspace's checkpoint key, what the backup is: its workspace,
// head, slot table, size and SHA-256. A restore that holds only the key's hash
// (the long-lived pin) can then choose the newest authentic backup of an
// untrusted sink: nothing is downloaded for a candidate whose checkpoint does not
// verify.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/checkpoint"
	"github.com/mochipool/workbench/spo/internal/domain/sshsig"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Limits on what a restore asks a sink for while it looks for a checkpoint.
const (
	// MaxCandidates is the number of backups a restore examines (newest first).
	MaxCandidates = 16
	// MaxNames is the number of names a restore looks at in all, with or without a
	// checkpoint (candidates without one do not count against MaxCandidates).
	MaxNames = 256
	// MaxCheckpointBytes is the total a restore reads of checkpoint objects.
	MaxCheckpointBytes = MaxCandidates * checkpoint.MaxObjectSize
)

// Signing is how a command asks the checkpoint key for a signature over a
// statement. It is the one place that touches the authenticator.
type Signing struct {
	Record  checkpoint.KeyRecord
	Source  ports.SignatureFactor
	Device  string
	PIN     func(ctx context.Context) (*ports.Secret, error)
	Notify  func(msg string)
	Now     func() time.Time
	MaxWait time.Duration
}

// Sign makes the armored SSH signature of text under namespace with the
// checkpoint key: one PIN and one touch. The signature is checked here (the key
// hash, the flags, the namespace and the ECDSA signature) before it is returned,
// so a faulty authenticator is noticed before anything is put in a sink.
func (s Signing) Sign(ctx context.Context, namespace string, text []byte) ([]byte, error) {
	signed, err := sshsig.SignedData(namespace, sshsig.SHA512, text)
	if err != nil {
		return nil, err
	}
	var pin *ports.Secret
	if s.PIN != nil {
		if pin, err = s.PIN(ctx); err != nil {
			return nil, err
		}
		if pin != nil {
			defer pin.Destroy()
		}
	}
	if s.Notify != nil {
		s.Notify("touch the checkpoint authenticator to sign")
	}
	a, err := s.Source.SignAssert(ctx, ports.SignRequest{
		Device: s.Device, RPID: checkpoint.Application, CredentialID: s.Record.CredentialID,
		ClientDataHash: sshsig.ClientDataHash(signed), PIN: pin,
	})
	if err != nil {
		return nil, err
	}
	blob, err := sshsig.Encode(s.Record.Key, namespace, sshsig.SHA512, sshsig.Assertion{Flags: a.Flags, Counter: a.Counter, Signature: a.Signature})
	if err != nil {
		return nil, err
	}
	if _, err := sshsig.Verify(blob, text, namespace, s.Record.Hash(), checkpoint.Application); err != nil {
		return nil, fmt.Errorf("the authenticator's answer is not a valid signature by the checkpoint key: %w", err)
	}
	return []byte(sshsig.Armor(blob)), nil
}

// Facts are what is known about one backup file when its checkpoint is made.
type Facts struct {
	WorkspaceID []byte
	Head        Head
	SlotTable   []byte
	SHA256      []byte
	Size        uint64
}

// StatementFor builds the statement of a backup file.
func StatementFor(f Facts, keyHash []byte, now time.Time) checkpoint.Statement {
	return checkpoint.Statement{
		WorkspaceID: f.WorkspaceID, Seq: f.Head.Seq, HeadMAC: f.Head.MAC, SlotTable: f.SlotTable,
		SHA256: f.SHA256, Size: f.Size, Time: now.UTC().Truncate(time.Second), KeyHash: keyHash,
	}
}

// SignFacts is the signed checkpoint object of a backup file.
func (s Signing) SignFacts(ctx context.Context, f Facts) (checkpoint.Signed, error) {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	text := StatementFor(f, s.Record.Hash(), now()).Encode()
	armored, err := s.Sign(ctx, checkpoint.TagCheckpoint, text)
	if err != nil {
		return checkpoint.Signed{}, err
	}
	return checkpoint.Signed{Statement: text, Armored: armored}, nil
}

// CheckpointName is the name of the checkpoint beside the backup object name.
func CheckpointName(backupName string) (string, bool) { return checkpoint.ObjectName(backupName) }

var checkpointRE = regexp.MustCompile(`^(backups/(?:[0-9a-f]{2})+/[0-9]{20}-[0-9a-f]{64})\.checkpoint$`)

// matchesFacts reports whether the statement describes exactly these facts.
func matchesFacts(st checkpoint.Statement, f Facts) bool {
	return bytes.Equal(st.WorkspaceID, f.WorkspaceID) && st.Seq == f.Head.Seq && bytes.Equal(st.HeadMAC, f.Head.MAC) &&
		bytes.Equal(st.SlotTable, f.SlotTable) && bytes.Equal(st.SHA256, f.SHA256) && st.Size == f.Size
}

// readBounded reads an object of at most max bytes; a longer one is an error.
func readBounded(ctx context.Context, r ports.ObjectReader, name string, max int64) ([]byte, error) {
	rc, err := r.Get(ports.WithExpectedSize(ctx, max), name)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(ctxReader{ctx, rc}, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("the object is larger than %d bytes", max)
	}
	return b, nil
}

// ErrNotSigned wraps the failure to sign a backup that was uploaded and verified.
var ErrNotSigned = errors.New("uploaded and verified, but NOT signed")

const noteNotSigned = "The backup object is in the sink and was verified, but it has no checkpoint, so a long-lived pin cannot restore it. Run the command again: it finds the object, does not upload it again and signs it."

// PushCheckpoint is the second half of a push: after the object was verified in
// the sink, sign its statement and put it as <name>.checkpoint. It makes no
// prompt when a valid checkpoint for exactly this file is already there (a
// re-run after the answer was lost), and refuses a checkpoint under that name
// that is not. The put is create-if-absent and is read back.
type CheckpointPush struct {
	Writer  ports.ObjectWriter
	Reader  ports.ObjectReader
	Signing Signing
}

// CheckpointResult says what PushCheckpoint did.
type CheckpointResult struct {
	Name string
	// Existing is true when a valid checkpoint for this file was already in the
	// sink and nothing was signed or put.
	Existing  bool
	Statement checkpoint.Statement
}

// Run signs and puts the checkpoint of the pushed object.
func (c CheckpointPush) Run(ctx context.Context, objectName string, f Facts) (res CheckpointResult, err error) {
	name, ok := checkpoint.ObjectName(objectName)
	if !ok {
		return res, errors.New("the object name has no checkpoint name")
	}
	res.Name = name
	defer func() {
		if err != nil {
			if errors.Is(err, ErrNotSigned) {
				err = stage(err, noteNotSigned)
			} else {
				err = stage(err, "The backup object is in the sink and was verified; the checkpoint beside it is not in a state this tool trusts. See the how-to.")
			}
		}
	}()
	have, err := c.Reader.Has(ctx, name)
	if err != nil {
		return res, fmt.Errorf("%w: the sink could not say whether a checkpoint exists (%v)", ErrNotSigned, err)
	}
	if have {
		b, err := readBounded(ctx, c.Reader, name, checkpoint.MaxObjectSize)
		if err != nil {
			return res, fmt.Errorf("the sink says a checkpoint exists under %s but cannot return it (%v): the sink is faulty or hostile", "this name", err)
		}
		sg, err := checkpoint.ParseObject(b)
		if err == nil {
			var st checkpoint.Statement
			if st, _, err = sg.Verify(c.Signing.Record.Hash()); err == nil && matchesFacts(st, f) {
				res.Existing, res.Statement = true, st
				return res, nil
			}
		}
		return res, errors.New("a checkpoint already in the sink under this name does not verify as the checkpoint of this file: the sink was altered or is faulty; this tool never deletes or replaces it")
	}
	sg, err := c.Signing.SignFacts(ctx, f)
	if err != nil {
		return res, fmt.Errorf("%w: %v", ErrNotSigned, err)
	}
	obj := sg.EncodeObject()
	if err := c.Writer.Put(ctx, name, bytes.NewReader(obj), int64(len(obj))); err != nil {
		return res, fmt.Errorf("%w: the checkpoint could not be put (%v)", ErrNotSigned, err)
	}
	back, err := readBounded(ctx, c.Reader, name, checkpoint.MaxObjectSize)
	if err != nil || !bytes.Equal(back, obj) {
		return res, fmt.Errorf("%w: the checkpoint read back from the sink is not the one that was put", ErrNotSigned)
	}
	st, _ := checkpoint.ParseStatement(sg.Statement)
	res.Statement = st
	return res, nil
}

// ---- verification of one checkpoint against a long-lived pin ----

// verifyAgainstPin checks a checkpoint object read from the sink for the backup
// object name: the signature against the pinned key hash, the workspace, the
// minimum sequence and the backup's own name.
func verifyAgainstPin(obj []byte, backupName string, pin checkpoint.LongPin) (checkpoint.Statement, error) {
	sg, err := checkpoint.ParseObject(obj)
	if err != nil {
		return checkpoint.Statement{}, err
	}
	st, _, err := sg.Verify(pin.KeyHash)
	if err != nil {
		return checkpoint.Statement{}, err
	}
	if !bytes.Equal(st.WorkspaceID, pin.WorkspaceID) {
		return checkpoint.Statement{}, errors.New("the statement names another workspace than the pin")
	}
	if pin.HasMin && st.Seq < pin.MinSeq {
		return checkpoint.Statement{}, fmt.Errorf("the statement's sequence %d is below the pin's minimum %d", st.Seq, pin.MinSeq)
	}
	ws, seq, sha, ok := ParseName(backupName)
	if !ok || !bytes.Equal(ws, st.WorkspaceID) || seq != st.Seq || !bytes.Equal(sha, st.SHA256) {
		return checkpoint.Statement{}, errors.New("the statement does not name the object it sits beside (workspace, sequence and SHA-256 in the object name)")
	}
	return st, nil
}

// VerifyObject checks a checkpoint object against a long-lived pin for the
// backup object name; it is what `store verify --checkpoint` and the listing use.
func VerifyObject(obj []byte, backupName string, pin checkpoint.LongPin) (checkpoint.Statement, error) {
	return verifyAgainstPin(obj, backupName, pin)
}

// VerifyFile checks a local backup file's own facts against a verified
// statement: SHA-256, size, workspace, head and slot table.
func VerifyFile(st checkpoint.Statement, f Facts) error {
	switch {
	case !bytes.Equal(st.SHA256, f.SHA256):
		return errors.New("the file's SHA-256 is not the one in the checkpoint")
	case st.Size != f.Size:
		return fmt.Errorf("the file's size (%d) is not the one in the checkpoint (%d)", f.Size, st.Size)
	case !bytes.Equal(st.WorkspaceID, f.WorkspaceID):
		return errors.New("the file is a backup of another workspace than the checkpoint names")
	case st.Seq != f.Head.Seq || !bytes.Equal(st.HeadMAC, f.Head.MAC):
		return fmt.Errorf("the file's head (sequence %d) is not the head in the checkpoint (sequence %d)", f.Head.Seq, st.Seq)
	case !bytes.Equal(st.SlotTable, f.SlotTable):
		return errors.New("the file's slot table is not the one in the checkpoint")
	}
	return nil
}

// HashBytes is SHA-256 of b.
func HashBytes(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

// ---- listing with checkpoints ----

// CheckpointStatus is what a listing says about the checkpoint of one backup.
type CheckpointStatus struct {
	Present  bool
	Examined bool  // the long-lived pin was given and this one was read
	Err      error // why it does not verify, when Examined
	Seq      uint64
}

// CheckPinned reads the checkpoints of up to MaxCandidates of the listed
// backups (newest first) and verifies each against the pin. It reads at most
// MaxCheckpointBytes in all.
func CheckPinned(ctx context.Context, r ports.ObjectReader, list ListResult, pin checkpoint.LongPin) map[string]CheckpointStatus {
	out := map[string]CheckpointStatus{}
	var budget int64 = MaxCheckpointBytes
	n := 0
	for _, b := range list.Backups {
		cs := CheckpointStatus{Present: b.HasCheckpoint}
		if !b.HasCheckpoint || n >= MaxCandidates || budget <= 0 {
			out[b.Name] = cs
			continue
		}
		n++
		cs.Examined = true
		name, _ := checkpoint.ObjectName(b.Name)
		max := int64(checkpoint.MaxObjectSize)
		if max > budget {
			max = budget
		}
		obj, err := readBounded(ctx, r, name, max)
		budget -= int64(len(obj))
		if err != nil {
			cs.Err = err
		} else if st, err := verifyAgainstPin(obj, b.Name, pin); err != nil {
			cs.Err = err
		} else {
			cs.Seq = st.Seq
		}
		out[b.Name] = cs
	}
	return out
}

// ---- restore from the newest authentic backup ----

// LatestInput is what FetchLatest needs: Fetch's, with a long-lived pin in
// place of the exact one.
type LatestInput struct {
	Reader  ports.ObjectReader
	Ranger  ports.ObjectRangeReader
	Lister  ports.ObjectLister
	Scratch ports.Scratch
	Pin     checkpoint.LongPin

	// Facts reads the workspace id, head and slot-table hash of the downloaded file.
	Facts   func(path string) (Facts, error)
	Inspect func(path string) (id []byte, h Head, err error)
	Restore func(name, path string, sha256 []byte) error
	// Below, when HasBelow, starts the search below that head sequence: candidates
	// at or above it are not looked at.
	Below    uint64
	HasBelow bool
	// Report is told of every candidate that was skipped, and why; the text may
	// hold what the sink supplied and is not safe to print as it is.
	Report func(name, why string)
}

// LatestResult says which backup was used.
type LatestResult struct {
	Name      string
	Statement checkpoint.Statement
	Examined  int
}

// restoreFailed marks an error from the restore itself, which ends the search.
type restoreFailed struct{ err error }

func (e *restoreFailed) Error() string { return e.err.Error() }
func (e *restoreFailed) Unwrap() error { return e.err }

// BadObject marks a download that is not the object the statement describes (the
// hash, the size or the head are wrong): the candidate is skipped.
type BadObject struct{ Err error }

func (e *BadObject) Error() string { return e.Err.Error() }
func (e *BadObject) Unwrap() error { return e.Err }

// FetchLatest restores the newest backup of the pinned workspace whose
// checkpoint verifies against the pinned key hash. It looks at no more than
// MaxCandidates backups, newest first by the sequence in their names; for each it
// reads the checkpoint (bounded), and only when that verifies does it download
// the object and check its SHA-256, size, workspace id, head and slot table
// against the statement before it hands the file to the restore. A candidate that
// fails is reported and skipped; a failure of the transport or of the restore
// itself ends the search, so a network error never silently restores an older
// backup. Without a minimum sequence in the pin the result proves authenticity,
// not freshness: a sink can offer an older checkpoint and object that were once
// valid.
func FetchLatest(ctx context.Context, in LatestInput) (LatestResult, error) {
	report := in.Report
	if report == nil {
		report = func(string, string) {}
	}
	list, err := List(ctx, in.Lister, in.Pin.WorkspaceID)
	if err != nil {
		return LatestResult{}, stage(err, noteFetchBefore)
	}
	var res LatestResult
	var budget int64 = MaxCheckpointBytes
	names := 0
	var queue []BackupEntry
	for _, b := range list.Backups {
		if in.HasBelow && b.Seq >= in.Below {
			continue
		}
		queue = append(queue, b)
	}
	stopped := func(why string, i int) error {
		left := len(queue) - i
		next := ""
		if i < len(queue) {
			next = fmt.Sprintf(" (start below the last one looked at with --below %d)", queue[i-1].Seq)
			if i == 0 {
				next = ""
			}
		}
		return stage(fmt.Errorf("no backup of this workspace in the sink has a checkpoint that verifies against the pin within the limits (%s); %d candidates were not examined and a valid backup may exist below them%s; nothing was restored", why, left, next), noteFetchBefore)
	}
	for i, b := range queue {
		if names >= MaxNames {
			report("", fmt.Sprintf("stopped after looking at %d names", MaxNames))
			return res, stopped(fmt.Sprintf("at most %d names are looked at", MaxNames), i)
		}
		names++
		if !b.HasCheckpoint {
			report(b.Name, "no checkpoint")
			continue
		}
		if res.Examined >= MaxCandidates {
			report("", fmt.Sprintf("stopped after %d candidates", MaxCandidates))
			return res, stopped(fmt.Sprintf("at most %d candidates with a checkpoint are examined", MaxCandidates), i)
		}
		if budget <= 0 {
			report("", "stopped: the limit on checkpoint bytes was reached")
			return res, stopped("the limit on checkpoint bytes was reached", i)
		}
		res.Examined++
		cpName, _ := checkpoint.ObjectName(b.Name)
		max := int64(checkpoint.MaxObjectSize)
		if max > budget {
			max = budget
		}
		obj, rerr := readBounded(ctx, in.Reader, cpName, max)
		budget -= int64(len(obj))
		if rerr != nil {
			if ctx.Err() != nil || errors.Is(rerr, ports.ErrObjectNotFound) {
				if ctx.Err() != nil {
					return res, stage(rerr, noteFetchBefore)
				}
				report(b.Name, "the sink listed a checkpoint it cannot return")
				continue
			}
			if strings.Contains(rerr.Error(), "larger than") {
				report(b.Name, "the checkpoint is too large")
				continue
			}
			return res, stage(fmt.Errorf("the checkpoint of %s could not be read: %w", b.Name, rerr), noteFetchBefore)
		}
		st, verr := verifyAgainstPin(obj, b.Name, in.Pin)
		if verr != nil {
			report(b.Name, "checkpoint refused: "+verr.Error())
			continue
		}
		// From here the checkpoint VERIFIED for st.Seq: that sequence is a floor. A
		// backup that was made, and whose object cannot be obtained or does not match,
		// is not a reason to quietly restore an older one.
		floor := func(why string) error {
			return stage(fmt.Errorf("the checkpoint for sequence %d verified against the pinned key, but its object %s; nothing was restored. An older backup can be restored only with an explicit --below %d, which you give knowing that sequence %d existed", st.Seq, why, st.Seq, st.Seq), noteFetchBefore)
		}
		if st.Size == 0 || st.Size > uint64(DefaultMaxObjectSize) {
			return res, floor("has a size outside the limits")
		}
		var restoreErr error
		err := Fetch(ctx, FetchInput{
			Reader: in.Reader, Ranger: in.Ranger, Scratch: in.Scratch, Name: b.Name,
			Pin:     Pin{WorkspaceID: st.WorkspaceID, Seq: st.Seq, HeadMAC: st.HeadMAC, SHA256: st.SHA256},
			MaxSize: int64(st.Size), ExpectedSize: int64(st.Size), HasExpectedSize: true,
			Inspect: in.Inspect,
			Check: func(path string) error {
				f, err := in.Facts(path)
				if err != nil {
					return err
				}
				f.SHA256, f.Size = st.SHA256, st.Size
				return VerifyFile(st, f)
			},
			Restore: func(path string, sha []byte) error {
				restoreErr = in.Restore(b.Name, path, sha)
				return restoreErr
			},
		})
		if err == nil {
			res.Name, res.Statement = b.Name, st
			return res, nil
		}
		var bad *BadObject
		switch {
		case restoreErr == nil && errors.As(err, &bad):
			report(b.Name, "the object does not match its checkpoint: "+bad.Err.Error())
			return res, floor("did not match it (" + bad.Err.Error() + ")")
		case restoreErr == nil && errors.Is(err, ports.ErrObjectNotFound):
			return res, floor("could not be obtained (the sink does not return it)")
		}
		return res, err
	}
	return res, stage(errors.New("no backup of this workspace in the sink has a checkpoint that verifies against the pin; nothing was restored"), noteFetchBefore)
}
