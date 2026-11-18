// Package backupsink is the use case of ADR 0012 stage 1: copy the existing
// sealed SQLite backup artefact to a sink (a directory or an S3 bucket) and
// fetch it back for the built `store restore`. It adds no cryptography: the
// file is already sealed. It knows the sink only through the object ports.
//
// Every failure says what state things are left in and that the command can be
// run again (StageError).
package backupsink

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// DefaultMaxObjectSize is the largest object Fetch downloads unless told
// otherwise (1 GiB).
const DefaultMaxObjectSize int64 = 1 << 30

// Head is the end of the audit chain of a backup: what `store verify` prints.
type Head struct {
	Seq uint64
	MAC []byte
}

// Pin is what the operator keeps outside the sink: the workspace id, the head
// of the backup and the SHA-256 of the file.
type Pin struct {
	WorkspaceID []byte
	Seq         uint64
	HeadMAC     []byte
	SHA256      []byte
}

// String is <workspace id hex>:<head sequence>:<head mac hex>:<sha256 hex>.
func (p Pin) String() string {
	return fmt.Sprintf("%s:%d:%s:%s", hex.EncodeToString(p.WorkspaceID), p.Seq, hex.EncodeToString(p.HeadMAC), hex.EncodeToString(p.SHA256))
}

var (
	hexRE = regexp.MustCompile(`^(?:[0-9a-f]{2})+$`)
	decRE = regexp.MustCompile(`^(?:0|[1-9][0-9]{0,19})$`)
)

// ParsePin parses a pin strictly.
func ParsePin(s string) (Pin, error) {
	f := strings.Split(s, ":")
	if len(f) != 4 || !hexRE.MatchString(f[0]) || !decRE.MatchString(f[1]) || !hexRE.MatchString(f[2]) || len(f[3]) != 64 || !hexRE.MatchString(f[3]) {
		return Pin{}, errors.New("the pin is not <workspace id hex>:<head sequence>:<head hash hex>:<file sha256 hex> (lower-case hex)")
	}
	seq, err := strconv.ParseUint(f[1], 10, 64)
	if err != nil {
		return Pin{}, errors.New("the pin's head sequence is not a number")
	}
	var p Pin
	p.WorkspaceID, _ = hex.DecodeString(f[0])
	p.Seq = seq
	p.HeadMAC, _ = hex.DecodeString(f[2])
	p.SHA256, _ = hex.DecodeString(f[3])
	return p, nil
}

// ObjectName is backups/<workspace id hex>/<head sequence, 20 digits>-<sha256 hex>.spo.
func ObjectName(ws []byte, seq uint64, sha []byte) string {
	return fmt.Sprintf("%s%020d-%s.spo", workspacePrefix(ws), seq, hex.EncodeToString(sha))
}

func workspacePrefix(ws []byte) string { return "backups/" + hex.EncodeToString(ws) + "/" }

var nameRE = regexp.MustCompile(`^backups/((?:[0-9a-f]{2})+)/([0-9]{20})-([0-9a-f]{64})\.spo$`)

// ParseName parses an object name strictly; ok is false for anything else.
func ParseName(name string) (ws []byte, seq uint64, sha []byte, ok bool) {
	m := nameRE.FindStringSubmatch(name)
	if m == nil {
		return nil, 0, nil, false
	}
	seq, err := strconv.ParseUint(m[2], 10, 64)
	if err != nil {
		return nil, 0, nil, false
	}
	ws, _ = hex.DecodeString(m[1])
	sha, _ = hex.DecodeString(m[3])
	return ws, seq, sha, true
}

// StageError is an error with one sentence saying what state the sink and the
// workspace are in and whether the command can be run again.
type StageError struct {
	Err  error
	Note string
}

func (e *StageError) Error() string {
	return strings.TrimRight(e.Err.Error(), ". \n") + ". " + e.Note
}
func (e *StageError) Unwrap() error { return e.Err }

const (
	noteRefused  = "Nothing was sent to the sink and the workspace is unchanged; once the cause is fixed the command can be run again."
	noteBefore   = "Nothing was sent to the sink and the workspace is unchanged; the command can be run again."
	noteUpload   = "The upload did not finish; the sink holds the complete object or none, never a partial one, and the workspace is unchanged; the command can be run again and completes or verifies the upload."
	noteExists   = "The object already in the sink was left as it was and nothing was added; the command cannot succeed until that name is free of other content (see the how-to)."
	noteUnverify = "The object is in the sink but was not verified; the command can be run again and verifies it without uploading it again."
	noteFaulty   = "Nothing was uploaded and the workspace is unchanged; do not rely on this sink until it has been checked."
	noteMismatch = "The object in the sink does not match the verified file and this tool never deletes it; treat this backup as not made, and see the how-to."

	noteFetchBefore = "Nothing was downloaded and the workspace is unchanged; the command can be run again."
	noteFetchStop   = "The download stopped and the workspace is unchanged; any partial download is kept, and the command can be run again with the same pin to resume it."
	noteFetchBad    = "The workspace is unchanged and the downloaded file was deleted; check the pin and the object, then run the command again."
	noteFetchKept   = "The workspace is unchanged and the verified download was kept; once the cause is fixed the command can be run again with the same pin and does not download again."
	noteFetchRest   = "The downloaded file was removed and the workspace was not replaced; once the cause is fixed the command can be run again."
)

func stage(err error, note string) error {
	if err == nil {
		return nil
	}
	return &StageError{Err: err, Note: note}
}

// Sink is a sink as the wiring hands it to a command: the ports an adapter
// honours, with the kind known without any network call. Each operation takes
// only the capabilities it needs (PushInput, FetchInput, List), so a missing
// capability is a compile-time fact for that operation.
type Sink struct {
	Kind   ports.SinkKind
	Writer ports.ObjectWriter
	Reader ports.ObjectReader
	Lister ports.ObjectLister
	Ranger ports.ObjectRangeReader
	Probe  ports.SinkProbe
}

// PushInput is what Push needs. Backup, Verify and Inspect are the existing
// backup, verification and keyless inspection of a backup file.
type PushInput struct {
	Kind   ports.SinkKind
	Writer ports.ObjectWriter
	Reader ports.ObjectReader
	Probe  ports.SinkProbe
	// Scratch is private space in the workspace directory for the temporary copy.
	Scratch ports.Scratch

	Policy      string
	WorkspaceID []byte

	Backup  func(ctx context.Context, dest string) (Head, error)
	Verify  func(path string) error
	Inspect func(path string) (id []byte, h Head, err error)
}

// PushResult is what a successful Push reports.
type PushResult struct {
	Name string
	Pin  Pin
	Size int64
	// StandardWarning: a standard workspace went to a directory; the command
	// prints the offline-guessing warning.
	StandardWarning bool
	// Uploaded is false when the object was already in the sink and only
	// verified.
	Uploaded bool
}

var errNoStandardS3 = errors.New("this workspace has the standard policy, which is password-only: whoever can read the bucket could guess the passphrase offline, so an S3 sink is refused for it. Rotate the workspace to the hardware policy (spo workspace rotate --policy hardware), or back up to a directory instead (spo store backup --sink dir:/absolute/path, or spo store backup <dest>)")

// RefuseStandardS3 is the first rule: an S3 sink is refused for a standard
// workspace. It needs no network, so a command applies it before it asks for
// anything.
func RefuseStandardS3(kind ports.SinkKind, policy string) error {
	if kind == ports.SinkS3 && policy == "standard" {
		return stage(errNoStandardS3, noteRefused)
	}
	return nil
}

// CheckSink applies the rules that must hold before any byte is sent: the
// policy of the workspace against the kind of sink and, for S3, what the bucket
// and the credentials are. A command runs it before it asks for any
// passphrase, PIN or touch.
func CheckSink(ctx context.Context, kind ports.SinkKind, policy string, probe ports.SinkProbe) error {
	switch kind {
	case ports.SinkDir:
		return nil
	case ports.SinkS3:
	default:
		return fmt.Errorf("unknown sink kind %q", kind)
	}
	if policy == "standard" {
		return errNoStandardS3
	}
	if policy != "hardware" && policy != "strict" {
		return fmt.Errorf("an S3 sink needs a workspace with the hardware or strict policy; this one reports %q", policy)
	}
	props, err := probe.Check(ctx)
	if err != nil {
		return fmt.Errorf("cannot check the bucket: %w", err)
	}
	var bad []string
	if !props.ShortLivedCredentials {
		bad = append(bad, "the credentials are not short-lived: they must expire within 12 hours and carry a session token, and static access keys are not accepted; use AWS SSO, IAM Roles Anywhere, IRSA or Workload Identity")
	}
	if !props.Versioning {
		bad = append(bad, "bucket versioning is not enabled")
	}
	if props.ObjectLockMode != "COMPLIANCE" {
		bad = append(bad, "Object Lock is not on in COMPLIANCE mode with a default rule (it reports "+quoteOrNone(props.ObjectLockMode)+")")
	} else if !props.ObjectLockDefaultRetention {
		bad = append(bad, "Object Lock has no default retention period")
	}
	if len(bad) > 0 {
		return errors.New("the bucket does not meet what a backup bucket needs: " + strings.Join(bad, "; "))
	}
	return nil
}

func quoteOrNone(s string) string {
	if s == "" {
		return "no mode"
	}
	return strconv.Quote(s)
}

func hashFile(f io.ReadSeeker) ([]byte, int64, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, 0, err
	}
	h := sha256.New()
	n, err := io.Copy(h, f)
	return h.Sum(nil), n, err
}

// ctxReader stops a copy when the context is cancelled.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// readBack downloads name and checks it is the size and SHA-256 given.
func readBack(ctx context.Context, r ports.ObjectReader, name string, size int64, sum []byte) error {
	rc, err := r.Get(ctx, name)
	if err != nil {
		return err
	}
	defer rc.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(ctxReader{ctx, rc}, size+1))
	if err != nil {
		return err
	}
	if n != size || !bytes.Equal(h.Sum(nil), sum) {
		return errMismatch
	}
	return nil
}

var errMismatch = errors.New("the object read back from the sink differs from the file that was uploaded")

// Sweep ages: only an entry of the exact own pattern, a regular file or a
// directory of this user (never a symbolic link), older than StaleAge is removed.
const StaleAge = time.Hour

var backupDirRE = regexp.MustCompile(`^\.spo-backup-[0-9]+$`)

// sweep removes the leftovers of a crashed run. A partial download of the pin in
// keep is not touched.
func sweep(sc ports.Scratch, keep string) {
	ents, err := sc.Entries()
	if err != nil {
		return
	}
	for _, e := range ents {
		if !e.Owned || time.Since(e.ModTime) < StaleAge || e.Name == keep {
			continue
		}
		switch {
		case backupDirRE.MatchString(e.Name) && e.Kind == ports.ScratchDirectory,
			partialRE.MatchString(e.Name) && e.Kind == ports.ScratchRegular:
			sc.Remove(e.Name)
		}
	}
}

// Push backs up the workspace into the sink. See the package comment. The
// rules are checked before the backup is made and before any byte is sent.
func Push(ctx context.Context, in PushInput) (res PushResult, err error) {
	note := noteRefused
	defer func() {
		if err != nil {
			err = stage(err, note)
		}
	}()
	if err = CheckSink(ctx, in.Kind, in.Policy, in.Probe); err != nil {
		return PushResult{}, err
	}
	note = noteBefore
	res.StandardWarning = in.Kind == ports.SinkDir && in.Policy == "standard"
	sweep(in.Scratch, "")

	tmp, err := in.Scratch.MakeDir(".spo-backup-")
	if err != nil {
		return PushResult{}, err
	}
	defer in.Scratch.Remove(tmp)
	rel := tmp + "/backup.spo"
	dest := in.Scratch.Path(rel)
	head, err := in.Backup(ctx, dest)
	if err != nil {
		return PushResult{}, err
	}
	if err := in.Verify(dest); err != nil {
		return PushResult{}, fmt.Errorf("the backup was written but FAILED verification (%w); it was not sent", err)
	}
	id, h, err := in.Inspect(dest)
	if err != nil {
		return PushResult{}, err
	}
	if !bytes.Equal(id, in.WorkspaceID) {
		return PushResult{}, errors.New("the backup file names another workspace than the one that was opened; it was not sent")
	}
	if h.Seq != head.Seq || !bytes.Equal(h.MAC, head.MAC) {
		return PushResult{}, errors.New("the head of the backup file is not the head the backup reported; it was not sent")
	}
	f, err := in.Scratch.Open(rel)
	if err != nil {
		return PushResult{}, err
	}
	defer f.Close()
	sum, size, err := hashFile(f)
	if err != nil {
		return PushResult{}, err
	}
	name := ObjectName(id, h.Seq, sum)
	res.Name, res.Size = name, size
	res.Pin = Pin{WorkspaceID: id, Seq: h.Seq, HeadMAC: h.MAC, SHA256: sum}

	// Only the object this file's own hash names is looked at: nothing a sink
	// lists is downloaded, parsed or verified here. A second object for the same
	// head (the same workspace backed up twice with other bytes) is accepted.
	have, err := in.Reader.Has(ctx, name)
	if err != nil {
		return PushResult{}, err
	}
	if !have {
		note = noteUpload
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return PushResult{}, err
		}
		if err := in.Writer.Put(ctx, name, f, size); err != nil {
			if errors.Is(err, ports.ErrObjectExists) {
				note = noteExists
			}
			return PushResult{}, err
		}
		res.Uploaded = true
	}
	note = noteUnverify
	if err := readBack(ctx, in.Reader, name, size, sum); err != nil {
		switch {
		case !res.Uploaded && (errors.Is(err, ports.ErrObjectNotFound) || errors.Is(err, errMismatch)):
			// the sink said the object exists and cannot return it, or returns other
			// bytes under a name that is their hash: not a transfer to repeat
			note = noteFaulty
			return PushResult{}, errors.New("the sink reports an object under this name that it cannot return as the file that was backed up: the sink is faulty or hostile")
		case errors.Is(err, errMismatch):
			note = noteMismatch
			return PushResult{}, fmt.Errorf("uploaded but NOT verified: %w", err)
		}
		return PushResult{}, fmt.Errorf("uploaded but not verified: the object could not be read back from the sink (%w)", err)
	}
	return res, nil
}

// BackupEntry is one recognised backup in a listing.
type BackupEntry struct {
	Name        string
	WorkspaceID []byte
	Seq         uint64
	SHA256      []byte
	Size        int64
}

// ListResult is what List found: the backups of the workspace, newest first,
// and the names under its prefix that do not parse (never trusted).
type ListResult struct {
	Backups      []BackupEntry
	Unrecognised []string
}

// List lists the backups of the workspace id in the sink.
func List(ctx context.Context, l ports.ObjectLister, ws []byte) (ListResult, error) {
	infos, err := l.List(ctx, workspacePrefix(ws))
	if err != nil {
		return ListResult{}, err
	}
	var res ListResult
	for _, o := range infos {
		id, seq, sha, ok := ParseName(o.Name)
		if !ok || !bytes.Equal(id, ws) {
			res.Unrecognised = append(res.Unrecognised, o.Name)
			continue
		}
		res.Backups = append(res.Backups, BackupEntry{Name: o.Name, WorkspaceID: id, Seq: seq, SHA256: sha, Size: o.Size})
	}
	sort.SliceStable(res.Backups, func(i, j int) bool {
		if res.Backups[i].Seq != res.Backups[j].Seq {
			return res.Backups[i].Seq > res.Backups[j].Seq
		}
		return res.Backups[i].Name < res.Backups[j].Name
	})
	return res, nil
}

// FetchInput is what Fetch needs. Restore is the existing restore path, which
// keeps every refusal it has; it is handed the path of the verified download and
// its SHA-256, which the restore checks again on its own private copy.
type FetchInput struct {
	Reader  ports.ObjectReader
	Ranger  ports.ObjectRangeReader
	Scratch ports.Scratch // the workspace directory: the partial download lives there
	Pin     Pin
	Name    string // optional; default: the object the pin names
	MaxSize int64  // 0: DefaultMaxObjectSize

	Inspect func(path string) (id []byte, h Head, err error)
	Restore func(path string, sha256 []byte) error
}

var partialRE = regexp.MustCompile(`^\.spo-fetch-[0-9a-f]{64}\.partial$`)

// PartialName is the private partial file of a download of the pinned file.
func PartialName(sha []byte) string { return ".spo-fetch-" + hex.EncodeToString(sha) + ".partial" }

// notAboutTheFile marks a restore refusal that is not about the content of the
// file (a wrong passphrase, a missing --force, a cancelled prompt).
type notAboutTheFile struct{ err error }

func (e *notAboutTheFile) Error() string { return e.err.Error() }
func (e *notAboutTheFile) Unwrap() error { return e.err }

// NotAboutTheFile marks err as a refusal that says nothing against the
// verified download: Fetch keeps the file so that a re-run does not download it
// again. Any other restore error deletes it.
func NotAboutTheFile(err error) error {
	if err == nil {
		return nil
	}
	return &notAboutTheFile{err}
}

// Fetch downloads the pinned backup and hands it to the restore path. The file
// is accepted only when its SHA-256, workspace id and head are the pin's. An
// interrupted download is resumed by the next run with the same pin.
func Fetch(ctx context.Context, in FetchInput) (err error) {
	note := noteFetchBefore
	keep := false
	var total int64 // bytes in the partial file
	own := PartialName(in.Pin.SHA256)
	defer func() {
		if !keep || total == 0 {
			in.Scratch.Remove(own)
		}
		if err != nil {
			err = stage(err, note)
		}
	}()
	max := in.MaxSize
	if max <= 0 {
		max = DefaultMaxObjectSize
	}
	name := in.Name
	if name == "" {
		name = ObjectName(in.Pin.WorkspaceID, in.Pin.Seq, in.Pin.SHA256)
	} else if ws, _, _, ok := ParseName(name); !ok || !bytes.Equal(ws, in.Pin.WorkspaceID) {
		return errors.New("the object name is not a backup of the pinned workspace")
	}
	sweep(in.Scratch, own)
	// a partial file of another pin is not ours to keep (exact pattern, regular
	// file of this user; a link or another type is left alone)
	if ents, derr := in.Scratch.Entries(); derr == nil {
		for _, e := range ents {
			if e.Name != own && e.Owned && e.Kind == ports.ScratchRegular && partialRE.MatchString(e.Name) {
				in.Scratch.Remove(e.Name)
			}
		}
	}
	keep = true // from here an interrupted download is resumable
	note = noteFetchStop
	f, err := in.Scratch.Open(own)
	if err != nil {
		return err
	}
	defer f.Close()
	bad := func(e error) error { keep = false; note = noteFetchBad; return e }
	have, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	total = have
	if have > max {
		if err := f.Truncate(0); err != nil {
			return err
		}
		have = 0
	}
	complete := false
	if have > 0 {
		if sum, _, err := hashFile(f); err != nil {
			return err
		} else if bytes.Equal(sum, in.Pin.SHA256) {
			complete = true
		}
	}
	if !complete {
		var rc io.ReadCloser
		if have > 0 {
			rc, err = in.Ranger.GetRange(ctx, name, have)
			if errors.Is(err, ports.ErrRangeNotSatisfiable) {
				rc, err, have = nil, nil, 0 // a stale partial longer than the object: start again
			}
		}
		if err != nil {
			return err
		}
		if rc == nil {
			if err := f.Truncate(0); err != nil {
				return err
			}
			have = 0
			if rc, err = in.Reader.Get(ctx, name); err != nil {
				return err
			}
		}
		defer rc.Close()
		if _, err := f.Seek(have, io.SeekStart); err != nil {
			return err
		}
		n, err := io.Copy(f, io.LimitReader(ctxReader{ctx, rc}, max-have+1))
		total = have + n
		if err != nil {
			return err
		}
		if have+n > max {
			return bad(fmt.Errorf("the object is larger than the limit of %d bytes", max))
		}
		if err := f.Sync(); err != nil {
			return err
		}
	}
	sum, _, err := hashFile(f)
	if err != nil {
		return err
	}
	if !bytes.Equal(sum, in.Pin.SHA256) {
		return bad(errors.New("the downloaded file's SHA-256 is not the one in the pin: the object was changed, or the pin or the partial file is wrong; the partial file was deleted"))
	}
	f.Close()
	path := in.Scratch.Path(own)
	id, h, err := in.Inspect(path)
	if err != nil {
		return bad(fmt.Errorf("the downloaded file cannot be read as a backup: %w", err))
	}
	if !bytes.Equal(id, in.Pin.WorkspaceID) {
		return bad(errors.New("the downloaded file is a backup of another workspace than the pin names"))
	}
	if h.Seq != in.Pin.Seq || !bytes.Equal(h.MAC, in.Pin.HeadMAC) {
		return bad(fmt.Errorf("the head of the downloaded file (sequence %d) is not the head in the pin (sequence %d)", h.Seq, in.Pin.Seq))
	}
	note = noteFetchRest
	keep = false
	if rerr := in.Restore(path, in.Pin.SHA256); rerr != nil {
		var na *notAboutTheFile
		if errors.As(rerr, &na) {
			keep = true
			note = noteFetchKept
		}
		return rerr
	}
	return nil
}
