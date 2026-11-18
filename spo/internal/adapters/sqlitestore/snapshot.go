package sqlitestore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// RAW SNAPSHOTS (ADR 0012 stage 3, spec/extensions/Xsnapshot.md).
//
// ReadSnapshot moves the rows of a verified store file into a ports.Snapshot
// and WriteSnapshotFile builds a new file from one, neither decrypting a
// record. Both verify through the presented credential (a passphrase, the
// printed recovery key, or FIDO2 factors, whichever the file's policy takes),
// exactly as `store verify` and a restore do.
//
// The one column that is not part of the workspace's state is
// meta.cleanup_pending, a marker of the file a rekey left behind until its
// VACUUM ran. ReadSnapshot reports it; WriteSnapshotFile always writes 0.

// SnapshotCredential is what verifies a file for a snapshot: exactly one field
// is set. Factors is the only one that opens a hardware or strict workspace.
type SnapshotCredential struct {
	// Passphrase is the passphrase text (a standard workspace).
	Passphrase *secret.Buffer
	// Recovery is the printed recovery key (a standard workspace).
	Recovery *secret.Buffer
	// Factors presents FIDO2 factors (a hardware or strict workspace).
	Factors *FactorInputs
	// master is the master key of a layout unlock (LayoutUnlock); only this package
	// sets it.
	master *secret.Buffer
}

// ErrSnapshotPlatform: this build has no file locking, so a snapshot cannot be
// taken or written safely.
var ErrSnapshotPlatform = errors.New("sqlitestore: snapshots need file locking, which this platform does not have")

// ErrSnapshotCredential: SnapshotCredential must have exactly one field set.
var ErrSnapshotCredential = errors.New("sqlitestore: a snapshot needs exactly one credential")

func (c SnapshotCredential) resolve() (credential, func(), error) {
	n := 0
	for _, set := range []bool{c.Passphrase != nil, c.Recovery != nil, c.Factors != nil, c.master != nil} {
		if set {
			n++
		}
	}
	if n != 1 {
		return credential{}, nil, ErrSnapshotCredential
	}
	switch {
	case c.Passphrase != nil:
		return credential{kind: seal.SlotPassphrase, buf: c.Passphrase}, func() {}, nil
	case c.master != nil:
		return credential{kind: credMaster, buf: c.master}, func() {}, nil
	case c.Recovery != nil:
		raw, err := seal.DecodeRecoveryKey(c.Recovery)
		if err != nil {
			return credential{}, nil, err
		}
		return credential{kind: seal.SlotRecovery, buf: raw}, raw.Destroy, nil
	}
	if c.Factors.Source == nil {
		return credential{}, nil, errors.New("sqlitestore: no factor source")
	}
	return credential{kind: credFactors, factors: c.Factors}, func() {}, nil
}

// SnapshotFacts are values derived from a snapshot that a converter needs and
// that audit rows refer to. They hold no key material.
type SnapshotFacts struct {
	WorkspaceID []byte
	// Head is the end of the audit chain of the snapshot.
	Head Head
	// SlotSetHash is the hash of the slot table that 'slots' and 'rollover'
	// audit rows record (the policy and every slot row).
	SlotSetHash []byte
	// RecordHashes[i] is the hash that 'touched' lists of audit rows record for
	// Records[i] (kind, lookup tag and the four sealed parts).
	RecordHashes [][]byte
	// Notices are what the verification of the file reported (a healed cold
	// record, records without a recovery wrap, a checkpoint key record) and
	// what the snapshot adds (the original has no head file).
	Notices []string
}

// FactsOf computes the SnapshotFacts of a snapshot from its rows.
func FactsOf(snap ports.Snapshot) (SnapshotFacts, error) {
	f := SnapshotFacts{WorkspaceID: append([]byte(nil), snap.Meta.WorkspaceID...), Head: Head{MAC: zeroMAC}}
	if n := len(snap.Audit); n > 0 {
		f.Head = Head{Seq: uint64(snap.Audit[n-1].Seq), MAC: append([]byte(nil), snap.Audit[n-1].MAC...)}
	}
	all := make([][]any, len(snap.Slots))
	for i, s := range snap.Slots {
		opt := func(p *int64) any {
			if p == nil {
				return nil
			}
			return *p
		}
		blob := func(b []byte) any {
			if b == nil {
				return nil
			}
			return b
		}
		all[i] = []any{s.ID, s.Kind, opt(s.KDFMemoryKiB), opt(s.KDFPasses), opt(s.KDFLanes), blob(s.Salt), s.KeyCommit, s.Nonce, s.WrappedKey, s.Bound, blob(s.RecHash), blob(s.Factors)}
	}
	b, err := seal.EncodeCanonical([]any{"spo/slotset/3", snap.Meta.Policy, all})
	if err != nil {
		return f, err
	}
	sum := sha256.Sum256(b)
	f.SlotSetHash = sum[:]
	f.RecordHashes = make([][]byte, len(snap.Records))
	for i, r := range snap.Records {
		h, err := recordHash(r.Kind, r.LookupTag, seal.SealedRecord{Nonce: r.Nonce, WrappedKey: r.WrappedKey, Owner: r.OwnerSealed, Ciphertext: r.Ciphertext})
		if err != nil {
			return f, err
		}
		f.RecordHashes[i] = h
	}
	return f, nil
}

// snapSideFiles refuses a file that a rollback journal or a WAL that holds
// anything sits beside: it is open elsewhere or was not closed cleanly.
func snapSideFiles(abs string) error {
	if _, err := os.Lstat(abs + "-journal"); err == nil {
		return fmt.Errorf("%w (%s-journal exists)", ErrUncheckpointed, abs)
	}
	if hasWAL(abs) {
		return fmt.Errorf("%w (%s-wal is not empty)", ErrUncheckpointed, abs)
	}
	return nil
}

// ReadSnapshot takes the snapshot of the store file at path through c.
//
// What is verified is what is read. The file is locked exclusively (ErrLocked
// while any handle has it open) and its bytes are copied through the locked
// descriptor into a private temporary file beside it (mode 0600, removed on
// every path). That copy is verified through c (the verification of `store
// verify`, without --deep), checked against the original's head file as an open
// checks it (a rolled-back original is refused), and its rows are read
// read-only; the copy is checked to be the same file before and after. The
// path of the original is not read again for its content, so a file renamed
// over it meanwhile changes nothing. A decrypted record or key is never
// returned. It refuses a file that is not of the current store format, one with
// a journal or non-empty WAL beside it, and one that fails verification.
//
// Residual: a process that writes to the locked inode itself while ignoring the
// lock, during the copy, can still make the copy differ from any state the
// workspace had; the copy then fails verification unless the writer can also
// forge the audit chain, which needs the workspace key.
func ReadSnapshot(ctx context.Context, path string, c SnapshotCredential) (ports.Snapshot, SnapshotFacts, error) {
	return readSnapshot(ctx, path, c, nil)
}

// readSnapshot is ReadSnapshot with a hook that runs on the verified copy while
// its store is still open (see TakeExport).
func readSnapshot(ctx context.Context, path string, c SnapshotCredential, then func(*Store) error) (ports.Snapshot, SnapshotFacts, error) {
	var zero ports.Snapshot
	if !snapshotLocking {
		return zero, SnapshotFacts{}, ErrSnapshotPlatform
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return zero, SnapshotFacts{}, err
	}
	cred, done, err := c.resolve()
	if err != nil {
		return zero, SnapshotFacts{}, err
	}
	defer done()
	if err := checkFile(abs); err != nil {
		return zero, SnapshotFacts{}, err
	}
	if err := snapSideFiles(abs); err != nil {
		return zero, SnapshotFacts{}, err
	}
	lock, err := lockFile(abs, false)
	if err != nil {
		return zero, SnapshotFacts{}, err
	}
	defer lock.Close()
	if err := upgradeLock(lock); err != nil {
		return zero, SnapshotFacts{}, fmt.Errorf("%w: another handle has the file open", err)
	}
	if err := snapSideFiles(abs); err != nil {
		return zero, SnapshotFacts{}, err
	}
	cp, cf, err := copyLocked(lock, filepath.Dir(abs))
	if err != nil {
		return zero, SnapshotFacts{}, err
	}
	defer func() {
		cf.Close()
		removeDB(cp)
	}()
	if err := ctx.Err(); err != nil {
		return zero, SnapshotFacts{}, err
	}
	res, err := verifyFileThen(cp, cred, false, then)
	os.Remove(cp + "-shm")
	os.Remove(cp + "-wal")
	if err != nil {
		return zero, SnapshotFacts{}, fmt.Errorf("sqlitestore: the file does not verify, so no snapshot was taken: %w", err)
	}
	if afterSnapshotCopyVerified != nil {
		afterSnapshotCopyVerified(cp)
	}
	same := func() error {
		fi, ferr := cf.Stat()
		li, lerr := os.Lstat(cp)
		if ferr != nil || lerr != nil || !os.SameFile(fi, li) {
			return fmt.Errorf("%w: the private copy was replaced after it was verified", ErrVerify)
		}
		return nil
	}
	if err := same(); err != nil {
		return zero, SnapshotFacts{}, err
	}
	var snap ports.Snapshot
	var facts SnapshotFacts
	err = withReadOnly(cp, func(db *sql.DB) error {
		var err error
		if snap, err = readSnapshotRows(ctx, db); err != nil {
			return err
		}
		if err = checkSnapshotBindings(ctx, db); err != nil {
			return err
		}
		if facts, err = FactsOf(snap); err != nil {
			return err
		}
		if snapshotFactsHook != nil {
			snapshotFactsHook(&facts)
		}
		// The slot set hash the audit chain uses, computed by the SQL path, must be
		// the one computed from the rows.
		if h, err := slotSetHash(ctx, db); err != nil {
			return err
		} else if !bytes.Equal(h, facts.SlotSetHash) {
			return fmt.Errorf("%w: the slot table read does not hash to the slot set hash of the store", ErrVerify)
		}
		// The original's head file, as an open compares it: the copy's chain must
		// contain the head recorded there. (The copy has no head file of its own.)
		_, notices, _, _, herr := checkHead(ctx, db, abs, snap.Meta.WorkspaceID, true, OpenOptions{}, nil)
		if herr != nil {
			return herr
		}
		facts.Notices = append(facts.Notices, notices...)
		for _, n := range res.Notices {
			if !strings.HasPrefix(n, "there is no head file") { // about the copy, which has none
				facts.Notices = append(facts.Notices, n)
			}
		}
		if _, _, found, _ := readHeadFile(abs); !found {
			facts.Notices = append(facts.Notices, "the workspace file has no head file: a rollback of it before now cannot be detected")
		}
		return nil
	})
	if err != nil {
		return zero, SnapshotFacts{}, err
	}
	if err := same(); err != nil {
		return zero, SnapshotFacts{}, err
	}
	return snap, facts, nil
}

// copyLocked copies the file open as lock into a new private temporary file in
// dir and returns its path and an open descriptor of it.
func copyLocked(lock *os.File, dir string) (string, *os.File, error) {
	tf, err := os.CreateTemp(dir, ".snapshot-read-*") // mode 0600
	if err != nil {
		return "", nil, err
	}
	name := tf.Name()
	ok := false
	defer func() {
		if !ok {
			tf.Close()
			removeDB(name)
		}
	}()
	if _, err := lock.Seek(0, io.SeekStart); err != nil {
		return "", nil, err
	}
	if _, err := io.Copy(tf, lock); err != nil {
		return "", nil, err
	}
	if err := tf.Sync(); err != nil {
		return "", nil, err
	}
	ok = true
	return name, tf, nil
}

// checkSnapshotBindings checks what no verification of the file does without a
// cold-role record to wrap: the recovery public key of the meta row is the one
// the slots bind (its hash is the rec_hash of every slot), and a table whose
// slots bind none has no recovery public key. A modified key is otherwise found
// only when a record is next wrapped to it.
func checkSnapshotBindings(ctx context.Context, q dbq) error {
	m, err := loadMeta(ctx, q)
	if err != nil {
		return err
	}
	t, err := loadTable(ctx, q, m.ws, uint64(m.format))
	if err != nil {
		return err
	}
	hash, bound, ok := t.commonRecHash()
	if ok && bound && len(hash) > 0 {
		_, err := recoveryPubOf(ctx, q, t)
		return err
	}
	var pub []byte
	if err := q.QueryRowContext(ctx, `SELECT recovery_pub FROM meta WHERE id = 1`).Scan(&pub); err != nil {
		return err
	}
	if !ok || pub != nil {
		return fmt.Errorf("%w: the key slots bind no recovery public key, or disagree about it, and the meta row has one", ErrRecoveryKeyMismatch)
	}
	return nil
}

// readSnapshotRows reads the four tables. The caller has checked the file.
func readSnapshotRows(ctx context.Context, db dbq) (ports.Snapshot, error) {
	var s ports.Snapshot
	v, err := checkDeclared(ctx, db, true)
	if err != nil {
		return s, err
	}
	if v != len(migrations) {
		return s, fmt.Errorf("sqlitestore: schema version %d is not the current one (%d)", v, len(migrations))
	}
	// Bounds before anything is loaded.
	for _, q := range []struct {
		table, what string
		max         int
		bytes       string
	}{
		{"keyslots", "key slots", ports.SnapshotMaxSlots, `coalesce(sum(length(id)+length(salt)+length(key_commit)+length(nonce)+length(wrapped_key)+length(rec_hash)+length(factors)),0)`},
		{"records", "records", ports.SnapshotMaxRecords, `coalesce(sum(length(id)+length(lookup_tag)+length(nonce)+length(wrapped_key)+length(owner_sealed)+length(ciphertext)),0)`},
		{"audit", "audit rows", ports.SnapshotMaxAudit, `coalesce(sum(length(event)+length(touched)+length(slotset)+length(mac)+length(prev_mac)),0)`},
	} {
		var n, size int64
		if err := db.QueryRowContext(ctx, `SELECT count(*), `+q.bytes+` FROM `+q.table).Scan(&n, &size); err != nil {
			return s, err
		}
		if n > int64(q.max) || size > ports.SnapshotMaxBytes {
			return s, fmt.Errorf("%w: the file holds %d %s and %d bytes in them (limits %d and %d)", ports.ErrSnapshot, n, q.what, size, q.max, ports.SnapshotMaxBytes)
		}
	}
	var nm int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM meta`).Scan(&nm); err != nil || nm != 1 {
		return s, &VerifyError{Problems: []string{"the meta table does not hold exactly one row"}}
	}
	m := &s.Meta
	m.SchemaVersion = int64(v)
	var rec any
	err = db.QueryRowContext(ctx, `SELECT workspace_id, format_version, created_at, key_epoch, epoch_mac, cleanup_pending, policy, recovery_pub FROM meta WHERE id = 1`).
		Scan(&m.WorkspaceID, &m.FormatVersion, &m.CreatedAt, &m.KeyEpoch, &m.EpochMAC, &m.CleanupPending, &m.Policy, &rec)
	if err != nil {
		return s, err
	}
	if m.FormatVersion != int64(seal.StoreFormat) {
		return s, fmt.Errorf("sqlitestore: format version %d is not the current store format (%d); migrate it first", m.FormatVersion, seal.StoreFormat)
	}
	if m.RecoveryPub, err = nullBlob(rec); err != nil {
		return s, err
	}
	rows, err := db.QueryContext(ctx, `SELECT id, kind, kdf_memory_kib, kdf_passes, kdf_lanes, salt, key_commit, nonce, wrapped_key, bound, rec_hash, factors FROM keyslots ORDER BY id`)
	if err != nil {
		return s, err
	}
	for rows.Next() {
		var r ports.SnapshotSlot
		var mem, passes, lanes, salt, rh, fac any
		if err := rows.Scan(&r.ID, &r.Kind, &mem, &passes, &lanes, &salt, &r.KeyCommit, &r.Nonce, &r.WrappedKey, &r.Bound, &rh, &fac); err != nil {
			rows.Close()
			return s, err
		}
		for _, x := range []struct {
			src any
			dst **int64
		}{{mem, &r.KDFMemoryKiB}, {passes, &r.KDFPasses}, {lanes, &r.KDFLanes}} {
			if *x.dst, err = nullInt(x.src); err != nil {
				rows.Close()
				return s, err
			}
		}
		for _, x := range []struct {
			src any
			dst *[]byte
		}{{salt, &r.Salt}, {rh, &r.RecHash}, {fac, &r.Factors}} {
			if *x.dst, err = nullBlob(x.src); err != nil {
				rows.Close()
				return s, err
			}
		}
		s.Slots = append(s.Slots, r)
	}
	if err := rows.Close(); err != nil {
		return s, err
	}
	if err := rows.Err(); err != nil {
		return s, err
	}
	rows, err = db.QueryContext(ctx, `SELECT id, lookup_tag, kind, version, nonce, wrapped_key, owner_sealed, ciphertext, updated_at FROM records ORDER BY id`)
	if err != nil {
		return s, err
	}
	for rows.Next() {
		var r ports.SnapshotRecord
		if err := rows.Scan(&r.ID, &r.LookupTag, &r.Kind, &r.Version, &r.Nonce, &r.WrappedKey, &r.OwnerSealed, &r.Ciphertext, &r.UpdatedAt); err != nil {
			rows.Close()
			return s, err
		}
		s.Records = append(s.Records, r)
	}
	if err := rows.Close(); err != nil {
		return s, err
	}
	if err := rows.Err(); err != nil {
		return s, err
	}
	rows, err = db.QueryContext(ctx, `SELECT seq, at, kind, event, touched, slotset, mac, prev_mac FROM audit ORDER BY seq`)
	if err != nil {
		return s, err
	}
	for rows.Next() {
		var r ports.SnapshotAudit
		if err := rows.Scan(&r.Seq, &r.At, &r.Kind, &r.Event, &r.Touched, &r.SlotSet, &r.MAC, &r.PrevMAC); err != nil {
			rows.Close()
			return s, err
		}
		s.Audit = append(s.Audit, r)
	}
	if err := rows.Close(); err != nil {
		return s, err
	}
	if err := rows.Err(); err != nil {
		return s, err
	}
	canonSnapshot(&s)
	return s, s.Validate()
}

func nullInt(v any) (*int64, error) {
	switch x := v.(type) {
	case nil:
		return nil, nil
	case int64:
		return &x, nil
	}
	return nil, fmt.Errorf("sqlitestore: a nullable integer column holds a %T", v)
}

func nullBlob(v any) ([]byte, error) {
	switch x := v.(type) {
	case nil:
		return nil, nil
	case []byte:
		return append([]byte{}, x...), nil
	}
	return nil, fmt.Errorf("sqlitestore: a nullable blob column holds a %T", v)
}

// canonSnapshot makes a NOT NULL blob that is empty a non-nil empty slice, so
// that a snapshot has one form per file.
func canonSnapshot(s *ports.Snapshot) {
	fix := func(p *[]byte) {
		if *p == nil {
			*p = []byte{}
		}
	}
	for _, p := range []*[]byte{&s.Meta.WorkspaceID, &s.Meta.KeyEpoch, &s.Meta.EpochMAC} {
		fix(p)
	}
	for i := range s.Slots {
		r := &s.Slots[i]
		for _, p := range []*[]byte{&r.ID, &r.KeyCommit, &r.Nonce, &r.WrappedKey} {
			fix(p)
		}
	}
	for i := range s.Records {
		r := &s.Records[i]
		for _, p := range []*[]byte{&r.ID, &r.LookupTag, &r.Nonce, &r.WrappedKey, &r.OwnerSealed, &r.Ciphertext} {
			fix(p)
		}
	}
	for i := range s.Audit {
		r := &s.Audit[i]
		for _, p := range []*[]byte{&r.Event, &r.Touched, &r.SlotSet, &r.MAC, &r.PrevMAC} {
			fix(p)
		}
	}
}

// Test hooks of the snapshot reader and writer. afterSnapshotCopyVerified runs
// in ReadSnapshot after the private copy was verified and before its rows are
// read; snapshotFactsHook may change the facts before they are cross-checked;
// beforeSnapshotReadback runs in WriteSnapshotFile after the built file passed
// verification and before it is read back.
var (
	afterSnapshotCopyVerified func(copyPath string)
	snapshotFactsHook         func(*SnapshotFacts)
	beforeSnapshotReadback    func(builtPath string)
)

// afterSnapshotBuild, when set, runs when the new file is built and verified
// and before anything is linked into place; an error is an ordinary failure
// there (a test sets it). afterSnapshotLink runs right after the file is linked
// and before the head file is written; an error stops the write there and
// leaves what a crash at that point leaves (a test sets it).
var afterSnapshotBuild, afterSnapshotLink func() error

// WriteSnapshotFile creates a NEW store file at path from snap. It never
// replaces an existing file (ErrExists). The file is built under a private
// temporary name in the same directory (mode 0600) from the schema the
// migrations produce, every row is inserted as given, and the result must pass
// the schema allow-list, the full verification through c, and a read-back that
// equals snap (except meta.cleanup_pending, written as 0). Only then is it
// linked into place without replacing anything and its head file written. On
// failure nothing is left behind: no file, no temporary file, no head file.
//
// It writes only to a path where nothing exists: the file, its .head,
// .head.next and .head.lock, -wal and -journal must all be absent. It is not a
// way to replace a workspace and must not become one. An import over an
// existing workspace writes the snapshot to a new file here and then installs
// it with RestoreWithFactors (or RestoreWithOptions), which applies the policy,
// rollback and counter rules of a restore.
func WriteSnapshotFile(ctx context.Context, path string, snap ports.Snapshot, c SnapshotCredential) (err error) {
	if !snapshotLocking {
		return ErrSnapshotPlatform
	}
	if err := snap.Validate(); err != nil {
		return err
	}
	if snap.Meta.SchemaVersion != int64(len(migrations)) {
		return fmt.Errorf("%w: schema version %d (this binary writes %d)", ports.ErrSnapshot, snap.Meta.SchemaVersion, len(migrations))
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	cred, done, err := c.resolve()
	if err != nil {
		return err
	}
	defer done()
	for _, p := range []string{abs, abs + "-wal", abs + "-shm", abs + "-journal", headPath(abs), sidecarPath(abs), headPath(abs) + ".lock"} {
		if _, lerr := os.Lstat(p); lerr == nil {
			return fmt.Errorf("%w: %s (a snapshot is never written over anything)", ErrExists, p)
		}
	}
	tf, err := os.CreateTemp(filepath.Dir(abs), ".snapshot-*") // mode 0600
	if err != nil {
		return err
	}
	tmp := tf.Name()
	tf.Close()
	tst, err := os.Stat(tmp)
	if err != nil {
		os.Remove(tmp)
		return err
	}
	linked, crashed, announced := false, false, false
	defer func() {
		if err == nil || crashed {
			return
		}
		if announced {
			os.Remove(sidecarPath(abs))
			if !linked {
				os.Remove(headPath(abs) + ".lock") // made by the announcement (none existed), belongs to no workspace
			}
		}
		if linked {
			if dst, serr := os.Stat(abs); serr == nil && os.SameFile(dst, tst) {
				removeDB(abs)
			}
		}
		removeDB(tmp)
	}()
	if err = buildSnapshotFile(ctx, tmp, snap); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = withReadOnly(tmp, func(db *sql.DB) error {
		if _, err := checkDeclared(ctx, db, true); err != nil { // the schema allow-list
			return err
		}
		return checkSnapshotBindings(ctx, db)
	}); err != nil {
		return fmt.Errorf("sqlitestore: the snapshot file built does not pass the schema check: %w", err)
	}
	res, err := verifyFile(tmp, cred, false)
	os.Remove(tmp + "-shm")
	os.Remove(tmp + "-wal")
	if err != nil {
		return fmt.Errorf("sqlitestore: the snapshot file built does not verify, so nothing was written: %w", err)
	}
	if beforeSnapshotReadback != nil {
		beforeSnapshotReadback(tmp)
	}
	var back ports.Snapshot
	if err = withReadOnly(tmp, func(db *sql.DB) error {
		var err error
		back, err = readSnapshotRows(ctx, db)
		return err
	}); err != nil {
		return err
	}
	want := snap
	want.Meta.CleanupPending = 0
	canonSnapshot(&want)
	if !reflect.DeepEqual(want, back) {
		return errors.New("sqlitestore: the snapshot file built does not read back as the snapshot given, so nothing was written")
	}
	if afterSnapshotBuild != nil {
		if err = afterSnapshotBuild(); err != nil {
			return err
		}
	}
	ws := snap.Meta.WorkspaceID
	// Announce the head file before the file is linked (as restore does): a crash
	// between the link and the head file leaves the sidecar the next open settles.
	if err = withHeadLock(abs, func() error { return replaceHeadAt(sidecarPath(abs), ws, res.Head) }); err != nil {
		return err
	}
	announced = true
	if err = os.Link(tmp, abs); err != nil { // fails if abs appeared meanwhile
		if errors.Is(err, os.ErrExist) {
			err = fmt.Errorf("%w: %s", ErrExists, abs)
		}
		return err
	}
	linked = true
	os.Remove(tmp)
	if afterSnapshotLink != nil {
		if herr := afterSnapshotLink(); herr != nil {
			crashed = true
			return herr
		}
	}
	if err = writeHeadFile(abs, ws, res.Head); err != nil {
		return err
	}
	os.Remove(sidecarPath(abs))
	return syncDir(filepath.Dir(abs))
}

// buildSnapshotFile creates the schema in the empty file at path and inserts
// every row of snap.
func buildSnapshotFile(ctx context.Context, path string, snap ports.Snapshot) error {
	db, err := openDB(path, false, false)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			db.Close()
		}
	}()
	if err := migrate(ctx, db); err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	blob := func(b []byte) any { // nil is NULL, a non-nil empty slice is an empty blob
		if b == nil {
			return nil
		}
		return b
	}
	opt := func(p *int64) any {
		if p == nil {
			return nil
		}
		return *p
	}
	m := snap.Meta
	if _, err := tx.ExecContext(ctx, `INSERT INTO meta (id, workspace_id, format_version, created_at, key_epoch, epoch_mac, cleanup_pending, policy, recovery_pub) VALUES (1,?,?,?,?,?,0,?,?)`,
		blob(m.WorkspaceID), m.FormatVersion, m.CreatedAt, blob(m.KeyEpoch), blob(m.EpochMAC), m.Policy, blob(m.RecoveryPub)); err != nil {
		return fmt.Errorf("sqlitestore: meta row: %w", err)
	}
	for i, r := range snap.Slots {
		if _, err := tx.ExecContext(ctx, `INSERT INTO keyslots (id, kind, kdf_memory_kib, kdf_passes, kdf_lanes, salt, key_commit, nonce, wrapped_key, bound, rec_hash, factors) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
			blob(r.ID), r.Kind, opt(r.KDFMemoryKiB), opt(r.KDFPasses), opt(r.KDFLanes), blob(r.Salt), blob(r.KeyCommit), blob(r.Nonce), blob(r.WrappedKey), r.Bound, blob(r.RecHash), blob(r.Factors)); err != nil {
			return fmt.Errorf("sqlitestore: key slot %d: %w", i, err)
		}
	}
	for i, r := range snap.Records {
		if _, err := tx.ExecContext(ctx, `INSERT INTO records (id, lookup_tag, kind, version, nonce, wrapped_key, owner_sealed, ciphertext, updated_at) VALUES (?,?,?,?,?,?,?,?,?)`,
			blob(r.ID), blob(r.LookupTag), r.Kind, r.Version, blob(r.Nonce), blob(r.WrappedKey), blob(r.OwnerSealed), blob(r.Ciphertext), r.UpdatedAt); err != nil {
			return fmt.Errorf("sqlitestore: record %d: %w", i, err)
		}
	}
	for i, r := range snap.Audit {
		if _, err := tx.ExecContext(ctx, `INSERT INTO audit (seq, at, kind, event, touched, slotset, mac, prev_mac) VALUES (?,?,?,?,?,?,?,?)`,
			r.Seq, r.At, r.Kind, blob(r.Event), blob(r.Touched), blob(r.SlotSet), blob(r.MAC), blob(r.PrevMAC)); err != nil {
			return fmt.Errorf("sqlitestore: audit row %d: %w", i, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	var busy, logFrames, ck int
	if err := db.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &ck); err != nil || busy != 0 {
		return fmt.Errorf("sqlitestore: checkpoint of the snapshot file: busy=%d error=%v", busy, err)
	}
	closed = true
	if err := db.Close(); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	return syncFile(path)
}
