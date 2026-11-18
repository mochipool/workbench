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

	"github.com/mochipool/workbench/spo/internal/domain/unlock"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// Backup writes a consistent copy of the workspace to destPath, which must not
// exist. The copy is made by SQLite's VACUUM INTO at one snapshot (safe while
// the workspace is open and in WAL mode) and is mode 0600. Records in it are
// already sealed and it carries the same key slots, so it needs no further
// encryption and opens with the same passphrase or recovery key. It has no
// head file of its own.
func (s *Store) Backup(ctx context.Context, destPath string) error {
	_, err := s.BackupWithHead(ctx, destPath)
	return err
}

// BackupWithHead is Backup that returns the head (sequence and MAC) of the
// audit chain in the copy it wrote. Record it where an attacker cannot write:
// it is what a later restore of this backup can be checked against.
func (s *Store) BackupWithHead(ctx context.Context, destPath string) (Head, error) {
	release, err := s.enter(ctx)
	if err != nil {
		return Head{}, err
	}
	defer release()
	// A schema with a trigger or view in it would be copied into the backup.
	if err := s.checkSchemaNow(ctx); err != nil {
		return Head{}, err
	}
	abs, err := filepath.Abs(destPath)
	if err != nil {
		return Head{}, err
	}
	f, err := os.OpenFile(abs, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return Head{}, fmt.Errorf("%w: %s", ErrExists, abs)
		}
		return Head{}, err
	}
	f.Close()
	ok := false
	defer func() {
		if !ok {
			removeDB(abs)
		}
	}()
	// VACUUM INTO accepts an empty existing file.
	if _, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, abs); err != nil {
		return Head{}, err
	}
	if err := os.Chmod(abs, 0o600); err != nil {
		return Head{}, err
	}
	if err := syncFile(abs); err != nil {
		return Head{}, err
	}
	_, h, err := inspectFile(ctx, abs)
	if err != nil {
		return Head{}, err
	}
	ok = true
	return h, nil
}

func syncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// withReadOnly runs fn on a read-only, immutable connection to the file at
// path. Callers use it only on files nobody else can be writing: a backup copy
// they just made or verified, or a destination they hold exclusively.
func withReadOnly(path string, fn func(db *sql.DB) error) error {
	db, err := openDB(path, true, true)
	if err != nil {
		return err
	}
	defer db.Close()
	return fn(db)
}

// inspectFile reads the workspace id and the chain head of a file without a
// key (both are structural data).
func inspectFile(ctx context.Context, path string) (ws []byte, h Head, err error) {
	err = withReadOnly(path, func(db *sql.DB) error {
		m, err := loadMeta(ctx, db)
		if err != nil {
			return err
		}
		ws = m.ws
		h, err = chainHead(ctx, db)
		return err
	})
	return ws, h, err
}

// InspectHead reads the workspace id and the chain head of the file at path
// without a key, read-only. It is what a backup file says about itself.
func InspectHead(path string) (ws []byte, h Head, err error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, Head{}, err
	}
	return inspectFile(context.Background(), abs)
}

// RestoreOptions are the choices of RestoreWithOptions.
type RestoreOptions struct {
	// Overwrite lets the restore replace an existing destination.
	Overwrite bool
	// ExpectedSHA256, when set, is the SHA-256 the backup file must have. It is
	// checked on the restore's own private copy before anything else is done
	// with it, so the bytes installed are the bytes that were hashed.
	ExpectedSHA256 []byte
	// AcceptLowerCounters lets a restore of an older backup go on although the
	// counters of the workspace it replaces cannot be read (the file is damaged, or
	// its credentials are lost). It never applies when that workspace can be
	// opened: its counters are carried whatever this says.
	AcceptLowerCounters bool
	// Report, when set, is filled in with what the counter rule did.
	Report *RestoreReport
	// AllowOlder lets it replace a workspace with a backup that is older than
	// the workspace (the workspace's last recorded state is not in the
	// backup's chain). Without it such a restore fails with ErrOlderBackup.
	AllowOlder bool
	// AllowOtherWorkspace lets it replace a workspace with a backup of a
	// different workspace. Without it such a restore fails with
	// ErrOtherWorkspace.
	AllowOtherWorkspace bool
	// AllowWeakerPolicy lets a backup whose unlock policy ranks weaker
	// (unlock.Weakens) than the policy of the workspace it replaces do so. It is
	// honoured only together with CurrentRecovery: restoring an older, weaker
	// copy of a workspace would otherwise undo a rotation to hardware or strict.
	AllowWeakerPolicy bool
	// CurrentRecovery presents the recovery credential of the workspace being
	// replaced (the recovery key as 32 raw bytes and, under hardware, the second
	// authenticator): the store opens the current file with it and checks it with
	// PresentRecovery before anything is replaced. A strict workspace has none, so
	// it is never replaced by a weaker backup.
	CurrentRecovery *FactorInputs
}

// ErrRestoreWeakens: the backup's unlock policy is weaker than the policy of the
// workspace it would replace.
var ErrRestoreWeakens = errors.New("sqlitestore: the backup's unlock policy is weaker than the workspace's: restoring it would undo the stronger policy. It needs --allow-weaker-policy and the current recovery credential presented (a strict workspace is never loosened)")

// Restore replaces the workspace at destPath with the backup at backupPath,
// after verifying the backup with the passphrase. The backup is copied beside
// the destination first and verified there (so the bytes checked are the
// bytes installed), then moved into place. An existing destination is refused
// unless overwrite is true; a destination that is open is refused (ErrLocked),
// and one with uncheckpointed changes in its -wal is checkpointed first or
// refused (ErrUncheckpointed). Replacing an
// existing workspace also requires that the backup is of the same workspace
// and is not older than it: see RestoreWithOptions.
func Restore(backupPath, destPath string, passphrase *secret.Buffer, overwrite bool) error {
	return RestoreWithOptions(backupPath, destPath, passphrase, RestoreOptions{Overwrite: overwrite})
}

// RestoreWithOptions is Restore with options.
//
// Replacing an existing destination is checked, without any key, against its
// workspace id and chain head (and its head file): the backup must be of the
// same workspace, and its chain must contain the destination's last recorded
// head, that is, the backup must be the same state or a later one. The swap
// is done holding an exclusive lock on the destination, which fails with
// ErrLocked while any handle has it open. The destination's head file is
// rewritten from the backup, because a restore is deliberate.
func RestoreWithOptions(backupPath, destPath string, passphrase *secret.Buffer, o RestoreOptions) error {
	return restore(backupPath, destPath, credential{kind: seal.SlotPassphrase, buf: passphrase}, o)
}

// RestoreWithFactors is RestoreWithOptions for a backup of a workspace that
// unlocks through FIDO2 factors (hardware or strict): the backup is verified
// through its factor slots (VerifyFileFactors), not with a passphrase.
func RestoreWithFactors(backupPath, destPath string, in FactorInputs, o RestoreOptions) error {
	if in.Source == nil {
		return errors.New("sqlitestore: no factor source")
	}
	return restore(backupPath, destPath, credential{kind: credFactors, factors: &in}, o)
}

// RestoreWithRecovery is Restore with the printed recovery key.
func RestoreWithRecovery(backupPath, destPath string, recovery *secret.Buffer, overwrite bool) error {
	return RestoreWithRecoveryOptions(backupPath, destPath, recovery, RestoreOptions{Overwrite: overwrite})
}

// RestoreWithRecoveryOptions is RestoreWithOptions with the printed recovery key.
func RestoreWithRecoveryOptions(backupPath, destPath string, recovery *secret.Buffer, o RestoreOptions) error {
	raw, err := seal.DecodeRecoveryKey(recovery)
	if err != nil {
		return err
	}
	defer raw.Destroy()
	return restore(backupPath, destPath, credential{kind: seal.SlotRecovery, buf: raw}, o)
}

// checkCopyHash re-reads the private copy and compares its SHA-256.
func checkCopyHash(path string, want []byte) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if !bytes.Equal(h.Sum(nil), want) {
		return ErrBackupHash
	}
	return nil
}

func restore(backupPath, destPath string, cred credential, o RestoreOptions) (err error) {
	ctx := context.Background()
	src, err := filepath.Abs(backupPath)
	if err != nil {
		return err
	}
	dest, err := filepath.Abs(destPath)
	if err != nil {
		return err
	}
	if src == dest {
		return errors.New("sqlitestore: backup and destination are the same file")
	}
	_, statErr := os.Lstat(dest)
	exists := statErr == nil
	if exists && !o.Overwrite {
		return fmt.Errorf("%w: %s (pass overwrite to replace it)", ErrExists, dest)
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("sqlitestore: %s is not a regular file", src)
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".restore-*") // mode 0600
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		if err != nil {
			removeDB(tmpPath)
		}
	}()
	if _, err = io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if o.ExpectedSHA256 != nil {
		if err = checkCopyHash(tmpPath, o.ExpectedSHA256); err != nil {
			return err
		}
	}
	if _, err = verifyFile(tmpPath, cred, false); err != nil {
		return fmt.Errorf("sqlitestore: backup does not verify: %w", err)
	}
	ws, head, err := inspectFile(ctx, tmpPath)
	if err != nil {
		return err
	}
	var plan *counterPlan
	if exists {
		// A weaker backup never replaces a stronger workspace unless the current
		// recovery credential is presented (before the lock: the presentation opens
		// the current file).
		var checked string
		if checked, err = checkRestorePolicy(ctx, dest, tmpPath, o); err != nil {
			return err
		}
		// The counter rule (restore_counters.go): reads the destination read-only,
		// carries the larger counters into the private copy, or refuses. Nothing is
		// written to the destination here.
		if plan, err = prepareCounters(ctx, dest, tmpPath, cred, o); err != nil {
			return err
		}
		if plan != nil && plan.carried {
			// the copy has a new head: the head file and the sidecar record it
			if ws, head, err = inspectFile(ctx, tmpPath); err != nil {
				return err
			}
			if _, err = verifyFile(tmpPath, cred, false); err != nil {
				return fmt.Errorf("sqlitestore: the restored copy does not verify after the counters were carried: %w", err)
			}
		}
		if afterCarry != nil {
			if err = afterCarry(); err != nil {
				return err
			}
		}
		if afterPolicyCheck != nil {
			afterPolicyCheck()
		}
		// Exclusive lock for the check and the swap: nobody may have the
		// workspace open, and nobody can open it between the two.
		lock, lerr := lockFile(dest, true)
		if lerr != nil {
			return lerr
		}
		defer lock.Close()
		// The policy check ran before the lock (it opens the file): under the lock
		// the table must still be the one that was checked.
		if err = checkpointDest(ctx, dest); err != nil {
			return err
		}
		if now, derr := tableSignatureLocked(dest); checked != "" && (derr != nil || now != checked) {
			return fmt.Errorf("%w: the workspace's slot table changed while the restore was being checked; nothing was replaced", ErrConflictRestore)
		}
		// Only now, under the lock, can the side files be trusted: another
		// process may have written and closed since the copy began. Fold a
		// committed WAL into the file before the file is inspected.
		if err = checkpointDest(ctx, dest); err != nil {
			return err
		}
		if err = checkReplace(ctx, dest, tmpPath, ws, o); err != nil {
			return err
		}
		// The counters were read from the destination as it was: it must not have
		// moved on since.
		if plan != nil && plan.destHead != nil {
			if _, nowHead, ierr := inspectFile(ctx, dest); ierr != nil || !nowHead.equal(*plan.destHead) {
				return fmt.Errorf("%w: the workspace changed after its counters were read; nothing was replaced", ErrConflictRestore)
			}
		}
	}
	os.Remove(tmpPath + "-shm")
	os.Remove(tmpPath + "-wal")
	// Immediately before the swap (under the lock when the destination exists):
	// the destination's side files belong to the file about to be replaced.
	if err = clearDestSides(dest); err != nil {
		return err
	}
	// Announce the head file before the swap. A crash between the swap and the
	// head file leaves the new file beside the old head file; the sidecar lets the
	// next open settle that when it names the file's own head (adoptSidecar).
	swapped := false
	if err = withHeadLock(dest, func() error { return replaceHeadAt(sidecarPath(dest), ws, head) }); err != nil {
		return err
	}
	defer func() {
		if err != nil && !swapped {
			os.Remove(sidecarPath(dest))
		}
	}()
	if o.Overwrite {
		err = os.Rename(tmpPath, dest)
	} else {
		// Link fails if dest appeared meanwhile, so we never clobber.
		if err = os.Link(tmpPath, dest); err == nil {
			os.Remove(tmpPath)
		}
	}
	if err != nil {
		return err
	}
	swapped = true
	if afterSwap != nil {
		if err = afterSwap(); err != nil {
			return err
		}
	}
	if err = writeHeadFile(dest, ws, head); err != nil {
		return err
	}
	os.Remove(sidecarPath(dest))
	if o.Report != nil && plan != nil {
		*o.Report = plan.report
	}
	return syncDir(filepath.Dir(dest))
}

// afterSwap, when set, runs right after the new file is in place and before the
// head file is written; an error stops the restore there, which is what a crash
// at that point looks like (a test sets it).
var afterSwap func() error

// ErrBackupHash: the backup's bytes are not the ones that were hashed.
var ErrBackupHash = errors.New("sqlitestore: the backup file is not the file whose SHA-256 was expected; nothing was installed")

// afterPolicyCheck, when set, runs between the policy check and the lock (a test
// changes the destination there).
var afterPolicyCheck func()

// ErrConflictRestore: the destination changed between the check and the swap.
var ErrConflictRestore = errors.New("sqlitestore: the destination changed during the restore")

// tableSignature is the policy and the slot ids and kinds of a file, read
// without a key.
func tableSignature(path string) (string, error) {
	pol, slots, err := Describe(path)
	if err != nil {
		return "", err
	}
	return signatureOf(pol, slots), nil
}

func signatureOf(pol unlock.Policy, slots []SlotInfo) string {
	sig := string(pol)
	for _, sl := range slots {
		sig += fmt.Sprintf("|%x:%s", sl.ID, sl.Kind)
	}
	return sig
}

// tableSignatureLocked is tableSignature for a file this process holds the
// exclusive lock of (Describe takes a shared one): a read-only immutable read.
func tableSignatureLocked(path string) (string, error) {
	var sig string
	err := withReadOnly(path, func(db *sql.DB) error {
		m, err := loadMeta(context.Background(), db)
		if err != nil {
			return err
		}
		t, err := loadTable(context.Background(), db, m.ws, uint64(m.format))
		if err != nil {
			return err
		}
		sig = signatureOf(t.policy, t.infos())
		return nil
	})
	return sig, err
}

// checkRestorePolicy refuses a backup that ranks weaker than the destination
// unless the operator said so AND presented the destination's recovery
// credential, checked with PresentRecovery on the destination file. A
// destination whose slot table cannot be read cannot be compared: it is replaced
// only with both --allow-weaker-policy and --allow-other-workspace (no recovery
// credential can be presented on a damaged file). It returns the signature of the
// table that was checked.
func checkRestorePolicy(ctx context.Context, dest, newPath string, o RestoreOptions) (string, error) {
	cur, _, err := Describe(dest)
	if err != nil {
		if o.AllowWeakerPolicy && o.AllowOtherWorkspace {
			return "", nil
		}
		return "", fmt.Errorf("%w: the policy of the workspace to be replaced cannot be read (%v), so the backup cannot be compared with it; --allow-weaker-policy together with --allow-other-workspace replaces it anyway, and --accept-lower-counters too, because the counters of such a file cannot be compared either", ErrRestoreWeakens, err)
	}
	sig, err := tableSignature(dest)
	if err != nil {
		return "", err
	}
	bak, _, err := Describe(newPath)
	if err != nil {
		return "", err
	}
	if !unlock.Weakens(cur, bak) {
		return sig, nil
	}
	if !o.AllowWeakerPolicy {
		return "", fmt.Errorf("%w (workspace %s, backup %s)", ErrRestoreWeakens, cur, bak)
	}
	if cur == unlock.Strict {
		return "", fmt.Errorf("%w: a strict workspace has no recovery credential to authorise it", ErrNoRecoveryPath)
	}
	in := o.CurrentRecovery
	if in == nil || in.Recovery == nil {
		return "", fmt.Errorf("%w: --allow-weaker-policy needs the current recovery credential", ErrRecoveryNotPresented)
	}
	var s *Store
	if cur == unlock.Standard {
		rk, rerr := in.Recovery(ctx)
		if rerr != nil {
			return "", rerr
		}
		s, err = open(dest, credential{kind: seal.SlotRecovery, buf: rk}, false, OpenOptions{})
		rk.Destroy()
	} else {
		if in.Source == nil {
			return "", errors.New("sqlitestore: no factor source to present the recovery authenticator")
		}
		s, err = OpenWithFactors(dest, *in, OpenOptions{})
	}
	if err != nil {
		return "", err
	}
	defer s.Close()
	if _, err = s.PresentRecovery(ctx, *in); err != nil {
		return "", err
	}
	return sig, nil
}

// ErrUncheckpointed: the destination workspace has changes in its -wal file that
// could not be folded into the database (or a rollback journal), so it is in
// use or was not closed cleanly. Open and close it once, then restore again.
var ErrUncheckpointed = errors.New("sqlitestore: the workspace has uncheckpointed changes (it is in use, or was not closed cleanly): open and close it once, then restore again")

// checkpointDest folds a non-empty -wal of the existing destination into the
// database, so that the file is inspected, and replaced, in its true state. The
// caller holds the exclusive lock on dest.
func checkpointDest(ctx context.Context, dest string) error {
	if _, err := os.Lstat(dest + "-journal"); err == nil {
		return fmt.Errorf("%w (%s-journal exists)", ErrUncheckpointed, dest)
	}
	if !hasWAL(dest) {
		return nil
	}
	db, err := openDB(dest, false, false)
	if err != nil {
		return fmt.Errorf("%w (%v)", ErrUncheckpointed, err)
	}
	var busy, logFrames, done int
	cerr := db.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &done)
	db.Close()
	if cerr != nil || busy != 0 || hasWAL(dest) {
		return fmt.Errorf("%w (checkpoint: busy=%d error=%v)", ErrUncheckpointed, busy, cerr)
	}
	return nil
}

// clearDestSides removes the stale -shm and empty -wal beside dest, which belong
// to the database file about to be replaced, and refuses a rollback journal or
// a WAL that still holds anything.
func clearDestSides(dest string) error {
	if _, err := os.Lstat(dest + "-journal"); err == nil {
		return fmt.Errorf("%w (%s-journal exists)", ErrUncheckpointed, dest)
	}
	if hasWAL(dest) {
		return fmt.Errorf("%w (%s-wal is not empty)", ErrUncheckpointed, dest)
	}
	os.Remove(dest + "-wal")
	os.Remove(dest + "-shm")
	return nil
}

// checkReplace decides, from structural data only, whether the verified backup
// at newPath may replace the workspace at dest.
func checkReplace(ctx context.Context, dest, newPath string, newWS []byte, o RestoreOptions) error {
	oldWS, oldHead, err := inspectFile(ctx, dest)
	if err != nil {
		if o.AllowOtherWorkspace {
			return nil // the destination is not a readable workspace; the operator said to replace it
		}
		return fmt.Errorf("%w: the destination cannot be read as a workspace (%v)", ErrOtherWorkspace, err)
	}
	if !bytes.Equal(oldWS, newWS) {
		if o.AllowOtherWorkspace {
			return nil
		}
		return ErrOtherWorkspace
	}
	if o.AllowOlder {
		return nil
	}
	// Every recorded head of the destination must be in the backup's chain.
	heads := []Head{oldHead}
	if hws, hh, found, herr := readHeadFile(dest); found && herr == nil && bytes.Equal(hws, oldWS) {
		heads = append(heads, hh)
	}
	return withReadOnly(newPath, func(db *sql.DB) error {
		for _, h := range heads {
			ok, err := chainContains(ctx, db, h)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("%w (destination is at sequence %d)", ErrOlderBackup, h.Seq)
			}
		}
		return nil
	})
}

// FileCounts is what a file shows without any key: its workspace id (the genesis
// nonce) and how many records and audit rows it holds. A file `Init` has just
// made has the counts of FreshInit and no more.
type FileCounts struct {
	WorkspaceID []byte
	Records     int
	AuditRows   int
}

// Inspect reads FileCounts of the workspace file at path, keylessly and
// read-only.
func Inspect(path string) (FileCounts, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return FileCounts{}, err
	}
	var c FileCounts
	err = withReadOnly(abs, func(db *sql.DB) error {
		m, err := loadMeta(context.Background(), db)
		if err != nil {
			return err
		}
		c.WorkspaceID = append([]byte(nil), m.ws...)
		if err := db.QueryRow(`SELECT count(*) FROM records`).Scan(&c.Records); err != nil {
			return err
		}
		return db.QueryRow(`SELECT count(*) FROM audit`).Scan(&c.AuditRows)
	})
	return c, err
}
