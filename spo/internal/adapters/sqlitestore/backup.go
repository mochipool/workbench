package sqlitestore

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

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

// RestoreOptions are the choices of RestoreWithOptions.
type RestoreOptions struct {
	// Overwrite lets the restore replace an existing destination.
	Overwrite bool
	// AllowOlder lets it replace a workspace with a backup that is older than
	// the workspace (the workspace's last recorded state is not in the
	// backup's chain). Without it such a restore fails with ErrOlderBackup.
	AllowOlder bool
	// AllowOtherWorkspace lets it replace a workspace with a backup of a
	// different workspace. Without it such a restore fails with
	// ErrOtherWorkspace.
	AllowOtherWorkspace bool
}

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
	return restore(backupPath, destPath, credential{seal.SlotPassphrase, passphrase}, o)
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
	return restore(backupPath, destPath, credential{seal.SlotRecovery, raw}, o)
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
	if _, err = verifyFile(tmpPath, cred, false); err != nil {
		return fmt.Errorf("sqlitestore: backup does not verify: %w", err)
	}
	ws, head, err := inspectFile(ctx, tmpPath)
	if err != nil {
		return err
	}
	if exists {
		// Exclusive lock for the check and the swap: nobody may have the
		// workspace open, and nobody can open it between the two.
		lock, lerr := lockFile(dest, true)
		if lerr != nil {
			return lerr
		}
		defer lock.Close()
		// Only now, under the lock, can the side files be trusted: another
		// process may have written and closed since the copy began. Fold a
		// committed WAL into the file before the file is inspected.
		if err = checkpointDest(ctx, dest); err != nil {
			return err
		}
		if err = checkReplace(ctx, dest, tmpPath, ws, o); err != nil {
			return err
		}
	}
	os.Remove(tmpPath + "-shm")
	os.Remove(tmpPath + "-wal")
	// Immediately before the swap (under the lock when the destination exists):
	// the destination's side files belong to the file about to be replaced.
	if err = clearDestSides(dest); err != nil {
		return err
	}
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
	if err = writeHeadFile(dest, ws, head); err != nil {
		return err
	}
	return syncDir(filepath.Dir(dest))
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
