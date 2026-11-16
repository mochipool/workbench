package sqlitestore

import (
	"context"
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
// encryption and opens with the same passphrase or recovery key.
func (s *Store) Backup(ctx context.Context, destPath string) error {
	abs, err := filepath.Abs(destPath)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(abs, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w: %s", ErrExists, abs)
		}
		return err
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
		return err
	}
	if err := os.Chmod(abs, 0o600); err != nil {
		return err
	}
	if err := syncFile(abs); err != nil {
		return err
	}
	ok = true
	return nil
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

// Restore replaces the workspace at destPath with the backup at backupPath,
// after verifying the backup with the passphrase. The backup is copied beside
// the destination first and verified there (so the bytes checked are the
// bytes installed), then moved into place. An existing destination is refused
// unless overwrite is true; a destination with -wal or -shm files (a workspace
// that is open or was not closed cleanly) is always refused.
func Restore(backupPath, destPath string, passphrase *secret.Buffer, overwrite bool) error {
	return restore(backupPath, destPath, credential{seal.SlotPassphrase, passphrase}, overwrite)
}

// RestoreWithRecovery is Restore with the printed recovery key.
func RestoreWithRecovery(backupPath, destPath string, recovery *secret.Buffer, overwrite bool) error {
	raw, err := seal.DecodeRecoveryKey(recovery)
	if err != nil {
		return err
	}
	defer raw.Destroy()
	return restore(backupPath, destPath, credential{seal.SlotRecovery, raw}, overwrite)
}

func restore(backupPath, destPath string, cred credential, overwrite bool) (err error) {
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
	if _, err := os.Lstat(dest); err == nil && !overwrite {
		return fmt.Errorf("%w: %s (pass overwrite to replace it)", ErrExists, dest)
	}
	for _, side := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(dest + side); err == nil {
			return fmt.Errorf("sqlitestore: %s%s exists: the workspace is open or was not closed cleanly; refusing to restore over it", dest, side)
		}
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
	if err = verifyFile(tmpPath, cred); err != nil {
		return fmt.Errorf("sqlitestore: backup does not verify: %w", err)
	}
	os.Remove(tmpPath + "-shm")
	os.Remove(tmpPath + "-wal")
	if overwrite {
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
	return syncDir(filepath.Dir(dest))
}
