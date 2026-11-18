//go:build unix

package layoutdir

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/mochipool/workbench/spo/internal/ports"
)

type lock struct {
	root     string
	rootFile *os.File
	rootInfo os.FileInfo
	f        *os.File
	path     string
}

// Lock takes an exclusive advisory lock on <dir>/.spo-export.lock without
// waiting: a second exporter is refused with ports.ErrLayoutLocked.
func (d *Dir) Lock(ctx context.Context) (ports.LayoutLock, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	opened, err := d.rootFile.Stat()
	if err != nil {
		return nil, err
	}
	ri, err := os.Lstat(d.root)
	if err != nil || !ri.IsDir() || !os.SameFile(ri, opened) {
		return nil, ports.ErrLayoutMoved
	}
	path := filepath.Join(d.root, LockName)
	lfd, err := unix.Openat(int(d.rootFile.Fd()), LockName, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("the lock file could not be opened: %w", err)
	}
	f := os.NewFile(uintptr(lfd), path)
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("the lock file is not a regular file")
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ports.ErrLayoutLocked
		}
		return nil, err
	}
	return &lock{root: d.root, rootFile: d.rootFile, rootInfo: opened, f: f, path: path}, nil
}

func (l *lock) Check() error {
	ri, err := os.Lstat(l.root)
	if err != nil || ri.Mode()&os.ModeSymlink != 0 || !ri.IsDir() || !os.SameFile(ri, l.rootInfo) {
		return ports.ErrLayoutMoved
	}
	// the lock file is still the file this lock holds: if it was unlinked and made
	// again, a second exporter holds the new one
	var held, now unix.Stat_t
	if err := unix.Fstat(int(l.f.Fd()), &held); err != nil {
		return ports.ErrLayoutMoved
	}
	if err := unix.Fstatat(int(l.rootFile.Fd()), LockName, &now, unix.AT_SYMLINK_NOFOLLOW); err != nil || now.Dev != held.Dev || now.Ino != held.Ino {
		return ports.ErrLayoutMoved
	}
	return nil
}

func (l *lock) Release() error {
	if l.f == nil {
		return nil
	}
	err := l.f.Close() // closing the descriptor drops the lock
	l.f = nil
	return err
}
