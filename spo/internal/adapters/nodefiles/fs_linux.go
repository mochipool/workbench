//go:build linux

package nodefiles

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"

	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Dir is an open directory that passed the checks of OpenDir. Every file is
// created relative to its descriptor.
type Dir struct {
	f *os.File
	w Writer
}

// dirFSOK applies the file-system rule to an open directory: the test override,
// else ramfs, else tmpfs whose mount has noswap.
func (w Writer) dirFSOK(st *unix.Stat_t, typ int64) bool {
	if w.allowFS != nil || typ != tmpfsMagic {
		return w.fsOK(typ)
	}
	ok, err := tmpfsHasNoswap(unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev)))
	return err == nil && ok
}

// OpenDir opens dir with O_DIRECTORY|O_NOFOLLOW (a symbolic link as the last
// component is refused) and checks the descriptor: a directory owned by the
// effective user, not writable by group or others, on a file system that the
// rule accepts (ramfs).
func (w Writer) OpenDir(dir string) (*Dir, error) {
	f, st, err := openDirFD(dir)
	if err != nil {
		return nil, err
	}
	if err := checkDirFD(f, st, false); err != nil {
		f.Close()
		return nil, err
	}
	var sfs unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &sfs); err != nil {
		f.Close()
		return nil, fmt.Errorf("%w: the file system of %s could not be determined: %v", ErrDirectory, dir, err)
	}
	if !w.dirFSOK(st, int64(sfs.Type)) {
		f.Close()
		return nil, fmt.Errorf("%w: %s is not on a ramfs mount (file system type 0x%x). A key in clear must never reach a disk; tmpfs is refused because its pages can be swapped. Mount a ramfs (mount -t ramfs ramfs DIR) or use the service's credentials directory if it is one", ErrDirectory, dir, sfs.Type)
	}
	return &Dir{f: f, w: w}, nil
}

func openDirFD(dir string) (*os.File, *unix.Stat_t, error) {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s: %v", ErrDirectory, dir, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, nil, fmt.Errorf("%w: %v", ErrDirectory, err)
	}
	return os.NewFile(uintptr(fd), dir), &st, nil
}

// checkDirFD: a directory, owned by the effective user (or by root when
// allowRoot), not writable by group or others.
func checkDirFD(f *os.File, st *unix.Stat_t, allowRoot bool) error {
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("%w: %s is not a directory", ErrDirectory, f.Name())
	}
	if st.Mode&0o022 != 0 {
		return fmt.Errorf("%w: %s is writable by group or others (mode %04o)", ErrDirectory, f.Name(), st.Mode&0o7777)
	}
	if int(st.Uid) != os.Geteuid() && !(allowRoot && st.Uid == 0) {
		return fmt.Errorf("%w: %s is not owned by the user this runs as", ErrDirectory, f.Name())
	}
	return nil
}

// Close closes the directory.
func (d *Dir) Close() error { return d.f.Close() }

// Write writes the envelope as the file of its kind, mode 0400, owned by the
// caller, never replacing a file, and returns its path. The envelope is checked
// (pool.ValidateHot) before anything is created, and a file that cannot be
// written completely is removed.
func (d *Dir) Write(kind ports.HotFileKind, envelope *secret.Buffer) (string, error) {
	spec, ok := kind.Spec()
	if !ok {
		return "", fmt.Errorf("%w: unknown kind %d", ErrNotHot, kind)
	}
	if err := envelope.Use(func(b []byte) error { return pool.ValidateHot(kind, b) }); err != nil {
		return "", err
	}
	fd, err := unix.Openat(int(d.f.Fd()), spec.File, unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_WRONLY|unix.O_CLOEXEC, 0o400)
	if err != nil {
		if errors.Is(err, unix.EEXIST) {
			return "", fmt.Errorf("%w: %s", ErrExists, spec.File)
		}
		return "", fmt.Errorf("%s: %w", spec.File, err)
	}
	f := os.NewFile(uintptr(fd), spec.File)
	done := false
	defer func() {
		f.Close()
		if !done {
			unix.Unlinkat(int(d.f.Fd()), spec.File, 0)
		}
	}()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return "", err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || int(st.Uid) != os.Geteuid() || st.Nlink != 1 {
		return "", fmt.Errorf("%s: the created file is not a plain file of this user", spec.File)
	}
	if err := unix.Fchmod(fd, 0o400); err != nil {
		return "", err
	}
	if _, err := envelope.WriteTo(f); err != nil {
		return "", err
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	done = true
	return d.f.Name() + "/" + spec.File, nil
}

// Remove deletes the file of a kind that Write created, for the rollback of a
// delivery that failed half way.
func (d *Dir) Remove(kind ports.HotFileKind) {
	if spec, ok := kind.Spec(); ok {
		unix.Unlinkat(int(d.f.Fd()), spec.File, 0)
	}
}

// readFileAt reads a plain file of at most max bytes relative to an open
// directory: O_NOFOLLOW, a regular file, owned by the effective user or by
// root, no group or other permission bits when private is set.
func readFileAt(d *os.File, name string, max int, private bool) ([]byte, error) {
	fd, err := unix.Openat(int(d.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	if int(st.Uid) != os.Geteuid() && st.Uid != 0 {
		return nil, fmt.Errorf("%s is owned by another user", name)
	}
	// A private file has no permission for others and none for the group except
	// read, which is allowed only when the file's group is the process's own
	// primary group (systemd makes credentials 0400 or 0440 of the service user).
	if private && (st.Mode&0o007 != 0 || st.Mode&0o030 != 0 || (st.Mode&0o040 != 0 && int(st.Gid) != os.Getegid())) {
		return nil, fmt.Errorf("%s is accessible by others or by a group other than this user's own (mode %04o, group %d)", name, st.Mode&0o7777, st.Gid)
	}
	if st.Size > int64(max) {
		return nil, fmt.Errorf("%s is larger than %d bytes", name, max)
	}
	buf := make([]byte, st.Size)
	n := 0
	for n < len(buf) {
		m, err := f.Read(buf[n:])
		n += m
		if err != nil {
			break
		}
	}
	if n != len(buf) {
		clear(buf)
		return nil, fmt.Errorf("%s: short read", name)
	}
	return buf, nil
}

// tmpfsHasNoswap reads /proc/self/mountinfo.
func tmpfsHasNoswap(major, minor uint32) (bool, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return false, err
	}
	defer f.Close()
	return mountHasNoswap(f, major, minor)
}
