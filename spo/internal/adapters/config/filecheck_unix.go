//go:build unix

package config

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// processUID is the owner spo.toml must have to name a backend (a test's seam).
var processUID = os.Getuid

// modeBitsBoundAccess is true where the mode bits bound who can write a file.
// On Linux a POSIX access control list cannot grant more than the group bits
// show (they are its mask), so the mode check is sound. On macOS and the BSDs
// an extended (NFSv4-style) access list can let another user write a file
// whose mode says 0600, and the standard library cannot read it: there every
// file is untrusted for a backend (SPO-Xunlock-PRE-050). A test's seam.
var modeBitsBoundAccess = runtime.GOOS == "linux"

// readFile reads spo.toml of dir and decides whether it may name a Vault or KMS
// backend on what was read (SPO-Xunlock-PRE-050). The workspace directory is
// opened first and checked through its descriptor (fstat), and the file is
// opened relative to that descriptor (openat, O_NOFOLLOW) and checked through
// its own (fstat), so there is no gap between a check and an open. The file is
// untrusted when its final component is a symbolic link, it has more than one
// hard link, it is owned by another user than this process's (or root), group
// or others can write it, or the directory is owned by another user (or root)
// or group or others can write it (with or without the sticky bit). The data is
// still returned: only a backend, and a rewrite (Save), refuse it. A file that
// is not a regular file, or is larger than MaxFileSize, is an error.
//
// Not checked: the directories above the workspace directory, and whether the
// workspace directory itself was reached through a symbolic link (the path to
// it is the user's own choice, as with -C).
func readFile(dir string) (data []byte, untrusted error, err error) {
	p := Path(dir)
	d, err := os.Open(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, err
		}
		// not readable as a directory: read the file by its path for every
		// other setting, and trust it with nothing
		data, err := readOpen(p, unix.O_RDONLY|unix.O_NONBLOCK)
		if err != nil {
			return nil, nil, err
		}
		return data, untrustedErr(p, errors.New("is in a directory this tool cannot open to check")), nil
	}
	defer d.Close()
	dfd := int(d.Fd())
	fd, err := unix.Openat(dfd, FileName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ELOOP) {
		// a symbolic link: read through it as before for every other setting
		untrusted = errors.New("is a symbolic link (the file itself must be in the workspace directory)")
		fd, err = unix.Openat(dfd, FileName, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		return nil, nil, &fs.PathError{Op: "open", Path: p, Err: err}
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s is not a regular file", p)
	}
	if st.Size() > MaxFileSize {
		return nil, nil, fmt.Errorf("%s is larger than %d bytes", p, MaxFileSize)
	}
	if untrusted == nil {
		untrusted = ownerAndMode(st)
	}
	if untrusted == nil {
		untrusted = directoryCheck(d, dir)
	}
	if untrusted == nil && !modeBitsBoundAccess {
		untrusted = fmt.Errorf("cannot be trusted here: %w (on %s an access control list can let another user write a file whatever its mode says, and this tool cannot read it)", ErrPlatformUnchecked, runtime.GOOS)
	}
	data, err = readAll(f, p)
	if err != nil {
		return nil, nil, err
	}
	if untrusted != nil {
		untrusted = untrustedErr(p, untrusted)
	}
	return data, untrusted, nil
}

// untrustedErr is the refusal: the file, the reason and the remedy.
func untrustedErr(p string, why error) error {
	if errors.Is(why, ErrPlatformUnchecked) {
		return fmt.Errorf("%w: %s %w; use --unlock passphrase or fido2 on this machine, or the backend from a Linux machine", ErrUntrustedFile, p, why)
	}
	return fmt.Errorf("%w: %s %w. Inspect it (above all [vault] and [kms]: they decide where a Vault token or an AWS identity goes), then recreate it: write a new file in the workspace directory, owned by you and writable by you only (mode 0600), and rename it over %s; keep the workspace directory yours and closed to group and others (chmod 700 or 755). chmod 600 alone does not undo a link, a second name or another owner", ErrUntrustedFile, p, why, p)
}

func readOpen(p string, flags int) ([]byte, error) {
	f, err := os.OpenFile(p, flags, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", p)
	}
	if st.Size() > MaxFileSize {
		return nil, fmt.Errorf("%s is larger than %d bytes", p, MaxFileSize)
	}
	return readAll(f, p)
}

func readAll(f *os.File, p string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxFileSize {
		return nil, fmt.Errorf("%s grew past %d bytes while it was read", p, MaxFileSize)
	}
	return data, nil
}

// ownerAndMode checks the open file: owned by this process's user or root, not
// writable by group or others, and with one name only (another hard link could
// be in a directory someone else controls).
func ownerAndMode(st os.FileInfo) error {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("has no owner this tool can check")
	}
	if uid := uint32(processUID()); sys.Uid != uid && sys.Uid != 0 {
		return fmt.Errorf("is owned by user %d, not by the user running spo (%d) or root", sys.Uid, uid)
	}
	if st.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("can be changed by group or others (mode %04o)", st.Mode().Perm())
	}
	if sys.Nlink != 1 {
		return fmt.Errorf("has %d hard links (another name of the file may be in a directory another user controls)", sys.Nlink)
	}
	return nil
}

// directoryCheck checks the workspace directory through the descriptor the file
// was opened under: owned by this process's user or root, and not writable by
// group or others. The sticky bit is not enough: in a directory such as /tmp
// another user can create spo.toml before the user does.
func directoryCheck(d *os.File, dir string) error {
	st, err := d.Stat()
	if err != nil || !st.IsDir() {
		return errors.New("is in a directory this tool cannot check")
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("is in a directory this tool cannot check")
	}
	if uid := uint32(processUID()); sys.Uid != uid && sys.Uid != 0 {
		return fmt.Errorf("is in %s, the directory of user %d, not of the user running spo (%d) or root", dir, sys.Uid, uid)
	}
	if st.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("is in %s, the directory that group or others can write (mode %04o)", dir, st.Mode().Perm())
	}
	return nil
}
