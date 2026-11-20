// Package mountfile reads a small file that a Kubernetes kubelet mounted into
// the pod (a Secret volume, a projected service-account token) or that an
// operator put on a host, with the care the repository takes for a file that
// holds a credential, and without refusing the layout kubelet really makes
// (ADR 0015 decisions 6 and 10).
//
// What kubelet makes (kubelet's atomic writer; the modes are from memory and
// not checked on a cluster): the mount directory, a tmpfs that is world-writable
// with the sticky bit (1777, 2777 with fsGroup) and owned by root; inside it a
// timestamped directory "..<date>" (0755, root) that holds the files; a link
// "..data" to that directory, replaced atomically at each rotation; and one
// link per file, "<name> -> ..data/<name>". The files are root-owned: a Secret
// gets its defaultMode with the group set to fsGroup and the group read bit
// added; a projected token is 0644 by default, 0640 with fsGroup, or 0600 owned
// by the pod's user when every container runs as one user.
//
// The rules, checked on what was opened:
//
//   - The directory of the path is resolved first, component by component (a
//     link in an ancestor, such as /var/run -> /run on Debian and Alpine images,
//     is followed), and every directory on the way, the links lead through
//     included, passes the directory rule below, and every link on the way is
//     owned by root or the effective user; the rest is checked against the
//     resolved directory.
//   - The directory of the path is owned by root or by the process's effective
//     user; when its group or others may write it, it must have the sticky bit
//     and be owned by root (so no other user can replace an entry in it).
//   - The final component is a regular file opened with O_NOFOLLOW and
//     O_NONBLOCK (a FIFO does not block the read and is refused), or a link,
//     owned by root or the effective user, that resolves to a file of the same
//     name in a directory "..<something>" directly inside the same directory:
//     kubelet's layout and nothing else. That directory is owned by root or the
//     effective user and not writable by its group or others. A link that
//     leaves the layout is refused.
//   - The file is owned by root or by the effective user and is not writable by
//     its group or others. Key (a relay key) is stricter: a file of the
//     effective user has no group or other bit at all; a file of root is
//     accepted only as kubelet mounts a Secret volume (reached through the
//     "<name> -> ..data/<name>" link; a plain root-owned file on a host, or a
//     subPath mount, is refused) and has only the read bits of its owner and
//     group (0400 or 0440), the group read bit only when the file's group is
//     the process's effective group (a supplementary group does not count).
//     Token (a web identity token, which kubelet mounts readable by others by
//     default) allows the read bits and a plain root-owned file.
//   - The size is checked by fstat before a byte is read (exactly the size of a
//     Key rule, at most the bound of a Token rule), and the read never takes
//     more than that.
//
// A rotation that removes the timestamped directory between the resolution and
// the open is retried twice. Errors name the path and the rule, never the
// content.
package mountfile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// ErrRefused is wrapped by every refusal of a file by the rules.
var ErrRefused = errors.New("refused")

// Rule is how strictly a file is read.
type Rule struct {
	max   int64
	exact bool
	key   bool
}

// Token is the rule of a web identity token of at most max bytes.
func Token(max int64) Rule { return Rule{max: max} }

// Key is the rule of a key file of exactly size bytes.
func Key(size int64) Rule { return Rule{max: size, exact: true, key: true} }

// Seams: a uid that counts as root besides 0, the effective uid and gid.
var (
	rootUID = 0
	euid    = os.Geteuid
	egid    = os.Getegid
)

// maxLinks bounds the links followed while the directory is resolved (the
// kernel's own bound is 40).
const maxLinks = 40

var errRotated = errors.New("the file was rotated while it was opened")

func refused(path, format string, a ...any) error {
	return fmt.Errorf("%w: %s %s", ErrRefused, path, fmt.Sprintf(format, a...))
}

// Read reads the file at path by r. A missing file is an error that satisfies
// fs.ErrNotExist.
func Read(path string, r Rule) ([]byte, error) {
	for attempt := 0; ; attempt++ {
		b, err := read(path, r)
		if errors.Is(err, errRotated) && attempt < 2 {
			continue
		}
		if errors.Is(err, errRotated) {
			return nil, refused(path, "kept changing while it was opened")
		}
		return b, err
	}
}

func owner(st fs.FileInfo) (uid, gid int, ok bool) {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return -1, -1, false
	}
	return int(sys.Uid), int(sys.Gid), true
}

func isRoot(uid int) bool { return uid == 0 || uid == rootUID }

func ours(uid int) bool { return isRoot(uid) || uid == euid() }

// trustedDir checks a directory: owned by root or the effective user; writable
// by its group or others only with the sticky bit and root as owner, unless
// sticky is false (the timestamped directory, which nobody else may write).
func trustedDir(path string, st fs.FileInfo, sticky bool) error {
	uid, _, ok := owner(st)
	switch {
	case !st.IsDir():
		return refused(path, "is not a directory")
	case !ok || !ours(uid):
		return refused(path, "is owned by uid %d, neither root nor the user running the relay", uid)
	case st.Mode().Perm()&0o022 == 0:
		return nil
	case sticky && st.Mode()&os.ModeSticky != 0 && isRoot(uid):
		return nil
	}
	return refused(path, "is writable by its group or others (mode %o) without being root's with the sticky bit", st.Mode().Perm())
}

// resolveDir resolves dir component by component, as the kernel would, and
// returns it with no link left. Every directory an entry is looked up in (each
// ancestor, and each directory a link leads through) must pass trustedDir,
// and every link followed must be root's or the effective user's: then no
// other user can change what the path resolves to, since that takes writing
// one of those directories or replacing one of those links. (spo.toml's own
// check, adapters/config, looks at the workspace directory only, because the
// user chose that path; a mounted file's path is the operator's or kubelet's
// and passes through directories such as /var/run that the image makes.)
func resolveDir(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	resolved := "/"
	rest := strings.Split(abs, "/")
	links := 0
	for len(rest) > 0 {
		name := rest[0]
		rest = rest[1:]
		switch name {
		case "", ".":
			continue
		case "..":
			resolved = filepath.Dir(resolved) // resolved holds no link: ".." is lexical
			continue
		}
		st, err := os.Lstat(resolved)
		if err != nil {
			return "", err
		}
		if err := trustedDir(resolved, st, true); err != nil {
			return "", err
		}
		next := filepath.Join(resolved, name)
		lst, err := os.Lstat(next)
		if err != nil {
			return "", err
		}
		if lst.Mode()&os.ModeSymlink == 0 {
			if !lst.IsDir() {
				return "", refused(next, "is not a directory")
			}
			resolved = next
			continue
		}
		if uid, _, ok := owner(lst); !ok || !ours(uid) {
			return "", refused(next, "is a link owned by uid %d, neither root nor the user running the relay", uid)
		}
		if links++; links > maxLinks {
			return "", refused(abs, "has more than %d links on its way", maxLinks)
		}
		target, err := os.Readlink(next)
		if err != nil {
			return "", err
		}
		if filepath.IsAbs(target) {
			resolved = "/"
		}
		rest = append(strings.Split(target, "/"), rest...)
	}
	return resolved, nil
}

func read(path string, r Rule) ([]byte, error) {
	dir, err := resolveDir(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	dst, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if err := trustedDir(dir, dst, true); err != nil {
		return nil, err
	}
	shown := path                                  // the errors name the path as given
	path = filepath.Join(dir, filepath.Base(path)) // and the reads use the resolved one
	lst, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	real, linked := path, lst.Mode()&os.ModeSymlink != 0
	if linked {
		if uid, _, ok := owner(lst); !ok || !ours(uid) {
			return nil, refused(shown, "is a link owned by uid %d, neither root nor the user running the relay", uid)
		}
		real, err = filepath.EvalSymlinks(path)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, errRotated
		}
		if err != nil {
			return nil, refused(shown, "is a link that cannot be resolved")
		}
		sub := filepath.Dir(real)
		if filepath.Base(real) != filepath.Base(path) || filepath.Dir(sub) != dir || !strings.HasPrefix(filepath.Base(sub), "..") {
			return nil, refused(shown, "is a link that leaves kubelet's layout (%s/..<date>/%s)", dir, filepath.Base(path))
		}
		sst, err := os.Lstat(sub)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, errRotated
		}
		if err != nil {
			return nil, err
		}
		if err := trustedDir(sub, sst, false); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(real, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	switch {
	case errors.Is(err, fs.ErrNotExist) && real != path:
		return nil, errRotated
	case errors.Is(err, syscall.ELOOP):
		return nil, refused(shown, "is a link where a file is expected")
	case err != nil:
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if err := r.check(shown, st, linked); err != nil {
		return nil, err
	}
	// one buffer of the stated size and one byte, never grown: a secret is not
	// left behind in a discarded smaller copy
	b := make([]byte, st.Size()+1)
	n, err := io.ReadFull(f, b)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		clear(b)
		return nil, refused(shown, "cannot be read")
	}
	if int64(n) != st.Size() {
		clear(b)
		return nil, refused(shown, "changed size while it was read")
	}
	return b[:n], nil
}

// check is the rule on the opened file; linked says it was reached through
// kubelet's links (the only form a root-owned key may have).
func (r Rule) check(path string, st fs.FileInfo, linked bool) error {
	uid, gid, ok := owner(st)
	perm := st.Mode().Perm()
	switch {
	case !st.Mode().IsRegular():
		return refused(path, "is not a regular file")
	case !ok || !ours(uid):
		return refused(path, "is owned by uid %d, neither root nor the user running the relay", uid)
	case perm&0o022 != 0:
		return refused(path, "is writable by its group or others (mode %o)", perm)
	}
	if r.key {
		switch {
		case uid == euid() && !isRoot(uid) && perm&0o077 != 0:
			return refused(path, "has group or other permission bits (mode %o); a key of the user running the relay must be readable by it alone (chmod 600)", perm)
		case isRoot(uid) && !linked:
			return refused(path, "is root's but is not a Secret volume as kubelet mounts it (<name> -> ..data/<name>); on a host the key must be the relay user's: chown it to that user and chmod 400 (or 600). A Secret mounted with subPath is not supported: mount the whole volume")
		case isRoot(uid) && perm&^0o440 != 0:
			return refused(path, "is root's with mode %o; a root-owned key may have only the read bits of its owner and group (0400 or 0440, the Secret's defaultMode)", perm)
		case isRoot(uid) && perm&0o040 != 0 && gid != egid():
			return refused(path, "is readable by group %d, which is not the effective group of the relay's process (a supplementary group, such as the pod's fsGroup alone, does not count: set the pod's runAsGroup to its fsGroup)", gid)
		}
	}
	switch {
	case r.exact && st.Size() != r.max:
		return refused(path, "is %d bytes; it must be %d", st.Size(), r.max)
	case st.Size() > r.max:
		return refused(path, "is %d bytes; the limit is %d", st.Size(), r.max)
	}
	return nil
}
