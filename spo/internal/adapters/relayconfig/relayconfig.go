// Package relayconfig reads the relay operator's files (ADR 0014 work package
// 10): the configuration file, version 2, and the relay's key file.
//
// The configuration names the admission (open, or an allow-list of wallet
// keys), the key file and the two store directories, the tunnel's port and DERP
// map, the device node keys the tunnel admits (restricted by default), the
// registry's bounds and policy, the open quota, the session limits, the
// retention and the sweep interval. It is read into a relayconf.Config whose
// parts are validated by the domain packages that use them; the session limits
// are kept as overrides and validated by app/relayhost, which owns the session's
// table (an adapter does not import a use case). The file is a small subset of
// TOML read by internal/platform/tomlsubset (see parse.go); unknown keys and
// tables are refused.
//
// The relay parses no identity document: the access list of version 1 is gone.
// Nothing this package links can open an envelope (SPO-Xmailbox-SEC-009).
package relayconfig

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/mochipool/workbench/spo/internal/domain/relayconf"
)

// geteuid is the effective uid owners are compared with; a variable so that a
// test can change it.
var geteuid = os.Geteuid

// Bounds of the file, checked before anything of that size is read or built.
const (
	// MaxFileBytes is the largest configuration file: room for the 4096 array
	// tables.
	MaxFileBytes = 1 << 20
	// MaxLineBytes is the longest line.
	MaxLineBytes = 4 << 10
	// MaxArrayTables is the most [[device]] and [[wallet]] tables together.
	MaxArrayTables = relayconf.MaxDevices
	// MaxLabelBytes is the longest label of a device or a wallet key.
	MaxLabelBytes = 64
)

// ErrConfig is the root of every refusal (relayconf's).
var ErrConfig = relayconf.ErrConfig

func bad(format string, a ...any) error { return relayconf.Bad(format, a...) }

// Load reads and validates the file at path, and checks the store and key paths
// on the disk (SPO-Xmailbox-PRE-063). The file must be a regular file owned by
// the effective user or by root (by fstat on the opened descriptor), that its
// group and others cannot write, of at most MaxFileBytes; the size is checked
// before a byte is read. A link is followed (a mounted secret or a store path
// is one) and a FIFO is refused without being waited on.
func Load(path string) (*relayconf.Config, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}
	switch {
	case !st.Mode().IsRegular():
		return nil, bad("%s is not a regular file", path)
	case !ownerOK(st, geteuid()):
		return nil, bad("%s is owned by uid %d; it must belong to the user running the relay (uid %d) or to root, or its owner could add a device or change the admission", path, fileUID(st), geteuid())
	case st.Mode().Perm()&0o022 != 0:
		return nil, bad("%s is writable by its group or by everyone (mode %o); another user could add a device or change the admission. Run: chmod 600 %s", path, st.Mode().Perm(), path)
	case st.Size() > MaxFileBytes:
		return nil, bad("%s is %d bytes; the limit is %d", path, st.Size(), MaxFileBytes)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}
	c, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := CheckPaths(c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// CheckPaths checks the store directories and the key file's directory on the
// disk: an existing store directory is a directory of the effective user with
// no group or other permission bit; the parent of one that does not exist yet,
// and the key's directory, belong to the user or to root and are not writable by
// their group or others; an existing key file has no group or other permission
// bit and belongs to the user (its content is checked by LoadKey).
func CheckPaths(c *relayconf.Config) error {
	dirs := []struct{ what, path string }{{"mailbox_dir", c.MailboxDir}, {"registry_dir", c.RegistryDir}}
	if c.StoreKind() != relayconf.StoreDirectory {
		dirs = nil // an object store has no directory; the token file is read at each exchange
	}
	for _, d := range dirs {
		st, err := os.Stat(d.path)
		switch {
		case errors.Is(err, os.ErrNotExist):
			if err := checkParent(d.what, filepath.Dir(d.path)); err != nil {
				return err
			}
			continue
		case err != nil:
			return fmt.Errorf("%w: %s: %w", ErrConfig, d.what, err)
		case !st.IsDir():
			return bad("%s %s is not a directory", d.what, d.path)
		case fileUID(st) != geteuid():
			return bad("%s %s is owned by uid %d, not by the user running the relay (uid %d)", d.what, d.path, fileUID(st), geteuid())
		case st.Mode().Perm()&0o077 != 0:
			return bad("%s %s has group or other permission bits (mode %o); the stores are the relay's alone. Run: chmod 700 %s", d.what, d.path, st.Mode().Perm(), d.path)
		}
	}
	// a root-owned key is a mounted Secret: its own rules check its directory
	if st, err := os.Stat(c.KeyFile); err == nil && rootOwned(st) {
		k, err := loadMounted(c.KeyFile)
		k.Destroy()
		return err
	}
	if err := checkParent("key_file", filepath.Dir(c.KeyFile)); err != nil {
		return err
	}
	st, err := os.Stat(c.KeyFile)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("%w: key_file: %w", ErrConfig, err)
	}
	return keyMode(c.KeyFile, st)
}

// keyMode is the rule of a key file's metadata: a regular file of the user with
// no group or other permission bit.
func keyMode(path string, st os.FileInfo) error {
	switch {
	case !st.Mode().IsRegular():
		return bad("key_file %s is not a regular file", path)
	case fileUID(st) != geteuid():
		return bad("key_file %s is owned by uid %d, not by the user running the relay (uid %d)", path, fileUID(st), geteuid())
	case st.Mode().Perm()&0o077 != 0:
		return bad("key_file %s has group or other permission bits (mode %o); the relay key must not be readable by anyone else. Run: chmod 600 %s", path, st.Mode().Perm(), path)
	}
	return nil
}

// checkParent requires dir to be a directory owned by the user or by root that
// its group and others cannot write.
func checkParent(what, dir string) error {
	st, err := os.Stat(dir)
	switch {
	case err != nil:
		return fmt.Errorf("%w: %s: the directory %s: %w", ErrConfig, what, dir, err)
	case !st.IsDir():
		return bad("%s: %s is not a directory", what, dir)
	case !ownerOK(st, geteuid()):
		return bad("%s: the directory %s is owned by uid %d; it must belong to the user running the relay or to root", what, dir, fileUID(st))
	case st.Mode().Perm()&0o022 != 0:
		return bad("%s: the directory %s is writable by its group or by everyone (mode %o); another user could replace what the relay keeps there", what, dir, st.Mode().Perm())
	}
	return nil
}

// ownerOK reports whether the file's owner may write the relay's
// configuration: the effective user, or root.
func ownerOK(st os.FileInfo, euid int) bool {
	uid := fileUID(st)
	return uid == euid || uid == 0
}

func fileUID(st os.FileInfo) int {
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		return int(sys.Uid)
	}
	return -1 // not a unix stat: nobody
}

// checkPathsText is the part of PRE-063 that needs no disk: required, absolute,
// clean, distinct and not inside one another.
func checkPathsText(c *relayconf.Config) error {
	paths := []struct{ what, p string }{{"key_file", c.KeyFile}, {"mailbox_dir", c.MailboxDir}, {"registry_dir", c.RegistryDir}}
	if c.StoreKind() == relayconf.StoreS3 {
		// the object store keeps no directory (relayconf's Check refuses the keys too)
		for _, d := range paths[1:] {
			if d.p != "" {
				return bad("[relay] %s is a key of the directory store; the object store ([store] kind = \"s3\") keeps no directory: remove it", d.what)
			}
		}
		paths = paths[:1]
	}
	for _, x := range paths {
		switch {
		case x.p == "":
			return bad("[relay] %s is required", x.what)
		case !filepath.IsAbs(x.p):
			return bad("[relay] %s %q is not an absolute path", x.what, x.p)
		case filepath.Clean(x.p) != x.p:
			return bad("[relay] %s %q is not a clean path (write it as %q)", x.what, x.p, filepath.Clean(x.p))
		}
	}
	for i, a := range paths {
		for _, b := range paths[i+1:] {
			if a.p == b.p {
				return bad("[relay] %s and %s are the same path; the three must be distinct", a.what, b.what)
			}
			if inside(a.p, b.p) || inside(b.p, a.p) {
				return bad("[relay] %s and %s: one is inside the other; the key and the two stores must be apart", a.what, b.what)
			}
		}
	}
	return nil
}

// inside reports whether p is below dir.
func inside(p, dir string) bool {
	if dir == "/" {
		return p != "/"
	}
	return strings.HasPrefix(p, dir+"/")
}
