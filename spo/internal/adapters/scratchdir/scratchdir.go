// Package scratchdir is ports.Scratch on the workspace directory: private
// files (0600) and directories (0700), no symbolic link followed.
package scratchdir

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// Dir is the scratch space of one directory.
type Dir struct{ root string }

var _ ports.Scratch = (*Dir)(nil)

var partRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// Open returns the scratch space of root, creating it (0700) when missing. It
// refuses a directory that is writable by its group or by others: another user
// could replace what is put there.
func Open(root string) (*Dir, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(root); errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(root, 0o700); err != nil {
			return nil, err
		}
	}
	real, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(real)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", root)
	}
	if st.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("the workspace directory %s is writable by its group or by everyone (mode %o); another user could replace a temporary file in it. Run: chmod go-w %s", root, st.Mode().Perm(), root)
	}
	return &Dir{root: real}, nil
}

func split(name string) ([]string, error) {
	parts := strings.Split(name, "/")
	if len(parts) < 1 || len(parts) > 2 {
		return nil, fmt.Errorf("bad scratch name %q", name)
	}
	for _, p := range parts {
		if !partRE.MatchString(p) || p == "." || p == ".." {
			return nil, fmt.Errorf("bad scratch name %q", name)
		}
	}
	return parts, nil
}

// Path is the path of name.
func (d *Dir) Path(name string) string { return filepath.Join(d.root, filepath.FromSlash(name)) }

// MakeDir creates a private directory.
func (d *Dir) MakeDir(prefix string) (string, error) {
	if !partRE.MatchString(prefix) {
		return "", fmt.Errorf("bad scratch prefix %q", prefix)
	}
	p, err := os.MkdirTemp(d.root, prefix)
	if err != nil {
		return "", err
	}
	return filepath.Base(p), nil
}

// parentOK checks that the directory part of a two-component name is a real
// directory, not a link.
func (d *Dir) parentOK(parts []string) error {
	if len(parts) == 1 {
		return nil
	}
	st, err := os.Lstat(filepath.Join(d.root, parts[0]))
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ports.ErrScratchUnsafe, parts[0])
	}
	return nil
}

// Open creates or opens the private file name.
func (d *Dir) Open(name string) (ports.ScratchFile, error) {
	parts, err := split(name)
	if err != nil {
		return nil, err
	}
	if err := d.parentOK(parts); err != nil {
		return nil, err
	}
	path := d.Path(name)
	for attempt := 0; ; attempt++ {
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
		if err != nil {
			// a symbolic link at the name: O_NOFOLLOW gives ELOOP. Remove the
			// link itself and make the file again; the target is never opened.
			if errors.Is(err, syscall.ELOOP) && attempt == 0 {
				if st, lerr := os.Lstat(path); lerr == nil && st.Mode()&fs.ModeSymlink != 0 {
					if rerr := os.Remove(path); rerr != nil {
						return nil, rerr
					}
					continue
				}
			}
			return nil, err
		}
		st, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, err
		}
		sys, _ := st.Sys().(*syscall.Stat_t)
		if !st.Mode().IsRegular() || sys == nil || sys.Nlink != 1 || int(sys.Uid) != os.Geteuid() {
			f.Close()
			return nil, ports.ErrScratchUnsafe
		}
		return f, nil
	}
}

// Remove deletes name, never following a link.
func (d *Dir) Remove(name string) error {
	parts, err := split(name)
	if err != nil {
		return err
	}
	if err := d.parentOK(parts); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		// a link where a directory should be: remove the link
		if len(parts) == 2 {
			return nil
		}
		return err
	}
	path := d.Path(name)
	st, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if st.IsDir() {
		return os.RemoveAll(path)
	}
	return os.Remove(path)
}

// Entries lists the top-level entries.
func (d *Dir) Entries() ([]ports.ScratchEntry, error) {
	ents, err := os.ReadDir(d.root)
	if err != nil {
		return nil, err
	}
	var out []ports.ScratchEntry
	for _, e := range ents {
		st, err := os.Lstat(filepath.Join(d.root, e.Name()))
		if err != nil {
			continue
		}
		en := ports.ScratchEntry{Name: e.Name(), ModTime: st.ModTime()}
		switch m := st.Mode(); {
		case m&fs.ModeSymlink != 0:
			en.Kind = ports.ScratchSymlink
		case m.IsDir():
			en.Kind = ports.ScratchDirectory
		case m.IsRegular():
			en.Kind = ports.ScratchRegular
		default:
			en.Kind = ports.ScratchOther
		}
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			en.Owned = int(sys.Uid) == os.Geteuid()
		}
		out = append(out, en)
	}
	return out, nil
}
