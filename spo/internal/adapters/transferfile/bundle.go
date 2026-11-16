package transferfile

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/mochipool/workbench/spo/internal/domain/transfer"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ErrChangedDuringWrite: the file changed on disk between the read and the
// write of a mutation, so the write was not made (a second writer would
// otherwise lose its update, SPO-Ptransfer-INV-002).
var ErrChangedDuringWrite = errors.New("the offline transfer file changed while it was being updated; nothing was written, try again")

// ReadBundle implements ports.BundleReader. A missing file is the empty
// bundle (SPO-01workOffline-IN-001); a file that is not JSON is an error
// wrapping transfer.ErrNotJSON (SPO-01workOffline-PRE-003).
//
// spec: SPO-01workOffline-IN-001, SPO-01workOffline-PRE-003
func (f *File) ReadBundle(context.Context) (*transfer.Bundle, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, found, _, err := f.readBundle()
	return b, found, err
}

func (f *File) readBundle() (*transfer.Bundle, bool, []byte, error) {
	raw, err := os.ReadFile(f.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return transfer.Empty(), false, nil, nil
	}
	if err != nil {
		return nil, false, nil, err
	}
	b, err := transfer.Parse(raw)
	if err != nil {
		return nil, true, raw, err
	}
	return b, len(bytes.TrimSpace(raw)) > 0, raw, nil
}

// MutateBundle implements ports.BundleMutator: one atomic read, change,
// write and read back of the whole file. The file is written to a temporary
// file in its directory, synced and renamed over the original, which keeps
// its mode (hazard H10); an error from fn, or from any step, leaves the file
// as it was. The rendering is the one `jq` makes, so the parts of the file
// that fn does not touch are byte-equal to what was read.
//
// spec: SPO-Ptransfer-INV-002, SPO-Ptransfer-OUT-012
func (f *File) MutateBundle(_ context.Context, fn func(*transfer.Bundle) error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, _, before, err := f.readBundle()
	if err != nil {
		return err
	}
	if err := fn(b); err != nil {
		return err
	}
	out, err := b.Marshal()
	if err != nil {
		return err
	}
	// A second writer that got in between would lose its update.
	if now, err := os.ReadFile(f.Path); err == nil {
		if !bytes.Equal(now, before) {
			return ErrChangedDuringWrite
		}
	} else if !errors.Is(err, fs.ErrNotExist) || before != nil {
		return ErrChangedDuringWrite
	}
	if err := writeAtomic(f.Path, out); err != nil {
		return err
	}
	if f.afterWrite != nil {
		f.afterWrite()
	}
	back, err := os.ReadFile(f.Path)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrReadBack, err)
	}
	if !bytes.Equal(back, out) {
		return ErrReadBack
	}
	return nil
}

// DirSink implements ports.FileSink on one directory. Extraction never
// writes outside it: a name must be a plain file name (transfer.SafeName),
// the destination is Dir joined with that name and nothing the bundle says
// is used as a path; an existing file is kept unless overwriting was asked
// for, and a symbolic link or other non-regular file is never written
// through (SPO-Ptransfer-SEC-001, SPO-01workOffline-SEC-004).
type DirSink struct {
	Dir string
}

// WriteFile implements ports.FileSink.
//
// spec: SPO-Ptransfer-SEC-001, SPO-01workOffline-SEC-001, SPO-01workOffline-SEC-004
func (s DirSink) WriteFile(_ context.Context, name string, data []byte, overwrite bool) (bool, error) {
	plain, err := transfer.SafeName(name)
	if err != nil {
		return false, err
	}
	if s.Dir == "" {
		return false, errors.New("no directory to extract into")
	}
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return false, err
	}
	target := filepath.Join(s.Dir, plain)
	if filepath.Dir(target) != filepath.Clean(s.Dir) {
		return false, fmt.Errorf("%w: %q", transfer.ErrUnsafeName, name)
	}
	if st, err := os.Lstat(target); err == nil {
		if !overwrite {
			return false, nil
		}
		if !st.Mode().IsRegular() {
			return false, fmt.Errorf("%s exists and is not a regular file; it is not replaced", plain)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	tmp, err := os.CreateTemp(s.Dir, ".extract-*")
	if err != nil {
		return false, err
	}
	tname := tmp.Name()
	fail := func(err error) (bool, error) {
		tmp.Close()
		os.Remove(tname)
		return false, err
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tname)
		return false, err
	}
	if overwrite {
		if err := os.Rename(tname, target); err != nil {
			os.Remove(tname)
			return false, err
		}
	} else {
		// Link, not rename: it fails when the name appeared meanwhile.
		err := os.Link(tname, target)
		os.Remove(tname)
		if errors.Is(err, fs.ErrExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
	}
	if d, err := os.Open(s.Dir); err == nil {
		d.Sync()
		d.Close()
	}
	return true, nil
}

var (
	_ ports.BundleReader  = (*File)(nil)
	_ ports.BundleMutator = (*File)(nil)
	_ ports.FileSink      = DirSink{}
)
