package layoutread

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// ScratchFile is the verified store file an import builds from a layout, in
// private scratch space. The verifier removes it; the importer hands it to the
// restore with its SHA-256 and removes it afterwards.
type ScratchFile struct {
	// Dir is the scratch directory (a name for ports.Scratch), Name the file in it
	// and Path its path, for the restore.
	Dir, Name, Path string
	// SHA256 is the hash of the file as written: the restore checks its own
	// private copy against it, so the bytes installed are the bytes that were
	// verified here.
	SHA256 []byte
}

// BuildScratch writes the snapshot into a new verified store file in a private
// scratch directory through w, which holds the credential and runs the store's
// full verification (the audit chain, the record hashes and the policy) before it
// links the file into place. Nothing else touches the file. On any failure the
// scratch directory is removed.
func BuildScratch(ctx context.Context, sc ports.Scratch, w ports.SnapshotFileWriter, snap ports.Snapshot) (_ *ScratchFile, err error) {
	if sc == nil || w == nil {
		return nil, errors.New("layoutread: no scratch space or snapshot writer")
	}
	dir, err := sc.MakeDir("layout-")
	if err != nil {
		return nil, fmt.Errorf("making private scratch space: %w", err)
	}
	defer func() {
		if err != nil {
			sc.Remove(dir)
		}
	}()
	name := dir + "/workspace.spo"
	path := sc.Path(name)
	if err = w.WriteSnapshotFile(ctx, path, snap); err != nil {
		return nil, err
	}
	f, err := sc.Open(name)
	if err != nil {
		return nil, fmt.Errorf("reading back the scratch file: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return nil, err
	}
	return &ScratchFile{Dir: dir, Name: name, Path: path, SHA256: h.Sum(nil)}, nil
}

// Remove deletes the scratch directory and what is in it.
func (f *ScratchFile) Remove(sc ports.Scratch) error {
	if f == nil || sc == nil {
		return nil
	}
	return sc.Remove(f.Dir)
}
