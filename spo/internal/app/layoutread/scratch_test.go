package layoutread_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/scratchdir"
	"github.com/mochipool/workbench/spo/internal/app/layoutread"
	"github.com/mochipool/workbench/spo/internal/ports"
)

type fileWriter struct {
	err   error
	paths []string
}

func (f *fileWriter) WriteSnapshotFile(_ context.Context, path string, snap ports.Snapshot) error {
	f.paths = append(f.paths, path)
	if f.err != nil {
		return f.err
	}
	return os.WriteFile(path, []byte("a verified store file with "+string(snap.Meta.WorkspaceID)), 0o600)
}

// spec: SPO-Xlayout-OUT-022
func TestTheScratchFileIsBuiltHashedAndRemoved(t *testing.T) {
	root := t.TempDir()
	sc, err := scratchdir.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	w := &fileWriter{}
	snap := ports.Snapshot{Meta: ports.SnapshotMeta{WorkspaceID: []byte("ws-id-16-bytes!!")}}
	f, err := layoutread.BuildScratch(context.Background(), sc, w, snap)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.paths) != 1 || w.paths[0] != f.Path || filepath.Dir(f.Path) == root {
		t.Fatalf("the writer was given %v for %s in %s", w.paths, f.Path, root)
	}
	b, err := os.ReadFile(f.Path)
	if err != nil {
		t.Fatal(err)
	}
	if h := sha256.Sum256(b); !bytes.Equal(h[:], f.SHA256) {
		t.Fatal("the hash is not the hash of the file")
	}
	st, _ := os.Stat(filepath.Dir(f.Path))
	if st.Mode().Perm() != 0o700 {
		t.Errorf("scratch directory mode %v", st.Mode().Perm())
	}
	if err := f.Remove(sc); err != nil {
		t.Fatal(err)
	}
	if ents, _ := os.ReadDir(root); len(ents) != 0 {
		t.Fatalf("scratch space left behind: %v", ents)
	}
	// a failed write leaves nothing
	w.err = errors.New("the store refused it")
	if _, err := layoutread.BuildScratch(context.Background(), sc, w, snap); err == nil || !errors.Is(err, w.err) {
		t.Fatalf("%v", err)
	}
	if ents, _ := os.ReadDir(root); len(ents) != 0 {
		t.Fatalf("scratch space left behind after a failure: %v", ents)
	}
}
