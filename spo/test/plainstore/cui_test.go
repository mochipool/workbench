package plainstore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// Every file the store writes is locked at 0400 (upstream file_lock). A file
// is rewritten by writing a temporary file that already has the locked mode
// and renaming it over the old one, so the file is never unlocked (upstream
// file_unlock to 0600, rewrite, lock again): a crash between those steps
// cannot leave a 0600 secret behind (SPO-Cui-INV-004), and a failed rewrite
// leaves the old file as it was.
//
// spec: SPO-Cui-OUT-001, SPO-Cui-OUT-002, SPO-Cui-INV-004
func TestFilesAreLockedAndRewrittenWithoutBeingUnlocked(t *testing.T) {
	s, dir := open(t)
	ref := ports.Ref{Name: "p", Kind: ports.KesCounter}
	path := filepath.Join(dir, "p.kes.counter")
	if err := s.Update(ctx, func(w ports.Writer) error { return w.Put(ref, []byte("000\n")) }); err != nil {
		t.Fatal(err)
	}
	mode := func() os.FileMode {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		return st.Mode().Perm()
	}
	if mode() != 0o400 {
		t.Fatalf("mode %o, want 0400", mode())
	}
	boom := errors.New("boom")
	if err := s.Update(ctx, func(w ports.Writer) error {
		w.Put(ref, []byte("999\n"))
		return boom
	}); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "000\n" || mode() != 0o400 {
		t.Fatalf("a failed rewrite changed the file: %q %o", b, mode())
	}
	if err := s.Update(ctx, func(w ports.Writer) error { return w.Put(ref, []byte("001\n")) }); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "001\n" || mode() != 0o400 {
		t.Fatalf("after the rewrite: %q %o", b, mode())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("temporary files left behind: %v", entries)
	}
}
