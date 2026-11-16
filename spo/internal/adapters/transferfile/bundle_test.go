package transferfile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/transfer"
)

var bg = context.Background()

func tmpFile(t *testing.T, content string, mode os.FileMode) *File {
	t.Helper()
	p := filepath.Join(t.TempDir(), "offlineTransfer.json")
	if content != "\x00missing" {
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	return &File{Path: p}
}

func entries(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

// spec: SPO-01workOffline-IN-001, SPO-01workOffline-PRE-003, SPO-Coffline-IN-001
func TestReadBundle(t *testing.T) {
	if b, found, err := tmpFile(t, "\x00missing", 0o600).ReadBundle(bg); err != nil || found || !b.IsEmpty() {
		t.Errorf("missing: %v %v", found, err)
	}
	if _, found, err := tmpFile(t, " \n", 0o600).ReadBundle(bg); err != nil || found {
		t.Errorf("blank: %v %v", found, err)
	}
	if _, _, err := tmpFile(t, "{oops", 0o600).ReadBundle(bg); !errors.Is(err, transfer.ErrNotJSON) {
		t.Errorf("invalid: %v", err)
	}
	if b, found, err := tmpFile(t, snapshot, 0o600).ReadBundle(bg); err != nil || !found || b.Usable() != nil {
		t.Errorf("snapshot: %v %v", found, err)
	}
}

// spec: SPO-Ptransfer-INV-002, SPO-Ptransfer-OUT-012
func TestMutateBundleIsAtomic(t *testing.T) {
	f := tmpFile(t, snapshot, 0o640)
	dir := filepath.Dir(f.Path)
	boom := errors.New("boom")

	// An error from the change leaves the file as it was, with no temporary file.
	if err := f.MutateBundle(bg, func(b *transfer.Bundle) error { b.ClearHistory("d"); return boom }); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(f.Path)
	if string(got) != snapshot {
		t.Error("a failed mutation changed the file")
	}
	if n := entries(t, dir); len(n) != 1 {
		t.Errorf("leftovers: %v", n)
	}

	// A change is written whole, keeps the mode and leaves nothing behind.
	if err := f.MutateBundle(bg, func(b *transfer.Bundle) error { return b.ClearFiles("Mon, 16 Nov 2026 10:00:00 +0100") }); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(f.Path)
	if st.Mode().Perm() != 0o640 {
		t.Errorf("mode %v", st.Mode().Perm())
	}
	got, _ = os.ReadFile(f.Path)
	if strings.Contains(string(got), `"files"`) || !strings.Contains(string(got), "attached files cleared") {
		t.Errorf("not cleared:\n%s", got)
	}
	if n := entries(t, dir); len(n) != 1 {
		t.Errorf("leftovers: %v", n)
	}

	// A file that is not JSON is never overwritten by a mutation (the operator
	// deletes it by hand).
	bad := tmpFile(t, "{oops", 0o600)
	if err := bad.MutateBundle(bg, func(*transfer.Bundle) error { return nil }); !errors.Is(err, transfer.ErrNotJSON) {
		t.Errorf("invalid: %v", err)
	}
	if got, _ := os.ReadFile(bad.Path); string(got) != "{oops" {
		t.Error("the invalid file was replaced")
	}

	// A missing file is created from the empty bundle.
	missing := tmpFile(t, "\x00missing", 0o600)
	if err := missing.MutateBundle(bg, func(b *transfer.Bundle) error { return b.ClearHistory("d") }); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(missing.Path); !strings.Contains(string(got), "history cleared") {
		t.Errorf("created: %s", got)
	}
}

// A second writer between the read and the write is detected, not overwritten.
//
// spec: SPO-Ptransfer-INV-002
func TestMutateBundleDetectsAConcurrentWriter(t *testing.T) {
	f := tmpFile(t, snapshot, 0o600)
	err := f.MutateBundle(bg, func(b *transfer.Bundle) error {
		if err := os.WriteFile(f.Path, []byte(`{"other":1}`), 0o600); err != nil {
			t.Fatal(err)
		}
		return b.ClearFiles("d")
	})
	if !errors.Is(err, ErrChangedDuringWrite) {
		t.Fatalf("%v", err)
	}
	if got, _ := os.ReadFile(f.Path); string(got) != `{"other":1}` {
		t.Errorf("the other writer's file was replaced: %s", got)
	}
}

// Whatever the bundle's own writer does not touch survives a rewrite byte for byte.
//
// spec: SPO-Ptransfer-INV-002
func TestMutateBundleKeepsWhatItDoesNotTouch(t *testing.T) {
	f := tmpFile(t, snapshot, 0o600)
	if err := f.MutateBundle(bg, func(b *transfer.Bundle) error { return nil }); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(f.Path)
	a, _ := transfer.Parse([]byte(snapshot))
	want, _ := a.Marshal()
	if string(got) != string(want) {
		t.Errorf("a no-op rewrite changed the document:\n%s", got)
	}
	if _, err := f.Utxos(bg, addr); err != nil {
		t.Errorf("the rewritten file is not readable as a snapshot: %v", err)
	}
}

// spec: SPO-Ptransfer-SEC-001, SPO-01workOffline-SEC-001, SPO-01workOffline-SEC-004
func TestDirSinkNeverLeavesItsDirectory(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "out")
	s := DirSink{Dir: dir}

	for _, bad := range []string{"../escape", "/etc/passwd", "a/b", "..", ".", "", "x/../../y", `a\b`} {
		if _, err := s.WriteFile(bg, bad, []byte("x"), true); !errors.Is(err, transfer.ErrUnsafeName) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if es, _ := os.ReadDir(root); len(es) > 1 {
		t.Errorf("something was written outside: %v", es)
	}

	// A plain name is written, with the default mode, atomically.
	if ok, err := s.WriteFile(bg, "./a.txt", []byte("one"), false); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if n := entries(t, dir); len(n) != 1 || n[0] != "a.txt" {
		t.Errorf("entries: %v", n)
	}
	// An existing file is kept unless overwriting is asked for.
	if ok, err := s.WriteFile(bg, "a.txt", []byte("two"), false); err != nil || ok {
		t.Errorf("overwrite without the option: %v %v", ok, err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "a.txt")); string(got) != "one" {
		t.Errorf("content %q", got)
	}
	if ok, err := s.WriteFile(bg, "a.txt", []byte("two"), true); err != nil || !ok {
		t.Errorf("overwrite: %v %v", ok, err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "a.txt")); string(got) != "two" {
		t.Errorf("content %q", got)
	}
	if n := entries(t, dir); len(n) != 1 {
		t.Errorf("temporary files left: %v", n)
	}

	// A symbolic link in the way is never written through, with or without the option.
	outside := filepath.Join(root, "outside.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link.txt")); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.WriteFile(bg, "link.txt", []byte("pwn"), false); err != nil || ok {
		t.Errorf("symlink, no overwrite: %v %v", ok, err)
	}
	if _, err := s.WriteFile(bg, "link.txt", []byte("pwn"), true); err == nil {
		t.Error("a symlink was replaced")
	}
	if got, _ := os.ReadFile(outside); string(got) != "secret" {
		t.Errorf("the file outside was written: %q", got)
	}
}

// A file that is not what was written, read back, is an error and not upstream's exit 0.
//
// spec: SPO-01workOffline-OUT-012, SPO-Ptransfer-OUT-009
func TestMutateBundleReadBackMismatchIsAnError(t *testing.T) {
	f := tmpFile(t, snapshot, 0o600)
	f.afterWrite = func() { _ = os.WriteFile(f.Path, []byte(`{"truncated":`), 0o600) }
	err := f.MutateBundle(bg, func(b *transfer.Bundle) error { return b.ClearFiles("d") })
	if !errors.Is(err, ErrReadBack) {
		t.Errorf("%v", err)
	}
}
