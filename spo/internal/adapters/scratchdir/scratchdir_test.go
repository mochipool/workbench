package scratchdir

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/mochipool/workbench/spo/internal/ports"
)

func newScratch(t *testing.T) (*Dir, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "ws")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	d, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	return d, root
}

// spec: SPO-Xbackup-SEC-008
func TestOpenCreatesPrivateFilesAndDirectories(t *testing.T) {
	d, root := newScratch(t)
	dir, err := d.MakeDir(".spo-backup-")
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(filepath.Join(root, dir)); st.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %o", st.Mode().Perm())
	}
	f, err := d.Open(dir + "/backup.spo")
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("x"))
	f.Close()
	if st, _ := os.Stat(d.Path(dir + "/backup.spo")); st.Mode().Perm() != 0o600 {
		t.Errorf("file mode %o", st.Mode().Perm())
	}
	for _, bad := range []string{"../x", "/x", "a/b/c", "", ".", "a/..", ".x\n"} {
		if _, err := d.Open(bad); err == nil {
			t.Errorf("name %q accepted", bad)
		}
	}
}

// A planted symbolic link at the name is unlinked, never followed and never
// written through, and a fresh file is made.
//
// spec: SPO-Xbackup-SEC-008
func TestOpenReplacesASymlinkWithoutTouchingItsTarget(t *testing.T) {
	d, root := newScratch(t)
	target := filepath.Join(t.TempDir(), "victim")
	os.WriteFile(target, []byte("precious"), 0o600)
	os.Symlink(target, filepath.Join(root, ".spo-fetch-x.partial"))
	f, err := d.Open(".spo-fetch-x.partial")
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("sealed bytes"))
	f.Close()
	if b, _ := os.ReadFile(target); string(b) != "precious" {
		t.Fatalf("the target was written through the link: %q", b)
	}
	st, _ := os.Lstat(filepath.Join(root, ".spo-fetch-x.partial"))
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		t.Fatal("the link is still there")
	}
}

// spec: SPO-Xbackup-SEC-008
func TestOpenRefusesAHardLinkedOrNonRegularFile(t *testing.T) {
	d, root := newScratch(t)
	other := filepath.Join(t.TempDir(), "other")
	os.WriteFile(other, []byte("x"), 0o600)
	if err := os.Link(other, filepath.Join(root, "linked")); err != nil {
		t.Skip("hard links not available:", err)
	}
	if _, err := d.Open("linked"); !errors.Is(err, ports.ErrScratchUnsafe) {
		t.Errorf("a file with two links: %v", err)
	}
	os.Mkdir(filepath.Join(root, "adir"), 0o700)
	if _, err := d.Open("adir"); err == nil {
		t.Error("a directory opened as a file")
	}
	if err := syscall.Mkfifo(filepath.Join(root, "fifo"), 0o600); err == nil {
		if _, err := d.Open("fifo"); err == nil {
			t.Error("a fifo opened")
		}
	}
}

// spec: SPO-Xbackup-SEC-012
func TestOpenRefusesALooseWorkspaceDirectory(t *testing.T) {
	for _, mode := range []os.FileMode{0o770, 0o707, 0o777} {
		root := filepath.Join(t.TempDir(), "loose")
		os.Mkdir(root, 0o700)
		os.Chmod(root, mode)
		if _, err := Open(root); err == nil {
			t.Errorf("a directory with mode %o was accepted", mode)
		}
	}
	root := filepath.Join(t.TempDir(), "ok")
	os.Mkdir(root, 0o755)
	if _, err := Open(root); err != nil {
		t.Errorf("0755: %v", err)
	}
}

func TestEntriesRemoveAndSymlinkParent(t *testing.T) {
	d, root := newScratch(t)
	dir, _ := d.MakeDir(".spo-backup-")
	os.WriteFile(filepath.Join(root, "f"), []byte("x"), 0o600)
	os.Symlink("/nonexistent", filepath.Join(root, "l"))
	got := map[string]ports.ScratchKind{}
	owned := map[string]bool{}
	ents, err := d.Entries()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		got[e.Name], owned[e.Name] = e.Kind, e.Owned
	}
	if got[dir] != ports.ScratchDirectory || got["f"] != ports.ScratchRegular || got["l"] != ports.ScratchSymlink || !owned["f"] {
		t.Fatalf("%v %v", got, owned)
	}
	// a directory named like a scratch directory but really a symlink to elsewhere
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "keep"), []byte("x"), 0o600)
	os.Symlink(outside, filepath.Join(root, "linkdir"))
	if _, err := d.Open("linkdir/keep"); err == nil {
		t.Error("a path through a symlinked directory was opened")
	}
	if err := d.Remove("linkdir"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outside, "keep")); err != nil {
		t.Fatal("Remove followed the link")
	}
	if err := d.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, dir)); err == nil {
		t.Fatal("directory not removed")
	}
}

// G2: an existing own file with a loose mode is made private.
//
// spec: SPO-Xbackup-SEC-008
func TestOpenTightensTheModeOfAnExistingFile(t *testing.T) {
	d, root := newScratch(t)
	p := filepath.Join(root, "loose")
	os.WriteFile(p, []byte("x"), 0o644)
	os.Chmod(p, 0o644)
	f, err := d.Open("loose")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
}

// G2: the directory must be owned by the user running the process.
//
// spec: SPO-Xbackup-SEC-012
func TestDirectoryOwnerIsChecked(t *testing.T) {
	st, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !ownedBy(st, os.Geteuid()) {
		t.Fatal("the user's own directory is not owned by the user")
	}
	if ownedBy(st, os.Geteuid()+1) {
		t.Fatal("a directory owned by another user was accepted")
	}
}

// Remove never goes through a link: a name below a symbolic link removes
// nothing.
func TestRemoveBelowASymlinkRemovesNothing(t *testing.T) {
	d, root := newScratch(t)
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "keep"), []byte("x"), 0o600)
	os.Symlink(outside, filepath.Join(root, "linkdir"))
	if err := d.Remove("linkdir/keep"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outside, "keep")); err != nil {
		t.Fatal("removed through the link")
	}
	if _, err := os.Lstat(filepath.Join(root, "linkdir")); err != nil {
		t.Fatal("the link itself was removed; the comment and the code must agree on nothing being removed")
	}
}
