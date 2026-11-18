package layoutdir

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/ports"
)

func setup(t *testing.T) (ws, root string) {
	t.Helper()
	base := t.TempDir()
	ws = filepath.Join(base, "workspace")
	if err := os.Mkdir(ws, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(ws, "workspace.spo"), filepath.Join(base, "layout")
}

// spec: SPO-Xlayout-PRE-013
func TestOpenRefusesTheWorkspaceDirectoryAndWhatIsInsideIt(t *testing.T) {
	wsFile, root := setup(t)
	wsDir := filepath.Dir(wsFile)
	for name, dir := range map[string]string{
		"the workspace directory":   wsDir,
		"inside it":                 filepath.Join(wsDir, "layout"),
		"deeper inside it":          filepath.Join(wsDir, "a", "b"),
		"a directory that holds it": filepath.Dir(wsDir),
	} {
		if _, err := Open(dir, wsFile); !errors.Is(err, ErrInsideWorkspace) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// a link into the workspace directory is the workspace directory
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(wsDir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link, wsFile); !errors.Is(err, ErrInsideWorkspace) {
		t.Errorf("a link to the workspace directory: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(wsDir, "layout")); err == nil {
		t.Error("a refused directory was created")
	}
	if _, err := Open("relative/dir", wsFile); err == nil {
		t.Error("a relative path")
	}
	d, err := Open(root, wsFile)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(root); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("the directory was not made with mode 0700: %v %v", fi, err)
	}
	_ = d
}

// spec: SPO-Xlayout-PRE-013
func TestOpenRefusesALooseDirectory(t *testing.T) {
	wsFile, root := setup(t)
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root, wsFile); err == nil || !strings.Contains(err.Error(), "writable by its group or by everyone") {
		t.Fatalf("%v", err)
	}
	if err := os.Chmod(root, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root, wsFile); err == nil {
		t.Fatal("a group-writable directory was accepted")
	}
}

// spec: SPO-Xlayout-PRE-014
func TestTheLockRefusesASecondExporterAndNoticesAReplacedDirectory(t *testing.T) {
	wsFile, root := setup(t)
	d, err := Open(root, wsFile)
	if err != nil {
		t.Fatal(err)
	}
	l1, err := d.Lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	d2, _ := Open(root, wsFile)
	if _, err := d2.Lock(context.Background()); !errors.Is(err, ports.ErrLayoutLocked) {
		t.Fatalf("a second lock: %v", err)
	}
	if err := l1.Check(); err != nil {
		t.Fatal(err)
	}
	if err := l1.Release(); err != nil {
		t.Fatal(err)
	}
	l3, err := d2.Lock(context.Background())
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	// the directory is moved away and a link to another directory put in its place
	other := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.Mkdir(other, 0o700); err != nil {
		t.Fatal(err)
	}
	moved := root + ".moved"
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, root); err != nil {
		t.Fatal(err)
	}
	if err := l3.Check(); !errors.Is(err, ports.ErrLayoutMoved) {
		t.Fatalf("a directory replaced by a link: %v", err)
	}
	l3.Release()
	// a directory replaced by another directory
	os.Remove(root)
	os.Rename(moved, root)
	l4, err := d.Lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	os.Rename(root, root+".old")
	os.Mkdir(root, 0o700)
	if err := l4.Check(); !errors.Is(err, ports.ErrLayoutMoved) {
		t.Fatalf("a directory replaced by another: %v", err)
	}
	l4.Release()
}

// spec: SPO-Xlayout-OUT-017, SPO-Xlayout-PRE-017
func TestThePinAdvancesOnlyIsAtomicAndAReplacedFileIsReported(t *testing.T) {
	wsFile, root := setup(t)
	d, err := Open(root, wsFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(d.PinPath(), filepath.Dir(wsFile)) || strings.HasPrefix(d.PinPath(), root) {
		t.Fatalf("the pin is not beside the workspace file: %s", d.PinPath())
	}
	if _, found, err := d.Load(); found || err != nil {
		t.Fatalf("%v %v", found, err)
	}
	h := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
	if err := d.Advance(ports.LayoutPin{Sequence: 1, HeadHash: h(1)}); err != nil {
		t.Fatal(err)
	}
	fi1, _ := os.Stat(d.PinPath())
	if fi1.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi1.Mode())
	}
	time.Sleep(20 * time.Millisecond)
	// the same pin again does not rewrite the file
	if err := d.Advance(ports.LayoutPin{Sequence: 1, HeadHash: h(1)}); err != nil {
		t.Fatal(err)
	}
	fi2, _ := os.Stat(d.PinPath())
	if !os.SameFile(fi1, fi2) || !fi1.ModTime().Equal(fi2.ModTime()) {
		t.Error("an unchanged pin was rewritten")
	}
	// forward only
	for name, p := range map[string]ports.LayoutPin{"the same sequence, another hash": {Sequence: 1, HeadHash: h(2)}, "an older one": {Sequence: 0, HeadHash: h(1)}} {
		if err := d.Advance(p); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if err := d.Advance(ports.LayoutPin{Sequence: 3, HeadHash: h(3)}); err != nil {
		t.Fatal(err)
	}
	if err := d.Advance(ports.LayoutPin{Sequence: 2, HeadHash: h(2)}); !errors.Is(err, ports.ErrLayoutPinBackwards) {
		t.Fatalf("backwards: %v", err)
	}
	got, found, err := d.Load()
	if err != nil || !found || got.Sequence != 3 || !bytes.Equal(got.HeadHash, h(3)) {
		t.Fatalf("%+v %v %v", got, found, err)
	}
	// no temporary file is left
	ents, _ := os.ReadDir(filepath.Dir(wsFile))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".spo-pin-") {
			t.Errorf("leftover %s", e.Name())
		}
	}
	// a damaged file is reported and never replaced
	for _, bad := range []string{"", "garbage\n", "spo-layout-pin 1 7 zz\n", "spo-layout-pin 1 0 " + strings.Repeat("a", 64) + "\n", "spo-layout-pin 1 3 " + strings.Repeat("A", 64) + "\n", "spo-layout-pin 1 3 " + strings.Repeat("a", 64)} {
		if err := os.WriteFile(d.PinPath(), []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := d.Load(); !errors.Is(err, ports.ErrLayoutPinCorrupt) {
			t.Errorf("%q: %v", bad, err)
		}
		if err := d.Advance(ports.LayoutPin{Sequence: 9, HeadHash: h(9)}); !errors.Is(err, ports.ErrLayoutPinCorrupt) {
			t.Errorf("%q: an advance over a corrupt file: %v", bad, err)
		}
		if b, _ := os.ReadFile(d.PinPath()); string(b) != bad {
			t.Errorf("%q: the corrupt file was replaced", bad)
		}
	}
	// a link in place of the file is reported too
	os.Remove(d.PinPath())
	os.Symlink("/etc/passwd", d.PinPath())
	if _, _, err := d.Load(); !errors.Is(err, ports.ErrLayoutPinCorrupt) {
		t.Errorf("a link: %v", err)
	}
	// two directories have two pins
	d2, _ := Open(root+"2", wsFile)
	if d2.PinPath() == d.PinPath() {
		t.Error("two layout directories share a pin file")
	}
}

// spec: SPO-Xlayout-PRE-013
func TestOpenRefusesADirectoryThatIsNotALayoutBeforeMakingAnythingInIt(t *testing.T) {
	wsFile, root := setup(t)
	os.Mkdir(root, 0o700)
	os.WriteFile(filepath.Join(root, "notes.txt"), []byte("x"), 0o600)
	if _, err := Open(root, wsFile); !errors.Is(err, ErrNotALayout) {
		t.Fatalf("%v", err)
	}
	ents, _ := os.ReadDir(root)
	if len(ents) != 1 {
		t.Errorf("something was made in the refused directory: %v", ents)
	}
	// an empty one, and one that holds a layout's two directories and the lock file, are fine
	ok := filepath.Join(filepath.Dir(root), "ok")
	os.Mkdir(ok, 0o700)
	os.Mkdir(filepath.Join(ok, "objects"), 0o700)
	os.Mkdir(filepath.Join(ok, "heads"), 0o700)
	os.WriteFile(filepath.Join(ok, LockName), nil, 0o600)
	if _, err := Open(ok, wsFile); err != nil {
		t.Fatal(err)
	}
}

func within(t *testing.T, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { f(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not return within 5 seconds", what)
	}
}

func plant(t *testing.T, kind, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	switch kind {
	case "fifo":
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Skip(err)
		}
	case "symlink":
		os.WriteFile(path+".target", []byte("x"), 0o600)
		if err := os.Symlink(path+".target", path); err != nil {
			t.Fatal(err)
		}
	case "directory":
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	case "socket":
		l, err := net.Listen("unix", path)
		if err != nil {
			t.Skip(err)
		}
		t.Cleanup(func() { l.Close() })
	}
}

var objName = "ab" + strings.Repeat("0", 62)

// Any entry under objects/ or heads/ that is not a regular file (or, in objects,
// a two-digit directory) is refused, by name, before the lock file is made and so
// before anything is asked, and without waiting on it.
//
// spec: SPO-Xlayout-PRE-018
func TestOpenRefusesAnythingThatIsNotARegularFileUnderTheLayoutDirectories(t *testing.T) {
	for _, kind := range []string{"fifo", "symlink", "directory", "socket"} {
		for where, rel := range map[string]string{
			"an object":        "objects/ab/" + objName,
			"a head":           "heads/00000000000000000001",
			"a head signature": "heads/00000000000000000001.sig",
		} {
			t.Run(kind+" as "+where, func(t *testing.T) {
				wsFile, root := setup(t)
				plant(t, kind, filepath.Join(root, filepath.FromSlash(rel)))
				within(t, "Open", func() {
					_, err := Open(root, wsFile)
					if err == nil || !strings.Contains(err.Error(), filepath.Base(rel)) {
						t.Errorf("%v", err)
					}
				})
				if _, err := os.Lstat(filepath.Join(root, LockName)); err == nil {
					t.Error("the lock file was made in a refused directory")
				}
			})
		}
	}
	// names that are not a layout's
	for name, rel := range map[string]string{
		"a three-digit object directory": "objects/abc/" + objName,
		"an object with a short name":    "objects/ab/short",
		"a file in objects":              "objects/stray",
		"a deep tree":                    "objects/ab/cd/ef/gh",
		"a head with a wrong name":       "heads/one",
	} {
		wsFile, root := setup(t)
		p := filepath.Join(root, filepath.FromSlash(rel))
		os.MkdirAll(filepath.Dir(p), 0o700)
		os.WriteFile(p, []byte("x"), 0o600)
		if _, err := Open(root, wsFile); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The scan stops at a cap on entries, before it has looked at the rest.
//
// spec: SPO-Xlayout-PRE-018
func TestOpenCapsTheScan(t *testing.T) {
	wsFile, root := setup(t)
	os.MkdirAll(filepath.Join(root, "heads"), 0o700)
	for i := 1; i <= 12; i++ {
		os.WriteFile(filepath.Join(root, "heads", fmt.Sprintf("%020d", i)), []byte("x"), 0o600)
	}
	saved := MaxEntries
	MaxEntries = 10
	defer func() { MaxEntries = saved }()
	if _, err := Open(root, wsFile); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("%v", err)
	}
	MaxEntries = 13
	if _, err := Open(root, wsFile); err != nil {
		t.Fatal(err)
	}
}

// The directory is opened once; replacing it afterwards, by a link or by another
// directory, cannot redirect a read, a write or a listing.
//
// spec: SPO-Xlayout-PRE-014
func TestReplacingTheDirectoryAfterOpenCannotRedirectAnything(t *testing.T) {
	wsFile, root := setup(t)
	d, err := Open(root, wsFile)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	put := func(name, data string) error {
		return d.Put(ctx, name, strings.NewReader(data), int64(len(data)))
	}
	if err := put("objects/ab/"+objName, "first"); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "elsewhere")
	os.MkdirAll(filepath.Join(other, "objects", "ab"), 0o700)
	os.WriteFile(filepath.Join(other, "objects", "ab", objName), []byte("planted"), 0o600)
	moved := root + ".moved"
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, root); err != nil {
		t.Fatal(err)
	}
	// a read still reads the directory that was opened
	rc, err := d.Get(ctx, "objects/ab/"+objName)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(rc)
	rc.Close()
	if string(b) != "first" {
		t.Errorf("a read through the replaced directory gave %q", b)
	}
	// a write lands in the directory that was opened, and nothing in the link's target
	if err := put("heads/00000000000000000001", "head"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(moved, "heads", "00000000000000000001")); err != nil {
		t.Errorf("the write did not land in the opened directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(other, "heads")); err == nil {
		t.Error("something was written through the link")
	}
	list, err := d.List(ctx, "")
	if err != nil || len(list) != 2 {
		t.Fatalf("%v %v", list, err)
	}
	for _, e := range list {
		if strings.Contains(e.Name, "planted") {
			t.Error("the listing shows the link's target")
		}
	}
	// the lock check still says so
	l, err := d.Lock(ctx)
	if err == nil {
		l.Release()
		t.Error("a lock was taken on a replaced directory")
	}
}

// A FIFO where the pin file should be does not hang the load.
//
// spec: SPO-Xlayout-PRE-017
func TestAFifoInPlaceOfThePinFileDoesNotHangTheLoad(t *testing.T) {
	wsFile, root := setup(t)
	d, err := Open(root, wsFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(d.PinPath(), 0o600); err != nil {
		t.Skip(err)
	}
	within(t, "Load", func() {
		if _, _, err := d.Load(); !errors.Is(err, ports.ErrLayoutPinCorrupt) {
			t.Errorf("%v", err)
		}
	})
	within(t, "Advance", func() {
		if err := d.Advance(ports.LayoutPin{Sequence: 1, HeadHash: bytes.Repeat([]byte{1}, 32)}); err == nil {
			t.Error("an advance over a FIFO")
		}
	})
}
