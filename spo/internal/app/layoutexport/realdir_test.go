package layoutexport_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/layoutdir"
	"github.com/mochipool/workbench/spo/internal/app/layoutexport"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// realWorld is a world whose directory, lock and pin are the real adapter on a
// temporary directory.
func realWorld(t *testing.T, n int) (*world, *layoutdir.Dir, string) {
	t.Helper()
	w := newWorld(t, "standard", n)
	base := t.TempDir()
	wsDir := filepath.Join(base, "ws")
	if err := os.Mkdir(wsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "layout")
	d, err := layoutdir.Open(root, filepath.Join(wsDir, "workspace.spo"))
	if err != nil {
		t.Fatal(err)
	}
	return w, d, root
}

func (w *world) realInput(d *layoutdir.Dir) layoutexport.Input {
	in := w.input()
	in.Dir = layoutexport.Dir{Writer: d, Reader: d, Lister: d, Locker: d, Pins: d}
	return in
}

func tree(t *testing.T, root string) (files []string) {
	t.Helper()
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			rel, _ := filepath.Rel(root, p)
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	return files
}

// The real directory adapter: files of mode 0600, no temporary file left, an
// unchanged re-export puts nothing new and leaves the pin file alone, and the lock
// file is not mistaken for part of the layout.
//
// spec: SPO-Xlayout-OUT-014, SPO-Xlayout-OUT-015, SPO-Xlayout-OUT-017, SPO-Xlayout-PRE-014
func TestRealDirectoryExportAndReExport(t *testing.T) {
	w, d, root := realWorld(t, 6)
	res, err := layoutexport.Run(context.Background(), w.realInput(d))
	if err != nil || !res.HeadWritten {
		t.Fatalf("%v %+v", err, res)
	}
	files := tree(t, root)
	for _, f := range files {
		if strings.Contains(f, ".tmp-") {
			t.Errorf("leftover %s", f)
		}
		if fi, _ := os.Stat(filepath.Join(root, f)); fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: mode %v", f, fi.Mode().Perm())
		}
	}
	pinInfo, err := os.Stat(d.PinPath())
	if err != nil {
		t.Fatal("no pin file: ", err)
	}
	res2, err := layoutexport.Run(context.Background(), w.realInput(d))
	if err != nil || !res2.UpToDate || res2.ObjectsWritten != 0 {
		t.Fatalf("%v %+v", err, res2)
	}
	pin2, _ := os.Stat(d.PinPath())
	if !os.SameFile(pinInfo, pin2) || !pinInfo.ModTime().Equal(pin2.ModTime()) {
		t.Error("the pin file was rewritten for the same head")
	}
	if len(tree(t, root)) != len(files) {
		t.Error("the second run changed the directory")
	}
	// a layout is recognised again after the lock file appeared
	w.change(2)
	if r, err := layoutexport.Run(context.Background(), w.realInput(d)); err != nil || r.HeadSequence != 2 {
		t.Fatalf("%v %+v", err, r)
	}
	// a second exporter on the same directory is refused while the first runs
	w3, d3, _ := realWorld(t, 3)
	d3b, _ := layoutdir.Open(filepath.Join(t.TempDir(), "x"), filepath.Join(t.TempDir(), "workspace.spo"))
	_ = d3b
	var second error
	in := w3.realInput(d3)
	inner := in.Unlock
	in.Unlock = func(ctx context.Context) (layoutexport.Material, error) {
		// while this exporter holds the directory, a second one asks for it
		in2 := w3.realInput(d3)
		_, second = layoutexport.Run(ctx, in2)
		return inner(ctx)
	}
	if _, err := layoutexport.Run(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(second, ports.ErrLayoutLocked) {
		t.Fatalf("the second exporter: %v", second)
	}
}

// The directory is moved away and a link to another directory put in its place
// while the export runs: the run stops, nothing is put through the link, and the
// directory that was written to still satisfies its newest head (none).
//
// spec: SPO-Xlayout-INV-012, SPO-Xlayout-PRE-014
func TestTheDirectoryReplacedByALinkMidRun(t *testing.T) {
	w, d, root := realWorld(t, 70) // more than 64 puts, so the periodic check runs too
	other := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.Mkdir(other, 0o700); err != nil {
		t.Fatal(err)
	}
	moved := root + ".moved"
	in := w.realInput(d)
	n := 0
	inner := in.Unlock
	in.Unlock = func(ctx context.Context) (layoutexport.Material, error) { return inner(ctx) }
	in.Dir.Writer = swapAfter{ObjectWriter: d, after: 5, do: func() {
		os.Rename(root, moved)
		os.Symlink(other, root)
	}, n: &n}
	_, err := layoutexport.Run(context.Background(), in)
	// the put that follows the swap is stopped by the check, or the read back of the
	// one that raced with it fails: either way the run ends
	if !errors.Is(err, ports.ErrLayoutMoved) && (err == nil || !strings.Contains(err.Error(), "read back failed")) {
		t.Fatalf("%v", err)
	}
	// nothing went to the directory the link points at, except possibly what the
	// adapter wrote before the next check; no head, ever
	for _, f := range tree(t, other) {
		if strings.HasPrefix(f, "heads/") {
			t.Errorf("a head was put through the link: %s", f)
		}
	}
	for _, f := range tree(t, moved) {
		if strings.HasPrefix(f, "heads/") {
			t.Errorf("a head was put: %s", f)
		}
	}
}

type swapAfter struct {
	ports.ObjectWriter
	after int
	do    func()
	n     *int
}

func (s swapAfter) Put(ctx context.Context, name string, r io.Reader, size int64) error {
	err := s.ObjectWriter.Put(ctx, name, r, size)
	*s.n++
	if *s.n == s.after {
		s.do()
	}
	return err
}

// A FIFO put where an object belongs, after the directory was opened, neither hangs
// the export nor is believed; the one that is there before the directory is opened
// is refused by Open.
//
// spec: SPO-Xlayout-PRE-018
func TestAFifoUnderAnObjectNameDoesNotHangTheExport(t *testing.T) {
	w, d, root := realWorld(t, 4)
	if _, err := layoutexport.Run(context.Background(), w.realInput(d)); err != nil {
		t.Fatal(err)
	}
	var victim string
	filepath.Walk(filepath.Join(root, "objects"), func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && victim == "" {
			victim = p
		}
		return nil
	})
	os.Remove(victim)
	if err := syscall.Mkfifo(victim, 0o600); err != nil {
		t.Skip(err)
	}
	// opened afterwards: the scan at Open refuses it
	if _, err := layoutdir.Open(root, filepath.Join(filepath.Dir(root), "ws", "workspace.spo")); err == nil || !strings.Contains(err.Error(), filepath.Base(victim)) {
		t.Errorf("Open: %v", err)
	}
	// the directory was opened before it appeared: the run ends, at once
	done := make(chan error, 1)
	var res layoutexport.Result
	go func() {
		var err error
		res, err = layoutexport.Run(context.Background(), w.realInput(d))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("a FIFO was accepted: %+v", res)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the export did not return within 10 seconds")
	}
}
