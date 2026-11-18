package layoutdir

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/ports"
)

func openLayout(t *testing.T) (*Dir, string, string) {
	t.Helper()
	wsFile, root := setup(t)
	d, err := Open(root, wsFile)
	if err != nil {
		t.Fatal(err)
	}
	return d, root, wsFile
}

func putS(d *Dir, name, data string) error {
	return d.Put(context.Background(), name, strings.NewReader(data), int64(len(data)))
}

// S3: a directory above the cap is read in chunks and abandoned at the cap, not read whole.
//
// spec: SPO-Xlayout-PRE-018
func TestTheScanReadsInChunksAndStopsAtTheCap(t *testing.T) {
	wsFile, root := setup(t)
	os.MkdirAll(filepath.Join(root, "heads"), 0o700)
	for i := 1; i <= 3000; i++ {
		os.WriteFile(filepath.Join(root, "heads", fmt.Sprintf("%020d", i)), nil, 0o600)
	}
	savedCap, savedHook := MaxEntries, readChunkHook
	defer func() { MaxEntries, readChunkHook = savedCap, savedHook }()
	MaxEntries = 100
	read, biggest := 0, 0
	readChunkHook = func(n int) {
		read += n
		if n > biggest {
			biggest = n
		}
	}
	if _, err := Open(root, wsFile); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("%v", err)
	}
	if read < MaxEntries || read > MaxEntries+readChunk || biggest > readChunk {
		t.Errorf("read %d names (largest read %d) of a directory above the cap of %d", read, biggest, MaxEntries)
	}
}

// S4: a lock file that was unlinked and made again by a second exporter is not
// the first one's lock any more.
//
// spec: SPO-Xlayout-PRE-014
func TestTheLockNoticesItsFileBeingUnlinked(t *testing.T) {
	d, root, wsFile := openLayout(t)
	l1, err := d.Lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer l1.Release()
	if err := os.Remove(filepath.Join(root, LockName)); err != nil {
		t.Fatal(err)
	}
	d2, err := Open(root, wsFile)
	if err != nil {
		t.Fatal(err)
	}
	l2, err := d2.Lock(context.Background())
	if err != nil {
		t.Fatalf("the second exporter: %v", err)
	}
	defer l2.Release()
	if err := l1.Check(); !errors.Is(err, ports.ErrLayoutMoved) {
		t.Fatalf("the first exporter's check passed on an unlinked lock: %v", err)
	}
	if err := l2.Check(); err != nil {
		t.Errorf("the second exporter's own lock: %v", err)
	}
	// the lock file absent altogether
	os.Remove(filepath.Join(root, LockName))
	if err := l2.Check(); !errors.Is(err, ports.ErrLayoutMoved) {
		t.Errorf("an absent lock file: %v", err)
	}
}

// (c) the directory's owner and mode are checked on the descriptor that was opened.
//
// spec: SPO-Xlayout-PRE-013
func TestOpenChecksTheModeOnTheOpenedDescriptor(t *testing.T) {
	wsFile, root := setup(t)
	os.Mkdir(root, 0o700)
	saved := afterRootChecks
	defer func() { afterRootChecks = saved }()
	afterRootChecks = func(p string) { os.Chmod(p, 0o777) } // after the checks by path
	if _, err := Open(root, wsFile); err == nil || !strings.Contains(err.Error(), "writable by its group") {
		t.Fatalf("%v", err)
	}
}

// (d) the tool's own stale temporary files are swept, and nothing else.
//
// spec: SPO-Xlayout-PRE-018
func TestStaleTemporaryFilesOfTheToolAreSwept(t *testing.T) {
	d, root, wsFile := openLayout(t)
	old := time.Now().Add(-2 * time.Hour)
	mk := func(p string, age time.Time, mode os.FileMode) {
		os.MkdirAll(filepath.Dir(p), 0o700)
		os.WriteFile(p, []byte("x"), mode)
		os.Chtimes(p, age, age)
	}
	wsDir := filepath.Dir(wsFile)
	staleObj := filepath.Join(root, "objects", "ab", ".tmp-0123456789abcdef")
	freshObj := filepath.Join(root, "objects", "ab", ".tmp-fedcba9876543210")
	otherObj := filepath.Join(root, "objects", "ab", ".tmp-short")
	stalePin := filepath.Join(wsDir, ".spo-pin-0123456789abcdef")
	freshPin := filepath.Join(wsDir, ".spo-pin-fedcba9876543210")
	otherPin := filepath.Join(wsDir, ".spo-pin-mine")
	mk(staleObj, old, 0o600)
	mk(freshObj, time.Now(), 0o600)
	mk(otherObj, old, 0o600)
	mk(stalePin, old, 0o600)
	mk(freshPin, time.Now(), 0o600)
	mk(otherPin, old, 0o600)
	// a link of the tool's name is never followed or removed as a file
	target := filepath.Join(t.TempDir(), "precious")
	os.WriteFile(target, []byte("keep"), 0o600)
	linkObj := filepath.Join(root, "objects", "ab", ".tmp-aaaaaaaaaaaaaaaa")
	os.Symlink(target, linkObj)
	if err := putS(d, "objects/ab/"+strings.Repeat("ab", 32)[:64], "data"); err != nil {
		t.Fatal(err)
	}
	if err := d.Advance(ports.LayoutPin{Sequence: 1, HeadHash: bytes.Repeat([]byte{1}, 32)}); err != nil {
		t.Fatal(err)
	}
	for p, gone := range map[string]bool{staleObj: true, freshObj: false, otherObj: false, stalePin: true, freshPin: false, otherPin: false} {
		_, err := os.Lstat(p)
		if gone == (err == nil) {
			t.Errorf("%s: removed=%v, want %v", filepath.Base(p), err != nil, gone)
		}
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Error("a link was followed")
	}
	if _, err := os.Lstat(linkObj); err != nil {
		t.Error("a link of the tool's name was removed")
	}
}

// F01, F05: a FIFO swapped in after Open is refused at once and never waited on.
//
// spec: SPO-Xlayout-PRE-018
func TestAFifoSwappedInAfterOpenIsRefusedAtOnce(t *testing.T) {
	d, root, _ := openLayout(t)
	name := "objects/ab/" + strings.Repeat("ab", 32)[:64]
	if err := putS(d, name, "data"); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, filepath.FromSlash(name))
	os.Remove(p)
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skip(err)
	}
	within(t, "Get", func() {
		rc, err := d.Get(context.Background(), name)
		if err == nil {
			rc.Close()
			t.Error("Get opened a FIFO")
		}
	})
	within(t, "Has", func() {
		if ok, err := d.Has(context.Background(), name); err == nil || ok {
			t.Errorf("%v %v", ok, err)
		}
	})
	within(t, "GetRange", func() {
		if rc, err := d.GetRange(context.Background(), name, 0); err == nil {
			rc.Close()
			t.Error("GetRange opened a FIFO")
		}
	})
	within(t, "Put", func() {
		if err := putS(d, name, "data"); err == nil || !errors.Is(err, ports.ErrObjectExists) {
			t.Errorf("%v", err)
		}
	})
}

// F02: a directory component replaced by a link after Open is refused for reads and
// writes, and nothing goes through it.
//
// spec: SPO-Xlayout-PRE-014
func TestADirectoryReplacedByALinkAfterOpenIsRefused(t *testing.T) {
	for _, level := range []string{"objects/ab", "objects"} {
		d, root, _ := openLayout(t)
		name := "objects/ab/" + strings.Repeat("ab", 32)[:64]
		if err := putS(d, name, "data"); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "target")
		os.MkdirAll(filepath.Join(target, "ab"), 0o700)
		os.MkdirAll(filepath.Join(target, "objects", "ab"), 0o700)
		os.WriteFile(filepath.Join(target, "ab", strings.Repeat("ab", 32)[:64]), []byte("data"), 0o600)
		os.WriteFile(filepath.Join(target, "objects", "ab", strings.Repeat("ab", 32)[:64]), []byte("data"), 0o600)
		path := filepath.Join(root, filepath.FromSlash(level))
		os.Rename(path, path+".away")
		dest := target
		if level == "objects/ab" {
			dest = filepath.Join(target, "ab")
		}
		os.Symlink(dest, path)
		if rc, err := d.Get(context.Background(), name); err == nil {
			rc.Close()
			t.Errorf("%s: Get went through the link", level)
		}
		if err := putS(d, "objects/ab/"+strings.Repeat("cd", 32)[:64], "other"); err == nil {
			t.Errorf("%s: Put went through the link", level)
		}
		for _, p := range []string{filepath.Join(dest, strings.Repeat("cd", 32)[:64]), filepath.Join(dest, "ab", strings.Repeat("cd", 32)[:64])} {
			if _, err := os.Lstat(p); err == nil {
				t.Errorf("%s: something was written through the link: %s", level, p)
			}
		}
	}
}

// F03: a Put of other bytes of the same size under an existing name is refused.
//
// spec: SPO-Xlayout-INV-012
func TestPutOfOtherBytesOfTheSameSizeUnderAnExistingNameIsRefused(t *testing.T) {
	d, _, _ := openLayout(t)
	name := "heads/00000000000000000001"
	if err := putS(d, name, "aaaa"); err != nil {
		t.Fatal(err)
	}
	if err := putS(d, name, "aaaa"); err != nil {
		t.Errorf("the same bytes: %v", err)
	}
	if err := putS(d, name, "bbbb"); !errors.Is(err, ports.ErrObjectExists) {
		t.Errorf("other bytes of the same size: %v", err)
	}
	if err := putS(d, name, "bbbbb"); !errors.Is(err, ports.ErrObjectExists) {
		t.Errorf("another size: %v", err)
	}
	rc, _ := d.Get(context.Background(), name)
	b, _ := io.ReadAll(rc)
	rc.Close()
	if string(b) != "aaaa" {
		t.Errorf("the object is %q", b)
	}
}
