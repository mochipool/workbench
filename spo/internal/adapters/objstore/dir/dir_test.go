package dir

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/ports"
)

func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "sink")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	return s, root
}

func put(s *Store, name, data string) error {
	return s.Put(context.Background(), name, strings.NewReader(data), int64(len(data)))
}

// spec: SPO-Xbackup-IF-001, SPO-Xbackup-IF-002
func TestDirPutGetHasList(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	if err := put(s, "backups/ab/1.spo", "one"); err != nil {
		t.Fatal(err)
	}
	if err := put(s, "backups/ab/2.spo", "two!"); err != nil {
		t.Fatal(err)
	}
	if err := put(s, "other/3.spo", "x"); err != nil {
		t.Fatal(err)
	}
	r, err := s.Get(ctx, "backups/ab/1.spo")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r)
	r.Close()
	if string(b) != "one" {
		t.Fatalf("got %q", b)
	}
	if ok, err := s.Has(ctx, "backups/ab/1.spo"); err != nil || !ok {
		t.Fatalf("Has: %v %v", ok, err)
	}
	if ok, _ := s.Has(ctx, "backups/ab/9.spo"); ok {
		t.Fatal("Has of an absent object")
	}
	if _, err := s.Get(ctx, "backups/ab/9.spo"); !errors.Is(err, ports.ErrObjectNotFound) {
		t.Fatalf("Get of absent: %v", err)
	}
	l, err := s.List(ctx, "backups/ab/")
	if err != nil {
		t.Fatal(err)
	}
	if len(l) != 2 || l[0].Name != "backups/ab/1.spo" || l[0].Size != 3 || l[1].Size != 4 {
		t.Fatalf("list: %+v", l)
	}
}

// spec: SPO-Xbackup-IF-001
func TestDirNeverOverwritesAndIdenticalRePutIsANoOp(t *testing.T) {
	s, root := newStore(t)
	if err := put(s, "a/b.spo", "first"); err != nil {
		t.Fatal(err)
	}
	st1, _ := os.Stat(filepath.Join(root, "a/b.spo"))
	if err := put(s, "a/b.spo", "first"); err != nil {
		t.Fatalf("identical re-put: %v", err)
	}
	st2, _ := os.Stat(filepath.Join(root, "a/b.spo"))
	if !os.SameFile(st1, st2) {
		t.Fatal("an identical re-put replaced the file")
	}
	for _, other := range []string{"second", "firsT", "first+"} {
		if err := put(s, "a/b.spo", other); !errors.Is(err, ports.ErrObjectExists) {
			t.Fatalf("different bytes %q: %v", other, err)
		}
	}
	b, _ := os.ReadFile(filepath.Join(root, "a/b.spo"))
	if string(b) != "first" {
		t.Fatalf("the object changed to %q", b)
	}
	// no temporary file is left behind
	ents, _ := os.ReadDir(filepath.Join(root, "a"))
	if len(ents) != 1 {
		t.Fatalf("leftovers: %v", ents)
	}
}

// spec: SPO-Xbackup-SEC-001
func TestDirRefusesPathEscapes(t *testing.T) {
	s, root := newStore(t)
	outside := filepath.Join(filepath.Dir(root), "outside")
	os.Mkdir(outside, 0o700)
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "f"), filepath.Join(root, "filelink")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../x", "a/../../x", "/etc/passwd", "a//b", "./a", "a/.", "", "a\\b", "link/x", "filelink", "a/\x00b"} {
		if err := put(s, name, "x"); err == nil {
			t.Errorf("Put(%q) was accepted", name)
		}
		if _, err := s.Get(context.Background(), name); err == nil {
			t.Errorf("Get(%q) was accepted", name)
		}
	}
	if m, _ := filepath.Glob(filepath.Join(outside, "*")); len(m) != 0 {
		t.Fatalf("something was written outside the sink: %v", m)
	}
}

// spec: SPO-Xbackup-SEC-002
func TestDirPermissions(t *testing.T) {
	s, root := newStore(t)
	if err := put(s, "x/y/z.spo", "data"); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]os.FileMode{"x": 0o700, "x/y": 0o700, "x/y/z.spo": 0o600} {
		st, err := os.Stat(filepath.Join(root, p))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != want {
			t.Errorf("%s has mode %o, want %o", p, st.Mode().Perm(), want)
		}
	}
}

// spec: SPO-Xbackup-SEC-003
func TestDirRefusesALooseSinkDirectory(t *testing.T) {
	for _, mode := range []os.FileMode{0o770, 0o707, 0o777, 0o720} {
		root := filepath.Join(t.TempDir(), "loose")
		os.Mkdir(root, 0o700)
		if err := os.Chmod(root, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(root); err == nil {
			t.Errorf("a sink directory with mode %o was accepted", mode)
		}
	}
	if _, err := Open("relative/dir"); err == nil {
		t.Error("a relative sink path was accepted")
	}
}

func TestDirCreatesAMissingSinkDirectoryPrivately(t *testing.T) {
	root := filepath.Join(t.TempDir(), "new", "sink")
	if _, err := Open(root); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(root)
	if err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("%v %v", st, err)
	}
}

func TestDirSizeMismatchIsRefusedAndLeavesNothing(t *testing.T) {
	s, root := newStore(t)
	if err := s.Put(context.Background(), "a/b", bytes.NewReader([]byte("abcdef")), 3); err == nil {
		t.Fatal("a reader longer than its size was accepted")
	}
	if err := s.Put(context.Background(), "a/c", bytes.NewReader([]byte("ab")), 3); err == nil {
		t.Fatal("a reader shorter than its size was accepted")
	}
	for _, n := range []string{"a/b", "a/c"} {
		if _, err := os.Stat(filepath.Join(root, n)); err == nil {
			t.Errorf("%s exists", n)
		}
	}
	ents, _ := os.ReadDir(filepath.Join(root, "a"))
	if len(ents) != 0 {
		t.Fatalf("leftovers: %v", ents)
	}
}

func TestDirProbe(t *testing.T) {
	s, _ := newStore(t)
	p, err := s.Check(context.Background())
	if err != nil || p.Kind != ports.SinkDir {
		t.Fatalf("%+v %v", p, err)
	}
}

type brokenReader struct {
	data []byte
	err  error
}

func (b *brokenReader) Read(p []byte) (int, error) {
	if len(b.data) == 0 {
		return 0, b.err
	}
	n := copy(p, b.data)
	b.data = b.data[n:]
	return n, nil
}

// A connection (a reader) that breaks mid-body leaves no object and no
// temporary file.
//
// spec: SPO-Xbackup-INV-001
func TestDirBrokenBodyLeavesNothing(t *testing.T) {
	s, root := newStore(t)
	err := s.Put(context.Background(), "a/b.spo", &brokenReader{data: []byte("half"), err: errors.New("connection reset")}, 100)
	if err == nil {
		t.Fatal("accepted")
	}
	if _, err := os.Stat(filepath.Join(root, "a/b.spo")); err == nil {
		t.Fatal("a partial object exists")
	}
	ents, _ := os.ReadDir(filepath.Join(root, "a"))
	if len(ents) != 0 {
		t.Fatalf("leftovers: %v", ents)
	}
	// and a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Put(ctx, "a/c.spo", strings.NewReader("x"), 1); err == nil {
		t.Fatal("put with a cancelled context")
	}
	ents, _ = os.ReadDir(filepath.Join(root, "a"))
	if len(ents) != 0 {
		t.Fatalf("leftovers: %v", ents)
	}
}

// A previous crashed run's own temporary files, older than an hour, are removed
// at the start of Put; nothing else is touched.
//
// spec: SPO-Xbackup-SEC-007
func TestDirRemovesStaleTemporaryFilesOfItsOwnPatternOnly(t *testing.T) {
	s, root := newStore(t)
	d := filepath.Join(root, "a")
	os.Mkdir(d, 0o700)
	old := time.Now().Add(-2 * time.Hour)
	mk := func(name string, age time.Time) string {
		p := filepath.Join(d, name)
		os.WriteFile(p, []byte("x"), 0o600)
		os.Chtimes(p, age, age)
		return p
	}
	stale := mk(".tmp-0123456789abcdef", old)
	fresh := mk(".tmp-fedcba9876543210", time.Now().Add(-5*time.Minute))
	otherName := mk(".tmp-notours", old)
	user := mk("keep.spo", old)
	if err := put(s, "a/new.spo", "data"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); err == nil {
		t.Error("a stale temporary file was kept")
	}
	for _, p := range []string{fresh, otherName, user} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s was removed", p)
		}
	}
}

// spec: SPO-Xbackup-IF-004
func TestDirGetRange(t *testing.T) {
	s, _ := newStore(t)
	put(s, "a/b", "0123456789")
	r, err := s.GetRange(context.Background(), "a/b", 4)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r)
	r.Close()
	if string(b) != "456789" {
		t.Fatalf("%q", b)
	}
	if _, err := s.GetRange(context.Background(), "a/b", 10); !errors.Is(err, ports.ErrRangeNotSatisfiable) {
		t.Fatalf("%v", err)
	}
	if _, err := s.GetRange(context.Background(), "a/zz", 1); !errors.Is(err, ports.ErrObjectNotFound) {
		t.Fatalf("%v", err)
	}
	if _, err := s.GetRange(context.Background(), "../a", 1); err == nil {
		t.Fatal("bad name")
	}
}

// A symbolic link or a directory named like a temporary file is left alone, and
// a link's target is never touched.
//
// spec: SPO-Xbackup-SEC-007
func TestDirStaleSweepIgnoresSymlinksAndDirectories(t *testing.T) {
	s, root := newStore(t)
	d := filepath.Join(root, "a")
	os.Mkdir(d, 0o700)
	old := time.Now().Add(-2 * time.Hour)
	victim := filepath.Join(t.TempDir(), "victim")
	os.WriteFile(victim, []byte("keep"), 0o600)
	os.Chtimes(victim, old, old)
	link := filepath.Join(d, ".tmp-0123456789abcdef")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	dirNamed := filepath.Join(d, ".tmp-fedcba9876543210")
	os.Mkdir(dirNamed, 0o700)
	os.Chtimes(dirNamed, old, old)
	if err := put(s, "a/new.spo", "data"); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Lstat(link); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Error("the symlink was removed")
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Error("the symlink target was touched")
	}
	if st, err := os.Lstat(dirNamed); err != nil || !st.IsDir() {
		t.Error("the directory was removed")
	}
}
