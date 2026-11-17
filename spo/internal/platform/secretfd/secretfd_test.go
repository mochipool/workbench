package secretfd

import (
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
)

// spec: SPO-Xcustody-OUT-005, SPO-Xcustody-PRE-006
func TestCheckAcceptsOnlyAPipeOrASocketOpenForWriting(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if err := Check("x-fd", int(w.Fd())); err != nil {
		t.Errorf("a pipe write end: %v", err)
	}
	if err := Check("x-fd", int(r.Fd())); err == nil || !strings.Contains(err.Error(), "reading only") {
		t.Errorf("a pipe read end: %v", err)
	}

	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(pair[0])
	defer syscall.Close(pair[1])
	if err := Check("x-fd", pair[0]); err != nil {
		t.Errorf("a unix socket: %v", err)
	}

	dir := t.TempDir()
	reg, err := os.Create(dir + "/f")
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()
	d, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	null, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	for name, fd := range map[string]int{
		"a regular file":   int(reg.Fd()),
		"a directory":      int(d.Fd()),
		"a character dev":  int(null.Fd()),
		"standard input":   0,
		"standard output":  1,
		"standard error":   2,
		"a closed fd":      57,
		"a negative value": -1,
	} {
		err := Check("x-fd", fd)
		if err == nil || !errors.Is(err, ErrNotAPipe) {
			t.Errorf("%s: %v", name, err)
			continue
		}
	}
	// The message says why and what to use.
	err = Check("x-fd", int(reg.Fd()))
	for _, want := range []string{"a regular file", "never written to a file", "pipe", "password manager"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message lacks %q: %v", want, err)
		}
	}
}

func TestWriteChecksBeforeWritingAndWritesToAPipe(t *testing.T) {
	dir := t.TempDir()
	reg, err := os.Create(dir + "/f")
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()
	if err := Write("x-fd", int(reg.Fd()), []byte("secret")); err == nil {
		t.Fatal("wrote a secret to a file")
	}
	if b, _ := os.ReadFile(dir + "/f"); len(b) != 0 {
		t.Fatalf("the file holds %q", b)
	}
	r, w, _ := os.Pipe()
	defer r.Close()
	if err := Write("x-fd", int(w.Fd()), []byte("secret")); err != nil {
		t.Fatal(err)
	}
	w.Close()
	if b, _ := io.ReadAll(r); string(b) != "secret" {
		t.Fatalf("%q", b)
	}
	// A pipe whose reader is gone is an error, not a signal.
	r2, w2, _ := os.Pipe()
	r2.Close()
	defer w2.Close()
	if err := Write("x-fd", int(w2.Fd()), []byte("secret")); err == nil {
		t.Fatal("a write to a pipe with no reader succeeded")
	}
}
