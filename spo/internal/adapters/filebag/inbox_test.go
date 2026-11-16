package filebag

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The inbox is the operator's directory: not a link, not group or other
// writable, owned by the operator (ADR 0005, obligation 5).
//
// spec: SPO-Xparty-IF-004
func TestOpenRefusesAnInboxOthersCanWriteOrALink(t *testing.T) {
	root := t.TempDir()
	good := filepath.Join(root, "good")
	if err := os.Mkdir(good, 0o700); err != nil {
		t.Fatal(err)
	}
	if b, err := Open(good); err != nil {
		t.Fatalf("a private directory: %v", err)
	} else {
		b.Close()
	}
	for _, mode := range []os.FileMode{0o770, 0o707, 0o777, 0o720} {
		d := filepath.Join(root, "w"+mode.String())
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(d); !errors.Is(err, ErrInbox) {
			t.Errorf("mode %04o accepted: %v", mode, err)
		}
		// An export target is lenient about the mode.
		if b, err := OpenOutput(d); err != nil {
			t.Errorf("OpenOutput %04o: %v", mode, err)
		} else {
			b.Close()
		}
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link); !errors.Is(err, ErrInbox) {
		t.Errorf("a symbolic link was accepted: %v", err)
	}
	if _, err := OpenOutput(link); !errors.Is(err, ErrInbox) {
		t.Errorf("a symbolic link was accepted as an output: %v", err)
	}
	file := filepath.Join(root, "file")
	os.WriteFile(file, nil, 0o600)
	if _, err := Open(file); !errors.Is(err, ErrInbox) {
		t.Errorf("a file was accepted: %v", err)
	}
}

// A namer gives the spec's file name; a name that is not a plain envelope name
// is ignored.
func TestSetNamerNamesTheFile(t *testing.T) {
	d := filepath.Join(t.TempDir(), "o")
	os.Mkdir(d, 0o700)
	b, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	b.SetNamer(func([]byte) string { return "signingrequest-aabbccdd-1.spo" })
	if err := b.Send(t.Context(), [20]byte{1}, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(d, "signingrequest-aabbccdd-1.spo")); err != nil {
		t.Fatal(err)
	}
	b.SetNamer(func([]byte) string { return "../evil.spo" })
	if err := b.Send(t.Context(), [20]byte{1}, []byte("y")); err != nil {
		t.Fatal(err)
	}
	if m, _ := filepath.Glob(filepath.Join(d, "envelope-*.spo")); len(m) != 1 {
		t.Fatalf("default name not used: %v", m)
	}
}

// An ancestor that others can write to, and that has no sticky bit, lets
// somebody replace what is below it: the inbox under it is refused (the sshd
// StrictModes rule), by Open and by CheckInbox. A sticky ancestor (/tmp) is
// fine. The test-only floor ignores what is above it.
//
// spec: SPO-Xparty-IF-004
func TestInboxRefusesAnAncestorOthersCanWrite(t *testing.T) {
	base := t.TempDir()
	shared := filepath.Join(base, "shared")
	if err := os.Mkdir(shared, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(shared, "sub")
	in := filepath.Join(sub, "inbox")
	if err := os.MkdirAll(in, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(in); !errors.Is(err, ErrInbox) {
		t.Fatalf("an inbox under a world-writable parent was accepted: %v", err)
	}
	if err := CheckInbox(in); !errors.Is(err, ErrInbox) {
		t.Fatalf("CheckInbox: %v", err)
	}
	// Through a symbolic link above it: the resolved ancestors are judged.
	ln := filepath.Join(base, "lnk")
	if err := os.Symlink(shared, ln); err != nil {
		t.Fatal(err)
	}
	if err := CheckInbox(filepath.Join(ln, "sub", "inbox")); !errors.Is(err, ErrInbox) {
		t.Fatalf("via a symbolic ancestor: %v", err)
	}
	// With the sticky bit the same parent is acceptable.
	if err := os.Chmod(shared, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := CheckInbox(in); err != nil {
		t.Fatalf("a sticky ancestor refused: %v", err)
	}
	// The test hook: a floor below the bad ancestor hides it.
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	ancestorFloor = sub
	defer func() { ancestorFloor = "" }()
	if err := CheckInbox(in); err != nil {
		t.Fatalf("with the floor at %s: %v", sub, err)
	}
}

// The default name of a file Send writes does not carry the recipient.
func TestDefaultFileNameCarriesNoRecipient(t *testing.T) {
	d := filepath.Join(t.TempDir(), "o")
	os.Mkdir(d, 0o700)
	b, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	to := [20]byte{0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a}
	if err := b.Send(t.Context(), to, []byte("x")); err != nil {
		t.Fatal(err)
	}
	m, _ := filepath.Glob(filepath.Join(d, "envelope-*.spo"))
	if len(m) != 1 {
		t.Fatal(m)
	}
	if n := filepath.Base(m[0]); strings.Contains(n, "abcdef12") || strings.Contains(n, "abcd") {
		t.Errorf("the file name %s carries the recipient", n)
	}
}
