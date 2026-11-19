package cli

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The address file of spo party relay add holds the relay's pre-shared key. It
// is opened without following a link and without waiting (a FIFO is refused at
// once, not waited on), must be a regular file that only its owner can read or
// write (the rule of the relay's own key file, SPO-Xmailbox-SEC-077), and is
// read into guarded memory only.
//
// spec: SPO-Xmailbox-IF-025, SPO-Xmailbox-SEC-081
func TestTheAddressFileIsASecretFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, text string, mode os.FileMode) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := write("good", "tailcat-address-1234\n", 0o600)
	buf, err := readAddressFile(good)
	if err != nil {
		t.Fatal(err)
	}
	var got string
	buf.Use(func(b []byte) error { got = string(b); return nil })
	buf.Destroy()
	if got != "tailcat-address-1234" {
		t.Fatalf("read %q", got)
	}
	if b, err := readAddressFile(write("owner-only-ro", "addr", 0o400)); err != nil {
		t.Fatalf("a 0400 file: %v", err)
	} else {
		b.Destroy()
	}
	for name, p := range map[string]string{
		"group readable": write("g", "addr\n", 0o640),
		"world readable": write("o", "addr\n", 0o604),
		"group writable": write("gw", "addr\n", 0o620),
	} {
		if _, err := readAddressFile(p); err == nil || !strings.Contains(err.Error(), "chmod 600") {
			t.Errorf("%s: %v", name, err)
		}
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readAddressFile(link); err == nil {
		t.Error("a symbolic link was followed")
	}
	for name, p := range map[string]string{
		"two words": write("w", "addr ess\n", 0o600),
		"empty":     write("e", "\n", 0o600),
		"too large": write("l", strings.Repeat("a", 1100), 0o600),
	} {
		if _, err := readAddressFile(p); err == nil {
			t.Errorf("%s: read", name)
		}
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := readAddressFile(fifo); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO was read")
		}
	case <-time.After(3 * time.Second):
		// unblock the open so that the goroutine ends
		if f, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			f.Close()
		}
		t.Fatal("readAddressFile waited on a FIFO")
	}
}
