//go:build unix

package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const vaultText = "network = \"preview\"\nmode = \"offline\"\n\n[vault]\naddress = \"https://vault.example:8200\"\nkey = \"spo\"\n"

// writeConfig writes spo.toml in a new directory of the given mode, with the
// file mode given (set after the umask).
func writeConfig(t *testing.T, dirMode, fileMode os.FileMode) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ws")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Path(dir), []byte(vaultText), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(Path(dir), fileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, dirMode); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A file that is the user's own, writable by the user only, in a directory
// others cannot write, may name a backend. Each way it can be another's to
// change makes Load mark it untrusted, naming the file and the remedy, while
// every setting is still read (a command without a backend keeps working).
//
// spec: SPO-Xunlock-PRE-050
func TestLoadMarksAConfigFileOthersCanChangeAsUntrusted(t *testing.T) {
	good := writeConfig(t, 0o700, 0o600)
	c, err := Load(good)
	if err != nil || c.Untrusted != nil {
		t.Fatalf("a private file: %v, untrusted %v", err, c.Untrusted)
	}
	if c.Vault == nil {
		t.Fatal("the [vault] section was not read")
	}
	for _, mode := range []os.FileMode{0o644, 0o640, 0o400} {
		if c, err := Load(writeConfig(t, 0o755, mode)); err != nil || c.Untrusted != nil {
			t.Fatalf("mode %04o (no write for group or others): %v, untrusted %v", mode, err, c.Untrusted)
		}
	}
	link := filepath.Join(t.TempDir(), "ws")
	if err := os.Mkdir(link, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(Path(good), Path(link)); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		dir  string
		want string
	}{
		"group-writable": {writeConfig(t, 0o700, 0o620), "group or others"},
		"other-writable": {writeConfig(t, 0o700, 0o602), "group or others"},
		"open directory": {writeConfig(t, 0o777, 0o600), "the directory"},
		"symbolic link":  {link, "symbolic link"},
	}
	for name, tc := range cases {
		c, err := Load(tc.dir)
		if err != nil {
			t.Fatalf("%s: every other setting must still load: %v", name, err)
		}
		if c.Vault == nil || c.Network != "preview" {
			t.Fatalf("%s: the settings were not read", name)
		}
		if !errors.Is(c.Untrusted, ErrUntrustedFile) {
			t.Fatalf("%s: untrusted = %v", name, c.Untrusted)
		}
		msg := c.Untrusted.Error()
		for _, w := range []string{tc.want, Path(tc.dir), "chmod 600"} {
			if !strings.Contains(msg, w) {
				t.Errorf("%s: %q does not say %q", name, msg, w)
			}
		}
	}
}

// The owner is checked on the descriptor that was read: a file of another user
// is untrusted.
//
// spec: SPO-Xunlock-PRE-050
func TestLoadMarksAConfigFileOfAnotherUserAsUntrusted(t *testing.T) {
	dir := writeConfig(t, 0o700, 0o600)
	saved := processUID
	t.Cleanup(func() { processUID = saved })
	processUID = func() int { return os.Getuid() + 1 }
	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(c.Untrusted, ErrUntrustedFile) || !strings.Contains(c.Untrusted.Error(), "owned by user") {
		t.Fatalf("untrusted = %v", c.Untrusted)
	}
}

// A FIFO in place of spo.toml does not hang Load, and neither does a file
// larger than the bound get read.
//
// spec: SPO-Xunlock-PRE-050
func TestLoadRefusesAFIFOAndAnOversizedConfigFile(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(Path(dir), 0o600); err != nil {
		t.Skipf("no FIFO here: %v", err)
	}
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("a FIFO: %v", err)
	}
	big := t.TempDir()
	f, err := os.OpenFile(Path(big), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	// a sparse file that claims more than the bound; nothing of it is read
	if err := f.Truncate(MaxFileSize + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := Load(big); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("an oversized file: %v", err)
	}
}
