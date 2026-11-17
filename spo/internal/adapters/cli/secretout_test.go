package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/mochipool/workbench/spo/internal/platform/uihint"
)

// refusedOutFDs opens one descriptor of every kind a secret must not go to and
// returns them by name: a regular file, a directory, /dev/null, a closed
// number, and the three standard descriptors.
func refusedOutFDs(t *testing.T) map[string]int {
	t.Helper()
	dir := t.TempDir()
	reg, err := os.Create(filepath.Join(dir, "pwfile"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	null, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reg.Close(); d.Close(); null.Close() })
	return map[string]int{
		"regular file": int(reg.Fd()), "directory": int(d.Fd()), "character device": int(null.Fd()),
		"closed": 57, "stdin": 0, "stdout": 1, "stderr": 2,
	}
}

// Every flag the UI classification marks as secret-output is checked by the
// root hook: a regular file, a device, a closed number or a standard
// descriptor is refused with the reason, and a pipe passes. The classification
// and the check are one table, so a flag added there cannot skip the check.
//
// spec: SPO-Xcustody-OUT-005, SPO-Xcustody-PRE-006
func TestEveryClassifiedSecretOutFlagGoesThroughTheHelper(t *testing.T) {
	root := NewRoot(Deps{Out: io.Discard, Err: io.Discard})
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	bad := refusedOutFDs(t)
	seen := map[string]bool{}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		c.Flags().VisitAll(func(f *pflag.Flag) {
			if secretFDFlags[f.Name] != uihint.SecretOut {
				return
			}
			seen[f.Name] = true
			for name, fd := range bad {
				c.Flags().Set(f.Name, itoaFD(fd))
				err := root.PersistentPreRunE(c, nil)
				if err == nil || !strings.Contains(err.Error(), "never written to a file") {
					t.Errorf("%s --%s %s (%d): %v", c.CommandPath(), f.Name, name, fd, err)
				}
			}
			c.Flags().Set(f.Name, itoaFD(int(w.Fd())))
			if err := root.PersistentPreRunE(c, nil); err != nil {
				t.Errorf("%s --%s on a pipe: %v", c.CommandPath(), f.Name, err)
			}
		})
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
	for name, dir := range secretFDFlags {
		if dir == uihint.SecretOut && !seen[name] {
			t.Errorf("--%s is classified secret-out but no command has it", name)
		}
	}
	// And the flags in the tree: every flag that writes a secret is classified.
	var all func(c *cobra.Command)
	all = func(c *cobra.Command) {
		c.Flags().VisitAll(func(f *pflag.Flag) {
			if strings.HasSuffix(f.Name, "-out-fd") || f.Name == "recovery-key-fd" {
				if secretFDFlags[f.Name] != uihint.SecretOut {
					t.Errorf("%s --%s writes a secret to a descriptor and is not classified secret-out", c.CommandPath(), f.Name)
				}
			}
		})
		for _, sub := range c.Commands() {
			all(sub)
		}
	}
	all(root)
}

// The hook runs on a real command through Execute, not only when called.
//
// spec: SPO-Xcustody-OUT-005, SPO-Xcustody-PRE-006
func TestRootRefusesASecretOutFileBeforeAnyEffect(t *testing.T) {
	f := newWsFix(t)
	f.gpg = true
	f.wallet(f.ws, "w", f.seed)
	target := filepath.Join(t.TempDir(), "out")
	f.audit.dest = target
	for name, fd := range refusedOutFDs(t) {
		err := f.run(&scriptTerm{t: t}, "workspace", "export", target, "--generate-password", "--password-out-fd", itoaFD(fd))
		if err == nil || !strings.Contains(err.Error(), "never written to a file") {
			t.Errorf("%s: %v", name, err)
		}
		if _, serr := os.Stat(target); serr == nil || len(f.audit.events) != 0 {
			t.Fatalf("%s: the refused export created the directory or recorded %v", name, f.audit.events)
		}
	}
	if err := f.run(&scriptTerm{t: t}, "workspace", "export", target, "--generate-password", "--password-out-fd", "1"); err == nil {
		t.Error("descriptor 1 accepted")
	}
}

// When the descriptor is a pipe whose reader is gone, the password cannot be
// delivered; it is delivered BEFORE any file is written, so no encrypted file
// is left whose password is lost.
//
// spec: SPO-Xcustody-OUT-005, SPO-Xcustody-PRE-006
func TestExportDeliversThePasswordBeforeWritingFiles(t *testing.T) {
	f := newWsFix(t)
	f.gpg = true
	f.wallet(f.ws, "w", f.seed)
	target := filepath.Join(t.TempDir(), "out")
	f.audit.dest = target
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	r.Close() // no reader: the write fails with EPIPE
	defer w.Close()
	err = f.run(&scriptTerm{t: t}, "workspace", "export", target, "--generate-password", "--password-out-fd", itoaFD(int(w.Fd())))
	if err == nil {
		t.Fatal("the export went on although the password could not be delivered")
	}
	if _, serr := os.Stat(target); serr == nil || len(f.audit.events) != 0 {
		t.Errorf("files or an audit record exist although the password was not delivered: %v", f.audit.events)
	}
}
