//go:build unix

package config

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hostileText is what another user plants in a file that they can change: a
// [vault] section that sends the token to their server, with their CA, and a
// [kms] private STS endpoint of theirs.
const hostileText = "network = \"preview\"\nmode = \"offline\"\n\n[vault]\naddress = \"https://vault.example:8200\"\nkey = \"spo\"\nca_file = \"/tmp/attacker-ca.pem\"\ntoken_file = \"/tmp/attacker-token\"\n\n[kms]\nkey_arn = \"arn:aws:kms:eu-west-1:111122223333:key/abc\"\nprivate_sts_endpoint = \"https://sts.attacker.example\"\n"

// The review's proof of concept, kept: spo.toml is a symbolic link to a file
// any user can write (mode 0666). Load marks it untrusted, and a save of the
// settings read from it (what `spo provider order` does) is refused with the
// file, the reason and the remedy: the file is not rewritten into a regular
// 0600 file of the user's own, so another user's [vault] and [kms] never become
// trusted. The link and the file it points to are unchanged.
//
// spec: SPO-Xunlock-PRE-051
func TestASaveNeverLaundersAnUntrustedSpoToml(t *testing.T) {
	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.Mkdir(ws, 0o700); err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(t.TempDir(), "planted.toml")
	if err := os.WriteFile(planted, []byte(hostileText), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(planted, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(planted, Path(ws)); err != nil {
		t.Fatal(err)
	}
	c, err := Load(ws)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(c.Untrusted, ErrUntrustedFile) || c.Vault == nil || c.KMS == nil {
		t.Fatalf("the planted file: untrusted %v, vault %v, kms %v", c.Untrusted, c.Vault, c.KMS)
	}
	c.Node = &Node{Address: "/run/cardano/node.socket"} // what `spo provider set node` changes
	err = Save(ws, c)
	if !errors.Is(err, ErrUntrustedFile) {
		t.Fatalf("a save of an untrusted file: %v", err)
	}
	for _, w := range []string{Path(ws), "symbolic link", "not rewritten", "Inspect", "recreate"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("the refusal %q does not say %q", err, w)
		}
	}
	if fi, err := os.Lstat(Path(ws)); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("spo.toml is no longer the link: %v", err)
	}
	if got, err := os.ReadFile(planted); err != nil || !bytes.Equal(got, []byte(hostileText)) {
		t.Fatalf("the planted file changed: %v", err)
	}
	if fi, err := os.Stat(planted); err != nil || fi.Mode().Perm() != 0o666 {
		t.Fatalf("the planted file's mode changed: %v", err)
	}

	// Save checks the file on disk too: settings that claim to be trusted do
	// not let a save replace a file others can change
	c.Untrusted = nil
	if err := Save(ws, c); !errors.Is(err, ErrUntrustedFile) {
		t.Fatalf("a save with the refusal dropped by the caller: %v", err)
	}
	if fi, err := os.Lstat(Path(ws)); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("spo.toml is no longer the link: %v", err)
	}
}

// Every reason a file is untrusted refuses the rewrite, and a file of the
// user's own is saved as before.
//
// spec: SPO-Xunlock-PRE-051
func TestASaveRefusesEveryUntrustedFileAndSavesAPrivateOne(t *testing.T) {
	for name, dir := range map[string]string{
		"group-writable file": writeConfig(t, 0o700, 0o620),
		"open directory":      writeConfig(t, 0o777, 0o600),
	} {
		c, err := Load(dir)
		if err != nil || c.Untrusted == nil {
			t.Fatalf("%s: %v, untrusted %v", name, err, c.Untrusted)
		}
		before, _ := os.ReadFile(Path(dir))
		c.Mode = "online"
		if err := Save(dir, c); !errors.Is(err, ErrUntrustedFile) {
			t.Errorf("%s: saved: %v", name, err)
		}
		if after, _ := os.ReadFile(Path(dir)); !bytes.Equal(before, after) {
			t.Errorf("%s: the file changed", name)
		}
		if c.RewriteRefusal() == nil {
			t.Errorf("%s: no rewrite refusal", name)
		}
	}
	good := writeConfig(t, 0o700, 0o600)
	c, err := Load(good)
	if err != nil || c.Untrusted != nil || c.RewriteRefusal() != nil {
		t.Fatalf("a private file: %v, %v", err, c.Untrusted)
	}
	c.Mode = "online"
	if err := Save(good, c); err != nil {
		t.Fatal(err)
	}
	if c, err := Load(good); err != nil || c.Mode != "online" || c.Vault == nil {
		t.Fatalf("after the save: %v %+v", err, c)
	}
}

// A file that only this platform cannot check (an access list the mode bits do
// not show) is untrusted for a backend, but its rewrite is not refused: the new
// file is just as unchecked on this platform, so a save blesses nothing.
//
// spec: SPO-Xunlock-PRE-050, SPO-Xunlock-PRE-051
func TestAPlatformThatCannotSeeAccessListsFailsClosedForABackendOnly(t *testing.T) {
	saved := modeBitsBoundAccess
	t.Cleanup(func() { modeBitsBoundAccess = saved })
	modeBitsBoundAccess = false
	dir := writeConfig(t, 0o700, 0o600)
	c, err := Load(dir)
	if err != nil || !errors.Is(c.Untrusted, ErrUntrustedFile) || !strings.Contains(c.Untrusted.Error(), "access control list") {
		t.Fatalf("untrusted = %v (%v)", c.Untrusted, err)
	}
	if c.RewriteRefusal() != nil {
		t.Fatalf("a platform reason refused the rewrite: %v", c.RewriteRefusal())
	}
	c.Mode = "online"
	if err := Save(dir, c); err != nil {
		t.Fatalf("a save: %v", err)
	}
	// a reason of the file itself still comes first and still refuses
	bad := writeConfig(t, 0o700, 0o620)
	c, _ = Load(bad)
	if !strings.Contains(c.Untrusted.Error(), "group or others") || c.RewriteRefusal() == nil {
		t.Fatalf("a group-writable file on such a platform: %v", c.Untrusted)
	}
}

// The directory that holds the file is checked on the descriptor the file was
// opened under: owned by the user or root, and writable by nobody else. A
// world-writable directory is refused even with the sticky bit (another user
// could have made the file there first), so is one group members can write and
// one owned by another user.
//
// spec: SPO-Xunlock-PRE-050
func TestTheWorkspaceDirectoryMustBeTheUsersAndClosed(t *testing.T) {
	cases := map[string]struct {
		mode os.FileMode
		want string
	}{
		"sticky world-writable": {0o777 | os.ModeSticky, "the directory"},
		"group-writable":        {0o770, "the directory"},
		"other-writable":        {0o703, "the directory"},
	}
	for name, tc := range cases {
		dir := writeConfig(t, tc.mode, 0o600)
		c, err := Load(dir)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !errors.Is(c.Untrusted, ErrUntrustedFile) || !strings.Contains(c.Untrusted.Error(), tc.want) {
			t.Errorf("%s: untrusted = %v", name, c.Untrusted)
		}
	}
	for _, mode := range []os.FileMode{0o700, 0o755, 0o750} {
		if c, err := Load(writeConfig(t, mode, 0o600)); err != nil || c.Untrusted != nil {
			t.Errorf("directory mode %04o: %v, untrusted %v", mode, err, c.Untrusted)
		}
	}
	// the owner of the directory: a check of the file passes (the seam names
	// the file's owner too) only when both are the process user's
	dir := writeConfig(t, 0o700, 0o600)
	saved := processUID
	t.Cleanup(func() { processUID = saved })
	uid := os.Getuid()
	calls := 0
	processUID = func() int {
		calls++
		if calls == 1 {
			return uid // the file
		}
		return uid + 1 // the directory
	}
	if uid == 0 {
		t.Skip("running as root: every directory is owned by an accepted user")
	}
	c, err := Load(dir)
	if err != nil || !errors.Is(c.Untrusted, ErrUntrustedFile) || !strings.Contains(c.Untrusted.Error(), "the directory") {
		t.Fatalf("a directory of another user: %v, untrusted %v", err, c.Untrusted)
	}
}

// A file with a second hard link can be changed through the other name, which
// may be in a directory another user controls: it is untrusted. The remedy says
// to inspect and recreate the file, not only to change its mode.
//
// spec: SPO-Xunlock-PRE-050
func TestAHardLinkedSpoTomlIsUntrustedAndTheRemedyIsToRecreateIt(t *testing.T) {
	dir := writeConfig(t, 0o700, 0o600)
	if err := os.Link(Path(dir), filepath.Join(t.TempDir(), "other-name")); err != nil {
		t.Skipf("no hard link here: %v", err)
	}
	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(c.Untrusted, ErrUntrustedFile) || !strings.Contains(c.Untrusted.Error(), "2 hard links") {
		t.Fatalf("untrusted = %v", c.Untrusted)
	}
	msg := c.Untrusted.Error()
	for _, w := range []string{"Inspect", "[vault]", "[kms]", "recreate", "new file", "rename", "chmod 600 alone"} {
		if !strings.Contains(msg, w) {
			t.Errorf("the remedy %q does not say %q", msg, w)
		}
	}
}
