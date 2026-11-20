package mountfile

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// asRoot makes the files this test creates look root-owned: the "root" uid is
// the test's own and the process's effective uid another, so the rules that
// tell root from the process are exercised without root.
func asRoot(t *testing.T, inGroup bool) {
	t.Helper()
	me, gid := os.Getuid(), os.Getgid()
	oldRoot, oldUID, oldGID := rootUID, euid, egid
	rootUID = me
	euid = func() int { return me + 4242 }
	egid = func() int {
		if inGroup {
			return gid
		}
		return gid + 4242
	}
	t.Cleanup(func() { rootUID, euid, egid = oldRoot, oldUID, oldGID })
}

// asSelf makes the files look owned by the process (the effective uid is the
// test's), with root another uid.
func asSelf(t *testing.T) {
	t.Helper()
	me := os.Getuid()
	oldRoot, oldUID := rootUID, euid
	rootUID = me + 4242
	euid = func() int { return me }
	t.Cleanup(func() { rootUID, euid = oldRoot, oldUID })
}

// kubelet lays out a Secret or projected volume as kubelet's atomic writer
// does: the mount directory, a timestamped directory holding the files, a
// "..data" link to it, and a link per file to "..data/<name>". mode is the
// file's, rootMode the mount directory's.
func kubelet(t *testing.T, name string, body []byte, mode, rootMode os.FileMode) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "mount")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	ts := filepath.Join(root, "..2026_11_20_10_00_00.000000001")
	if err := os.Mkdir(ts, 0o755); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(ts, name)
	if err := os.WriteFile(f, body, 0o600); err != nil {
		t.Fatal(err)
	}
	must(t, os.Chmod(f, mode))
	must(t, os.Symlink(filepath.Base(ts), filepath.Join(root, "..data")))
	must(t, os.Symlink("..data/"+name, filepath.Join(root, name)))
	must(t, os.Chmod(root, rootMode))
	return filepath.Join(root, name)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// What kubelet gives a pod is read: a projected service-account token (0644 by
// default, or 0640 with fsGroup, or 0600 owned by the pod's user) under a
// mount directory that is world-writable with the sticky bit (tmpfs, 1777),
// reached through the "..data" link.
//
// spec: SPO-Xobjstore-SEC-302
func TestTheKubeletLayoutIsRead(t *testing.T) {
	for name, mode := range map[string]os.FileMode{"0644": 0o644, "0640": 0o640, "0444": 0o444} {
		asRoot(t, true)
		p := kubelet(t, "token", []byte("eyJ.token\n"), mode, 0o1777|os.ModeSticky)
		b, err := Read(p, Token(16<<10))
		if err != nil || string(b) != "eyJ.token\n" {
			t.Errorf("%s: %q %v", name, b, err)
		}
	}
	asSelf(t)
	p := kubelet(t, "token", []byte("eyJ.token"), 0o600, 0o755)
	if b, err := Read(p, Token(16<<10)); err != nil || string(b) != "eyJ.token" {
		t.Errorf("a token owned by the pod's user: %q %v", b, err)
	}
}

// A Secret mounted with fsGroup: root-owned, group-readable by the process's
// group, no other bit, no write bit. The key rule reads it; it refuses a group
// that is not the process's, any bit for others and any write bit.
//
// spec: SPO-Xobjstore-SEC-302
func TestTheKeyRuleTakesASecretVolume(t *testing.T) {
	asRoot(t, true)
	p := kubelet(t, "relay.key", []byte("k"), 0o440, 0o1777|os.ModeSticky)
	if b, err := Read(p, Key(1)); err != nil || string(b) != "k" {
		t.Fatalf("a Secret with fsGroup: %q %v", b, err)
	}
	for name, mode := range map[string]os.FileMode{"other read": 0o444, "owner write": 0o640, "group write": 0o460, "exec": 0o540} {
		asRoot(t, true)
		p := kubelet(t, "relay.key", []byte("k"), mode, 0o755)
		if _, err := Read(p, Key(1)); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
	asRoot(t, false)
	p = kubelet(t, "relay.key", []byte("k"), 0o440, 0o755)
	if _, err := Read(p, Key(1)); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "group") {
		t.Errorf("a group the process is not in: %v", err)
	}
	asRoot(t, false)
	p = kubelet(t, "relay.key", []byte("k"), 0o400, 0o755)
	if _, err := Read(p, Key(1)); err != nil {
		t.Errorf("owner read only, any group: %v", err)
	}
}

// What is refused, for both rules: a file owned by someone else, a write bit
// for the group or others, a mount directory writable by others without the
// sticky bit or not owned by root, a link that leaves the kubelet layout, a
// FIFO, a file over the bound, and a file that is not exactly the size of a
// fixed-size rule.
//
// spec: SPO-Xobjstore-SEC-302
func TestWhatTheRulesRefuse(t *testing.T) {
	refused := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, ErrRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// another user's file: neither the process's nor root's
	asSelf(t)
	p := kubelet(t, "token", []byte("t"), 0o600, 0o755)
	euid = func() int { return os.Getuid() + 1 }
	_, err := Read(p, Token(64))
	refused("another user's token", err)

	asRoot(t, true)
	p = kubelet(t, "token", []byte("t"), 0o646, 0o755)
	_, err = Read(p, Token(64))
	refused("writable by others", err)

	asRoot(t, true)
	p = kubelet(t, "token", []byte("t"), 0o644, 0o777)
	_, err = Read(p, Token(64))
	refused("a world-writable mount without the sticky bit", err)

	asSelf(t)
	p = kubelet(t, "token", []byte("t"), 0o600, 0o1777|os.ModeSticky)
	_, err = Read(p, Token(64))
	refused("a sticky world-writable mount not owned by root", err)

	asRoot(t, true)
	p = kubelet(t, "token", []byte("t"), 0o644, 0o755)
	ts := filepath.Join(filepath.Dir(p), "..2026_11_20_10_00_00.000000001")
	must(t, os.Chmod(ts, 0o777))
	_, err = Read(p, Token(64))
	refused("a timestamped directory writable by others", err)
	must(t, os.Chmod(ts, 0o755))

	// a link out of the layout: to a file elsewhere, and a link chain inside the
	// directory that is not the kubelet's
	asRoot(t, true)
	p = kubelet(t, "token", []byte("t"), 0o644, 0o755)
	outside := filepath.Join(t.TempDir(), "elsewhere")
	must(t, os.WriteFile(outside, []byte("t"), 0o644))
	must(t, os.Remove(p))
	must(t, os.Symlink(outside, p))
	_, err = Read(p, Token(64))
	refused("a link out of the mount", err)
	must(t, os.Remove(p))
	must(t, os.Symlink("..data/other", p))
	must(t, os.WriteFile(filepath.Join(filepath.Dir(p), "..data", "other"), []byte("t"), 0o644))
	_, err = Read(p, Token(64))
	refused("a link to another name", err)

	asSelf(t)
	dir := t.TempDir()
	must(t, os.Chmod(dir, 0o700))
	fifo := filepath.Join(dir, "token")
	must(t, syscall.Mkfifo(fifo, 0o600))
	_, err = Read(fifo, Token(64))
	refused("a FIFO", err)

	asSelf(t)
	p = kubelet(t, "token", []byte(strings.Repeat("t", 65)), 0o600, 0o755)
	_, err = Read(p, Token(64))
	refused("over the bound", err)

	asRoot(t, true)
	p = kubelet(t, "relay.key", []byte("kk"), 0o440, 0o755)
	_, err = Read(p, Key(3))
	refused("not the fixed size", err)

	if _, err := Read(filepath.Join(t.TempDir(), "none"), Token(64)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a missing file: %v", err)
	}
}

// A plain file (no link) in a directory of the process's user is read, as an
// operator on a host writes it.
//
// spec: SPO-Xobjstore-SEC-302
func TestAPlainFileOnAHostIsRead(t *testing.T) {
	asSelf(t)
	dir := t.TempDir()
	must(t, os.Chmod(dir, 0o700))
	p := filepath.Join(dir, "token")
	must(t, os.WriteFile(p, []byte("t"), 0o600))
	if b, err := Read(p, Token(64)); err != nil || string(b) != "t" {
		t.Fatalf("%q %v", b, err)
	}
	must(t, os.Chmod(dir, 0o770))
	if _, err := Read(p, Token(64)); !errors.Is(err, ErrRefused) {
		t.Fatalf("a group-writable directory: %v", err)
	}
}

// A path through a link in an ancestor (Debian's and Alpine's /var/run -> /run,
// under which IRSA mounts /var/run/secrets/eks.amazonaws.com/serviceaccount)
// is read: the directory is resolved first and the layout compared with the
// resolved directory. A Key of root under such a path is read too.
//
// spec: SPO-Xobjstore-SEC-302
func TestALinkedAncestorIsResolved(t *testing.T) {
	asRoot(t, true)
	p := kubelet(t, "token", []byte("eyJ.token"), 0o644, 0o1777|os.ModeSticky)
	base := t.TempDir()
	must(t, os.Mkdir(filepath.Join(base, "var"), 0o755))
	// var/run -> ../real-run, real-run -> the mount (an absolute link)
	must(t, os.Symlink(filepath.Dir(filepath.Dir(p)), filepath.Join(base, "real-run")))
	must(t, os.Symlink("../real-run", filepath.Join(base, "var", "run")))
	via := filepath.Join(base, "var", "run", "mount", "token")
	if b, err := Read(via, Token(64)); err != nil || string(b) != "eyJ.token" {
		t.Fatalf("a token under a linked ancestor: %q %v", b, err)
	}
	k := kubelet(t, "relay.key", []byte("k"), 0o440, 0o1777|os.ModeSticky)
	kl := filepath.Join(t.TempDir(), "secrets")
	must(t, os.Symlink(filepath.Dir(k), kl))
	if b, err := Read(filepath.Join(kl, "relay.key"), Key(1)); err != nil || string(b) != "k" {
		t.Fatalf("a key under a linked ancestor: %q %v", b, err)
	}
}

// Every directory the path is resolved through must be root's or the
// process's and closed to group and others (or root's with the sticky bit), and
// every link on the way root's or the process's: otherwise another user could
// swap a component and point the path at a file of their choosing. A link in
// a directory others can write is refused, and so is a plain ancestor others
// can write.
//
// spec: SPO-Xobjstore-SEC-302
func TestAnAncestorOthersCanWriteIsRefused(t *testing.T) {
	asRoot(t, true)
	p := kubelet(t, "token", []byte("eyJ.token"), 0o644, 0o755)
	open := t.TempDir()
	must(t, os.Chmod(open, 0o777))
	must(t, os.Symlink(filepath.Dir(p), filepath.Join(open, "run")))
	if _, err := Read(filepath.Join(open, "run", "token"), Token(64)); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), open) {
		t.Fatalf("a link in a directory others can write: %v", err)
	}
	// the mount's own parent made writable by others: the mount could be
	// replaced as a whole
	parent := filepath.Dir(filepath.Dir(p))
	must(t, os.Chmod(parent, 0o777))
	t.Cleanup(func() { os.Chmod(parent, 0o700) })
	if _, err := Read(p, Token(64)); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), parent) {
		t.Fatalf("an ancestor others can write: %v", err)
	}
	// the same directory with the sticky bit and root's: a mount under /tmp
	must(t, os.Chmod(parent, 0o777|os.ModeSticky))
	if _, err := Read(p, Token(64)); err != nil {
		t.Fatalf("a sticky ancestor of root's: %v", err)
	}
	// a link chain that loops is refused, not followed for ever
	loop := t.TempDir()
	must(t, os.Symlink("b", filepath.Join(loop, "a")))
	must(t, os.Symlink("a", filepath.Join(loop, "b")))
	if _, err := Read(filepath.Join(loop, "a", "token"), Token(64)); err == nil {
		t.Fatal("a loop of links was read")
	}
}

// A root-owned key is the Secret volume's form only: reached through kubelet's
// links. A plain root-owned file (on a host) is refused with the remedy, and
// the group read bit counts only for the process's effective group, not for a
// supplementary one.
//
// spec: SPO-Xmailbox-SEC-077, SPO-Xobjstore-SEC-302
func TestARootKeyMustBeASecretVolume(t *testing.T) {
	asRoot(t, true)
	dir := t.TempDir()
	must(t, os.Chmod(dir, 0o755))
	p := filepath.Join(dir, "relay.key")
	must(t, os.WriteFile(p, []byte("k"), 0o400))
	if _, err := Read(p, Key(1)); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "chown") || !strings.Contains(err.Error(), "subPath") {
		t.Fatalf("a plain root-owned key on a host: %v", err)
	}
	// the same file as a token is fine: a token is not a long-lived secret
	if _, err := Read(p, Token(64)); err != nil {
		t.Fatalf("a plain root-owned token: %v", err)
	}
	// a supplementary group: the test's own group is one (os.Getgroups lists
	// it), the effective group another
	sup, err := os.Getgroups()
	if err != nil || !slices.Contains(sup, os.Getgid()) {
		t.Skipf("the test's group is not a supplementary group here: %v %v", sup, err)
	}
	asRoot(t, false)
	k := kubelet(t, "relay.key", []byte("k"), 0o440, 0o755)
	if _, err := Read(k, Key(1)); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "effective group") {
		t.Fatalf("a group that is only a supplementary one: %v", err)
	}
}

// The error names the path and the rule broken, never the content.
//
// spec: SPO-Xobjstore-SEC-302
func TestTheErrorNamesNoContent(t *testing.T) {
	asRoot(t, true)
	p := kubelet(t, "token", []byte("SECRET-TOKEN-BYTES"), 0o646, 0o755)
	_, err := Read(p, Token(64))
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("%v", err)
	}
}
