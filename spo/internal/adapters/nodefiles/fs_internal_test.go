//go:build linux

package nodefiles

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// The file-system rule: ramfs is accepted, tmpfs and everything else is not.
//
// spec: SPO-Xcustody-PRE-014
func TestOnlyRamfsIsAcceptedByTheReleaseRule(t *testing.T) {
	w := Writer{}
	for name, magic := range map[string]int64{"ramfs": ramfsMagic} {
		if !w.fsOK(magic) {
			t.Errorf("%s refused", name)
		}
	}
	for name, magic := range map[string]int64{"tmpfs": 0x01021994, "ext4": 0xEF53, "btrfs": 0x9123683E, "xfs": 0x58465342, "overlayfs": 0x794c7630, "zero": 0} {
		if w.fsOK(magic) {
			t.Errorf("%s accepted", name)
		}
	}
}

// spec: SPO-Xcustody-PRE-014
func TestDirectoryOwnerAndModeChecks(t *testing.T) {
	f, st, err := openDirFD(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := checkDirFD(f, st, false); err != nil {
		t.Fatalf("a private directory of this user: %v", err)
	}
	other := *st
	other.Uid = uint32(os.Geteuid()) + 1
	if err := checkDirFD(f, &other, false); err == nil {
		t.Error("a directory of another owner was accepted")
	}
	if err := checkDirFD(f, &other, true); err == nil {
		t.Error("a directory of a non-root other owner was accepted when only root is allowed too")
	}
	rootOwned := *st
	rootOwned.Uid = 0
	if err := checkDirFD(f, &rootOwned, false); err == nil && os.Geteuid() != 0 {
		t.Error("a root-owned directory was accepted for the output")
	}
	if err := checkDirFD(f, &rootOwned, true); err != nil {
		t.Errorf("a root-owned directory refused where root may own it: %v", err)
	}
	for _, mode := range []uint32{0o020, 0o002, 0o022, 0o070 | 0o002} {
		m := *st
		m.Mode = unix.S_IFDIR | mode
		if err := checkDirFD(f, &m, false); err == nil {
			t.Errorf("mode %04o accepted", mode)
		}
	}
	notDir := *st
	notDir.Mode = unix.S_IFREG | 0o600
	if err := checkDirFD(f, &notDir, false); err == nil {
		t.Error("a regular file accepted as a directory")
	}
}

// spec: SPO-Xcustody-PRE-014
func TestTmpfsIsAcceptedOnlyWithNoswap(t *testing.T) {
	const noswap = `36 25 0:41 / /run/spo rw,nosuid,nodev - tmpfs tmpfs rw,size=1024k,noswap
37 25 0:42 / /run/other rw,nosuid,nodev,noswap - tmpfs tmpfs rw,size=1024k
38 25 0:43 / /run/plain rw,nosuid,nodev - tmpfs tmpfs rw,size=1024k
39 25 0:44 / /run/ram rw - ramfs ramfs rw
40 25 0:45 / /mnt rw,noswap - ext4 /dev/sda1 rw,noswap
41 25 0:46 / /a rw - tmpfs tmpfs rw,noswap
42 25 0:46 / /b rw - tmpfs tmpfs rw
`
	for name, c := range map[string]struct {
		major, minor uint32
		want         bool
	}{
		"noswap in the super options":  {0, 41, true},
		"noswap in the mount options":  {0, 42, true},
		"tmpfs without noswap":         {0, 43, false},
		"a ramfs is not a tmpfs":       {0, 44, false},
		"noswap on a disk file system": {0, 45, false},
		"no such device":               {0, 99, false},
		"two mounts, one without":      {0, 46, false},
	} {
		got, err := mountHasNoswap(strings.NewReader(noswap), c.major, c.minor)
		if err != nil || got != c.want {
			t.Errorf("%s: %v %v", name, got, err)
		}
	}
	// the decision function: ramfs always, tmpfs by the listing, the rest never
	w := Writer{}
	if !w.dirFSOK(&unix.Stat_t{}, ramfsMagic) || w.dirFSOK(&unix.Stat_t{}, 0xEF53) {
		t.Error("ramfs or a disk file system decided wrongly")
	}
	if w.dirFSOK(&unix.Stat_t{Dev: 0xffffff00}, tmpfsMagic) {
		t.Error("a tmpfs whose mount is not listed was accepted")
	}
}

// A credential file: owner root or this user, no access for others, group read
// only for this user's own group.
//
// spec: SPO-Xcustody-PRE-013
func TestCredentialFileModes(t *testing.T) {
	dir := t.TempDir()
	f, _, err := openDirFD(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for mode, ok := range map[os.FileMode]bool{0o400: true, 0o440: true, 0o600: true, 0o640: true, 0o444: false, 0o404: false, 0o420: false, 0o410: false} {
		p := dir + "/c"
		os.Remove(p)
		os.WriteFile(p, []byte("x"), 0o600)
		os.Chmod(p, mode)
		_, err := readFileAt(f, "c", 100, true)
		if (err == nil) != ok {
			t.Errorf("mode %04o: %v", mode, err)
		}
	}
}
