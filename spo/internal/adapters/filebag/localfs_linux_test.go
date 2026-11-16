//go:build linux

package filebag

import (
	"testing"

	"golang.org/x/sys/unix"
)

// The network and shared file systems the review listed are refused.
func TestRemoteFSMagicNumbers(t *testing.T) {
	for magic, name := range map[int64]string{
		0x6a656a63: "shared folder", 0x786f4256: "vboxsf", 0x6B414653: "kAFS",
		0x73757245: "Coda", 0x564c: "ncpfs", 0x19830326: "BeeGFS",
		0x6969: "NFS", 0x65735546: "FUSE",
	} {
		if _, ok := remoteFS[magic]; !ok {
			t.Errorf("%s (%#x) is not in the remote file system table", name, magic)
		}
	}
}

// The table names the constants verified in golang.org/x/sys/unix, and the
// POSIX message queue file system, whose magic 0x19800202 an earlier table
// mislabelled as Lustre, is not a remote file system.
func TestRemoteFSTableUsesVerifiedConstants(t *testing.T) {
	for magic, want := range map[int64]string{
		0x6969: "NFS", 0x517B: "SMB", 0xFF534D42: "CIFS", 0xFE534D42: "SMB2", 0xC36400: "Ceph",
		0x5346414F: "OpenAFS", 0x73757245: "Coda", 0x564C: "NetWare (ncpfs)", 0x01021997: "9p", 0x6B414653: "kAFS",
	} {
		if got := remoteFS[magic]; got != want {
			t.Errorf("%#x is %q, want %q", magic, got, want)
		}
	}
	if name, ok := remoteFS[0x19800202]; ok {
		t.Errorf("0x19800202 is the POSIX message queue file system (MQUEUE_MAGIC), listed as %q", name)
	}
	if _, ok := remoteFS[unix.FUSE_SUPER_MAGIC]; !ok {
		t.Error("FUSE is not in the table")
	}
}

// On 32-bit Linux f_type is an int32: the CIFS and SMB2 magics are negative and
// sign-extend when widened. The comparison must still find them, and must not
// find a magic that is not in the table.
func TestRemoteFSNameFindsMagicsThatAreNegativeInt32(t *testing.T) {
	cifs, smb2 := uint32(0xFF534D42), uint32(0xFE534D42)
	for want, v := range map[string]int32{"CIFS": int32(cifs), "SMB2": int32(smb2)} {
		if v >= 0 {
			t.Fatalf("%s as int32 is not negative: %d", want, v)
		}
		if name, ok := remoteFSName(int64(v)); !ok || name != want {
			t.Errorf("the int32 %d: %q, %v; want %s", v, name, ok, want)
		}
	}
	// the same values as a 64-bit f_type still match, and an unknown magic does not
	if name, ok := remoteFSName(int64(cifs)); !ok || name != "CIFS" {
		t.Errorf("64-bit CIFS: %q, %v", name, ok)
	}
	if _, ok := remoteFSName(0xEF53); ok { // ext4
		t.Error("ext4 is listed as a remote file system")
	}
}
