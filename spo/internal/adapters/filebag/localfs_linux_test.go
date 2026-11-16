//go:build linux

package filebag

import "testing"

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
