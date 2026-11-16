//go:build linux

package filebag

import (
	"fmt"
	"os"
	"syscall"
)

// Magic numbers of file systems that are not a local disk (statfs f_type).
var remoteFS = map[int64]string{
	0x6969:     "NFS",
	0x517B:     "SMB",
	0xFF534D42: "CIFS",
	0xFE534D42: "SMB2",
	0x65735546: "FUSE (sshfs, rclone, a cloud drive or another userspace file system)",
	0x01021997: "9p",
	0xC36400:   "Ceph",
	0x5346414F: "OpenAFS",
	0x47504653: "GPFS",
	0x19800202: "Lustre",
	// Verified against linux/magic.h (/usr/include/linux/magic.h):
	0x6B414653: "kAFS (AFS_FS_MAGIC)",
	0x73757245: "Coda",
	0x564C:     "NetWare (ncpfs)",
	// NOT in linux/magic.h, so not verified there: vboxsf (VirtualBox shared
	// folders) defines VBSF_SUPER_MAGIC in fs/vboxsf; 0x6a656a63 and
	// BeeGFS's 0x19830326 are as listed by the security review of this
	// wiring and could not be checked against kernel headers here. virtiofs
	// itself reports the FUSE magic above.
	0x786f4256: "VirtualBox shared folder (vboxsf), constant not verified against linux/magic.h",
	0x6a656a63: "a shared-folder file system (listed by the security review), constant not verified against linux/magic.h",
	0x19830326: "BeeGFS, constant not verified against linux/magic.h",
}

// localFS refuses a directory (asked of the open descriptor) on a file system known to be remote or
// userspace-served. It cannot see a sync client that copies a local directory
// to other machines.
func localFS(dir *os.File) error {
	var s syscall.Statfs_t
	if err := syscall.Fstatfs(int(dir.Fd()), &s); err != nil {
		return err
	}
	if name, bad := remoteFS[int64(s.Type)]; bad {
		return fmt.Errorf("it is on a %s file system, which is not a local directory", name)
	}
	return nil
}
