//go:build linux

package filebag

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// Magic numbers of file systems that are not a local disk (statfs f_type).
//
// Verification, done against two sources: golang.org/x/sys/unix (generated
// from the kernel headers; its *_SUPER_MAGIC names are used below) and
// /usr/include/linux/magic.h (the few the package lacks). Each entry says
// where it was found.
var remoteFS = map[int64]string{
	unix.NFS_SUPER_MAGIC:  "NFS",  // x/sys/unix, linux/magic.h
	unix.SMB_SUPER_MAGIC:  "SMB",  // x/sys/unix, linux/magic.h
	unix.CIFS_SUPER_MAGIC: "CIFS", // x/sys/unix, linux/magic.h
	unix.SMB2_SUPER_MAGIC: "SMB2", // x/sys/unix, linux/magic.h
	unix.FUSE_SUPER_MAGIC: "FUSE (sshfs, rclone, a cloud drive or another userspace file system)",
	unix.CEPH_SUPER_MAGIC: "Ceph",            // x/sys/unix, linux/magic.h
	unix.AFS_SUPER_MAGIC:  "OpenAFS",         // x/sys/unix, linux/magic.h (AFS_SUPER_MAGIC)
	unix.CODA_SUPER_MAGIC: "Coda",            // x/sys/unix, linux/magic.h
	unix.NCP_SUPER_MAGIC:  "NetWare (ncpfs)", // x/sys/unix, linux/magic.h
	0x01021997:            "9p",              // linux/magic.h V9FS_MAGIC; not in x/sys/unix
	0x6B414653:            "kAFS",            // linux/magic.h AFS_FS_MAGIC; not in x/sys/unix
	// Found in another project's table (moby's fstype package, in the module
	// cache), not in linux/magic.h.
	0x47504653: "GPFS",
	// NOT verified. None of the following is in linux/magic.h or in
	// golang.org/x/sys/unix, and nothing in this tree states them: vboxsf
	// (VirtualBox shared folders), 0x6a656a63 (listed by the security review
	// of this wiring, owner unknown) and BeeGFS. They are kept because a false
	// positive only refuses a directory, and a false negative lets a shared
	// folder feed envelopes. Lustre is here by its value from memory
	// (LL_SUPER_MAGIC 0x0BD00BD0), also not checked. virtiofs reports the FUSE
	// magic above.
	0x786f4256: "VirtualBox shared folder (vboxsf), constant not verified against linux/magic.h",
	0x6a656a63: "a shared-folder file system (listed by the security review), constant not verified against linux/magic.h",
	0x19830326: "BeeGFS, constant not verified against linux/magic.h",
	0x0BD00BD0: "Lustre, constant not verified against linux/magic.h",
}

// remoteFSName looks a statfs f_type up in the table. The type is a 32-bit
// magic: Statfs_t.Type is an int32 on 32-bit Linux, where CIFS (0xFF534D42) and
// SMB2 (0xFE534D42) are negative and sign-extend when widened to int64, so the
// value is reduced to its low 32 bits before the lookup.
func remoteFSName(fType int64) (string, bool) {
	name, bad := remoteFS[int64(uint32(fType))]
	return name, bad
}

// localFS refuses a directory (asked of the open descriptor) on a file system known to be remote or
// userspace-served. It cannot see a sync client that copies a local directory
// to other machines.
func localFS(dir *os.File) error {
	var s syscall.Statfs_t
	if err := syscall.Fstatfs(int(dir.Fd()), &s); err != nil {
		return err
	}
	if name, bad := remoteFSName(int64(s.Type)); bad {
		return fmt.Errorf("it is on a %s file system, which is not a local directory", name)
	}
	return nil
}
