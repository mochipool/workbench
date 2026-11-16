//go:build linux

package cardanocli

import "golang.org/x/sys/unix"

// memoryBacked reports whether dir is on tmpfs or ramfs.
func memoryBacked(dir string) bool {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return false
	}
	return st.Type == unix.TMPFS_MAGIC || st.Type == unix.RAMFS_MAGIC
}
