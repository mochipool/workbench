//go:build unix

package filebag

import (
	"os"
	"syscall"
)

const (
	// noFollow makes open fail on a symbolic link as the last path component.
	noFollow = syscall.O_NOFOLLOW
	// nonBlock makes open of a FIFO or a device return at once instead of
	// waiting for the other end.
	nonBlock = syscall.O_NONBLOCK
)

// openDirNoFollow opens dir as a directory without following a link in its
// last component; every later check is made on this descriptor.
func openDirNoFollow(dir string) (*os.File, error) {
	return os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
}
