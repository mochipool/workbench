//go:build unix

package filebag

import "syscall"

const (
	// noFollow makes open fail on a symbolic link as the last path component.
	noFollow = syscall.O_NOFOLLOW
	// nonBlock makes open of a FIFO or a device return at once instead of
	// waiting for the other end.
	nonBlock = syscall.O_NONBLOCK
)
