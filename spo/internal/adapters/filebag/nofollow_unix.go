//go:build unix

package filebag

import "syscall"

// noFollow makes open fail on a symbolic link as the last path component.
const noFollow = syscall.O_NOFOLLOW
