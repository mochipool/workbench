//go:build unix

package relaylock

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Acquire takes the lock on path without waiting: ErrHeld when another holder
// has it. The file is made (mode 0600) when it is missing, never followed
// through a symbolic link, and must be a regular file.
func Acquire(path string) (*Lock, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("the relay-login lock file %s could not be opened: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("the relay-login lock file %s is not a regular file", path)
	}
	for {
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrHeld
		}
		return nil, fmt.Errorf("the relay-login lock file %s: %w", path, err)
	}
	return &Lock{release: f.Close}, nil // closing the descriptor drops the lock
}
