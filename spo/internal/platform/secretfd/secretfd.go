// Package secretfd is the one place a secret is written to an inherited file
// descriptor. The release binary must be unable to put a signing key or other
// secret on persistent storage unencrypted, so a descriptor that could be a
// file is refused: only a pipe or a Unix socket is accepted.
package secretfd

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// ErrNotAPipe means a descriptor given to receive a secret is not a pipe or a
// socket, or is not open for writing.
var ErrNotAPipe = errors.New("secret output descriptor refused")

// Check says whether fd may receive a secret. It accepts a pipe (FIFO) or a
// Unix-domain socket that is open for writing. It refuses a network socket, a regular file, a
// directory, a block or character device (a terminal included: a secret
// shown on a terminal goes through the interactive display, not this flag),
// descriptors 0, 1 and 2, and a descriptor that is not open. flag names the
// option for the message. Check changes nothing: run it before any effect.
func Check(flag string, fd int) error {
	if fd < 0 {
		return fmt.Errorf("%w: --%s needs a file descriptor number; %s", ErrNotAPipe, flag, tail(flag))
	}
	if fd <= 2 {
		return fmt.Errorf("%w: --%s %d is standard input, output or error, where a secret mixes with other output; %s", ErrNotAPipe, flag, fd, tail(flag))
	}
	var st unix.Stat_t
	for {
		err := unix.Fstat(fd, &st)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return fmt.Errorf("%w: --%s %d is not an open file descriptor (%v); %s", ErrNotAPipe, flag, fd, err, tail(flag))
		}
		break
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFIFO:
	case unix.S_IFSOCK:
		// Only a Unix-domain socket: a TCP or other network socket would send
		// the secret off the machine.
		sa, err := unix.Getsockname(fd)
		if err != nil {
			return fmt.Errorf("%w: --%s %d: %v", ErrNotAPipe, flag, fd, err)
		}
		if _, ok := sa.(*unix.SockaddrUnix); !ok {
			return fmt.Errorf("%w: --%s %d is a network socket, not a Unix socket; %s", ErrNotAPipe, flag, fd, tail(flag))
		}
	default:
		return fmt.Errorf("%w: --%s %d is %s; %s", ErrNotAPipe, flag, fd, kind(st.Mode&unix.S_IFMT), tail(flag))
	}
	fl, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return fmt.Errorf("%w: --%s %d: %v", ErrNotAPipe, flag, fd, err)
	}
	if fl&unix.O_ACCMODE == unix.O_RDONLY {
		return fmt.Errorf("%w: --%s %d is open for reading only; %s", ErrNotAPipe, flag, fd, tail(flag))
	}
	return nil
}

func tail(flag string) string {
	return "a secret is never written to a file: pass the write end of a pipe (to a password manager, or to the process that consumes the secret), or omit --" + flag + " to have it shown once on the terminal"
}

func kind(m uint32) string {
	switch m {
	case unix.S_IFREG:
		return "a regular file"
	case unix.S_IFDIR:
		return "a directory"
	case unix.S_IFBLK:
		return "a block device"
	case unix.S_IFCHR:
		return "a character device (a terminal is one)"
	case unix.S_IFLNK:
		return "a symbolic link"
	}
	return "not a pipe or a socket"
}

// Write checks fd and then writes data to it completely. It is the only
// writer of a secret to a descriptor.
func Write(flag string, fd int, data []byte) error {
	if err := Check(flag, fd); err != nil {
		return err
	}
	for len(data) > 0 {
		n, err := unix.Write(fd, data)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			if e, ok := err.(unix.Errno); ok {
				err = errors.New(e.Error())
			}
			return fmt.Errorf("cannot write to file descriptor %d: %w", fd, err)
		}
		data = data[n:]
	}
	return nil
}
