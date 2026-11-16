//go:build linux

package secret

import "golang.org/x/sys/unix"

// HardenProcess disables core dumps and makes the process undumpable, so its
// memory cannot be read through a core file or by ptrace from the same user.
func HardenProcess() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return err
	}
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
