//go:build unix && !linux

package secret

import "golang.org/x/sys/unix"

// HardenProcess disables core dumps.
func HardenProcess() error {
	return unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
}
