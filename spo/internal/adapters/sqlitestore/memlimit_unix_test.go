//go:build unix

package sqlitestore

import "golang.org/x/sys/unix"

// setMemlockLimit lowers RLIMIT_MEMLOCK (soft and hard) of this process.
func setMemlockLimit(n uint64) error {
	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: n, Max: n})
}
