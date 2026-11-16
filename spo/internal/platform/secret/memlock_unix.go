//go:build unix

package secret

import "golang.org/x/sys/unix"

// raiseMemlock lifts the soft RLIMIT_MEMLOCK to the hard limit (allowed
// without privilege) and returns the limit now in force. The error is from
// raising; the returned limit is valid regardless.
func raiseMemlock() (limit uint64, unlimited bool, err error) {
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rl); err != nil {
		return 0, true, err // cannot tell: do not impose a limit of our own
	}
	if rl.Cur != rl.Max {
		want := unix.Rlimit{Cur: rl.Max, Max: rl.Max}
		if err = unix.Setrlimit(unix.RLIMIT_MEMLOCK, &want); err == nil {
			rl = want
		}
	}
	return uint64(rl.Cur), rl.Cur >= 1<<62, err
}
