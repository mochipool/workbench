//go:build !unix

package relaylock

// Acquire has no lock on this platform: it succeeds, and two processes are not
// kept apart (see the package comment).
func Acquire(string) (*Lock, error) { return &Lock{}, nil }
