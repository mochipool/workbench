//go:build !unix

package secret

// raiseMemlock: platforms without RLIMIT_MEMLOCK get no budget of our own.
func raiseMemlock() (uint64, bool, error) { return 0, true, nil }
