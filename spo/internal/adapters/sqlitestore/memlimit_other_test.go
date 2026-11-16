//go:build !unix

package sqlitestore

import "errors"

func setMemlockLimit(uint64) error { return errors.New("no RLIMIT_MEMLOCK on this platform") }
