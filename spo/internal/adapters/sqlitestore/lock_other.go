//go:build !unix

package sqlitestore

import "os"

const openHeadFlags = 0

var currentUID = os.Getuid

func checkOwner(string, os.FileInfo) error { return nil }

// lockFile has no locking on this platform: it only opens the file.
func lockFile(path string, _ bool) (*os.File, error) { return os.Open(path) }

func upgradeLock(*os.File) error   { return nil }
func downgradeLock(*os.File) error { return nil }

// withHeadLock has no locking on this platform.
func withHeadLock(_ string, fn func() error) error { return fn() }
