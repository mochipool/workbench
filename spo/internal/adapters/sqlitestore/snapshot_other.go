//go:build !unix

package sqlitestore

// snapshotLocking is false: lock_other.go takes no lock, so ReadSnapshot and
// WriteSnapshotFile refuse with ErrSnapshotPlatform.
const snapshotLocking = false
