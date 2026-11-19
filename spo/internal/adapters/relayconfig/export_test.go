package relayconfig

import (
	"os"
	"syscall"
	"time"
)

// SetEuid replaces the effective uid Load compares owners with and returns the
// func that puts it back.
func SetEuid(f func() int) (restore func()) {
	old := geteuid
	geteuid = f
	return func() { geteuid = old }
}

// OwnerOK is ownerOK for a file owned by uid.
func OwnerOK(uid, euid int) bool { return ownerOK(fakeInfo{uid}, euid) }

type fakeInfo struct{ uid int }

func (fakeInfo) Name() string       { return "f" }
func (fakeInfo) Size() int64        { return 0 }
func (fakeInfo) Mode() os.FileMode  { return 0o600 }
func (fakeInfo) ModTime() time.Time { return time.Time{} }
func (fakeInfo) IsDir() bool        { return false }
func (f fakeInfo) Sys() any         { return &syscall.Stat_t{Uid: uint32(f.uid)} }
