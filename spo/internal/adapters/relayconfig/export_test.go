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

// SetRootUID replaces the uid that counts as root for the key file's form and
// returns the func that puts it back.
func SetRootUID(uid int) (restore func()) {
	old := rootUID
	rootUID = uid
	return func() { rootUID = old }
}

// SetReadMounted replaces the reader of a root-owned key file (the Secret
// volume's rules, platform/mountfile) and returns the func that puts it back.
func SetReadMounted(f func(path string) ([]byte, error)) (restore func()) {
	old := readMounted
	readMounted = f
	return func() { readMounted = old }
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
