//go:build !linux

package filebag

import "os"

// localFS cannot tell a remote file system on this platform.
func localFS(*os.File) error { return nil }
