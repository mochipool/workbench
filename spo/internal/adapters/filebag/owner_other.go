//go:build !unix

package filebag

import "os"

func ownedByMe(os.FileInfo) error { return nil }

// CheckAncestors cannot judge the ancestors on this platform.
func CheckAncestors(string) error { return nil }

func sameFile(a, b os.FileInfo) bool { return os.SameFile(a, b) }
