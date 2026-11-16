//go:build unix && !linux

package filebag

func ownedOutsideNamespace(uint32) bool { return false }
