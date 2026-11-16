//go:build !linux

package cardanocli

// memoryBacked reports false: this platform has no memory-backed file system
// the adapter can verify, so KES and VRF generation is refused here until
// native generation exists.
func memoryBacked(string) bool { return false }
