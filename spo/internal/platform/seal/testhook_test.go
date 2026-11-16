package seal

// The only place the Argon2id floor is lowered. Test files are not part of
// the package non-test code sees, so production cannot reach this.
func init() {
	kdfFloor = KDFParams{MemoryKiB: 64, Passes: 1, Lanes: 1}
}

// withProductionFloor restores the real floor for the duration of a test.
func withProductionFloor(t interface{ Cleanup(func()) }) {
	old := kdfFloor
	kdfFloor = MinKDF()
	t.Cleanup(func() { kdfFloor = old })
}
