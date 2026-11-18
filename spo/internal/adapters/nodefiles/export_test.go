package nodefiles

// WithFS returns a writer whose file-system rule is f. It is the only way the
// rule is relaxed, and it exists in test builds of this package only.
func WithFS(f func(fsType int64) bool) Writer { return Writer{allowFS: f} }

// RamfsMagic is the file-system type the release rule accepts.
const RamfsMagic = ramfsMagic
