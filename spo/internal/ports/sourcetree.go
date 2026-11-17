package ports

import "context"

// SourceTree names the directories directly inside a source directory, so
// that an import can look below the folder it was given (to a bounded depth).
// A directory entry that is a symbolic link is never listed: a link is not
// followed (SPO-Xmulti-SEC-001).
type SourceTree interface {
	// Subdirs returns the names (not paths) of the real directories inside
	// the source, hidden ones excluded, sorted.
	Subdirs(ctx context.Context) ([]string, error)
}
