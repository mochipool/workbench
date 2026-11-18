package ports

import (
	"errors"
	"io"
	"time"
)

// ErrScratchUnsafe is returned when a scratch name resolves to something a
// private file must not be: a file with another owner, with more than one
// link, a device, or a directory where a file is wanted.
var ErrScratchUnsafe = errors.New("the scratch file is not a private regular file of this user")

// ScratchKind says what a scratch entry is, from lstat (a symbolic link is
// never followed).
type ScratchKind int

const (
	ScratchRegular ScratchKind = iota + 1
	ScratchDirectory
	ScratchSymlink
	ScratchOther
)

// ScratchEntry is one top-level entry of the scratch directory.
type ScratchEntry struct {
	Name    string
	Kind    ScratchKind
	Owned   bool // owned by the user running the process
	ModTime time.Time
}

// ScratchFile is an open private file.
type ScratchFile interface {
	io.Reader
	io.Writer
	io.Seeker
	io.Closer
	Truncate(size int64) error
	Sync() error
}

// Scratch is private scratch space in the workspace directory: files of mode
// 0600 and directories of mode 0700, names of one or two path components (a
// directory and a file in it), never a symbolic link followed. A use case that
// needs a temporary or partial file asks for it here instead of touching the
// file system.
type Scratch interface {
	// MakeDir creates a private directory whose name starts with prefix and
	// returns its name.
	MakeDir(prefix string) (string, error)
	// Path is the path of name, for code that wants a path (the existing backup,
	// verification and restore take one).
	Path(name string) string
	// Open creates or opens the file name for reading and writing. A symbolic
	// link at the name is removed (the link, never its target) and the file made
	// again. A file with another owner, with a link count above one, or that is
	// not regular is refused with ErrScratchUnsafe.
	Open(name string) (ScratchFile, error)
	// Remove deletes a file, a symbolic link (the link itself) or a directory
	// tree, never following a link.
	Remove(name string) error
	// Entries lists the top-level entries of the scratch directory.
	Entries() ([]ScratchEntry, error)
}
