//go:build !unix

package filebag

// noFollow and nonBlock are unavailable here; read checks the opened file is
// regular and next has already refused links with Lstat.
const (
	noFollow = 0
	nonBlock = 0
)
