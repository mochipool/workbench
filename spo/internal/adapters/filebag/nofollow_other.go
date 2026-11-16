//go:build !unix

package filebag

// noFollow is unavailable here; read checks the opened file is regular and
// Receive has already refused links with Lstat.
const noFollow = 0
