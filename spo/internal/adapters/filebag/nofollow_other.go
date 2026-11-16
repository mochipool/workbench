//go:build !unix

package filebag

import (
	"fmt"
	"os"
)

// noFollow and nonBlock are unavailable here; read checks the opened file is
// regular and next has already refused links with Lstat.
const (
	noFollow = 0
	nonBlock = 0
)

func openDirNoFollow(dir string) (*os.File, error) {
	st, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return nil, fmt.Errorf("%s is a symbolic link or not a directory", dir)
	}
	return os.Open(dir)
}
