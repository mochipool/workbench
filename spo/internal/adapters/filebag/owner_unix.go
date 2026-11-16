//go:build unix

package filebag

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// ownedByMe reports an error unless the directory belongs to the user running
// the program.
func ownedByMe(st os.FileInfo) error {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot tell who owns it")
	}
	if int(sys.Uid) != os.Geteuid() {
		return fmt.Errorf("it is owned by uid %d, not by you (uid %d)", sys.Uid, os.Geteuid())
	}
	return nil
}

func sameFile(a, b os.FileInfo) bool { return os.SameFile(a, b) }

// ancestorFloor, when not empty, is the highest directory CheckAncestors
// looks at (it is checked, nothing above it is). It exists only for tests,
// whose temporary directories sit under ancestors the test does not own. It is
// never set by the program.
var ancestorFloor string

// CheckAncestors applies the rule sshd uses under StrictModes to every
// directory above path (the directory that holds it, then its parent, up to
// the filesystem root), after links are resolved: it must be owned by root or
// by the user running the program, and must not be writable by group or
// others unless it has the sticky bit (/tmp). Whoever may rename or replace
// such a directory can put another one where the inbox, or a snapshot, is.
func CheckAncestors(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return err
	}
	for d := filepath.Dir(real); ; d = filepath.Dir(d) {
		st, err := os.Lstat(d)
		if err != nil {
			return err
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("cannot tell who owns %s", d)
		}
		// The one exception is the root directory itself when its owner has
		// no mapping in this user namespace (a rootless container, a build
		// sandbox). It is NOT extended to other ancestors: inside a user
		// namespace every unmapped host user looks the same, so a bind mount
		// owned by another unprivileged host user would pass.
		if sys.Uid != 0 && int(sys.Uid) != os.Geteuid() && !(d == "/" && ownedOutsideNamespace(sys.Uid)) {
			return fmt.Errorf("%s, above %s, is owned by uid %d, who is neither root nor you: it could be replaced", d, path, sys.Uid)
		}
		if st.Mode().Perm()&0o022 != 0 && st.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("%s, above %s, is writable by its group or by others (mode %04o) and has no sticky bit: somebody else could replace what is below it", d, path, st.Mode().Perm())
		}
		if d == "/" || d == filepath.Dir(d) || (ancestorFloor != "" && d == ancestorFloor) {
			return nil
		}
	}
}
