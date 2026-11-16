//go:build linux

package filebag

import (
	"os"
	"strconv"
	"strings"
)

// ownedOutsideNamespace reports whether uid is the kernel's overflow id and
// stands for an owner that has no mapping in this user namespace. That is what
// "/" looks like in a rootless container or a build sandbox: the real owner is
// outside, and no process inside the namespace can be that owner, so it cannot
// replace the directory. CheckAncestors applies this to "/" only: every
// unmapped host user shows as the same id, so for any other directory (a bind
// mount, say) it proves nothing. An overflow id that IS mapped here is an ordinary
// user and is not trusted. When anything cannot be read, the answer is no.
func ownedOutsideNamespace(uid uint32) bool {
	return outside(uid, readTrim("/proc/sys/kernel/overflowuid"), readTrim("/proc/self/uid_map"))
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func outside(uid uint32, overflow, uidMap string) bool {
	of, err := strconv.ParseUint(overflow, 10, 32)
	if err != nil || uint64(uid) != of || uidMap == "" {
		return false
	}
	for _, line := range strings.Split(uidMap, "\n") {
		f := strings.Fields(line)
		if len(f) != 3 {
			return false
		}
		start, e1 := strconv.ParseUint(f[0], 10, 64)
		n, e2 := strconv.ParseUint(f[2], 10, 64)
		if e1 != nil || e2 != nil {
			return false
		}
		if uint64(uid) >= start && uint64(uid) < start+n {
			return false // mapped here: a real user of this namespace
		}
	}
	return true
}
