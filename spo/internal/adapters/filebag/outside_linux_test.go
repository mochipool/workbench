//go:build linux

package filebag

import "testing"

// An ancestor owned by the overflow id is trusted only when that id has no
// mapping in this user namespace (a rootless container, a build sandbox).
func TestOutsideOwnerIsTheUnmappedOverflowIDOnly(t *testing.T) {
	for _, c := range []struct {
		name        string
		uid         uint32
		overflow, m string
		want        bool
	}{
		{"sandbox: only the build user is mapped", 65534, "65534", "1000 1000 1", true},
		{"host: everything is mapped, nobody is a real user", 65534, "65534", "0 0 4294967295", false},
		{"container that maps nobody", 65534, "65534", "0 100000 65536", false},
		{"another uid", 1001, "65534", "1000 1000 1", false},
		{"no overflow id readable", 65534, "", "1000 1000 1", false},
		{"no map readable", 65534, "65534", "", false},
		{"a malformed map", 65534, "65534", "garbage", false},
	} {
		if got := outside(c.uid, c.overflow, c.m); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}
