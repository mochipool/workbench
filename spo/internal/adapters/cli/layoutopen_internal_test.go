package cli

import (
	"os"
	"testing"
	"time"
)

// The owner, mode, kind and age test of the sweep of stale scratch directories,
// without a second user: the uid of the entry is a parameter.
//
// spec: SPO-Xlayout-MODE-006
func TestStaleScratchIsOnlyAnOldPrivateDirectoryOfThisUser(t *testing.T) {
	const me = 1000
	old := staleLayoutOpen + time.Minute
	cases := []struct {
		name  string
		isDir bool
		perm  os.FileMode
		owner int
		age   time.Duration
		want  bool
	}{
		{"an old private directory of mine", true, 0o700, me, old, true},
		{"exactly a day old", true, 0o700, me, staleLayoutOpen, true},
		{"another user's", true, 0o700, me + 1, old, false},
		{"root's", true, 0o700, 0, old, false},
		{"an owner that is not known", true, 0o700, -1, old, false},
		{"too young", true, 0o700, me, staleLayoutOpen - time.Second, false},
		{"group readable", true, 0o750, me, old, false},
		{"world writable", true, 0o777, me, old, false},
		{"a file or a link", false, 0o700, me, old, false},
	}
	for _, c := range cases {
		if got := staleScratch(c.isDir, c.perm, c.owner, me, c.age); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// The mode is read from the stored decision, not from the directory.
//
// spec: SPO-Xlayout-MODE-009
func TestInLayoutIsTheStoredDecision(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(dir+"/heads", 0o700); err != nil {
		t.Fatal(err)
	}
	a := &app{workspace: dir}
	if a.inLayout() {
		t.Error("a mode nobody decided is a layout")
	}
	if err := a.layoutRefuse(nil); err != nil && a.layMode != modeLayout {
		t.Fatal(err)
	}
	if !a.inLayout() {
		t.Fatal("a directory with heads/ and no workspace file is not decided as a layout")
	}
	if err := os.WriteFile(dir+"/"+WorkspaceFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !a.inLayout() {
		t.Error("a workspace file that appeared later changed the decision")
	}
}
