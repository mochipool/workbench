package fsstore

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// A symbolic link to a folder is not a sub-folder and a symbolic link to a
// file is listed as ignored, not as an artefact; hidden folders are skipped.
//
// spec: SPO-Xmulti-SEC-001
func TestSubdirsNeverFollowsLinks(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.Mkdir(filepath.Join(root, "real"), 0o700))
	must(os.Mkdir(filepath.Join(root, ".hidden"), 0o700))
	must(os.Symlink(outside, filepath.Join(root, "linked")))
	must(os.WriteFile(filepath.Join(outside, "w.staking.vkey"), []byte("x"), 0o600))
	must(os.Symlink(filepath.Join(outside, "w.staking.vkey"), filepath.Join(root, "l.staking.vkey")))
	s, err := Open(root)
	must(err)
	got, err := s.Subdirs(context.Background())
	must(err)
	if !reflect.DeepEqual(got, []string{"real"}) {
		t.Errorf("subdirs %v", got)
	}
	l, err := s.List(context.Background())
	must(err)
	if len(l.Entries) != 0 {
		t.Errorf("entries %v", l.Entries)
	}
	links := 0
	for _, u := range l.Unknown {
		if u.File == "linked" || u.File == "l.staking.vkey" {
			links++
		}
	}
	if links != 2 {
		t.Errorf("unknown %v", l.Unknown)
	}
}
