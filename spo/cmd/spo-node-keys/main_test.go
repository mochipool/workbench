package main

import (
	"os"
	"path/filepath"
	"testing"
)

// spec: SPO-Xcustody-IF-006, SPO-Xcustody-PRE-014
func TestHelperUsageAndTheReleaseFileSystemRule(t *testing.T) {
	for _, args := range [][]string{nil, {"export"}, {"deliver"}, {"deliver", "--from", "x"}, {"deliver", "--to", "x"}, {"deliver", "--from", "a", "--to"}, {"deliver", "--bogus", "x"}} {
		if code := run(args, func(string) string { return "" }); code != 2 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
	// With the release rule a test directory, which is on disk or tmpfs, is no place for
	// an identity or a key: nothing is read or written.
	root := t.TempDir()
	for _, d := range []string{"from", "to", "creds"} {
		os.Mkdir(filepath.Join(root, d), 0o700)
	}
	os.WriteFile(filepath.Join(root, "creds", "spo-node-age-identity"), []byte("AGE-SECRET-KEY-1QQQ\n"), 0o400)
	code := run([]string{"deliver", "--from", filepath.Join(root, "from"), "--to", filepath.Join(root, "to")},
		func(k string) string {
			if k == "CREDENTIALS_DIRECTORY" {
				return filepath.Join(root, "creds")
			}
			return ""
		})
	if code != 1 {
		t.Errorf("exit %d", code)
	}
	if ents, _ := os.ReadDir(filepath.Join(root, "to")); len(ents) != 0 {
		t.Errorf("wrote %v", ents)
	}
}
