package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
)

// A recovery key sent to a file is refused before the workspace exists, and a
// recovery key that cannot be delivered to a pipe leaves no workspace behind.
//
// spec: SPO-Xcustody-OUT-005, SPO-Xcustody-PRE-006
func TestInitRefusesAFileForTheRecoveryKeyAndLeavesNoWorkspaceWhenDeliveryFails(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ws")
	pf, pfd := fdIn(t, testPass+"\n")
	defer pf.Close()
	plain, err := os.Create(filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	_, err = exec(t, nil, "-C", dir, "init", "--network", "preview", "--passphrase-fd", pfd, "--recovery-key-fd", strconv.Itoa(int(plain.Fd())))
	if err == nil || !strings.Contains(err.Error(), "never written to a file") {
		t.Fatalf("a file was accepted: %v", err)
	}
	if _, serr := os.Stat(filepath.Join(dir, cli.WorkspaceFile)); serr == nil {
		t.Fatal("the workspace was created before the descriptor was refused")
	}

	pf2, pfd2 := fdIn(t, testPass+"\n")
	defer pf2.Close()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	defer w.Close()
	_, err = exec(t, nil, "-C", dir, "init", "--network", "preview", "--passphrase-fd", pfd2, "--recovery-key-fd", strconv.Itoa(int(w.Fd())))
	if err == nil || !strings.Contains(err.Error(), "was removed") {
		t.Fatalf("%v", err)
	}
	for _, n := range []string{cli.WorkspaceFile, "spo.toml"} {
		if _, serr := os.Stat(filepath.Join(dir, n)); serr == nil {
			t.Errorf("%s was left behind with its recovery key undelivered", n)
		}
	}
}
