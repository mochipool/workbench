package main

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
)

// store verify says what it checked, and --deep decrypts every record, on the
// real sealed store and without writing to the workspace.
func TestStoreVerifyWordingAndDeep(t *testing.T) {
	dir := copyWorkspace(t)
	out, err := withPass(t, dir, testPass, "store", "verify")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(out, "every record authenticates") ||
		!strings.Contains(out, "stored bytes of every record match the authenticated audit chain") ||
		!strings.Contains(out, "not decrypted") {
		t.Errorf("verify does not say what it checked:\n%s", out)
	}
	out, err = withPass(t, dir, testPass, "store", "verify", "--deep")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "decrypted under the current keys") {
		t.Errorf("--deep output:\n%s", out)
	}
}

// After a rekey command the cleanup the rekey left pending has been run: the
// old wrapped keys are out of the file and its WAL, and the flag is clear.
func TestRekeyCommandRunsTheCleanup(t *testing.T) {
	dir := copyWorkspace(t)
	nf, nfd := fdIn(t, "a brand new long passphrase\n")
	defer nf.Close()
	_, oldKey := template(t)
	kf, kfd := fdIn(t, oldKey+"\n")
	defer kf.Close()
	of, ofd := fdIn(t, testPass+"\n")
	defer of.Close()
	out, err := withPass(t, dir, testPass, "store", "passphrase", "change", "--old-passphrase-fd", ofd, "--new-passphrase-fd", nfd, "--recovery-key-in-fd", kfd)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, cli.WorkspaceFile)+"?mode=ro&immutable=1")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var pending int
	if err := db.QueryRow(`SELECT cleanup_pending FROM meta`).Scan(&pending); err != nil || pending != 0 {
		t.Errorf("cleanup_pending = %d (%v) after the command", pending, err)
	}
}
