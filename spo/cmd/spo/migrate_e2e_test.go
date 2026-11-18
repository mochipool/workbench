package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
)

// A workspace of the old format (records keyed by name) is refused by every
// command, naming `spo workspace migrate`; the migration converts it, keeps a
// copy beside it, and the workspace then works by name: a wallet is renamed with
// one command and the pool that names it by key hash is unaffected.
//
// spec: SPO-Xidentity-IF-003, SPO-Xidentity-IF-005
func TestMigrateCommandAndRenameOnAnOldWorkspace(t *testing.T) {
	const pass = "legacy fixture passphrase"
	src, err := os.ReadFile(filepath.Join("..", "..", "internal", "adapters", "sqlitestore", "testdata", "legacy-v1", "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, cli.WorkspaceFile), src, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "spo.toml"), []byte("network = \"preview\"\nmode = \"offline\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := withPass(t, dir, pass, "pool", "descriptor", "show", "pool1")
	if err == nil || !strings.Contains(err.Error(), "spo workspace migrate") {
		t.Fatalf("a command on an old workspace: %v\n%s", err, out)
	}
	out, err = withPass(t, dir, pass, "workspace", "migrate")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{"Migrated", "pre-migrate-v1", "descriptor of pool pool1", "unassigned"} {
		if !strings.Contains(out, want) && want != "unassigned" {
			t.Errorf("the report lacks %q:\n%s", want, out)
		}
	}
	if m, _ := filepath.Glob(filepath.Join(dir, cli.WorkspaceFile+".pre-migrate-v1*")); len(m) != 1 {
		t.Errorf("backup files: %v", m)
	}
	// a second migrate has nothing to do
	if _, err := withPass(t, dir, pass, "workspace", "migrate"); err == nil {
		t.Error("migrating a migrated workspace was accepted")
	}
	// the workspace works by name, and a rename is one command
	if out, err = withPass(t, dir, pass, "pool", "descriptor", "show", "pool1"); err != nil || !strings.Contains(out, "pool1") {
		t.Fatalf("descriptor show: %v\n%s", err, out)
	}
	if out, err = withPass(t, dir, pass, "wallet", "rename", "alice", "alicia"); err != nil || !strings.Contains(out, "alicia") {
		t.Fatalf("rename: %v\n%s", err, out)
	}
	if _, err = withPass(t, dir, pass, "wallet", "rename", "alice", "again"); err == nil {
		t.Error("a name that no longer exists was renamed")
	}
	if _, err = withPass(t, dir, pass, "wallet", "rename", "bob", "alicia"); err == nil {
		t.Error("a name another wallet has was taken")
	}
	if out, err = withPass(t, dir, pass, "pool", "descriptor", "show", "pool1"); err != nil {
		t.Fatalf("the pool after the rename: %v\n%s", err, out)
	}
}

// A workspace of store format 2 is refused by every command, naming `spo
// workspace migrate`, before any key is derived; the migration converts it to
// format 3 (policy standard, slots unchanged), keeps a copy named
// pre-migrate-v2, and the workspace then opens with the same passphrase.
//
// spec: SPO-Xunlock-PRE-022, SPO-Xunlock-OUT-008
func TestMigrateCommandOnAFormat2Workspace(t *testing.T) {
	const pass = "legacy fixture passphrase"
	src, err := os.ReadFile(filepath.Join("..", "..", "internal", "adapters", "sqlitestore", "testdata", "legacy-v2", "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, cli.WorkspaceFile), src, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "spo.toml"), []byte("network = \"preview\"\nmode = \"offline\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := withPass(t, dir, pass, "store", "slots")
	if err == nil || !strings.Contains(err.Error(), "spo workspace migrate") || !strings.Contains(err.Error(), "format 2") {
		t.Fatalf("a command on a format 2 workspace: %v\n%s", err, out)
	}
	if out, err = withPass(t, dir, pass, "workspace", "migrate"); err != nil || !strings.Contains(out, "format 3") {
		t.Fatalf("%v\n%s", err, out)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, cli.WorkspaceFile+".pre-migrate-v2*")); len(m) != 1 {
		t.Errorf("backup files: %v", m)
	}
	out, err = withPass(t, dir, pass, "store", "slots")
	if err != nil || !strings.Contains(out, "passphrase") || !strings.Contains(out, "legacy (rekey to bind policy)") {
		t.Fatalf("slots after the migration: %v\n%s", err, out)
	}
	if _, err := withPass(t, dir, pass, "workspace", "migrate"); err == nil {
		t.Error("migrating a migrated workspace was accepted")
	}
}

func fixtureVKey(typ, label string) string {
	s := sha256.Sum256([]byte("legacy fixture seed " + label))
	pub := ed25519.NewKeyFromSeed(s[:]).Public().(ed25519.PublicKey)
	return `{"type":"` + typ + `","description":"","cborHex":"5820` + hex.EncodeToString(pub) + `"}`
}

// `wallet merge NAME --from DIR` accepts a directory whose wallet has the member set
// of the workspace's (here the same anchor: nothing to add) and refuses one whose
// member set differs; `rename` refuses a name another wallet has.
//
// spec: SPO-Xidentity-IF-003, SPO-Xidentity-IF-004
func TestMergeAndRenameCommands(t *testing.T) {
	const pass = "legacy fixture passphrase"
	src, err := os.ReadFile(filepath.Join("..", "..", "internal", "adapters", "sqlitestore", "testdata", "legacy-v1", "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, cli.WorkspaceFile), src, 0o600)
	os.WriteFile(filepath.Join(dir, "spo.toml"), []byte("network = \"preview\"\nmode = \"offline\"\n"), 0o600)
	if out, err := withPass(t, dir, pass, "workspace", "migrate"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	same := t.TempDir()
	os.WriteFile(filepath.Join(same, "alice.payment.vkey"), []byte(fixtureVKey("PaymentVerificationKeyShelley_ed25519", "alice payment")), 0o600)
	os.WriteFile(filepath.Join(same, "alice.staking.vkey"), []byte(fixtureVKey("StakeVerificationKeyShelley_ed25519", "alice stake")), 0o600)
	if out, err := withPass(t, dir, pass, "wallet", "merge", "alice", "--from", same); err != nil || !strings.Contains(out, "alice") {
		t.Fatalf("merge of identical member sets: %v\n%s", err, out)
	}
	partial := t.TempDir()
	// a wallet anchored by its stake key alone: another anchor and another member set
	os.WriteFile(filepath.Join(partial, "alice.staking.vkey"), []byte(fixtureVKey("StakeVerificationKeyShelley_ed25519", "alice stake")), 0o600)
	if _, err := withPass(t, dir, pass, "wallet", "merge", "alice", "--from", partial); err == nil || !strings.Contains(err.Error(), "different member sets") && !strings.Contains(err.Error(), "cannot be merged") {
		t.Fatalf("merge of different member sets: %v", err)
	}
	if _, err := withPass(t, dir, pass, "wallet", "merge", "alice", "--from", t.TempDir()); err == nil {
		t.Error("a merge from a directory that holds no such wallet")
	}
	if _, err := withPass(t, dir, pass, "wallet", "rename", "bob", "alice"); err == nil {
		t.Error("rename onto a name another wallet has")
	}
	if _, err := withPass(t, dir, pass, "wallet", "rename", "bob", "key-hash:"+strings.Repeat("ab", 28)); err == nil {
		t.Error("rename to the form of an identity")
	}
}

// The migration says that its copies hold the cold key in the older form, and
// with --remove-copies unlinks them once the migrated file verifies and opens.
//
// spec: SPO-Xunlock-OUT-008
func TestMigrateRemoveCopies(t *testing.T) {
	const pass = "legacy fixture passphrase"
	src, err := os.ReadFile(filepath.Join("..", "..", "internal", "adapters", "sqlitestore", "testdata", "legacy-v2", "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, remove := range []bool{false, true} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, cli.WorkspaceFile), src, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "spo.toml"), []byte("network = \"preview\"\nmode = \"offline\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		args := []string{"workspace", "migrate"}
		if remove {
			args = append(args, "--remove-copies")
		}
		out, err := withPass(t, dir, pass, args...)
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		if !strings.Contains(out, "older format") || !strings.Contains(out, "best effort") {
			t.Errorf("the notice is missing:\n%s", out)
		}
		m, _ := filepath.Glob(filepath.Join(dir, cli.WorkspaceFile+".pre-migrate-v2*"))
		if remove && len(m) != 0 || !remove && len(m) != 1 {
			t.Errorf("remove=%v: copies left %v\n%s", remove, m, out)
		}
	}
}
