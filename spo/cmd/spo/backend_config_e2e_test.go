package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// spo.toml decides where the Vault token goes, so a spo.toml that someone else
// can change names no backend: with the file writable by its group, an unlock
// through the backend and an enrolment are refused before any prompt, any
// credential or any call, and the refusal names the file and the remedy. A
// command that uses no backend keeps working with the same file, and once the
// mode is put right the backend opens again.
//
// spec: SPO-Xunlock-PRE-050
func TestASpoTomlOthersCanChangeNamesNoBackend(t *testing.T) {
	v, srv := newE2EVault(t)
	dir := copyWorkspace(t)
	toml := filepath.Join(dir, "spo.toml")
	b, err := os.ReadFile(toml)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(toml, append(b, vaultTOML(srv.URL)...), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VAULT_TOKEN", v.token)
	_, pfd := fdIn(t, testPass+"\n")
	_, npfd := fdIn(t, compositePassE2E+"\n")
	if out, err := exec(t, nil, "-C", dir, "--passphrase-fd", pfd, "workspace", "slot", "add-backend", "--backend", "vault", "--with", "passphrase", "--new-passphrase-fd", npfd); err != nil {
		t.Fatalf("add-backend: %v\n%s", err, out)
	}

	if err := os.Chmod(toml, 0o620); err != nil {
		t.Fatal(err)
	}
	before := v.calls.Load()
	term := &fakeTerm{secrets: []string{compositePassE2E}}
	out, err := exec(t, term, "-C", dir, "--unlock", "backend", "store", "verify")
	if err == nil || !strings.Contains(err.Error(), toml) || !strings.Contains(err.Error(), "chmod 600") || !strings.Contains(err.Error(), "group or others") {
		t.Fatalf("an unlock through a spo.toml others can change: %v\n%s", err, out)
	}
	if len(term.asked) != 0 || v.calls.Load() != before {
		t.Errorf("asked %v, %d backend calls", term.asked, v.calls.Load()-before)
	}
	if strings.Contains(out, "asking vault-transit") {
		t.Errorf("the notice was printed:\n%s", out)
	}
	_, pfd = fdIn(t, testPass+"\n")
	_, npfd = fdIn(t, compositePassE2E+"\n")
	out, err = exec(t, nil, "-C", dir, "--passphrase-fd", pfd, "workspace", "slot", "add-backend", "--backend", "vault", "--with", "passphrase", "--new-passphrase-fd", npfd)
	if err == nil || !strings.Contains(err.Error(), toml) || v.calls.Load() != before {
		t.Fatalf("an enrolment through a spo.toml others can change: %v (%d calls)\n%s", err, v.calls.Load()-before, out)
	}
	// the passphrase still opens the workspace; the file's other settings are read
	if err := withPassStoreVerify(t, dir); err != nil {
		t.Fatalf("a command without a backend: %v", err)
	}

	if err := os.Chmod(toml, 0o600); err != nil {
		t.Fatal(err)
	}
	_, cfd := fdIn(t, compositePassE2E+"\n")
	if out, err := exec(t, nil, "-C", dir, "--unlock", "backend", "--passphrase-fd", cfd, "store", "verify"); err != nil {
		t.Fatalf("after chmod 600: %v\n%s", err, out)
	}
}

// The review's proof of concept through the binary: spo.toml is a symbolic
// link to a file any user can write, with a [vault] section another user
// planted. A command that rewrites spo.toml (mode set, provider order) is
// refused with the file and the remedy; the link and the planted file are
// unchanged, so the next backend unlock still refuses the file.
//
// spec: SPO-Xunlock-PRE-051
func TestARewriteThroughTheBinaryNeverLaundersASpoToml(t *testing.T) {
	dir := copyWorkspace(t)
	toml := filepath.Join(dir, "spo.toml")
	b, err := os.ReadFile(toml)
	if err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(t.TempDir(), "planted.toml")
	text := append(b, vaultTOML("https://vault.attacker.example")...)
	if err := os.WriteFile(planted, text, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(planted, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(toml); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(planted, toml); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"mode", "set", "offline"}, {"provider", "set", "node", "/run/cardano/node.socket"}} {
		out, err := exec(t, nil, append([]string{"-C", dir}, args...)...)
		if err == nil || !strings.Contains(err.Error(), toml) || !strings.Contains(err.Error(), "not rewritten") || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("%v through a planted link: %v\n%s", args, err, out)
		}
		if fi, err := os.Lstat(toml); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("%v: spo.toml is no longer the link: %v", args, err)
		}
		if got, err := os.ReadFile(planted); err != nil || string(got) != string(text) {
			t.Fatalf("%v: the planted file changed: %v", args, err)
		}
	}
}
