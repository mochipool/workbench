package main

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func upstreamRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := exec(t, nil, append([]string{"-C", dir, "--upstream-layout"}, args...)...)
	if err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return out
}

// nestedUpstream builds <root>/pool (the pool p) and <root>/wallets (its owner
// wallet) with this binary's own upstream-layout commands, and makes the
// descriptor name the wallet by a relative path, as an operator keeping the
// two in separate folders does.
func nestedUpstream(t *testing.T) (root, pools, wallets string) {
	t.Helper()
	root = t.TempDir()
	pools, wallets = filepath.Join(root, "pool"), filepath.Join(root, "wallets")
	for _, d := range []string{pools, wallets} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	upstreamRun(t, wallets, "wallet", "new", "quartz-owner", "--stake")
	for _, a := range [][]string{{"pool", "keys", "generate", "p"}, {"pool", "vrf", "generate", "p"}, {"pool", "kes", "generate", "p"}} {
		upstreamRun(t, pools, a...)
	}
	args := append([]string{"pool", "descriptor", "new", "p", "--owner", "quartz-owner"}, descriptorFlags...)
	upstreamRun(t, pools, args...)
	f := filepath.Join(pools, "p.pool.json")
	b, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	d := strings.ReplaceAll(string(b), `"quartz-owner"`, `"../wallets/quartz-owner"`)
	if d == string(b) {
		t.Fatalf("the descriptor does not name the owner:\n%s", b)
	}
	os.Chmod(f, 0o600)
	if err := os.WriteFile(f, []byte(d), 0o400); err != nil {
		t.Fatal(err)
	}
	return root, pools, wallets
}

// A pool and its wallet kept in separate folders, the descriptor naming the
// wallet by a relative path, are imported with both renamed; afterwards the
// commands that read the descriptor and the counters work with no editing:
// the descriptor shows the flat names, the certificate is generated, and the
// next KES key continues the counter that was imported under the new name.
//
// spec: SPO-Xmulti-IN-004, SPO-Xmulti-OUT-004, SPO-Xmulti-OUT-005, SPO-Xmulti-OUT-006, SPO-Xmulti-OUT-009
func TestImportNestedLayoutWithRenameThenUseThePool(t *testing.T) {
	_, pools, wallets := nestedUpstream(t)
	dir := copyWorkspace(t)
	out, err := withPass(t, dir, testPass, "workspace", "import", pools, wallets, "--all",
		"--rename", "pool:p=q", "--rename", "wallet:quartz-owner=boss")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "descriptor rewrites", `"../wallets/quartz-owner" -> "boss"`, `"p" -> "q"`)

	desc, err := withPass(t, dir, testPass, "pool", "descriptor", "show", "q")
	if err != nil {
		t.Fatalf("%v\n%s", err, desc)
	}
	mustHave(t, desc, `"poolName": "q"`, `"ownerName": "boss"`, `"poolRewards": "boss"`, `"poolPledge": "100000000"`)
	if strings.Contains(desc, "..") || strings.Contains(desc, "quartz-owner") {
		t.Errorf("the descriptor still holds the old names:\n%s", desc)
	}

	genesis := writeGenesis(t)
	file := filepath.Join(t.TempDir(), "offlineTransfer.json")
	_, addr := walletKey()
	poolSnapshot(t, file, addr)
	out, err = exec2(t, dir, nil, "pool", "cert", "generate", "q", "--transfer-file", file, "--shelley-genesis", genesis)
	if err != nil {
		t.Fatalf("pool cert generate: %v\n%s", err, out)
	}
	mustHave(t, out, "Generated the registration certificate of pool q")

	// The KES key, its counters and the cold counter came along under the new
	// name: the newest KES key has no certificate yet (the refusal says so), the
	// certificate is issued for it, and the next key is number 1.
	if out, err = exec2(t, dir, nil, "pool", "kes", "generate", "q"); err == nil || !strings.Contains(err.Error(), "has not been used for an operational certificate") {
		t.Fatalf("kes generate before the certificate: %v\n%s", err, out)
	}
	if out, err = exec2(t, dir, nil, "pool", "opcert", "issue", "q", "--shelley-genesis", genesis); err != nil {
		t.Fatalf("pool opcert issue: %v\n%s", err, out)
	}
	out, err = exec2(t, dir, nil, "pool", "kes", "generate", "q")
	if err != nil {
		t.Fatalf("pool kes generate: %v\n%s", err, out)
	}
	mustHave(t, out, "Generated KES key 001 for pool q")

	// Nothing of the old names is in the workspace.
	for _, name := range []string{"p", "quartz-owner"} {
		if o, err := exec2(t, dir, nil, "pool", "descriptor", "show", name); err == nil {
			t.Errorf("%s is still in the workspace:\n%s", name, o)
		}
	}
}

// dirDigest maps every entry under dir (files with a hash of their content,
// directories and links by name and mode) to what it is, so that two states of
// a workspace directory can be compared exactly, the audit and session files
// included.
func dirDigest(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			l, _ := os.Readlink(p)
			out[rel] = "link " + l
		case d.IsDir():
			out[rel] = "dir " + info.Mode().String()
		default:
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			out[rel] = fmt.Sprintf("file %s %x", info.Mode(), sha256.Sum256(b))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// With --dry-run nothing in the workspace directory changes: not a record, not
// the audit log, not a session or lock file. Every file is compared by hash
// before and after, and the pool is not there afterwards.
//
// spec: SPO-Xmulti-OUT-010, SPO-Xmulti-INV-001
func TestImportNestedDryRunWritesNothing(t *testing.T) {
	_, pools, wallets := nestedUpstream(t)
	dir := copyWorkspace(t)
	before, srcBefore := dirDigest(t, dir), dirDigest(t, filepath.Dir(pools))
	if len(before) == 0 {
		t.Fatal("the workspace directory is empty")
	}
	out, err := withPass(t, dir, testPass, "workspace", "import", pools, wallets, "--all", "--dry-run")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Dry run: nothing was written", "planned")
	after, srcAfter := dirDigest(t, dir), dirDigest(t, filepath.Dir(pools))
	if !reflect.DeepEqual(before, after) {
		for k, v := range after {
			if before[k] != v {
				t.Errorf("changed or new in the workspace directory: %s (%s, was %q)", k, v, before[k])
			}
		}
		for k := range before {
			if _, ok := after[k]; !ok {
				t.Errorf("removed from the workspace directory: %s", k)
			}
		}
	}
	if !reflect.DeepEqual(srcBefore, srcAfter) {
		t.Error("a source folder changed")
	}
	if o, err := exec2(t, dir, nil, "pool", "descriptor", "show", "p"); err == nil {
		t.Errorf("the pool is in the workspace after a dry run:\n%s", o)
	}
	// opening the workspace to look is not a write either
	if after2 := dirDigest(t, dir); !reflect.DeepEqual(before, after2) {
		t.Error("looking for the pool changed the workspace directory")
	}
	// the digest does see a write: the real import changes it
	if out, err := withPass(t, dir, testPass, "workspace", "import", pools, wallets, "--all"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if reflect.DeepEqual(before, dirDigest(t, dir)) {
		t.Error("the real import left the workspace directory unchanged: the comparison proves nothing")
	}
}

// The guided import on a real pseudo-terminal: reach it from the form of
// `workspace import`, add two folders by typed path, see what was found, select,
// read the plan with the descriptor rewrite, confirm, and find the pool in the
// workspace with the flat names. The passphrase is asked in a hidden modal each
// time the command opens the workspace.
//
// spec: SPO-Xmulti-IF-003, SPO-Xmulti-OUT-009
func TestPTYGuidedImport(t *testing.T) {
	_, pools, wallets := nestedUpstream(t)
	dir := copyWorkspace(t)
	p := startTUI(t, dir, rows, cols)
	p.wait("up/down move")
	p.send("/")
	p.typeText("workspace imp")
	p.send(keyEnter)
	p.wait("ctrl+g guided import")
	p.send("\x07") // ctrl+g
	p.wait("Folders to read")
	p.send("a")
	p.typeText(pools)
	p.send(keyEnter)
	p.send("a")
	p.typeText(wallets)
	p.send(keyEnter)
	p.wait(wallets)
	p.send(keyEnter)
	p.wait("Passphrase")
	p.typeText(testPass)
	p.send(keyEnter)
	p.wait("Owners found")
	p.wait("quartz-owner")
	p.send("a") // every owner that can be imported
	p.send(keyEnter)
	p.wait("Passphrase")
	p.typeText(testPass)
	p.send(keyEnter)
	p.wait("What the import would do")
	p.wait("Changes to pool descriptors")
	p.wait(`"../wallets/quartz-owner" -> "quartz-owner"`)
	p.wait("The same import on the command line")
	p.send(keyEnter)
	p.wait("Passphrase")
	p.typeText(testPass)
	p.send(keyEnter)
	p.wait("2 owner(s) of 2 imported")
	p.send(keyEsc) // back to the menu, still searching
	p.send(keyEsc) // end the search
	p.send("q")
	if st := p.exited(); !st.Success() {
		t.Fatalf("spo tui exited with %v", st)
	}
	p.checkRestored()
	p.noSecretAnywhere(testPass, "battery staple")

	desc, err := withPass(t, dir, testPass, "pool", "descriptor", "show", "p")
	if err != nil {
		t.Fatalf("%v\n%s", err, desc)
	}
	mustHave(t, desc, `"ownerName": "quartz-owner"`, `"poolRewards": "quartz-owner"`)
	if strings.Contains(desc, "..") {
		t.Errorf("the descriptor still names a path:\n%s", desc)
	}
}
