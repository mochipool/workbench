package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func poolDesc(t *testing.T, dir, name, owner string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	d := `{"poolName":"` + name + `","poolOwner":[{"ownerName":"` + owner + `","ownerWitness":"local"}],"poolRewards":"` + owner + `","poolPledge":"1"}`
	if err := os.WriteFile(filepath.Join(dir, name+".pool.json"), []byte(d), 0o600); err != nil {
		t.Fatal(err)
	}
}

// nested builds <src>/pool (pools) and <src>/wallets (wallets); the pool
// descriptors name their wallet by a relative path.
func (f *wsFix) nested() (pools, wallets string) {
	pools, wallets = filepath.Join(f.src, "pool"), filepath.Join(f.src, "wallets")
	os.MkdirAll(pools, 0o700)
	os.MkdirAll(wallets, 0o700)
	f.wallet(wallets, "owner", f.seed)
	// a pool can only name a wallet that has a stake key
	os.WriteFile(filepath.Join(wallets, "owner.staking.skey"), []byte(skeyText(f.seed)), 0o400)
	os.WriteFile(filepath.Join(wallets, "owner.staking.vkey"), []byte(vkeyText(f.seed)), 0o600)
	poolDesc(f.t, pools, "mypool", "../wallets/owner")
	poolDesc(f.t, pools, "other", "../wallets/owner")
	return
}

func (f *wsFix) read(name string) string {
	b, _ := os.ReadFile(filepath.Join(f.ws, name))
	return string(b)
}

func (f *wsFix) has(name string) bool {
	_, err := os.Stat(filepath.Join(f.ws, name))
	return err == nil
}

// Several folders, a selection and a rename: only what is chosen arrives,
// under the new name, and the descriptor carries the flat name. The table
// shows the folder, the stored name and the rewrite.
//
// spec: SPO-Xmulti-IF-001, SPO-Xmulti-IN-003, SPO-Xmulti-IN-004, SPO-Xmulti-OUT-005, SPO-Xmulti-OUT-009
func TestImportSeveralFoldersSelectAndRename(t *testing.T) {
	f := newWsFix(t)
	pools, wallets := f.nested()
	err := f.run(&scriptTerm{t: t}, "workspace", "import", pools, wallets,
		"--only", "pool:mypool", "--only", "wallet:owner@"+wallets, "--rename", "wallet:owner="+"boss")
	out := f.out.String()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !f.has("boss.skey") || f.has("owner.skey") || f.has("other.pool.json") {
		t.Errorf("wrong files in the workspace\n%s", out)
	}
	d := f.read("mypool.pool.json")
	if !strings.Contains(d, `"ownerName":"boss"`) || !strings.Contains(d, `"poolRewards":"boss"`) || !strings.Contains(d, `"poolPledge":"1"`) {
		t.Errorf("descriptor %s", d)
	}
	mustContain(t, out, "FOLDER", "STORED AS", "boss", pools, wallets, "descriptor rewrites", `"../wallets/owner" -> "boss"`, "other", "not selected")
}

// Nothing is written by a dry run; it prints the plan, and fails when the
// plan would.
//
// spec: SPO-Xmulti-OUT-010, SPO-Xmulti-OUT-009
func TestImportDryRun(t *testing.T) {
	f := newWsFix(t)
	pools, wallets := f.nested()
	if err := f.run(&scriptTerm{t: t}, "workspace", "import", pools, wallets, "--all", "--dry-run"); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	mustContain(t, f.out.String(), "planned", "Dry run: nothing was written", `"../wallets/owner" -> "owner"`)
	if ents, _ := os.ReadDir(f.ws); len(ents) > 1 { // only the workspace file
		t.Errorf("the dry run wrote: %v", ents)
	}
	f.out.Reset()
	err := f.run(&scriptTerm{t: t}, "workspace", "import", pools, wallets, "--only", "pool:mypool", "--dry-run")
	if err == nil || !strings.Contains(err.Error(), "would not be imported") || !strings.Contains(f.out.String(), "--only wallet:owner@") {
		t.Errorf("a refused plan: %v\n%s", err, f.out.String())
	}
}

// The JSON plan carries owners, status and rewrites; --format json needs
// --dry-run.
//
// spec: SPO-Xmulti-IF-001, SPO-Xmulti-OUT-009
func TestImportPlanJSON(t *testing.T) {
	f := newWsFix(t)
	pools, wallets := f.nested()
	if err := f.run(&scriptTerm{t: t}, "workspace", "import", pools, wallets, "--all", "--dry-run", "--format", "json"); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	var p struct {
		DryRun bool `json:"dry_run"`
		Owners []struct {
			Kind, Name, Dir, Status string
			Rewrites                []struct{ Field, Old, New string }
		}
	}
	if err := json.Unmarshal(f.out.Bytes(), &p); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	if !p.DryRun || len(p.Owners) != 3 || p.Owners[0].Dir != pools {
		t.Fatalf("%+v", p)
	}
	for _, o := range p.Owners {
		if o.Status != "would-import" {
			t.Errorf("%+v", o)
		}
		if o.Kind == "pool" && (len(o.Rewrites) != 2 || o.Rewrites[0].New != "owner") {
			t.Errorf("%+v", o)
		}
	}
	if err := f.run(&scriptTerm{t: t}, "workspace", "import", pools, "--all", "--format", "json"); err == nil || !strings.Contains(err.Error(), "--dry-run") {
		t.Errorf("json without dry run: %v", err)
	}
}

// The manifest printed for a set of flags replays the same import; it does
// not combine with the flags it replaces; it never replaces a file.
//
// spec: SPO-Xmulti-IF-002, SPO-Xmulti-PRE-003, SPO-Xmulti-OUT-001
func TestImportManifestRoundTrip(t *testing.T) {
	f := newWsFix(t)
	pools, wallets := f.nested()
	flags := []string{"workspace", "import", pools, wallets, "--only", "pool:mypool", "--only", "wallet:owner", "--rename", "wallet:owner@" + wallets + "=boss", "--depth", "0"}
	if err := f.run(&scriptTerm{t: t}, append(flags, "--print-manifest")...); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	printed := f.out.String()
	mustContain(t, printed, "sources", pools, "pool:mypool", "wallet:owner@"+wallets+"=boss")
	if ents, _ := os.ReadDir(f.ws); len(ents) > 1 {
		t.Errorf("--print-manifest imported: %v", ents)
	}
	mf := filepath.Join(t.TempDir(), "m.toml")
	f.out.Reset()
	if err := f.run(&scriptTerm{t: t}, append(flags, "--manifest-out", mf)...); err != nil {
		t.Fatalf("%v", err)
	}
	if b, _ := os.ReadFile(mf); string(b) != printed {
		t.Errorf("the file differs from the printed manifest:\n%s\n%s", b, printed)
	}
	if err := f.run(&scriptTerm{t: t}, append(flags, "--manifest-out", mf)...); err == nil {
		t.Error("a manifest file was replaced")
	}
	// printing the manifest read back gives the same text
	f.out.Reset()
	if err := f.run(&scriptTerm{t: t}, "workspace", "import", "--manifest", mf, "--print-manifest"); err != nil {
		t.Fatal(err)
	}
	if f.out.String() != printed {
		t.Errorf("round trip:\n%s\n%s", f.out.String(), printed)
	}
	// flags and manifest together
	for _, extra := range [][]string{{pools}, {"--only", "pool:x"}, {"--depth", "1"}, {"--all"}, {"--rename", "pool:a=b"}, {"--owner", "x"}} {
		err := f.run(&scriptTerm{t: t}, append([]string{"workspace", "import", "--manifest", mf}, extra...)...)
		if err == nil || !strings.Contains(err.Error(), "manifest") {
			t.Errorf("%v: %v", extra, err)
		}
	}
	// the manifest alone does the import
	f.out.Reset()
	if err := f.run(&scriptTerm{t: t}, "workspace", "import", "--manifest", mf); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	if !f.has("boss.skey") || !f.has("mypool.pool.json") || !strings.Contains(f.read("mypool.pool.json"), `"ownerName":"boss"`) {
		t.Error("the manifest did not import the selection")
	}
}

// A relative folder in a manifest is relative to the manifest's own folder; a
// malformed or foreign key is refused.
//
// spec: SPO-Xmulti-IF-002
func TestImportManifestParsing(t *testing.T) {
	f := newWsFix(t)
	_, _ = f.nested()
	mf := filepath.Join(f.src, "m.toml")
	os.WriteFile(mf, []byte("# c\nsources = [\"wallets\"] # the folder\ndepth = 0\nall = true\n"), 0o600)
	if err := f.run(&scriptTerm{t: t}, "workspace", "import", "--manifest", mf, "--dry-run"); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	mustContain(t, f.out.String(), "owner", "planned")
	for _, bad := range []string{"bogus = 1\n", "sources = [\"a\"\n", "depth = \"x\"\n", "sources = \"a\"\n", "sources = [1]\n", "all = maybe\n", "depth = 1\ndepth = 2\n", "all = true\n"} {
		os.WriteFile(mf, []byte(bad), 0o600)
		if err := f.run(&scriptTerm{t: t}, "workspace", "import", "--manifest", mf, "--dry-run"); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// Two folders with one wallet name collide; a rename fixes it. Flag
// syntax errors are refused.
//
// spec: SPO-Xmulti-OUT-002, SPO-Xmulti-PRE-001, SPO-Xmulti-PRE-002
func TestImportCollisionAndBadSelectors(t *testing.T) {
	f := newWsFix(t)
	a, b := filepath.Join(f.src, "a"), filepath.Join(f.src, "b")
	os.MkdirAll(a, 0o700)
	os.MkdirAll(b, 0o700)
	f.wallet(a, "w", f.seed)
	other := make([]byte, 32)
	other[0] = 7
	saved := f.seed
	f.seed = other
	f.wallet(b, "w", other)
	f.seed = saved
	err := f.run(&scriptTerm{t: t}, "workspace", "import", a, b, "--all")
	if err == nil || !strings.Contains(err.Error(), a) || !strings.Contains(err.Error(), b) || f.has("w.skey") {
		t.Fatalf("%v", err)
	}
	if err := f.run(&scriptTerm{t: t}, "workspace", "import", a, b, "--only", "wallet:w"); err == nil || !strings.Contains(err.Error(), "more than one folder") {
		t.Errorf("ambiguous: %v", err)
	}
	if err := f.run(&scriptTerm{t: t}, "workspace", "import", a, b, "--all", "--rename", "wallet:w@"+b+"=w2"); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	if !f.has("w.skey") || !f.has("w2.skey") {
		t.Error("both wallets should be stored")
	}
	for _, bad := range [][]string{{"--only", "key:x"}, {"--only", ":x"}, {"--only", "pool:"}, {"--rename", "pool:x"}, {"--rename", "pool:x="}, {"--depth", "9", "--all"}} {
		if err := f.run(&scriptTerm{t: t}, append([]string{"workspace", "import", a}, bad...)...); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	if err := f.run(&scriptTerm{t: t}, "workspace", "import", a, b); err == nil || !strings.Contains(err.Error(), "--all") {
		t.Errorf("no selection: %v", err)
	}
	if err := f.run(&scriptTerm{t: t}, "workspace", "import"); err == nil {
		t.Error("no folder")
	}
}

// --depth reads sub-folders; a symbolic link to a folder is not entered, and
// what a source folder calls itself is printed cleaned.
//
// spec: SPO-Xmulti-IN-002, SPO-Xmulti-SEC-001, SPO-Xmulti-SEC-004
func TestImportDepthSymlinksAndHostileNames(t *testing.T) {
	f := newWsFix(t)
	outside := t.TempDir()
	f.wallet(outside, "linked", f.seed)
	sub := filepath.Join(f.src, "sub\x1b[31mred")
	os.MkdirAll(sub, 0o700)
	f.wallet(sub, "deep", f.seed)
	os.Symlink(outside, filepath.Join(f.src, "link"))
	if err := f.run(&scriptTerm{t: t}, "workspace", "import", f.src, "--all", "--dry-run"); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	if strings.Contains(f.out.String(), "deep") {
		t.Error("depth 0 entered a sub-folder")
	}
	f.out.Reset()
	if err := f.run(&scriptTerm{t: t}, "workspace", "import", f.src, "--depth", "1", "--all", "--dry-run"); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	out := f.out.String()
	if !strings.Contains(out, "deep") || strings.Contains(out, "linked") || strings.Contains(out, "\x1b") {
		t.Errorf("depth 1:\n%q", out)
	}
	if !strings.Contains(out, "a symbolic link is never followed") {
		t.Errorf("the link is not listed as ignored:\n%s", out)
	}
}

// A single folder with no option behaves as it always did: everything is
// imported.
//
// spec: SPO-Xmulti-IN-003
func TestImportSingleFolderUnchanged(t *testing.T) {
	f := newWsFix(t)
	f.wallet(f.src, "w1", f.seed)
	if err := f.run(&scriptTerm{t: t}, "workspace", "import", f.src); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	mustContain(t, f.out.String(), "1 owner(s) of 1 imported")
	if !f.has("w1.skey") {
		t.Error("not imported")
	}
}

// A comment may stand inside a multi-line array; two strings with no comma
// between them, and keys the manifest does not define, are refused.
//
// spec: SPO-Xmulti-IF-002
func TestManifestParserIsStrict(t *testing.T) {
	good := "sources = [\n  \"/a\", # first\n  # a comment line\n  \"/b\", # second\n]\ndepth = 1 # one level\nall = true\nonly = [\"pool:p\" # no comma needed after the last\n]\n"
	m, err := parseManifest([]byte(good))
	if err != nil || strings.Join(m.Sources, ",") != "/a,/b" || m.Depth != 1 || !m.All || len(m.Only) != 1 || m.Only[0] != "pool:p" {
		t.Fatalf("%v %+v", err, m)
	}
	for name, bad := range map[string]string{
		"missing comma, one line":   "sources = [\"/a\" \"/b\"]\n",
		"missing comma, many lines": "sources = [\n \"/a\"\n \"/b\"\n]\n",
		"leading comma":             "sources = [, \"/a\"]\n",
		"double comma":              "sources = [\"/a\",, \"/b\"]\n",
		"unknown scalar key":        "sources = [\"/a\"]\nbogus = 1\n",
		"unknown array key":         "sources = [\"/a\"]\nbogus = [\"x\"]\n",
		"quoted key":                "\"sources\" = [\"/a\"]\n",
		"unknown key in a table":    "sources = [\"/a\"]\n[extra]\nx = 1\n",
		"text after the array":      "sources = [\"/a\"] x\n",
		"hash inside a string kept": "sources = [\"/a#b\" \"c\"]\n",
	} {
		if _, err := parseManifest([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if m, err := parseManifest([]byte("sources = [\"/a#b\"]\n")); err != nil || m.Sources[0] != "/a#b" {
		t.Errorf("a # inside a string: %v %+v", err, m)
	}
}
