package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/sqlitestore"
	"github.com/mochipool/workbench/spo/internal/domain/layout"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ADR 0012 stage 3, work packages 4 and 5, through the real command tree: `store
// verify --layout` and `store convert --from-layout`. No real authenticator is used.

var verifyPinRE = regexp.MustCompile(`(?m)^Pin of this head: ([0-9a-f]{32}:layout:[0-9]+:[0-9a-f]{64})$`)

func exportLayout(t *testing.T, dir, root string, extra ...string) string {
	t.Helper()
	out, err := withPass(t, dir, testPass, append([]string{"store", "convert", "--to-layout", root}, extra...)...)
	if err != nil {
		t.Fatalf("export: %v\n%s", err, out)
	}
	m := layoutPinRE.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no pin:\n%s", out)
	}
	return m[1]
}

func tempLeftovers(t *testing.T) int {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(os.TempDir(), "spo-layout-verify-*"))
	return len(m)
}

func snapshotOf(t *testing.T, dir string) ports.Snapshot {
	t.Helper()
	snap, _, err := sqlitestore.ReadSnapshot(context.Background(), filepath.Join(dir, "workspace.spo"), sqlitestore.SnapshotCredential{Passphrase: pass(testPass)})
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func pass(s string) *secret.Buffer {
	b, err := secret.Fill(len(s), func(dst []byte) error { copy(dst, s); return nil })
	if err != nil {
		panic(err)
	}
	return b
}

// spec: SPO-Xlayout-IF-002, SPO-Xlayout-PRE-020, SPO-Xlayout-OUT-020, SPO-Xlayout-OUT-021, SPO-Xlayout-OUT-022, SPO-Xlayout-INV-016
func TestStoreVerifyLayoutStandard(t *testing.T) {
	dir := copyWorkspace(t)
	root := filepath.Join(t.TempDir(), "layout")
	pin := exportLayout(t, dir, root)
	wsBefore := sha(t, filepath.Join(dir, "workspace.spo"))
	tree := readLayout(t, root)
	leftovers := tempLeftovers(t)

	out, err := withPass(t, dir, testPass, "store", "verify", "--layout", root, "--pin", pin)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	flat := strings.ReplaceAll(out, "\n", " ")
	for _, want := range []string{"head 1", "Signed: no", "not signed", "Established without any credential", "Opened ", "records and ", "scratch store file", "full verification", "No record was decrypted", "Pin of this head: " + pin, "was not changed"} {
		if !strings.Contains(flat, want) {
			t.Errorf("the output lacks %q:\n%s", want, out)
		}
	}
	notLeaked(t, out, testPass)
	if sha(t, filepath.Join(dir, "workspace.spo")) != wsBefore || !reflect.DeepEqual(readLayout(t, root), tree) {
		t.Error("verify changed the workspace or the layout")
	}
	noLeftovers(t, dir)
	if tempLeftovers(t) != leftovers {
		t.Error("a scratch directory was left behind")
	}

	// --locked asks for nothing
	term := &fakeTerm{}
	out, err = exec(t, term, "-C", dir, "store", "verify", "--layout", root, "--pin", pin, "--locked")
	if err != nil || len(term.asked) != 0 || !strings.Contains(out, "Not established") || !strings.Contains(out, "--locked") {
		t.Fatalf("%v asked %v\n%s", err, term.asked, out)
	}
	// the pin of this machine
	if out, err = withPass(t, dir, testPass, "store", "verify", "--layout", root, "--pin", "local"); err != nil || !strings.Contains(out, "Pin of this head") {
		t.Fatalf("%v\n%s", err, out)
	}
	// the printed pin is the one verify prints
	if m := verifyPinRE.FindStringSubmatch(out); m == nil || m[1] != pin {
		t.Errorf("verify's pin is not the export's: %v", m)
	}
}

// Everything that can be refused is refused before the terminal is read.
//
// spec: SPO-Xlayout-PRE-020, SPO-Xlayout-PRE-025, SPO-Xlayout-SEC-009
func TestStoreVerifyLayoutRefusesBeforeAnyPrompt(t *testing.T) {
	dir := copyWorkspace(t)
	root := filepath.Join(t.TempDir(), "layout")
	pin := exportLayout(t, dir, root)
	parts := strings.Split(pin, ":")
	wrongHash := strings.Join([]string{parts[0], parts[1], parts[2], strings.Repeat("0", 64)}, ":")
	loose := filepath.Join(t.TempDir(), "loose")
	os.Mkdir(loose, 0o700)
	os.Chmod(loose, 0o777)
	cases := map[string]struct {
		args []string
		want string
	}{
		"no pin":                    {[]string{"--layout", root}, "--pin PIN"},
		"a pin that is not a pin":   {[]string{"--layout", root, "--pin", "trust-me"}, "pin"},
		"a pin of another head":     {[]string{"--layout", root, "--pin", wrongHash}, "not the head the pin names"},
		"a pin of a later head":     {[]string{"--layout", root, "--pin", strings.Join([]string{parts[0], parts[1], "2", parts[3]}, ":")}, "rolled back"},
		"at below the pin":          {[]string{"--layout", root, "--pin", pin, "--at", "0"}, "--at"},
		"a file for a directory":    {[]string{"--layout", filepath.Join(dir, "spo.toml"), "--pin", pin}, ""},
		"a missing directory":       {[]string{"--layout", filepath.Join(t.TempDir(), "nope"), "--pin", pin}, "cannot be read"},
		"an s3 URL":                 {[]string{"--layout", "s3://b/p", "--pin", pin}, "local directory only"},
		"loose permissions":         {[]string{"--layout", loose, "--pin", pin}, "writable by its group"},
		"the recovery composite":    {[]string{"--layout", root, "--pin", pin, "--unlock", "recovery-composite"}, "recovery-composite"},
		"a passphrase for hardware": {nil, ""}, // placeholder removed below
	}
	delete(cases, "a passphrase for hardware")
	for name, c := range cases {
		term := &fakeTerm{}
		out, err := exec(t, term, append([]string{"-C", dir, "store", "verify"}, c.args...)...)
		if err == nil {
			t.Errorf("%s: accepted:\n%s", name, out)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
		if len(term.asked) != 0 {
			t.Errorf("%s: the terminal was asked %q", name, term.asked)
		}
	}
	// flags that do not belong together
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--at", "1"}, "go with --layout"},
		{[]string{"--locked"}, "go with --layout"},
		{[]string{"--layout", root, "--pin", pin, "--deep"}, "--layout goes with"},
		{[]string{"--layout", root, "--pin", pin, "--backup", "x"}, "--layout goes with"},
		{[]string{"--layout", root, "--pin", pin, "--locked", "--unlock", "recovery-composite"}, "recovery-composite"},
		{[]string{"--layout", root, "--pin", pin, "--unlock", "fido2"}, "opened with its passphrase"},
		{[]string{"--layout", root, "--pin", pin, "--unlock", "bogus"}, "use passphrase or fido2"},
		{[]string{"--layout", filepath.Join(t.TempDir(), "nowhere")}, "--pin PIN"},
	} {
		term := &fakeTerm{}
		_, err := exec(t, term, append([]string{"-C", dir, "store", "verify"}, c.args...)...)
		if err == nil || !strings.Contains(err.Error(), c.want) || len(term.asked) != 0 {
			t.Errorf("%v: %v (asked %v), want %q", c.args, err, term.asked, c.want)
		}
	}
	// a wrong passphrase
	if out, err := withPass(t, dir, "not the passphrase", "store", "verify", "--layout", root, "--pin", pin); err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Errorf("a wrong passphrase: %v\n%s", err, out)
	}
}

// A real layout, damaged in the ways a directory can be damaged.
//
// spec: SPO-Xlayout-OUT-021, SPO-Xlayout-PRE-024, SPO-Xlayout-INV-025
func TestStoreVerifyLayoutOfADamagedDirectory(t *testing.T) {
	dir := copyWorkspace(t)
	pristine := filepath.Join(t.TempDir(), "layout")
	pin := exportLayout(t, dir, pristine)
	files := readLayout(t, pristine)
	var sealed, slots string
	for n, b := range files {
		if strings.HasPrefix(n, "objects/") {
			if b[0] == 0x02 {
				slots = n
			} else if sealed == "" || n < sealed {
				sealed = n
			}
		}
	}
	damage := map[string]func(root string){
		"a flipped byte in a sealed object": func(root string) {
			b := readFile(t, filepath.Join(root, sealed))
			b[len(b)/2] ^= 1
			os.WriteFile(filepath.Join(root, sealed), b, 0o600)
		},
		"a truncated sealed object": func(root string) {
			b := readFile(t, filepath.Join(root, sealed))
			os.WriteFile(filepath.Join(root, sealed), b[:len(b)-1], 0o600)
		},
		"a sealed object with an extra byte": func(root string) {
			b := readFile(t, filepath.Join(root, sealed))
			os.WriteFile(filepath.Join(root, sealed), append(b, 0), 0o600)
		},
		"a missing sealed object": func(root string) { os.Remove(filepath.Join(root, sealed)) },
		"a missing slots object":  func(root string) { os.Remove(filepath.Join(root, slots)) },
		"junk at the next head": func(root string) {
			os.WriteFile(filepath.Join(root, "heads", "00000000000000000002"), []byte("junk\n"), 0o600)
		},
		"a head of another note": func(root string) {
			os.WriteFile(filepath.Join(root, "heads", "00000000000000000001"), []byte("junk\n"), 0o600)
		},
		"a symbolic link for an object": func(root string) {
			os.Remove(filepath.Join(root, sealed))
			os.Symlink("/etc/passwd", filepath.Join(root, sealed))
		},
	}
	for name, f := range damage {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "copy")
			copyTree(t, pristine, root)
			f(root)
			term := &fakeTerm{}
			out, err := exec(t, term, "-C", dir, "--passphrase-fd", fdOf(t, testPass), "store", "verify", "--layout", root, "--pin", pin)
			if err == nil {
				t.Fatalf("a damaged layout verified:\n%s", out)
			}
			if strings.Contains(out+err.Error(), "scratch store file, which passed") {
				t.Errorf("the check went on to the end:\n%s", out)
			}
		})
	}
}

func fdOf(t *testing.T, content string) string {
	t.Helper()
	f, fd := fdIn(t, content+"\n")
	t.Cleanup(func() { f.Close() })
	return fd
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		return os.WriteFile(target, readFile(t, p), 0o600)
	})
}

// spec: SPO-Xlayout-IF-003, SPO-Xlayout-OUT-022, SPO-Xlayout-OUT-023, SPO-Xlayout-OUT-024, SPO-Xlayout-INV-026, SPO-Xlayout-INV-015
func TestStoreConvertFromLayoutIntoAnEmptyDirectoryAndBack(t *testing.T) {
	src := copyWorkspace(t)
	root := filepath.Join(t.TempDir(), "layout")
	if o, err := withPass(t, src, testPass, "pool", "keys", "generate", poolName); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	pin := exportLayout(t, src, root)
	tree := readLayout(t, root)

	// refused before any prompt: an empty directory has no spo.toml
	fresh := t.TempDir()
	term := &fakeTerm{}
	if out, err := exec(t, term, "-C", fresh, "store", "convert", "--from-layout", root, "--pin", pin); err == nil || !strings.Contains(err.Error(), "--network") || len(term.asked) != 0 {
		t.Fatalf("%v asked %v\n%s", err, term.asked, out)
	}
	if exists(filepath.Join(fresh, "workspace.spo")) {
		t.Fatal("a workspace file was made by a refused import")
	}
	out, err := withPass(t, fresh, testPass, "store", "convert", "--from-layout", root, "--pin", pin, "--network", "preview")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{"Restored", "every layout check passed", "Layout pin recorded", "Pin of this head: " + pin, "Cold-role records were carried",
		"No workspace was replaced, so no operational certificate or KES counter was compared", "spo pool opcert counter", "not necessarily the newest that exists"} {
		if !strings.Contains(out, want) {
			t.Errorf("the output lacks %q:\n%s", want, out)
		}
	}
	if !exists(filepath.Join(fresh, "spo.toml")) || !exists(filepath.Join(fresh, "workspace.spo")) {
		t.Fatal("the workspace was not installed")
	}
	noLeftovers(t, fresh)
	if !reflect.DeepEqual(readLayout(t, root), tree) {
		t.Error("the layout was changed by an import")
	}
	// the imported workspace passes the deepest check and equals the source row for row
	if o, err := withPass(t, fresh, testPass, "store", "verify", "--deep"); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	a, b := snapshotOf(t, src), snapshotOf(t, fresh)
	a.Meta.CleanupPending, b.Meta.CleanupPending = 0, 0
	if !reflect.DeepEqual(a, b) {
		t.Error("the imported workspace is not the source row for row")
	}
	// the pin of the directory is recorded beside the imported workspace, and an
	// export after the import continues the chain
	pinFileOf(t, fresh)
	time.Sleep(20 * time.Millisecond)
	out, err = withPass(t, fresh, testPass, "store", "convert", "--to-layout", root)
	if err != nil || !strings.Contains(out, "already up to date") {
		t.Fatalf("an export right after an import: %v\n%s", err, out)
	}
	if o, err := withPass(t, fresh, testPass, "pool", "vrf", "generate", poolName); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	out, err = withPass(t, fresh, testPass, "store", "convert", "--to-layout", root)
	if err != nil || strings.Contains(out, "already up to date") {
		t.Fatalf("%v\n%s", err, out)
	}
	h, _, _ := newestLayoutHead(t, readLayout(t, root))
	if h.Sequence != 2 {
		t.Fatalf("the chain did not continue: head %d", h.Sequence)
	}
	// and the new head verifies against the pin of the first
	if o, err := withPass(t, fresh, testPass, "store", "verify", "--layout", root, "--pin", pin); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	// the same import again needs --force
	term = &fakeTerm{}
	if out, err := exec(t, term, "-C", fresh, "store", "convert", "--from-layout", root, "--pin", pin); err == nil || !strings.Contains(err.Error(), "--force") || len(term.asked) != 0 {
		t.Fatalf("%v asked %v\n%s", err, term.asked, out)
	}
}

// The restore rules apply to an import: older needs --allow-older and then the
// counters are carried; another workspace needs its flag; nothing is changed by a
// refusal.
//
// spec: SPO-Xlayout-OUT-023, SPO-Xlayout-PRE-025
func TestStoreConvertFromLayoutAppliesTheRestoreRules(t *testing.T) {
	dir := copyWorkspace(t)
	genesis := writeGenesis(t)
	step := func(args ...string) string {
		t.Helper()
		out, err := withPass(t, dir, testPass, args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		return out
	}
	step("pool", "keys", "generate", poolName)
	step("pool", "vrf", "generate", poolName)
	step("pool", "kes", "generate", poolName)
	step("pool", "opcert", "issue", poolName, "--offline", "--shelley-genesis", genesis) // counter 0
	root := filepath.Join(t.TempDir(), "layout")
	pin := exportLayout(t, dir, root)
	for i := 1; i <= 2; i++ { // the workspace moves on: counter 3 next
		step("pool", "kes", "generate", poolName)
		step("pool", "opcert", "issue", poolName, "--offline", "--shelley-genesis", genesis)
	}
	before := sha(t, filepath.Join(dir, "workspace.spo"))
	// the layout is older than the workspace: refused without --allow-older, nothing changes
	if out, err := withPass(t, dir, testPass, "store", "convert", "--from-layout", root, "--pin", pin, "--force"); err == nil {
		t.Fatalf("an older layout replaced the workspace:\n%s", out)
	}
	if sha(t, filepath.Join(dir, "workspace.spo")) != before {
		t.Fatal("the workspace changed after a refused import")
	}
	noLeftovers(t, dir)
	noScratch(t, dir)
	out := step("store", "convert", "--from-layout", root, "--pin", pin, "--force", "--allow-older")
	if !strings.Contains(out, "carried forward") || !strings.Contains(out, "node.counter") || !strings.Contains(out, "is 3 in the replaced workspace") {
		t.Fatalf("the import did not say what it carried:\n%s", out)
	}
	noLeftovers(t, dir)
	noScratch(t, dir)
	step("store", "verify", "--deep")
	if gen := step("pool", "kes", "generate", poolName); !strings.Contains(gen, "Generated KES key 003") {
		t.Fatalf("the KES number after the import is not the next one:\n%s", gen)
	}
	if iss := step("pool", "opcert", "issue", poolName, "--offline", "--shelley-genesis", genesis); !strings.Contains(iss, "with counter 3") {
		t.Fatalf("the certificate after the import does not take the live counter:\n%s", iss)
	}

	// another workspace: refused before any prompt, and then only with both flags
	other := copyWorkspace(t)
	otherRoot := filepath.Join(t.TempDir(), "other-layout")
	otherDir := t.TempDir()
	pf, pfd := fdIn(t, testPass+"\n")
	rf, rfd := fdOut(t)
	if o, err := exec(t, nil, "-C", otherDir, "init", "--network", "preview", "--passphrase-fd", pfd, "--recovery-key-fd", rfd); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	pf.Close()
	_ = rf
	otherPin := exportLayout(t, otherDir, otherRoot)
	_ = other
	term := &fakeTerm{}
	if out, err := exec(t, term, "-C", dir, "store", "convert", "--from-layout", otherRoot, "--pin", otherPin, "--force"); err == nil || !strings.Contains(err.Error(), "another workspace") || len(term.asked) != 0 {
		t.Fatalf("%v asked %v\n%s", err, term.asked, out)
	}
	if _, err := withPass(t, dir, testPass, "store", "convert", "--from-layout", otherRoot, "--pin", otherPin, "--allow-other-workspace"); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("--allow-other-workspace without --force: %v", err)
	}
}

// A hardware workspace is verified and imported with its daily authenticator; a
// passphrase never opens it; the recovery composite is refused before the
// authenticator is touched.
//
// spec: SPO-Xlayout-PRE-026, SPO-Xlayout-OUT-023
func TestStoreVerifyAndConvertFromLayoutHardware(t *testing.T) {
	rig := newDeviceRunner(t)
	dir, recKey := toHardwareDR(t, rig)
	root := filepath.Join(t.TempDir(), "layout")
	counter := &countingRunner{Runner: rig}
	run := func(wsDir string, args ...string) (string, error) {
		t.Helper()
		full := []string{"-C", wsDir}
		f, fd := fdIn(t, fidoPIN+"\n")
		defer f.Close()
		full = append(full, "--fido2-pin-fd", fd, "--fido2-device", dev0)
		return runFidoWith(t, counter, nil, append(full, args...)...)
	}
	out, err := run(dir, "store", "convert", "--to-layout", root)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	pin := layoutPinRE.FindStringSubmatch(out)[1]

	// refused before the authenticator is touched
	before := counter.n.Load()
	if out, err := run(dir, "--unlock", "recovery-composite", "store", "verify", "--layout", root, "--pin", pin); err == nil || !strings.Contains(err.Error(), "recovery-composite") {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, err := run(dir, "--unlock", "passphrase", "store", "verify", "--layout", root, "--pin", pin); err == nil || !strings.Contains(err.Error(), "no passphrase opens it") {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, err := run(dir, "store", "verify", "--layout", root, "--pin", "nonsense"); err == nil {
		t.Fatalf("%s", out)
	}
	if counter.n.Load() != before {
		t.Errorf("the authenticator was called %d times for refused commands", counter.n.Load()-before)
	}
	// a passphrase alone
	if o, err := withPass(t, dir, testPass, "store", "verify", "--layout", root, "--pin", pin); err == nil {
		t.Errorf("a passphrase verified a hardware layout:\n%s", o)
	}
	// --locked touches nothing
	before = counter.n.Load()
	if out, err := run(dir, "store", "verify", "--layout", root, "--pin", pin, "--locked"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if counter.n.Load() != before {
		t.Errorf("--locked called the authenticator %d times", counter.n.Load()-before)
	}
	// the unlocked verification
	out, err = run(dir, "store", "verify", "--layout", root, "--pin", pin)
	if err != nil || !strings.Contains(out, "passed the store's own full verification") {
		t.Fatalf("%v\n%s", err, out)
	}
	notLeaked(t, out, testPass, recKey, fidoPIN)
	// the recovery authenticator is not a daily credential: no slot opens with it
	rf2, rfd2 := fdIn(t, fidoPIN2+"\n")
	defer rf2.Close()
	if o, err := runFidoWith(t, counter, nil, "-C", dir, "--fido2-pin-fd", rfd2, "--fido2-device", dev1, "store", "verify", "--layout", root, "--pin", pin); err == nil || !strings.Contains(err.Error(), "does not open this layout's workspace") {
		t.Errorf("%v\n%s", err, o)
	}
	// the touches: one verification of the workspace costs the authenticator some
	// assertions; the verification of a layout and the import cost a multiple of it
	base := counter.asserts.Load()
	if o, err := run(dir, "store", "verify"); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	perPresentation := counter.asserts.Load() - base
	base = counter.asserts.Load()
	if out, err = run(dir, "store", "verify", "--layout", root, "--pin", pin); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	verifyTouches := counter.asserts.Load() - base
	t.Logf("assertions: one store verify %d, store verify --layout %d", perPresentation, verifyTouches)
	// import into an empty directory
	fresh := t.TempDir()
	base = counter.asserts.Load()
	out, err = run(fresh, "store", "convert", "--from-layout", root, "--pin", pin, "--network", "preview")
	if err != nil || !strings.Contains(out, "Restored") {
		t.Fatalf("%v\n%s", err, out)
	}
	importTouches := counter.asserts.Load() - base
	t.Logf("assertions: import %d", importTouches)
	// the documented number of presentations: layout unlock, scratch verification, restore
	if verifyTouches != 2*perPresentation || importTouches != 3*perPresentation {
		t.Errorf("a presentation costs %d assertions; verify --layout made %d and the import %d (expected 2 and 3 presentations)", perPresentation, verifyTouches, importTouches)
	}
	if o, err := run(fresh, "store", "verify", "--deep"); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	noLeftovers(t, fresh)
}

// A standard layout is refused over a workspace that was moved to hardware since:
// the weaker-policy rule of the restore applies, and nothing is changed.
//
// spec: SPO-Xlayout-OUT-023
func TestStoreConvertFromLayoutRefusesAWeakerPolicy(t *testing.T) {
	rig := newDeviceRunner(t)
	dir := copyWorkspace(t)
	_, oldRec := template(t)
	root := filepath.Join(t.TempDir(), "layout")
	pin := exportLayout(t, dir, root)
	rf, rfd := fdOut(t)
	pf, pfd := fdIn(t, testPass+"\n")
	defer pf.Close()
	if out, err := (drCmd{t, rig, dir}).run(map[string]string{"--fido2-pin-fd": fidoPIN, "--recovery-pin-fd": fidoPIN2, "--recovery-key-in-fd": oldRec}, "--passphrase-fd", pfd, "--recovery-key-fd", rfd,
		"workspace", "rotate", "--policy", "hardware", "--fido2-device", dev0, "--recovery-device", dev1); err != nil || strings.TrimSpace(contents(rf)) == "" {
		t.Fatalf("%v\n%s", err, out)
	}
	before := sha(t, filepath.Join(dir, "workspace.spo"))
	out, err := withPass(t, dir, testPass, "store", "convert", "--from-layout", root, "--pin", pin, "--force", "--allow-older")
	if err == nil || !strings.Contains(err.Error(), "weaker") {
		t.Fatalf("%v\n%s", err, out)
	}
	if sha(t, filepath.Join(dir, "workspace.spo")) != before {
		t.Error("the workspace changed")
	}
	noLeftovers(t, dir)
}

func noScratch(t *testing.T, dir string) {
	t.Helper()
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "layout-") || strings.HasPrefix(e.Name(), ".snapshot") {
			t.Errorf("scratch space %s left in %s", e.Name(), dir)
		}
	}
}

// Every refusal of the import that needs no secret is made before the terminal is
// read, with the message that names it.
//
// spec: SPO-Xlayout-PRE-025, SPO-Xlayout-IF-003, SPO-Xlayout-PRE-026
func TestStoreConvertFromLayoutRefusesBeforeAnyPrompt(t *testing.T) {
	src := copyWorkspace(t)
	root := filepath.Join(t.TempDir(), "layout")
	pin := exportLayout(t, src, root)
	fresh := t.TempDir()
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no pin", []string{"--from-layout", root, "--network", "preview"}, "--pin PIN"},
		{"both directions", []string{"--from-layout", root, "--to-layout", filepath.Join(t.TempDir(), "o"), "--pin", pin, "--network", "preview"}, "not both"},
		{"checkpoint flags with the import", []string{"--from-layout", root, "--pin", pin, "--network", "preview", "--no-checkpoint"}, "go with --to-layout"},
		{"import flags with the export", []string{"--to-layout", filepath.Join(t.TempDir(), "o"), "--pin", pin}, "goes with --from-layout"},
		{"recovery key flag with the export", []string{"--to-layout", filepath.Join(t.TempDir(), "o"), "--recovery-key-in-fd", "3"}, "goes with --from-layout"},
		{"recovery PIN flag with the export", []string{"--to-layout", filepath.Join(t.TempDir(), "o"), "--recovery-pin-fd", "3"}, "goes with --from-layout"},
		{"recovery device flag with the export", []string{"--to-layout", filepath.Join(t.TempDir(), "o"), "--current-recovery-device", "/dev/x"}, "goes with --from-layout"},
		{"force with the export", []string{"--to-layout", filepath.Join(t.TempDir(), "o"), "--force"}, "goes with --from-layout"},
		{"at with the export", []string{"--to-layout", filepath.Join(t.TempDir(), "o"), "--at", "1"}, "goes with --from-layout"},
		{"other workspace without force", []string{"--from-layout", root, "--pin", pin, "--network", "preview", "--allow-other-workspace"}, "--allow-other-workspace replaces"},
		{"weaker policy without force", []string{"--from-layout", root, "--pin", pin, "--network", "preview", "--allow-weaker-policy"}, "--allow-weaker-policy replaces"},
		{"fido2 for a standard layout", []string{"--from-layout", root, "--pin", pin, "--network", "preview", "--unlock", "fido2"}, "opened with its passphrase"},
		{"the recovery composite", []string{"--from-layout", root, "--pin", pin, "--network", "preview", "--unlock", "recovery-composite"}, "recovery-composite"},
		{"no network", []string{"--from-layout", root, "--pin", pin}, "--network"},
	}
	for _, c := range cases {
		term := &fakeTerm{}
		out, err := exec(t, term, append([]string{"-C", fresh, "store", "convert"}, c.args...)...)
		if err == nil || !strings.Contains(err.Error(), c.want) || len(term.asked) != 0 {
			t.Errorf("%s: %v (asked %v), want %q\n%s", c.name, err, term.asked, c.want, out)
		}
	}
	if exists(filepath.Join(fresh, "workspace.spo")) {
		t.Error("a refused import made a workspace")
	}
	// a plain upstream-layout build never imports
	if out, err := exec(t, &fakeTerm{}, "--upstream-layout", "-C", fresh, "store", "convert", "--from-layout", root, "--pin", pin, "--network", "preview"); err == nil || !strings.Contains(err.Error(), "do not apply with --upstream-layout") {
		t.Errorf("%v\n%s", err, out)
	}
	// a machine with no workspace directory yet: verify and import make it
	newDir := filepath.Join(t.TempDir(), "not", "yet")
	if out, err := exec(t, &fakeTerm{}, "-C", newDir, "store", "verify", "--layout", root, "--pin", pin, "--locked"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, err := withPass(t, newDir, testPass, "store", "convert", "--from-layout", root, "--pin", pin, "--network", "preview"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	pinFileOf(t, newDir)
	// a pin of this machine that does not exist
	if out, err := exec(t, &fakeTerm{}, "-C", copyWorkspace(t), "store", "verify", "--layout", root, "--pin", "local", "--locked"); err == nil || !strings.Contains(err.Error(), "no pin for this directory") {
		t.Errorf("%v\n%s", err, out)
	}
	// a wrong passphrase leaves nothing and changes nothing
	empty := t.TempDir()
	if out, err := withPass(t, empty, "not the passphrase", "store", "convert", "--from-layout", root, "--pin", pin, "--network", "preview"); err == nil || exists(filepath.Join(empty, "workspace.spo")) {
		t.Errorf("%v\n%s", err, out)
	}
	noScratch(t, empty)
}

// The restore checks the hash of the scratch file the import verified: a file put
// in its place after the hash was taken (a valid workspace file, even) is refused,
// and a refused import leaves no scratch space behind.
//
// spec: SPO-Xlayout-OUT-023, SPO-Xlayout-OUT-022
func TestStoreConvertFromLayoutInstallsOnlyTheFileItVerified(t *testing.T) {
	src := copyWorkspace(t)
	root := filepath.Join(t.TempDir(), "layout")
	pin := exportLayout(t, src, root)
	if o, err := withPass(t, src, testPass, "pool", "keys", "generate", poolName); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	other := readFile(t, filepath.Join(src, "workspace.spo")) // a valid file of the same workspace, not the one verified
	fresh := t.TempDir()
	var out bytes.Buffer
	pf, pfd := fdIn(t, testPass+"\n")
	defer pf.Close()
	deps := newDeps(&out, &out, &fakeTerm{out: &out})
	describe := deps.Sealed.Describe
	deps.Sealed.Describe = func(path string) (cli.WorkspaceInfo, error) {
		if strings.Contains(path, "layout-") {
			if err := os.WriteFile(path, other, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return describe(path)
	}
	root2 := cli.NewRoot(deps)
	root2.SetArgs([]string{"-C", fresh, "--passphrase-fd", pfd, "store", "convert", "--from-layout", root, "--pin", pin, "--network", "preview"})
	err := root2.ExecuteContext(context.Background())
	if err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("a replaced scratch file was installed: %v\n%s", err, out.String())
	}
	if exists(filepath.Join(fresh, "workspace.spo")) {
		t.Error("a workspace was installed")
	}
	noScratch(t, fresh)
	noLeftovers(t, fresh)
}

// A restore into an empty directory has nothing to compare the counters with, and
// says so: for a file, for a sink and for a layout.
//
// spec: SPO-Xbackup-PRE-007, SPO-Xlayout-OUT-023
func TestARestoreIntoAnEmptyDirectorySaysNoCounterWasCompared(t *testing.T) {
	const want = "No workspace was replaced, so no operational certificate or KES counter was compared"
	src := copyWorkspace(t)
	backup := filepath.Join(t.TempDir(), "bk.spo")
	if o, err := withPass(t, src, testPass, "store", "backup", backup); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	out, err := withPass(t, t.TempDir(), testPass, "store", "restore", backup, "--network", "preview")
	if err != nil || !strings.Contains(out, want) {
		t.Fatalf("a file: %v\n%s", err, out)
	}
	sink := "dir:" + filepath.Join(t.TempDir(), "sink")
	sout, err := withPass(t, src, testPass, "store", "backup", "--sink", sink)
	if err != nil {
		t.Fatalf("%v\n%s", err, sout)
	}
	pin := pinOf(t, sout)
	out, err = withPass(t, t.TempDir(), testPass, "store", "restore", "--sink", sink, "--pin", pin, "--network", "preview")
	if err != nil || !strings.Contains(out, want) {
		t.Fatalf("a sink: %v\n%s", err, out)
	}
	// and a restore over a workspace does not say it
	out, err = withPass(t, src, testPass, "store", "restore", backup, "--force")
	if err != nil || strings.Contains(out, want) {
		t.Fatalf("over a workspace: %v\n%s", err, out)
	}
}

// An attacker who can write the directory adds a head above the pin that chains by
// hash, reuses the manifest and names a plaintext slots object of their own. The
// credential and the authenticator request follow from the slot table, so a table
// the pin does not vouch for must be refused before any prompt: no passphrase asked
// of a hardware workspace, no authenticator called.
//
// spec: SPO-Xlayout-PRE-028, SPO-Xlayout-PRE-026
func TestAForgedHeadCannotChooseTheCredential(t *testing.T) {
	for _, form := range []string{"exact", "local"} {
		t.Run(form, func(t *testing.T) {
			rig := newDeviceRunner(t)
			dir, _ := toHardwareDR(t, rig)
			root := filepath.Join(t.TempDir(), "layout")
			counter := &countingRunner{Runner: rig}
			f, fd := fdIn(t, fidoPIN+"\n")
			defer f.Close()
			out, err := runFidoWith(t, counter, nil, "-C", dir, "--fido2-pin-fd", fd, "--fido2-device", dev0, "store", "convert", "--to-layout", root)
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			pin := layoutPinRE.FindStringSubmatch(out)[1]
			if form == "local" {
				pin = "local"
			}
			// the forgery: head 2, standard table, same recovery key
			files := readLayout(t, root)
			h1, note1, _ := newestLayoutHead(t, files)
			_, so, err := layout.ParseSlotsObject(files["objects/"+hexOf(h1.Slots)[:2]+"/"+hexOf(h1.Slots)])
			if err != nil {
				t.Fatal(err)
			}
			rec := so.Meta.RecoveryPubHash
			mem, passes, lanes := int64(65536), int64(3), int64(1)
			so.Meta.Policy = "standard"
			so.Slots = []layout.Slot{
				{ID: bytes.Repeat([]byte{0x30}, 16), Kind: "passphrase", KDFMemoryKiB: &mem, KDFPasses: &passes, KDFLanes: &lanes, Salt: bytes.Repeat([]byte{7}, 16),
					KeyCommit: bytes.Repeat([]byte{1}, 32), Nonce: bytes.Repeat([]byte{2}, 24), WrappedKey: bytes.Repeat([]byte{3}, 48), Bound: 1, RecHash: rec},
				{ID: bytes.Repeat([]byte{0x40}, 16), Kind: "recovery", Salt: []byte{}, KeyCommit: bytes.Repeat([]byte{4}, 32), Nonce: bytes.Repeat([]byte{5}, 24), WrappedKey: bytes.Repeat([]byte{6}, 48), Bound: 1, RecHash: rec},
			}
			stored, err := layout.EncodeSlotsObject(so.Meta.KeyEpoch, so)
			if err != nil {
				t.Fatal(err)
			}
			name := layout.ObjectName(stored)
			if err := os.MkdirAll(filepath.Join(root, "objects", name[:2]), 0o700); err != nil {
				t.Fatal(err)
			}
			os.WriteFile(filepath.Join(root, "objects", name[:2], name), stored, 0o600)
			h2 := h1
			h2.Sequence, h2.Previous, h2.Time = 2, layout.HeadHash(note1), h1.Time.Add(time.Minute)
			h2.Slots, _ = hex.DecodeString(name)
			note2, err := h2.Encode()
			if err != nil {
				t.Fatal(err)
			}
			os.WriteFile(filepath.Join(root, "heads", layout.HeadPath(2)[6:]), note2, 0o600)

			before := counter.n.Load()
			pf, pfd := fdIn(t, testPass+"\n")
			defer pf.Close()
			term := &fakeTerm{}
			out, err = runFidoWith(t, counter, term, "-C", dir, "--passphrase-fd", pfd, "store", "verify", "--layout", root, "--pin", pin)
			if err == nil || !strings.Contains(err.Error(), "weaker") || !strings.Contains(err.Error(), "--at 1") {
				t.Fatalf("a forged table was accepted: %v\n%s", err, out)
			}
			if counter.n.Load() != before || len(term.asked) != 0 {
				t.Errorf("the authenticator was called %d times and the terminal asked %v", counter.n.Load()-before, term.asked)
			}
			if pos, _ := pf.Seek(0, 1); pos != 0 {
				t.Error("the passphrase descriptor was read")
			}
			if form == "exact" { // the local pin needs the workspace it is kept for
				// the same refusal for an import, which never installs anything
				fresh := t.TempDir()
				out, err = runFidoWith(t, counter, &fakeTerm{}, "-C", fresh, "store", "convert", "--from-layout", root, "--pin", pin, "--network", "preview")
				if err == nil || !strings.Contains(err.Error(), "weaker") || exists(filepath.Join(fresh, "workspace.spo")) || counter.n.Load() != before {
					t.Fatalf("%v\n%s", err, out)
				}
			}
			// the pinned head alone is still usable
			if out, err = runFidoWith(t, counter, &fakeTerm{}, "-C", dir, "store", "verify", "--layout", root, "--pin", pin, "--at", "1", "--locked"); err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
		})
	}
}
