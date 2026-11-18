package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/fido2cli"
	"github.com/mochipool/workbench/spo/internal/adapters/sqlitestore"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// ADR 0012 stage 3, the read-only opener, through the real command tree: `spo -C
// DIR --pin PIN COMMAND` on a sealed layout directory. No real authenticator is
// used.

const readOnlyWords = "opened read-only"

// treeFingerprint is every entry of a directory tree: its path, type, mode, size,
// modification time and content hash. A command that touches the tree in any way
// changes it.
func treeFingerprint(t *testing.T, root string) string {
	t.Helper()
	var lines []string
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		line := fmt.Sprintf("%s %v %o %d %d", rel, info.Mode().Type(), info.Mode().Perm(), info.Size(), info.ModTime().UnixNano())
		if info.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			line += fmt.Sprintf(" %x", sha256.Sum256(b))
		}
		lines = append(lines, line)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// isolateTmp points TMPDIR at a directory of this test, so that the count of scratch
// directories is not disturbed by a leftover of an earlier or a concurrent run. The
// shared template workspace is made first, outside it.
func isolateTmp(t *testing.T) {
	t.Helper()
	template(t)
	t.Setenv("TMPDIR", t.TempDir())
}

// openScratchLeftovers counts the private directories a read-only open makes in
// the temporary directory (the TMPDIR of the test: see isolateTmp).
func openScratchLeftovers() int {
	m, _ := filepath.Glob(filepath.Join(os.TempDir(), "spo-layout-open-*"))
	return len(m)
}

// standardLayout is a standard workspace with some records, exported once: the
// layout directory and its pin.
func standardLayout(t *testing.T) (ws, root, pin string) {
	t.Helper()
	ws = copyWorkspace(t)
	if out, err := withPass(t, ws, testPass, "pool", "kes", "generate", poolName); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	root = filepath.Join(t.TempDir(), "layout")
	return ws, root, exportLayout(t, ws, root)
}

// openCmd runs a command on a layout directory with the passphrase on a descriptor.
func openCmd(t *testing.T, root, pin string, args ...string) (string, error, *fakeTerm) {
	t.Helper()
	term := &fakeTerm{}
	full := []string{"-C", root, "--pin", pin, "--passphrase-fd", fdOf(t, testPass)}
	out, err := exec(t, term, append(full, args...)...)
	return out, err, term
}

// spec: SPO-Xlayout-MODE-001, SPO-Xlayout-MODE-002, SPO-Xlayout-MODE-006
func TestLayoutOpenerListsAndShowsAStandardLayoutAndChangesNothing(t *testing.T) {
	isolateTmp(t)
	ws, root, pin := standardLayout(t)
	want, _ := withPass(t, ws, testPass, "store", "slots")
	wsBefore := treeFingerprint(t, ws)
	before := treeFingerprint(t, root)
	leftovers := openScratchLeftovers()

	out, err, term := openCmd(t, root, pin, "store", "slots")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "passphrase") || !strings.Contains(out, "recovery") {
		t.Errorf("store slots of the layout:\n%s", out)
	}
	for _, line := range strings.Split(strings.TrimSpace(want), "\n") {
		if !strings.Contains(out, strings.TrimSpace(line)) {
			t.Errorf("the slot line %q of the workspace is not in the layout's:\n%s", line, out)
		}
	}
	if !strings.Contains(out, "read-only") || !strings.Contains(out, "not audited") {
		t.Errorf("the open does not say that it is read-only and not audited:\n%s", out)
	}
	if len(term.asked) != 0 {
		t.Errorf("the terminal was asked %q (the passphrase came on a descriptor)", term.asked)
	}
	for _, c := range [][]string{{"workspace", "policy", "show"}, {"workspace", "slot", "list"}, {"workspace", "checkpoint-key", "show"}} {
		out, err, _ := openCmd(t, root, pin, c...)
		if c[1] == "checkpoint-key" {
			if err != nil && !strings.Contains(err.Error(), "no checkpoint key") {
				t.Errorf("%v: %v\n%s", c, err, out)
			}
			continue
		}
		if err != nil {
			t.Errorf("%v: %v\n%s", c, err, out)
		}
		if c[1] == "policy" && !strings.Contains(out, "standard") {
			t.Errorf("policy show:\n%s", out)
		}
	}
	if got := treeFingerprint(t, root); got != before {
		t.Errorf("the layout directory changed:\n%s\n--- now\n%s", before, got)
	}
	if got := treeFingerprint(t, ws); got != wsBefore {
		t.Error("the workspace changed")
	}
	if openScratchLeftovers() != leftovers {
		t.Error("a scratch directory was left behind")
	}
}

// A pin is required, and every refusal that needs no secret comes before anything
// is asked or read.
//
// spec: SPO-Xlayout-MODE-001
func TestLayoutOpenerNeedsAPinAndRefusesBeforeAnyPrompt(t *testing.T) {
	isolateTmp(t)
	_, root, pin := standardLayout(t)
	before := treeFingerprint(t, root)
	parts := strings.Split(pin, ":")
	wrong := strings.Join([]string{parts[0], parts[1], parts[2], strings.Repeat("0", 64)}, ":")
	cases := map[string]struct {
		args []string
		want string
	}{
		"no pin":                        {[]string{"-C", root, "store", "slots"}, "-C names a sealed layout"},
		"a pin of no kind":              {[]string{"-C", root, "--pin", "trust-me", "store", "slots"}, "pin"},
		"a pin of a head not there":     {[]string{"-C", root, "--pin", wrong, "store", "slots"}, "not the head the pin names"},
		"the local pin":                 {[]string{"-C", root, "--pin", "local", "store", "slots"}, "names the layout itself"},
		"the recovery composite":        {[]string{"-C", root, "--pin", pin, "--unlock", "recovery-composite", "store", "slots"}, "recovery-composite"},
		"fido2 for a passphrase layout": {[]string{"-C", root, "--pin", pin, "--unlock", "fido2", "store", "slots"}, "opened with its passphrase"},
	}
	for name, c := range cases {
		term := &fakeTerm{}
		out, err := exec(t, term, c.args...)
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
	if out, err := withPass(t, root, "not the passphrase", "store", "slots"); err == nil {
		t.Errorf("a layout with no pin opened:\n%s", out)
	}
	if out, err, _ := openCmd(t, root, pin, "store", "slots"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	f, fd := fdIn(t, "not the passphrase\n")
	defer f.Close()
	if out, err := exec(t, nil, "-C", root, "--pin", pin, "--passphrase-fd", fd, "store", "slots"); err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Errorf("a wrong passphrase: %v\n%s", err, out)
	}
	if treeFingerprint(t, root) != before {
		t.Error("the layout directory changed")
	}
	if openScratchLeftovers() != 0 {
		t.Error("a scratch directory was left behind")
	}
}

// sampleArgs finds arguments that satisfy the command's own argument check, so the
// walk reaches the read-only gate of every command.
func sampleArgs(t *testing.T, c *cobra.Command) []string {
	t.Helper()
	for n := 0; n <= 6; n++ {
		args := make([]string, n)
		for i := range args {
			args[i] = "x"
		}
		if c.ValidateArgs(args) == nil {
			return args
		}
	}
	t.Fatalf("no arguments satisfy %q", c.CommandPath())
	return nil
}

// Every command of the tree the binary builds (including the hidden ones, `tui`
// and cobra's `help` and `completion`) is classified; a command that writes or needs
// what a layout does not hold is refused with the one read-only error, before the
// terminal or any authenticator is asked, and writes nothing. A command added later
// and not classified is refused as well.
//
// spec: SPO-Xlayout-MODE-005, SPO-Xlayout-MODE-009
func TestLayoutOpenerEveryCommandIsClassifiedAndTheWritingOnesAreRefused(t *testing.T) {
	isolateTmp(t)
	_, root, pin := standardLayout(t)
	before := treeFingerprint(t, root)
	tree := buildRoot(newDeps(io.Discard, io.Discard, nil))
	tree.InitDefaultHelpCmd()
	tree.InitDefaultCompletionCmd()
	paths := allPaths(tree)
	hasTUI, hasHelp, hasCompletion := false, false, false
	classes := map[string]int{}
	byClass := map[string][]string{}
	for _, p := range paths {
		hasTUI = hasTUI || p == "tui"
		hasHelp = hasHelp || p == "help"
		hasCompletion = hasCompletion || strings.HasPrefix(p, "completion ")
		c, _, err := tree.Find(strings.Fields(p))
		if err != nil || c == nil {
			t.Fatalf("%s: %v", p, err)
		}
		class := cli.LayoutAccess(c)
		classes[class]++
		byClass[class] = append(byClass[class], p)
		if !cli.LayoutListed(c) {
			t.Errorf("%s is not in the layout classification table", p)
		}
		switch class {
		case cli.LayoutOwn, cli.LayoutOpens:
			continue
		case cli.LayoutExempt, cli.LayoutRefused:
		default:
			t.Errorf("%s is not classified for a layout (%q)", p, class)
			continue
		}
		term := &fakeTerm{}
		var out bytes.Buffer
		term.out = &out
		deps := newDeps(&out, &out, term)
		runner := &countingRunner{Runner: fidoRunner{"/nonexistent"}}
		deps.Factors = &fido2cli.Source{Tools: fidoTools{t.TempDir()}, Runner: runner}
		root2 := buildRoot(deps)
		f, fd := fdIn(t, testPass+"\n")
		args := append([]string{"-C", root, "--pin", pin, "--passphrase-fd", fd}, strings.Fields(p)...)
		root2.SetArgs(append(args, sampleArgs(t, c)...))
		err = root2.ExecuteContext(context.Background())
		if pos, _ := f.Seek(0, io.SeekCurrent); pos != 0 {
			t.Errorf("%s: the passphrase descriptor was read", p)
		}
		if len(term.asked) != 0 || runner.n.Load() != 0 {
			t.Errorf("%s: the terminal was asked %q and the authenticator tools were called %d times", p, term.asked, runner.n.Load())
		}
		// the note a read-only open prints (the help text of --pin says "opened read-only" too)
		if strings.Contains(out.String(), "is open read-only; nothing is written") {
			t.Errorf("%s ran against the layout:\n%s", p, out.String())
		}
		if class == cli.LayoutExempt {
			// does not use the directory: it may succeed or fail on its own terms
			continue
		}
		if err == nil || !strings.Contains(err.Error(), readOnlyWords) || !strings.Contains(err.Error(), "spo store convert --from-layout") {
			t.Errorf("%s: want the read-only refusal, got %v\n%s", p, err, out.String())
		}
	}
	if !hasTUI || !hasHelp || !hasCompletion {
		t.Errorf("the walk missed commands: tui %v, help %v, completion %v (%v)", hasTUI, hasHelp, hasCompletion, paths)
	}
	if treeFingerprint(t, root) != before {
		t.Error("a refused command changed the layout directory")
	}
	if openScratchLeftovers() != 0 {
		t.Error("a scratch directory was left behind")
	}
	t.Logf("%d commands: %v", len(paths), classes)
	// the commands that run against a layout are exactly these: a command that writes
	// must never be added to the list by accident
	for class, want := range map[string]string{
		cli.LayoutOpens:  "store slots, workspace checkpoint-key show, workspace policy show, workspace slot list",
		cli.LayoutOwn:    "store verify",
		cli.LayoutExempt: "completion bash, completion fish, completion powershell, completion zsh, help, toolchain check, version",
	} {
		got := byClass[class]
		sort.Strings(got)
		if strings.Join(got, ", ") != want {
			t.Errorf("the %s commands are %v, want %s", class, got, want)
		}
	}
	for _, p := range []string{"tui"} {
		if !inList(byClass[cli.LayoutRefused], p) {
			t.Errorf("%s is not deliberately refused", p)
		}
	}
}

func inList(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// allPaths is every runnable command of the tree, hidden and deprecated ones too.
func allPaths(root *cobra.Command) []string {
	var out []string
	var walk func(c *cobra.Command, path []string)
	walk = func(c *cobra.Command, path []string) {
		if len(path) > 0 && c.Runnable() {
			out = append(out, strings.Join(path, " "))
		}
		for _, s := range c.Commands() {
			walk(s, append(append([]string(nil), path...), s.Name()))
		}
	}
	walk(root, nil)
	sort.Strings(out)
	return out
}

// A command nobody classified is refused by the gate itself: a dummy command added
// to the tree the binary builds is run with -C naming a layout.
//
// spec: SPO-Xlayout-MODE-005
func TestLayoutOpenerRefusesACommandNobodyClassified(t *testing.T) {
	isolateTmp(t)
	_, root, pin := standardLayout(t)
	before := treeFingerprint(t, root)
	var out bytes.Buffer
	term := &fakeTerm{out: &out}
	r := buildRoot(newDeps(&out, &out, term))
	ran := false
	r.AddCommand(&cobra.Command{Use: "zz-new", RunE: func(*cobra.Command, []string) error { ran = true; return nil }})
	r.SetArgs([]string{"-C", root, "--pin", pin, "--passphrase-fd", fdOf(t, testPass), "zz-new"})
	err := r.ExecuteContext(context.Background())
	if err == nil || !strings.Contains(err.Error(), readOnlyWords) || ran {
		t.Errorf("an unclassified command: ran %v, %v\n%s", ran, err, out.String())
	}
	if len(term.asked) != 0 || treeFingerprint(t, root) != before || openScratchLeftovers() != 0 {
		t.Error("an unclassified command asked, wrote or left a scratch directory")
	}
}

// A shell completion request (cobra's hidden __complete) runs with flag parsing
// off, so the root's pre-run sees no -C and no --pin, and it is not in the table;
// it cannot reach the layout either: the
// names it lists come from a workspace opened with a passphrase, which a completion
// request never has. With -C naming a layout it asks nothing, reads no descriptor,
// starts no read-only open and writes nothing.
//
// spec: SPO-Xlayout-MODE-005
func TestAShellCompletionRequestOnALayoutReadsAndWritesNothing(t *testing.T) {
	isolateTmp(t)
	_, root, pin := standardLayout(t)
	before := treeFingerprint(t, root)
	for _, name := range []string{"__complete", "__completeNoDesc"} {
		g := runGuarded(t, "-C", root, "--pin", pin, name, "pool", "kes", "generate", "")
		if g.err != nil && !strings.Contains(g.err.Error(), readOnlyWords) {
			t.Errorf("%s: %v", name, g.err)
		}
		if len(g.asked) != 0 || g.tools != 0 || g.fdRead || strings.Contains(g.out, "is open read-only; nothing is written") {
			t.Errorf("%s: asked %q, tool calls %d, passphrase read %v\n%s", name, g.asked, g.tools, g.fdRead, g.out)
		}
	}
	if treeFingerprint(t, root) != before || openScratchLeftovers() != 0 {
		t.Error("a completion request changed the layout directory or left a scratch directory")
	}
}

// guarded is the outcome of a run that must not have asked for anything.
type guarded struct {
	out    string
	err    error
	asked  []string
	tools  int32
	fdRead bool
}

// runGuarded runs the binary's tree with the passphrase on a descriptor, an
// authenticator whose every call is counted, and a terminal that records its prompts.
func runGuarded(t *testing.T, args ...string) guarded {
	t.Helper()
	var out bytes.Buffer
	term := &fakeTerm{out: &out}
	deps := newDeps(&out, &out, term)
	runner := &countingRunner{Runner: fidoRunner{"/nonexistent"}}
	deps.Factors = &fido2cli.Source{Tools: fidoTools{t.TempDir()}, Runner: runner}
	f, fd := fdIn(t, testPass+"\n")
	r := buildRoot(deps)
	r.SetArgs(append([]string{"--passphrase-fd", fd}, args...))
	err := r.ExecuteContext(context.Background())
	pos, _ := f.Seek(0, io.SeekCurrent)
	return guarded{out.String(), err, term.asked, runner.n.Load(), pos != 0}
}

// A top-level --pin is only for opening a sealed layout. A directory that holds a
// workspace file (a hostile sink may plant one beside the layout's objects), a
// plain workspace and a directory that is neither are refused before anything is
// read, asked or written, whatever the pin is and whatever the command is: the
// planted file is never opened as a workspace.
//
// spec: SPO-Xlayout-MODE-010
func TestTopLevelPinIsRefusedWhenTheDirectoryIsNotAPureLayout(t *testing.T) {
	isolateTmp(t)
	_, layout, realPin := standardLayout(t)
	planted := func(t *testing.T) string {
		d := filepath.Join(t.TempDir(), "layout")
		copyTree(t, layout, d)
		b := readFile(t, filepath.Join(copyWorkspace(t), cli.WorkspaceFile))
		if err := os.WriteFile(filepath.Join(d, cli.WorkspaceFile), b, 0o600); err != nil {
			t.Fatal(err)
		}
		return d
	}
	dirs := map[string]func(t *testing.T) string{
		"a layout with a planted workspace file": planted,
		"a plain workspace":                      copyWorkspace,
		"a directory that is neither":            func(t *testing.T) string { return t.TempDir() },
		"a workspace file and an empty heads directory": func(t *testing.T) string {
			d := copyWorkspace(t)
			if err := os.Mkdir(filepath.Join(d, "heads"), 0o700); err != nil {
				t.Fatal(err)
			}
			return d
		},
	}
	cmds := map[string][]string{
		"a read command":  {"store", "slots"},
		"a write command": {"pool", "kes", "generate", poolName},
	}
	for dn, mk := range dirs {
		for _, pin := range []string{realPin, "garbage"} {
			for cn, c := range cmds {
				t.Run(dn+"/"+pin[:7]+"/"+cn, func(t *testing.T) {
					d := mk(t)
					before := treeFingerprint(t, d)
					g := runGuarded(t, append([]string{"-C", d, "--pin", pin}, c...)...)
					if g.err == nil || !strings.Contains(g.err.Error(), "only for opening a sealed layout") {
						t.Fatalf("accepted or refused for another reason: %v\n%s", g.err, g.out)
					}
					if len(g.asked) != 0 || g.tools != 0 || g.fdRead {
						t.Errorf("asked %q, tool calls %d, passphrase read %v", g.asked, g.tools, g.fdRead)
					}
					if treeFingerprint(t, d) != before {
						t.Error("the directory changed")
					}
					if openScratchLeftovers() != 0 {
						t.Error("a scratch directory was left behind")
					}
				})
			}
		}
	}
}

// The --pin of a command that has one of its own (store verify --layout) is not the
// top-level one: it still works from an ordinary workspace.
//
// spec: SPO-Xlayout-MODE-010
func TestACommandsOwnPinStillWorksOnAnOrdinaryWorkspace(t *testing.T) {
	isolateTmp(t)
	ws, root, pin := standardLayout(t)
	out, err := withPass(t, ws, testPass, "store", "verify", "--layout", root, "--pin", pin)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(out, "only for opening a sealed layout") {
		t.Errorf("the top-level refusal fired:\n%s", out)
	}
}

// The mode is decided once, before the command runs. A workspace file that appears
// in the layout directory after that (a hostile sink, between the check and the
// run) does not turn the command into an ordinary open: it is still handled as a
// layout command (the layout reader refuses the foreign file), the planted file is
// not opened and nothing is written beside it.
//
// spec: SPO-Xlayout-MODE-009
func TestTheModeIsDecidedOnceAndAWorkspaceFileThatAppearsLaterChangesNothing(t *testing.T) {
	isolateTmp(t)
	for _, cmd := range [][]string{{"store", "slots"}, {"store", "verify"}, {"store", "verify", "--deep"}} {
		t.Run(strings.Join(cmd, " "), func(t *testing.T) {
			_, root, pin := standardLayout(t)
			planted := readFile(t, filepath.Join(copyWorkspace(t), cli.WorkspaceFile))
			var out bytes.Buffer
			term := &fakeTerm{out: &out}
			r := buildRoot(newDeps(&out, &out, term))
			c, _, err := r.Find(cmd)
			if err != nil {
				t.Fatal(err)
			}
			// PreRunE runs after the root's persistent pre-run (which decides the mode)
			// and before RunE
			c.PreRunE = func(*cobra.Command, []string) error {
				return os.WriteFile(filepath.Join(root, cli.WorkspaceFile), planted, 0o600)
			}
			r.SetArgs(append([]string{"-C", root, "--pin", pin, "--passphrase-fd", fdOf(t, testPass)}, cmd...))
			err = r.ExecuteContext(context.Background())
			// the layout reader refuses a directory with a foreign file in it; either way
			// the command was handled as a layout command, and never opened the planted file
			if err == nil || !strings.Contains(err.Error(), "is not part of a layout") {
				t.Errorf("the command was not handled as a layout command: %v\n%s", err, out.String())
			}
			if strings.Contains(out.String(), "argon2id") || len(term.asked) != 0 {
				t.Errorf("the planted workspace file was opened or the terminal asked %q:\n%s", term.asked, out.String())
			}
			if got := readFile(t, filepath.Join(root, cli.WorkspaceFile)); !bytes.Equal(got, planted) {
				t.Error("the planted file was changed")
			}
			for _, n := range []string{cli.WorkspaceFile + ".head", cli.WorkspaceFile + ".head.lock"} {
				if _, err := os.Lstat(filepath.Join(root, n)); err == nil {
					t.Errorf("%s was created in the layout directory", n)
				}
			}
		})
	}
}

// A hardware layout is opened with the daily authenticator, once. The commands that
// are refused touch the authenticator not at all, and the open changes nothing.
//
// spec: SPO-Xlayout-MODE-004, SPO-Xlayout-MODE-003
func TestLayoutOpenerHardwarePresentsTheAuthenticatorOnce(t *testing.T) {
	isolateTmp(t)
	rig := newDeviceRunner(t)
	ws, _ := toHardwareDR(t, rig)
	counter := &countingRunner{Runner: rig}
	run := func(wsDir string, args ...string) (string, error) {
		t.Helper()
		f, fd := fdIn(t, fidoPIN+"\n")
		defer f.Close()
		full := append([]string{"-C", wsDir, "--fido2-pin-fd", fd, "--fido2-device", dev0}, args...)
		return runFidoWith(t, counter, nil, full...)
	}
	// a pool with its cold key, and the hot keys
	for _, c := range [][]string{{"pool", "keys", "generate", poolName}, {"pool", "vrf", "generate", poolName}, {"pool", "kes", "generate", poolName}} {
		if out, err := run(ws, c...); err != nil {
			t.Fatalf("%v: %v\n%s", c, err, out)
		}
	}
	root := filepath.Join(t.TempDir(), "layout")
	out, err := run(ws, "store", "convert", "--to-layout", root)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	pin := layoutPinRE.FindStringSubmatch(out)[1]
	base := counter.asserts.Load()
	if o, err := run(ws, "store", "slots"); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	perPresentation := counter.asserts.Load() - base
	before := treeFingerprint(t, root)
	leftovers := openScratchLeftovers()

	base = counter.asserts.Load()
	out, err = run(root, "--pin", pin, "store", "slots")
	if err != nil || !strings.Contains(out, "fido2-hmac") {
		t.Fatalf("%v\n%s", err, out)
	}
	if got := counter.asserts.Load() - base; got != perPresentation {
		t.Errorf("a read-only open of a hardware layout touched the authenticator %d times; one presentation is %d", got, perPresentation)
	}
	t.Logf("assertions: one presentation %d, a read-only open %d", perPresentation, counter.asserts.Load()-base)
	// the commands that are refused touch nothing; so does a passphrase
	base = counter.asserts.Load()
	for _, c := range [][]string{{"pool", "opcert", "issue", poolName}, {"pool", "kes", "generate", poolName}, {"store", "backup", filepath.Join(t.TempDir(), "b")}, {"workspace", "export", t.TempDir()}} {
		if o, err := run(root, append([]string{"--pin", pin}, c...)...); err == nil || !strings.Contains(err.Error(), readOnlyWords) {
			t.Errorf("%v: %v\n%s", c, err, o)
		}
	}
	if o, err := run(root, "--pin", pin, "--unlock", "passphrase", "store", "slots"); err == nil || !strings.Contains(err.Error(), "no passphrase opens it") {
		t.Errorf("%v\n%s", err, o)
	}
	if o, err := run(root, "--pin", pin, "--unlock", "recovery-composite", "store", "slots"); err == nil || !strings.Contains(err.Error(), "recovery-composite") {
		t.Errorf("%v\n%s", err, o)
	}
	if counter.asserts.Load() != base {
		t.Errorf("the authenticator was touched %d times for refused commands", counter.asserts.Load()-base)
	}
	// store verify and its --deep through the layout: one presentation each
	for _, extra := range [][]string{nil, {"--deep"}} {
		base = counter.asserts.Load()
		o, err := run(root, append([]string{"--pin", pin, "store", "verify"}, extra...)...)
		if err != nil {
			t.Fatalf("%v\n%s", err, o)
		}
		got := counter.asserts.Load() - base
		t.Logf("store verify %v: %d assertions", extra, got)
		if len(extra) == 1 && got != perPresentation {
			t.Errorf("store verify --deep of a layout touched the authenticator %d times, one presentation is %d", got, perPresentation)
		}
		if len(extra) == 1 && !strings.Contains(o, "cold-role") {
			t.Errorf("--deep does not say that cold-role records were not opened:\n%s", o)
		}
	}
	if treeFingerprint(t, root) != before {
		t.Error("the layout directory changed")
	}
	if openScratchLeftovers() != leftovers {
		t.Error("a scratch directory was left behind")
	}
}

// store verify -C LAYOUT is store verify --layout LAYOUT, and --deep decrypts every
// record of the scratch store.
//
// spec: SPO-Xlayout-MODE-007
func TestStoreVerifyOfALayoutDirectoryEqualsVerifyLayout(t *testing.T) {
	ws, root, pin := standardLayout(t)
	want, err := withPass(t, ws, testPass, "store", "verify", "--layout", root, "--pin", pin)
	if err != nil {
		t.Fatalf("%v\n%s", err, want)
	}
	got, err, _ := openCmd(t, root, pin, "store", "verify")
	if err != nil {
		t.Fatalf("%v\n%s", err, got)
	}
	if got != want {
		t.Errorf("store verify -C layout differs from store verify --layout:\n--- layout\n%s\n--- -C\n%s", want, got)
	}
	deep, err, _ := openCmd(t, root, pin, "store", "verify", "--deep")
	if err != nil || !strings.Contains(deep, "Every record was also decrypted") || !strings.Contains(deep, "Pin of this head: "+pin) {
		t.Fatalf("%v\n%s", err, deep)
	}
	if o, err, term := openCmd(t, root, pin, "store", "verify", "--locked"); err != nil || len(term.asked) != 0 || !strings.Contains(o, "Only the locked checks") {
		t.Errorf("%v\n%s", err, o)
	}
	// --locked with --deep is refused the same way through -C and through --layout
	_, errC, _ := openCmd(t, root, pin, "store", "verify", "--locked", "--deep")
	_, errL := withPass(t, ws, testPass, "store", "verify", "--layout", root, "--pin", pin, "--locked", "--deep")
	if errC == nil || errL == nil || errC.Error() != errL.Error() || !strings.Contains(errC.Error(), "--locked asks for no credential") {
		t.Errorf("--locked --deep: -C gives %v, --layout gives %v", errC, errL)
	}
	for _, bad := range [][]string{{"--backup", "x"}, {"--with-cold-factor"}} {
		if _, err, _ := openCmd(t, root, pin, append([]string{"store", "verify"}, bad...)...); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

// The hostile-directory cases of the verifier apply unchanged to the opener: a
// damaged layout is refused, nothing runs, no scratch store is left.
//
// spec: SPO-Xlayout-MODE-001, SPO-Xlayout-MODE-006, SPO-Xlayout-OUT-021, SPO-Xlayout-INV-025
func TestLayoutOpenerRefusesADamagedDirectory(t *testing.T) {
	isolateTmp(t)
	_, pristine, pin := standardLayout(t)
	files := readLayout(t, pristine)
	var sealed string
	for n := range files {
		if strings.HasPrefix(n, "objects/") && files[n][0] != 0x02 && (sealed == "" || n < sealed) {
			sealed = n
		}
	}
	damage := map[string]func(root string){
		"a flipped byte in a sealed object": func(root string) {
			b := readFile(t, filepath.Join(root, sealed))
			b[len(b)/2] ^= 1
			os.WriteFile(filepath.Join(root, sealed), b, 0o600)
		},
		"a missing sealed object": func(root string) { os.Remove(filepath.Join(root, sealed)) },
		"junk at the head": func(root string) {
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
			before := treeFingerprint(t, root)
			out, err, _ := openCmd(t, root, pin, "store", "slots")
			if err == nil {
				t.Fatalf("a damaged layout opened:\n%s", out)
			}
			if strings.Contains(out, "Opened read-only") || strings.Contains(out, "passphrase") && strings.Contains(out, "passphrase    ") {
				t.Errorf("a command ran on a damaged layout:\n%s", out)
			}
			if treeFingerprint(t, root) != before {
				t.Error("the damaged directory was changed")
			}
			if openScratchLeftovers() != 0 {
				t.Error("a scratch directory was left behind")
			}
		})
	}
}

// The private scratch directory is removed on every exit: success, a refusal after
// it was made, a cancelled context and a panic; and a directory a killed process
// left behind is swept by the next open.
//
// spec: SPO-Xlayout-MODE-006
func TestLayoutOpenerLeavesNoScratchOnAnyExit(t *testing.T) {
	isolateTmp(t)
	_, root, pin := standardLayout(t)
	pf := func() string { return fdOf(t, testPass) }
	// a wrong passphrase, after the locked pass
	f, fd := fdIn(t, "wrong\n")
	defer f.Close()
	if _, err := exec(t, nil, "-C", root, "--pin", pin, "--passphrase-fd", fd, "store", "slots"); err == nil {
		t.Fatal("a wrong passphrase opened the layout")
	}
	if n := openScratchLeftovers(); n != 0 {
		t.Errorf("%d scratch directories after a wrong passphrase", n)
	}
	// a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	cr := cli.NewRoot(newDeps(&out, &out, &fakeTerm{out: &out}))
	cr.SetArgs([]string{"-C", root, "--pin", pin, "--passphrase-fd", pf(), "store", "slots"})
	if err := cr.ExecuteContext(ctx); err == nil {
		t.Error("a cancelled context opened the layout")
	}
	if n := openScratchLeftovers(); n != 0 {
		t.Errorf("%d scratch directories after a cancelled context", n)
	}
	// a panic after the layout is open
	deps := newDeps(&out, &out, &fakeTerm{out: &out})
	describe := deps.Sealed.Describe
	deps.Sealed.Describe = func(path string) (cli.WorkspaceInfo, error) {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("the scratch store file is not there when the command asks for it: %v", err)
		}
		panic("a command failed in the middle")
	}
	_ = describe
	pr := cli.NewRoot(deps)
	pr.SetArgs([]string{"-C", root, "--pin", pin, "--passphrase-fd", pf(), "workspace", "policy", "show"})
	func() {
		defer func() {
			if recover() == nil {
				t.Error("the panic did not happen")
			}
		}()
		pr.ExecuteContext(context.Background())
	}()
	if n := openScratchLeftovers(); n != 0 {
		t.Errorf("%d scratch directories after a panic", n)
	}
	// a stale directory of a killed process is swept; a young one and one of
	// another name are left
	stale, err := os.MkdirTemp("", "spo-layout-open-")
	if err != nil {
		t.Fatal(err)
	}
	young, _ := os.MkdirTemp("", "spo-layout-open-")
	defer os.RemoveAll(young)
	old := time.Now().Add(-48 * time.Hour)
	os.Chtimes(stale, old, old)
	if out, err, _ := openCmd(t, root, pin, "store", "slots"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, err := os.Stat(stale); err == nil {
		t.Error("the stale scratch directory was not swept")
		os.RemoveAll(stale)
	}
	if _, err := os.Stat(young); err != nil {
		t.Error("a young scratch directory was removed")
	}
}

// countingSession wraps the layout session of the wiring so that a test sees what
// --deep asks of the read-only handle.
type countingSession struct {
	cli.LayoutSession
	verify *atomic.Int32
	fail   error
}

type countingStore struct {
	cli.SealedStore
	verify *atomic.Int32
	fail   error
}

func (c countingStore) VerifyPayloads(ctx context.Context) error {
	c.verify.Add(1)
	return c.fail
}

func (c countingSession) OpenReadOnly(path string) (cli.SealedStore, error) {
	st, err := c.LayoutSession.OpenReadOnly(path)
	if err != nil {
		return nil, err
	}
	return countingStore{st, c.verify, c.fail}, nil
}

// --deep decrypts every record through the read-only handle, once, and a record
// that does not decrypt fails the check; without --deep nothing is decrypted.
//
// spec: SPO-Xlayout-MODE-007
func TestStoreVerifyDeepOfALayoutDecryptsThroughTheReadOnlyHandle(t *testing.T) {
	_, root, pin := standardLayout(t)
	run := func(fail error, args ...string) (string, error) {
		var out bytes.Buffer
		deps := newDeps(&out, &out, &fakeTerm{out: &out})
		inner := deps.LayoutRead.Session
		n := &atomic.Int32{}
		deps.LayoutRead.Session = func(p *secret.Buffer, f *cli.FactorOpen) cli.LayoutSession {
			return countingSession{inner(p, f), n, fail}
		}
		r := cli.NewRoot(deps)
		r.SetArgs(append([]string{"-C", root, "--pin", pin, "--passphrase-fd", fdOf(t, testPass)}, args...))
		err := r.ExecuteContext(context.Background())
		t.Logf("%v: decrypted %d times", args, n.Load())
		if len(args) == 2 && args[1] == "verify" && n.Load() != 0 {
			t.Errorf("a plain verify decrypted %d times", n.Load())
		}
		if len(args) == 3 && n.Load() != 1 {
			t.Errorf("--deep decrypted %d times", n.Load())
		}
		return out.String(), err
	}
	if out, err := run(nil, "store", "verify"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, err := run(nil, "store", "verify", "--deep"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, err := run(errors.New("record does not decrypt"), "store", "verify", "--deep"); err == nil || !strings.Contains(err.Error(), "did not decrypt") || strings.Contains(out, "Every record was also decrypted") {
		t.Errorf("a record that does not decrypt passed: %v\n%s", err, out)
	}
}

// A directory that has a heads directory and a workspace file is a workspace, not a
// layout: the commands run on the workspace as ever.
//
// spec: SPO-Xlayout-MODE-001
func TestADirectoryWithAWorkspaceFileIsNotOpenedAsALayout(t *testing.T) {
	ws := copyWorkspace(t)
	if err := os.Mkdir(filepath.Join(ws, "heads"), 0o700); err != nil {
		t.Fatal(err)
	}
	out, err := withPass(t, ws, testPass, "pool", "kes", "generate", poolName)
	if err != nil || strings.Contains(out, "read-only") {
		t.Fatalf("a workspace with a heads directory was opened as a layout: %v\n%s", err, out)
	}
}

// The errors of the read-only handle are the command layer's errors, with the one
// message that names the conversion; a cold-role refusal and a write refusal are
// told apart.
//
// spec: SPO-Xlayout-MODE-002, SPO-Xlayout-MODE-003
func TestTheStoresLayoutErrorsAreMappedForTheCommandLayer(t *testing.T) {
	if err := mapStoreErr(fmt.Errorf("a write: %w", sqlitestore.ErrLayoutReadOnly)); !errors.Is(err, cli.ErrLayoutReadOnly) || !strings.Contains(err.Error(), "opened read-only; convert it into a workspace") {
		t.Errorf("the write refusal: %v", err)
	}
	err := mapStoreErr(&sqlitestore.RefError{Err: sqlitestore.ErrLayoutColdRecord})
	if !errors.Is(err, cli.ErrLayoutColdRecord) || errors.Is(err, cli.ErrLayoutReadOnly) || !strings.Contains(err.Error(), "cold-role record is never opened") || !strings.Contains(err.Error(), "spo store convert --from-layout") {
		t.Errorf("the cold-role refusal: %v", err)
	}
}

// Cobra runs only the nearest persistent pre-run, so one on any command but the
// root would replace the check that decides the mode of -C.
//
// spec: SPO-Xlayout-MODE-009
func TestOnlyTheRootHasAPersistentPreRun(t *testing.T) {
	root := buildRoot(newDeps(io.Discard, io.Discard, nil))
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if c != root && (c.PersistentPreRun != nil || c.PersistentPreRunE != nil) {
			t.Errorf("%s has its own persistent pre-run; it replaces the root's layout check", c.CommandPath())
		}
		for _, s := range c.Commands() {
			walk(s)
		}
	}
	walk(root)
	if root.PersistentPreRunE == nil {
		t.Fatal("the root has no persistent pre-run")
	}
}

// A command that reaches the workspace without the root's check having run (a
// persistent pre-run of its own) opens nothing, even with a workspace file planted
// in the layout.
//
// spec: SPO-Xlayout-MODE-009
func TestACommandThatSkippedTheModeDecisionOpensNothing(t *testing.T) {
	isolateTmp(t)
	_, root, pin := standardLayout(t)
	var out bytes.Buffer
	term := &fakeTerm{out: &out}
	r := buildRoot(newDeps(&out, &out, term))
	st, _, err := r.Find([]string{"store"})
	if err != nil {
		t.Fatal(err)
	}
	st.PersistentPreRunE = func(*cobra.Command, []string) error { return nil }
	before := treeFingerprint(t, root)
	r.SetArgs([]string{"-C", root, "--pin", pin, "store", "slots"})
	err = r.ExecuteContext(context.Background())
	if err == nil || !strings.Contains(err.Error(), "nothing was opened") {
		t.Errorf("store slots without the mode decision: %v\n%s", err, out.String())
	}
	if len(term.asked) != 0 || treeFingerprint(t, root) != before {
		t.Error("a command that skipped the mode decision asked or wrote")
	}
}
