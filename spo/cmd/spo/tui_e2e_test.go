package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/tui"
	"github.com/mochipool/workbench/spo/internal/platform/uihint"
)

// The TUI drives the same command tree as the CLI (ADR 0009). These tests run
// real commands through it on a real sealed workspace and compare with the
// CLI; and they keep the two drivers' command sets identical (concern U1).

func newTUI(t *testing.T, dir string) *tui.Driver {
	t.Helper()
	d, err := tui.NewDriver(tui.Options{
		Factory: tuiFactory(func(out, errw io.Writer, term cli.Terminal) (cli.Deps, error) { return newDeps(out, errw, term), nil }),
		Globals: []string{"-C=" + dir},
		Status:  func() tui.Status { return workspaceStatus(dir, nil) },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	return d
}

var lastGroupRE = regexp.MustCompile(`(?m)^\s+([A-Z2-7]{4}(?:-[A-Z2-7]{4}){13})$`)

// drive runs the command at path with the form values, answering each prompt
// from answers (matched by prefix of the prompt; "@LASTGROUP" is the last
// group of the recovery key the command showed). It returns the final state.
func drive(t *testing.T, d *tui.Driver, path []string, set map[string]string, answers map[string]string) tui.State {
	t.Helper()
	if err := d.Open(path...); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := d.Set(k, set[k]); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.Run(); err != nil {
		t.Fatal(err)
	}
	for {
		st, err := d.Await(2 * time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if st.Done {
			return st
		}
		var ans string
		found := false
		for prefix, a := range answers {
			if strings.HasPrefix(st.Prompt, prefix) {
				ans, found = a, true
			}
		}
		if !found {
			t.Fatalf("unexpected prompt %q (output so far %q)", st.Prompt, st.Out)
		}
		if ans == "@LASTGROUP" {
			m := lastGroupRE.FindStringSubmatch(st.Out)
			if m == nil {
				t.Fatalf("no recovery key in the output: %q", st.Out)
			}
			ans = m[1][len(m[1])-4:]
		}
		if st.Secret && strings.Contains(d.Screen(), ans) && ans != "" && len(ans) > 4 {
			t.Fatalf("the screen shows a secret before it is typed")
		}
		d.Answer(ans)
	}
}

// cliRun runs the same arguments on the CLI, with separate stdout and stderr
// and the same scripted answers.
func cliRun(t *testing.T, dir string, secrets []string, args ...string) (stdout string, err error) {
	t.Helper()
	var o, e bytes.Buffer
	term := &fakeTerm{out: &o, secrets: secrets}
	root := cli.NewRoot(newDeps(&o, &e, term))
	root.SetArgs(append([]string{"-C", dir}, args...))
	err = root.ExecuteContext(context.Background())
	return o.String(), err
}

func TestTUIRunsInitWalletAndAddressLikeTheCLI(t *testing.T) {
	dir := t.TempDir()
	d := newTUI(t, dir)
	pass := testPass

	// init: two passphrase prompts, a recovery key, its confirmation.
	st := drive(t, d, []string{"init"}, map[string]string{"--network": "preview"}, map[string]string{
		"New passphrase":        pass,
		"Repeat the passphrase": pass,
		"To confirm":            "@LASTGROUP",
	})
	if st.Err != nil || !strings.Contains(st.Out, "Created workspace") || !strings.Contains(st.Out, "Recovery key confirmed.") {
		t.Fatalf("init: err %v out %q", st.Err, st.Out)
	}
	if !strings.Contains(workspaceStatus(dir, nil).State, "sealed") {
		t.Errorf("status = %+v", workspaceStatus(dir, nil))
	}
	d.Back()

	// wallet new w: the passphrase modal, then the command's own output.
	st = drive(t, d, []string{"wallet", "new"}, map[string]string{"name": "w"}, map[string]string{"Passphrase": pass})
	if st.Err != nil {
		t.Fatalf("wallet new: %v\n%s", st.Err, st.Out)
	}
	if strings.Contains(st.Out+st.ErrOut, pass) {
		t.Error("the passphrase is in the output")
	}
	d.Back()

	// address w: the TUI's output equals the CLI's for the same arguments.
	st = drive(t, d, []string{"address"}, map[string]string{"name|address": "w", "--offline": "true"}, map[string]string{"Passphrase": pass})
	want, werr := cliRun(t, dir, []string{pass}, "address", "w", "--offline")
	if st.Out != want {
		t.Errorf("address output differs:\nTUI: %q\nCLI: %q", st.Out, want)
	}
	t.Logf("address: out %q err %v", st.Out, st.Err)
	if (st.Err == nil) != (werr == nil) || (werr != nil && st.Err.Error() != werr.Error()) {
		t.Errorf("address error differs: TUI %v, CLI %v", st.Err, werr)
	}
	if strings.Contains(d.Screen(), pass) {
		t.Error("the passphrase is on the screen")
	}
}

func TestTUIDeclinedConfirmationChangesNothing(t *testing.T) {
	dir := copyWorkspace(t)
	d := newTUI(t, dir)
	out := filepath.Join(t.TempDir(), "export")
	st := drive(t, d, []string{"workspace", "export"}, map[string]string{"dir": out, "--plaintext": "true"}, map[string]string{
		"Passphrase": testPass,
		"Type":       "no",
	})
	if st.Err == nil || !strings.Contains(st.Err.Error(), "declined") {
		t.Fatalf("err = %v, out %q", st.Err, st.Out)
	}
	if _, err := os.Stat(out); err == nil {
		entries, _ := os.ReadDir(out)
		if len(entries) != 0 {
			t.Errorf("a declined export wrote %d files", len(entries))
		}
	}
}

func TestTUICancelAtThePassphraseModalLeavesTheWorkspaceUntouched(t *testing.T) {
	dir := copyWorkspace(t)
	before, _ := os.ReadFile(filepath.Join(dir, cli.WorkspaceFile))
	d := newTUI(t, dir)
	if err := d.Open("store", "slots"); err != nil {
		t.Fatal(err)
	}
	if err := d.Run(); err != nil {
		t.Fatal(err)
	}
	st, err := d.Await(time.Minute)
	if err != nil || st.Prompt != "Passphrase: " || !st.Secret {
		t.Fatalf("state %+v err %v", st, err)
	}
	d.Cancel()
	st, err = d.Await(time.Minute)
	if err != nil || !st.Done || st.Err == nil {
		t.Fatalf("state %+v err %v", st, err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, cli.WorkspaceFile))
	if !bytes.Equal(before, after) {
		t.Error("a cancelled command changed the workspace file")
	}
	// The same cancel in the CLI: the prompt returns the context's error.
	_, cerr := func() (string, error) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		var o bytes.Buffer
		root := cli.NewRoot(newDeps(&o, &o, &fakeTerm{out: &o}))
		root.SetArgs([]string{"-C", dir, "store", "slots"})
		return o.String(), root.ExecuteContext(ctx)
	}()
	if cerr == nil {
		t.Error("expected the CLI cancel to be an error too")
	}
}

// cliPaths is an independent walk of the command tree.
func cliPaths(root *cobra.Command) []string {
	var out []string
	var walk func(c *cobra.Command, path []string)
	walk = func(c *cobra.Command, path []string) {
		if len(path) > 0 && c.Runnable() {
			out = append(out, strings.Join(path, " "))
		}
		for _, s := range c.Commands() {
			if s.Hidden || s.Deprecated != "" {
				continue
			}
			walk(s, append(append([]string(nil), path...), s.Name()))
		}
	}
	walk(root, nil)
	sort.Strings(out)
	return out
}

// Concern U1: a use case reachable from the CLI and not from the TUI (or the
// other way round) is a failure. The menu is generated from the tree, so this
// holds by construction; the test keeps it from being broken by a menu that
// starts to filter.
func TestU1EveryCommandIsReachableInTheTUIAndOnlyThose(t *testing.T) {
	factory := tuiFactory(func(out, errw io.Writer, term cli.Terminal) (cli.Deps, error) { return newDeps(out, errw, term), nil })
	root, err := factory(nil, discard{}, discard{})
	if err != nil {
		t.Fatal(err)
	}
	want := cliPaths(root)
	if len(want) < 50 {
		t.Fatalf("only %d commands found; is the tree built?", len(want))
	}
	d, err := tui.NewDriver(tui.Options{Factory: factory})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d commands in the menu", len(want))
	got := d.Paths()
	sort.Strings(got)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the TUI menu and the command tree differ:\nTUI: %v\nCLI: %v", got, want)
	}
	// Navigating the menu really reaches each one, and its form builds.
	for _, p := range want {
		if err := d.Open(strings.Fields(p)...); err != nil {
			t.Errorf("cannot open %q from the menu: %v", p, err)
		}
	}
	// The one command only the binary adds is the way in to the TUI itself.
	bin := cli.NewRoot(newDeps(discard{}, discard{}, nil))
	bin.AddCommand(tuiCommand(buildDeps))
	extra := map[string]bool{}
	for _, p := range cliPaths(bin) {
		extra[p] = true
	}
	for _, p := range want {
		delete(extra, p)
	}
	if len(extra) != 1 || !extra["tui"] {
		t.Errorf("the binary has commands the TUI factory tree lacks: %v", extra)
	}
}

// Concern U2: no descriptor number is ever a form field, every descriptor
// flag of the tree is classified as carrying a secret in or out, and a
// command that can show a secret is marked so its output is cleared.
func TestU2DescriptorFlagsAreClassified(t *testing.T) {
	root := cli.NewRoot(newDeps(discard{}, discard{}, nil))
	cli.MarkForUI(root)
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		check := func(f *pflag.Flag) {
			if !strings.HasSuffix(f.Name, "-fd") {
				return
			}
			dir := f.Annotations[uihint.SecretFD]
			if len(dir) != 1 {
				t.Errorf("%s --%s is a descriptor flag not classified in cli.secretFDFlags", c.CommandPath(), f.Name)
				return
			}
			if dir[0] == uihint.SecretOut && c.Annotations[uihint.SensitiveOutput] != "true" {
				t.Errorf("%s writes a secret to --%s when given and shows it otherwise, so it must be marked sensitive", c.CommandPath(), f.Name)
			}
		}
		c.Flags().VisitAll(check)
		c.PersistentFlags().VisitAll(check)
		for _, s := range c.Commands() {
			walk(s)
		}
	}
	walk(root)

	factory := tuiFactory(func(out, errw io.Writer, term cli.Terminal) (cli.Deps, error) { return newDeps(out, errw, term), nil })
	d, err := tui.NewDriver(tui.Options{Factory: factory})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range d.Paths() {
		if err := d.Open(strings.Fields(p)...); err != nil {
			t.Fatal(err)
		}
		for _, f := range d.FormLabels() {
			if strings.HasSuffix(f, "-fd") && !d.IsSecretField(f) {
				t.Errorf("%s offers %s as a number", p, f)
			}
		}
	}
}

// sensitive commands: the recovery key is shown by these, and the pane is
// cleared when the operator leaves.
func TestTUIRecoveryKeyOutputIsClearedOnLeaving(t *testing.T) {
	dir := t.TempDir()
	d := newTUI(t, dir)
	pass := testPass
	st := drive(t, d, []string{"init"}, map[string]string{"--network": "preview"}, map[string]string{
		"New passphrase": pass, "Repeat the passphrase": pass, "To confirm": "@LASTGROUP",
	})
	key := lastGroupRE.FindStringSubmatch(st.Out)
	if key == nil {
		t.Fatalf("no recovery key shown: %q", st.Out)
	}
	if !strings.Contains(d.Screen(), key[1][:4]) {
		t.Error("the recovery key is not on the screen of the command that shows it")
	}
	d.Back()
	if s := d.Screen(); strings.Contains(s, key[1]) || strings.Contains(s, key[1][:9]) {
		t.Errorf("the recovery key is still on screen after leaving:\n%s", s)
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func TestTUIAddressOutputEqualsTheCLIs(t *testing.T) {
	dir := copyWorkspace(t)
	_, addr := importWallet(t, dir)
	transfer := filepath.Join(dir, "offlineTransfer.json")
	writeTransferFile(t, transfer, addr)
	d := newTUI(t, dir)
	st := drive(t, d, []string{"address"}, map[string]string{"name|address": walletName, "--offline": "true"},
		map[string]string{"Passphrase": testPass})
	want, werr := cliRun(t, dir, []string{testPass}, "address", walletName, "--offline")
	if st.Err != nil || werr != nil {
		t.Fatalf("TUI %v, CLI %v", st.Err, werr)
	}
	if st.Out == "" || st.Out != want {
		t.Errorf("address output differs:\nTUI: %q\nCLI: %q", st.Out, want)
	}
	if !strings.Contains(st.Out, addr) {
		t.Errorf("the output does not show the address: %q", st.Out)
	}
}
