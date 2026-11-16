package tui

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/platform/uihint"
)

// hintFactory builds commands whose arguments and flags carry hints and flag
// groups, the way the CLI's tree does through cli.MarkForUI.
func hintFactory(t Terminal, out, errw io.Writer) (*cobra.Command, error) {
	root := &cobra.Command{Use: "spo", SilenceUsage: true, SilenceErrors: true}
	root.SetOut(out)
	root.SetErr(errw)
	send := &cobra.Command{Use: "send <from> <to> [--out FILE] [--dir DIR] [--in FILE]", Short: "send", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, _ = io.WriteString(out, strings.Join(args, ",")+"\n")
			return nil
		}}
	send.Flags().String("out", "", "output file")
	send.Flags().String("dir", "", "directory")
	send.Flags().String("in", "", "input json")
	uihint.SetArg(send, "from", uihint.Names(uihint.ClassWallet))
	uihint.SetArg(send, "to", uihint.Names(uihint.ClassWallet))
	uihint.SetFlag(send.Flags().Lookup("out"), uihint.NewFile(".json"))
	uihint.SetFlag(send.Flags().Lookup("dir"), uihint.Dir())
	uihint.SetFlag(send.Flags().Lookup("in"), uihint.File(".json"))

	exp := &cobra.Command{Use: "export [--password-fd N] [--plaintext] [--hardware] [--mnemonic] [--account N] [--index N]", Short: "export", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return nil }}
	exp.Flags().Int("password-fd", -1, "password on a descriptor")
	exp.Flags().Lookup("password-fd").Annotations = map[string][]string{uihint.SecretFD: {uihint.SecretIn}}
	exp.Flags().Bool("plaintext", false, "in clear")
	exp.Flags().Bool("hardware", false, "")
	exp.Flags().Bool("mnemonic", false, "")
	exp.Flags().String("account", "", "")
	exp.Flags().String("index", "", "")
	exp.MarkFlagsMutuallyExclusive("hardware", "mnemonic")
	exp.MarkFlagsOneRequired("password-fd", "plaintext")
	exp.MarkFlagsRequiredTogether("account", "index")
	root.AddCommand(send, exp)
	return root, nil
}

func newHintHarness(t *testing.T, names NameLister, start string) *harness {
	t.Helper()
	h := &harness{t: t, ch: make(chan tea.Msg, 64)}
	m, err := newModel(Options{Factory: hintFactory, Names: names, StartDir: start}, func(msg tea.Msg) { h.ch <- msg })
	if err != nil {
		t.Fatal(err)
	}
	h.m = m
	return h
}

var testNames = map[string][]string{uihint.ClassWallet: {"alice", "alpha", "bob"}}

func TestNameCompletionFromTheLister(t *testing.T) {
	h := newHintHarness(t, func(_ context.Context, pass *secret.Buffer) (map[string][]string, error) {
		if pass != nil {
			t.Error("a form open asked for a passphrase")
		}
		return testNames, nil
	}, "")
	h.open("send")
	h.typ("a")
	h.press("tab")
	if got := h.m.form.fields[0].text.String(); got != "al" {
		t.Fatalf("tab completed to %q, want the common prefix al", got)
	}
	h.press("tab") // ambiguous: cycles
	if got := h.m.form.fields[0].text.String(); got != "alice" {
		t.Fatalf("first cycle = %q", got)
	}
	h.press("tab")
	if got := h.m.form.fields[0].text.String(); got != "alpha" {
		t.Fatalf("second cycle = %q", got)
	}
	if !strings.Contains(h.m.render(), "tab completes") {
		t.Errorf("no candidates shown:\n%s", h.m.render())
	}
	// A unique match completes whole; an exact one moves on.
	h.focus("to")
	h.typ("bo")
	h.press("tab")
	if got := h.m.form.fields[1].text.String(); got != "bob" {
		t.Fatalf("unique completion = %q", got)
	}
	h.press("tab")
	if h.m.form.cursor == 1 {
		t.Error("tab on an exact name did not move to the next field")
	}
	// No candidates: tab moves on, nothing is changed.
	h.focus("from")
	h.m.form.fields[0].text.set("zzz")
	h.m.form.fields[0].cyc = nil
	h.press("tab")
	if h.m.form.fields[0].text.String() != "zzz" || h.m.form.cursor != 1 {
		t.Errorf("tab with no candidates: %q cursor %d", h.m.form.fields[0].text.String(), h.m.form.cursor)
	}
}

func TestSealedNamesStayLockedUntilAskedAndNeverEchoThePassphrase(t *testing.T) {
	var calls []bool // whether each call had a passphrase
	var got string
	lister := func(_ context.Context, pass *secret.Buffer) (map[string][]string, error) {
		calls = append(calls, pass != nil)
		if pass == nil {
			return nil, ErrLocked
		}
		_ = pass.Use(func(b []byte) error { got = string(b); return nil })
		return testNames, nil
	}
	h := newHintHarness(t, lister, "")
	h.open("send")
	if len(calls) != 1 || calls[0] {
		t.Fatalf("calls = %v, want one without a passphrase", calls)
	}
	if !strings.Contains(h.m.render(), "ctrl+n") {
		t.Errorf("the form does not say how to unlock:\n%s", h.m.render())
	}
	h.press("tab") // no candidates: moves on, does not prompt
	if h.m.unlock != nil {
		t.Fatal("a passphrase was asked for without ctrl+n")
	}
	h.focus("from")
	h.press("ctrl+n")
	if h.m.unlock == nil {
		t.Fatal("ctrl+n did not open the passphrase modal")
	}
	h.typ("correct horse battery")
	if scr := h.m.render(); strings.Contains(scr, "correct") || strings.Contains(scr, "horse") {
		t.Fatalf("the passphrase is on the screen:\n%s", scr)
	}
	h.press("enter")
	h.until("the names", func() bool { return h.m.names.lists != nil })
	if got != "correct horse battery" {
		t.Errorf("the lister got %q", got)
	}
	if h.m.unlock != nil || !h.m.unlock.isNil() {
		t.Error("the modal is still open")
	}
	h.typ("b")
	h.press("tab")
	if h.m.form.fields[0].text.String() != "bob" {
		t.Errorf("no completion after unlocking: %q", h.m.form.fields[0].text.String())
	}
	// Running a command drops what was listed.
	h.m.form.fields[1].text.set("alice")
	h.press("ctrl+r")
	if h.m.names.lists != nil {
		t.Error("the names survive a command run")
	}
}

func (p *promptState) isNil() bool { return p == nil }

func TestEscAtTheUnlockModalListsNothing(t *testing.T) {
	called := 0
	h := newHintHarness(t, func(_ context.Context, pass *secret.Buffer) (map[string][]string, error) {
		if pass != nil {
			called++
		}
		return nil, ErrLocked
	}, "")
	h.open("send")
	h.press("ctrl+n")
	h.typ("secret")
	h.press("esc")
	if h.m.unlock != nil || called != 0 || h.m.screen != scForm {
		t.Errorf("unlock %v called %d screen %v", h.m.unlock, called, h.m.screen)
	}
}

func fieldIndex(t *testing.T, h *harness, label string) *field {
	t.Helper()
	for _, f := range h.m.form.fields {
		if f.label == label {
			return f
		}
	}
	t.Fatalf("no field %q", label)
	return nil
}

func TestMutuallyExclusiveFlagsAreDisabledBeforeRunning(t *testing.T) {
	h := newHintHarness(t, nil, "")
	h.open("export")
	h.focus("--hardware")
	h.press("space")
	h.focus("--mnemonic")
	h.press("space")
	if fieldIndex(t, h, "--mnemonic").on {
		t.Error("the excluded switch could be set")
	}
	if !strings.Contains(h.m.notice, "cannot be used with --hardware") {
		t.Errorf("notice = %q", h.m.notice)
	}
	if !strings.Contains(h.m.render(), "not with --hardware") {
		t.Errorf("the excluded field is not marked:\n%s", h.m.render())
	}
	// Turning the first off frees the other.
	h.focus("--hardware")
	h.press("space")
	h.focus("--mnemonic")
	h.press("space")
	if !fieldIndex(t, h, "--mnemonic").on {
		t.Error("the switch stayed disabled after the other was cleared")
	}
}

func TestOneRequiredAndRequiredTogetherAreCheckedByTheForm(t *testing.T) {
	h := newHintHarness(t, nil, "")
	h.open("export")
	h.press("ctrl+r")
	if h.m.screen != scForm || !strings.Contains(h.m.notice, "give one of --password-fd, --plaintext") {
		t.Fatalf("screen %v notice %q", h.m.screen, h.m.notice)
	}
	h.focus("--plaintext")
	h.press("space")
	h.focus("--account")
	h.typ("1")
	h.press("ctrl+r")
	if h.m.screen != scForm || !strings.Contains(h.m.notice, "--account, --index go together") {
		t.Fatalf("screen %v notice %q", h.m.screen, h.m.notice)
	}
	if !strings.Contains(h.m.render(), "needed with --account") {
		t.Errorf("the partner field is not marked:\n%s", h.m.render())
	}
	h.focus("--index")
	h.typ("2")
	h.press("ctrl+r")
	if h.m.screen != scRun {
		t.Fatalf("the form refused a valid combination: %q", h.m.notice)
	}
}

func makeTree(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	for _, f := range []string{"a.json", "b.txt", ".hidden.json", "sub/c.json", "sub/d.cbor"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(d, f)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, f), []byte("secret contents\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func names(p *picker) []string {
	var out []string
	for _, e := range p.entries {
		out = append(out, e.name)
	}
	return out
}

func TestFilePickerListsFiltersAndChooses(t *testing.T) {
	d := makeTree(t)
	// a FIFO would hang anything that opened it
	if err := unix.Mkfifo(filepath.Join(d, "fifo.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := newHintHarness(t, nil, d)
	h.open("send")
	h.focus("--in")
	h.press("ctrl+o")
	p := h.m.picker
	if p == nil {
		t.Fatal("ctrl+o did not open the picker")
	}
	if got := strings.Join(names(p), " "); got != ".. sub a.json fifo.json" {
		t.Errorf("entries = %q (extension filter, hidden off, directories first)", got)
	}
	h.press(".")
	if got := strings.Join(names(p), " "); !strings.Contains(got, ".hidden.json") {
		t.Errorf("hidden entries not shown on request: %q", got)
	}
	h.press(".")
	// descend into sub, back, choose a.json
	h.press("down", "enter")
	if filepath.Base(p.dir) != filepath.Base(d)+"/sub" && filepath.Base(p.dir) != "sub" {
		t.Fatalf("dir = %s", p.dir)
	}
	if got := strings.Join(names(p), " "); got != ".. c.json" {
		t.Errorf("sub = %q", got)
	}
	h.press("h")
	h.press("down", "down", "enter")
	if h.m.picker != nil {
		t.Fatalf("picker still open:\n%s", h.m.render())
	}
	if got := fieldIndex(t, h, "--in").text.String(); got != filepath.Join(d, "a.json") {
		t.Errorf("chosen = %q", got)
	}
	// Esc cancels and leaves the field alone.
	h.press("ctrl+o")
	h.press("esc")
	if h.m.picker != nil || fieldIndex(t, h, "--in").text.String() != filepath.Join(d, "a.json") {
		t.Error("esc changed the field")
	}
}

func TestFilePickerDirectoryAndNewFileModes(t *testing.T) {
	d := makeTree(t)
	h := newHintHarness(t, nil, d)
	h.open("send")
	h.focus("--dir")
	h.press("ctrl+o")
	if got := strings.Join(names(h.m.picker), " "); got != ".. sub" {
		t.Errorf("directory mode lists %q", got)
	}
	h.press("down", "enter", "s")
	if got := fieldIndex(t, h, "--dir").text.String(); got != filepath.Join(d, "sub") {
		t.Errorf("dir = %q", got)
	}
	h.focus("--out")
	h.press("ctrl+o")
	h.typ("new.json") // typing names the file; letters are not shortcuts here
	if h.m.picker == nil {
		t.Fatal("typing closed the picker")
	}
	h.press("enter")
	if got := fieldIndex(t, h, "--out").text.String(); got != filepath.Join(d, "new.json") {
		t.Errorf("new file = %q", got)
	}
	// A name that escapes the directory is refused.
	h.press("ctrl+o")
	h.typ("..")
	h.press("enter")
	if h.m.picker == nil || !strings.Contains(h.m.picker.note, "not a file name") {
		t.Errorf("'..' accepted as a file name")
	}
}

func TestFilePickerShowsALinkTargetAndFollowsOnlyOnASecondEnter(t *testing.T) {
	d := makeTree(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "x.json"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(d, "elsewhere")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "x.json"), filepath.Join(d, "l.json")); err != nil {
		t.Fatal(err)
	}
	h := newHintHarness(t, nil, d)
	h.open("send")
	h.focus("--in")
	h.press("ctrl+o")
	p := h.m.picker
	if scr := h.m.render(); !strings.Contains(scr, "elsewhere/ -> "+outside[:4]) {
		t.Fatalf("the link target is not shown:\n%s", scr)
	}
	var idx int
	for i, e := range p.entries {
		if e.name == "elsewhere" {
			idx = i
		}
	}
	p.cursor = idx
	h.press("enter")
	if p.dir != d || !strings.Contains(p.note, "symbolic link") {
		t.Fatalf("a link was followed on the first Enter: dir %s note %q", p.dir, p.note)
	}
	h.press("enter")
	if p.dir != outside {
		t.Errorf("second Enter did not follow: %s", p.dir)
	}
	// A file link is chosen only after the same confirmation.
	p.dir = d
	p.load()
	for i, e := range p.entries {
		if e.name == "l.json" {
			p.cursor = i
		}
	}
	h.press("enter")
	if h.m.picker == nil {
		t.Fatal("a file link was chosen on the first Enter")
	}
	h.press("enter")
	if got := fieldIndex(t, h, "--in").text.String(); got != filepath.Join(d, "l.json") || h.m.picker != nil {
		t.Errorf("chosen = %q", got)
	}
}
