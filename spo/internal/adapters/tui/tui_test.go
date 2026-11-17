package tui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/mochipool/workbench/spo/internal/platform/uihint"
)

// testFactory builds a small tree that exercises every form feature and
// every kind of prompt, using only what a real command uses.
func testFactory(t Terminal, out, errw io.Writer) (*cobra.Command, error) {
	root := &cobra.Command{Use: "spo", SilenceUsage: true, SilenceErrors: true}
	root.SetOut(out)
	root.SetErr(errw)
	root.PersistentFlags().StringP("workspace", "C", ".", "workspace directory")
	root.PersistentFlags().Lookup("workspace").Annotations = map[string][]string{uihint.Global: {"true"}}

	greet := &cobra.Command{
		Use:   "greet <name> [count] [--shout] [--times N] [--tag TEXT]... [--token-fd N]",
		Short: "Greet someone",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			shout, _ := cmd.Flags().GetBool("shout")
			times, _ := cmd.Flags().GetInt("times")
			tags, _ := cmd.Flags().GetStringArray("tag")
			ws, _ := cmd.Flags().GetString("workspace")
			s := "hello " + args[0]
			if shout {
				s = strings.ToUpper(s)
			}
			fmt.Fprintf(out, "%s x%d tags=%v args=%v ws=%s\n", s, times, tags, args, ws)
			if cmd.Flags().Changed("token-fd") {
				fd, _ := cmd.Flags().GetInt("token-fd")
				buf := make([]byte, 64)
				n, _ := unix.Read(fd, buf)
				fmt.Fprintf(out, "token=%q\n", strings.TrimSpace(string(buf[:n])))
			}
			return nil
		},
	}
	greet.Flags().Bool("shout", false, "shout it")
	greet.Flags().Int("times", 1, "how many times")
	greet.Flags().StringArray("tag", nil, "a tag; repeat")
	greet.Flags().Int("token-fd", -1, "read the token from this descriptor")
	greet.Flags().Lookup("token-fd").Annotations = map[string][]string{uihint.SecretFD: {uihint.SecretIn}}
	greet.Flags().Int("key-fd", -1, "write the key to this descriptor")
	greet.Flags().Lookup("key-fd").Annotations = map[string][]string{uihint.SecretFD: {uihint.SecretOut}}

	grp := &cobra.Command{Use: "vault", Short: "Group"}
	grp.AddCommand(
		&cobra.Command{Use: "confirm", Short: "Ask", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			ans, err := t.ReadLine(cmd.Context(), "Proceed? [y/N] ")
			if err != nil {
				return err
			}
			if ans != "y" {
				return errors.New("declined: nothing was changed")
			}
			fmt.Fprintln(out, "proceeded")
			return nil
		}},
		&cobra.Command{Use: "unlock", Short: "Passphrase", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := t.ReadSecret(cmd.Context(), "Passphrase: ")
			if err != nil {
				return err
			}
			defer p.Destroy()
			fmt.Fprintf(out, "got %d bytes\n", p.Len())
			return nil
		}},
		&cobra.Command{Use: "evil", Short: "Hostile \x1b[31mshort", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
			fmt.Fprint(out, "a\x1b[2Jb\x1b]0;title\x07c\rd‮evil\x1b[1;1Hz\x00\n")
			return nil
		}},
		&cobra.Command{Use: "hidden", Hidden: true, Short: "no", RunE: func(*cobra.Command, []string) error { return nil }},
	)
	secretShow := &cobra.Command{Use: "reveal", Short: "Shows a secret once", Args: cobra.NoArgs,
		Annotations: map[string]string{uihint.SensitiveOutput: "true"},
		RunE:        func(*cobra.Command, []string) error { fmt.Fprintln(out, "RECOVERY-KEY-1234"); return nil }}
	root.AddCommand(greet, grp, secretShow)
	return root, nil
}

type harness struct {
	t  *testing.T
	m  *model
	ch chan tea.Msg
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, ch: make(chan tea.Msg, 512)}
	m, err := newModel(Options{Factory: testFactory, Globals: []string{"-C", "/ws"},
		Status: func() Status { return Status{Workspace: "/ws", Network: "preview", Mode: "offline", State: "sealed"} }},
		func(msg tea.Msg) { h.ch <- msg })
	if err != nil {
		t.Fatal(err)
	}
	h.m = m
	return h
}

var specialKeys = map[string]bool{"enter": true, "esc": true, "tab": true, "down": true, "up": true, "ctrl+c": true,
	"ctrl+r": true, "pgup": true, "pgdown": true, "backspace": true, "right": true, "left": true, "space": true, "shift+tab": true,
	"ctrl+n": true, "ctrl+o": true, "ctrl+a": true, "ctrl+g": true, "home": true, "end": true}

func (h *harness) press(keys ...string) {
	for _, k := range keys {
		if specialKeys[k] {
			h.m.Update(keyMsg(k))
			continue
		}
		for _, r := range k {
			h.m.Update(keyMsg(string(r)))
		}
	}
}

func (h *harness) typ(s string) { h.press(s) }

// until processes the messages commands send until cond holds.
func (h *harness) until(what string, cond func() bool) {
	h.t.Helper()
	deadline := time.After(5 * time.Second)
	for !cond() {
		select {
		case msg := <-h.ch:
			h.m.Update(msg)
		case <-deadline:
			h.t.Fatalf("timed out waiting for %s\n%s", what, h.m.render())
		}
	}
}

// focus moves the form cursor to the field with the label.
func (h *harness) focus(label string) {
	h.t.Helper()
	for i, f := range h.m.form.fields {
		if f.label == label {
			h.m.form.cursor = i
			return
		}
	}
	h.t.Fatalf("no field %q", label)
}

func (h *harness) prompting() bool { return h.m.run != nil && h.m.run.prompt != nil }
func (h *harness) done() bool      { return h.m.run != nil && h.m.run.done }

// open navigates the menu to the command at path and opens its form.
func (h *harness) open(path ...string) {
	h.t.Helper()
	h.m.screen, h.m.group = scMenu, nil
	for i, p := range path {
		es := h.m.entries()
		found := -1
		for j, e := range es {
			if e.n != nil && e.n.name() == p && !(e.run && e.n.cmd == h.m.current().cmd) {
				found = j
			}
		}
		if found < 0 {
			h.t.Fatalf("no entry %q in the menu at %v", p, path[:i])
		}
		h.m.cursors[h.m.cursorKey()] = found
		h.press("enter")
	}
	if h.m.screen != scForm {
		h.t.Fatalf("path %v did not open a form", path)
	}
}

func TestMenuIsGeneratedFromTheTree(t *testing.T) {
	root, _ := testFactory(nopTerminal{}, io.Discard, io.Discard)
	want := []string{"greet", "reveal", "vault confirm", "vault evil", "vault unlock"}
	if got := Paths(root); !reflect.DeepEqual(got, want) {
		t.Errorf("Paths = %v, want %v", got, want)
	}
	h := newHarness(t)
	var labels []string
	for _, e := range h.m.entries() {
		labels = append(labels, e.label)
	}
	if !reflect.DeepEqual(labels, []string{"greet", "reveal", "vault >"}) {
		t.Errorf("top menu = %v", labels)
	}
	h.press("down", "down", "enter")
	labels = nil
	for _, e := range h.m.entries() {
		labels = append(labels, e.label)
	}
	if !reflect.DeepEqual(labels, []string{"confirm", "evil", "unlock"}) {
		t.Errorf("group menu = %v (a hidden command must not appear)", labels)
	}
	h.press("esc")
	if len(h.m.group) != 0 {
		t.Error("esc did not go back")
	}
	h.press("/")
	h.typ("unl")
	es := h.m.entries()
	if len(es) != 1 || es[0].label != "vault unlock" {
		t.Errorf("search = %+v", es)
	}
}

func TestParseUse(t *testing.T) {
	for use, want := range map[string]string{
		"send <from> <to> <amount> [--message TEXT]... [--yes]":                  "from to amount",
		"export <dir> [--owner NAME]... (--password-fd N | --plaintext) [--yes]": "dir",
		"vote <txhash> [index]":                                 "txhash [index]",
		"init --network <mainnet|preprod|preview> [--mode a|b]": "",
		"show": "",
		"enroll FILE --as NAME --role ROLE... [--key-role R]... [--pool P]... [--unscoped]": "FILE",
		"import FILE|DIR... [--as coordinator|signer]":                                      "FILE|DIR...",
		"request export POOL [--out DIR] [--purpose TEXT]":                                  "POOL",
		"add <name> <file>...": "name file...",
		"restore <backup> [--force] [--allow-older] [--network N]": "backup",
	} {
		var got []string
		for _, p := range parseUse(use) {
			s := p.name
			if p.optional {
				s = "[" + s + "]"
			}
			if p.repeat {
				s += "..."
			}
			got = append(got, s)
		}
		if strings.Join(got, " ") != want {
			t.Errorf("parseUse(%q) = %q, want %q", use, strings.Join(got, " "), want)
		}
	}
}

func TestFormIsGeneratedFromMetadata(t *testing.T) {
	h := newHarness(t)
	h.open("greet")
	var got []string
	for _, f := range h.m.form.fields {
		got = append(got, fmt.Sprintf("%s:%d", f.label, f.kind))
	}
	want := []string{"name:5", "count:5", "--shout:1", "--tag:2", "--times:0", "--token-fd:3"}
	// kinds: positional=5 bool=1 text=0 list=2 secret=3; the write-side key-fd and the global flag are not offered
	if !reflect.DeepEqual(got, want) {
		t.Errorf("fields = %v, want %v", got, want)
	}
	// Nothing edited: the command line is the bare command.
	h.m.form.fields[0].text.set("ada")
	if p := h.m.form.preview(); p != "spo greet -- ada" {
		t.Errorf("preview = %q", p)
	}
}

func TestRunPassesFlagsPositionalsAndSecretsOnAPipe(t *testing.T) {
	h := newHarness(t)
	h.open("greet")
	fm := h.m.form
	// Run with a missing required positional is refused by the form, not run.
	h.press("ctrl+r")
	if h.m.screen != scForm || !strings.Contains(h.m.notice, "<name> is required") {
		t.Fatalf("screen %v notice %q", h.m.screen, h.m.notice)
	}
	h.typ("ada")
	h.focus("--shout")
	h.press("space")
	h.focus("--times")
	h.typ("3")
	h.focus("--tag")
	h.typ("x")
	h.press("enter")
	h.typ("y y") // a pending entry is included
	h.focus("--token-fd")
	h.typ("s3cret-token")
	if strings.Contains(h.m.render(), "s3cret-token") {
		t.Error("the secret is drawn on screen")
	}
	if !strings.Contains(h.m.render(), "••••••••••••") {
		t.Error("the secret is not masked")
	}
	if p := fm.preview(); strings.Contains(p, "s3cret") || !strings.Contains(p, "--token-fd=<private pipe>") {
		t.Errorf("preview = %q", p)
	}
	h.press("ctrl+r")
	h.until("done", h.done)
	if !fm.fields[len(fm.fields)-1].secret.empty() {
		t.Error("the typed secret survives the run")
	}
	out := h.m.run.outText()
	want := "HELLO ADA x3 tags=[x y y] args=[ada] ws=/ws\ntoken=\"s3cret-token\"\n"
	if out != want {
		t.Errorf("output %q, want %q", out, want)
	}
	if h.m.run.err != nil {
		t.Error(h.m.run.err)
	}
	if len(h.m.run.fds) != 0 {
		t.Error("the secret pipe is still open after the run")
	}
}

func TestPromptsAreTheCommandsOwnAndCaptureAnswers(t *testing.T) {
	h := newHarness(t)
	h.open("vault", "unlock")
	h.press("ctrl+r")
	h.until("passphrase prompt", h.prompting)
	if p := h.m.run.prompt; p.text != "Passphrase: " || !p.secret {
		t.Fatalf("prompt = %+v", p)
	}
	h.typ("hunter2 hunter2")
	view := h.m.render()
	if strings.Contains(view, "hunter2") {
		t.Error("masked input echoed")
	}
	h.press("enter")
	h.until("done", h.done)
	if got := h.m.run.outText(); got != "got 15 bytes\n" {
		t.Errorf("output %q", got)
	}
	for _, s := range h.m.run.segs {
		if strings.Contains(string(s.data), "hunter2") {
			t.Errorf("the transcript kept the secret: %q", s.data)
		}
	}
}

func TestConfirmationAnswerAndDecline(t *testing.T) {
	h := newHarness(t)
	h.open("vault", "confirm")
	h.press("ctrl+r")
	h.until("prompt", h.prompting)
	if h.m.run.prompt.text != "Proceed? [y/N] " || h.m.run.prompt.secret {
		t.Fatalf("prompt = %+v", h.m.run.prompt)
	}
	h.press("enter") // the default: no
	h.until("done", h.done)
	if h.m.run.err == nil || !strings.Contains(h.m.run.err.Error(), "declined") || h.m.run.outText() != "" {
		t.Errorf("err %v out %q", h.m.run.err, h.m.run.outText())
	}
	h.press("e") // edit and run again
	h.press("ctrl+r")
	h.until("prompt", h.prompting)
	h.typ("y")
	h.press("enter")
	h.until("done", h.done)
	if h.m.run.err != nil || h.m.run.outText() != "proceeded\n" {
		t.Errorf("err %v out %q", h.m.run.err, h.m.run.outText())
	}
}

func TestCancelDuringAPromptCancelsTheCommand(t *testing.T) {
	h := newHarness(t)
	h.open("vault", "unlock")
	h.press("ctrl+r")
	h.until("prompt", h.prompting)
	h.typ("half typed")
	h.press("esc")
	h.until("done", h.done)
	if !errors.Is(h.m.run.err, context.Canceled) {
		t.Errorf("err = %v", h.m.run.err)
	}
	if h.m.run.outText() != "" {
		t.Errorf("a cancelled command printed %q", h.m.run.outText())
	}
	if !strings.Contains(h.m.render(), "cancelled") {
		t.Error("the screen does not say it was cancelled")
	}
}

func TestHostileOutputIsRenderedInert(t *testing.T) {
	h := newHarness(t)
	h.open("vault", "evil")
	h.press("ctrl+r")
	h.until("done", h.done)
	view := h.m.render()
	if strings.Contains(view, "\x1b[2J") || strings.Contains(view, "\x1b]0") || strings.Contains(view, "\x1b[1;1H") ||
		strings.ContainsRune(view, '‮') || strings.ContainsRune(view, '\r') || strings.ContainsRune(view, 0) || strings.Contains(view, "\a") {
		t.Errorf("hostile output reached the screen: %q", view)
	}
	if !strings.Contains(view, "abc") {
		t.Errorf("the harmless text is lost: %q", view)
	}
	// The menu entry's hostile short text is cleaned too.
	h2 := newHarness(t)
	h2.press("down", "down", "enter")
	if v := h2.m.render(); strings.Contains(v, "\x1b[31m") {
		t.Errorf("menu: %q", v)
	}
}

func TestSensitiveOutputIsClearedOnLeaving(t *testing.T) {
	h := newHarness(t)
	h.open("reveal")
	h.press("ctrl+r")
	h.until("done", h.done)
	if !strings.Contains(h.m.render(), "RECOVERY-KEY-1234") {
		t.Fatal("not shown")
	}
	segs := h.m.run.segs
	h.press("esc")
	if h.m.run != nil {
		t.Error("the run is kept after leaving")
	}
	for _, s := range segs {
		if strings.Trim(string(s.data), "\x00") != "" {
			t.Errorf("segment not wiped: %q", s.data)
		}
	}
	if strings.Contains(h.m.render(), "RECOVERY-KEY") {
		t.Error("still on screen")
	}
}

func TestCtrlCCancelsARunningCommandBeforeQuitting(t *testing.T) {
	h := newHarness(t)
	h.m.screen = scRun
	ctx, cancel := context.WithCancel(context.Background())
	h.m.run = &runState{id: 9, cancel: cancel, node: h.m.top}
	h.press("ctrl+c")
	if ctx.Err() == nil || !h.m.run.cancelling {
		t.Error("first Ctrl-C did not cancel")
	}
	_, cmd := h.m.Update(keyMsg("ctrl+c"))
	if cmd == nil || cmd() != tea.Quit() {
		t.Error("second Ctrl-C did not quit")
	}
}

func TestCleanStripsControlSequences(t *testing.T) {
	for in, want := range map[string]string{
		"plain":                    "plain",
		"a\x1b[31mred\x1b[0m":      "ared"[:1] + "red",
		"x\x1b]8;;http://e\x1b\\y": "xy",
		"x\x1b]0;t\x07y":           "xy",
		"x\x1bPdata\x1b\\y":        "xy",
		"a\rb":                     "ab",
		"a‮b⁦c":                    "a�b�c",
		"t\tz":                     "t    z",
		"\u009b31mq":               "q",
		"bad\xffbyte":              "bad�byte",
		"\x1b":                     "",
		"a\x00b\x07c":              "a�b�c",
		"x\x1b(By":                 "xy",
	} {
		if got := Clean(in); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
	if got := CleanLine("a\nb"); got != "a b" {
		t.Errorf("CleanLine = %q", got)
	}
}

func TestViewFitsTheTerminal(t *testing.T) {
	h := newHarness(t)
	h.m.Update(tea.WindowSizeMsg{Width: 40, Height: 12})
	for _, v := range []string{h.m.render()} {
		if n := strings.Count(v, "\n") + 1; n > 12 {
			t.Errorf("view has %d lines for 12", n)
		}
	}
	h.open("greet")
	if n := strings.Count(h.m.render(), "\n") + 1; n > 12 {
		t.Errorf("form view has %d lines for 12", n)
	}
	_ = bytes.MinRead
}

func TestPasteGoesInLikeTypingWithoutControlCharacters(t *testing.T) {
	h := newHarness(t)
	h.open("vault", "unlock")
	h.press("ctrl+r")
	h.until("prompt", h.prompting)
	h.m.Update(tea.PasteMsg{Content: "pa\x1b[2Jss\nword"})
	if got := h.m.run.prompt.mask.n(); got != len("pa[2Jssword") {
		t.Errorf("pasted %d characters", got)
	}
	if strings.Contains(h.m.render(), "pass") || strings.Contains(h.m.render(), "\x1b[2J") {
		t.Error("pasted secret shown")
	}
	h.press("enter")
	h.until("done", h.done)
}

// A command prints far more than a screen and then asks. The question is
// drawn with the last lines of the output above it, whole, so that the
// summary a command printed last is the thing in view when it is answered;
// and the terminal the command is given reports the size of that area.
func TestPromptShowsTheTailOfALongOutputAndReportsTheSize(t *testing.T) {
	for _, question := range []string{"Sign this transaction? [y/N] ", "NET 2.000000 ADA leaves you (EXCLUDING your inputs: not checked) + 1 net asset; request 01020300 body 04000000. Sign this transaction? [y/N] "} {
		testTailWithQuestion(t, question)
	}
}

func testTailWithQuestion(t *testing.T, question string) {
	t.Helper()
	factory := func(term Terminal, out, errw io.Writer) (*cobra.Command, error) {
		root := &cobra.Command{Use: "spo", SilenceUsage: true, SilenceErrors: true}
		root.AddCommand(&cobra.Command{Use: "ask", Short: "Prints, then asks", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			for i := 1; i <= 200; i++ {
				fmt.Fprintf(out, "output line %03d\n", i)
			}
			cols, rows, ok := term.(interface{ Size() (int, int, bool) }).Size()
			fmt.Fprintf(out, "size %d %d %v\n", cols, rows, ok)
			_, err := term.ReadLine(cmd.Context(), question)
			return err
		}})
		return root, nil
	}
	ch := make(chan tea.Msg, 1024)
	m, err := newModel(Options{Factory: factory}, func(msg tea.Msg) { ch <- msg })
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := (&guiTerminal{size: m.outputArea}).Size(); ok {
		t.Error("a size is reported before the first window size")
	}
	m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	h := &harness{t: t, m: m, ch: ch}
	h.m.screen = scMenu
	for i, e := range h.m.entries() {
		if e.n != nil && e.n.name() == "ask" {
			h.m.cursors[h.m.cursorKey()] = i
		}
	}
	h.press("enter")
	h.press("ctrl+r")
	h.until("the question", h.prompting)
	view := h.m.render()
	if n := strings.Count(view, "\n") + 1; n > 24 {
		t.Errorf("the view is %d rows for 24", n)
	}
	for i := 187; i <= 200; i++ {
		if want := fmt.Sprintf("output line %03d", i); !strings.Contains(view, want) {
			t.Fatalf("the view lacks %q:\n%s", want, view)
		}
	}
	for _, want := range []string{"size 79 19 true", "Sign this transaction? [y/N]"} {
		if !strings.Contains(view, want) {
			t.Errorf("the view lacks %q:\n%s", want, view)
		}
	}
}

// A command lays its block out for the size the terminal reports, keeping the
// question it is about to ask, wrapped whole, out of it. The pane above the
// question is drawn with exactly the rows that leaves, so every row of such a
// block is in the view, at narrow widths where the question takes 4 or more
// rows too; and the pane scrolls while the question is open.
func TestPromptPaneHoldsABlockLaidOutForTheWrappedQuestion(t *testing.T) {
	question := "NET 12345.678901 ADA leaves you (EXCLUDING your inputs, NOT checked) + 12 net assets; request 01020300 body 04000000. Sign this transaction? [y/N] "
	for _, width := range []int{44, 60, 80} {
		for _, height := range []int{24, 30} {
			var blockRows int
			factory := func(term Terminal, out, errw io.Writer) (*cobra.Command, error) {
				root := &cobra.Command{Use: "spo", SilenceUsage: true, SilenceErrors: true}
				root.AddCommand(&cobra.Command{Use: "ask", Short: "Prints a block, then asks", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
					for i := 1; i <= 100; i++ {
						fmt.Fprintf(out, "earlier line %03d\n", i)
					}
					cols, rows, _ := term.(interface{ Size() (int, int, bool) }).Size()
					blockRows = rows - (len(wrap(question, cols)) + 2)
					for i := 1; i <= blockRows; i++ {
						fmt.Fprintf(out, "block row %02d\n", i)
					}
					_, err := term.ReadLine(cmd.Context(), question)
					return err
				}})
				return root, nil
			}
			ch := make(chan tea.Msg, 1024)
			m, err := newModel(Options{Factory: factory}, func(msg tea.Msg) { ch <- msg })
			if err != nil {
				t.Fatal(err)
			}
			m.Update(tea.WindowSizeMsg{Width: width, Height: height})
			h := &harness{t: t, m: m, ch: ch}
			h.m.screen = scMenu
			for i, e := range h.m.entries() {
				if e.n != nil && e.n.name() == "ask" {
					h.m.cursors[h.m.cursorKey()] = i
				}
			}
			h.press("enter")
			h.press("ctrl+r")
			h.until("the question", h.prompting)
			view := h.m.render()
			for i := 1; i <= blockRows; i++ {
				if want := fmt.Sprintf("block row %02d", i); !strings.Contains(view, want) {
					t.Fatalf("%dx%d: the view lacks %q (block of %d rows):\n%s", width, height, want, blockRows, view)
				}
			}
			if n := strings.Count(view, "\n") + 1; n > height {
				t.Errorf("%dx%d: the view is %d rows", width, height, n)
			}
			// page up scrolls the pane while the question is open
			h.press("pgup")
			if up := h.m.render(); strings.Contains(up, "block row 01") == strings.Contains(view, "block row 01") && !strings.Contains(up, "earlier line") {
				t.Errorf("%dx%d: page up did not scroll the pane:\n%s", width, height, up)
			}
			h.press("esc")
		}
	}
}

// A drawing printed by a command (the QR code of a voting key) is wiped on
// every way out of the run view: Esc, Enter, Backspace, Left, h, e (edit and
// run again), opening another command through the driver, and the end of the
// session. A command not marked sensitive is wiped too.
func TestRunOutputIsWipedOnEveryWayOut(t *testing.T) {
	wiped := func(t *testing.T, how string, segs []seg) {
		t.Helper()
		if len(segs) == 0 {
			t.Fatalf("%s: no output was captured", how)
		}
		for _, s := range segs {
			if strings.Trim(string(s.data), "\x00") != "" {
				t.Errorf("%s: segment not wiped: %q", how, s.data)
			}
		}
	}
	for _, key := range []string{"esc", "enter", "backspace", "left", "h", "e"} {
		h := newHarness(t)
		h.open("reveal")
		h.m.form.node.cmd.Annotations = nil // not marked sensitive: wiped all the same
		h.press("ctrl+r")
		h.until("done", h.done)
		segs := h.m.run.segs
		if !strings.Contains(h.m.render(), "RECOVERY-KEY-1234") {
			t.Fatal("not shown")
		}
		h.press(key)
		wiped(t, key, segs)
		if h.m.run != nil || strings.Contains(h.m.render(), "RECOVERY-KEY-1234") {
			t.Errorf("%s: the run or its output is still there", key)
		}
	}
	h := newHarness(t)
	h.open("reveal")
	h.m.form.node.cmd.Annotations = nil // not marked sensitive: wiped all the same
	h.press("ctrl+r")
	h.until("done", h.done)
	segs := h.m.run.segs
	h.m.Wipe()
	wiped(t, "the end of the session", segs)

	// The scripted driver: opening another command with a finished run on
	// screen drops that run wiped.
	d, err := NewDriver(Options{Factory: testFactory, Globals: []string{"-C", "/ws"},
		Status: func() Status { return Status{Workspace: "/ws", Network: "preview", Mode: "offline", State: "sealed"} }})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Open("reveal"); err != nil {
		t.Fatal(err)
	}
	d.m.form.node.cmd.Annotations = nil
	d.key("ctrl+r")
	for i := 0; i < 200 && d.m.run != nil && !d.m.run.done; i++ {
		select {
		case msg := <-d.ch:
			d.m.Update(msg)
		case <-time.After(50 * time.Millisecond):
		}
	}
	if d.m.run == nil || !d.m.run.done {
		t.Fatal("the run did not finish")
	}
	segs = d.m.run.segs
	if err := d.Open("greet"); err != nil {
		t.Fatal(err)
	}
	wiped(t, "Driver.Open", segs)
}
