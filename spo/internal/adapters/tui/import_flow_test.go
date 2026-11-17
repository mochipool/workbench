package tui

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/platform/uihint"
)

// importStub stands in for `workspace import`: it records the arguments it
// was given and prints the JSON plan the real command prints, so the tests
// see what the flow asks for and what it builds. It has no import logic of
// its own beyond echoing selections back.
type importStub struct {
	mu    sync.Mutex
	calls [][]string
}

func (s *importStub) record(args []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, args)
}

func (s *importStub) last() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[len(s.calls)-1]
}

func (s *importStub) factory(t Terminal, out, errw io.Writer) (*cobra.Command, error) {
	root := &cobra.Command{Use: "spo", SilenceUsage: true, SilenceErrors: true}
	root.SetOut(out)
	root.SetErr(errw)
	root.PersistentFlags().StringP("workspace", "C", ".", "workspace directory")
	root.PersistentFlags().Lookup("workspace").Annotations = map[string][]string{uihint.Global: {"true"}}
	ws := &cobra.Command{Use: "workspace", Short: "Workspace"}
	var only, rename []string
	var dry, all bool
	var format, manifestOut string
	var depth int
	imp := &cobra.Command{
		Use:         "import [dir]... [--depth N] [--only SEL]... [--rename SEL=NEW]... [--all] [--dry-run] [--manifest-out FILE]",
		Short:       "Import",
		Args:        cobra.ArbitraryArgs,
		Annotations: map[string]string{uihint.Guided: uihint.GuidedImport},
		RunE: func(cmd *cobra.Command, args []string) error {
			s.record(append(append([]string{}, cmd.Flags().Args()...), fmt.Sprintf("dry=%v all=%v depth=%d format=%s only=%v rename=%v out=%s", dry, all, depth, format, only, rename, manifestOut)))
			if manifestOut != "" {
				fmt.Fprintln(out, "wrote "+manifestOut)
				return nil
			}
			if !dry {
				fmt.Fprintln(out, "imported")
				return nil
			}
			type ow = map[string]any
			var owners []ow
			if all {
				owners = []ow{
					{"kind": "pool", "name": "mypool", "dir": "/w/pool", "stored_as": "mypool", "status": "would-import"},
					{"kind": "wallet", "name": "w", "dir": "/w/wallets", "stored_as": "w", "status": "would-import"},
					{"kind": "wallet", "name": "w", "dir": "/w/other", "stored_as": "w", "status": "refused", "reason": "it would be stored as w; rename one", "collision": true},
					{"kind": "wallet", "name": "bad", "dir": "/w/wallets", "stored_as": "bad", "status": "refused", "reason": "the signing key does not belong to the verification key file"},
				}
			} else {
				stored := map[string]int{}
				for _, o := range only {
					name := o[strings.Index(o, ":")+1 : strings.Index(o, "@")]
					st := name
					for _, r := range rename {
						if strings.HasPrefix(r, o+"=") {
							st = strings.TrimPrefix(r, o+"=")
						}
					}
					stored[st]++
				}
				for _, o := range only {
					kind, rest, _ := strings.Cut(o, ":")
					name, dir, _ := strings.Cut(rest, "@")
					st := name
					for _, r := range rename {
						if strings.HasPrefix(r, o+"=") {
							st = strings.TrimPrefix(r, o+"=")
						}
					}
					x := ow{"kind": kind, "name": name, "dir": dir, "stored_as": st, "selected": true, "status": "would-import"}
					if stored[st] > 1 {
						x["status"], x["collision"], x["reason"] = "refused", true, "it would be stored as "+st+"; rename one"
					}
					if kind == "pool" {
						x["rewrites"] = []ow{{"pool": name, "field": "poolRewards", "old": "../wallets/w", "new": "w"}}
					}
					owners = append(owners, x)
				}
			}
			json.NewEncoder(out).Encode(ow{"version": 1, "dry_run": true, "owners": owners})
			for _, o := range owners {
				if o["collision"] == true && !all {
					return errors.New("two owners would be stored under one name")
				}
				if o["status"] == "refused" && !all {
					return errors.New("1 owner(s) would not be imported")
				}
			}
			return nil
		},
	}
	imp.Flags().StringArrayVar(&only, "only", nil, "")
	imp.Flags().StringArrayVar(&rename, "rename", nil, "")
	imp.Flags().BoolVar(&dry, "dry-run", false, "")
	imp.Flags().BoolVar(&all, "all", false, "")
	imp.Flags().StringVar(&format, "format", "table", "")
	imp.Flags().StringVar(&manifestOut, "manifest-out", "", "")
	imp.Flags().IntVar(&depth, "depth", 0, "")
	ws.AddCommand(imp)
	root.AddCommand(ws)
	return root, nil
}

func newImportHarness(t *testing.T) (*harness, *importStub) {
	t.Helper()
	st := &importStub{}
	h := &harness{t: t, ch: make(chan tea.Msg, 512)}
	m, err := newModel(Options{Factory: st.factory, Globals: []string{"-C", "/ws"}, StartDir: t.TempDir(),
		Status: func() Status { return Status{Workspace: "/ws"} }}, func(msg tea.Msg) { h.ch <- msg })
	if err != nil {
		t.Fatal(err)
	}
	h.m = m
	return h, st
}

func (h *harness) atImport(stage impStage) func() bool {
	return func() bool {
		return h.m.screen == scImport && h.m.imp != nil && h.m.imp.stage == stage && h.m.run == nil
	}
}

func (h *harness) typeLine(s string) { h.m.paste(s) }

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if strings.Contains(a, want) {
			return true
		}
	}
	return false
}

// The guided flow is reached from the command's form, reads folders, shows
// the plan the command printed with its statuses, lets the operator toggle
// and rename, shows the rewrites and the equivalent command line, and runs
// the command with exactly the flags those choices stand for.
//
// spec: SPO-Xmulti-IF-003, SPO-Xmulti-OUT-009
func TestGuidedImportBuildsTheCommandsOwnRequest(t *testing.T) {
	h, st := newImportHarness(t)
	h.open("workspace", "import")
	h.press("ctrl+g")
	if h.m.screen != scImport {
		t.Fatalf("the form did not open the guided import:\n%s", h.m.render())
	}
	h.press("a")
	h.typeLine("/w/pool")
	h.press("enter", "a")
	h.typeLine("/w/wallets")
	h.press("enter", "+", "enter")
	h.until("the discovery", h.atImport(stSelect))
	args := st.last()
	if !hasArg(args, "dry=true all=true depth=1 format=json") || args[0] != "/w/pool" || args[1] != "/w/wallets" {
		t.Fatalf("discovery asked %v", args)
	}
	view := h.m.render()
	for _, w := range []string{"mypool", "/w/wallets", "the signing key does not belong", "[-]"} {
		if !strings.Contains(view, w) {
			t.Errorf("select screen lacks %q:\n%s", w, view)
		}
	}
	// nothing is selected by default; a refused owner cannot be selected
	for _, o := range h.m.imp.owners {
		if o.chosen {
			t.Errorf("%s was selected by default", o.Name)
		}
	}
	h.press("down", "down", "down", "space")
	if h.m.imp.owners[3].chosen || !strings.Contains(h.m.imp.notice, "cannot be imported") {
		t.Errorf("a refused owner was toggled: %q", h.m.imp.notice)
	}
	h.press("up", "up", "up", "space", "down", "space", "r")
	h.typeLine("boss")
	h.press("enter", "enter")
	h.until("the plan", h.atImport(stSummary))
	args = st.last()
	if !hasArg(args, "dry=true all=false depth=1 format=json only=[pool:mypool@/w/pool wallet:w@/w/wallets] rename=[wallet:w@/w/wallets=boss]") {
		t.Fatalf("the plan was asked with %v", args)
	}
	view = strings.ReplaceAll(h.m.render(), "\n", "")
	for _, w := range []string{"mypool -> mypool", "w -> boss", "poolRewards", `"../wallets/w" -> "w"`, "spo -C /ws workspace import --depth=1 --only=pool:mypool@/w/pool --only=wallet:w@/w/wallets --rename=wallet:w@/w/wallets=boss /w/pool /w/wallets"} {
		if !strings.Contains(view, w) {
			t.Errorf("summary lacks %q:\n%s", w, view)
		}
	}
	// save as a manifest: the command writes it, then we are back
	h.press("m")
	h.typeLine("/tmp/m.toml")
	h.press("enter")
	h.until("the manifest", func() bool { return h.done() })
	if a := st.last(); !hasArg(a, "out=/tmp/m.toml") || !hasArg(a, "dry=false") {
		t.Errorf("manifest call %v", a)
	}
	h.press("esc")
	if h.m.screen != scImport || h.m.imp.stage != stSummary {
		t.Fatalf("not back at the summary: %v", h.m.screen)
	}
	// confirm: the same flags without --dry-run
	h.press("enter")
	h.until("the import", h.done)
	args = st.last()
	if !hasArg(args, "dry=false all=false depth=1 format=table only=[pool:mypool@/w/pool wallet:w@/w/wallets] rename=[wallet:w@/w/wallets=boss]") {
		t.Errorf("the import ran with %v", args)
	}
	if !strings.Contains(h.m.run.outText(), "imported") {
		t.Errorf("output %q", h.m.run.outText())
	}
	h.press("esc")
	if h.m.screen != scMenu || h.m.imp != nil {
		t.Error("did not return to the menu")
	}
}

// A selection whose owners would be stored under one name is sent back to the
// selection with a prompt for a new name; the command's own refusal decides.
//
// spec: SPO-Xmulti-IF-003, SPO-Xmulti-OUT-002
func TestGuidedImportAsksForANewNameOnCollision(t *testing.T) {
	h, st := newImportHarness(t)
	h.open("workspace", "import")
	h.press("ctrl+g", "a")
	h.typeLine("/w/wallets")
	h.press("enter", "enter")
	h.until("the discovery", h.atImport(stSelect))
	// two wallets called w in two folders: select both (the second is flagged by the command)
	h.press("down", "space", "down", "space", "enter")
	h.until("the refused plan", h.atImport(stSelect))
	if !h.m.imp.renamed || !strings.Contains(h.m.imp.notice, "give w in") {
		t.Fatalf("no rename prompt: %q\n%s", h.m.imp.notice, h.m.render())
	}
	h.typeLine("w2")
	h.press("enter", "enter")
	h.until("the plan", h.atImport(stSummary))
	if !h.m.imp.planOK || !hasArg(st.last(), "rename=[wallet:w@/w/other=w2]") && !hasArg(st.last(), "rename=[wallet:w@/w/wallets=w2]") {
		t.Errorf("plan %v ok=%v", st.last(), h.m.imp.planOK)
	}
}

// A plan that would fail cannot be run from the summary.
//
// spec: SPO-Xmulti-IF-003
func TestGuidedImportRefusesAFailingPlan(t *testing.T) {
	h, st := newImportHarness(t)
	h.open("workspace", "import")
	h.press("ctrl+g", "a")
	h.typeLine("/w/wallets")
	h.press("enter", "enter")
	h.until("the discovery", h.atImport(stSelect))
	h.press("down", "space", "down", "space", "enter") // both w: collision, send back
	h.until("the refused plan", h.atImport(stSelect))
	h.press("esc") // cancel the rename prompt
	h.press("enter")
	h.until("the plan again", func() bool { return h.m.screen == scImport && h.m.run == nil })
	before := len(st.calls)
	h.m.imp.stage, h.m.imp.planOK = stSummary, false
	h.press("enter")
	if len(st.calls) != before || !strings.Contains(h.m.imp.notice, "would not be imported") {
		t.Errorf("a failing plan was run: %d calls, notice %q", len(st.calls), h.m.imp.notice)
	}
}

// Without a folder nothing is asked; the folder list is edited with the
// keyboard; the picker chooses directories only; esc leaves.
//
// spec: SPO-Xmulti-IF-003
func TestGuidedImportFolderList(t *testing.T) {
	h, st := newImportHarness(t)
	h.open("workspace", "import")
	h.press("ctrl+g", "enter")
	if len(st.calls) != 0 || !strings.Contains(h.m.imp.notice, "add a folder") {
		t.Fatalf("calls %d notice %q", len(st.calls), h.m.imp.notice)
	}
	h.press("a")
	h.typeLine("/x")
	h.press("enter", "a")
	h.typeLine("/x")
	h.press("enter")
	if len(h.m.imp.folders) != 1 || !strings.Contains(h.m.imp.notice, "already") {
		t.Errorf("duplicate folder: %v %q", h.m.imp.folders, h.m.imp.notice)
	}
	h.press("o")
	if h.m.picker == nil || h.m.picker.spec.Kind != uihint.KindDir {
		t.Fatal("no directory picker")
	}
	h.press("s")
	if len(h.m.imp.folders) != 2 {
		t.Errorf("folders %v", h.m.imp.folders)
	}
	h.press("d")
	if len(h.m.imp.folders) != 1 {
		t.Errorf("not removed: %v", h.m.imp.folders)
	}
	h.press("+", "+", "+", "+", "+", "+")
	if h.m.imp.depth != importMaxDepth {
		t.Errorf("depth %d", h.m.imp.depth)
	}
	h.press("esc")
	if h.m.screen != scForm {
		t.Error("esc did not leave the flow")
	}
}

// The flow adds no menu entry: the menu still lists exactly the command tree.
//
// spec: SPO-Xmulti-IF-003
func TestGuidedImportAddsNoMenuEntry(t *testing.T) {
	st := &importStub{}
	root, _ := st.factory(nopTerminal{}, io.Discard, io.Discard)
	got := strings.Join(Paths(root), ",")
	if got != "workspace import" {
		t.Errorf("paths %s", got)
	}
}
