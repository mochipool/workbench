package main

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/tui"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/platform/uihint"
)

func newNamedTUI(t *testing.T, dir string, globals ...string) *tui.Driver {
	t.Helper()
	build := func(out, errw io.Writer, term cli.Terminal) (cli.Deps, error) { return newDeps(out, errw, term), nil }
	d, err := tui.NewDriver(tui.Options{
		Factory:  tuiFactory(build),
		Globals:  append([]string{"-C=" + dir}, globals...),
		StartDir: dir,
		Names:    tuiNames(build, dir, append([]string{"-C=" + dir}, globals...)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	return d
}

// The listing the TUI completes from is the CLI's, names only, and a sealed
// workspace is not opened without the passphrase.
func TestTUINamesFromTheSealedWorkspace(t *testing.T) {
	dir := copyWorkspace(t)
	importWallet(t, dir)
	build := func(out, errw io.Writer, term cli.Terminal) (cli.Deps, error) { return newDeps(out, errw, term), nil }
	lister := tuiNames(build, dir, nil)

	if _, err := lister(context.Background(), nil); err != tui.ErrLocked {
		t.Fatalf("without a passphrase: err = %v, want ErrLocked", err)
	}
	names, err := lister(context.Background(), secret.Take([]byte(testPass)))
	if err != nil {
		t.Fatal(err)
	}
	if got := names[uihint.ClassWallet]; len(got) != 1 || got[0] != walletName {
		t.Errorf("wallets = %v", got)
	}
	if _, err := lister(context.Background(), secret.Take([]byte("not the passphrase at all"))); err == nil {
		t.Error("a wrong passphrase listed names")
	}

	d := newNamedTUI(t, dir)
	if err := d.Open("address"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.Screen(), "names are sealed") {
		t.Errorf("the form does not say the names are sealed:\n%s", d.Screen())
	}
	d.Press("ctrl+n")
	d.Type(testPass)
	if strings.Contains(d.Screen(), testPass) {
		t.Fatal("the passphrase is on the screen")
	}
	d.Press("enter")
	if err := d.AwaitNames(time.Minute); err != nil {
		t.Fatal(err)
	}
	d.Type("wall")
	d.Press("tab")
	if got := d.Value("name|address"); got != walletName {
		t.Errorf("completed to %q", got)
	}
	if strings.Contains(d.Screen(), testPass) {
		t.Error("the passphrase is on the screen after listing")
	}
}

func TestTUINamesFromTheUpstreamLayoutNeedNoPassphrase(t *testing.T) {
	dir := t.TempDir()
	d := newNamedTUI(t, dir, "--upstream-layout=true")
	st := drive(t, d, []string{"wallet", "new"}, map[string]string{"name": "up-w"}, nil)
	if st.Err != nil {
		t.Fatalf("wallet new: %v\n%s", st.Err, st.Out)
	}
	d.Back()
	if err := d.Open("address"); err != nil {
		t.Fatal(err)
	}
	d.Type("up")
	d.Press("tab")
	if got := d.Value("name|address"); got != "up-w" {
		t.Errorf("completed to %q; screen:\n%s", got, d.Screen())
	}
}

// The file picker starts in the workspace directory.
func TestTUIFilePickerStartsInTheWorkspace(t *testing.T) {
	dir := copyWorkspace(t)
	d := newNamedTUI(t, dir)
	if err := d.Open("address"); err != nil {
		t.Fatal(err)
	}
	if err := d.Focus("--transfer-file"); err != nil {
		t.Fatal(err)
	}
	d.Press("ctrl+o")
	scr := d.Screen()
	if !strings.Contains(scr, "choose or name a file") || !strings.Contains(scr, filepath.Base(dir)) {
		t.Errorf("the picker did not open in the workspace directory %s:\n%s", dir, scr)
	}
}

// The exclusions the commands declare reach the form (wallet new, workspace
// export), and are cobra's own: the CLI refuses the same combination.
func TestTUIShowsTheExclusionsCommandsDeclare(t *testing.T) {
	dir := copyWorkspace(t)
	d := newNamedTUI(t, dir)
	if err := d.Open("workspace", "export"); err != nil {
		t.Fatal(err)
	}
	if err := d.Run(); err == nil || !strings.Contains(err.Error(), "give one of --password-fd, --plaintext") {
		t.Errorf("export with neither: %v", err)
	}
	if err := d.Open("wallet", "new"); err != nil {
		t.Fatal(err)
	}
	if err := d.Focus("--mnemonic"); err != nil {
		t.Fatal(err)
	}
	d.Press("space")
	if err := d.Focus("--hardware"); err != nil {
		t.Fatal(err)
	}
	d.Press("space")
	if !strings.Contains(d.Notice(), "cannot be used with --mnemonic") {
		t.Errorf("notice = %q\n%s", d.Notice(), d.Screen())
	}
	if _, err := cliRun(t, dir, nil, "wallet", "new", "x", "--mnemonic", "--hardware"); err == nil || !strings.Contains(err.Error(), "none of the others can be") {
		t.Errorf("the CLI did not refuse it as cobra does: %v", err)
	}
}
