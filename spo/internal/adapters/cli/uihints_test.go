package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/platform/uihint"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

func hintRoot(t *testing.T) *cobra.Command {
	t.Helper()
	root := NewRoot(Deps{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}})
	MarkForUI(root)
	return root
}

func find(root *cobra.Command, path string) *cobra.Command {
	c, _, err := root.Find(strings.Fields(path))
	if err != nil || c == root || c.CommandPath() != root.Name()+" "+path {
		return nil
	}
	return c
}

// Every entry of the hint tables names a command, an argument label and a flag
// that exist, so a renamed argument cannot silently lose its completion.
func TestUIHintTableMatchesTheTree(t *testing.T) {
	root := hintRoot(t)
	for path, labels := range argHints {
		c := find(root, path)
		if c == nil {
			t.Errorf("argHints: no command %q", path)
			continue
		}
		have := map[string]bool{}
		for _, p := range uihint.Positionals(c.Use) {
			have[p.Name] = true
		}
		for label, h := range labels {
			if !have[label] {
				t.Errorf("argHints: %q has no argument %q (its usage line: %s)", path, label, c.Use)
			}
			if _, ok := uihint.Decode(h); !ok {
				t.Errorf("argHints: %q %q: bad hint %q", path, label, h)
			}
			if _, ok := uihint.OfArg(c, label); !ok {
				t.Errorf("%q %q was not annotated by MarkForUI", path, label)
			}
		}
	}
	for path, flags := range flagHints {
		c := find(root, path)
		if c == nil {
			t.Errorf("flagHints: no command %q", path)
			continue
		}
		for name := range flags {
			f := c.Flags().Lookup(name)
			if f == nil {
				t.Errorf("flagHints: %q has no flag --%s", path, name)
			} else if _, ok := uihint.Of(f); !ok {
				t.Errorf("%q --%s was not annotated by MarkForUI", path, name)
			}
		}
	}
	for name := range flagsEverywhere {
		found := false
		var walk func(c *cobra.Command)
		walk = func(c *cobra.Command) {
			found = found || c.Flags().Lookup(name) != nil
			for _, s := range c.Commands() {
				walk(s)
			}
		}
		walk(root)
		if !found {
			t.Errorf("flagsEverywhere: no command has --%s", name)
		}
	}
}

func seedUpstream(t *testing.T) (string, Deps) {
	t.Helper()
	dir := t.TempDir()
	st, err := plainstore.OpenTestnet(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Update(context.Background(), func(w ports.NamedWriter) error {
		for _, r := range []ports.NamedRef{
			{Name: "w1.payment", Kind: ports.AddrFile}, {Name: "w2", Kind: ports.AddrFile},
			{Name: "w1", Kind: ports.StakingVKey}, {Name: "pool1", Kind: ports.NodeVKey}, {Name: "pol", Kind: ports.PolicyVKey},
		} {
			if err := w.Put(r, []byte("x\n")); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return dir, Deps{Out: &bytes.Buffer{}, Err: &bytes.Buffer{},
		OpenUpstream: plainstore.Upstream}
}

func TestWorkspaceNamesListsNamesByClassAndNothingElse(t *testing.T) {
	dir, d := seedUpstream(t)
	got, err := WorkspaceNames(context.Background(), d, dir, true, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"w1", "w2"}; !reflect.DeepEqual(got[uihint.ClassWallet], want) {
		t.Errorf("wallets = %v, want %v (the .payment suffix is not part of the name)", got[uihint.ClassWallet], want)
	}
	if !reflect.DeepEqual(got[uihint.ClassStake], []string{"w1"}) || !reflect.DeepEqual(got[uihint.ClassPool], []string{"pool1"}) || !reflect.DeepEqual(got[uihint.ClassPolicy], []string{"pol"}) {
		t.Errorf("names = %v", got)
	}
	for class, names := range got {
		for _, n := range names {
			if strings.Contains(n, "x") && n != "pool1" && !strings.HasPrefix(n, "pol") {
				t.Errorf("%s lists %q: record contents leaked into the names", class, n)
			}
		}
	}
	// A directory with no workspace has no names, and no error.
	if got, err := WorkspaceNames(context.Background(), d, t.TempDir(), false, false, nil); got != nil || err != nil {
		t.Errorf("empty dir: %v %v", got, err)
	}
	// A sealed workspace is not opened without a passphrase.
	sealed := t.TempDir()
	if err := os.WriteFile(filepath.Join(sealed, WorkspaceFile), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	opened := false
	d.Sealed.Open = func(string, *secret.Buffer, OpenOptions) (SealedStore, error) { opened = true; return nil, nil }
	if _, err := WorkspaceNames(context.Background(), d, sealed, false, false, nil); err != ErrSealed || opened {
		t.Errorf("err %v opened %v: a sealed workspace must stay closed without a passphrase", err, opened)
	}
}

func TestShellCompletionOffersNamesAndFileKinds(t *testing.T) {
	dir, d := seedUpstream(t)
	complete := func(args ...string) string {
		var out bytes.Buffer
		dd := d
		dd.Out, dd.Err = &out, &out
		root := NewRoot(dd)
		MarkForUI(root)
		AttachCompletion(root, dd)
		root.SetArgs(append([]string{"__complete"}, args...))
		if err := root.ExecuteContext(context.Background()); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	out := complete("wallet", "send", "--upstream-layout", "-C", dir, "w")
	if !strings.Contains(out, "w1\n") || !strings.Contains(out, "w2\n") || strings.Contains(out, "pool1") {
		t.Errorf("first argument:\n%s", out)
	}
	if out := complete("wallet", "send", "w1", "--upstream-layout", "-C", dir, "w2"); !strings.Contains(out, "w2\n") {
		t.Errorf("second argument:\n%s", out)
	}
	if out := complete("pool", "register", "--upstream-layout", "-C", dir, "p"); !strings.Contains(out, "pool1\n") || strings.Contains(out, "w1") {
		t.Errorf("pool class:\n%s", out)
	}
	if out := complete("wallet", "send", "w1", "w2", "1", "--transfer-file", ""); !strings.Contains(out, "json\n") {
		t.Errorf("file flag has no extension filter:\n%s", out)
	}
	if out := complete("workspace", "export", ""); !strings.Contains(out, ":16") { // ShellCompDirectiveFilterDirs
		t.Errorf("directory argument:\n%s", out)
	}
	// Sealed: nothing is offered, and nothing is asked.
	sealed := t.TempDir()
	_ = os.WriteFile(filepath.Join(sealed, WorkspaceFile), []byte("x"), 0o600)
	if out := complete("wallet", "send", "-C", sealed, ""); strings.Contains(out, "w1") {
		t.Errorf("a sealed workspace offered names:\n%s", out)
	}
}
