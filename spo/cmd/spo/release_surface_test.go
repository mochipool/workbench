//go:build !plainlayout

package main

import (
	"bytes"
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
)

// The release command tree has no way to write a signing key or any other secret
// unprotected: no plain-directory workspace flag, no `key unprotect` or
// `key protect`, no `--plaintext` on the export, no confirmation word. The
// plainlayout tag is the only thing that brings the flag back, and a build with
// the tag is not a release (SPO-Xcustody-INV-001, SPO-Xcustody-IF-001).
//
// spec: SPO-Xcustody-INV-001, SPO-Xcustody-IF-001
func TestReleaseHasNoPlaintextWriter(t *testing.T) {
	if openPlain != nil || plainAudit != nil {
		t.Fatal("the release wiring has a plain-directory opener")
	}
	var out bytes.Buffer
	root := cli.NewRoot(newDeps(&out, &out, &fakeTerm{out: &out}))
	if f := root.PersistentFlags().Lookup("upstream-layout"); f != nil {
		t.Errorf("the global flag --upstream-layout exists: %q", f.Usage)
	}
	var walk func(c *cobra.Command, path string)
	walk = func(c *cobra.Command, path string) {
		p := strings.TrimSpace(path + " " + c.Name())
		if strings.HasSuffix(p, "key unprotect") || strings.HasSuffix(p, "key protect") {
			t.Errorf("the command %q exists", p)
		}
		for _, name := range []string{"plaintext", "upstream-layout", "unprotect"} {
			if c.Flags().Lookup(name) != nil || c.PersistentFlags().Lookup(name) != nil {
				t.Errorf("%q has the flag --%s", p, name)
			}
		}
		for _, sub := range c.Commands() {
			walk(sub, p)
		}
	}
	walk(root, "")
	// The help of the commands that took them says nothing of them either.
	for _, args := range [][]string{{"--help"}, {"workspace", "--help"}, {"workspace", "export", "--help"}, {"key", "--help"}} {
		h, _ := exec(t, nil, args...)
		for _, bad := range []*regexp.Regexp{regexp.MustCompile(`--upstream-layout`), regexp.MustCompile(`--plaintext`), regexp.MustCompile(`\bunprotect\b`)} {
			if bad.MatchString(h) {
				t.Errorf("%v --help mentions %q", args, bad)
			}
		}
	}
	// Asked for, the flag is refused as unknown (not through exec, which
	// wires a plain workspace for a test that names the flag).
	dir := t.TempDir()
	for _, args := range [][]string{
		{"-C", dir, "--upstream-layout", "wallet", "new", "w"},
		{"-C", dir, "workspace", "export", dir + "/x", "--plaintext"},
	} {
		var o bytes.Buffer
		r := cli.NewRoot(newDeps(&o, &o, &fakeTerm{out: &o}))
		r.SetArgs(args)
		err := r.ExecuteContext(context.Background())
		if err == nil || !(strings.Contains(err.Error(), "unknown flag") || strings.Contains(err.Error(), "unknown command")) {
			t.Errorf("%v: %v", args, err)
		}
	}
}
