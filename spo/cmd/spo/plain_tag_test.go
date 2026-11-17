//go:build plainlayout

package main

import (
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
)

// A build with the plainlayout tag (not a release) wires the plain-directory
// workspace, so the binary can be run on a plain directory by the parity and
// differential checks; the flag exists only then (SPO-Xcustody-INV-001).
//
// spec: SPO-Xcustody-INV-001
func TestPlainLayoutTagWiresTheStore(t *testing.T) {
	if openPlain == nil || plainAudit == nil {
		t.Fatal("the plainlayout build does not wire the plain store")
	}
	root := cli.NewRoot(newDeps(nil, nil, nil))
	if root.PersistentFlags().Lookup("upstream-layout") == nil {
		t.Error("the plainlayout build has no --upstream-layout flag")
	}
}
