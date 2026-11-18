package main

import (
	"slices"
	"testing"

	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

// usePlainLayout wires the test-only plain-directory workspace (--upstream-layout)
// for the length of the test. The release binary has none (SPO-Xcustody-INV-001);
// tests that build or inspect an upstream-layout directory with this binary's
// commands wire it here, in a test file, and the tag-built binary wires it in
// wiring_plain.go. Tests do not run in parallel in this package.
func usePlainLayout(t *testing.T) {
	t.Helper()
	oldOpen, oldAudit := openPlain, plainAudit
	openPlain = plainstore.Upstream
	plainAudit = func(dir string, store ports.NamedStore) ports.NamedStore {
		if as, ok := labels.AnchorOf(store); ok && plainstore.IsPlain(as) {
			return plainstore.AuditStore(dir)
		}
		return store
	}
	t.Cleanup(func() { openPlain, plainAudit = oldOpen, oldAudit })
}

// usePlainLayoutIfAsked wires it when the arguments name --upstream-layout.
func usePlainLayoutIfAsked(t *testing.T, args []string) {
	t.Helper()
	if slices.ContainsFunc(args, func(a string) bool { return a == "--upstream-layout" || a == "--upstream-layout=true" }) {
		usePlainLayout(t)
	}
}
