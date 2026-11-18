//go:build plainlayout

package main

import (
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

// This file is built only with -tags plainlayout, for the parity and
// differential checks that run the binary on a plain upstream-layout
// directory (--upstream-layout). The release build never contains it, and
// internal/archtest keeps it the only non-test file outside spo/test that
// imports the plain store. The store opens a directory only when its spo.toml
// exists and names a network other than mainnet (plainstore.Open).
func init() {
	openPlain, plainAudit = plainOpener, plainAuditor
}

func plainOpener(dir string) (ports.Store, error) {
	st, err := plainstore.Open(dir)
	if err != nil {
		return nil, err
	}
	return st.Anchor(), nil
}

func plainAuditor(dir string, store ports.NamedStore) ports.NamedStore {
	if as, ok := labels.AnchorOf(store); ok && plainstore.IsPlain(as) {
		return plainstore.AuditStore(dir)
	}
	return store
}
