package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/storeaudit"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

// singleSourceEvents are the single-source records of a workspace: the sealed
// store's audit log when the directory holds one, else the audit file of an
// upstream-layout directory.
func singleSourceEvents(t *testing.T, dir string) []storeaudit.Event {
	t.Helper()
	var evs []storeaudit.Event
	var err error
	if _, serr := os.Stat(filepath.Join(dir, cli.WorkspaceFile)); serr == nil {
		st, oerr := openCold(filepath.Join(dir, cli.WorkspaceFile), secret.Take([]byte(testPass)))
		if oerr != nil {
			t.Fatal(oerr)
		}
		defer st.Close()
		evs, err = storeaudit.Events(context.Background(), labels.Named(st))
	} else {
		evs, err = storeaudit.Events(context.Background(), plainstore.AuditStore(dir))
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []storeaudit.Event
	for _, e := range evs {
		if e.Operation == cli.SingleSourceOperation {
			out = append(out, e)
		}
	}
	return out
}

// wantSingleSource asserts the records of a workspace: want[i] is the command of
// the i-th record, each marked single-source with a source and a read.
func wantSingleSource(t *testing.T, dir string, want ...string) {
	t.Helper()
	got := singleSourceEvents(t, dir)
	if len(got) != len(want) {
		t.Fatalf("%d single-source records, want %d: %+v", len(got), len(want), got)
	}
	for i, e := range got {
		if e.Command != want[i] || !e.SingleSource || e.Source == "" || e.Read == "" {
			t.Errorf("record %d: %+v, want command %q", i, e, want[i])
		}
	}
}

// The wiring the commands run with has an audit recorder; a build without one
// would skip the record (singlesource.go).
func TestProductionDepsRecordSingleSource(t *testing.T) {
	if newDeps(nil, nil, nil).WorkspaceAuditor == nil {
		t.Fatal("no WorkspaceAuditor in the production wiring")
	}
}

// F5: Koios and Blockfrost URLs on one host (here the loopback) are not two
// independent sources; the Env is refused unless same_host_ok is set.
func TestSameHostProvidersAreRefusedAtEnvBuild(t *testing.T) {
	plain := "network = \"preview\"\nmode = \"light\"\n[koios]\nurl = \"http://" + koiosLoopback + "/api/v1\"\n[blockfrost]\nurl = \"http://" + blockfrostLoopback + "/api/v0\"\n"
	r := newCrossRig(t, plain)
	out, err := r.dereg()
	if err == nil || !strings.Contains(err.Error(), "both are on the host") || !strings.Contains(err.Error(), "same_host_ok") {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(r.stand.submitted) != 0 {
		t.Fatal("submitted")
	}
}
