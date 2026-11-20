package relaystore

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/relaydir"
	"github.com/mochipool/workbench/spo/test/s3stand"
)

func (e *env) cli(confirm func(string) (bool, error)) (CLI, *bytes.Buffer, *bytes.Buffer) {
	var out, errb bytes.Buffer
	return CLI{
		Open: func(path string) (Deps, func(), error) {
			if path != "/etc/spo-relay/relay.toml" {
				return Deps{}, nil, errors.New("no such configuration")
			}
			return e.deps(), func() {}, nil
		},
		OpenDir: func(m, r string) (DirSource, func() error, error) {
			src, err := relaydir.Open(m, r)
			if err != nil {
				return nil, nil, err
			}
			return src, src.Close, nil
		},
		Confirm: confirm,
		Stdout:  &out, Stderr: &errb,
	}, &out, &errb
}

const conf = "--config=/etc/spo-relay/relay.toml"

// The usage errors exit 2, as the relay's other commands do.
//
// spec: SPO-Xobjstore-IF-906
func TestStoreCommandsUsage(t *testing.T) {
	e := newEnv(t)
	c, _, _ := e.cli(nil)
	for _, args := range [][]string{
		{"store"}, {"store", "frob", conf}, {"init-store"}, {"init-store", conf, "extra"},
		{"store", "repair", conf}, {"store", "repair", conf, "--action=everything"},
		{"store", "inspect", conf}, {"migrate-store", conf}, {"migrate-store", conf, "--from-mailbox=/m"},
		{"store", "verify", "--no-such-flag", conf},
	} {
		if got := Main(bg(t), args, c); got != 2 {
			t.Errorf("%v: exit %d, want 2", args, got)
		}
	}
	var out bytes.Buffer
	c.Stdout = &out
	if got := Main(bg(t), []string{"store", "--help"}, c); got != 0 || !strings.Contains(out.String(), "migrate-store") {
		t.Errorf("--help: %d %s", got, out.String())
	}
}

// The commands run, and a failing verify exits 1.
//
// spec: SPO-Xobjstore-IF-906
func TestStoreCommandsRun(t *testing.T) {
	e := newEnv(t)
	c, out, errb := e.cli(nil)
	if got := Main(bg(t), []string{"init-store", conf}, c); got != 0 {
		t.Fatalf("init-store: %d %s", got, errb.String())
	}
	if !strings.Contains(out.String(), "the store is initialised") {
		t.Errorf("init-store printed %s", out.String())
	}
	if got := Main(bg(t), []string{"store", "verify", conf}, c); got != 0 {
		t.Fatalf("verify: %d %s %s", got, out.String(), errb.String())
	}
	if got := Main(bg(t), []string{"store", "inspect", conf, "--bucket=working", "--path=registry/"}, c); got != 0 || !strings.Contains(out.String(), "registry/rates") {
		t.Errorf("inspect: %d %s", got, out.String())
	}
	e.srv.AdminPutVersion(workBucket, testPrefix+pathLease, []byte("junk"))
	if got := Main(bg(t), []string{"store", "verify", conf}, c); got != 1 {
		t.Errorf("verify of an unreadable lease: exit %d", got)
	}
	if got := Main(bg(t), []string{"init-store", "--config=/elsewhere"}, c); got != 1 {
		t.Errorf("a configuration that does not load: exit %d", got)
	}
}

// Repair and migration ask on the terminal unless --yes; without a terminal
// they refuse; a dry run asks nothing.
//
// spec: SPO-Xobjstore-PR-901
func TestStoreCommandsConfirm(t *testing.T) {
	e := newEnv(t)
	p := e.populate()
	e.faulty(p)
	wrote := func(from int) bool {
		for _, r := range e.srv.Records()[from:] {
			if r.Op == s3stand.OpDelete || r.Op == s3stand.OpDeleteVersion {
				return true
			}
		}
		return false
	}
	repair := []string{"store", "repair", conf, "--action=delete-markers", "--action=mailbox-unparsable"}
	// no terminal
	c, _, errb := e.cli(nil)
	n := len(e.srv.Records())
	if got := Main(bg(t), repair, c); got != 1 || !strings.Contains(errb.String(), "--yes") || wrote(n) {
		t.Errorf("without a terminal: exit %d, %s", got, errb.String())
	}
	// declined
	var asked string
	c, _, _ = e.cli(func(q string) (bool, error) { asked = q; return false, nil })
	n = len(e.srv.Records())
	if got := Main(bg(t), repair, c); got != 1 || wrote(n) || !strings.Contains(asked, "delete") {
		t.Errorf("declined: exit %d, asked %q", got, asked)
	}
	// a dry run asks nothing
	c, out, _ := e.cli(func(string) (bool, error) { t.Error("a dry run asked"); return false, nil })
	if got := Main(bg(t), append(repair, "--dry-run"), c); got != 0 || !strings.Contains(out.String(), "would") {
		t.Errorf("dry run: %d %s", got, out.String())
	}
	// --yes asks nothing and repairs
	c, out, _ = e.cli(func(string) (bool, error) { t.Error("--yes asked"); return false, nil })
	if got := Main(bg(t), append(repair, "--yes"), c); got != 0 || !strings.Contains(out.String(), "did") {
		t.Errorf("--yes: %d %s", got, out.String())
	}
	// migrate-store asks too
	e2 := newEnv(t)
	dr := buildDirRelay(t, e2.clock)
	c, _, errb = e2.cli(nil)
	mig := []string{"migrate-store", conf, "--from-mailbox=" + dr.mdir, "--from-registry=" + dr.rdir}
	if got := Main(bg(t), mig, c); got != 1 || !strings.Contains(errb.String(), "--yes") {
		t.Errorf("migrate without a terminal: %d %s", got, errb.String())
	}
	c, out, errb = e2.cli(func(string) (bool, error) { return true, nil })
	if got := Main(bg(t), mig, c); got != 0 || !strings.Contains(out.String(), "the migration is complete") {
		t.Errorf("migrate confirmed: %d %s %s", got, out.String(), errb.String())
	}
}
