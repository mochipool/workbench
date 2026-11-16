package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// failTerm fails the test when it is asked anything: a command that cannot
// run must say so before it prompts.
type failTerm struct{ t *testing.T }

func (f failTerm) ReadSecret(context.Context, string) (*secret.Buffer, error) {
	f.t.Error("asked for a secret before the needs were checked")
	return nil, ErrNoTerminal
}
func (f failTerm) ReadLine(context.Context, string) (string, error) {
	f.t.Error("asked a question before the needs were checked")
	return "", ErrNoTerminal
}

// ADR 0008: a command states all its needs first and fails once, listing
// every missing capability and why, before any prompt or effect.
func TestRequireListsEveryMissingCapabilityBeforeAnyPrompt(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, WorkspaceFile), []byte("sealed"), 0o600)
	var out bytes.Buffer
	opened := false
	d := Deps{
		Out: &out, Err: &out, Terminal: failTerm{t},
		Config: memConfig(map[string]WorkspaceConfig{dir: {Network: "preview", Mode: ModeOffline}}),
		Sealed: SealedOps{Open: func(string, *secret.Buffer, OpenOptions) (SealedStore, error) {
			opened = true
			return nil, nil
		}},
	}
	// Offline, no transfer file, no genesis: the wiring leaves these out.
	d.Wire = func(st ports.Store, o WireOptions) (*Env, error) {
		env, _ := newSendFixture(t).deps.Wire(st, o)
		env.Tip, env.Params, env.Utxos, env.Queue, env.Genesis = nil, nil, nil, nil, nil
		env.Absent(CapTip, "offline mode computes the slot from the clock and the Shelley genesis")
		env.Absent(CapUtxos, "offline mode reads this from an offline transfer file and it does not exist")
		env.Absent(CapParams, "offline mode reads this from an offline transfer file and it does not exist")
		env.Absent(CapQueue, "offline mode reads this from an offline transfer file and it does not exist")
		return env, nil
	}
	root := NewRoot(d)
	root.SetArgs([]string{"-C", dir, "wallet", "send", "w", sendTo, "ALL"})
	err := root.ExecuteContext(context.Background())
	if err == nil {
		t.Fatal("ran without its needs")
	}
	if opened {
		t.Error("the workspace was opened before the needs were checked")
	}
	msg := err.Error()
	for _, want := range []string{string(CapGenesis), string(CapTip), string(CapParams), string(CapUtxos), "one of tx-submit, tx-queue", "no transaction submitter; queue to a transfer file instead"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error does not mention %q:\n%s", want, msg)
		}
	}
	if strings.Count(msg, "\n  - ") < 5 {
		t.Errorf("not one line per missing need:\n%s", msg)
	}
}

func TestEnvRequireBasics(t *testing.T) {
	e := &Env{Mode: ModeOffline, KesKeys: fakeKeyGen{}}
	if err := e.Require(CapKesKeys); err != nil {
		t.Error(err)
	}
	e.Absent(CapUtxos, "because")
	e.Absent(CapUtxos, "a later reason does not replace it")
	err := e.Require(CapKesKeys, CapUtxos, OneOf(CapSubmit, CapQueue))
	if err == nil || !strings.Contains(err.Error(), "utxo: because") || !strings.Contains(err.Error(), "one of tx-submit, tx-queue") {
		t.Errorf("%v", err)
	}
	if strings.Contains(err.Error(), "kes-keygen") {
		t.Errorf("a present capability is listed: %v", err)
	}
	// A typed nil is absent.
	var q *recQueue
	e.Queue = q
	if e.Has(CapQueue) {
		t.Error("a typed nil counts as present")
	}
}
