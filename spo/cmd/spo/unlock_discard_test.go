package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/fido2cli"
	"github.com/mochipool/workbench/spo/internal/adapters/sqlitestore"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// A rotation that presented the recovery credential and then failed (here: the new
// authenticator cannot make an hmac-secret credential) leaves no recovery
// presentation on the handle, so the handle cannot go on to change the recovery path.
//
// spec: SPO-Xunlock-PRE-030
func TestAFailedRotationDiscardsTheRecoveryPresentation(t *testing.T) {
	rig := newFidoRig(t, "seed-one", "noEnrolHMAC")
	dir := copyWorkspace(t)
	_, oldRec := template(t)
	s, err := sqlitestore.Open(filepath.Join(dir, cli.WorkspaceFile), secret.Take([]byte(testPass)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	w := sealedStore{s}
	src := &fido2cli.Source{Tools: fidoTools{rig.dir}, Runner: fidoRunner{rig.cfg}}
	pin := func(p string) func(context.Context) (*secret.Buffer, error) {
		return func(context.Context) (*secret.Buffer, error) { return secret.Take([]byte(p)), nil }
	}
	req := cli.RotateRequest{Policy: "hardware",
		Daily:    cli.FactorOpen{Source: src, Device: dev0, PIN: pin(fidoPIN)},
		Recovery: cli.FactorOpen{Source: src, Device: dev1, PIN: pin(fidoPIN2)},
		CurrentRecovery: cli.FactorOpen{Recovery: func(context.Context) (*secret.Buffer, error) {
			return secret.Take([]byte(oldRec)), nil
		}},
	}
	if _, _, err := w.Rotate(context.Background(), req); err == nil {
		t.Fatal("the rotation with an authenticator that cannot enrol succeeded")
	}
	if _, err := s.ChangePassphraseRekey(context.Background(), secret.Take([]byte("another workspace passphrase"))); !errors.Is(err, sqlitestore.ErrRecoveryNotPresented) {
		t.Fatalf("the handle still held the recovery presentation after the failed rotation: %v", err)
	}
}
