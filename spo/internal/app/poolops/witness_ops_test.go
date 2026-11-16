package poolops

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
)

type witnessApprover struct {
	answer bool
	shown  []party.TxView
	slots  []string
}

func (a *witnessApprover) ApproveSigning(_ context.Context, slot string, v party.TxView) (bool, error) {
	a.shown = append(a.shown, v)
	a.slots = append(a.slots, slot)
	return a.answer, nil
}

// pendingWitness is a registration waiting for bob's witness: the transfer
// file is what the coordinator handed to bob, the rig is the coordinator's
// workspace.
func pendingWitness(t *testing.T) (*prig, pool.TransferFile) {
	t.Helper()
	r := ready(t)
	r.setOwnerWitness("external")
	res, err := r.run(r.register(false, func(uc *RegisterPool) { uc.AllowPending = true }))
	if err != nil {
		t.Fatal(err)
	}
	return r, r.transferFile(res.TransferFiles[0])
}

func (r *prig) witnessSigner(ok bool) (SignWitnessFile, *witnessApprover) {
	a := &witnessApprover{answer: ok}
	return SignWitnessFile{Store: r.store, Tip: r.chain, Clock: r.clock, Viewer: native.TxViewer{}, TxIDs: r.led,
		Signers: pdir{native.VaultSigner{Vault: r.store}}, Approver: a}, a
}

// spec: SPO-05d-IF-003, SPO-05d-IF-004
func TestSigningKeyAndWitnessFileNames(t *testing.T) {
	for in, want := range map[string]string{"bob": "bob.staking", "bob.staking": "bob.staking", "./bob": "bob.staking", "./bob.staking": "bob.staking"} {
		if got := SigningKeyName(in); got != want {
			t.Errorf("key %q -> %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"x": "x.witness", "x.witness": "x.witness", "./x": "x.witness", "./x.witness": "x.witness"} {
		if got := WitnessFileName(in); got != want {
			t.Errorf("file %q -> %q, want %q", in, got, want)
		}
	}
}

// The signer's side, end to end: the owner's machine signs the file with its
// staking key (the transfer file is the only input besides the keys), the
// coordinator imports the answer and re-runs the registration, and the
// assembled transaction is the one an all-local registration gives. The
// signer is shown the decoded body, which names the pool registration, the
// deposit and the TTL, before the witness is made; the file keeps its other
// fields and gets `signedWitness` and `date-signed`; nothing else is written.
//
// spec: SPO-05d-EXT-002, SPO-05d-OUT-001, SPO-05d-OUT-002, SPO-05d-IN-003, SPO-05d-IN-004, SPO-05d-INV-008, SPO-05d-SEC-001, SPO-05d-MODE-001
func TestSignedFileImportsAndAssemblesTheSameTransaction(t *testing.T) {
	ref := ready(t)
	if _, err := ref.run(ref.register(false)); err != nil {
		t.Fatal(err)
	}

	r, tf := pendingWitness(t)
	uc, appr := r.witnessSigner(true)
	before := r.snapshot()
	res, err := uc.Run(ctx, SignRequest{File: tf.Render(), Key: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	r.nothingChanged(before, "signing a transfer file") // the use case writes nothing; the caller writes the file back
	if len(appr.shown) != 1 || appr.slots[0] != "bob.staking" || len(appr.shown[0].Certificates) == 0 || appr.shown[0].TTL == nil || *appr.shown[0].TTL != tf.TTL {
		t.Fatalf("the signer was shown %+v", appr.shown)
	}
	if res.Tip != 1000 || res.NameMismatch || res.Hardware {
		t.Errorf("%+v", res)
	}
	signed, err := pool.ParseTransferFile(res.File)
	if err != nil || !signed.Signed() || signed.DateSigned != "Mon, 16 Nov 2026 12:00:00 +0000" || signed.ID != tf.ID || string(signed.TxBody) != string(tf.TxBody) {
		t.Fatalf("%+v %v", signed, err)
	}
	if bytes.Contains(res.File, []byte("skey")) || bytes.Contains(res.File, []byte("SigningKey")) {
		t.Error("the file carries a signing key")
	}

	if _, err := r.importer().Run(ctx, ImportRequest{Pool: "mypool", File: res.File}); err != nil {
		t.Fatal(err)
	}
	out, err := r.run(r.register(false))
	if err != nil || !out.Submitted {
		t.Fatalf("%+v %v", out, err)
	}
	if !bytes.Equal(r.sub.sent[0], ref.sub.sent[0]) {
		t.Error("the assembled transaction differs from the all-local one")
	}
}

// The checks are upstream's, in order: valid JSON; the window (the port also
// refuses at the TTL itself, a transaction is invalid from that slot on);
// signed once; the key must be the file's signing-vkey, so a file for the
// cold key or the payer cannot be signed with an owner's staking key
// (SPO-05d-INV-007); a name that differs only warns.
//
// spec: SPO-05d-PRE-001, SPO-05d-PRE-002, SPO-05d-PRE-003, SPO-05d-PRE-004, SPO-05d-PRE-005, SPO-05d-PRE-006, SPO-05d-INV-007
func TestSignRefusals(t *testing.T) {
	r, tf := pendingWitness(t)
	uc, appr := r.witnessSigner(true)
	run := func(file []byte, key string) error {
		_, err := uc.Run(ctx, SignRequest{File: file, Key: key})
		return err
	}
	if err := run([]byte("{not json"), "bob"); err == nil {
		t.Error("invalid JSON accepted")
	}
	if err := run(tf.Render(), "nobody"); err == nil {
		t.Error("a missing key file accepted")
	}
	r.chain.tip.Slot = tf.TTL
	if err := run(tf.Render(), "bob"); !errors.Is(err, ErrWitnessExpired) {
		t.Errorf("at the ttl: %v", err)
	}
	r.chain.tip.Slot = tf.TTL - 1
	if err := run(tf.Render(), "bob"); err != nil {
		t.Errorf("one slot before the ttl: %v", err)
	}
	r.chain.tip.Slot = 1000

	signed := r.signWitness(tf, "bob", "StakeVerificationKeyShelley_ed25519")
	if err := run(signed.Render(), "bob"); !errors.Is(err, ErrAlreadySigned) {
		t.Errorf("signed twice: %v", err)
	}
	if err := run(tf.Render(), "alice"); !errors.Is(err, ErrWrongSigningKey) {
		t.Errorf("another owner's key: %v", err)
	}
	// A file asking for the pool's cold key: no staking key of an owner is it.
	nodeFile := tf
	nodeFile.SigningName = "mypool.node"
	nodeFile.SigningVKey = []byte(r.read("mypool.node.vkey"))
	if err := run(nodeFile.Render(), "bob"); !errors.Is(err, ErrWrongSigningKey) {
		t.Errorf("a cold-key request signed with a staking key: %v", err)
	}
	// The name is only a hint: the vkey comparison decides.
	renamed := tf
	renamed.SigningName = "robert.staking"
	res, err := uc.Run(ctx, SignRequest{File: renamed.Render(), Key: "bob"})
	if err != nil || !res.NameMismatch {
		t.Errorf("a name mismatch: %+v %v", res, err)
	}
	if len(appr.shown) != 2 {
		t.Errorf("the body was shown %d times", len(appr.shown))
	}
}

// A witness is made only for a body the signer was shown and approved. The
// file's ttl is a claim: it must be the body's. A body the viewer cannot
// decode in full is refused, as is a missing way to ask (upstream signs
// whatever the file holds without showing it, SPO-05d-INV-008).
//
// spec: SPO-05d-INV-008, SPO-05d-SEC-002
func TestSignNeedsAnApprovedDecodedBody(t *testing.T) {
	r, tf := pendingWitness(t)
	uc, appr := r.witnessSigner(false)
	if _, err := uc.Run(ctx, SignRequest{File: tf.Render(), Key: "bob"}); !errors.Is(err, ErrSigningNotApproved) || len(appr.shown) != 1 {
		t.Errorf("declined: %v", err)
	}
	uc.Approver = nil
	if _, err := uc.Run(ctx, SignRequest{File: tf.Render(), Key: "bob"}); !errors.Is(err, ErrNoApprover) {
		t.Errorf("no approver: %v", err)
	}
	uc, appr = r.witnessSigner(true)
	lie := tf
	lie.TTL += 5000
	if _, err := uc.Run(ctx, SignRequest{File: lie.Render(), Key: "bob"}); !errors.Is(err, ErrBodyNotDisplayable) || len(appr.shown) != 0 {
		t.Errorf("a ttl that is not the body's: %v", err)
	}
	junk := tf
	junk.TxBody = []byte(`{"type":"Unwitnessed Tx ConwayEra","description":"Ledger Cddl Format","cborHex":"84a0a0f5f6"}`)
	if _, err := uc.Run(ctx, SignRequest{File: junk.Render(), Key: "bob"}); err == nil || len(appr.shown) != 0 {
		t.Errorf("a body with no fields was shown or signed: %v", err)
	}
}

// info lists the slots ready or missing in creation order, with the transfer
// file name upstream prints for a missing one, and reads the tip from its
// reader; the pool without a collection answers "no witnesses"; an expired
// collection is reported in full and the error says so. After an import the
// report and the import's own list agree.
//
// spec: SPO-05d-IF-005, SPO-05d-IN-002, SPO-05d-IN-004, SPO-05d-INV-002, SPO-05d-PRE-012, SPO-05d-PRE-013, SPO-05d-OUT-004
func TestWitnessInfo(t *testing.T) {
	r, tf := pendingWitness(t)
	info := WitnessInfo{Store: r.store, Tip: r.chain, TxIDs: r.led}
	got, err := info.Run(ctx, "mypool.pool.json")
	if err != nil || !got.Present || got.State != pool.CollectionOpenIncomplete || got.TTL != tf.TTL || got.Tip != 1000 || got.Ticker == "" || got.Type != tf.Type {
		t.Fatalf("%+v %v", got, err)
	}
	var missing []string
	for _, s := range got.Slots {
		if !s.Ready {
			missing = append(missing, s.Name)
			if s.FileName != "mypool.bob.witness" {
				t.Errorf("the printed name of %s is %q", s.Name, s.FileName)
			}
		}
	}
	if len(got.Slots) != 4 || len(missing) != 1 || missing[0] != "bob.staking" {
		t.Errorf("slots %+v", got.Slots)
	}

	signed := r.signWitness(tf, "bob", "StakeVerificationKeyShelley_ed25519")
	imp, err := r.importer().Run(ctx, ImportRequest{Pool: "mypool", File: signed.Render()})
	if err != nil {
		t.Fatal(err)
	}
	got, err = info.Run(ctx, "mypool")
	if err != nil || got.State != pool.CollectionOpenComplete || len(imp.Missing) != 0 {
		t.Fatalf("%+v %v", got, err)
	}
	for _, s := range got.Slots {
		if !s.Ready {
			t.Errorf("slot %s is missing after the import", s.Name)
		}
	}

	r.chain.tip.Slot = got.TTL + 1
	got, err = info.Run(ctx, "mypool")
	if !errors.Is(err, ErrWitnessExpired) || !got.Present || got.State != pool.CollectionExpired || len(got.Slots) != 4 {
		t.Errorf("expired: %+v %v", got, err)
	}

	r2 := ready(t)
	if got, err := (WitnessInfo{Store: r2.store, Tip: r2.chain, TxIDs: r2.led}).Run(ctx, "mypool"); err != nil || got.Present {
		t.Errorf("no collection: %+v %v", got, err)
	}
	if _, err := info.Run(ctx, "nopool"); err == nil {
		t.Error("a pool with no descriptor")
	}
}

// clear needs the confirmation, removes only `regWitness`, answers "no
// witnesses" without a collection, and leaves the transfer files. The
// descriptor stays locked at 0400 as every store write leaves it (upstream
// leaves it at 0600, SPO-05d-OUT-005: not reproduced).
//
// spec: SPO-05d-PR-001, SPO-05d-OUT-005, SPO-05d-INV-001, SPO-05d-IF-005
func TestClearWitnesses(t *testing.T) {
	r, tf := pendingWitness(t)
	uc := ClearWitnesses{Store: r.store, TxIDs: r.led}
	before := r.snapshot()
	if res, err := uc.Run(ctx, ClearRequest{Pool: "mypool"}); err != nil || !res.Present || res.Cleared {
		t.Fatalf("declined: %+v %v", res, err)
	}
	r.nothingChanged(before, "a declined clear")

	if res, err := uc.Run(ctx, ClearRequest{Pool: "mypool.pool", Confirmed: true}); err != nil || !res.Cleared {
		t.Fatalf("%+v %v", res, err)
	}
	d := r.descriptor()
	if d.Has("regWitness") {
		t.Error("the collection is still in the descriptor")
	}
	st, err := os.Stat(filepath.Join(r.dir, "mypool.pool.json"))
	if err != nil || st.Mode().Perm() != 0o400 {
		t.Errorf("descriptor mode %v %v", st, err)
	}
	if !r.exists(tf.Name() + ".witness") {
		t.Error("clear removed a transfer file")
	}
	if res, err := uc.Run(ctx, ClearRequest{Pool: "mypool", Confirmed: true}); err != nil || res.Present || res.Cleared {
		t.Errorf("no collection: %+v %v", res, err)
	}
	// An expired collection is cleared the same way, then a registration can start again.
	r2, _ := pendingWitness(t)
	r2.chain.tip.Slot = 1000 + 100000 + 10
	if res, err := (ClearWitnesses{Store: r2.store, TxIDs: r2.led}).Run(ctx, ClearRequest{Pool: "mypool", Confirmed: true}); err != nil || !res.Cleared {
		t.Errorf("expired: %+v %v", res, err)
	}
}
