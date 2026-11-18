package sqlitestore

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/unlock"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// standardThenRotated makes a standard workspace, takes a backup of it, then
// rotates the workspace to the policy (hardware or strict). It returns the
// workspace path, the standard backup, the fake authenticators and the recovery
// key text current for the rotated workspace (the standard recovery key, for
// strict, which has none).
// firstRecovery is the recovery key the workspace of standardThenRotated was
// created with.
var firstRecovery string

// firstHardwareRecovery is the recovery key of the hardware table the helper made.
var firstHardwareRecovery string

func standardThenRotated(t *testing.T, to unlock.Policy) (path, backup string, f *fakeSource, rec string) {
	t.Helper()
	s, path, rec0 := scratch(t)
	firstRecovery = rec0
	putSecret(t, s, skey0, "the-signing-key")
	backup = filepath.Join(t.TempDir(), "standard.bak")
	if err := s.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	f = newFake()
	fa, _, err := EnrolFactor(ctx, f.inputs("devA", "1234"), s.ws, nil)
	if err != nil {
		t.Fatal(err)
	}
	if to == unlock.Strict {
		text, _, err := s.Rotate(ctx, RotatePlan{Policy: unlock.Strict, Proof: presentStd(t, s, rec0), Slots: []SlotPlan{{Kind: seal.SlotFIDO2HMAC, Factors: []FactorPlan{fa}}}})
		if err != nil || text != nil {
			t.Fatalf("%v", err)
		}
		s.Close()
		return path, backup, f, ""
	}
	fb, _, err := EnrolFactor(ctx, f.inputs("devB", "5678"), s.ws, nil)
	if err != nil {
		t.Fatal(err)
	}
	text, _, err := s.Rotate(ctx, RotatePlan{Policy: unlock.Hardware, Proof: presentStd(t, s, rec0), Slots: []SlotPlan{
		{Kind: seal.SlotFIDO2HMAC, Factors: []FactorPlan{fa}},
		{Kind: seal.SlotComposite, Factors: []FactorPlan{{Params: seal.FactorParams{Kind: seal.FactorRecovery}}, fb}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	text.Use(func(b []byte) error { rec = string(b); return nil })
	text.Destroy()
	firstHardwareRecovery = rec
	s.Close()
	return path, backup, f, rec
}

func recoveryRaw(t *testing.T, text string) func(context.Context) (*secret.Buffer, error) {
	t.Helper()
	raw, err := seal.DecodeRecoveryKey(secret.Take([]byte(text)))
	if err != nil {
		t.Fatal(err)
	}
	b := rawBytes(raw)
	raw.Destroy()
	return func(context.Context) (*secret.Buffer, error) { return secret.Take(append([]byte(nil), b...)), nil }
}

// Restore never weakens the policy: a standard backup does not replace a
// hardware or strict workspace, with or without --force and --allow-older,
// unless the weaker policy is allowed AND the current recovery credential is
// presented on the current file.
//
// spec: SPO-Xunlock-PRE-033
func TestRestoreRefusesABackupWithAWeakerPolicy(t *testing.T) {
	refusedUnchanged := func(t *testing.T, path string, err, want error) {
		t.Helper()
		if !errors.Is(err, want) {
			t.Fatalf("%v (want %v)", err, want)
		}
		if pol, _, derr := Describe(path); derr != nil || pol == unlock.Standard {
			t.Errorf("the refused restore changed the policy to %q (%v)", pol, derr)
		}
	}
	t.Run("hardware, forced and older allowed, is still refused", func(t *testing.T) {
		path, backup, _, _ := standardThenRotated(t, unlock.Hardware)
		err := RestoreWithOptions(backup, path, pw(), RestoreOptions{Overwrite: true, AllowOlder: true})
		refusedUnchanged(t, path, err, ErrRestoreWeakens)
	})
	t.Run("hardware, weaker allowed but no recovery presented", func(t *testing.T) {
		path, backup, _, _ := standardThenRotated(t, unlock.Hardware)
		err := RestoreWithOptions(backup, path, pw(), RestoreOptions{Overwrite: true, AllowOlder: true, AllowWeakerPolicy: true})
		refusedUnchanged(t, path, err, ErrRecoveryNotPresented)
	})
	t.Run("hardware, a wrong recovery key", func(t *testing.T) {
		path, backup, f, _ := standardThenRotated(t, unlock.Hardware)
		in := f.inputs("devB", "5678")
		in.Recovery = func(context.Context) (*secret.Buffer, error) { return secret.Take(make([]byte, 32)), nil }
		err := RestoreWithOptions(backup, path, pw(), RestoreOptions{Overwrite: true, AllowOlder: true, AllowWeakerPolicy: true, CurrentRecovery: &in})
		if !errors.Is(err, ErrWrongRecovery) && !errors.Is(err, ErrWrongCredential) {
			t.Fatalf("a wrong recovery key: %v", err)
		}
		if pol, _, _ := Describe(path); pol != unlock.Hardware {
			t.Errorf("policy %q", pol)
		}
	})
	t.Run("hardware, the recovery credential presented: restored", func(t *testing.T) {
		path, backup, f, rec := standardThenRotated(t, unlock.Hardware)
		in := f.inputs("devB", "5678")
		in.Recovery = recoveryRaw(t, rec)
		if err := RestoreWithOptions(backup, path, pw(), RestoreOptions{Overwrite: true, AllowOlder: true, AllowWeakerPolicy: true, CurrentRecovery: &in}); err != nil {
			t.Fatal(err)
		}
		if pol, _, _ := Describe(path); pol != unlock.Standard {
			t.Errorf("policy %q", pol)
		}
	})
	t.Run("strict is never loosened, even with a recovery key", func(t *testing.T) {
		path, backup, f, _ := standardThenRotated(t, unlock.Strict)
		in := f.inputs("devA", "1234")
		in.Recovery = func(context.Context) (*secret.Buffer, error) { return secret.Take(make([]byte, 32)), nil }
		err := RestoreWithOptions(backup, path, pw(), RestoreOptions{Overwrite: true, AllowOlder: true, AllowWeakerPolicy: true, CurrentRecovery: &in})
		refusedUnchanged(t, path, err, ErrNoRecoveryPath)
		err = RestoreWithOptions(backup, path, pw(), RestoreOptions{Overwrite: true, AllowOlder: true})
		refusedUnchanged(t, path, err, ErrRestoreWeakens)
	})
	t.Run("the same or a stronger policy needs none of it", func(t *testing.T) {
		s, path, _ := scratch(t)
		bk := filepath.Join(t.TempDir(), "b")
		if err := s.Backup(ctx, bk); err != nil {
			t.Fatal(err)
		}
		s.Close()
		if err := RestoreWithOptions(bk, path, pw(), RestoreOptions{Overwrite: true}); err != nil {
			t.Errorf("standard over standard: %v", err)
		}
	})
}

// A backup of a hardware workspace is restored through its factors; a passphrase
// cannot verify it.
//
// spec: SPO-Xunlock-PRE-034
func TestRestoreOfAHardwareBackupWorksThroughFactors(t *testing.T) {
	path, f, _ := hardwareWS(t)
	s, err := openHW(path, f, "devA", "1234")
	if err != nil {
		t.Fatal(err)
	}
	bk := filepath.Join(t.TempDir(), "hw.bak")
	if err := s.Backup(ctx, bk); err != nil {
		t.Fatal(err)
	}
	s.Close()
	dest := filepath.Join(t.TempDir(), "restored.db")
	if err := RestoreWithOptions(bk, dest, pw(), RestoreOptions{}); err == nil {
		t.Fatal("a passphrase verified a hardware backup")
	}
	if exists(dest) {
		t.Error("a failed restore left a file")
	}
	if err := RestoreWithFactors(bk, dest, f.inputs("devA", "1234"), RestoreOptions{}); err != nil {
		t.Fatal(err)
	}
	if pol, _, err := Describe(dest); err != nil || pol != unlock.Hardware {
		t.Errorf("%q %v", pol, err)
	}
	r, err := openHW(dest, f, "devA", "1234")
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	// a wrong PIN verifies nothing
	dest2 := filepath.Join(t.TempDir(), "r2.db")
	if err := RestoreWithFactors(bk, dest2, f.inputs("devA", "0000"), RestoreOptions{}); err == nil || exists(dest2) {
		t.Errorf("a wrong PIN restored: %v", err)
	}
}

// After the rotation that `init --policy hardware` does, the throwaway passphrase
// the workspace was first created with opens nothing, no slot of the old table
// remains and no cleanup is pending.
//
// spec: SPO-Xunlock-PRE-035
func TestRotationLeavesNoTraceOfTheThrowawayPassphrase(t *testing.T) {
	path, _, f, _ := standardThenRotated(t, unlock.Hardware) // a workspace created with pw(), then rotated
	if _, err := Open(path, pw()); !errors.Is(err, ErrWrongCredential) {
		t.Fatalf("the first passphrase still opens the workspace: %v", err)
	}
	if o, err := OpenWithRecoveryOptions(path, secret.Take([]byte(firstRecovery)), OpenOptions{}); err == nil {
		o.Close()
		t.Error("the first recovery key still opens the workspace")
	}
	pol, slots, err := Describe(path)
	if err != nil || pol != unlock.Hardware {
		t.Fatalf("%q %v", pol, err)
	}
	for _, sl := range slots {
		if sl.Kind == seal.SlotPassphrase || sl.Kind == seal.SlotRecovery {
			t.Errorf("a slot of the old table is still there: %s", sl.Kind)
		}
	}
	if len(slots) != 2 {
		t.Errorf("%d slots, want the daily one and the recovery composite", len(slots))
	}
	db := rawDB(t, path)
	defer db.Close()
	var n, pending int
	if err := db.QueryRow(`SELECT count(*) FROM keyslots`).Scan(&n); err != nil || n != 2 {
		t.Errorf("keyslots rows %d %v", n, err)
	}
	if err := db.QueryRow(`SELECT cleanup_pending FROM meta`).Scan(&pending); err != nil || pending != 0 {
		t.Errorf("cleanup_pending %d %v", pending, err)
	}
	h, err := openHW(path, f, "devA", "1234")
	if err != nil {
		t.Fatal(err)
	}
	h.Close()
}

// slotRemovedEvents reads the sealed audit trail of the open handle and returns
// the slot ids named by "slot-removed" events.
func slotRemovedEvents(t *testing.T, s *Store) map[string]string {
	t.Helper()
	rows, err := s.db.Query(`SELECT seq, event FROM audit ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]string{} // hex id -> kind
	for rows.Next() {
		var seq uint64
		var ev []byte
		if err := rows.Scan(&seq, &ev); err != nil {
			t.Fatal(err)
		}
		evs, err := openEvent(s.keys, s.ws, seq, ev)
		if err != nil {
			continue // rows of the older segments are sealed under the previous keys
		}
		for _, e := range evs {
			if len(e) == 3 && e[0] == "slot-removed" {
				id, _ := e[2].([]byte)
				kind, _ := e[1].(string)
				got[hex.EncodeToString(id)] = kind
			}
		}
	}
	return got
}

// A strict rotation, and a slot removal, write an audit event naming each
// removed slot id.
//
// spec: SPO-Xunlock-OUT-017
func TestRotationAndSlotRemovalNameTheRemovedSlotsInTheAuditTrail(t *testing.T) {
	t.Run("a strict rotation names every slot of the old table", func(t *testing.T) {
		path, _, f, _ := standardThenRotated(t, unlock.Hardware)
		s, err := openHW(path, f, "devA", "1234")
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		_, before, err := Describe(path)
		if err != nil || len(before) != 2 {
			t.Fatalf("%d slots %v", len(before), err)
		}
		// a strict rotation by the daily factor: the recovery composite of another
		// holder is removed too
		plan := strictPlan(t, s, f, "devA", "1234")
		plan.Proof = presentHW(t, s, f, firstHardwareRecovery)
		if txt, _, err := s.Rotate(ctx, plan); err != nil || txt != nil {
			t.Fatalf("%v", err)
		}
		got := slotRemovedEvents(t, s)
		for _, sl := range before {
			if got[hex.EncodeToString(sl.ID)] != string(sl.Kind) {
				t.Errorf("the removed %s slot %x is not named in the audit trail (%v)", sl.Kind, sl.ID, got)
			}
		}
		if len(got) != len(before) {
			t.Errorf("%d events for %d removed slots", len(got), len(before))
		}
		if err := s.Verify(ctx); err != nil {
			t.Errorf("the audit chain does not verify: %v", err)
		}
	})
	t.Run("slot remove names the one slot", func(t *testing.T) {
		s, _, rec := scratch(t)
		put(t, s, counter, "1")
		f := newFake()
		fa, _, err := EnrolFactor(ctx, f.inputs("devA", "1234"), s.ws, nil)
		if err != nil {
			t.Fatal(err)
		}
		id, err := s.AddFactorSlot(ctx, []FactorPlan{fa})
		if err != nil {
			t.Fatal(err)
		}
		fa.Output.Destroy()
		req := RemoveRequest{SlotID: id, Daily: f.inputs("devA", "1234"), Proof: presentStd(t, s, rec)}
		req.Daily.Passphrase = pinOf(string(rawBytes(pw())))
		if txt, _, err := s.RemoveSlotByRotation(ctx, req); err != nil {
			t.Fatal(err)
		} else if txt != nil {
			txt.Destroy()
		}
		got := slotRemovedEvents(t, s)
		if len(got) != 1 || got[hex.EncodeToString(id)] != "fido2-hmac" {
			t.Errorf("audit trail %v, want only slot %x", got, id)
		}
	})
}

// A removal re-creates every kept FIDO2 slot from the presented authenticator;
// an authenticator that is not the slot's (same credential id byte, other secret)
// must not become its factor.
//
// spec: SPO-Xunlock-PRE-037
func TestSlotRemovalChecksTheKeptSlotsWithTheirOldOutputs(t *testing.T) {
	impostorOf := func(f *fakeSource) *fakeSource {
		g := newFake()
		g.auths["devA"] = &fakeAuth{f.auths["devA"].id, "an impostor seed", "1234"}
		return g
	}
	t.Run("hardware", func(t *testing.T) {
		path, _, f, rec := standardThenRotated(t, unlock.Hardware)
		s, err := openHW(path, f, "devA", "1234")
		if err != nil {
			t.Fatal(err)
		}
		fx, _, _ := EnrolFactor(ctx, f.inputs("devA", "1234"), s.ws, nil)
		id, err := s.AddFactorSlot(ctx, []FactorPlan{fx})
		if err != nil {
			t.Fatal(err)
		}
		req := RemoveRequest{SlotID: id, Proof: presentHW(t, s, f, rec), Daily: impostorOf(f).inputs("devA", "1234"), Recovery: f.inputs("devB", "5678")}
		req.Recovery.Recovery = recoveryRaw(t, rec)
		if _, _, err := s.RemoveSlotByRotation(ctx, req); !errors.Is(err, ErrWrongCredential) {
			t.Fatalf("an impostor authenticator re-created the daily slot: %v", err)
		}
		s.Close()
		h, err := openHW(path, f, "devA", "1234")
		if err != nil {
			t.Fatalf("the real authenticator no longer opens: %v", err)
		}
		h.Close()
		if _, err := openHW(path, impostorOf(f), "devA", "1234"); err == nil {
			t.Error("the impostor opens the workspace")
		}
	})
	t.Run("strict", func(t *testing.T) {
		path, _, f, _ := standardThenRotated(t, unlock.Strict)
		s, err := openHW(path, f, "devA", "1234")
		if err != nil {
			t.Fatal(err)
		}
		fx, _, _ := EnrolFactor(ctx, f.inputs("devA", "1234"), s.ws, nil)
		id, err := s.AddFactorSlot(ctx, []FactorPlan{fx})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.RemoveSlotByRotation(ctx, RemoveRequest{SlotID: id, Daily: impostorOf(f).inputs("devA", "1234")}); !errors.Is(err, ErrWrongCredential) {
			t.Fatalf("a wrong-secret authenticator was accepted under strict: %v", err)
		}
		s.Close()
		h, err := openHW(path, f, "devA", "1234")
		if err != nil {
			t.Fatal(err)
		}
		h.Close()
	})
	t.Run("the honest authenticator still works", func(t *testing.T) {
		path, _, f, _ := standardThenRotated(t, unlock.Strict)
		s, _ := openHW(path, f, "devA", "1234")
		defer s.Close()
		fx, _, _ := EnrolFactor(ctx, f.inputs("devA", "1234"), s.ws, nil)
		id, _ := s.AddFactorSlot(ctx, []FactorPlan{fx})
		if _, _, err := s.RemoveSlotByRotation(ctx, RemoveRequest{SlotID: id, Daily: f.inputs("devA", "1234")}); err != nil {
			t.Fatal(err)
		}
	})
}

// The key RekeyKeepRecovery keeps must be the one that was presented.
//
// spec: SPO-Xunlock-PRE-031
func TestKeepRecoveryKeepsOnlyThePresentedKey(t *testing.T) {
	s, _, rec := scratchPresented(t)
	presentStd(t, s, rec)
	other := make([]byte, 32)
	other[0] = 1
	if err := s.RekeyKeepRecovery(ctx, passphrase("brand new passphrase"), secret.Take(other)); !errors.Is(err, ErrWrongRecovery) {
		t.Fatalf("a recovery key other than the presented one was kept: %v", err)
	}
	// the refused attempt consumed the presentation, whatever its outcome
	presentStd(t, s, rec)
	raw, _ := seal.DecodeRecoveryKey(secret.Take([]byte(rec)))
	if err := s.RekeyKeepRecovery(ctx, passphrase("brand new passphrase"), raw); err != nil {
		t.Fatal(err)
	}
	// the presentation does not outlive the rekey
	raw2, _ := seal.DecodeRecoveryKey(secret.Take([]byte(rec)))
	if err := s.RekeyKeepRecovery(ctx, passphrase("another new passphrase"), raw2); !errors.Is(err, ErrRecoveryNotPresented) {
		t.Errorf("a second rekey without a new presentation: %v", err)
	}
}

// The destination changes between the policy check and the swap (a rotation to a
// stronger policy), and a destination that cannot be read is not simply replaced.
//
// spec: SPO-Xunlock-PRE-033
func TestRestoreRechecksUnderTheLockAndRefusesAnUnreadableDestination(t *testing.T) {
	t.Run("a rotation between the check and the swap", func(t *testing.T) {
		s, path, rec := scratch(t)
		bk := filepath.Join(t.TempDir(), "std.bak")
		if err := s.Backup(ctx, bk); err != nil {
			t.Fatal(err)
		}
		s.Close()
		afterPolicyCheck = func() {
			afterPolicyCheck = nil
			o, err := OpenWithRecovery(path, secret.Take([]byte(rec)))
			if err != nil {
				t.Error(err)
				return
			}
			f := newFake()
			fa, _, _ := EnrolFactor(ctx, f.inputs("devA", "1234"), o.ws, nil)
			if _, _, err := o.Rotate(ctx, RotatePlan{Policy: unlock.Strict, Slots: []SlotPlan{{Kind: seal.SlotFIDO2HMAC, Factors: []FactorPlan{fa}}}}); err != nil {
				t.Error(err)
			}
			o.Close()
		}
		defer func() { afterPolicyCheck = nil }()
		err := RestoreWithOptions(bk, path, pw(), RestoreOptions{Overwrite: true, AllowOlder: true})
		if !errors.Is(err, ErrConflictRestore) {
			t.Fatalf("%v", err)
		}
		if pol, _, _ := Describe(path); pol != unlock.Strict {
			t.Errorf("policy %q: the stale check replaced the strengthened workspace", pol)
		}
	})
	t.Run("an unreadable destination", func(t *testing.T) {
		s, path, _ := scratch(t)
		bk := filepath.Join(t.TempDir(), "std.bak")
		s.Backup(ctx, bk)
		s.Close()
		os.WriteFile(path, []byte("not a database at all, damaged"), 0o600)
		os.Remove(path + "-wal")
		os.Remove(path + "-shm")
		if err := RestoreWithOptions(bk, path, pw(), RestoreOptions{Overwrite: true, AllowOlder: true}); !errors.Is(err, ErrRestoreWeakens) {
			t.Fatalf("an unreadable destination was replaced: %v", err)
		}
		if b, _ := os.ReadFile(path); string(b) != "not a database at all, damaged" {
			t.Error("the damaged file was touched")
		}
		if err := RestoreWithOptions(bk, path, pw(), RestoreOptions{Overwrite: true, AllowOlder: true, AllowWeakerPolicy: true, AllowOtherWorkspace: true}); err != nil {
			t.Errorf("both flags replace it: %v", err)
		}
	})
}

// A strict rotation is checked against the table that is there when it commits,
// not the one the operator saw.
//
// spec: SPO-Xunlock-PRE-032
func TestStrictRotationRechecksTheConfirmedSlotsInTheTransaction(t *testing.T) {
	path, _, f, _ := standardThenRotated(t, unlock.Strict)
	s, err := openHW(path, f, "devA", "1234")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, slots, _ := Describe(path)
	confirmed := map[string]bool{}
	for _, sl := range slots {
		confirmed[hex.EncodeToString(sl.ID)] = true
	}
	// another holder adds a slot after the operator confirmed
	fx, _, _ := EnrolFactor(ctx, f.inputs("devA", "1234"), s.ws, nil)
	if _, err := s.AddFactorSlot(ctx, []FactorPlan{fx}); err != nil {
		t.Fatal(err)
	}
	plan := strictPlan(t, s, f, "devA", "1234")
	plan.ConfirmRemoved = confirmed
	if _, _, err := s.Rotate(ctx, plan); !errors.Is(err, ErrRemovalNotConfirmed) {
		t.Fatalf("a slot that appeared after the confirmation was removed: %v", err)
	}
	if _, _, err := s.Rotate(ctx, strictPlan(t, s, f, "devA", "1234")); err != nil {
		t.Errorf("without a confirmation set (an API caller) the rotation is unchanged: %v", err)
	}
}
