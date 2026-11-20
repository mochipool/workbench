package sqlitestore

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/unlock"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// A backup says, without a key, its workspace id, head and slot-table hash; the
// slot-table hash changes with the slots and not with records.
//
// spec: SPO-Xbackup-IF-006
func TestInspectBackupFactsReadsHeadAndSlotTableWithoutAKey(t *testing.T) {
	s, _, _ := scratch(t)
	b1 := filepath.Join(t.TempDir(), "b1")
	h1, err := s.BackupWithHead(ctx, b1)
	if err != nil {
		t.Fatal(err)
	}
	putCounters(t, s, "poolA", cstate{issue: 1, kesCur: 0, kesNext: 1})
	b2 := filepath.Join(t.TempDir(), "b2")
	h2, _ := s.BackupWithHead(ctx, b2)
	f1, err := InspectBackupFacts(b1)
	if err != nil {
		t.Fatal(err)
	}
	f2, _ := InspectBackupFacts(b2)
	if !bytes.Equal(f1.WorkspaceID, s.ws) || f1.Head.Seq != h1.Seq || !bytes.Equal(f1.Head.MAC, h1.MAC) || len(f1.SlotTable) != 32 {
		t.Fatalf("%+v", f1)
	}
	if f2.Head.Seq == f1.Head.Seq || !bytes.Equal(f1.SlotTable, f2.SlotTable) || f2.Head.Seq != h2.Seq {
		t.Fatal("a record write changed the slot-table hash, or the head did not move")
	}
	// a rotation changes it
	path, _, f, _ := standardThenRotated(t, unlock.Strict)
	before, _ := InspectBackupFacts(path)
	st, err := openHW(path, f, "devA", pinA)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Rotate(ctx, strictPlan(t, st, f, "devB", pinB)); err != nil {
		t.Fatal(err)
	}
	st.Close()
	after, _ := InspectBackupFacts(path)
	if bytes.Equal(before.SlotTable, after.SlotTable) {
		t.Fatal("a rotation left the slot-table hash as it was")
	}
}

// The daily credentials are those of the slots that unlock day to day: not the
// recovery composite's.
//
// spec: SPO-Xbackup-PRE-016
func TestDailyCredentialIDsExcludeTheRecoveryComposite(t *testing.T) {
	path, f, _ := hardwareWS(t)
	s, err := openHW(path, f, "devA", pinA)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ids, err := s.DailyCredentialIDs(ctx)
	if err != nil || len(ids) != 1 || ids[0][0] != 1 /* the fake's id byte of devA */ {
		t.Fatalf("%v %v", err, ids)
	}
}

// A workspace rotation keeps the checkpoint key record: it is a sealed record
// like any other.
//
// spec: SPO-Xbackup-PRE-019
func TestARotationKeepsTheCheckpointKeyRecord(t *testing.T) {
	s, path, rec0 := scratch(t)
	ref := rf("checkpoint", ports.CheckpointKey)
	want := []byte("spo/checkpoint-key/v1\nkey-type x\n")
	if err := s.Update(ctx, func(w ports.Writer) error { return w.Put(ref, want) }); err != nil {
		t.Fatal(err)
	}
	f := newFake()
	fa, _, err := enrolOwned(ctx, f.inputs("devA", pinA), s.ws, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Rotate(ctx, RotatePlan{Policy: unlock.Strict, Proof: presentStd(t, s, rec0), Slots: []SlotPlan{{Kind: seal.SlotFIDO2HMAC, Factors: []FactorPlan{fa}}}}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	r, err := openHW(path, f, "devA", pinA)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got, err := get(r, ref)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("%v %q", err, got)
	}
}
