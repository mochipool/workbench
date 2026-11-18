package sqlitestore

import (
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// migratedColdWorkspace is the format 2 fixture, migrated with a sub-key
// passphrase: its legacy slots bind no recovery hash, so its cold key has no
// recovery wrap.
func migratedColdWorkspace(t *testing.T) (string, *Store) {
	t.Helper()
	p := format2Copy(t)
	old, err := OpenFormat2(p, legacyPW())
	if err != nil {
		t.Fatal(err)
	}
	old.SetColdSource(coldPass("sub-key passphrase one"))
	if _, err := old.Migrate3(ctx, ""); err != nil {
		t.Fatal(err)
	}
	old.Close()
	s, err := Open(p, legacyPW())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return p, s
}

func coldRecord(t *testing.T, s *Store) wrapCand {
	t.Helper()
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	c, err := (&txn{s: s, ctx: ctx, q: tx, ops: nil}).coldRowsWithoutWrap()
	if err != nil || len(c) != 1 {
		t.Fatalf("%d cold records without a wrap: %v", len(c), err)
	}
	return c[0]
}

// A rekey that leaves the table binding a recovery hash adds a recovery wrap to
// every cold record that lacks one. It needs the cold factor once, presented before
// the write transaction; without a source it is refused before anything is asked,
// with the wrong factor it is refused with nothing written; afterwards the recovery
// key reaches the cold key.
//
// spec: SPO-Xcustody-PR-009, SPO-Xcustody-PRE-029, SPO-Xcustody-OUT-011
func TestARekeyAddsRecoveryWrapsToColdRecordsThatLackOne(t *testing.T) {
	path, s := migratedColdWorkspace(t)
	c := coldRecord(t, s)
	if cold, without, err := s.ColdWithoutWrap(ctx); err != nil || cold != 1 || without != 1 {
		t.Fatalf("%d %d %v", cold, without, err)
	}
	presentLegacyRecoveryForTest(t, s)

	// no source: refused before anything is asked, nothing changed
	before := fileState(t, s)
	s.SetColdSource(nil)
	if _, err := s.ChangePassphraseRekey(ctx, passphrase("a new workspace passphrase")); !errors.Is(err, ErrColdFactorRequired) {
		t.Fatalf("a rekey that must add a wrap, with no cold source: %v", err)
	}
	if fileState(t, s) != before {
		t.Error("a refused rekey changed the file")
	}
	// the wrong factor: refused, nothing changed
	presentLegacyRecoveryForTest(t, s)
	s.SetColdSource(coldPass("not the sub-key passphrase"))
	if _, err := s.ChangePassphraseRekey(ctx, passphrase("a new workspace passphrase")); !errors.Is(err, ErrColdFactorWrong) {
		t.Fatalf("a rekey with the wrong cold passphrase: %v", err)
	}
	if fileState(t, s) != before {
		t.Error("a refused rekey changed the file")
	}

	// the right factor: asked once, with no write lock held
	var held []bool
	promptHook = func(_ *Store, what string, w bool) { held = append(held, w) }
	defer func() { promptHook = nil }()
	presentLegacyRecoveryForTest(t, s)
	s.SetColdSource(coldPass("sub-key passphrase one"))
	text, err := s.ChangePassphraseRekey(ctx, passphrase("a new workspace passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	var newKey string
	text.Use(func(b []byte) error { newKey = string(b); return nil })
	text.Destroy()
	promptHook = nil
	if len(held) != 1 || held[0] {
		t.Errorf("the cold factor was asked %d time(s) (write lock held at each: %v), want once with none held", len(held), held)
	}
	if cold, without, err := s.ColdWithoutWrap(ctx); err != nil || cold != 1 || without != 0 {
		t.Fatalf("after the rekey: %d cold, %d without a wrap: %v", cold, without, err)
	}
	// the recovery key now reaches the cold key
	oc := mustOuter(t, s, c.ref)
	dk, err := oc.RecoverDataKey(recPrivOf(t, newKey).priv(), c.ident)
	if err != nil {
		t.Fatalf("the new recovery key does not unwrap the migrated cold key: %v", err)
	}
	pt, err := oc.OpenSecretWithDataKey(dk)
	dk.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	pt.Destroy()
	if err := s.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	// the cold passphrase still opens it
	if _, err := s.Open(ctx, c.ref); err != nil {
		t.Fatalf("the cold key does not open after the rekey: %v", err)
	}
	s.Close()
	// and a recovery re-establishes it: opened through the recovery key, the new
	// passphrase and recovery key carry the cold record (its wrap moves to the new key)
	r, err := OpenWithRecovery(path, secret.Take([]byte(newKey)))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	text2, err := r.ChangePassphraseRekey(ctx, passphrase("the passphrase after recovery"))
	if err != nil {
		t.Fatal(err)
	}
	var key2 string
	text2.Use(func(b []byte) error { key2 = string(b); return nil })
	text2.Destroy()
	oc = mustOuter(t, r, c.ref)
	if dk, err = oc.RecoverDataKey(recPrivOf(t, key2).priv(), c.ident); err != nil {
		t.Fatalf("after the recovery rekey: %v", err)
	}
	dk.Destroy()
	r.SetColdSource(coldPass("sub-key passphrase one"))
	if v, err := r.Open(ctx, c.ref); err != nil {
		t.Fatalf("the cold key after the recovery: %v", err)
	} else {
		v.Destroy()
	}
}
