package sqlitestore

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/unlock"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// A faulty authenticator that answers the NEXT salt wrongly in the session that
// rotates a salt would, with one wrap, leave the record sealed under an output
// nobody can reproduce (for good under strict, which has no recovery wrap). The
// record keeps the previous wrap beside the current one: it still opens, and the
// next good open heals it, keeping the previous wrap until an open succeeds with
// the current one.
//
// spec: SPO-Xcustody-INV-020
func TestAFaultyNextSaltOutputDoesNotStrandAColdRecord(t *testing.T) {
	for _, pol := range []unlock.Policy{unlock.Hardware, unlock.Strict} {
		t.Run(string(pol), func(t *testing.T) {
			var s *Store
			var f *fakeSource
			if pol == unlock.Hardware {
				s, _, f, _ = hwCold(t)
			} else {
				path, _, ff, _ := standardThenRotated(t, unlock.Strict)
				f = ff
				var err error
				if s, err = openHW(path, f, "devA", "1234"); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { s.Close() })
				in := f.inputs("devA", "1234")
				s.SetColdSource(&ColdSource{Factors: &in, Deriver: fakeDeriver{}})
				putSecret(t, s, coldRef, "cold-secret-hw")
			}
			h0, _ := headerOf(t, s, coldRef)
			if len(h0.Prev) != 0 {
				t.Fatal("a new record has a previous salt")
			}
			// open 1: the authenticator answers the second salt wrongly
			f.corruptNext = 1
			if v, err := openString(t, s, coldRef); err != nil || v != "cold-secret-hw" {
				t.Fatalf("open 1: %q %v", v, err)
			}
			h1, _ := headerOf(t, s, coldRef)
			if !bytes.Equal(h1.Salt, h0.Next) || !bytes.Equal(h1.Prev, h0.Salt) {
				t.Fatalf("open 1 did not keep the proved salt as the previous one: %+v", h1)
			}
			// open 2: the current wrap is under a wrong output; the previous one opens it,
			// the answer for the new salt is verified by a second assertion (three touches),
			// and the healed record needs no previous wrap
			n := f.asserts
			if v, err := openString(t, s, coldRef); err != nil || v != "cold-secret-hw" {
				t.Fatalf("a record sealed under a wrong next-salt output did not open: %q %v", v, err)
			}
			if got := f.asserts - n; got != 3 {
				t.Errorf("%d assertions (the current salt, the previous one, the verification of the new one)", got)
			}
			h2, _ := headerOf(t, s, coldRef)
			if len(h2.Prev) != 0 || h2.Fallbacks != 1 {
				t.Errorf("a verified heal keeps no previous wrap and counts itself: prev %x, fallbacks %d", h2.Prev, h2.Fallbacks)
			}
			if bytes.Equal(h2.Salt, h1.Salt) || bytes.Equal(h2.Salt, h0.Salt) {
				t.Error("the healing open did not renew the current salt")
			}
			// open 3: the healed current wrap opens with one assertion and replaces the previous
			n = f.asserts
			if v, err := openString(t, s, coldRef); err != nil || v != "cold-secret-hw" {
				t.Fatalf("open 3: %q %v", v, err)
			}
			if got := f.asserts - n; got != 1 {
				t.Errorf("%d assertions for an open with a good current wrap", got)
			}
			h3, _ := headerOf(t, s, coldRef)
			if !bytes.Equal(h3.Prev, h2.Salt) {
				t.Errorf("the previous salt is not the one the last successful open proved")
			}
			if err := s.Verify(ctx); err != nil {
				t.Fatal(err)
			}
			// an authenticator wrong for every salt opens nothing and writes nothing
			before := fileState(t, s)
			f.corruptAll = true
			if _, err := s.Open(ctx, coldRef); !errors.Is(err, ErrColdFactorWrong) {
				t.Fatalf("wrong outputs: %v", err)
			}
			f.corruptAll = false
			if fileState(t, s) != before {
				t.Error("a refused open changed the file")
			}
			if v, err := openString(t, s, coldRef); err != nil || v != "cold-secret-hw" {
				t.Fatalf("after the fault: %q %v", v, err)
			}
		})
	}
}

// ---- the factor of a NEW cold record is gathered before the write transaction ----

// lockStates records, at every prompt, whether the handle held a write transaction
// or the exclusive file lock.
func lockStates() (*[]bool, func()) {
	var held []bool
	promptHook = func(_ *Store, what string, w bool) { held = append(held, w) }
	return &held, func() { promptHook = nil }
}

// spec: SPO-Xcustody-INV-021
func TestAnewColdRecordIsSealedWithAFactorGatheredBeforeTheTransaction(t *testing.T) {
	// standard: a pool cold key; a second writer proceeds during the prompt
	s, path, _ := stdCold(t, "sub-key passphrase one")
	b, err := Open(path, pw())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	held, done := lockStates()
	defer done()
	var wrote error
	prompts := 0
	s.SetColdSource(&ColdSource{Deriver: fakeDeriver{}, Passphrase: func(pctx context.Context, create bool) (*secret.Buffer, error) {
		prompts++
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		wrote = b.Update(cctx, func(w ports.Writer) error { return w.Put(rf("other", ports.KesCounter), []byte("1")) })
		return secret.Take([]byte("sub-key passphrase one")), nil
	}})
	k := secret.Take([]byte("a second cold key"))
	if err := s.Update(ctx, func(w ports.Writer) error { return putKeyW(w, rf("pool2", ports.NodeSKey), k) }); err != nil {
		t.Fatal(err)
	}
	if wrote != nil {
		t.Errorf("a second writer was blocked or failed during the prompt: %v", wrote)
	}
	if prompts != 1 || len(*held) != 1 || (*held)[0] {
		t.Errorf("standard: %d prompts, write lock held at each: %v", prompts, *held)
	}
	if !seal.IsColdSealed(rowOf(t, s, rf("pool2", ports.NodeSKey)).sealed) {
		t.Error("the new key is not cold")
	}
	// a wrong passphrase (not the one of the existing cold record) is refused and writes nothing
	before := fileState(t, s)
	s.SetColdSource(coldPass("another passphrase"))
	k3 := secret.Take([]byte("a third cold key"))
	if err := s.Update(ctx, func(w ports.Writer) error { return putKeyW(w, rf("pool3", ports.NodeSKey), k3) }); !errors.Is(err, ErrColdPassphraseDiffers) {
		t.Fatalf("a second cold passphrase: %v", err)
	}
	if fileState(t, s) != before {
		t.Error("a refused write changed the file")
	}
	// the write is unchanged when no cold record is created: nothing is asked
	*held = nil
	s.SetColdSource(&ColdSource{Passphrase: func(context.Context, bool) (*secret.Buffer, error) { t.Error("asked"); return nil, errors.New("asked") }})
	if err := s.Update(ctx, func(w ports.Writer) error { return w.Put(rf("other", ports.KesCounter), []byte("2")) }); err != nil || len(*held) != 0 {
		t.Fatalf("a write with no cold record: %v, %d prompts", err, len(*held))
	}
}

// spec: SPO-Xcustody-INV-021
func TestAnewHardwareColdRecordsAreSealedWithAssertionsGatheredBeforeTheTransaction(t *testing.T) {
	s, _, f, _ := hwCold(t)
	held, done := lockStates()
	defer done()
	n := f.asserts
	k1, k2 := secret.Take([]byte("cold key two")), secret.Take([]byte("cold key three"))
	if err := s.Update(ctx, func(w ports.Writer) error {
		if err := putKeyW(w, rf("pool2", ports.NodeSKey), k1); err != nil {
			return err
		}
		return putKeyW(w, rf("pool3", ports.NodeSKey), k2)
	}); err != nil {
		t.Fatal(err)
	}
	if f.asserts-n != 4 || len(*held) != 4 { // two assertions per record: each answer is verified
		t.Errorf("%d assertions, write lock held at each: %v", f.asserts-n, *held)
	}
	if (*held)[0] || (*held)[1] || (*held)[2] || (*held)[3] {
		t.Errorf("%d assertions, write lock held at each: %v", f.asserts-n, *held)
	}
	for _, r := range []ports.Ref{rf("pool2", ports.NodeSKey), rf("pool3", ports.NodeSKey)} {
		if v, err := openString(t, s, r); err != nil || v == "" {
			t.Fatalf("%v: %q %v", r, v, err)
		}
	}
}

// A write that creates a cold record the preparation does not cover fails with a
// clear error and never asks.
//
// spec: SPO-Xcustody-INV-021
func TestAColdRecordWithNoGatheredFactorFailsInsteadOfAsking(t *testing.T) {
	s, _, _ := stdCold(t, "sub-key passphrase one")
	held, done := lockStates()
	defer done()
	s.SetColdSource(&ColdSource{Deriver: fakeDeriver{}, Passphrase: func(context.Context, bool) (*secret.Buffer, error) {
		t.Error("the passphrase was asked under the write lock")
		return secret.Take([]byte("sub-key passphrase one")), nil
	}})
	k := secret.Take([]byte("a second cold key"))
	release, err := s.enter(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	_, err = s.withWriteTx(ctx, func(q dbq) (*Head, error) {
		if e := s.catchUp(ctx, q); e != nil {
			return nil, e
		}
		tx := &txn{s: s, ctx: ctx, q: q, writable: true, ops: map[ports.Ref]*op{}} // no preparation, not a probe
		defer tx.discard()
		if e := putKeyW(tx, rf("pool2", ports.NodeSKey), k); e != nil {
			return nil, e
		}
		return tx.apply()
	}, nil)
	if !errors.Is(err, ErrColdNotGathered) {
		t.Fatalf("a cold record with no gathered factor: %v", err)
	}
	if len(*held) != 0 {
		t.Errorf("asked %d time(s)", len(*held))
	}
}

// Migration: the sub-key passphrase of the cold keys it seals is asked for before the
// exclusive lock and the write transaction.
//
// spec: SPO-Xcustody-INV-021
func TestMigrationAsksTheColdPassphraseOutsideTheWriteTransaction(t *testing.T) {
	p := format2Copy(t)
	old, err := OpenFormat2(p, legacyPW())
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	held, done := lockStates()
	defer done()
	prompts := 0
	old.SetColdSource(&ColdSource{Passphrase: func(context.Context, bool) (*secret.Buffer, error) {
		prompts++
		return secret.Take([]byte("sub-key passphrase one")), nil
	}})
	if _, err := old.Migrate3(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if prompts != 1 || len(*held) != 1 || (*held)[0] {
		t.Errorf("%d prompts, write lock held at each: %v", prompts, *held)
	}
}

// A cold-form row that does not authenticate cannot make the same-passphrase check
// pass: the check finds the genuine record, and with only tampered rows the
// creation is refused.
//
// spec: SPO-Xcustody-INV-022
func TestATamperedColdRowCannotMakeTheSamePassphraseCheckPass(t *testing.T) {
	s, _, _ := stdCold(t, "sub-key passphrase one")
	put := func(name string) error {
		k := secret.Take([]byte("cold key " + name))
		defer k.Destroy()
		return s.Update(ctx, func(w ports.Writer) error { return putKeyW(w, rf(name, ports.NodeSKey), k) })
	}
	if err := put("poolb"); err != nil {
		t.Fatal(err)
	}
	tamper := func(ref ports.Ref) {
		r := rowOf(t, s, ref)
		wk := append([]byte(nil), r.sealed.WrappedKey...)
		wk[len(wk)/2] ^= 1
		if _, err := s.db.Exec(`UPDATE records SET wrapped_key = ? WHERE id = ?`, wk, r.id); err != nil {
			t.Fatal(err)
		}
	}
	// the check is the one the creation runs before its transaction (gatherColdCreate);
	// the rows are tampered behind the store's back, which later writes would
	// notice by other means, so the check is exercised on its own
	gather := func(pass string) error {
		s.SetColdSource(coldPass(pass))
		prep, err := s.gatherColdCreate(ctx, 1)
		prep.destroy()
		return err
	}
	tamper(coldRef) // the first record no longer authenticates
	// another passphrase: the genuine second record is found and refuses it
	if err := gather("another passphrase"); !errors.Is(err, ErrColdPassphraseDiffers) {
		t.Fatalf("a different cold passphrase with one tampered and one genuine record: %v", err)
	}
	// the same passphrase is accepted (the genuine record opens with it)
	if err := gather("sub-key passphrase one"); err != nil {
		t.Fatalf("the same passphrase: %v", err)
	}
	// only tampered rows: refused whatever the passphrase
	tamper(rf("poolb", ports.NodeSKey))
	for _, pass := range []string{"sub-key passphrase one", "another passphrase"} {
		if err := gather(pass); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("a cold record created beside only tampered cold rows (%q): %v", pass, err)
		}
	}
}
