package sqlitestore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func fileSum(t *testing.T, p string) [32]byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(b)
}

// The read-only handle of a sealed layout (ADR 0012 stage 3, the owner decision on
// scope): one unlock of the slot table is all it takes, every write fails with one
// error, a cold-role record is refused and no factor is asked for it, and nothing
// is written to the file.
//
// spec: SPO-Xlayout-MODE-001, SPO-Xlayout-MODE-002, SPO-Xlayout-MODE-003, SPO-Xlayout-MODE-004
func TestLayoutUnlockGivesAReadOnlyHandleAfterOnePresentation(t *testing.T) {
	for _, b := range snapBuilders() {
		t.Run(b.name, func(t *testing.T) {
			f := b.build(t)
			snap, _, err := ReadSnapshot(ctx, f.path, f.cred())
			if err != nil {
				t.Fatal(err)
			}
			src := f.open(t, f.path)
			want, err := src.ListRecords(ctx)
			if err != nil {
				t.Fatal(err)
			}
			meta, slots := slotsOnly(snap)

			asserts := func() int {
				if f.fake == nil {
					return 0
				}
				return f.fake.asserts
			}
			base := asserts()
			op, err := OpenLayoutKeys(ctx, meta, slots, f.cred())
			if err != nil {
				t.Fatal(err)
			}
			op.Close()
			perUnlock := asserts() - base

			base = asserts()
			op, u, err := UnlockLayout(ctx, meta, slots, f.cred())
			if err != nil {
				t.Fatal(err)
			}
			op.Close()
			defer u.Close()
			scratchFile := filepath.Join(t.TempDir(), "workspace.spo")
			if err := u.WriteFile(ctx, scratchFile, snap); err != nil {
				t.Fatalf("the scratch file: %v", err)
			}
			sum := fileSum(t, scratchFile)
			st, err := u.OpenReadOnly(scratchFile)
			if err != nil {
				t.Fatalf("the read-only open: %v", err)
			}
			if got := asserts() - base; got != perUnlock {
				t.Errorf("the unlock, the scratch file and the read-only open took %d presentations of the authenticator; one unlock takes %d", got, perUnlock)
			}
			got, err := st.ListRecords(ctx)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("the records differ: %v\n%v\n%v", err, got, want)
			}
			if err := st.Update(ctx, func(w ports.Writer) error { return nil }); !errors.Is(err, ErrLayoutReadOnly) {
				t.Errorf("Update on a layout handle: %v", err)
			}
			if _, err := st.ChangePassphraseRekey(ctx, tmpPass(t, "a new passphrase here")); !errors.Is(err, ErrLayoutReadOnly) {
				t.Errorf("a rekey on a layout handle: %v", err)
			}
			// Cleanup deletes leftover files, which is a write: it must be refused.
			if err := st.Cleanup(ctx); !errors.Is(err, ErrLayoutReadOnly) {
				t.Errorf("cleanup on a layout handle: %v", err)
			}
			base = asserts()
			cold, hot := 0, 0
			for _, ref := range got {
				if !ref.Kind.Secret() {
					if _, err := st.Open(ctx, ref); err == nil {
						t.Errorf("%s: a non-secret record opened as a secret", ref)
					}
					continue
				}
				sec, err := st.Open(ctx, ref)
				switch {
				case err == nil:
					hot++
					sec.Destroy()
				case errors.Is(err, ErrLayoutColdRecord):
					cold++
				default:
					t.Errorf("%s: %v", ref, err)
				}
			}
			if asserts() != base {
				t.Errorf("opening secrets asked the authenticator %d times", asserts()-base)
			}
			t.Logf("%d hot secrets opened, %d cold-role records refused", hot, cold)
			if b.name == "standard cold record" || b.name == "hardware cold record" {
				if cold == 0 {
					t.Error("no cold-role record was refused")
				}
			}
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}
			if fileSum(t, scratchFile) != sum {
				t.Error("the scratch file changed")
			}
		})
	}
}

// A read-only open writes nothing to the store file: it is byte for byte what it
// was (SQLite's own -wal and -shm files of a read-only connection live in the
// private scratch directory, which is removed).
//
// spec: SPO-Xlayout-MODE-002
func TestLayoutReadOnlyHandleWritesNothing(t *testing.T) {
	f := snapBuilders()[0].build(t)
	snap, _, err := ReadSnapshot(ctx, f.path, f.cred())
	if err != nil {
		t.Fatal(err)
	}
	meta, slots := slotsOnly(snap)
	op, u, err := UnlockLayout(ctx, meta, slots, f.cred())
	if err != nil {
		t.Fatal(err)
	}
	op.Close()
	defer u.Close()
	scratchFile := filepath.Join(t.TempDir(), "workspace.spo")
	if err := u.WriteFile(ctx, scratchFile, snap); err != nil {
		t.Fatal(err)
	}
	before := fileSum(t, scratchFile)
	if _, err := os.Stat(scratchFile + "-wal"); err == nil {
		t.Fatal("WriteFile left a -wal file")
	}
	st, err := u.OpenReadOnly(scratchFile)
	if err != nil {
		t.Fatal(err)
	}
	// below the port: the SQLite connection itself is read-only
	if _, err := st.db.Exec(`DELETE FROM records`); err == nil {
		t.Error("the connection of a layout handle accepted a write")
	}
	refs, _ := st.ListRecords(ctx)
	for _, r := range refs {
		if r.Kind.Secret() {
			if s, err := st.Open(ctx, r); err == nil {
				s.Destroy()
			}
		}
	}
	st.Verify(ctx)
	st.Close()
	if fileSum(t, scratchFile) != before {
		t.Error("the file changed")
	}
}

// A master key that is not the key of the layout's epoch is refused by the
// read-only open, as an unlock with a wrong credential is.
//
// spec: SPO-Xlayout-MODE-004
func TestLayoutReadOnlyOpenRefusesAMasterKeyOfAnotherEpoch(t *testing.T) {
	f := snapBuilders()[0].build(t)
	snap, _, err := ReadSnapshot(ctx, f.path, f.cred())
	if err != nil {
		t.Fatal(err)
	}
	meta, slots := slotsOnly(snap)
	op, u, err := UnlockLayout(ctx, meta, slots, f.cred())
	if err != nil {
		t.Fatal(err)
	}
	op.Close()
	scratchFile := filepath.Join(t.TempDir(), "workspace.spo")
	if err := u.WriteFile(ctx, scratchFile, snap); err != nil {
		t.Fatal(err)
	}
	u.Close()
	if _, err := u.OpenReadOnly(scratchFile); err == nil {
		t.Error("a closed unlock opened a read-only handle")
	}
	other := &LayoutUnlock{master: secret.Take(bytes.Repeat([]byte{7}, 32))}
	defer other.Close()
	if st, err := other.OpenReadOnly(scratchFile); err == nil {
		st.Close()
		t.Error("a master key that is not the workspace's opened the file")
	} else if !errors.Is(err, ErrKeyEpoch) {
		t.Errorf("%v", err)
	}
	if err := other.WriteFile(ctx, filepath.Join(t.TempDir(), "x.spo"), snap); err == nil {
		t.Error("a master key that is not the workspace's wrote a verified file")
	}
}

// Defence in depth: a read-only layout handle takes no cold factor source, and the
// check that opens every cold-role record with that factor is refused outright, so
// no passphrase or authenticator is asked for even if a caller wires one.
//
// spec: SPO-Xlayout-MODE-003
func TestLayoutReadOnlyHandleTakesNoColdSourceAndVerifiesNoColdPayload(t *testing.T) {
	for _, b := range snapBuilders() {
		if b.name != "standard cold record" && b.name != "hardware cold record" {
			continue
		}
		t.Run(b.name, func(t *testing.T) {
			f := b.build(t)
			snap, _, err := ReadSnapshot(ctx, f.path, f.cred())
			if err != nil {
				t.Fatal(err)
			}
			meta, slots := slotsOnly(snap)
			op, u, err := UnlockLayout(ctx, meta, slots, f.cred())
			if err != nil {
				t.Fatal(err)
			}
			op.Close()
			defer u.Close()
			scratchFile := filepath.Join(t.TempDir(), "workspace.spo")
			if err := u.WriteFile(ctx, scratchFile, snap); err != nil {
				t.Fatal(err)
			}
			st, err := u.OpenReadOnly(scratchFile)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			asked := 0
			st.SetColdSource(&ColdSource{
				Passphrase: func(context.Context, bool) (*secret.Buffer, error) {
					asked++
					return secret.Take([]byte("x")), nil
				},
				Deriver: fakeDeriver{},
			})
			if st.coldSource() != nil {
				t.Error("a read-only layout handle kept a cold factor source")
			}
			base := 0
			if f.fake != nil {
				base = f.fake.asserts
			}
			n, err := st.VerifyColdPayloads(ctx)
			if !errors.Is(err, ErrLayoutColdRecord) || n != 0 {
				t.Errorf("VerifyColdPayloads on a layout handle: %d, %v", n, err)
			}
			if asked != 0 {
				t.Errorf("the cold passphrase was asked %d times", asked)
			}
			if f.fake != nil && f.fake.asserts != base {
				t.Errorf("the authenticator was asked %d times", f.fake.asserts-base)
			}
		})
	}
}
