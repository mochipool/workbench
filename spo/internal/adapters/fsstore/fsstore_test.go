package fsstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var ctx = context.Background()

func open(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}

// spec: SPO-Pfiles-OUT-013, SPO-Pfiles-INV-003, SPO-04c-INV-001
func TestUpstreamNamesAndLockedMode(t *testing.T) {
	s, dir := open(t)
	key := secret.Take([]byte(`{"type":"KesSigningKey_ed25519_kes_2^6"}`))
	defer key.Destroy()
	err := s.Update(ctx, func(w ports.Writer) error {
		w.Put(ports.Ref{Name: "mypool", Kind: ports.KesVKey, Num: 7}, []byte("v"))
		w.PutSecret(ports.Ref{Name: "mypool", Kind: ports.KesSKey, Num: 7}, key)
		w.Put(ports.Ref{Name: "mypool", Kind: ports.KesCounter}, []byte("007\n"))
		w.Put(ports.Ref{Name: "mypool", Kind: ports.KesCounterNext}, []byte("007\n"))
		return w.Put(ports.Ref{Name: "mypool", Kind: ports.KesVKey, Num: 1000}, []byte("v"))
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"mypool.kes-007.vkey", "mypool.kes-007.skey", "mypool.kes.counter", "mypool.kes.counter-next", "mypool.kes-1000.vkey"} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o400 {
			t.Errorf("%s mode %o, want 0400", name, st.Mode().Perm())
		}
	}
	// A locked file can be replaced (upstream: unlock, write, lock).
	if err := s.Update(ctx, func(w ports.Writer) error {
		return w.Put(ports.Ref{Name: "mypool", Kind: ports.KesCounter}, []byte("008\n"))
	}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "mypool.kes.counter"))
	if string(b) != "008\n" {
		t.Fatalf("counter = %q", b)
	}
}

// H10: a failed update writes nothing, and leaves no temporary files.
func TestFailedUpdateWritesNothing(t *testing.T) {
	s, dir := open(t)
	boom := errors.New("boom")
	err := s.Update(ctx, func(w ports.Writer) error {
		w.Put(ports.Ref{Name: "p", Kind: ports.KesCounter}, []byte("000\n"))
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("workspace not empty: %v", entries)
	}
}

func TestReadYourWritesAndDelete(t *testing.T) {
	s, _ := open(t)
	ref := ports.Ref{Name: "p", Kind: ports.KesCounter}
	err := s.Update(ctx, func(w ports.Writer) error {
		if _, err := w.Get(ref); !errors.Is(err, ports.ErrNotFound) {
			t.Errorf("before put: %v", err)
		}
		w.Put(ref, []byte("001\n"))
		if b, err := w.Get(ref); err != nil || string(b) != "001\n" {
			t.Errorf("after put: %q %v", b, err)
		}
		w.Delete(ref)
		if ok, _ := w.Exists(ref); ok {
			t.Error("exists after delete")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	s.View(ctx, func(r ports.Reader) error {
		if ok, _ := r.Exists(ref); ok {
			t.Error("deleted artefact persisted")
		}
		return nil
	})
}

// Secrets are only reachable through the vault side of the adapter.
func TestSecretsAreNotReadableThroughTheStore(t *testing.T) {
	s, _ := open(t)
	ref := ports.Ref{Name: "p", Kind: ports.KesSKey, Num: 0}
	key := secret.Take([]byte("skey-bytes"))
	defer key.Destroy()
	s.Update(ctx, func(w ports.Writer) error {
		if err := w.Put(ref, []byte("x")); !errors.Is(err, ports.ErrSecretKind) {
			t.Errorf("Put of a secret kind: %v", err)
		}
		return w.PutSecret(ref, key)
	})
	s.View(ctx, func(r ports.Reader) error {
		if _, err := r.Get(ref); !errors.Is(err, ports.ErrSecretKind) {
			t.Errorf("Get of a secret kind: %v", err)
		}
		return nil
	})
	got, err := s.Open(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Destroy()
	got.Use(func(b []byte) error {
		if string(b) != "skey-bytes" {
			t.Errorf("vault returned %q", b)
		}
		return nil
	})
}

// H7: names are labels, never paths or syntax.
func TestHostileNamesAreRefused(t *testing.T) {
	s, dir := open(t)
	for _, name := range []string{"", "../evil", "a/b", ".hidden", "a..b", "x;rm -rf ~", "$(id)", "a b", "pool\x00", "a[$(id)]"} {
		err := s.Update(ctx, func(w ports.Writer) error {
			return w.Put(ports.Ref{Name: name, Kind: ports.KesCounter}, []byte("0"))
		})
		if !errors.Is(err, ports.ErrInvalidRef) {
			t.Errorf("name %q: %v", name, err)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("something was written: %v", entries)
	}
}
