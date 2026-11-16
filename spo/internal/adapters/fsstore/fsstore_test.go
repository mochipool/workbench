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

// The certificate artefacts keep upstream's file names and the locked mode,
// and a rewrite replaces them (05b, 08a and 22a replace without a warning).
//
// spec: SPO-Pfiles-OUT-006, SPO-Pfiles-OUT-007, SPO-Pfiles-OUT-008, SPO-Pfiles-OUT-009, SPO-05b-OUT-001, SPO-08a-OUT-001, SPO-22a-OUT-001
func TestCertificateArtefactNames(t *testing.T) {
	s, dir := open(t)
	want := map[ports.Kind]string{
		ports.StakingCert: "w.staking.cert", ports.DelegCert: "w.deleg.cert", ports.VoteDelegCert: "w.vote-deleg.cert",
		ports.StakingDeregCert: "w.staking.dereg-cert", ports.DRepVKey: "w.drep.vkey",
	}
	for round := 0; round < 2; round++ {
		err := s.Update(ctx, func(w ports.Writer) error {
			for k := range want {
				if err := w.Put(ports.Ref{Name: "w", Kind: k}, []byte{byte('0' + round)}); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for k, name := range want {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil || st.Mode().Perm() != 0o400 {
			t.Errorf("%s: %v %v", name, st, err)
		}
		if b, _ := os.ReadFile(filepath.Join(dir, name)); string(b) != "1" {
			t.Errorf("%s was not replaced: %q", name, b)
		}
		if k.Secret() {
			t.Errorf("%s must not be secret", k)
		}
	}
}

// The pool artefacts have the upstream file names and modes: the descriptor
// and the certificates locked, the published metadata readable by all, and the
// witness transfer file and the additional metadata left writable for the
// operator and for `05d sign`.
//
// spec: SPO-Pfiles-OUT-017, SPO-Pfiles-OUT-018, SPO-Pfiles-OUT-019, SPO-Pfiles-OUT-020, SPO-Pfiles-OUT-021, SPO-Pfiles-OUT-023, SPO-05a-OUT-003, SPO-05d-OUT-001
func TestPoolArtefactNamesAndModes(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := map[ports.Ref]struct {
		file string
		mode os.FileMode
	}{
		{Name: "p", Kind: ports.PoolDescriptor}:            {"p.pool.json", 0o400},
		{Name: "p", Kind: ports.PoolIDFile}:                {"p.pool.id", 0o400},
		{Name: "p", Kind: ports.PoolIDBechFile}:            {"p.pool.id-bech", 0o400},
		{Name: "p", Kind: ports.PoolCert}:                  {"p.pool.cert", 0o400},
		{Name: "p", Kind: ports.PoolDeregCert}:             {"p.pool.dereg-cert", 0o400},
		{Name: "p", Kind: ports.PoolMetadata}:              {"p.metadata.json", 0o444},
		{Name: "p", Kind: ports.PoolExtendedMetadata}:      {"p.extended-metadata.json", 0o444},
		{Name: "p", Kind: ports.PoolAdditionalMetadata}:    {"p.additional-metadata.json", 0o644},
		{Name: "p_o_17", Kind: ports.PoolWitnessFile}:      {"p_o_17.witness", 0o644},
		{Name: "p_p.node_17", Kind: ports.PoolWitnessFile}: {"p_p.node_17.witness", 0o644},
	}
	if err := st.Update(context.Background(), func(w ports.Writer) error {
		for ref := range want {
			if err := w.Put(ref, []byte("x")); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for ref, w := range want {
		fi, err := os.Stat(filepath.Join(dir, w.file))
		if err != nil || fi.Mode().Perm() != w.mode {
			t.Errorf("%v: %v %v", ref, err, fi)
		}
	}
	// The ITN signing key is secret: it is read through the vault, never Get.
	if err := st.View(context.Background(), func(r ports.Reader) error {
		if _, err := r.Get(ports.Ref{Name: "p", Kind: ports.PoolItnSKey}); !errors.Is(err, ports.ErrSecretKind) {
			t.Errorf("%v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Replacing and deleting a file that is not 0400 works.
	if err := st.Update(context.Background(), func(w ports.Writer) error {
		if err := w.Put(ports.Ref{Name: "p_o_17", Kind: ports.PoolWitnessFile}, []byte("y")); err != nil {
			return err
		}
		return w.Delete(ports.Ref{Name: "p", Kind: ports.PoolMetadata})
	}); err != nil {
		t.Fatal(err)
	}
}
