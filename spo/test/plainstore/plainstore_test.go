package plainstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/config"
	"github.com/mochipool/workbench/spo/internal/adapters/upstreamdir"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var ctx = context.Background()

func open(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := OpenTestnet(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}

// spec: SPO-Pfiles-OUT-013, SPO-Pfiles-INV-003, SPO-04c-INV-001, SPO-Pfiles-SEC-002
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
	st, err := OpenTestnet(dir)
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

// Modes of the artefacts that stay unlocked (SPO-Pfiles-INV-004) and of the
// published metadata (SPO-Pfiles-INV-005); everything else is 0400. The
// offline transfer bag is not a workspace artefact (SPO-Pfiles-OUT-037): the
// lister reports it and nothing writes it.
//
// spec: SPO-Pfiles-INV-004, SPO-Pfiles-INV-005, SPO-Pfiles-OUT-037
func TestModesOfUnlockedArtefacts(t *testing.T) {
	dir := t.TempDir()
	st, _ := OpenTestnet(dir)
	want := map[ports.Ref]os.FileMode{
		{Name: "p", Kind: ports.PoolMetadata}:           0o444,
		{Name: "p", Kind: ports.PoolExtendedMetadata}:   0o444,
		{Name: "p", Kind: ports.PoolAdditionalMetadata}: 0o644,
		{Name: "p_1_ab", Kind: ports.PoolWitnessFile}:   0o644,
		{Name: "v", Kind: ports.VoteRegistration}:       0o644,
		{Name: "k", Kind: ports.CalidusRegistration}:    0o644,
		{Name: "pol", Kind: ports.PolicyScript}:         0o400,
		{Name: "p", Kind: ports.NodeVKey}:               0o400,
	}
	err := st.Update(ctx, func(w ports.Writer) error {
		for r := range want {
			if err := w.Put(r, []byte("{}")); err != nil {
				return err
			}
		}
		return w.PutSecret(ports.Ref{Name: "v", Kind: ports.CatalystQRCode}, secret.Take([]byte("png")))
	})
	if err != nil {
		t.Fatal(err)
	}
	for r, m := range want {
		name, _ := upstreamdir.FileName(r)
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil || fi.Mode().Perm() != m {
			t.Errorf("%s: %v %v, want %v", name, fi, err, m)
		}
	}
	// upstream leaves the QR code at the process default; it is secret, so it is 0400 here
	if fi, _ := os.Stat(filepath.Join(dir, "v.catalyst-qrcode.png")); fi == nil || fi.Mode().Perm() != 0o400 {
		t.Errorf("the secret QR code must be 0400: %v", fi)
	}
}

// The plain store refuses mainnet unconditionally: by the network magic, by a
// directory whose spo.toml names mainnet, and by an spo.toml that cannot be read
// (the network is then unknown).
//
// spec: SPO-Xcustody-SEC-002
func TestRefusesMainnet(t *testing.T) {
	if _, err := OpenNetwork(t.TempDir(), MainnetMagic); !errors.Is(err, ErrMainnet) {
		t.Errorf("the mainnet magic: %v", err)
	}
	preview := t.TempDir()
	if err := os.WriteFile(filepath.Join(preview, "spo.toml"), []byte("network = \"preview\"\nmode = \"offline\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenNetwork(preview, 2); err != nil {
		t.Errorf("the preview magic: %v", err)
	}
	for _, tc := range []struct {
		name, toml string
		refused    bool
	}{
		{"mainnet", "network = \"mainnet\"\nmode = \"offline\"\n", true},
		{"preview", "network = \"preview\"\nmode = \"offline\"\n", false},
		{"unreadable", "this is = = not toml [", true},
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "spo.toml"), []byte(tc.toml), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := Open(dir)
		if tc.refused != (err != nil) {
			t.Errorf("%s: %v", tc.name, err)
		}
		if tc.name == "mainnet" && !errors.Is(err, ErrMainnet) {
			t.Errorf("%s: %v", tc.name, err)
		}
		// a refused directory is not written, whatever follows
		if tc.refused {
			if ents, _ := os.ReadDir(dir); len(ents) != 1 {
				t.Errorf("%s: the refused directory was changed: %v", tc.name, ents)
			}
		}
	}
	// An absent spo.toml is refused too: the network is unknown. Nothing is
	// written to such a directory.
	bare := t.TempDir()
	if _, err := Open(bare); !errors.Is(err, ErrNoNetwork) {
		t.Errorf("a directory with no spo.toml: %v", err)
	}
	if _, err := OpenNetwork(bare, 2); !errors.Is(err, ErrNoNetwork) {
		t.Errorf("OpenNetwork on a directory with no spo.toml: %v", err)
	}
	if ents, _ := os.ReadDir(bare); len(ents) != 0 {
		t.Errorf("the refused directory was changed: %v", ents)
	}
	// The test helper writes a testnet spo.toml and then opens; it does not
	// rescue a mainnet directory.
	if _, err := OpenTestnet(bare); err != nil {
		t.Errorf("the helper: %v", err)
	}
	if _, err := config.Load(bare); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the helper left its spo.toml: %v", err)
	}
	if _, err := Open(bare); !errors.Is(err, ErrNoNetwork) {
		t.Errorf("Open after the helper removed its file: %v", err)
	}
	main := t.TempDir()
	if err := os.WriteFile(filepath.Join(main, "spo.toml"), []byte("network = \"mainnet\"\nmode = \"offline\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenTestnet(main); !errors.Is(err, ErrMainnet) {
		t.Errorf("the helper opened a mainnet directory: %v", err)
	}
}
