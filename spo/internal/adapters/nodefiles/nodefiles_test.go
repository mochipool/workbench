package nodefiles_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"filippo.io/age"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/adapters/nodeage"
	"github.com/mochipool/workbench/spo/internal/adapters/nodefiles"
	"github.com/mochipool/workbench/spo/internal/app/nodekeys"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func anyFS(int64) bool { return true }

type memStore struct{ files, secrets map[ports.NamedRef][]byte }

func (m *memStore) View(_ context.Context, fn func(ports.NamedReader) error) error { return fn(m) }
func (m *memStore) Update(context.Context, func(ports.NamedWriter) error) error {
	return errors.New("read only")
}
func (m *memStore) Get(r ports.NamedRef) ([]byte, error) {
	if b, ok := m.files[r]; ok {
		return b, nil
	}
	return nil, ports.ErrNotFound
}
func (m *memStore) Exists(r ports.NamedRef) (bool, error) { _, ok := m.files[r]; return ok, nil }
func (m *memStore) Open(_ context.Context, r ports.NamedRef) (*secret.Buffer, error) {
	if b, ok := m.secrets[r]; ok {
		return secret.Take(append([]byte(nil), b...)), nil
	}
	return nil, ports.ErrNotFound
}

type nullAudit struct{}

func (nullAudit) Record(context.Context, ports.AuditEvent) error { return nil }

// delivery is what `node export` makes for one pool, built through the use case
// with real keys, the real derivation and the real age sealer.
type delivery struct {
	plain  map[string][]byte // plain file name -> bytes
	cipher map[string][]byte // ciphertext file name -> bytes
	id     *age.X25519Identity
	header pool.DeliveryHeader // the header export wrote for the KES file
}

var testCold = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5c}, 32))

// signedOpcert is a certificate really signed by a test cold key.
func signedOpcert(kesVKey []byte, cold ed25519.PrivateKey, counter, period byte) []byte {
	signable := append(append([]byte(nil), kesVKey...), make([]byte, 16)...)
	signable[32+7], signable[40+7] = counter, period
	sig := ed25519.Sign(cold, signable)
	h := "8284" + "5820" + hex.EncodeToString(kesVKey) + hex.EncodeToString([]byte{counter}) + hex.EncodeToString([]byte{period}) + "5840" + hex.EncodeToString(sig) + "5820" + hex.EncodeToString(cold.Public().(ed25519.PublicKey))
	return []byte(`{"type":"NodeOperationalCertificate","description":"","cborHex":"` + h + `"}`)
}

func opcertFor(kesVKey []byte) []byte { return signedOpcert(kesVKey, testCold, 0, 0) }

func vk32(t *testing.T, env []byte) []byte {
	t.Helper()
	e, err := pool.ParseEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	k, err := e.Key32()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func export(t *testing.T, id *age.X25519Identity) delivery {
	t.Helper()
	ctx := context.Background()
	kp, _ := native.KeyGen{}.GenerateKES(ctx)
	vp, _ := native.KeyGen{}.GenerateVRF(ctx)
	var kesS, vrfS []byte
	kp.SKey.Use(func(b []byte) error { kesS = append([]byte(nil), b...); return nil })
	vp.SKey.Use(func(b []byte) error { vrfS = append([]byte(nil), b...); return nil })
	oc := opcertFor(vk32(t, kp.VKey))
	n := func(k ports.Kind) ports.NamedRef { return ports.NamedRef{Name: "p", Kind: k} }
	cpub := testCold.Public().(ed25519.PublicKey)
	coldVK := []byte(`{"type":"StakePoolVerificationKey_ed25519","description":"","cborHex":"5820` + hex.EncodeToString(cpub) + `"}`)
	ic := pool.IssueCounter{Next: 1}
	copy(ic.ColdVKey[:], cpub)
	st := &memStore{
		files: map[ports.NamedRef][]byte{n(ports.NodeVKey): coldVK, n(ports.NodeCounter): ic.Envelope(), n(ports.KesVKey): kp.VKey, n(ports.VrfVKey): vp.VKey, n(ports.OpCert): oc,
			n(ports.KesCounter): []byte("000\n"), n(ports.KesCounterNext): []byte("001\n")},
		secrets: map[ports.NamedRef][]byte{n(ports.KesSKey): kesS, n(ports.VrfSKey): vrfS},
	}
	kid, _ := ports.IdentityOfVKey(custody.RoleKES, kp.VKey)
	vid, _ := ports.IdentityOfVKey(custody.RoleVRF, vp.VKey)
	uc := nodekeys.Export{Store: st, Vault: st, Derive: native.HotKeyDeriver{}, Sealer: nodeage.Sealer{}, Auditor: nullAudit{},
		History: func(_ context.Context, i identity.Ref) (custody.RoleHistory, bool, error) {
			role := custody.RoleKES
			if i == vid {
				role = custody.RoleVRF
			}
			h, err := custody.NewRoleHistory(i, role)
			return h, err == nil && (i == kid || i == vid), err
		}}
	res, err := uc.Run(ctx, nodekeys.Request{Pool: "p", Recipient: id.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	d := delivery{plain: map[string][]byte{"kes.skey": kesS, "vrf.skey": vrfS, "node.cert": oc}, cipher: map[string][]byte{}, id: id}
	idn, _ := nodeage.ParseIdentity(secret.Take([]byte(id.String())))
	for _, f := range res.Files {
		d.cipher[f.Name] = f.Ciphertext
		if f.Name == "kes.skey.age" {
			pt, err := idn.Open(f.Ciphertext, 4096)
			if err != nil {
				t.Fatal(err)
			}
			pt.Use(func(b []byte) error { d.header, _, err = pool.UnframeDelivery(b); return err })
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	return d
}

type host struct{ from, to, creds string }

func newHost(t *testing.T, d delivery) host {
	t.Helper()
	root := t.TempDir()
	h := host{from: filepath.Join(root, "from"), to: filepath.Join(root, "to"), creds: filepath.Join(root, "creds")}
	for _, p := range []string{h.from, h.to, h.creds} {
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for n, b := range d.cipher {
		if err := os.WriteFile(filepath.Join(h.from, n), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(h.creds, nodefiles.IdentityCredential), []byte(d.id.String()+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h host) cfg() nodefiles.DeliverConfig {
	return nodefiles.DeliverConfig{From: h.from, To: h.to, CredentialsDir: h.creds, Derive: native.HotKeyDeriver{}}
}

func (h host) writtenFiles(t *testing.T) []string {
	t.Helper()
	ents, err := os.ReadDir(h.to)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

func newID(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// spec: SPO-Xcustody-INV-007, SPO-Xcustody-MODE-001, SPO-Xcustody-MODE-002, SPO-Xcustody-PR-002
func TestExportThenHelperWritesTheRightFilesWithTheRightModes(t *testing.T) {
	d := export(t, newID(t))
	h := newHost(t, d)
	paths, err := nodefiles.WithFS(anyFS).Deliver(context.Background(), h.cfg())
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 3 {
		t.Fatalf("%v", paths)
	}
	for name, want := range d.plain {
		p := filepath.Join(h.to, name)
		got, err := os.ReadFile(p)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s: the bytes differ (%v)", name, err)
		}
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm() != 0o400 {
			t.Errorf("%s: mode %v %v", name, st, err)
		}
		if sys := st.Sys().(*syscall.Stat_t); int(sys.Uid) != os.Geteuid() || sys.Nlink != 1 {
			t.Errorf("%s: owner %d links %d", name, sys.Uid, sys.Nlink)
		}
	}
	// a second run never replaces: the files exist, nothing is touched
	before, _ := os.ReadFile(filepath.Join(h.to, "kes.skey"))
	if _, err := nodefiles.WithFS(anyFS).Deliver(context.Background(), h.cfg()); !errors.Is(err, nodefiles.ErrExists) {
		t.Errorf("a second delivery: %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(h.to, "kes.skey"))
	if !bytes.Equal(before, after) || len(h.writtenFiles(t)) != 3 {
		t.Error("an existing file was replaced or a file was removed")
	}
}

// spec: SPO-Xcustody-PRE-012, SPO-Xcustody-PRE-013, SPO-Xcustody-PRE-016, SPO-Xcustody-PRE-015
func TestHelperRefusesWhatIsNotForIt(t *testing.T) {
	ctx := context.Background()
	w := nodefiles.WithFS(anyFS)
	good := export(t, newID(t))

	t.Run("ciphertext sealed to another recipient", func(t *testing.T) {
		d := export(t, newID(t))
		h := newHost(t, d)
		// the host holds a different identity than the one the delivery was sealed to
		os.Remove(filepath.Join(h.creds, nodefiles.IdentityCredential))
		os.WriteFile(filepath.Join(h.creds, nodefiles.IdentityCredential), []byte(newID(t).String()+"\n"), 0o400)
		if _, err := w.Deliver(ctx, h.cfg()); !errors.Is(err, nodeage.ErrOpen) {
			t.Fatalf("%v", err)
		}
		if n := h.writtenFiles(t); len(n) != 0 {
			t.Errorf("wrote %v", n)
		}
	})
	t.Run("tampered ciphertext", func(t *testing.T) {
		d := export(t, newID(t))
		for name := range d.cipher {
			h := newHost(t, d)
			ct := append([]byte(nil), d.cipher[name]...)
			ct[len(ct)-5] ^= 1
			os.WriteFile(filepath.Join(h.from, name), ct, 0o644)
			if _, err := w.Deliver(ctx, h.cfg()); !errors.Is(err, nodeage.ErrOpen) {
				t.Errorf("%s: %v", name, err)
			}
			if n := h.writtenFiles(t); len(n) != 0 {
				t.Errorf("%s: wrote %v", name, n)
			}
		}
	})
	t.Run("a file of another kind under a kind's name", func(t *testing.T) {
		d := export(t, newID(t))
		h := newHost(t, d)
		// the VRF key sealed under the name of the KES key, to the right recipient
		os.WriteFile(filepath.Join(h.from, "kes.skey.age"), d.cipher["vrf.skey.age"], 0o644)
		if _, err := w.Deliver(ctx, h.cfg()); err == nil || !strings.Contains(err.Error(), "header says") {
			t.Fatalf("the header names another kind: %v", err)
		}
		// a header that agrees with the name but a body of another kind
		os.WriteFile(filepath.Join(h.from, "kes.skey.age"), reseal(t, d, "kes.skey", d.plain["vrf.skey"], nil), 0o644)
		if _, err := w.Deliver(ctx, h.cfg()); !errors.Is(err, pool.ErrNotHot) {
			t.Fatalf("%v", err)
		}
		if n := h.writtenFiles(t); len(n) != 0 {
			t.Errorf("wrote %v", n)
		}
	})
	t.Run("a certificate for another KES key", func(t *testing.T) {
		d := export(t, newID(t))
		other := export(t, d.id) // same recipient, other keys
		h := newHost(t, d)
		os.WriteFile(filepath.Join(h.from, "node.cert.age"), other.cipher["node.cert.age"], 0o644)
		if _, err := w.Deliver(ctx, h.cfg()); err == nil || !strings.Contains(err.Error(), "does not name the KES key") {
			t.Fatalf("%v", err)
		}
		if n := h.writtenFiles(t); len(n) != 0 {
			t.Errorf("wrote %v", n)
		}
	})
	t.Run("a certificate whose cold signature does not verify", func(t *testing.T) {
		d := export(t, newID(t))
		h := newHost(t, d)
		bad := append([]byte(nil), d.plain["node.cert"]...)
		i := bytes.Index(bad, []byte("5840")) + 4
		if bad[i] == '0' {
			bad[i] = '1'
		} else {
			bad[i] = '0'
		}
		ct := reseal(t, d, "node.cert", bad, nil)
		os.WriteFile(filepath.Join(h.from, "node.cert.age"), ct, 0o644)
		if _, err := w.Deliver(ctx, h.cfg()); err == nil || !strings.Contains(err.Error(), "signature") {
			t.Fatalf("%v", err)
		}
		if n := h.writtenFiles(t); len(n) != 0 {
			t.Errorf("wrote %v", n)
		}
	})
	// spec: SPO-Xcustody-PRE-015
	t.Run("a mixed set: files of different deliveries", func(t *testing.T) {
		for name, mod := range map[string]func(h *pool.DeliveryHeader){
			"another counter":    func(h *pool.DeliveryHeader) { h.Counter++ },
			"another pool":       func(h *pool.DeliveryHeader) { h.PoolID = strings.Repeat("ab", 28) },
			"another KES number": func(h *pool.DeliveryHeader) { h.KesNumber++ },
		} {
			d := export(t, newID(t))
			h := newHost(t, d)
			os.WriteFile(filepath.Join(h.from, "vrf.skey.age"), reseal(t, d, "vrf.skey", d.plain["vrf.skey"], mod), 0o644)
			if _, err := w.Deliver(ctx, h.cfg()); err == nil || !strings.Contains(err.Error(), "one delivery") {
				t.Errorf("%s: %v", name, err)
			}
			if n := h.writtenFiles(t); len(n) != 0 {
				t.Errorf("%s: wrote %v", name, n)
			}
		}
	})
	t.Run("a file with no header, or a header for another kind", func(t *testing.T) {
		d := export(t, newID(t))
		h := newHost(t, d)
		ct, _ := nodeage.Sealer{}.Seal(context.Background(), d.id.Recipient().String(), secret.Take(append([]byte(nil), d.plain["vrf.skey"]...)))
		os.WriteFile(filepath.Join(h.from, "vrf.skey.age"), ct, 0o644)
		if _, err := w.Deliver(ctx, h.cfg()); !errors.Is(err, pool.ErrDelivery) {
			t.Errorf("no header: %v", err)
		}
		os.WriteFile(filepath.Join(h.from, "vrf.skey.age"), reseal(t, d, "vrf.skey", d.plain["vrf.skey"], func(h *pool.DeliveryHeader) { h.Kind = "kes.skey" }), 0o644)
		if _, err := w.Deliver(ctx, h.cfg()); err == nil || !strings.Contains(err.Error(), "header says") {
			t.Errorf("wrong kind: %v", err)
		}
	})
	t.Run("a missing ciphertext file", func(t *testing.T) {
		h := newHost(t, good)
		os.Remove(filepath.Join(h.from, "vrf.skey.age"))
		if _, err := w.Deliver(ctx, h.cfg()); err == nil {
			t.Fatal("delivered two of three")
		}
		if n := h.writtenFiles(t); len(n) != 0 {
			t.Errorf("wrote %v", n)
		}
	})
	t.Run("a failed write removes what it created", func(t *testing.T) {
		h := newHost(t, good)
		os.WriteFile(filepath.Join(h.to, "node.cert"), []byte("old"), 0o400) // the third file exists
		if _, err := w.Deliver(ctx, h.cfg()); !errors.Is(err, nodefiles.ErrExists) {
			t.Fatalf("%v", err)
		}
		n := h.writtenFiles(t)
		if len(n) != 1 || n[0] != "node.cert" {
			t.Errorf("after the rollback the directory holds %v", n)
		}
	})
	t.Run("an identity that is not an age secret key", func(t *testing.T) {
		h := newHost(t, good)
		os.Remove(filepath.Join(h.creds, nodefiles.IdentityCredential))
		os.WriteFile(filepath.Join(h.creds, nodefiles.IdentityCredential), []byte("not an identity\n"), 0o400)
		if _, err := w.Deliver(ctx, h.cfg()); !errors.Is(err, nodeage.ErrIdentity) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("an identity readable by others", func(t *testing.T) {
		h := newHost(t, good)
		os.Chmod(filepath.Join(h.creds, nodefiles.IdentityCredential), 0o644)
		if _, err := w.Deliver(ctx, h.cfg()); err == nil || !strings.Contains(err.Error(), "accessible by others") {
			t.Fatalf("%v", err)
		}
	})
	t.Run("an identity that is a symbolic link", func(t *testing.T) {
		h := newHost(t, good)
		p := filepath.Join(h.creds, nodefiles.IdentityCredential)
		os.Rename(p, filepath.Join(h.creds, "real"))
		os.Symlink(filepath.Join(h.creds, "real"), p)
		if _, err := w.Deliver(ctx, h.cfg()); err == nil {
			t.Fatal("followed a symbolic link")
		}
	})
	t.Run("no credentials directory", func(t *testing.T) {
		h := newHost(t, good)
		c := h.cfg()
		c.CredentialsDir = ""
		if _, err := w.Deliver(ctx, c); err == nil {
			t.Fatal("delivered with no identity")
		}
	})
}

// spec: SPO-Xcustody-PRE-014
func TestHelperRefusesDirectoriesThatAreNotPrivateRamfs(t *testing.T) {
	ctx := context.Background()
	d := export(t, newID(t))

	// a directory that is a symbolic link, for each of the three directories
	for _, which := range []string{"to", "from", "creds"} {
		h := newHost(t, d)
		real := map[string]*string{"to": &h.to, "from": &h.from, "creds": &h.creds}[which]
		link := *real + "-link"
		if err := os.Symlink(*real, link); err != nil {
			t.Fatal(err)
		}
		*real = link
		if _, err := nodefiles.WithFS(anyFS).Deliver(ctx, h.cfg()); !errors.Is(err, nodefiles.ErrDirectory) {
			t.Errorf("%s as a symbolic link: %v", which, err)
		}
		if which != "to" {
			continue
		}
		if n, _ := os.ReadDir(strings.TrimSuffix(link, "-link")); len(n) != 0 {
			t.Errorf("wrote through a symbolic link: %v", n)
		}
	}
	// group- and other-writable output directory
	for _, mode := range []os.FileMode{0o770, 0o707, 0o777, 0o720} {
		h := newHost(t, d)
		os.Chmod(h.to, mode)
		if _, err := nodefiles.WithFS(anyFS).Deliver(ctx, h.cfg()); !errors.Is(err, nodefiles.ErrDirectory) {
			t.Errorf("output directory mode %04o: %v", mode, err)
		}
	}
	// the release rule: a directory on tmpfs or disk is not a ramfs
	h := newHost(t, d)
	if _, err := (nodefiles.Writer{}).Deliver(ctx, h.cfg()); !errors.Is(err, nodefiles.ErrDirectory) {
		t.Errorf("the release rule accepted a test directory: %v", err)
	}
	// ramfs only: a rule that accepts the ramfs magic and nothing else still refuses this directory
	h = newHost(t, d)
	if _, err := nodefiles.WithFS(func(m int64) bool { return m == nodefiles.RamfsMagic }).Deliver(ctx, h.cfg()); !errors.Is(err, nodefiles.ErrDirectory) {
		t.Errorf("a non-ramfs directory passed the ramfs rule: %v", err)
	}
	// not a directory
	h = newHost(t, d)
	os.Remove(h.to)
	os.WriteFile(h.to, nil, 0o600)
	if _, err := nodefiles.WithFS(anyFS).Deliver(ctx, h.cfg()); !errors.Is(err, nodefiles.ErrDirectory) {
		t.Errorf("a file as the output directory: %v", err)
	}
}

// spec: SPO-Xcustody-INV-008
func TestWriterTakesOnlyTheThreeKindsOfTheirExactForm(t *testing.T) {
	w := nodefiles.WithFS(anyFS)
	d := export(t, newID(t))
	for kind, name := range map[ports.HotFileKind]string{ports.HotKES: "kes.skey", ports.HotVRF: "vrf.skey", ports.HotOpCert: "node.cert"} {
		dir := filepath.Join(t.TempDir(), "d")
		os.Mkdir(dir, 0o700)
		p, err := w.WriteHot(dir, kind, secret.Take(append([]byte(nil), d.plain[name]...)))
		if err != nil || filepath.Base(p) != name {
			t.Fatalf("%s: %v %s", name, err, p)
		}
		// each other kind's file under this kind is refused and leaves nothing
		for other, oname := range map[ports.HotFileKind]string{ports.HotKES: "kes.skey", ports.HotVRF: "vrf.skey", ports.HotOpCert: "node.cert"} {
			if other == kind {
				continue
			}
			dir2 := filepath.Join(t.TempDir(), "d")
			os.Mkdir(dir2, 0o700)
			if _, err := w.WriteHot(dir2, kind, secret.Take(append([]byte(nil), d.plain[oname]...))); !errors.Is(err, nodefiles.ErrNotHot) {
				t.Errorf("%s written as %s: %v", oname, name, err)
			}
			if ents, _ := os.ReadDir(dir2); len(ents) != 0 {
				t.Errorf("a refused write left %d file(s)", len(ents))
			}
		}
	}
	if _, err := w.WriteHot(t.TempDir(), ports.HotFileKind(0), secret.Take(d.plain["kes.skey"])); !errors.Is(err, nodefiles.ErrNotHot) {
		t.Errorf("an unknown kind: %v", err)
	}
}

// reseal makes the ciphertext of a file with its header (as export writes it),
// optionally altered, sealed to the delivery's recipient.
func reseal(t *testing.T, d delivery, file string, plain []byte, mod func(*pool.DeliveryHeader)) []byte {
	t.Helper()
	h := d.header
	h.Kind = file
	if mod != nil {
		mod(&h)
	}
	f, err := pool.FrameDelivery(h, plain)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := nodeage.Sealer{}.Seal(context.Background(), d.id.Recipient().String(), secret.Take(f))
	if err != nil {
		t.Fatal(err)
	}
	return ct
}

// The output directory's own rule, apart from the credentials directory's: a
// directory that is not on ramfs (or tmpfs with noswap) is refused by OpenDir.
//
// spec: SPO-Xcustody-PRE-014
func TestOutputDirectoryRuleOnItsOwn(t *testing.T) {
	dir := t.TempDir()
	if _, err := nodefiles.WithFS(func(m int64) bool { return m == nodefiles.RamfsMagic }).OpenDir(dir); !errors.Is(err, nodefiles.ErrDirectory) {
		t.Errorf("a directory that is not a ramfs: %v", err)
	}
	d, err := nodefiles.WithFS(anyFS).OpenDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
}
