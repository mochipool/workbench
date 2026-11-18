package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/storeaudit"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
)

// hotPool makes the keys of a pool through commands, as an operator would: the
// cold key, the VRF key, KES key 0 and its certificate.
func hotPool(t *testing.T) string {
	t.Helper()
	dir := copyWorkspace(t)
	genesis := writeGenesis(t)
	for _, args := range [][]string{
		{"pool", "keys", "generate", poolName}, {"pool", "vrf", "generate", poolName}, {"pool", "kes", "generate", poolName},
		{"pool", "opcert", "issue", poolName, "--offline", "--shelley-genesis", genesis},
	} {
		if out, err := withPass(t, dir, testPass, args...); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	return dir
}

func recipientFile(t *testing.T) (*age.X25519Identity, string) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "producer.pub")
	if err := os.WriteFile(p, []byte("# the block producer\n"+id.Recipient().String()+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return id, p
}

// editStore runs fn on the open workspace, for a test that needs a record the
// commands cannot make.
func editStore(t *testing.T, dir string, fn func(w ports.Writer)) {
	t.Helper()
	st, err := openCold(filepath.Join(dir, cli.WorkspaceFile), secret.Take([]byte(testPass)))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Update(context.Background(), func(w ports.Writer) error { fn(w); return nil }); err != nil {
		t.Fatal(err)
	}
}

func getNamed(t *testing.T, dir string, ref ports.NamedRef) []byte {
	t.Helper()
	st, err := openCold(filepath.Join(dir, cli.WorkspaceFile), secret.Take([]byte(testPass)))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var out []byte
	if err := labels.Named(st).View(context.Background(), func(r ports.NamedReader) error {
		var e error
		out, e = r.Get(ref)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func putNamed(t *testing.T, dir string, ref ports.NamedRef, data []byte) {
	t.Helper()
	st, err := openCold(filepath.Join(dir, cli.WorkspaceFile), secret.Take([]byte(testPass)))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := labels.Named(st).Update(context.Background(), func(w ports.NamedWriter) error { return w.Put(ref, data) }); err != nil {
		t.Fatal(err)
	}
}

func kesIdentityOf(t *testing.T, dir string) (id ports.Ref) {
	t.Helper()
	st, err := openCold(filepath.Join(dir, cli.WorkspaceFile), secret.Take([]byte(testPass)))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.Close()
	vk := getNamed(t, dir, ports.NamedRef{Name: poolName, Kind: ports.KesVKey})
	ident, err := ports.IdentityOfVKey(custody.RoleKES, vk)
	if err != nil {
		t.Fatal(err)
	}
	return ports.Ref{Anchor: ident, Kind: ports.RoleHistory}
}

// The command writes age ciphertext only, to the recipient named, with an audit
// event, and the decrypted bytes are the workspace's keys.
//
// spec: SPO-Xcustody-IF-005, SPO-Xcustody-OUT-006, SPO-Xcustody-OUT-007
func TestNodeExportWritesOnlyCiphertextForTheRecipient(t *testing.T) {
	dir := hotPool(t)
	id, rf := recipientFile(t)
	out := filepath.Join(t.TempDir(), "delivery")
	text, err := withPass(t, dir, testPass, "node", "export", poolName, "--recipient", rf, "--out", out, "--reason", "producer 1")
	if err != nil {
		t.Fatalf("%v\n%s", err, text)
	}
	ents, err := os.ReadDir(out)
	if err != nil || len(ents) != 3 {
		t.Fatalf("%v %v", ents, err)
	}
	want := map[string]string{
		"kes.skey.age": secretHex(t, dir, ports.NamedRef{Name: poolName, Kind: ports.KesSKey}),
		"vrf.skey.age": secretHex(t, dir, ports.NamedRef{Name: poolName, Kind: ports.VrfSKey}),
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(out, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if st, _ := e.Info(); st.Mode().Perm() != 0o600 {
			t.Errorf("%s: mode %v", e.Name(), st.Mode())
		}
		for _, leak := range []string{"cborHex", "SigningKey", "NodeOperationalCertificate", want["kes.skey.age"], want["vrf.skey.age"]} {
			if leak != "" && bytes.Contains(b, []byte(leak)) {
				t.Errorf("%s holds plaintext %.12s", e.Name(), leak)
			}
		}
		r, err := age.Decrypt(bytes.NewReader(b), id)
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		var pt bytes.Buffer
		pt.ReadFrom(r)
		if h, ok := want[e.Name()]; ok && !strings.Contains(pt.String(), h) {
			t.Errorf("%s does not hold the workspace's key", e.Name())
		}
		if e.Name() == "node.cert.age" && !strings.Contains(pt.String(), "NodeOperationalCertificate") {
			t.Error("the certificate is not a certificate")
		}
		other, _ := age.GenerateX25519Identity()
		if _, err := age.Decrypt(bytes.NewReader(b), other); err == nil {
			t.Errorf("%s opens for another identity", e.Name())
		}
	}
	notLeaked(t, text, testPass, want["kes.skey.age"], want["vrf.skey.age"], "SigningKey")

	// the audit trail names the delivery, never the keys
	st, err := openCold(filepath.Join(dir, cli.WorkspaceFile), secret.Take([]byte(testPass)))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	evs, err := storeaudit.Events(context.Background(), labels.Named(st))
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range evs {
		if e.Operation != "node-export" {
			continue
		}
		found = true
		d := strings.Join(e.Detail, " ")
		if e.Reason != "producer 1" || len(e.Owners) != 1 || e.Owners[0] != poolName ||
			!strings.Contains(d, "kes=0") || !strings.Contains(d, "recipient=") || !strings.Contains(d, "node.cert.age") || !strings.Contains(d, "tpm-identity=") {
			t.Errorf("audit event %+v", e)
		}
		if strings.Contains(d, id.Recipient().String()) {
			t.Error("the audit event holds the whole recipient")
		}
	}
	if !found {
		t.Errorf("no node-export event in %+v", evs)
	}
	// the same directory is not reused
	if _, err := withPass(t, dir, testPass, "node", "export", poolName, "--recipient", rf, "--out", out); err == nil {
		t.Error("an export wrote into a directory that holds a delivery")
	}
}

// spec: SPO-Xcustody-PRE-007, SPO-Xcustody-PRE-008, SPO-Xcustody-PRE-011
func TestNodeExportRefusalsOnARealWorkspaceWriteNothing(t *testing.T) {
	_, rf := recipientFile(t)
	refused := func(t *testing.T, dir string, want string, extra ...string) {
		t.Helper()
		out := filepath.Join(t.TempDir(), "delivery")
		text, err := withPass(t, dir, testPass, append([]string{"node", "export", poolName, "--recipient", rf, "--out", out}, extra...)...)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("want %q: %v\n%s", want, err, text)
		}
		if _, err := os.Stat(out); err == nil {
			t.Error("a refused export created its directory")
		}
		// and no audit event of a delivery
		st, oerr := openCold(filepath.Join(dir, cli.WorkspaceFile), secret.Take([]byte(testPass)))
		if oerr != nil {
			t.Fatal(oerr)
		}
		defer st.Close()
		evs, _ := storeaudit.Events(context.Background(), labels.Named(st))
		for _, e := range evs {
			if e.Operation == "node-export" {
				t.Error("a refused export was recorded as a delivery")
			}
		}
	}
	t.Run("a cold role in the KES key's history", func(t *testing.T) {
		dir := hotPool(t)
		ref := kesIdentityOf(t, dir)
		editStore(t, dir, func(w ports.Writer) {
			if err := labels.RecordRole(w, ref.Anchor, custody.RolePoolCold); err != nil {
				t.Fatal(err)
			}
		})
		refused(t, dir, "cold")
	})
	// (A workspace cannot be edited into having no role history or another KES
	// verification key: its identity records refuse the write. Those cases, and a
	// signing key that does not derive the stored verification key, are tested
	// through the use case in internal/app/nodekeys.)
	t.Run("a signing key of another pair", func(t *testing.T) {
		dir := hotPool(t)
		other := hotPool(t)
		stO, err := openCold(filepath.Join(other, cli.WorkspaceFile), secret.Take([]byte(testPass)))
		if err != nil {
			t.Fatal(err)
		}
		sk, err := labels.Named(stO).Open(context.Background(), ports.NamedRef{Name: poolName, Kind: ports.KesSKey})
		stO.Close()
		if err != nil {
			t.Fatal(err)
		}
		st, err := openCold(filepath.Join(dir, cli.WorkspaceFile), secret.Take([]byte(testPass)))
		if err != nil {
			t.Fatal(err)
		}
		perr := labels.Named(st).Update(context.Background(), func(w ports.NamedWriter) error {
			return w.PutSecret(ports.NamedRef{Name: poolName, Kind: ports.KesSKey}, sk)
		})
		st.Close()
		if perr != nil {
			t.Fatalf("the workspace did not take the other pair's KES key: %v", perr)
		}
		refused(t, dir, "does not derive")
	})
	t.Run("a certificate of another KES key", func(t *testing.T) {
		dir := hotPool(t)
		other := hotPool(t)
		putNamed(t, dir, ports.NamedRef{Name: poolName, Kind: ports.OpCert}, getNamed(t, other, ports.NamedRef{Name: poolName, Kind: ports.OpCert}))
		refused(t, dir, "does not name this KES key")
	})
	t.Run("a recipient file with a secret key", func(t *testing.T) {
		dir := hotPool(t)
		id, _ := age.GenerateX25519Identity()
		bad := filepath.Join(t.TempDir(), "r")
		os.WriteFile(bad, []byte(id.String()+"\n"), 0o600)
		out := filepath.Join(t.TempDir(), "delivery")
		text, err := withPass(t, dir, testPass, "node", "export", poolName, "--recipient", bad, "--out", out)
		if err == nil || !strings.Contains(err.Error(), "PUBLIC key") {
			t.Fatalf("%v\n%s", err, text)
		}
	})
	t.Run("a non-empty output directory", func(t *testing.T) {
		dir := hotPool(t)
		out := t.TempDir()
		os.WriteFile(filepath.Join(out, "x"), nil, 0o600)
		text, err := withPass(t, dir, testPass, "node", "export", poolName, "--recipient", rf, "--out", out)
		if err == nil || !strings.Contains(err.Error(), "not empty") {
			t.Fatalf("%v\n%s", err, text)
		}
	})
	t.Run("a pool with no certificate", func(t *testing.T) {
		dir := copyWorkspace(t)
		for _, args := range [][]string{{"pool", "keys", "generate", poolName}, {"pool", "vrf", "generate", poolName}, {"pool", "kes", "generate", poolName}} {
			if out, err := withPass(t, dir, testPass, args...); err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
		}
		refused(t, dir, "no KES key number")
	})
}

// A KES signing key imported by stem pairs with its verification key, and a
// file with the hot envelope type and other material is refused (the import
// checks every signing key against its stored verification key with the same
// derivation `node export` uses).
//
// spec: SPO-Xcustody-PRE-009, SPO-Xcustody-PRE-010
func TestImportChecksAHotKeyAgainstItsVerificationKey(t *testing.T) {
	build := func() string {
		d := t.TempDir()
		for _, a := range [][]string{{"pool", "keys", "generate", "p"}, {"pool", "vrf", "generate", "p"}, {"pool", "kes", "generate", "p"}} {
			upstreamRun(t, d, a...)
		}
		return d
	}
	imp := func(t *testing.T, src string) (string, error) {
		return withPass(t, copyWorkspace(t), testPass, "workspace", "import", src, "--all")
	}
	// the control: untouched keys import
	if out, err := imp(t, build()); err != nil || strings.Contains(out, "failed") {
		t.Fatalf("a good pool: %v\n%s", err, out)
	}
	other := build()
	for _, c := range []struct{ name, file string }{
		{"KES", "p.kes-000.vkey"}, {"VRF", "p.vrf.vkey"},
	} {
		t.Run(c.name+" verification key of another pair", func(t *testing.T) {
			src := build()
			b, err := os.ReadFile(filepath.Join(other, c.file))
			if err != nil {
				t.Fatal(err)
			}
			os.Chmod(filepath.Join(src, c.file), 0o600)
			if err := os.WriteFile(filepath.Join(src, c.file), b, 0o400); err != nil {
				t.Fatal(err)
			}
			out, err := imp(t, src)
			if err == nil || !strings.Contains(out, "does not belong") {
				t.Fatalf("the mismatched key was imported:\n%s", out)
			}
		})
	}
	for name, c := range map[string]struct{ file, typ, hex string }{
		"KES": {"p.kes-000.skey", "KesSigningKey_ed25519_kes_2^6", "5820" + strings.Repeat("11", 32)},
		"VRF": {"p.vrf.skey", "VrfSigningKey_PraosVRF", "5840" + strings.Repeat("11", 64)},
	} {
		t.Run(name+" type with other key material", func(t *testing.T) {
			src := build()
			p := filepath.Join(src, c.file)
			os.Chmod(p, 0o600)
			if err := os.WriteFile(p, []byte(`{"type":"`+c.typ+`","description":"","cborHex":"`+c.hex+`"}`), 0o400); err != nil {
				t.Fatal(err)
			}
			out, err := imp(t, src)
			if err == nil || !strings.Contains(out, "could not be derived") {
				t.Fatalf("a crafted hot key was imported:\n%s", out)
			}
		})
	}
}
