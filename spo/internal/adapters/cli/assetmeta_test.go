package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/domain/assets"
	"github.com/mochipool/workbench/spo/internal/domain/tokenmeta"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// dirLogos reads logo files relative to a directory, as the composition root's
// reader does.
type dirLogos struct{ dir string }

func (l dirLogos) ReadLogoFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		path = filepath.Join(l.dir, path)
	}
	return os.ReadFile(path)
}

// fakeRegistry serves one entry (or an error) for every subject and records
// what it was asked.
type fakeRegistry struct {
	entry tokenmeta.Entry
	err   error
	asked []string
}

func (f *fakeRegistry) Registry() string { return "registry.test" }
func (f *fakeRegistry) TokenMetadata(_ context.Context, subject string) (tokenmeta.Entry, error) {
	f.asked = append(f.asked, subject)
	return f.entry, f.err
}

// withRegistry gives the fixture the registry capabilities the composition root
// wires: the vault registry signer, the logo reader and, when reg is not nil, a
// registry reader (light mode). Without one the reader is absent with the
// reason offline mode gives.
func withRegistry(f *sendFixture, reg ports.TokenRegistryReader) {
	withExtras(f)
	old := f.deps.Wire
	f.deps.Wire = func(st ports.Store, o WireOptions) (*Env, error) {
		env, err := old(st, o)
		if err != nil {
			return nil, err
		}
		var v ports.Vault
		if st != nil {
			v = st.(ports.Vault)
		}
		env.Signers = native.RegistrySigners{Vault: v}
		env.RegistrySigner = native.VaultRegistry{VaultSignatures: native.VaultSignatures{VaultSigner: native.VaultSigner{Vault: v}}}
		env.Logos = dirLogos{dir: f.dir}
		if reg != nil {
			env.Registry = reg
		} else {
			env.Absent(CapTokenRegistry, "offline mode makes no network request, so the token registry is not asked")
		}
		return env, nil
	}
}

func readRecord(t *testing.T, dir, name string) assets.Record {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name+".asset"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := assets.ParseRecord(b)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// storedEntry reads the submission file `<subject>.json`.
func storedEntry(t *testing.T, dir, subject string) ([]byte, tokenmeta.Entry) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, subject+".json"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := tokenmeta.ParseEntry(b)
	if err != nil {
		t.Fatal(err)
	}
	return b, e
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var n []string
	for _, e := range es {
		n = append(n, e.Name())
	}
	return n
}

// spec: SPO-12a-IF-001, SPO-12a-OUT-001, SPO-12a-OUT-002, SPO-12a-OUT-003, SPO-12a-OUT-004
// The first run creates the record and says which fields to fill in; the second
// run, with the fields set, signs and stores an entry that verifies, and prints
// the subject, the sequence number and where the entry is. --out writes the
// public entry, byte for byte what the workspace holds.
func TestAssetMetaGenerateTwice(t *testing.T) {
	f := newSendFixture(t)
	withRegistry(f, nil)
	run := func(args ...string) error { return f.run(t, &scriptTerm{t: t}, args...) }
	if err := run("policy", "new", "p"); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	f.out.Reset()

	if err := run("asset", "meta", "generate", "p.tok.asset"); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	mustContain(t, f.out.String(), "Created the asset record p.tok/asset", "metaName", "metaDescription", "metaDecimals", "metaTicker", "metaUrl", "metaLogoPNG", "--set")
	rec := readRecord(t, f.dir, "p.tok")
	subject := rec.Get("subject")
	if len(subject) < 56 || rec.Get("sequenceNumber") != "0" {
		t.Fatalf("record %q seq %q", subject, rec.Get("sequenceNumber"))
	}
	if _, err := os.Stat(filepath.Join(f.dir, subject+".json")); err == nil {
		t.Fatal("the first run signed an entry")
	}

	// Second run: fields set on the command line, signed in one go.
	f.out.Reset()
	out := filepath.Join(t.TempDir(), "entry.json")
	if err := run("asset", "meta", "generate", "p.tok", "--set", "metaName=Token", "--set", "metaDescription=A test token",
		"--set", "metaTicker=TOK", "--set", "metaDecimals=2", "--set", "metaUrl=https://example.org", "--out", out); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	mustContain(t, f.out.String(), "Signed the registry entry", "subject      "+subject, "sequence     1", subject+"/", "public data", "Wrote the signed entry to "+out)
	stored, entry := storedEntry(t, f.dir, subject)
	if v := entry.Verify(); !v.OK {
		t.Fatalf("the stored entry does not verify: %+v", v)
	}
	if got, _ := os.ReadFile(out); !bytes.Equal(got, stored) {
		t.Error("--out is not the stored entry")
	}
	if seq, _ := entry.Sequence(); seq != 1 || entry.Props[tokenmeta.PropName].Value.String() != "Token" {
		t.Errorf("entry seq %d name %v", seq, entry.Props[tokenmeta.PropName].Value)
	}
	if r := readRecord(t, f.dir, "p.tok"); r.Get("sequenceNumber") != "1" || r.Get("metaTicker") != "TOK" {
		t.Errorf("record %v", r.Get("sequenceNumber"))
	}
	if strings.Contains(f.out.String(), "skey") || strings.Contains(f.out.String(), "cborHex") {
		t.Errorf("key material in the output:\n%s", f.out.String())
	}

	// The output file is never replaced, and that is found before anything is signed.
	f.out.Reset()
	if err := run("asset", "meta", "generate", "p.tok", "--out", out); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing --out: %v", err)
	}
	if r := readRecord(t, f.dir, "p.tok"); r.Get("sequenceNumber") != "1" {
		t.Errorf("a refused run advanced the sequence to %s", r.Get("sequenceNumber"))
	}
	// Without --set the record's own fields are signed again, one number higher.
	if err := run("asset", "meta", "generate", "p.tok"); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	if _, e := storedEntry(t, f.dir, subject); !e.Verify().OK {
		t.Error("second entry does not verify")
	} else if seq, _ := e.Sequence(); seq != 2 {
		t.Errorf("sequence %d", seq)
	}
}

// spec: SPO-12a-IN-002, SPO-12a-INV-002
// A hardware policy key is refused by the signing plan before anything is written.
func TestAssetMetaGenerateRefusesAHardwarePolicy(t *testing.T) {
	f := newSendFixture(t)
	withRegistry(f, nil)
	if err := f.run(t, &scriptTerm{t: t}, "policy", "new", "p"); err != nil {
		t.Fatal(err)
	}
	writeFile(t, f.dir, "p.policy.hwsfile", "{}")
	before := dirNames(t, f.dir)
	err := f.run(t, &scriptTerm{t: t}, "asset", "meta", "generate", "p.tok", "--set", "metaName=Token")
	if err == nil || !strings.Contains(err.Error(), "hardware") {
		t.Fatalf("a hardware policy key: %v", err)
	}
	if after := dirNames(t, f.dir); strings.Join(before, ",") != strings.Join(after, ",") {
		t.Errorf("a refusal changed the workspace: %v -> %v", before, after)
	}
}

// Needs are stated before anything is created or asked: a build without a
// registry signer lists the capability, and no record appears.
func TestAssetMetaGenerateNeedsAreCheckedFirst(t *testing.T) {
	f := newSendFixture(t)
	withExtras(f) // no registry signer
	if err := f.run(t, &scriptTerm{t: t}, "policy", "new", "p"); err != nil {
		t.Fatal(err)
	}
	term := &scriptTerm{t: t}
	err := f.run(t, term, "asset", "meta", "generate", "p.tok")
	if err == nil || !strings.Contains(err.Error(), "registry-signing") || term.asked != 0 {
		t.Fatalf("%v (asked %d)", err, term.asked)
	}
	if _, err := os.Stat(filepath.Join(f.dir, "p.tok.asset")); err == nil {
		t.Error("a record was created by a refused command")
	}
	// A field that is not one of the entry's, and a malformed --set, are refused before the workspace is opened.
	for _, a := range []string{"colour=red", "metaName", "metaName=a\nb"} {
		withRegistry(f, nil)
		if err := f.run(t, &scriptTerm{t: t}, "asset", "meta", "generate", "p.tok", "--set", a); err == nil {
			t.Errorf("--set %q accepted", a)
		}
	}
	if _, err := os.Stat(filepath.Join(f.dir, "p.tok.asset")); err == nil {
		t.Error("a record was created by a refused --set")
	}
}

// spec: SPO-12b-IF-001, SPO-12b-IF-002, SPO-12b-OUT-001, SPO-12b-OUT-003, SPO-12b-INV-001, SPO-12b-PRE-001
// check reports published, then behind, per property, with the verification of
// the registry's entry; "not found" is a normal result; offline the capability
// is absent with the reason and nothing is looked up.
func TestAssetMetaCheck(t *testing.T) {
	reg := &fakeRegistry{}
	f := newSendFixture(t)
	withRegistry(f, reg)
	run := func(args ...string) error { return f.run(t, &scriptTerm{t: t}, args...) }
	if err := run("policy", "new", "p"); err != nil {
		t.Fatal(err)
	}
	if err := run("asset", "meta", "generate", "p.tok", "--set", "metaName=Token", "--set", "metaDescription=D", "--set", "metaTicker=TOK", "--set", "metaDecimals=0"); err != nil {
		// first run creates, --set signs in the same run
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	subject := readRecord(t, f.dir, "p.tok").Get("subject")
	first, e1 := storedEntry(t, f.dir, subject)
	_ = first

	// Not found is a result, not an error, and the registry was asked for the record's subject.
	f.out.Reset()
	reg.err = ports.ErrTokenNotFound
	if err := run("asset", "meta", "check", "p.tok"); err != nil {
		t.Fatalf("not found: %v\n%s", err, f.out.String())
	}
	mustContain(t, f.out.String(), "not found", "Registry  registry.test", "Subject   "+subject, "not published yet")
	if len(reg.asked) != 1 || reg.asked[0] != subject {
		t.Errorf("asked %v", reg.asked)
	}

	// Published: the registry serves the record's sequence number.
	f.out.Reset()
	reg.err, reg.entry = nil, e1
	if err := run("asset", "meta", "check", "p.tok"); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	mustContain(t, f.out.String(), "Status    published (registry sequence 1)", "Verify    OK", "name", "registry Token | record matches", "ticker", "decimals")

	// The record moves on (sequence 2, another name): the registry is behind.
	f.out.Reset()
	if err := run("asset", "meta", "generate", "p.tok", "--set", "metaName=Token Two"); err != nil {
		t.Fatal(err)
	}
	f.out.Reset()
	if err := run("asset", "meta", "check", "p.tok"); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	mustContain(t, f.out.String(), "Status    behind (registry sequence 1)", "record differs: Token Two")

	// A subject alone has nothing to compare with.
	f.out.Reset()
	if err := run("asset", "meta", "check", subject); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	mustContain(t, f.out.String(), "not compared")

	// An entry that does not verify is an error, and is said so.
	bad := e1
	bad.Props = map[tokenmeta.Property]tokenmeta.Attested{}
	for k, v := range e1.Props {
		bad.Props[k] = v
	}
	n := bad.Props[tokenmeta.PropName]
	n.Value = tokenmeta.Text("Forged")
	bad.Props[tokenmeta.PropName] = n
	reg.entry = bad
	f.out.Reset()
	if err := run("asset", "meta", "check", "p.tok"); err == nil || !strings.Contains(f.out.String(), "Verify    FAILED") {
		t.Errorf("a forged entry: %v\n%s", err, f.out.String())
	}

	// A registry that cannot be reached is an error, never "not found".
	reg.err = errors.New("connection refused")
	if err := run("asset", "meta", "check", "p.tok"); err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("unreachable: %v", err)
	}

	// Offline: the capability is absent with its reason; nothing was asked.
	g := newSendFixture(t)
	withRegistry(g, nil)
	term := &scriptTerm{t: t}
	err := g.run(t, term, "asset", "meta", "check", "p.tok")
	if err == nil || !strings.Contains(err.Error(), "token-registry") || !strings.Contains(err.Error(), "offline mode makes no network request") || term.asked != 0 {
		t.Errorf("offline: %v", err)
	}
}

func TestPlainTextMakesAThirdPartysTextSafe(t *testing.T) {
	got := plainText("a\x1b[31mred\x07\nb", 100)
	if strings.ContainsAny(got, "\x1b\x07\n") || !strings.Contains(got, "red") {
		t.Errorf("%q", got)
	}
	if got := plainText(strings.Repeat("x", 300), 10); got != strings.Repeat("x", 10)+"..." {
		t.Errorf("%q", got)
	}
}
