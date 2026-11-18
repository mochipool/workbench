package workspace

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/keyfile"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func exporter(src, dst *memStore, g *fakeGPG, a *auditLog) ExportWorkspace {
	return ExportWorkspace{Source: src, SourceVault: src, Lister: src, Dest: dst, Encryptor: g, Decryptor: g, Auditor: a}
}

// An export without a password is refused before anything is read, written or
// audited: no signing key leaves the workspace in clear, and there is no option
// to say otherwise.
//
// spec: SPO-Xcustody-INV-001, SPO-Xcustody-OUT-003, SPO-Xcustody-PRE-001, SPO-Xcustody-PRE-003
func TestExportWithoutAPasswordIsRefused(t *testing.T) {
	src, _ := workspaceFixture(t)
	dst := newMem()
	audit := &auditLog{}
	ex := exporter(src, dst, &fakeGPG{}, audit)
	if _, err := ex.Run(context.Background(), ExportOptions{}); !errors.Is(err, ErrExportPasswordRequired) {
		t.Fatalf("got %v", err)
	}
	if len(dst.snapshot()) != 0 || len(audit.events) != 0 {
		t.Error("something was written or audited before the refusal")
	}
}

// The audit record is made before any secret is written, and a failing audit
// sink stops the owner.
//
// spec: SPO-Pfiles-SEC-001, SPO-Ckey-SEC-002
func TestExportAuditComesFirstAndFailsClosed(t *testing.T) {
	src, _ := workspaceFixture(t)
	dst := newMem()
	var seen []int
	audit := &auditLog{onRec: func() { seen = append(seen, len(dst.snapshot())) }}
	pw := sec("Str0ng-Passw0rd!-And-Long")
	if _, err := exporter(src, dst, &fakeGPG{}, audit).Run(context.Background(), ExportOptions{Password: pw, Owners: []string{"w"}}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0] != 0 {
		t.Errorf("destination held %v artefacts when the audit record was made", seen)
	}
	dst = newMem()
	failing := &auditLog{err: errors.New("disk full")}
	rep, err := exporter(src, dst, &fakeGPG{}, failing).Run(context.Background(), ExportOptions{Password: pw})
	if err != nil || rep.Failed() != 2 || len(dst.snapshot()) != 0 {
		t.Errorf("%v failed=%d written=%d", err, rep.Failed(), len(dst.snapshot()))
	}
	if _, err := (ExportWorkspace{Source: src, SourceVault: src, Lister: src, Dest: dst}).Run(context.Background(), ExportOptions{Password: pw}); !errors.Is(err, ErrNoAuditor) {
		t.Errorf("no auditor: %v", err)
	}
}

// Every signing key is written in upstream's encrypted form; the password is
// enforced strong; mnemonics have no encrypted form and are never written.
// The password is used as upstream's prompt would store it.
//
// spec: SPO-Ckey-INV-001, SPO-Ckey-OUT-001, SPO-Ckey-EXT-001, SPO-Pfiles-OUT-003, SPO-01protectKey-OUT-001, SPO-Xcustody-OUT-003, SPO-Xcustody-PRE-001, SPO-Xcustody-PRE-003
func TestExportEncryptsEverySigningKey(t *testing.T) {
	src, keys := workspaceFixture(t)
	g := &fakeGPG{}
	audit := &auditLog{}
	// Strong in upstream's sense but under 20 characters: refused as too short
	// (SPO-Xcustody-PRE-003).
	if _, err := exporter(src, newMem(), g, audit).Run(context.Background(), ExportOptions{Password: sec("Password1!")}); !errors.Is(err, ErrShortExportPassword) {
		t.Errorf("a 10-character strong password: %v", err)
	}
	if _, err := exporter(src, newMem(), g, audit).Run(context.Background(), ExportOptions{Password: sec("Abcdefghij-12345678!")}); err != nil {
		t.Errorf("a 20-character password: %v", err)
	}
	for _, weak := range []string{"short", "alllowercase-no-digit", "NoSpecial1234"} {
		if _, err := exporter(src, newMem(), g, audit).Run(context.Background(), ExportOptions{Password: sec(weak)}); !errors.Is(err, ErrWeakPassword) {
			t.Errorf("%q: %v", weak, err)
		}
	}
	dst := newMem()
	rep, err := exporter(src, dst, g, audit).Run(context.Background(), ExportOptions{Password: sec(`Abc\def-12345-and-long-enough`)})
	if err != nil || rep.Failed() != 0 {
		t.Fatalf("%v %+v", err, rep)
	}
	for _, r := range []ports.NamedRef{ref("w.payment", ports.AddrSKey), ref("w", ports.StakingSKey), ref("mypool", ports.NodeSKey)} {
		got := dst.snapshot()[r]
		info, cerr := keyfile.Classify([]byte(got))
		if cerr != nil || info.Form != keyfile.FormEncrypted {
			t.Errorf("%v is not in the encrypted form: %v", r, cerr)
		}
		if strings.Contains(got, keys["pay"].cbor[4:30]) {
			t.Errorf("%v holds plaintext key material", r)
		}
	}
	// encrypted with upstream's form of the password: Abcdef-12345-and-long-enough
	enc, _ := keyfile.ParseEncrypted([]byte(dst.snapshot()[ref("w.payment", ports.AddrSKey)]))
	if _, err := g.Decrypt(context.Background(), enc.EncrHex, sec("Abcdef-12345-and-long-enough")); err != nil {
		t.Errorf("the key does not open with the password as upstream stores it: %v", err)
	}
	if g.decrypts < 3 {
		t.Errorf("the encrypted keys were not verified (decrypts=%d)", g.decrypts)
	}
	// no secret of any other kind is written, and the report says why
	for r := range dst.snapshot() {
		if r.Kind.Secret() && !r.Kind.IsSigningKey() {
			t.Errorf("%v (a secret that is no signing key) was exported", r)
		}
	}
	if _, ok := dst.snapshot()[ref("w", ports.PaymentMnemonics)]; ok {
		t.Error("mnemonics were written")
	}
	foundSkip := false
	for _, o := range rep.Owners {
		for _, a := range o.Artefacts {
			if a.Ref.Kind == ports.PaymentMnemonics && a.Status == StatusSkipped {
				foundSkip = true
			}
		}
	}
	if !foundSkip {
		t.Error("the skipped mnemonics are not in the report")
	}
	for _, e := range audit.events {
		if !e.Protected || e.PlaintextKeys != 0 || e.Acknowledged {
			t.Errorf("event %+v", e)
		}
	}
}

// A key imported still-encrypted is never written back out.
//
// spec: SPO-Xcustody-OUT-003, SPO-Xcustody-INV-003
func TestExportNeverWritesAKeptEncryptedKey(t *testing.T) {
	src, keys := workspaceFixture(t)
	enc := encryptedOf(t, keys["cold"], "Str0ng-Passw0rd!-And-Long")
	src.put(ref("mypool", ports.NodeSKey), enc)
	// a record an older import made: no new import creates one
	mid := newMem()
	for r, b := range src.snapshot() {
		if OwnerOf(r) == "mypool" && r.Kind != ports.NodeSKey {
			mid.put(r, []byte(b))
		}
	}
	mid.put(ref("mypool.node", ports.UpstreamEncryptedSKey), enc)
	out := newMem()
	rep, err := exporter(mid, out, &fakeGPG{}, &auditLog{}).Run(context.Background(), ExportOptions{Owners: []string{"mypool"}, Password: sec("Str0ng-Passw0rd!-And-Long")})
	if err != nil || rep.Failed() != 0 {
		t.Fatalf("%v %+v", err, rep)
	}
	for r := range out.snapshot() {
		if r == ref("mypool", ports.NodeSKey) || r.Kind == ports.UpstreamEncryptedSKey {
			t.Errorf("%v was exported", r)
		}
	}
	skipped := false
	for _, o := range rep.Owners {
		for _, a := range o.Artefacts {
			skipped = skipped || (a.Ref.Kind == ports.UpstreamEncryptedSKey && a.Status == StatusSkipped && strings.Contains(a.Reason, "key convert"))
		}
	}
	if !skipped {
		t.Error("the report does not say the kept key was left out, and what to do")
	}
}

// Import, then export (encrypted), then import with the password again, is the
// identity on every artefact.
func TestImportExportImportRoundTrips(t *testing.T) {
	src, _ := workspaceFixture(t)
	mid, out, back := newMem(), newMem(), newMem()
	g := &fakeGPG{}
	if rep, err := importer(src, mid, g).Run(context.Background(), ImportOptions{}); err != nil || rep.Failed() != 0 {
		t.Fatalf("%v %+v", err, rep)
	}
	pw := "Str0ng-Passw0rd!-And-Long"
	if rep, err := exporter(mid, out, g, &auditLog{}).Run(context.Background(), ExportOptions{Password: sec(pw)}); err != nil || rep.Failed() != 0 {
		t.Fatalf("%v %+v", err, rep)
	}
	if rep, err := importer(out, back, g).Run(context.Background(), ImportOptions{Password: sec(pw)}); err != nil || rep.Failed() != 0 {
		t.Fatalf("%v %+v", err, rep)
	}
	a, b := mid.snapshot(), back.snapshot()
	for r, v := range a {
		if r.Kind.Secret() && !r.Kind.IsSigningKey() {
			continue // mnemonics are not exported
		}
		if strip(b[r]) != strip(v) { // the envelope is re-formatted by the decrypt
			t.Errorf("%v differs after the round trip:\n%s\n%s", r, v, b[r])
		}
	}
}

func strip(s string) string { return strings.Join(strings.Fields(s), "") }

// Keys of this program's own records are never exported.
func TestExportLeavesOwnRecordsOut(t *testing.T) {
	src, _ := workspaceFixture(t)
	src.put(ref("local", ports.PartyKeys), []byte("x"))
	dst := newMem()
	if _, err := exporter(src, dst, &fakeGPG{}, &auditLog{}).Run(context.Background(), ExportOptions{Password: sec("Str0ng-Passw0rd!-And-Long")}); err != nil {
		t.Fatal(err)
	}
	if _, ok := dst.snapshot()[ref("local", ports.PartyKeys)]; ok {
		t.Error("a party identity was exported")
	}
}

// An encrypted envelope that does not open again is never written.
//
// spec: SPO-01protectKey-INV-001, SPO-Ckey-INV-001
func TestExportNeverWritesAnUnverifiableEnvelope(t *testing.T) {
	src, _ := workspaceFixture(t)
	dst := newMem()
	ex := ExportWorkspace{Source: src, SourceVault: src, Lister: src, Dest: dst, Encryptor: &fakeGPG{}, Decryptor: brokenDecryptor{}, Auditor: &auditLog{}}
	rep, err := ex.Run(context.Background(), ExportOptions{Password: sec("Str0ng-Passw0rd!-And-Long")})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Failed() == 0 {
		t.Error("an unverifiable envelope did not fail the owner")
	}
	for r := range dst.snapshot() {
		if r.Kind.IsSigningKey() {
			t.Errorf("%v was written", r)
		}
	}
}

type brokenDecryptor struct{}

func (brokenDecryptor) Decrypt(context.Context, []byte, *ports.Secret) (*ports.Secret, error) {
	return sec("5820deadbeef"), nil
}

// labeledStore gives the readers of a store the label lookup of the label
// resolver, with a fixed table.
type labeledStore struct {
	*memStore
	labels map[string]string // identity name -> label
}

type labeledReader struct {
	ports.NamedReader
	labels map[string]string
}

func (r labeledReader) LabelOfIdentity(_ identity.OwnerKind, id string) (string, bool, error) {
	if n, ok := r.labels[id]; ok {
		return n, true, nil
	}
	return "", false, ports.ErrNotFound
}

func (s labeledStore) View(ctx context.Context, fn func(ports.NamedReader) error) error {
	return s.memStore.View(ctx, func(r ports.NamedReader) error { return fn(labeledReader{r, s.labels}) })
}

// A descriptor of the workspace refers to its owners, its reward account and the
// payer of an open registration by key hash; the export writes the labels back, so
// the upstream scripts read names: `<label>.payment` for the payment account of a
// wallet that has one. A reference whose owner has no label is left as it is.
//
// spec: SPO-Xidentity-INV-026
func TestExportWritesTheLabelsBackIntoADescriptor(t *testing.T) {
	src := newMem()
	stake := "key-hash:" + strings.Repeat("ab", 28)
	pay := "key-hash:" + strings.Repeat("cd", 28)
	ghost := "key-hash:" + strings.Repeat("ef", 28)
	src.put(ref("p", ports.PoolDescriptor), []byte(`{"poolName":"p","poolOwner":[{"ownerName":"`+stake+`","ownerWitness":"local"},{"ownerName":"`+ghost+`","ownerWitness":"external"}],"poolRewards":"`+stake+`","regWitness":{"id":1,"regPayName":"`+pay+`","txBody":{"type":"x","description":"","cborHex":"a0"},"witnesses":{"p.node":{"witness":{}}}}}`))
	ls := labeledStore{src, map[string]string{stake: "alice", pay: "alice"}}
	dst := newMem()
	ex := ExportWorkspace{Source: ls, SourceVault: src, Lister: src, Dest: dst, Encryptor: &fakeGPG{}, Decryptor: &fakeGPG{}, Auditor: &auditLog{}}
	if _, err := ex.Run(context.Background(), ExportOptions{Password: sec("Str0ng-Passw0rd!-And-Long")}); err != nil {
		t.Fatal(err)
	}
	got := string(dst.files[ref("p", ports.PoolDescriptor)])
	for _, want := range []string{`"ownerName":"alice"`, `"poolRewards": "alice"`, `"regPayName":"alice.payment"`, ghost} {
		if !strings.Contains(strings.ReplaceAll(got, ` `, ``), strings.ReplaceAll(want, ` `, ``)) {
			t.Errorf("the exported descriptor lacks %s:\n%s", want, got)
		}
	}
	if strings.Contains(got, stake) || strings.Contains(got, pay) {
		t.Errorf("an identity was exported where a label exists:\n%s", got)
	}
}
