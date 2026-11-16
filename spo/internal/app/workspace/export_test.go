package workspace

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/keyfile"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func exporter(src, dst *memStore, g *fakeGPG, a *auditLog) ExportWorkspace {
	return ExportWorkspace{Source: src, SourceVault: src, Lister: src, Dest: dst, Encryptor: g, Decryptor: g, Auditor: a}
}

// Plaintext export needs the explicit acknowledgement, is audited before the
// first write, and returns the files verbatim.
//
// spec: SPO-Pfiles-SEC-002, SPO-Pfiles-INV-003, SPO-Ckey-SEC-002, SPO-01protectKey-SEC-001
func TestExportPlaintextNeedsAcknowledgementAndIsAudited(t *testing.T) {
	src, _ := workspaceFixture(t)
	dst := newMem()
	audit := &auditLog{}
	ex := exporter(src, dst, &fakeGPG{}, audit)
	if _, err := ex.Run(context.Background(), ExportOptions{}); !errors.Is(err, ErrPlaintextNotAcknowledged) {
		t.Fatalf("got %v", err)
	}
	if len(dst.snapshot()) != 0 || len(audit.events) != 0 {
		t.Error("something was written or audited before the refusal")
	}
	written := 0
	audit.onRec = func() { written = len(dst.snapshot()) }
	rep, err := ex.Run(context.Background(), ExportOptions{PlaintextAcknowledged: true})
	if err != nil || rep.Failed() != 0 {
		t.Fatalf("%v %+v", err, rep)
	}
	_ = written
	if len(audit.events) != 2 {
		t.Fatalf("audit events: %+v", audit.events)
	}
	for _, e := range audit.events {
		if !e.Acknowledged || e.Protected || e.PlaintextKeys == 0 {
			t.Errorf("event %+v", e)
		}
	}
	before := src.snapshot()
	for r, want := range before {
		if dst.snapshot()[r] != want {
			t.Errorf("%v differs after export", r)
		}
	}
}

// The audit record is made before any secret is written, and a failing audit
// sink stops the owner.
func TestExportAuditComesFirstAndFailsClosed(t *testing.T) {
	src, _ := workspaceFixture(t)
	dst := newMem()
	var seen []int
	audit := &auditLog{onRec: func() { seen = append(seen, len(dst.snapshot())) }}
	if _, err := exporter(src, dst, &fakeGPG{}, audit).Run(context.Background(), ExportOptions{PlaintextAcknowledged: true, Owners: []string{"w"}}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0] != 0 {
		t.Errorf("destination held %v artefacts when the audit record was made", seen)
	}
	dst = newMem()
	failing := &auditLog{err: errors.New("disk full")}
	rep, err := exporter(src, dst, &fakeGPG{}, failing).Run(context.Background(), ExportOptions{PlaintextAcknowledged: true})
	if err != nil || rep.Failed() != 2 || len(dst.snapshot()) != 0 {
		t.Errorf("%v failed=%d written=%d", err, rep.Failed(), len(dst.snapshot()))
	}
	if _, err := (ExportWorkspace{Source: src, SourceVault: src, Lister: src, Dest: dst}).Run(context.Background(), ExportOptions{PlaintextAcknowledged: true}); !errors.Is(err, ErrNoAuditor) {
		t.Errorf("no auditor: %v", err)
	}
}

// With a password every signing key is written in upstream's encrypted form;
// the password is enforced strong; mnemonics are left out unless
// acknowledged. The password is used as upstream's prompt would store it.
//
// spec: SPO-Ckey-INV-001, SPO-Ckey-OUT-001, SPO-Ckey-EXT-001, SPO-Pfiles-OUT-003, SPO-Pfiles-OUT-005, SPO-01protectKey-OUT-001
func TestExportProtectedByDefaultWithAPassword(t *testing.T) {
	src, keys := workspaceFixture(t)
	g := &fakeGPG{}
	audit := &auditLog{}
	for _, weak := range []string{"short", "alllowercase-no-digit", "NoSpecial1234"} {
		if _, err := exporter(src, newMem(), g, audit).Run(context.Background(), ExportOptions{Password: sec(weak)}); !errors.Is(err, ErrWeakPassword) {
			t.Errorf("%q: %v", weak, err)
		}
	}
	dst := newMem()
	rep, err := exporter(src, dst, g, audit).Run(context.Background(), ExportOptions{Password: sec(`Abc\def-12345`)})
	if err != nil || rep.Failed() != 0 {
		t.Fatalf("%v %+v", err, rep)
	}
	for _, r := range []ports.Ref{ref("w.payment", ports.AddrSKey), ref("w", ports.StakingSKey), ref("mypool", ports.NodeSKey)} {
		got := dst.snapshot()[r]
		info, cerr := keyfile.Classify([]byte(got))
		if cerr != nil || info.Form != keyfile.FormEncrypted {
			t.Errorf("%v is not in the encrypted form: %v", r, cerr)
		}
		if strings.Contains(got, keys["pay"].cbor[4:30]) {
			t.Errorf("%v holds plaintext key material", r)
		}
	}
	// encrypted with upstream's form of the password: Abcdef-12345
	enc, _ := keyfile.ParseEncrypted([]byte(dst.snapshot()[ref("w.payment", ports.AddrSKey)]))
	if _, err := g.Decrypt(context.Background(), enc.EncrHex, sec("Abcdef-12345")); err != nil {
		t.Errorf("the key does not open with the password as upstream stores it: %v", err)
	}
	if g.decrypts < 3 {
		t.Errorf("the encrypted keys were not verified (decrypts=%d)", g.decrypts)
	}
	// the KES key (a signing key) is protected too, the mnemonics have no
	// protected form and are left out
	if _, ok := dst.snapshot()[ref("w", ports.PaymentMnemonics)]; ok {
		t.Error("mnemonics were written without PlaintextAcknowledged")
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
		if !e.Protected || e.PlaintextKeys != 0 {
			t.Errorf("event %+v", e)
		}
	}
	// both: keys protected, mnemonics in clear
	dst = newMem()
	if _, err := exporter(src, dst, g, audit).Run(context.Background(), ExportOptions{Password: sec("Str0ng-Passw0rd!"), PlaintextAcknowledged: true}); err != nil {
		t.Fatal(err)
	}
	if _, ok := dst.snapshot()[ref("w", ports.PaymentMnemonics)]; !ok {
		t.Error("acknowledged mnemonics were not written")
	}
}

// A key imported still-encrypted is written back as it was.
func TestExportWritesKeptEncryptedKeysBack(t *testing.T) {
	src, keys := workspaceFixture(t)
	enc := encryptedOf(t, keys["cold"], "Str0ng-Passw0rd!")
	src.put(ref("mypool", ports.NodeSKey), enc)
	mid := newMem()
	if rep, err := importer(src, mid, &fakeGPG{}).Run(context.Background(), ImportOptions{Owners: []string{"mypool"}, KeepEncrypted: true}); err != nil || rep.Failed() != 0 {
		t.Fatalf("%v %+v", err, rep)
	}
	out := newMem()
	rep, err := exporter(mid, out, &fakeGPG{}, &auditLog{}).Run(context.Background(), ExportOptions{Owners: []string{"mypool"}, PlaintextAcknowledged: true})
	if err != nil || rep.Failed() != 0 {
		t.Fatalf("%v %+v", err, rep)
	}
	if out.snapshot()[ref("mypool", ports.NodeSKey)] != string(enc) {
		t.Error("the kept key was not written back byte for byte")
	}
}

// Import then export (plaintext) is the identity.
func TestImportThenExportRoundTrips(t *testing.T) {
	src, _ := workspaceFixture(t)
	mid, out := newMem(), newMem()
	if rep, err := importer(src, mid, &fakeGPG{}).Run(context.Background(), ImportOptions{}); err != nil || rep.Failed() != 0 {
		t.Fatalf("%v %+v", err, rep)
	}
	if rep, err := exporter(mid, out, &fakeGPG{}, &auditLog{}).Run(context.Background(), ExportOptions{PlaintextAcknowledged: true}); err != nil || rep.Failed() != 0 {
		t.Fatalf("%v %+v", err, rep)
	}
	a, b := src.snapshot(), out.snapshot()
	if len(a) != len(b) {
		t.Fatalf("%d != %d artefacts", len(a), len(b))
	}
	for r, v := range a {
		if b[r] != v {
			t.Errorf("%v differs", r)
		}
	}
}

// Keys of this program's own records are never exported.
func TestExportLeavesOwnRecordsOut(t *testing.T) {
	src, _ := workspaceFixture(t)
	src.put(ref("local", ports.PartyKeys), []byte("x"))
	dst := newMem()
	if _, err := exporter(src, dst, &fakeGPG{}, &auditLog{}).Run(context.Background(), ExportOptions{PlaintextAcknowledged: true}); err != nil {
		t.Fatal(err)
	}
	if _, ok := dst.snapshot()[ref("local", ports.PartyKeys)]; ok {
		t.Error("a party identity was exported")
	}
}

// 01_protectKey on the upstream-layout store, and its meaninglessness on the
// sealed one.
//
// spec: SPO-01protectKey-PRE-003, SPO-01protectKey-PRE-004, SPO-01protectKey-EXT-001, SPO-01protectKey-EXT-002, SPO-01protectKey-OUT-001, SPO-01protectKey-OUT-002, SPO-01protectKey-INV-001, SPO-01protectKey-PR-002, SPO-01protectKey-PR-005, SPO-Ckey-PRE-005, SPO-Ckey-PRE-002
func TestProtectAndUnprotectKey(t *testing.T) {
	s, keys := workspaceFixture(t)
	g := &fakeGPG{}
	ctx := context.Background()
	r := ref("w.payment", ports.AddrSKey)
	prot := ProtectKey{Store: s, Vault: s, Encryptor: g, Decryptor: g}
	if err := (ProtectKey{Store: s, Vault: s, Encryptor: g, Sealed: true}).Run(ctx, r, sec("Str0ng-Passw0rd!")); !errors.Is(err, ErrSealedStore) {
		t.Errorf("sealed: %v", err)
	}
	if err := prot.Run(ctx, r, sec("weak")); !errors.Is(err, ErrWeakPassword) {
		t.Errorf("weak: %v", err)
	}
	if err := prot.Run(ctx, ref("w.payment", ports.AddrVKey), sec("Str0ng-Passw0rd!")); !errors.Is(err, ErrNotSigningKey) {
		t.Errorf("not a key: %v", err)
	}
	if err := prot.Run(ctx, r, sec("Str0ng-Passw0rd!")); err != nil {
		t.Fatal(err)
	}
	if g.decrypts != 1 {
		t.Errorf("the new envelope was not verified before the file was replaced")
	}
	if info, _ := keyfile.Classify(s.files[r]); info.Form != keyfile.FormEncrypted {
		t.Fatal("the key was not encrypted")
	}
	if err := prot.Run(ctx, r, sec("Str0ng-Passw0rd!")); !errors.Is(err, ErrAlreadyEncrypted) {
		t.Errorf("enc of an encrypted key: %v", err)
	}
	audit := &auditLog{}
	un := UnprotectKey{Store: s, Vault: s, Decryptor: g, Auditor: audit}
	if err := un.Run(ctx, r, sec("Str0ng-Passw0rd!"), false); !errors.Is(err, ErrPlaintextNotAcknowledged) {
		t.Errorf("unacknowledged: %v", err)
	}
	if err := un.Run(ctx, r, sec("Wrong-Passw0rd!x"), true); !errors.Is(err, ports.ErrWrongPassphrase) {
		t.Errorf("wrong password: %v", err)
	}
	if g.decrypts != 2 { // the verification, plus one try with a one-candidate password
		t.Errorf("a wrong password must not be retried: %d decrypts", g.decrypts)
	}
	if err := un.Run(ctx, r, sec("Str0ng-Passw0rd!"), true); err != nil {
		t.Fatal(err)
	}
	got := string(s.files[r])
	want := string(keyfile.AppendPlainEnvelope(nil, "PaymentSigningKeyShelley_ed25519", "Payment Signing Key", []byte(keys["pay"].cbor), 0, "  "))
	if got != want {
		t.Errorf("decrypted file:\n%s\nwant (jq formatting, two-space indent)\n%s", got, want)
	}
	if len(audit.events) != 1 || audit.events[0].Operation != "unprotect-key" {
		t.Errorf("audit: %+v", audit.events)
	}
	if err := un.Run(ctx, r, sec("Str0ng-Passw0rd!"), true); !errors.Is(err, ErrNotEncrypted) {
		t.Errorf("dec of a plain key: %v", err)
	}
	if err := (UnprotectKey{Store: s, Vault: s, Decryptor: g, Auditor: audit, Sealed: true}).Run(ctx, r, sec("x"), true); !errors.Is(err, ErrSealedStore) {
		t.Errorf("sealed: %v", err)
	}
}

// A key file that is missing, not a signing key, or whose replacement fails
// is never half-written; an encrypted envelope that does not open again is
// never written either.
//
// spec: SPO-01protectKey-PRE-001, SPO-01protectKey-PRE-005, SPO-01protectKey-PRE-006, SPO-01protectKey-INV-001, SPO-01protectKey-SEC-007, SPO-Ckey-PRE-008
func TestProtectKeyNeverLeavesAHalfWrittenFile(t *testing.T) {
	s, _ := workspaceFixture(t)
	g := &fakeGPG{}
	ctx := context.Background()
	prot := ProtectKey{Store: s, Vault: s, Encryptor: g, Decryptor: g}
	if err := prot.Run(ctx, ref("nobody", ports.AddrSKey), sec("Str0ng-Passw0rd!")); !errors.Is(err, ports.ErrNotFound) {
		t.Errorf("a missing key file: %v", err)
	}
	s.put(ref("v", ports.AddrSKey), []byte(`{"type":"PaymentVerificationKeyShelley_ed25519","description":"x","cborHex":"5820aa"}`))
	if err := prot.Run(ctx, ref("v", ports.AddrSKey), sec("Str0ng-Passw0rd!")); !errors.Is(err, ErrNotAKeyFile) {
		t.Errorf("a file that is no signing key: %v", err)
	}
	r := ref("w.payment", ports.AddrSKey)
	orig := string(s.files[r])
	// the write fails: the original stays
	s.failUpdate = errors.New("disk full")
	if err := prot.Run(ctx, r, sec("Str0ng-Passw0rd!")); err == nil {
		t.Error("a failed write was not reported")
	}
	s.failUpdate = nil
	if string(s.files[r]) != orig {
		t.Error("the key file changed although the write failed")
	}
	// the new envelope does not open again: nothing is written
	bad := ProtectKey{Store: s, Vault: s, Encryptor: g, Decryptor: brokenDecryptor{}}
	if err := bad.Run(ctx, r, sec("Str0ng-Passw0rd!")); !errors.Is(err, ErrVerifyFailed) {
		t.Errorf("an unverifiable envelope: %v", err)
	}
	if string(s.files[r]) != orig {
		t.Error("an unverified envelope replaced the key")
	}
	// decrypting: a failed write is reported too (upstream reports success)
	if err := prot.Run(ctx, r, sec("Str0ng-Passw0rd!")); err != nil {
		t.Fatal(err)
	}
	encrypted := string(s.files[r])
	s.failUpdate = errors.New("disk full")
	un := UnprotectKey{Store: s, Vault: s, Decryptor: g, Auditor: &auditLog{}}
	if err := un.Run(ctx, r, sec("Str0ng-Passw0rd!"), true); err == nil {
		t.Error("a failed write of the decrypted key was not reported")
	}
	s.failUpdate = nil
	if string(s.files[r]) != encrypted {
		t.Error("the encrypted key file changed although the write failed")
	}
}

type brokenDecryptor struct{}

func (brokenDecryptor) Decrypt(context.Context, []byte, *ports.Secret) (*ports.Secret, error) {
	return sec("5820deadbeef"), nil
}
