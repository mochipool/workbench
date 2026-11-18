package sqlitestore

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/unlock"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// A stand-in authenticator in memory: a credential id starts with the id byte of
// the authenticator that made it, and the hmac-secret output is HMAC-SHA-256 of
// the salt under a secret that only that authenticator and credential give. It
// stands in for the libfido2 tools at the port; the e2e tests of cmd/spo drive
// the same flows through fido2cli and fakefido.
type fakeAuth struct {
	id   byte
	seed string
	pin  string
}

type fakeSource struct {
	auths       map[string]*fakeAuth
	credProtect int
	profile     *ports.FactorProfile
	enrols      int
	asserts     int
	profiles    int
	touch       ports.TouchProbe
	pinChecks   int
	// corruptNext, when set, makes the output for the NEXT salt of an assertion
	// wrong (a faulty authenticator that answers the first salt rightly and the
	// second wrongly); it counts down and is cleared at zero.
	corruptNext int
	// corruptAll makes every output wrong.
	corruptAll bool
	// corruptOnce makes the primary output of the next assertion wrong, once.
	corruptOnce bool
}

func newFake() *fakeSource {
	return &fakeSource{credProtect: 3, auths: map[string]*fakeAuth{
		"devA": {1, "seed-a", "1234"},
		"devB": {2, "seed-b", "5678"},
	}}
}

func (f *fakeSource) auth(dev string) (*fakeAuth, error) {
	a, ok := f.auths[dev]
	if !ok {
		return nil, ports.ErrFactorNoDevice
	}
	return a, nil
}

func (f *fakeSource) Profile(ctx context.Context, dev string) (ports.FactorProfile, error) {
	f.profiles++
	if _, err := f.auth(dev); err != nil {
		return ports.FactorProfile{}, err
	}
	if f.profile != nil {
		return *f.profile, nil
	}
	return ports.FactorProfile{HMACSecret: true, TwoSalts: true, CredProtect3: true, UserVerification: true, CTAP21: true, ClientPIN: true}, nil
}

func (a *fakeAuth) checkPIN(pin *secret.Buffer) error {
	if pin == nil {
		return nil
	}
	var got string
	pin.Use(func(b []byte) error { got = string(b); return nil })
	if got != a.pin {
		return ports.ErrFactorPIN
	}
	return nil
}

func (a *fakeAuth) secretFor(cred []byte) []byte {
	m := hmac.New(sha256.New, []byte(a.seed))
	m.Write(cred)
	return m.Sum(nil)
}

func (f *fakeSource) Enrol(ctx context.Context, req ports.EnrolRequest) (ports.Enrolment, error) {
	f.enrols++
	a, err := f.auth(req.Device)
	if err != nil {
		return ports.Enrolment{}, err
	}
	if err := a.checkPIN(req.PIN); err != nil {
		return ports.Enrolment{}, err
	}
	h := sha256.Sum256([]byte(a.seed + req.RPID + string(rune(f.enrols))))
	cred := append([]byte{a.id}, h[:31]...)
	return ports.Enrolment{CredentialID: cred, CredProtect: f.credProtect, Versions: []string{"FIDO_2_1"}, FactorID: ports.FactorIDOf(cred), Touch: f.touch}, nil
}

// CheckPIN is the PIN check without a credential (ports.PINChecker).
func (f *fakeSource) CheckPIN(ctx context.Context, dev string, pin *secret.Buffer) error {
	f.pinChecks++
	a, err := f.auth(dev)
	if err != nil {
		return err
	}
	return a.checkPIN(pin)
}

func (f *fakeSource) Assert(ctx context.Context, req ports.AssertRequest) (ports.Assertion, error) {
	f.asserts++
	a, err := f.auth(req.Device)
	if err != nil {
		return ports.Assertion{}, err
	}
	if len(req.CredentialID) == 0 || req.CredentialID[0] != a.id {
		return ports.Assertion{}, ports.ErrFactorNoCredential
	}
	if err := a.checkPIN(req.PIN); err != nil {
		return ports.Assertion{}, err
	}
	m := hmac.New(sha256.New, a.secretFor(req.CredentialID))
	m.Write([]byte(req.RPID))
	m.Write(req.Salt)
	o1 := m.Sum(nil)
	if f.corruptAll || f.corruptOnce {
		o1[0] ^= 0xff
		f.corruptOnce = false
	}
	out := ports.Assertion{Output: secret.Take(o1), UP: true, UV: true}
	if req.NextSalt != nil {
		m2 := hmac.New(sha256.New, a.secretFor(req.CredentialID))
		m2.Write([]byte(req.RPID))
		m2.Write(req.NextSalt)
		out.NextOutput = secret.Take(m2.Sum(nil))
		if f.corruptNext > 0 {
			f.corruptNext--
			bad := m2.Sum(nil)
			bad[0] ^= 0xff
			out.NextOutput = secret.Take(bad)
		}
	}
	return out, nil
}

func pinOf(p string) func(context.Context) (*secret.Buffer, error) {
	return func(context.Context) (*secret.Buffer, error) { return secret.Take([]byte(p)), nil }
}

func (f *fakeSource) inputs(dev, pin string) FactorInputs {
	return FactorInputs{Source: f, Device: dev, PIN: pinOf(pin)}
}

// hardwareWS makes a workspace under the hardware policy: a daily authenticator
// (devA) in a fido2-hmac slot and a recovery composite of the recovery key AND a
// second authenticator (devB). It holds one secret record.
func hardwareWS(t *testing.T) (path string, f *fakeSource, recovery string) {
	t.Helper()
	s, path, rec0 := scratch(t)
	putSecret(t, s, skey0, "the-signing-key")
	f = newFake()
	fa, _, err := EnrolFactor(ctx, f.inputs("devA", "1234"), s.ws, nil)
	if err != nil {
		t.Fatal(err)
	}
	fb, _, err := EnrolFactor(ctx, f.inputs("devB", "5678"), s.ws, nil)
	if err != nil {
		t.Fatal(err)
	}
	text, _, err := s.Rotate(ctx, RotatePlan{Policy: unlock.Hardware, Proof: presentStd(t, s, rec0), Slots: []SlotPlan{
		{Kind: seal.SlotFIDO2HMAC, Factors: []FactorPlan{fa}},
		{Kind: seal.SlotComposite, Factors: []FactorPlan{{Params: seal.FactorParams{Kind: seal.FactorRecovery}}, fb}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	text.Use(func(b []byte) error { recovery = string(b); return nil })
	text.Destroy()
	s.Close()
	return path, f, recovery
}

// presentStd presents the recovery key of a standard workspace and returns the
// proof a rotation needs.
func presentStd(t *testing.T, s *Store, rec string) *RecoveryProof {
	t.Helper()
	text := secret.Take([]byte(rec))
	defer text.Destroy()
	raw, err := seal.DecodeRecoveryKey(text)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Destroy()
	p, err := s.PresentRecovery(ctx, FactorInputs{Recovery: func(context.Context) (*secret.Buffer, error) {
		return secret.Take(rawBytes(raw)), nil
	}})
	if err != nil {
		t.Fatalf("presenting the recovery key: %v", err)
	}
	return p
}

func rawBytes(b *secret.Buffer) []byte {
	var out []byte
	b.Use(func(x []byte) error { out = append([]byte(nil), x...); return nil })
	return out
}

// presentHW presents the recovery composite of a hardware workspace: the recovery
// key and the second authenticator.
func presentHW(t *testing.T, s *Store, f *fakeSource, rec string) *RecoveryProof {
	t.Helper()
	raw, err := seal.DecodeRecoveryKey(secret.Take([]byte(rec)))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Destroy()
	in := f.inputs("devB", "5678")
	in.Recovery = func(context.Context) (*secret.Buffer, error) { return secret.Take(rawBytes(raw)), nil }
	p, err := s.PresentRecovery(ctx, in)
	if err != nil {
		t.Fatalf("presenting the recovery composite: %v", err)
	}
	return p
}

func openHW(path string, f *fakeSource, dev, pin string) (*Store, error) {
	return OpenWithFactors(path, f.inputs(dev, pin), OpenOptions{})
}

func exists(p string) bool { _, err := os.Lstat(p); return err == nil }

func cloneDB(t *testing.T, src string) string {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "ws.db")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// spec: SPO-Xunlock-INV-004
func TestInitMakesAFormat3WorkspaceUnderStandard(t *testing.T) {
	s, _, _ := scratch(t)
	if p, err := s.Policy(ctx); err != nil || p != unlock.Standard {
		t.Fatalf("policy %q %v", p, err)
	}
	infos, err := s.Slots(ctx)
	if err != nil || len(infos) != 2 {
		t.Fatalf("%v %d", err, len(infos))
	}
	if infos[0].Legacy || infos[1].Legacy || len(infos[0].RecoveryPubKeyHash) != 32 || !bytes.Equal(infos[0].RecoveryPubKeyHash, infos[1].RecoveryPubKeyHash) {
		t.Errorf("slots do not bind one recovery public key hash: %+v", infos)
	}
	var f int
	s.db.QueryRow(`SELECT format_version FROM meta`).Scan(&f)
	if uint64(f) != seal.StoreFormat {
		t.Errorf("format %d", f)
	}
}

func format2Copy(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "legacy-v2", "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "ws.db")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The opener refuses format 2 before deriving any key, naming the command.
//
// spec: SPO-Xunlock-PRE-022
func TestOpenerRefusesFormat2BeforeDerivingAnyKey(t *testing.T) {
	p := format2Copy(t)
	before := readAll(t, p)
	called := false
	beforeUnlock = func() { called = true }
	defer func() { beforeUnlock = nil }()
	_, err := Open(p, legacyPW())
	if !errors.Is(err, ErrFormat2) {
		t.Fatalf("%v", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("spo workspace migrate")) {
		t.Errorf("the refusal does not name the command: %v", err)
	}
	if called {
		t.Error("a key was derived before the refusal")
	}
	if _, err := OpenWithFactors(p, newFake().inputs("devA", "1234"), OpenOptions{}); !errors.Is(err, ErrFormat2) {
		t.Errorf("OpenWithFactors: %v", err)
	}
	if !bytes.Equal(before, readAll(t, p)) {
		t.Error("the refused file changed")
	}
}

// spec: SPO-Xunlock-OUT-008
func TestMigrate3FromFormat2(t *testing.T) {
	p := format2Copy(t)
	old, err := OpenFormat2(p, legacyPW())
	if err != nil {
		t.Fatal(err)
	}
	before := ids(t, old)
	rows := count(t, old, "audit")
	old.SetColdSource(coldPass("a cold sub-key passphrase")) // the fixture holds a pool cold key
	rep, err := old.Migrate3(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	old.Close()
	if filepath.Base(rep.Backup) != "ws.db.pre-migrate-v2" {
		t.Errorf("backup %s", rep.Backup)
	}
	st, err := os.Stat(rep.Backup)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("backup: %v %v", st, err)
	}
	if b, err := OpenFormat2(rep.Backup, legacyPW()); err != nil {
		t.Errorf("the backup is not the old format 2 file: %v", err)
	} else {
		b.Close()
	}
	s, err := Open(p, legacyPW())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if pol, _ := s.Policy(ctx); pol != unlock.Standard {
		t.Errorf("policy %q", pol)
	}
	infos, _ := s.Slots(ctx)
	if len(infos) < 2 {
		t.Fatalf("%d slots", len(infos))
	}
	for _, i := range infos {
		if !i.Legacy {
			t.Errorf("slot %x is not legacy: existing slots keep their meaning", i.ID)
		}
	}
	if err := s.Verify(ctx); err != nil {
		t.Errorf("the audit chain does not verify after the migration: %v", err)
	}
	if got := count(t, s, "audit"); got != rows+2 { // an update row that seals the cold key, and the migration row
		t.Errorf("audit rows %d -> %d", rows, got)
	}
	after := ids(t, s)
	for id, ct := range before {
		if after[id] == ct {
			continue
		}
		// a format 3 migration re-seals no record, except a signing key whose identity
		// has a cold role: that one is sealed in the cold form
		var kind string
		var wrapped []byte
		if err := s.db.QueryRow(`SELECT kind, wrapped_key FROM records WHERE hex(id) = ?`, id).Scan(&kind, &wrapped); err != nil {
			t.Fatal(err)
		}
		if kind != "node.skey" || len(wrapped) == 72 {
			t.Errorf("record %s (%s) was re-sealed; a format 3 migration re-seals only cold-role keys, and into the cold form", id[:8], kind)
		}
	}
	// A second migration has nothing to do, and a format 3 file is not opened as format 2.
	if _, err := OpenFormat2(p, legacyPW()); !errors.Is(err, ErrNotLegacy) {
		t.Errorf("%v", err)
	}
	// Legacy slots stay usable and the table is standard: a passphrase added now is
	// legacy too (no recovery public key exists to bind), a FIDO2 slot is refused
	// until a rekey binds one.
	if _, err := s.AddPassphraseSlot(ctx, passphrase("second")); err != nil {
		t.Fatal(err)
	}
	fa, _, err := EnrolFactor(ctx, newFake().inputs("devA", "1234"), s.ws, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddFactorSlot(ctx, []FactorPlan{fa}); !errors.Is(err, ErrUseRekey) {
		t.Errorf("a FIDO2 slot in a table of legacy slots: %v", err)
	}
	presentLegacyRecoveryForTest(t, s)
	// the migrated cold key has no recovery wrap (the legacy slots bind no recovery
	// hash); the rekey binds one, so it adds the wrap and needs the cold factor
	s.SetColdSource(coldPass("a cold sub-key passphrase"))
	text, err := s.Rekey(ctx, []Credential{PassphraseCredential(passphrase("after-rekey"))})
	if err != nil {
		t.Fatal(err)
	}
	text.Destroy()
	infos, _ = s.Slots(ctx)
	for _, i := range infos {
		if i.Legacy {
			t.Error("a rekey leaves a legacy slot")
		}
	}
	fa, _, _ = EnrolFactor(ctx, newFake().inputs("devA", "1234"), s.ws, nil)
	if _, err := s.AddFactorSlot(ctx, []FactorPlan{fa}); err != nil {
		t.Errorf("a FIDO2 slot after the rekey: %v", err)
	}
}

// spec: SPO-Xunlock-OUT-008
func TestMigrate3IsOneTransaction(t *testing.T) {
	p := format2Copy(t)
	s, err := OpenFormat2(p, legacyPW())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	migrate3Hook = func() error { return errors.New("injected") }
	defer func() { migrate3Hook = nil }()
	var v1, f1 int
	s.db.QueryRow(`SELECT version FROM schema_version`).Scan(&v1)
	s.db.QueryRow(`SELECT format_version FROM meta`).Scan(&f1)
	rows := count(t, s, "audit")
	if _, err := s.Migrate3(ctx, ""); err == nil {
		t.Fatal("an injected failure did not fail the migration")
	}
	var v2, f2 int
	s.db.QueryRow(`SELECT version FROM schema_version`).Scan(&v2)
	s.db.QueryRow(`SELECT format_version FROM meta`).Scan(&f2)
	if v1 != v2 || f1 != f2 || count(t, s, "audit") != rows {
		t.Errorf("a failed migration changed the file: schema %d->%d format %d->%d", v1, v2, f1, f2)
	}
	if hasCol, _ := hasColumn(ctx, s.db, "keyslots", "factors"); hasCol {
		t.Error("the new slot columns exist after a failed migration")
	}
}

// Opening through a fido2-hmac slot of a standard workspace, the capability
// check before any prompt, the wrong device and the wrong PIN.
//
// spec: SPO-Xunlock-OUT-009
func TestOpenThroughAFido2Slot(t *testing.T) {
	s, path, _ := scratch(t)
	f := newFake()
	fa, _, err := EnrolFactor(ctx, f.inputs("devA", "1234"), s.ws, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddFactorSlot(ctx, []FactorPlan{fa}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	h, err := openHW(path, f, "devA", "1234")
	if err != nil {
		t.Fatal(err)
	}
	h.Close()
	// another authenticator holds no credential of this slot
	if _, err := openHW(path, f, "devB", "5678"); !errors.Is(err, ErrNoFactorSlot) {
		t.Errorf("wrong authenticator: %v", err)
	}
	// a wrong PIN stops the open at once (no retry through another slot)
	if _, err := openHW(path, f, "devA", "0000"); !errors.Is(err, ports.ErrFactorPIN) {
		t.Errorf("wrong PIN: %v", err)
	}
	// a source without a capability is refused before the PIN is asked
	f.profile = &ports.FactorProfile{HMACSecret: true}
	asked := false
	in := f.inputs("devA", "1234")
	in.PIN = func(context.Context) (*secret.Buffer, error) { asked = true; return secret.Take([]byte("1234")), nil }
	asserts := f.asserts
	if _, err := OpenWithFactors(path, in, OpenOptions{}); !errors.Is(err, ports.ErrFactorCapability) {
		t.Errorf("a source that lacks credProtect 3: %v", err)
	}
	if asked || f.asserts != asserts {
		t.Error("the PIN was asked or the authenticator touched before the capability check")
	}
}

// A workspace under the hardware policy: nothing opens from a passphrase alone or
// from the recovery key alone; the daily authenticator and the recovery composite
// open it; every payload was re-encrypted by the rotation that made it.
//
// spec: SPO-Xunlock-PRE-023, SPO-Xunlock-OUT-010
func TestHardwareWorkspaceOpensOnlyThroughHardware(t *testing.T) {
	s0, p0, _ := scratch(t)
	putSecret(t, s0, skey0, "the-signing-key")
	var oldCT, oldWK []byte
	s0.db.QueryRow(`SELECT ciphertext, wrapped_key FROM records WHERE kind = ?`, string(skey0.Kind)).Scan(&oldCT, &oldWK)
	s0.Close()
	_ = p0
	path, f, rec := hardwareWS(t)
	if pol := func() unlock.Policy {
		s, err := openHW(path, f, "devA", "1234")
		if err != nil {
			t.Fatal(err)
			return ""
		}
		defer s.Close()
		p, _ := s.Policy(ctx)
		return p
	}(); pol != unlock.Hardware {
		t.Fatalf("policy %q", pol)
	}
	if _, err := Open(path, pw()); !errors.Is(err, ErrWrongCredential) {
		t.Errorf("a passphrase alone: %v", err)
	}
	if _, err := OpenWithRecovery(path, secret.Take([]byte(rec))); !errors.Is(err, ErrWrongCredential) {
		t.Errorf("the recovery key alone: %v", err)
	}
	// the recovery composite: the recovery key AND the second authenticator
	raw, err := seal.DecodeRecoveryKey(secret.Take([]byte(rec)))
	if err != nil {
		t.Fatal(err)
	}
	in := f.inputs("devB", "5678")
	in.Recovery = func(context.Context) (*secret.Buffer, error) { return raw, nil }
	r, err := OpenWithFactors(path, in, OpenOptions{})
	if err != nil {
		t.Fatalf("recovery composite: %v", err)
	}
	r.Close()
	// the second authenticator alone, the recovery key alone through a source
	if _, err := openHW(path, f, "devB", "5678"); !errors.Is(err, ErrNoFactorSlot) {
		t.Errorf("the recovery authenticator alone: %v", err)
	}
	s, err := openHW(path, f, "devA", "1234")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	b, err := s.Open(ctx, skey0)
	if err != nil {
		t.Fatal(err)
	}
	b.Use(func(x []byte) error {
		if string(x) != "the-signing-key" {
			t.Errorf("secret %q", x)
		}
		return nil
	})
	b.Destroy()
	var ct, wk []byte
	s.db.QueryRow(`SELECT ciphertext, wrapped_key FROM records WHERE kind = ?`, string(skey0.Kind)).Scan(&ct, &wk)
	if bytes.Equal(ct, oldCT) || bytes.Equal(wk, oldWK) {
		t.Error("the signing key record kept its ciphertext or wrapped data key through the rotation")
	}
	if err := s.Verify(ctx); err != nil {
		t.Error(err)
	}
	// a rotation leaves no copy of the file beside it: a copy opens with the
	// credentials the rotation revoked
	if m, _ := filepath.Glob(path + ".pre-rotate*"); len(m) != 0 {
		t.Errorf("a rotation left a copy: %v", m)
	}
}

// The policy function bounds slot add, rekey and rotation.
//
// spec: SPO-Xunlock-PRE-024
func TestPolicyBoundsSlotAddRekeyAndRotation(t *testing.T) {
	path, f, rec := hardwareWS(t)
	s, err := openHW(path, f, "devA", "1234")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	before := readAll(t, path)
	if _, err := s.AddPassphraseSlot(ctx, passphrase("x")); !errors.Is(err, ErrPolicyViolated) {
		t.Errorf("a passphrase slot under hardware: %v", err)
	}
	if _, err := s.Rekey(ctx, []Credential{PassphraseCredential(passphrase("x"))}); !errors.Is(err, ErrPolicyViolated) {
		t.Errorf("a rekey under hardware: %v", err)
	}
	fa, _, _ := EnrolFactor(ctx, f.inputs("devA", "1234"), s.ws, nil)
	proof := presentHW(t, s, f, rec)
	// a hardware table with no recovery composite
	if _, _, err := s.Rotate(ctx, RotatePlan{Policy: unlock.Hardware, Proof: proof, Slots: []SlotPlan{{Kind: seal.SlotFIDO2HMAC, Factors: []FactorPlan{fa}}}}); !errors.Is(err, ErrPolicyViolated) {
		t.Errorf("hardware without a recovery composite: %v", err)
	}
	// strict with a recovery slot
	fa, _, _ = EnrolFactor(ctx, f.inputs("devA", "1234"), s.ws, nil)
	if _, _, err := s.Rotate(ctx, RotatePlan{Policy: unlock.Strict, Proof: proof, Slots: []SlotPlan{{Kind: seal.SlotFIDO2HMAC, Factors: []FactorPlan{fa}}, {Kind: seal.SlotRecovery}}}); !errors.Is(err, ErrPolicyViolated) {
		t.Errorf("strict with a recovery slot: %v", err)
	}
	if err := s.Verify(ctx); err != nil {
		t.Errorf("a refused operation damaged the workspace: %v", err)
	}
	_ = before
	// strict with no recovery path is allowed and has no recovery key
	fa, _, _ = EnrolFactor(ctx, f.inputs("devA", "1234"), s.ws, nil)
	text, _, err := s.Rotate(ctx, RotatePlan{Policy: unlock.Strict, Proof: proof, Slots: []SlotPlan{{Kind: seal.SlotFIDO2HMAC, Factors: []FactorPlan{fa}}}})
	if err != nil || text != nil {
		t.Fatalf("strict rotation: %v %v", text, err)
	}
	infos, _ := s.Slots(ctx)
	if len(infos) != 1 || len(infos[0].RecoveryPubKeyHash) != 0 {
		t.Errorf("strict table: %+v", infos)
	}
}

// An attacker who edits the file can make the workspace refuse to open and
// nothing else: it cannot weaken the policy, drop a factor from a composite,
// swap rows between workspaces, replace the recovery key hash or roll a slot
// back.
//
// spec: SPO-Xunlock-SEC-006
func TestEditedFilesNeverOpenWithAWeakerFactorSet(t *testing.T) {
	assertRefused := func(t *testing.T, name, path string, f *fakeSource, want error) {
		t.Helper()
		s, err := openHW(path, f, "devA", "1234")
		if err == nil {
			s.Close()
			t.Fatalf("%s: the edited workspace opened", name)
		}
		t.Logf("%s: refused: %v", name, err)
		if errors.Is(err, ErrPolicyViolated) && (!strings.Contains(err.Error(), "store verify") || !strings.Contains(err.Error(), "edited")) {
			t.Errorf("%s: the refusal does not say the table was edited and name `store verify`: %v", name, err)
		}
		if want == nil {
			t.Fatalf("%s: the subtest names no expected error", name)
		}
		if !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", name, err, want)
		}
	}
	base, f, recBase := hardwareWS(t)
	if s, err := openHW(base, f, "devA", "1234"); err != nil {
		t.Fatal(err)
	} else {
		s.Close()
	}
	edit := func(t *testing.T, q string, args ...any) string {
		t.Helper()
		p := cloneDB(t, base)
		db := rawDB(t, p)
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
		db.Close()
		return p
	}
	t.Run("policy flipped to standard", func(t *testing.T) {
		assertRefused(t, "flip", edit(t, `UPDATE meta SET policy = 'standard'`), f, ErrPolicyViolated)
	})
	t.Run("policy flipped to standard with legacy passphrase and recovery rows planted", func(t *testing.T) {
		p := edit(t, `UPDATE meta SET policy = 'standard'`)
		db := rawDB(t, p)
		db.Exec(`INSERT INTO keyslots (id,kind,kdf_memory_kib,kdf_passes,kdf_lanes,salt,key_commit,nonce,wrapped_key,bound) VALUES (randomblob(16),'passphrase',65536,3,1,randomblob(16),randomblob(32),randomblob(24),randomblob(48),0)`)
		db.Exec(`INSERT INTO keyslots (id,kind,key_commit,nonce,wrapped_key,bound) VALUES (randomblob(16),'recovery',randomblob(32),randomblob(24),randomblob(48),0)`)
		db.Close()
		// the table now passes the standard check; the factor slots bind the policy
		// they were made under, so none of them opens
		assertRefused(t, "flip+plant", p, f, ErrPolicyViolated)
	})
	t.Run("factor dropped from the recovery composite", func(t *testing.T) {
		var fb []byte
		rawDB(t, base).QueryRow(`SELECT factors FROM keyslots WHERE kind = 'composite'`).Scan(&fb)
		fl, err := seal.DecodeFactors(fb)
		if err != nil || len(fl) != 2 {
			t.Fatalf("%v %d", err, len(fl))
		}
		for drop := range fl {
			keep := []seal.FactorParams{fl[1-drop]}
			nb, _ := seal.EncodeFactors(keep)
			p := edit(t, `UPDATE keyslots SET factors = ? WHERE kind = 'composite'`, nb)
			assertRefused(t, "composite with one factor", p, f, ErrPolicyViolated)
			// the same one-factor list under the fido2-hmac kind passes the shape rule
			// and still opens nothing: the kind and the list are bound in the key
			p = edit(t, `UPDATE keyslots SET factors = ?, kind = 'fido2-hmac' WHERE kind = 'composite'`, nb)
			if s, err := openHW(p, f, "devB", "5678"); err == nil {
				s.Close()
				t.Error("a composite turned into a fido2-hmac slot opened")
			}
		}
	})
	t.Run("recovery key hash replaced in every slot", func(t *testing.T) {
		assertRefused(t, "hash", edit(t, `UPDATE keyslots SET rec_hash = x'0101010101010101010101010101010101010101010101010101010101010101'`), f, ErrWrongCredential)
	})
	t.Run("recovery key hash emptied in every slot", func(t *testing.T) {
		assertRefused(t, "empty hash", edit(t, `UPDATE keyslots SET rec_hash = x''`), f, ErrPolicyViolated)
	})
	t.Run("slot row swapped in from another workspace", func(t *testing.T) {
		other, of, _ := hardwareWS(t)
		var row [12]any
		ptr := make([]any, 12)
		for i := range row {
			ptr[i] = &row[i]
		}
		if err := rawDB(t, other).QueryRow(`SELECT id,kind,kdf_memory_kib,kdf_passes,kdf_lanes,salt,key_commit,nonce,wrapped_key,bound,rec_hash,factors FROM keyslots WHERE kind = 'fido2-hmac'`).Scan(ptr...); err != nil {
			t.Fatal(err)
		}
		_ = of
		p := cloneDB(t, base)
		db := rawDB(t, p)
		if _, err := db.Exec(`DELETE FROM keyslots WHERE kind = 'fido2-hmac'`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO keyslots (id,kind,kdf_memory_kib,kdf_passes,kdf_lanes,salt,key_commit,nonce,wrapped_key,bound,rec_hash,factors) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`, row[:]...); err != nil {
			t.Fatal(err)
		}
		db.Close()
		assertRefused(t, "swap", p, f, ErrPolicyViolated)
	})
	t.Run("a passphrase slot added", func(t *testing.T) {
		p := edit(t, `INSERT INTO keyslots (id,kind,kdf_memory_kib,kdf_passes,kdf_lanes,salt,key_commit,nonce,wrapped_key,bound,rec_hash) SELECT randomblob(16),'passphrase',65536,3,1,randomblob(16),randomblob(32),randomblob(24),randomblob(48),1,rec_hash FROM keyslots LIMIT 1`)
		asserts, profiles := f.asserts, f.profiles
		assertRefused(t, "added passphrase slot", p, f, ErrPolicyViolated)
		if f.asserts != asserts || f.profiles != profiles {
			t.Error("the authenticator was asked before the table was refused")
		}
	})
	t.Run("a slot rolled back", func(t *testing.T) {
		// capture the table, rotate to a new table, put the old slot rows and meta back
		p := cloneDB(t, base)
		old := rawDB(t, p)
		rows, err := old.Query(`SELECT id,kind,kdf_memory_kib,kdf_passes,kdf_lanes,salt,key_commit,nonce,wrapped_key,bound,rec_hash,factors FROM keyslots`)
		if err != nil {
			t.Fatal(err)
		}
		var saved [][]any
		for rows.Next() {
			row := make([]any, 12)
			ptr := make([]any, 12)
			for i := range row {
				ptr[i] = &row[i]
			}
			rows.Scan(ptr...)
			saved = append(saved, row)
		}
		rows.Close()
		var ep, em []byte
		old.QueryRow(`SELECT key_epoch, epoch_mac FROM meta`).Scan(&ep, &em)
		old.Close()
		s, err := openHW(p, f, "devA", "1234")
		if err != nil {
			t.Fatal(err)
		}
		fa, _, _ := EnrolFactor(ctx, f.inputs("devA", "1234"), s.ws, nil)
		fb, _, _ := EnrolFactor(ctx, f.inputs("devB", "5678"), s.ws, nil)
		if txt, _, err := s.Rotate(ctx, RotatePlan{Policy: unlock.Hardware, Proof: presentHW(t, s, f, recBase), Slots: []SlotPlan{
			{Kind: seal.SlotFIDO2HMAC, Factors: []FactorPlan{fa}},
			{Kind: seal.SlotComposite, Factors: []FactorPlan{{Params: seal.FactorParams{Kind: seal.FactorRecovery}}, fb}},
		}}); err != nil {
			t.Fatal(err)
		} else {
			txt.Destroy()
		}
		s.Close()
		p2 := cloneDB(t, p) // the rotated file; only its slot rows go back
		db2 := rawDB(t, p2)
		db2.Exec(`DELETE FROM keyslots`)
		for _, r := range saved {
			db2.Exec(`INSERT INTO keyslots (id,kind,kdf_memory_kib,kdf_passes,kdf_lanes,salt,key_commit,nonce,wrapped_key,bound,rec_hash,factors) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`, r...)
		}
		db2.Close()
		assertRefused(t, "old slot rows, new meta row", p2, f, ErrKeyEpoch)
		db := rawDB(t, p)
		db.Exec(`DELETE FROM keyslots`)
		for _, r := range saved {
			if _, err := db.Exec(`INSERT INTO keyslots (id,kind,kdf_memory_kib,kdf_passes,kdf_lanes,salt,key_commit,nonce,wrapped_key,bound,rec_hash,factors) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`, r...); err != nil {
				t.Fatal(err)
			}
		}
		db.Exec(`UPDATE meta SET key_epoch = ?, epoch_mac = ?`, ep, em)
		db.Close()
		assertRefused(t, "old slot rows and old meta row, new audit chain", p, f, ErrVerify)
	})
}

// Under hardware the recovery public key derives from the recovery composite:
// the recovery key alone derives another key, so it cannot reproduce the hash
// bound in the slots. (ADR 0011 decision 6: "under `hardware` the recovery
// private key is derived only from the recovery composite".)
//
// spec: SPO-Xunlock-OUT-012
func TestHardwareRecoveryPublicKeyDerivesFromTheComposite(t *testing.T) {
	path, f, rec := hardwareWS(t)
	s, err := openHW(path, f, "devA", "1234")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	infos, _ := s.Slots(ctx)
	raw, _ := seal.DecodeRecoveryKey(secret.Take([]byte(rec)))
	alone, err := seal.RecoveryPublicKeyHash(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range infos {
		if len(i.RecoveryPubKeyHash) != 32 || bytes.Equal(i.RecoveryPubKeyHash, alone) {
			t.Errorf("slot %x binds a hash that the recovery key alone reproduces", i.ID)
		}
	}
}

// A rotation that fails after some records were re-encrypted changes nothing: the
// old credentials open the file, every record is as it was and the file verifies.
//
// spec: SPO-Xunlock-INV-005
func TestRotationThatStopsHalfWayLeavesTheFileUnchanged(t *testing.T) {
	s, path, rec := scratch(t)
	putSecret(t, s, skey0, "the-signing-key")
	put(t, s, counter, "1")
	before := ids(t, s)
	f := newFake()
	fa, _, err := EnrolFactor(ctx, f.inputs("devA", "1234"), s.ws, nil)
	if err != nil {
		t.Fatal(err)
	}
	rotateHook = func(done int) error {
		if done >= 1 {
			return errors.New("injected crash")
		}
		return nil
	}
	defer func() { rotateHook = nil }()
	if _, _, err := s.Rotate(ctx, RotatePlan{Policy: unlock.Strict, Proof: presentStd(t, s, rec), Slots: []SlotPlan{{Kind: seal.SlotFIDO2HMAC, Factors: []FactorPlan{fa}}}}); err == nil {
		t.Fatal("the injected failure did not fail the rotation")
	}
	rotateHook = nil
	if pol, _ := s.Policy(ctx); pol != unlock.Standard {
		t.Errorf("policy %q", pol)
	}
	if err := s.Verify(ctx); err != nil {
		t.Errorf("the file does not verify after a failed rotation: %v", err)
	}
	if after := ids(t, s); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Error("a record changed in a failed rotation")
	}
	s.Close()
	o, err := Open(path, pw())
	if err != nil {
		t.Fatalf("the old passphrase does not open the file after a failed rotation: %v", err)
	}
	o.Close()
}

// presentLegacyRecoveryForTest stands in for PresentRecovery on the format 2
// fixture, whose recovery key was never kept (the fixture was converted from
// format 1 and holds no secret that is not the passphrase). It builds the proof
// that PresentRecovery would return for this table, from _test.go code only.
func presentLegacyRecoveryForTest(t *testing.T, s *Store) {
	t.Helper()
	tb, err := s.currentTable(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hash, _, _ := tb.commonRecHash()
	s.recProof = &RecoveryProof{s: s, epoch: append([]byte(nil), s.epoch...), hash: append([]byte(nil), hash...)}
}
