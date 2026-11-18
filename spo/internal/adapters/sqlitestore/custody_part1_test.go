package sqlitestore

// Tests of the custody follow-up to the security review of store format 3: the
// rotation copy (M1), the recovery presentation rule (S1), the stored touch
// probe (S2), the PIN preflight (S3) and the isolating epoch test (S7).

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/unlock"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func strictPlan(t *testing.T, s *Store, f *fakeSource, dev, pin string) RotatePlan {
	t.Helper()
	fa, _, err := EnrolFactor(ctx, f.inputs(dev, pin), s.ws, nil)
	if err != nil {
		t.Fatal(err)
	}
	return RotatePlan{Policy: unlock.Strict, Slots: []SlotPlan{{Kind: seal.SlotFIDO2HMAC, Factors: []FactorPlan{fa}}}}
}

// M1: a rotation makes no copy of the file, on success or on failure; the copy is
// an explicit opt-in that opens with the OLD credentials and is removed when the
// rotation fails.
//
// spec: SPO-Xunlock-OUT-010
func TestRotationMakesNoCopyUnlessAskedAndRemovesItOnFailure(t *testing.T) {
	stray := func(path string) []string {
		m, _ := filepath.Glob(path + "*pre-rotate*")
		return m
	}
	t.Run("default, success", func(t *testing.T) {
		s, path, rec := scratch(t)
		plan := strictPlan(t, s, newFake(), "devA", "1234")
		plan.Proof = presentStd(t, s, rec)
		if _, bk, err := s.Rotate(ctx, plan); err != nil || bk != "" {
			t.Fatalf("%v %q", err, bk)
		}
		if m := stray(path); len(m) != 0 {
			t.Errorf("a stray copy: %v", m)
		}
	})
	t.Run("default, failure", func(t *testing.T) {
		s, path, rec := scratch(t)
		put(t, s, counter, "1")
		plan := strictPlan(t, s, newFake(), "devA", "1234")
		plan.Proof = presentStd(t, s, rec)
		rotateHook = func(int) error { return errors.New("injected") }
		defer func() { rotateHook = nil }()
		if _, _, err := s.Rotate(ctx, plan); err == nil {
			t.Fatal("the injected failure did not fail the rotation")
		}
		if m := stray(path); len(m) != 0 {
			t.Errorf("a stray copy: %v", m)
		}
	})
	t.Run("opt-in, success: the copy opens with the old passphrase only", func(t *testing.T) {
		s, path, rec := scratch(t)
		copyPath := filepath.Join(t.TempDir(), "old.copy")
		plan := strictPlan(t, s, newFake(), "devA", "1234")
		plan.Proof, plan.KeepCopy = presentStd(t, s, rec), copyPath
		_, bk, err := s.Rotate(ctx, plan)
		if err != nil || bk != copyPath {
			t.Fatalf("%v %q", err, bk)
		}
		st, err := os.Stat(copyPath)
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("copy: %v %v", st, err)
		}
		o, err := Open(copyPath, pw())
		if err != nil {
			t.Fatalf("the copy does not open with the OLD passphrase: %v", err)
		}
		o.Close()
		s.Close()
		if _, err := Open(path, pw()); err == nil {
			t.Error("the rotated file still opens with the old passphrase")
		}
	})
	t.Run("opt-in, failure: the copy is removed", func(t *testing.T) {
		s, _, rec := scratch(t)
		put(t, s, counter, "1")
		copyPath := filepath.Join(t.TempDir(), "old.copy")
		plan := strictPlan(t, s, newFake(), "devA", "1234")
		plan.Proof, plan.KeepCopy = presentStd(t, s, rec), copyPath
		rotateHook = func(int) error { return errors.New("injected") }
		defer func() { rotateHook = nil }()
		if _, bk, err := s.Rotate(ctx, plan); err == nil || bk != "" {
			t.Fatalf("%v %q", err, bk)
		}
		if exists(copyPath) {
			t.Error("a failed rotation left the copy that opens with the old credentials")
		}
	})
	t.Run("opt-in refuses an existing file", func(t *testing.T) {
		s, _, rec := scratch(t)
		copyPath := filepath.Join(t.TempDir(), "old.copy")
		os.WriteFile(copyPath, []byte("mine"), 0o600)
		plan := strictPlan(t, s, newFake(), "devA", "1234")
		plan.Proof, plan.KeepCopy = presentStd(t, s, rec), copyPath
		if _, _, err := s.Rotate(ctx, plan); !errors.Is(err, ErrExists) {
			t.Errorf("%v", err)
		}
		if b, _ := os.ReadFile(copyPath); string(b) != "mine" {
			t.Error("the existing file was overwritten")
		}
	})
}

// S1: the store refuses a rotation that does not present the current recovery
// credential, checked against the bound recovery public key hash, before
// anything is written; a daily-credential-only handle cannot rotate.
//
// spec: SPO-Xunlock-PRE-027
func TestRotationNeedsTheRecoveryCredentialPresented(t *testing.T) {
	unchanged := func(t *testing.T, s *Store) {
		t.Helper()
		if err := s.Verify(ctx); err != nil {
			t.Errorf("the refused rotation damaged the file: %v", err)
		}
	}
	t.Run("standard, no proof", func(t *testing.T) {
		s, _, _ := scratch(t)
		put(t, s, counter, "1")
		before := ids(t, s)
		plan := strictPlan(t, s, newFake(), "devA", "1234")
		if _, _, err := s.Rotate(ctx, plan); !errors.Is(err, ErrRecoveryNotPresented) {
			t.Fatalf("%v", err)
		}
		if p, _ := s.Policy(ctx); p != unlock.Standard {
			t.Errorf("policy %s", p)
		}
		unchanged(t, s)
		if got := ids(t, s); len(got) != len(before) {
			t.Error("records changed")
		}
	})
	t.Run("a wrong recovery key presents nothing", func(t *testing.T) {
		s, _, _ := scratch(t)
		other := bytes.Repeat([]byte{5}, 32)
		_, err := s.PresentRecovery(ctx, FactorInputs{Recovery: func(context.Context) (*secret.Buffer, error) { return secret.Take(other), nil }})
		if !errors.Is(err, ErrWrongRecovery) {
			t.Errorf("%v", err)
		}
	})
	t.Run("a proof of another handle is refused (an older epoch: TestPassphraseBytesAndOlderEpochPresentNothing)", func(t *testing.T) {
		s, path, rec := scratch(t)
		old := presentStd(t, s, rec)
		s.Close() // a rotation needs every other handle closed
		s2, err := Open(path, pw())
		if err != nil {
			t.Fatal(err)
		}
		defer s2.Close()
		plan := strictPlan(t, s2, newFake(), "devA", "1234")
		plan.Proof = old // made on s, used on s2
		if _, _, err := s2.Rotate(ctx, plan); !errors.Is(err, ErrRecoveryNotPresented) {
			t.Errorf("a proof of another handle: %v", err)
		}
	})
	t.Run("a proof is spent by the rotation it authorised", func(t *testing.T) {
		s, _, rec := scratch(t)
		proof := presentStd(t, s, rec)
		next := func() RotatePlan {
			return RotatePlan{Policy: unlock.Standard, Proof: proof, Slots: []SlotPlan{{Kind: seal.SlotPassphrase, Passphrase: secret.Take([]byte("another passphrase"))}, {Kind: seal.SlotRecovery}}}
		}
		txt, _, err := s.Rotate(ctx, next())
		if err != nil {
			t.Fatal(err)
		}
		txt.Destroy()
		if _, _, err := s.Rotate(ctx, next()); !errors.Is(err, ErrRecoveryNotPresented) {
			t.Errorf("the same proof twice: %v", err)
		}
	})
	t.Run("strict to strict needs no proof", func(t *testing.T) {
		s, _, rec := scratch(t)
		f := newFake()
		p1 := strictPlan(t, s, f, "devA", "1234")
		p1.Proof = presentStd(t, s, rec)
		if txt, _, err := s.Rotate(ctx, p1); err != nil || txt != nil {
			t.Fatalf("%v %v", txt, err)
		}
		if _, _, err := s.Rotate(ctx, strictPlan(t, s, f, "devA", "1234")); err != nil {
			t.Errorf("%v", err)
		}
	})
	t.Run("hardware: the daily authenticator alone cannot rotate", func(t *testing.T) {
		path, f, rec := hardwareWS(t)
		s, err := openHW(path, f, "devA", "1234")
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		plan := strictPlan(t, s, f, "devA", "1234")
		if _, _, err := s.Rotate(ctx, plan); !errors.Is(err, ErrRecoveryNotPresented) {
			t.Fatalf("a daily-only handle rotated: %v", err)
		}
		// the recovery key without the second authenticator, and the second
		// authenticator without the recovery key, present nothing
		raw, _ := seal.DecodeRecoveryKey(secret.Take([]byte(rec)))
		defer raw.Destroy()
		recOnly := f.inputs("devA", "1234") // the daily token holds no credential of the composite
		recOnly.Recovery = func(context.Context) (*secret.Buffer, error) { return secret.Take(rawBytes(raw)), nil }
		if _, err := s.PresentRecovery(ctx, recOnly); !errors.Is(err, ErrWrongRecovery) {
			t.Errorf("the recovery key with the daily authenticator: %v", err)
		}
		badKey := f.inputs("devB", "5678")
		badKey.Recovery = func(context.Context) (*secret.Buffer, error) { return secret.Take(bytes.Repeat([]byte{3}, 32)), nil }
		if _, err := s.PresentRecovery(ctx, badKey); !errors.Is(err, ErrWrongRecovery) {
			t.Errorf("a wrong recovery key with the right authenticator: %v", err)
		}
		// the full composite works, and weakening to standard is allowed with it
		plan.Proof = presentHW(t, s, f, rec)
		pw2 := secret.Take([]byte("a new passphrase here"))
		std := RotatePlan{Policy: unlock.Standard, Proof: plan.Proof, Slots: []SlotPlan{{Kind: seal.SlotPassphrase, Passphrase: pw2}, {Kind: seal.SlotRecovery}}}
		txt, _, err := s.Rotate(ctx, std)
		if err != nil || txt == nil {
			t.Fatalf("hardware to standard with the composite presented: %v", err)
		}
		txt.Destroy()
		unchanged(t, s)
	})
	t.Run("strict cannot be loosened", func(t *testing.T) {
		s, _, rec := scratch(t)
		f := newFake()
		p1 := strictPlan(t, s, f, "devA", "1234")
		p1.Proof = presentStd(t, s, rec)
		if _, _, err := s.Rotate(ctx, p1); err != nil {
			t.Fatal(err)
		}
		fa, _, _ := EnrolFactor(ctx, f.inputs("devA", "1234"), s.ws, nil)
		fb, _, _ := EnrolFactor(ctx, f.inputs("devB", "5678"), s.ws, nil)
		hw := RotatePlan{Policy: unlock.Hardware, Slots: []SlotPlan{{Kind: seal.SlotFIDO2HMAC, Factors: []FactorPlan{fa}},
			{Kind: seal.SlotComposite, Factors: []FactorPlan{{Params: seal.FactorParams{Kind: seal.FactorRecovery}}, fb}}}}
		if _, _, err := s.Rotate(ctx, hw); !errors.Is(err, ErrRotateWeakens) {
			t.Errorf("strict to hardware: %v", err)
		}
		if _, err := s.PresentRecovery(ctx, FactorInputs{Recovery: func(context.Context) (*secret.Buffer, error) { return secret.Take(bytes.Repeat([]byte{1}, 32)), nil }}); !errors.Is(err, ErrNoRecoveryPath) {
			t.Errorf("presenting a recovery path that strict has: %v", err)
		}
		unchanged(t, s)
	})
}

func TestDomainWeakens(t *testing.T) {
	for _, c := range []struct {
		from, to unlock.Policy
		want     bool
	}{
		{unlock.Hardware, unlock.Standard, true}, {unlock.Strict, unlock.Hardware, true}, {unlock.Strict, unlock.Standard, true},
		{unlock.Standard, unlock.Hardware, false}, {unlock.Hardware, unlock.Strict, false}, {unlock.Strict, unlock.Strict, false},
	} {
		if got := unlock.Weakens(c.from, c.to); got != c.want {
			t.Errorf("%s -> %s: %v", c.from, c.to, got)
		}
	}
}

// N2: a rekey under hardware or strict is refused and names the rotation.
//
// spec: SPO-Xunlock-PRE-024
func TestRekeyUnderHardwareNamesRotation(t *testing.T) {
	path, f, _ := hardwareWS(t)
	s, err := openHW(path, f, "devA", "1234")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, err = s.Rekey(ctx, []Credential{PassphraseCredential(passphrase("x"))})
	if !errors.Is(err, ErrPolicyViolated) || !bytes.Contains([]byte(err.Error()), []byte("spo workspace rotate")) {
		t.Errorf("%v", err)
	}
}

// S2: the touch probe result is stored with the factor, bound in the slot's
// associated data and listed; a file edited to say "touch enforced" opens
// nothing.
//
// spec: SPO-Xunlock-SEC-004, SPO-Xunlock-OUT-006
func TestTouchProbeIsStoredAndBound(t *testing.T) {
	s, path, _ := scratch(t)
	f := newFake()
	f.touch = ports.TouchNotEnforced
	fa, en, err := EnrolFactor(ctx, f.inputs("devA", "1234"), s.ws, nil)
	if err != nil {
		t.Fatal(err)
	}
	if en.Touch != ports.TouchNotEnforced || fa.Params.Touch != uint8(ports.TouchNotEnforced) {
		t.Fatalf("EnrolFactor dropped the probe result: %d %d", en.Touch, fa.Params.Touch)
	}
	if _, err := s.AddFactorSlot(ctx, []FactorPlan{fa}); err != nil {
		t.Fatal(err)
	}
	infos, _ := s.Slots(ctx)
	var got []uint8
	for _, i := range infos {
		for _, fi := range i.Factors {
			if fi.Kind == "fido2" {
				got = append(got, fi.Touch)
			}
		}
	}
	if len(got) != 1 || got[0] != uint8(ports.TouchNotEnforced) {
		t.Fatalf("the listing does not carry the probe result: %v", got)
	}
	s.Close()
	h, err := openHW(path, f, "devA", "1234")
	if err != nil {
		t.Fatal(err)
	}
	h.Close()
	// the stored value says "enforced": the slot no longer opens
	db := rawDB(t, path)
	var fb []byte
	if err := db.QueryRow(`SELECT factors FROM keyslots WHERE kind = 'fido2-hmac'`).Scan(&fb); err != nil {
		t.Fatal(err)
	}
	fl, err := seal.DecodeFactors(fb)
	if err != nil {
		t.Fatal(err)
	}
	fl[0].Touch = uint8(ports.TouchEnforced)
	nb, _ := seal.EncodeFactors(fl)
	if _, err := db.Exec(`UPDATE keyslots SET factors = ? WHERE kind = 'fido2-hmac'`, nb); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, err := openHW(path, f, "devA", "1234"); err == nil {
		t.Error("a workspace whose stored touch result was edited opened through that slot")
	}
}

// S3: the preflight checks both PINs before any credential is made; a wrong
// recovery PIN leaves no credential on either authenticator.
//
// spec: SPO-Xunlock-PRE-028
func TestPreflightChecksEveryPINBeforeAnyEnrolment(t *testing.T) {
	f := newFake()
	if err := PreflightFactors(ctx, f.inputs("devA", "1234"), f.inputs("devB", "0000")); !errors.Is(err, ports.ErrFactorPIN) {
		t.Fatalf("%v", err)
	}
	if f.enrols != 0 {
		t.Errorf("%d credentials were made", f.enrols)
	}
	if err := PreflightFactors(ctx, f.inputs("devA", "1234"), f.inputs("devB", "5678")); err != nil {
		t.Fatalf("%v", err)
	}
	// a source that cannot say whether a PIN is right is not stopped here
	f.profile = &ports.FactorProfile{HMACSecret: true}
	if err := PreflightFactors(ctx, f.inputs("devA", "1234")); !errors.Is(err, ports.ErrFactorCapability) {
		t.Errorf("a source that lacks a capability: %v", err)
	}
}

// S7: an old fido2 slot row from before a strict-to-strict rotation, put back
// into the rotated file, unwraps to a master key of the earlier epoch and is
// refused as ErrKeyEpoch (the table itself passes the policy check, so nothing
// else refuses it).
//
// spec: SPO-Xunlock-SEC-006
func TestOldFactorSlotRowPutBackIsRefusedByTheKeyEpoch(t *testing.T) {
	s, path, rec := scratch(t)
	f := newFake()
	p1 := strictPlan(t, s, f, "devA", "1234")
	p1.Proof = presentStd(t, s, rec)
	if _, _, err := s.Rotate(ctx, p1); err != nil {
		t.Fatal(err)
	}
	row := func() (r [12]any) {
		db := rawDB(t, path)
		defer db.Close()
		ptr := make([]any, 12)
		for i := range r {
			ptr[i] = &r[i]
		}
		if err := db.QueryRow(`SELECT id,kind,kdf_memory_kib,kdf_passes,kdf_lanes,salt,key_commit,nonce,wrapped_key,bound,rec_hash,factors FROM keyslots WHERE kind='fido2-hmac'`).Scan(ptr...); err != nil {
			t.Fatal(err)
		}
		return r
	}
	old := row()
	p2 := strictPlan(t, s, f, "devA", "1234")
	if _, _, err := s.Rotate(ctx, p2); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if r := row(); bytes.Equal(r[0].([]byte), old[0].([]byte)) {
		t.Fatal("the second rotation kept the slot id")
	}
	db := rawDB(t, path)
	if _, err := db.Exec(`DELETE FROM keyslots`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO keyslots (id,kind,kdf_memory_kib,kdf_passes,kdf_lanes,salt,key_commit,nonce,wrapped_key,bound,rec_hash,factors) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`, old[:]...); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, err := openHW(path, f, "devA", "1234"); !errors.Is(err, ErrKeyEpoch) {
		t.Errorf("the old slot row opened or failed otherwise: %v", err)
	}
}

var _ = context.Background

// S5(b) at the store: the gate asks the authenticator again, checks the answer
// against the master key of this handle, and fails closed with no source.
//
// spec: SPO-Xunlock-PRE-029
func TestReauthenticateAsksTheAuthenticatorAgainAndFailsClosed(t *testing.T) {
	path, f, _ := hardwareWS(t)
	s, err := openHW(path, f, "devA", "1234")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	asserts := f.asserts
	if err := s.Reauthenticate(ctx, f.inputs("devA", "1234")); err != nil {
		t.Fatalf("%v", err)
	}
	if f.asserts == asserts {
		t.Error("the authenticator was not asked")
	}
	if err := s.Reauthenticate(ctx, FactorInputs{}); err == nil {
		t.Error("a re-authentication with no factor source succeeded")
	}
	if err := s.Reauthenticate(ctx, f.inputs("devA", "0000")); !errors.Is(err, ports.ErrFactorPIN) {
		t.Errorf("a wrong PIN: %v", err)
	}
	// the second authenticator holds no credential of the daily slot
	if err := s.Reauthenticate(ctx, f.inputs("devB", "5678")); err == nil {
		t.Error("another authenticator re-authenticated the session")
	}
}

// auditHas opens the sealed events of the audit chain of s and looks for text.
func auditHas(t *testing.T, s *Store, text string) bool {
	t.Helper()
	rows, err := s.db.Query(`SELECT seq, event FROM audit`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var seq int64
		var e []byte
		rows.Scan(&seq, &e)
		r, err := seal.ParseSealed(e)
		if err != nil {
			continue
		}
		if pt, err := s.keys.OpenRecord(eventMeta(s.ws, uint64(seq)), r); err == nil && bytes.Contains(pt, []byte(text)) {
			return true
		}
	}
	return false
}

// B': removing a slot is a rotation that re-creates the others; it needs the
// recovery credential, refuses the last slot the policy needs, and is audited.
//
// spec: SPO-Xunlock-PRE-030, SPO-Xunlock-OUT-016
func TestRemoveSlotByRotation(t *testing.T) {
	t.Run("a FIDO2 convenience slot of a standard workspace", func(t *testing.T) {
		s, path, rec := scratch(t)
		put(t, s, counter, "1")
		f := newFake()
		fa, _, err := EnrolFactor(ctx, f.inputs("devA", "1234"), s.ws, nil)
		if err != nil {
			t.Fatal(err)
		}
		id, err := s.AddFactorSlot(ctx, []FactorPlan{fa})
		if err != nil {
			t.Fatal(err)
		}
		fa.Output.Destroy()
		req := RemoveRequest{SlotID: id, Daily: f.inputs("devA", "1234")}
		req.Daily.Passphrase = pinOf(string(rawBytes(pw())))
		if _, _, err := s.RemoveSlotByRotation(ctx, req); !errors.Is(err, ErrRecoveryNotPresented) {
			t.Fatalf("without the recovery credential: %v", err)
		}
		req.Proof = presentStd(t, s, rec)
		txt, bk, err := s.RemoveSlotByRotation(ctx, req)
		if err != nil || bk != "" {
			t.Fatalf("%v %q", err, bk)
		}
		txt.Destroy()
		infos, _ := s.Slots(ctx)
		if len(infos) != 2 {
			t.Fatalf("%d slots remain", len(infos))
		}
		for _, i := range infos {
			if i.Kind != seal.SlotPassphrase && i.Kind != seal.SlotRecovery {
				t.Errorf("slot %s remains", i.Kind)
			}
		}
		if err := s.Verify(ctx); err != nil {
			t.Error(err)
		}
		if !auditHas(t, s, "slot-removed") {
			t.Error("the removal is not in the audit chain")
		}
		s.Close()
		if _, err := openHW(path, f, "devA", "1234"); err == nil {
			t.Error("the removed FIDO2 slot still opens the workspace")
		}
		o, err := Open(path, pw())
		if err != nil {
			t.Fatal(err)
		}
		o.Close()
	})
	t.Run("the last slot a policy needs", func(t *testing.T) {
		s, _, rec := scratch(t)
		infos, _ := s.Slots(ctx)
		for _, i := range infos {
			req := RemoveRequest{SlotID: i.ID, Proof: presentStd(t, s, rec)}
			req.Daily.Passphrase = pinOf(string(rawBytes(pw())))
			if _, _, err := s.RemoveSlotByRotation(ctx, req); !errors.Is(err, ErrLastSlot) {
				t.Errorf("removing the only %s slot of a standard workspace: %v", i.Kind, err)
			}
		}
		path, f, hrec := hardwareWS(t)
		h, err := openHW(path, f, "devA", "1234")
		if err != nil {
			t.Fatal(err)
		}
		defer h.Close()
		infos, _ = h.Slots(ctx)
		for _, i := range infos {
			req := RemoveRequest{SlotID: i.ID, Proof: presentHW(t, h, f, hrec), Daily: f.inputs("devA", "1234"), Recovery: f.inputs("devB", "5678")}
			req.Recovery.Recovery = nil
			want := ErrLastSlot // the only daily slot
			if i.Kind == seal.SlotComposite {
				want = ErrPolicyViolated // the only recovery composite: hardware needs one
			}
			if _, _, err := h.RemoveSlotByRotation(ctx, req); !errors.Is(err, want) {
				t.Errorf("removing %s of a hardware workspace with one daily slot and one recovery composite: %v", i.Kind, err)
			}
		}
		if err := h.Verify(ctx); err != nil {
			t.Error(err)
		}
	})
	t.Run("an unknown slot", func(t *testing.T) {
		s, _, _ := scratch(t)
		if _, _, err := s.RemoveSlotByRotation(ctx, RemoveRequest{SlotID: bytes.Repeat([]byte{9}, 16)}); !errors.Is(err, ErrNotFoundSlot) {
			t.Errorf("%v", err)
		}
	})
}

// Review 2, M1: under standard no credential but the recovery credential
// replaces the recovery path. A handle opened with the passphrase (or through a
// FIDO2 convenience slot) cannot rekey or change the passphrase; with the
// recovery key presented a passphrase change keeps the recovery key.
//
// spec: SPO-Xunlock-PRE-031
func TestRekeyNeedsTheRecoveryCredentialUnderStandard(t *testing.T) {
	s, path, rec := scratchUnpresented(t)
	if _, err := s.ChangePassphraseRekey(ctx, passphrase("brand new passphrase")); !errors.Is(err, ErrRecoveryNotPresented) {
		t.Fatalf("a passphrase holder minted a recovery key: %v", err)
	}
	if _, err := s.Rekey(ctx, []Credential{PassphraseCredential(passphrase("x y z w"))}); !errors.Is(err, ErrRecoveryNotPresented) {
		t.Fatalf("Rekey: %v", err)
	}
	// a holder of only a FIDO2 convenience slot
	f := newFake()
	fa, _, _ := EnrolFactor(ctx, f.inputs("devA", "1234"), s.ws, nil)
	if _, err := s.AddFactorSlot(ctx, []FactorPlan{fa}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	h, err := openHW(path, f, "devA", "1234")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.RekeyKeepRecovery(ctx, passphrase("fido holder passphrase"), secret.Take(bytes.Repeat([]byte{1}, 32))); !errors.Is(err, ErrRecoveryNotPresented) {
		t.Fatalf("a FIDO2-only handle changed the passphrase: %v", err)
	}
	h.Close()
	// with the recovery key presented: the passphrase changes, the recovery key and its hash stay
	s, err = Open(path, pw())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	before, _ := s.Slots(ctx)
	presentStd(t, s, rec)
	raw, _ := seal.DecodeRecoveryKey(secret.Take([]byte(rec)))
	if err := s.RekeyKeepRecovery(ctx, passphrase("the new passphrase!"), raw); err != nil {
		t.Fatalf("%v", err)
	}
	after, _ := s.Slots(ctx)
	if !bytes.Equal(before[0].RecoveryPubKeyHash, after[0].RecoveryPubKeyHash) {
		t.Error("the bound recovery public key hash changed")
	}
	s.Close()
	o, err := OpenWithRecovery(path, secret.Take([]byte(rec)))
	if err != nil {
		t.Fatalf("the same recovery key no longer opens: %v", err)
	}
	o.Close()
}

// An unlock with the recovery credential is a presentation of it (store recover).
func TestRecoveryUnlockMayRekey(t *testing.T) {
	s0, path, rec := scratch(t)
	s0.Close()
	r, err := OpenWithRecovery(path, secret.Take([]byte(rec)))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if k, err := r.ChangePassphraseRekey(ctx, passphrase("recovered passphrase")); err != nil {
		t.Fatalf("%v", err)
	} else {
		k.Destroy()
	}
}

// The passphrase of the session is not a recovery presentation, and a proof from
// before a rotation is not one after it.
//
// spec: SPO-Xunlock-PRE-027
func TestPassphraseBytesAndOlderEpochPresentNothing(t *testing.T) {
	s, _, rec := scratch(t)
	pwBytes := rawBytes(pw())
	pad := append(append([]byte(nil), pwBytes...), bytes.Repeat([]byte{0}, 32-len(pwBytes)%32)...)[:32]
	if _, err := s.PresentRecovery(ctx, FactorInputs{Recovery: func(context.Context) (*secret.Buffer, error) { return secret.Take(pad), nil }}); !errors.Is(err, ErrWrongRecovery) {
		t.Errorf("the passphrase bytes: %v", err)
	}
	old := presentStd(t, s, rec)
	txt, _, err := s.Rotate(ctx, RotatePlan{Policy: unlock.Standard, Proof: old, Slots: []SlotPlan{{Kind: seal.SlotPassphrase, Passphrase: passphrase("another passphrase")}, {Kind: seal.SlotRecovery}}})
	if err != nil {
		t.Fatal(err)
	}
	txt.Destroy()
	if _, err := s.ChangePassphraseRekey(ctx, passphrase("third passphrase!!")); !errors.Is(err, ErrRecoveryNotPresented) {
		t.Errorf("a proof of an older epoch: %v", err)
	}
}

// Review 2, SHOULD 3: a FIDO2 slot that stays through a removal is re-created with
// a fresh hmac-secret salt, so an output captured before survives nothing.
//
// spec: SPO-Xunlock-OUT-016
func TestKeptFactorsGetAFreshSaltInARemoval(t *testing.T) {
	path, f, rec := hardwareWS(t)
	s, err := openHW(path, f, "devA", "1234")
	if err != nil {
		t.Fatal(err)
	}
	// a second daily authenticator slot, to remove
	fx, _, _ := EnrolFactor(ctx, f.inputs("devA", "1234"), s.ws, nil)
	id, err := s.AddFactorSlot(ctx, []FactorPlan{fx})
	if err != nil {
		t.Fatal(err)
	}
	salts := func() map[string]bool {
		db := rawDB(t, path)
		defer db.Close()
		rows, _ := db.Query(`SELECT factors FROM keyslots WHERE kind IN ('fido2-hmac','composite')`)
		defer rows.Close()
		out := map[string]bool{}
		for rows.Next() {
			var b []byte
			rows.Scan(&b)
			fl, _ := seal.DecodeFactors(b)
			for _, x := range fl {
				if x.Kind == seal.FactorFIDO2 {
					out[string(x.HMACSalt)] = true
				}
			}
		}
		return out
	}
	s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	before := salts()
	req := RemoveRequest{SlotID: id, Proof: presentHW(t, s, f, rec), Daily: f.inputs("devA", "1234"), Recovery: f.inputs("devB", "5678")}
	req.Recovery.Recovery = recoveryRaw(t, rec) // the kept composite is checked with the recovery key too
	txt, _, err := s.RemoveSlotByRotation(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	txt.Destroy()
	s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	after := salts()
	if len(before) < 3 || len(after) != 2 {
		t.Fatalf("salts before %d after %d", len(before), len(after))
	}
	for k := range after {
		if before[k] {
			t.Error("a kept factor kept its hmac-secret salt")
		}
	}
	s.Close()
	if h, err := openHW(path, f, "devA", "1234"); err != nil {
		t.Errorf("the daily authenticator does not open the rotated workspace: %v", err)
	} else {
		h.Close()
	}
}
