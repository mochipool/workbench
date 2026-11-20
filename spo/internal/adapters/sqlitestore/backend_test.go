package sqlitestore

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/unlock"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/porttest"
)

const compositePass = "the composite passphrase"

var testBackendRef = ports.BackendRef{Kind: ports.BackendVaultTransit, Address: "https://vault.example:8200", Namespace: "ops", Key: "transit/spo"}

// resolver hands out kb for the reference it names, and refuses any other.
func resolver(kb ports.KeyWrapBackend) func(context.Context, ports.BackendRef) (ports.KeyWrapBackend, error) {
	return func(_ context.Context, ref ports.BackendRef) (ports.KeyWrapBackend, error) {
		if ref != kb.Ref() {
			return nil, errors.New("no client for that backend")
		}
		return kb, nil
	}
}

func passFactor(t *testing.T, p string) FactorPlan {
	t.Helper()
	pw := secret.Take([]byte(p))
	defer pw.Destroy()
	fp, err := NewPassphraseFactor(pw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fp.Output.Destroy() })
	return fp
}

// localConfig is the BackendCheck of an operator whose spo.toml names ref.
func localConfig(ref ports.BackendRef) func(ports.BackendRef) error {
	return func(claim ports.BackendRef) error { return ports.CheckBackendClaim(claim, ref) }
}

func backendInputs(kb ports.KeyWrapBackend, pass string) FactorInputs {
	in := FactorInputs{Backend: resolver(kb), BackendCheck: localConfig(kb.Ref())}
	if pass != "" {
		in.Passphrase = pinOf(pass)
	}
	return in
}

// standardWithBackend is a standard workspace with a composite slot of a new
// passphrase factor AND a backend factor. It holds one record.
func standardWithBackend(t *testing.T) (path string, kb *porttest.FakeKeyWrap, slotID []byte) {
	t.Helper()
	s, path, _ := scratch(t)
	put(t, s, counter, "042\n")
	kb = porttest.NewFakeKeyWrap(testBackendRef)
	id, err := s.AddBackendSlot(ctx, kb, []FactorPlan{passFactor(t, compositePass)})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	return path, kb, id
}

// A composite of a passphrase factor and a backend factor opens with both, and
// with neither alone: the backend operator, who can unwrap B, lacks the
// passphrase; a holder of the file and the passphrase lacks the backend.
//
// spec: SPO-Xunlock-OUT-019, SPO-Xunlock-OUT-020, SPO-Xunlock-SEC-011
func TestBackendCompositeOpensWithBothFactorsOnly(t *testing.T) {
	path, kb, id := standardWithBackend(t)
	s, err := OpenWithFactors(path, backendInputs(kb, compositePass), OpenOptions{})
	if err != nil {
		t.Fatalf("both factors: %v", err)
	}
	if b, err := get(s, counter); err != nil || string(b) != "042\n" {
		t.Errorf("record %q %v", b, err)
	}
	s.Close()
	// the backend operator alone: B, no passphrase
	if _, err := OpenWithFactors(path, backendInputs(kb, ""), OpenOptions{}); !errors.Is(err, ErrNoFactorSlot) {
		t.Errorf("backend alone: %v", err)
	}
	// the backend operator with a guessed passphrase
	if _, err := OpenWithFactors(path, backendInputs(kb, "a guess"), OpenOptions{}); !errors.Is(err, ErrWrongCredential) {
		t.Errorf("backend and a wrong passphrase: %v", err)
	}
	// the file and the passphrase, no backend access
	if _, err := OpenWithFactors(path, FactorInputs{Passphrase: pinOf(compositePass)}, OpenOptions{}); err == nil {
		t.Error("the passphrase alone opened the composite")
	}
	kb.Fail = ports.ErrBackendCredential
	_, err = OpenWithFactors(path, backendInputs(kb, compositePass), OpenOptions{})
	if !errors.Is(err, ErrBackendFactor) || !errors.Is(err, ports.ErrBackendCredential) {
		t.Errorf("a backend that refuses the credential: %v", err)
	}
	if err != nil && (strings.Contains(err.Error(), compositePass) || !strings.Contains(err.Error(), string(ports.BackendVaultTransit))) {
		t.Errorf("the error leaks the passphrase or does not name the factor: %v", err)
	}
	kb.Fail = porttest.ErrFakeDown
	if _, err := OpenWithFactors(path, backendInputs(kb, compositePass), OpenOptions{}); !errors.Is(err, ErrBackendFactor) || !errors.Is(err, ports.ErrBackendUnavailable) {
		t.Errorf("a backend that is down: %v", err)
	}
	kb.Fail = nil
	// the listing shows the backend's public parameters and no secret
	_, infos, err := Describe(path)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, si := range infos {
		if !bytes.Equal(si.ID, id) {
			continue
		}
		for _, f := range si.Factors {
			if f.Kind == string(unlock.Backend) {
				found = f.Backend == testBackendRef
			}
		}
	}
	if !found {
		t.Errorf("the slot listing has no backend factor %v: %+v", testBackendRef, infos)
	}
}

// A hostile backend that answers a B of its choosing opens nothing: the
// commitment of the slot key refuses it, whatever 32 bytes it picks, and an
// answer of another length is refused before any derivation.
//
// spec: SPO-Xunlock-SEC-011, SPO-Xunlock-PRE-042
func TestAHostileBackendCannotMakeASlotOpen(t *testing.T) {
	path, kb, _ := standardWithBackend(t)
	for _, chosen := range [][]byte{make([]byte, 32), bytes.Repeat([]byte{0xff}, 32), []byte("0123456789abcdef0123456789abcdef")} {
		kb.Chosen = chosen
		if _, err := OpenWithFactors(path, backendInputs(kb, compositePass), OpenOptions{}); !errors.Is(err, ErrWrongCredential) {
			t.Errorf("chosen B %x: %v", chosen[:4], err)
		}
	}
	for _, n := range []int{1, 31, 33} {
		kb.Chosen = make([]byte, n)
		_, err := OpenWithFactors(path, backendInputs(kb, compositePass), OpenOptions{})
		if !errors.Is(err, ErrBackendFactor) || !errors.Is(err, ports.ErrBackendResponse) {
			t.Errorf("a B of %d bytes: %v", n, err)
		}
	}
}

// A blob moved to another slot, or to another workspace, does not unwrap: the
// backend binds the genesis nonce and the slot id, and the slot's own
// associated data binds the blob, so even a backend that ignored its context
// would not make the moved blob open the other slot.
//
// spec: SPO-Xunlock-SEC-012, SPO-Xunlock-IF-007
func TestABackendBlobDoesNotMoveBetweenSlotsOrWorkspaces(t *testing.T) {
	s, path, _ := scratch(t)
	kb := porttest.NewFakeKeyWrap(testBackendRef)
	idA, err := s.AddBackendSlot(ctx, kb, []FactorPlan{passFactor(t, compositePass)})
	if err != nil {
		t.Fatal(err)
	}
	idB, err := s.AddBackendSlot(ctx, kb, []FactorPlan{passFactor(t, "another composite passphrase")})
	if err != nil {
		t.Fatal(err)
	}
	t1, err := s.currentTable(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	var blobA []byte
	var slotB tslot
	for _, ts := range t1.slots {
		for _, f := range ts.fs.Spec.Factors {
			if f.Kind == seal.FactorBackend && bytes.Equal(ts.id, idA) {
				blobA = f.BackendBlob
			}
		}
		if bytes.Equal(ts.id, idB) {
			slotB = ts
		}
	}
	// the slot B row with slot A's blob
	moved := slotB
	moved.fs.Spec.Factors = append([]seal.FactorParams(nil), slotB.fs.Spec.Factors...)
	for i := range moved.fs.Spec.Factors {
		if moved.fs.Spec.Factors[i].Kind == seal.FactorBackend {
			moved.fs.Spec.Factors[i].BackendBlob = blobA
		}
	}
	enc, err := seal.EncodeFactors(moved.fs.Spec.Factors)
	if err != nil {
		t.Fatal(err)
	}
	db := rawDB(t, path)
	if _, err := db.Exec(`UPDATE keyslots SET factors = ? WHERE id = ?`, enc, idB); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM keyslots WHERE id = ?`, idA); err != nil {
		t.Fatal(err)
	}
	db.Close()
	in := backendInputs(kb, "another composite passphrase")
	if _, err := OpenWithFactors(path, in, OpenOptions{}); !errors.Is(err, ErrBackendFactor) || !errors.Is(err, ports.ErrBackendRefused) {
		t.Errorf("the backend unwrapped a blob under another slot's context: %v", err)
	}
	// a backend that ignores its context (a compromised one): the slot's own
	// associated data still refuses the moved blob
	in.Backend = resolver(contextBlind{kb, idA})
	if _, err := OpenWithFactors(path, in, OpenOptions{}); !errors.Is(err, ErrWrongCredential) {
		t.Errorf("a blob moved to another slot, with a backend that ignores its context: %v", err)
	}
}

// contextBlind unwraps every blob under one fixed slot's context, whatever it
// is asked: a backend that does not enforce its binding.
type contextBlind struct {
	*porttest.FakeKeyWrap
	slot []byte
}

func (c contextBlind) Unwrap(ctx context.Context, blob []byte, wc ports.WrapContext) (*secret.Buffer, error) {
	return c.FakeKeyWrap.Unwrap(ctx, blob, ports.WrapContext{GenesisNonce: wc.GenesisNonce, SlotID: c.slot})
}

// A workspace's backend blob does not unwrap in another workspace: the genesis
// nonce is in the context.
//
// spec: SPO-Xunlock-SEC-012
func TestABackendBlobDoesNotMoveBetweenWorkspaces(t *testing.T) {
	kb := porttest.NewFakeKeyWrap(testBackendRef)
	s1, _, _ := scratch(t)
	id1, err := s1.AddBackendSlot(ctx, kb, []FactorPlan{passFactor(t, compositePass)})
	if err != nil {
		t.Fatal(err)
	}
	t1, _ := s1.currentTable(ctx)
	var blob []byte
	for _, ts := range t1.slots {
		if bytes.Equal(ts.id, id1) {
			for _, f := range ts.fs.Spec.Factors {
				if f.Kind == seal.FactorBackend {
					blob = f.BackendBlob
				}
			}
		}
	}
	s2, _, _ := scratch(t)
	if bytes.Equal(s1.ws, s2.ws) {
		t.Fatal("two workspaces with one nonce")
	}
	if out, err := kb.Unwrap(ctx, blob, ports.WrapContext{GenesisNonce: s2.ws, SlotID: id1}); !errors.Is(err, ports.ErrBackendRefused) {
		if err == nil {
			out.Destroy()
		}
		t.Errorf("another workspace's nonce: %v", err)
	}
}

// Decision 6: a backend factor needs a factor the backend does not control, and
// under hardware a FIDO2 factor; the refusal comes before the backend is asked.
//
// spec: SPO-Xunlock-PRE-011, SPO-Xunlock-PRE-043
func TestBackendSlotPolicyIsCheckedBeforeTheBackendIsAsked(t *testing.T) {
	s, _, _ := scratch(t)
	kb := porttest.NewFakeKeyWrap(testBackendRef)
	if _, err := s.AddBackendSlot(ctx, kb, nil); !errors.Is(err, ErrPolicyViolated) {
		t.Errorf("a backend alone: %v", err)
	}
	if kb.Calls != 0 {
		t.Errorf("the backend was asked %d times", kb.Calls)
	}

	path, f, _ := hardwareWS(t)
	h, err := openHW(path, f, "devA", pinA)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if _, err := h.AddBackendSlot(ctx, kb, []FactorPlan{passFactor(t, compositePass)}); !errors.Is(err, ErrPolicyViolated) || !strings.Contains(err.Error(), string(unlock.RuleBackend)) {
		t.Errorf("hardware, backend and a passphrase: %v", err)
	}
	if kb.Calls != 0 {
		t.Errorf("the backend was asked %d times", kb.Calls)
	}
	// a FIDO2 credential of its own on a third authenticator
	f.auths["devC"] = &fakeAuth{3, "seed-c", pinC}
	fc, _, err := EnrolFactor(ctx, f.inputs("devC", pinC), h.ws, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer fc.Output.Destroy()
	if _, err := h.AddBackendSlot(ctx, kb, []FactorPlan{fc}); err != nil {
		t.Fatalf("hardware, backend and FIDO2: %v", err)
	}
	h.Close()
	in := f.inputs("devC", pinC)
	in.Backend, in.BackendCheck = resolver(kb), localConfig(kb.Ref())
	s2, err := OpenWithFactors(path, in, OpenOptions{})
	if err != nil {
		t.Fatalf("FIDO2 and the backend: %v", err)
	}
	s2.Close()
	if _, err := OpenWithFactors(path, f.inputs("devC", pinC), OpenOptions{}); !errors.Is(err, ErrNoFactorSlot) {
		t.Errorf("the composite's authenticator without the backend: %v", err)
	}
	// the daily authenticator's own credential is not accepted in a backend
	// composite: it would also be a standalone slot
	h2, _ := openHW(path, f, "devA", pinA)
	defer h2.Close()
	t2, _ := h2.currentTable(ctx)
	var daily seal.FactorParams
	for _, ts := range t2.slots {
		if ts.kind == seal.SlotFIDO2HMAC {
			daily = ts.fs.Spec.Factors[0]
		}
	}
	calls := kb.Calls
	if _, err := h2.AddBackendSlot(ctx, kb, []FactorPlan{{Params: daily, Output: owned(secret.Take(make([]byte, 32)))}}); !errors.Is(err, ErrPolicyViolated) {
		t.Errorf("the daily credential in a backend composite: %v", err)
	}
	if kb.Calls != calls {
		t.Error("the backend was asked for a refused slot")
	}
}

// Enrolment unwraps once what it wrapped and refuses a backend that does not
// give B back; nothing is added.
//
// spec: SPO-Xunlock-OUT-019
func TestBackendEnrolmentChecksTheRoundTrip(t *testing.T) {
	s, _, _ := scratch(t)
	kb := porttest.NewFakeKeyWrap(testBackendRef)
	kb.Chosen = bytes.Repeat([]byte{7}, 32)
	before, _ := s.currentTable(ctx)
	if _, err := s.AddBackendSlot(ctx, kb, []FactorPlan{passFactor(t, compositePass)}); !errors.Is(err, ErrBackendFactor) {
		t.Errorf("a backend that answers another B: %v", err)
	}
	after, _ := s.currentTable(ctx)
	if len(after.slots) != len(before.slots) {
		t.Error("a slot was added")
	}
	kb.Chosen = nil
	kb.Fail = porttest.ErrFakeDown
	if _, err := s.AddBackendSlot(ctx, kb, []FactorPlan{passFactor(t, compositePass)}); !errors.Is(err, ports.ErrBackendUnavailable) {
		t.Errorf("a backend that is down: %v", err)
	}
}

// Removing the backend composite is a rotation: afterwards the backend and the
// composite passphrase open nothing, and the passphrase slot still does.
//
// spec: SPO-Xunlock-OUT-021
func TestRemovingABackendSlot(t *testing.T) {
	path, kb, id := standardWithBackend(t)
	s, err := Open(path, pw())
	if err != nil {
		t.Fatal(err)
	}
	rec := heldRecoveryOf(t, path)
	proof := presentStd(t, s, rec)
	text, _, err := s.RemoveSlotByRotation(ctx, RemoveRequest{SlotID: id, Proof: proof, Daily: FactorInputs{Passphrase: pinOf(testPass)}})
	if err != nil {
		t.Fatal(err)
	}
	text.Destroy()
	s.Close()
	if _, err := OpenWithFactors(path, backendInputs(kb, compositePass), OpenOptions{}); !errors.Is(err, ErrNoFactorSlot) {
		t.Errorf("after the removal: %v", err)
	}
	s, err = Open(path, pw())
	if err != nil {
		t.Fatalf("the passphrase after the removal: %v", err)
	}
	s.Close()
}

// A slot that would stay with a backend factor cannot be re-created by a
// rotation (the new slot id needs a new wrap at the backend), so removing
// another slot is refused, naming the reason; nothing is written.
//
// spec: SPO-Xunlock-OUT-021
func TestRemovingAnotherSlotBesideABackendSlotIsRefused(t *testing.T) {
	s, path, rec := scratch(t)
	kb := porttest.NewFakeKeyWrap(testBackendRef)
	if _, err := s.AddBackendSlot(ctx, kb, []FactorPlan{passFactor(t, compositePass)}); err != nil {
		t.Fatal(err)
	}
	extra, err := s.AddPassphraseSlot(ctx, passphrase("a second passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	proof := presentStd(t, s, rec)
	_, _, err = s.RemoveSlotByRotation(ctx, RemoveRequest{SlotID: extra, Proof: proof, Daily: FactorInputs{Passphrase: pinOf(testPass)}})
	if err == nil || !strings.Contains(err.Error(), "backend") {
		t.Errorf("removal beside a backend slot: %v", err)
	}
	s.Close()
	if err := closed(OpenWithFactors(path, backendInputs(kb, compositePass), OpenOptions{})); err != nil {
		t.Errorf("the backend slot no longer opens: %v", err)
	}
}

// A rotation plan never carries a backend factor: its wrap would be bound to a
// slot id the rotation has not drawn, and the slot could never open.
//
// spec: SPO-Xunlock-OUT-021
func TestARotationCreatesNoBackendSlot(t *testing.T) {
	s, _, rec := scratch(t)
	bp := FactorPlan{Params: seal.FactorParams{Kind: seal.FactorBackend, ID: bytes.Repeat([]byte{1}, 32), BackendKind: "vault-transit",
		BackendAddress: "https://v", BackendKeyRef: "t/k", BackendBlob: []byte("x")}, Output: secret.Take(make([]byte, 32))}
	defer bp.Output.Destroy()
	_, _, err := s.Rotate(ctx, RotatePlan{Policy: unlock.Standard, Proof: presentStd(t, s, rec), Slots: []SlotPlan{
		{Kind: seal.SlotPassphrase, Passphrase: pw()}, {Kind: seal.SlotRecovery},
		{Kind: seal.SlotComposite, Factors: []FactorPlan{passFactor(t, compositePass), bp}}}})
	if !errors.Is(err, ErrPolicyViolated) || !strings.Contains(err.Error(), "backend") {
		t.Errorf("a rotation with a backend factor: %v", err)
	}
}

// heldRecoveryOf returns the recovery text scratch recorded for the workspace.
func heldRecoveryOf(t *testing.T, path string) string {
	t.Helper()
	var out string
	heldRecovery.Range(func(k, v any) bool {
		if s, ok := k.(*Store); ok && s.path == path {
			out = v.(string)
		}
		return true
	})
	if out == "" {
		t.Fatal("no recovery key recorded for", path)
	}
	return out
}
