package sqlitestore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/porttest"
)

// rewriteBackendRef replaces the backend reference a slot stores, and its
// factor id, as whoever can write the workspace file or a backup can: the slot
// row is not authenticated until the slot opens.
func rewriteBackendRef(t *testing.T, path string, slotID []byte, ref ports.BackendRef) {
	t.Helper()
	p := pw()
	defer p.Destroy()
	s, err := Open(path, p)
	if err != nil {
		t.Fatal(err)
	}
	tb, err := s.currentTable(ctx)
	s.Close()
	if err != nil {
		t.Fatal(err)
	}
	for _, ts := range tb.slots {
		if !bytes.Equal(ts.id, slotID) {
			continue
		}
		fs := append([]seal.FactorParams(nil), ts.fs.Spec.Factors...)
		for i := range fs {
			if fs[i].Kind == seal.FactorBackend {
				fs[i].BackendKind, fs[i].BackendAddress, fs[i].BackendNamespace, fs[i].BackendKeyRef = string(ref.Kind), ref.Address, ref.Namespace, ref.Key
				if fs[i].ID, err = backendFactorID(ref); err != nil {
					t.Fatal(err)
				}
			}
		}
		enc, err := seal.EncodeFactors(fs)
		if err != nil {
			t.Fatal(err)
		}
		db := rawDB(t, path)
		if _, err := db.Exec(`UPDATE keyslots SET factors = ? WHERE id = ?`, enc, slotID); err != nil {
			t.Fatal(err)
		}
		db.Close()
		return
	}
	t.Fatal("no such slot")
}

// claimInputs counts what an open asks for: the resolver (which loads the
// credential and then calls the backend) and the composite's passphrase.
type claimInputs struct {
	kb                ports.KeyWrapBackend
	resolved, prompts int
}

func (c *claimInputs) inputs() FactorInputs {
	return FactorInputs{
		Backend: func(context.Context, ports.BackendRef) (ports.KeyWrapBackend, error) {
			c.resolved++
			return c.kb, nil
		},
		Passphrase: func(context.Context) (*secret.Buffer, error) {
			c.prompts++
			return secret.Take([]byte(compositePass)), nil
		},
		BackendCheck: localConfig(testBackendRef),
	}
}

// The review's proof of concept: whoever can edit the workspace file (or a
// backup) changes the address a backend slot stores to a server of theirs. An
// open must refuse that slot before the resolver is asked (no credential is
// loaded, nothing is sent) and before the composite's passphrase is asked for,
// with an error that shows both addresses. The same holds for every other path
// that opens a file through its factors: verify, restore, the export of a
// layout. Inputs with no local check at all fail closed the same way.
//
// spec: SPO-Xunlock-IF-012, SPO-Xunlock-PRE-045
func TestAnEditedBackendAddressIsRefusedBeforeAnyCredentialOrPrompt(t *testing.T) {
	path, kb, id := standardWithBackend(t)
	evil := testBackendRef
	evil.Address = "https://attacker.example:8200"
	rewriteBackendRef(t, path, id, evil)

	c := &claimInputs{kb: porttest.NewFakeKeyWrap(evil)}
	check := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, ports.ErrBackendMismatch) || !errors.Is(err, ErrBackendFactor) {
			t.Errorf("%s: %v", what, err)
		}
		if err != nil && (!strings.Contains(err.Error(), evil.Address) || !strings.Contains(err.Error(), testBackendRef.Address) || !strings.Contains(err.Error(), "altered")) {
			t.Errorf("%s: the error does not show both addresses and the cause: %v", what, err)
		}
		if c.resolved != 0 || c.prompts != 0 {
			t.Fatalf("%s: the resolver was asked %d times and the passphrase %d times before the claim was checked: %v", what, c.resolved, c.prompts, err)
		}
	}
	_, err := OpenWithFactors(path, c.inputs(), OpenOptions{})
	check("open", err)
	_, err = VerifyFileFactors(path, c.inputs(), false)
	check("verify", err)
	_, err = VerifyFileFactors(path, c.inputs(), true)
	check("verify --deep", err)
	err = RestoreWithFactors(path, filepath.Join(t.TempDir(), "restored.db"), c.inputs(), RestoreOptions{})
	check("restore", err)
	in := c.inputs()
	_, err = TakeExport(ctx, path, SnapshotCredential{Factors: &in})
	check("layout export", err)
	// with no local configuration to check against: fail closed, nothing asked
	in = c.inputs()
	in.BackendCheck = nil
	_, err = OpenWithFactors(path, in, OpenOptions{})
	if !errors.Is(err, ports.ErrBackendMismatch) || c.resolved != 0 || c.prompts != 0 {
		t.Errorf("no local check: %v (resolver %d, passphrase %d)", err, c.resolved, c.prompts)
	}
	// each field of the reference is compared: kind, namespace and key too
	for name, edit := range map[string]func(*ports.BackendRef){
		"namespace": func(r *ports.BackendRef) { r.Namespace = "other" },
		"key":       func(r *ports.BackendRef) { r.Key = "transit/other" },
		"kind":      func(r *ports.BackendRef) { r.Kind = ports.BackendAWSKMS; r.Namespace = "" },
	} {
		path2, _, id2 := standardWithBackend(t)
		r := testBackendRef
		edit(&r)
		rewriteBackendRef(t, path2, id2, r)
		_, err := OpenWithFactors(path2, c.inputs(), OpenOptions{})
		if !errors.Is(err, ports.ErrBackendMismatch) || c.resolved != 0 || c.prompts != 0 {
			t.Errorf("%s: %v", name, err)
		}
	}
	// the unedited reference still opens, and the open asks in the order: the
	// check, the passphrase, then the resolver
	path3, kb3, _ := standardWithBackend(t)
	ok := &claimInputs{kb: kb3}
	s, err := OpenWithFactors(path3, ok.inputs(), OpenOptions{})
	if err != nil {
		t.Fatalf("the unedited slot: %v", err)
	}
	s.Close()
	if ok.resolved != 1 || ok.prompts != 1 {
		t.Errorf("resolver %d, passphrase %d", ok.resolved, ok.prompts)
	}
	_ = kb
}

// CheckBackendSlot gives the refusals of AddBackendSlot with no backend and no
// other factor: a command runs it before it makes a FIDO2 credential.
//
// spec: SPO-Xunlock-PRE-044, SPO-Xunlock-PRE-043
func TestCheckBackendSlotRefusesWithoutAnyCall(t *testing.T) {
	path, f, _ := hardwareWS(t)
	h, err := openHW(path, f, "devA", "1234")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	count := func() int { return f.enrols + f.asserts + f.profiles + f.pinChecks }
	calls := count()
	if err := h.CheckBackendSlot(ctx, testBackendRef, []seal.FactorKind{seal.FactorPassphrase}); !errors.Is(err, ErrPolicyViolated) {
		t.Errorf("hardware, backend and a passphrase: %v", err)
	}
	if err := h.CheckBackendSlot(ctx, testBackendRef, nil); !errors.Is(err, ErrPolicyViolated) {
		t.Errorf("a backend alone: %v", err)
	}
	if err := h.CheckBackendSlot(ctx, testBackendRef, []seal.FactorKind{seal.FactorFIDO2}); err != nil {
		t.Errorf("hardware, backend and a new FIDO2 credential: %v", err)
	}
	if err := h.CheckBackendSlot(ctx, ports.BackendRef{Kind: "gcp"}, []seal.FactorKind{seal.FactorFIDO2}); err == nil {
		t.Error("an invalid reference")
	}
	if count() != calls {
		t.Errorf("the authenticator was asked %d times", count()-calls)
	}
}

// A backend failure ends the open (fail closed) and the error names the slot
// and says that another way in remains.
//
// spec: SPO-Xunlock-OUT-020
func TestABackendFailureNamesTheSlotAndTheOtherWayIn(t *testing.T) {
	path, kb, id := standardWithBackend(t)
	kb.Fail = porttest.ErrFakeDown
	_, err := OpenWithFactors(path, backendInputs(kb, compositePass), OpenOptions{})
	if !errors.Is(err, ErrBackendFactor) || !strings.Contains(err.Error(), fmt.Sprintf("slot %x", id[:4])) || !strings.Contains(err.Error(), "--unlock passphrase") {
		t.Errorf("%v", err)
	}
}

// A backend that ignores the associated data (a Vault without associated_data
// support that does not warn, a server that drops it) unwraps a blob under any
// slot id. Enrolment detects it: after the round trip it unwraps under another
// slot id and requires a refusal; nothing is added.
//
// spec: SPO-Xunlock-OUT-019
func TestBackendEnrolmentRefusesABackendThatIgnoresTheContext(t *testing.T) {
	s, _, _ := scratch(t)
	kb := porttest.NewFakeKeyWrap(testBackendRef)
	kb.IgnoreContext = true
	before, _ := s.currentTable(ctx)
	_, err := s.AddBackendSlot(ctx, kb, []FactorPlan{passFactor(t, compositePass)})
	if !errors.Is(err, ErrBackendFactor) || !errors.Is(err, ports.ErrBackendConfig) || !strings.Contains(err.Error(), "associated data") {
		t.Errorf("a backend that ignores its context: %v", err)
	}
	after, _ := s.currentTable(ctx)
	if len(after.slots) != len(before.slots) {
		t.Error("a slot was added")
	}
	kb.IgnoreContext = false
	if _, err := s.AddBackendSlot(ctx, kb, []FactorPlan{passFactor(t, compositePass)}); err != nil {
		t.Errorf("a backend that binds its context: %v", err)
	}
}
