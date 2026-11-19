package seal

import (
	"errors"
	"strings"
	"testing"
)

func backendParams() FactorParams {
	return FactorParams{Kind: FactorBackend, ID: rep(0xbb, 32), BackendKind: "vault-transit", BackendAddress: "https://vault.example:8200",
		BackendNamespace: "ops", BackendKeyRef: "transit/spo", BackendBlob: []byte("vault:v1:QUJDREVGR0g=")}
}

func backendSpec() SlotSpec {
	s := fidoSpec()
	s.Kind = SlotComposite
	s.Factors = []FactorParams{passParams(), backendParams()}
	return s
}

// A backend factor stores its kind, address, namespace, key reference and the
// wrapped B, and the slot's associated data binds every one: a slot whose
// stored parameters were changed (another address, another key, another blob)
// no longer opens, and the stored form round-trips exactly.
//
// spec: SPO-Xunlock-OUT-018
func TestBackendFactorParametersAreBoundAndRoundTrip(t *testing.T) {
	spec := backendSpec()
	enc, err := EncodeFactors(spec.Factors)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeFactors(enc)
	if err != nil {
		t.Fatal(err)
	}
	b := dec[1]
	if b.BackendKind != "vault-transit" || b.BackendAddress != "https://vault.example:8200" || b.BackendNamespace != "ops" ||
		b.BackendKeyRef != "transit/spo" || string(b.BackendBlob) != "vault:v1:QUJDREVGR0g=" {
		t.Fatalf("decoded %+v", b)
	}
	master, _ := NewMasterKey()
	defer master.Destroy()
	o := outs(rep(0x55, 32), rep(0x66, 32))
	defer destroy(o)
	slot, err := NewFactorSlot(spec, o, master)
	if err != nil {
		t.Fatal(err)
	}
	m, err := slot.Unwrap(o)
	if err != nil {
		t.Fatal(err)
	}
	m.Destroy()
	for name, mut := range map[string]func(*FactorParams){
		"kind":      func(f *FactorParams) { f.BackendKind = "aws-kms" },
		"address":   func(f *FactorParams) { f.BackendAddress = "https://evil.example:8200" },
		"namespace": func(f *FactorParams) { f.BackendNamespace = "" },
		"key":       func(f *FactorParams) { f.BackendKeyRef = "transit/other" },
		"blob":      func(f *FactorParams) { f.BackendBlob = []byte("vault:v1:QUJDREVGR0k=") },
	} {
		s2 := slot
		s2.Spec = backendSpec()
		mut(&s2.Spec.Factors[1])
		if _, err := s2.Unwrap(o); !errors.Is(err, ErrAuth) {
			t.Errorf("%s changed: %v", name, err)
		}
	}
}

// spec: SPO-Xunlock-PRE-016
func TestBackendFactorShapeIsChecked(t *testing.T) {
	for name, mut := range map[string]func(*FactorParams){
		"no kind":           func(f *FactorParams) { f.BackendKind = "" },
		"kind with a space": func(f *FactorParams) { f.BackendKind = "vault transit" },
		"no address":        func(f *FactorParams) { f.BackendAddress = "" },
		"no key":            func(f *FactorParams) { f.BackendKeyRef = "" },
		"no blob":           func(f *FactorParams) { f.BackendBlob = nil },
		"huge blob":         func(f *FactorParams) { f.BackendBlob = make([]byte, maxBackendBlob+1) },
		"huge namespace":    func(f *FactorParams) { f.BackendNamespace = strings.Repeat("n", 257) },
		"fido2 fields":      func(f *FactorParams) { f.HMACSalt = rep(1, 32) },
	} {
		s := backendSpec()
		mut(&s.Factors[1])
		if _, err := s.AD(rep(1, MACSize)); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// backend fields on another kind are refused
	s := backendSpec()
	s.Factors[0].BackendBlob = []byte("x")
	if _, err := s.AD(rep(1, MACSize)); !errors.Is(err, ErrFormat) {
		t.Errorf("a blob on a passphrase factor: %v", err)
	}
}
