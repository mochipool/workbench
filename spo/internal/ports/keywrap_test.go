package ports_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/porttest"
)

// The Vault associated data is the canonical CBOR of [nonce, slot id], the
// same bytes the seal package's encoder gives, and the KMS context is the two
// ids in lower-case hex under the names of decision 5.
//
// spec: SPO-Xunlock-IN-004
func TestWrapContextEncodings(t *testing.T) {
	n, s := bytes.Repeat([]byte{0xab}, 16), bytes.Repeat([]byte{0x01}, 16)
	wc := ports.WrapContext{GenesisNonce: n, SlotID: s}
	got, err := wc.Encode()
	if err != nil {
		t.Fatal(err)
	}
	want, err := seal.EncodeCanonical([]any{n, s})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) || len(got) != 35 {
		t.Fatalf("encode %x, want %x", got, want)
	}
	m, err := wc.KMSContext()
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 || m["spo-genesis"] != "abababababababababababababababab" || m["spo-slot"] != "01010101010101010101010101010101" {
		t.Fatalf("kms context %v", m)
	}
	for _, bad := range []ports.WrapContext{{GenesisNonce: n[:15], SlotID: s}, {GenesisNonce: n, SlotID: append(s, 0)}, {}} {
		if _, err := bad.Encode(); !errors.Is(err, ports.ErrBackendConfig) {
			t.Errorf("%x/%x encoded: %v", bad.GenesisNonce, bad.SlotID, err)
		}
		if _, err := bad.KMSContext(); !errors.Is(err, ports.ErrBackendConfig) {
			t.Errorf("%x/%x gave a KMS context: %v", bad.GenesisNonce, bad.SlotID, err)
		}
	}
}

// spec: SPO-Xunlock-IF-007
func TestBackendRefValidate(t *testing.T) {
	ok := ports.BackendRef{Kind: ports.BackendVaultTransit, Address: "https://vault.example:8200", Namespace: "ops", Key: "transit/spo"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, r := range map[string]ports.BackendRef{
		"unknown kind":      {Kind: "gcp-kms", Address: "https://x", Key: "k"},
		"no address":        {Kind: ports.BackendVaultTransit, Key: "k"},
		"no key":            {Kind: ports.BackendVaultTransit, Address: "https://x"},
		"space in key":      {Kind: ports.BackendVaultTransit, Address: "https://x", Key: "a b"},
		"newline":           {Kind: ports.BackendVaultTransit, Address: "https://x\n", Key: "k"},
		"kms namespace":     {Kind: ports.BackendAWSKMS, Address: "https://x", Namespace: "n", Key: "arn"},
		"address too long":  {Kind: ports.BackendAWSKMS, Address: string(bytes.Repeat([]byte{'a'}, 513)), Key: "arn"},
		"namespace control": {Kind: ports.BackendVaultTransit, Address: "https://x", Namespace: "a\x1b", Key: "k"},
	} {
		if err := r.Validate(); !errors.Is(err, ports.ErrBackendConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The fake backend the store tests use passes the contract, so the contract
// is not vacuous and the fake behaves as a backend must.
//
// spec: SPO-Xunlock-IF-007, SPO-Xunlock-SEC-008
func TestFakeKeyWrapPassesTheContract(t *testing.T) {
	porttest.KeyWrapContract(t, porttest.KeyWrapSubject{Backend: porttest.NewFakeKeyWrap(ports.BackendRef{Kind: ports.BackendVaultTransit, Address: "http://127.0.0.1:1", Key: "transit/k"})})
}

// A slot's reference is a claim: every field must equal the local one, and the
// refusal shows both.
//
// spec: SPO-Xunlock-PRE-045
func TestCheckBackendClaim(t *testing.T) {
	local := ports.BackendRef{Kind: ports.BackendVaultTransit, Address: "https://vault.example:8200", Namespace: "ops", Key: "transit/k"}
	if err := ports.CheckBackendClaim(local, local); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*ports.BackendRef){
		func(r *ports.BackendRef) { r.Kind = ports.BackendAWSKMS },
		func(r *ports.BackendRef) { r.Address += "/" },
		func(r *ports.BackendRef) { r.Namespace = "Ops" },
		func(r *ports.BackendRef) { r.Key = "transit/K" },
	} {
		claim := local
		edit(&claim)
		err := ports.CheckBackendClaim(claim, local)
		if !errors.Is(err, ports.ErrBackendMismatch) || !strings.Contains(err.Error(), claim.String()) || !strings.Contains(err.Error(), local.String()) {
			t.Errorf("%v: %v", claim, err)
		}
	}
}
