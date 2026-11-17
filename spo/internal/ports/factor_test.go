package ports

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

func assertion(up, uv bool) Assertion {
	return Assertion{Output: secret.Take(make([]byte, 32)), NextOutput: secret.Take(make([]byte, 32)), UP: up, UV: uv}
}

// spec: SPO-Xunlock-PRE-003, SPO-Xunlock-INV-003
func TestRequireRefusesAMissingFlagAndDestroysTheOutputs(t *testing.T) {
	for _, c := range []struct {
		name     string
		up, uv   bool
		req      Requirement
		refuse   bool
		whatFlag string
	}{
		{"both set, both required", true, true, Requirement{true, true}, false, ""},
		{"UV missing, required", true, false, Requirement{true, true}, true, "user-verification"},
		{"UP missing, required", false, true, Requirement{true, true}, true, "user-presence"},
		{"UP missing, not required", false, true, Requirement{false, true}, false, ""},
		{"UV missing, not required", true, false, Requirement{true, false}, false, ""},
		{"nothing required, nothing set", false, false, Requirement{}, false, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := assertion(c.up, c.uv)
			defer a.Destroy()
			err := a.Require(c.req)
			if !c.refuse {
				if err != nil || a.Output.Len() != 32 {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrFactorFlags) {
				t.Fatalf("got %v", err)
			}
			if a.Output.Len() != 0 || a.NextOutput.Len() != 0 {
				t.Fatal("a refused assertion still holds its outputs")
			}
		})
	}
}

// spec: SPO-Xunlock-IF-002, SPO-Xunlock-INV-003
func TestCheckFactorProfileNamesEveryMissingCapability(t *testing.T) {
	full := FactorProfile{HMACSecret: true, TwoSalts: true, CredProtect3: true, UserVerification: true, CTAP21: true}
	if err := CheckFactorProfile(full, NeedsOfColdSubKey); err != nil {
		t.Fatal(err)
	}
	err := CheckFactorProfile(FactorProfile{HMACSecret: true, UserVerification: true, CTAP21: true}, NeedsOfColdSubKey)
	if !errors.Is(err, ErrFactorCapability) {
		t.Fatalf("got %v", err)
	}
	for _, want := range []string{"two salts", "credProtect level 3"} {
		if !contains(err.Error(), want) {
			t.Fatalf("%q is not named in %q", want, err)
		}
	}
	if contains(err.Error(), "hmac-secret") {
		t.Fatalf("a capability the source has is named: %q", err)
	}
	if err := CheckFactorProfile(FactorProfile{}, 0); err != nil {
		t.Fatalf("no need, no refusal: %v", err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// spec: SPO-Xunlock-IN-002
func TestFactorIDIsFixedAndDependsOnTheCredential(t *testing.T) {
	// printf 'spo/factor-id/fido2-credential\0credential-1' | sha256sum
	const want = "0e666786563f1ee92fda1ee2c202c90efd258ad0bf884320bc668db0411ae641"
	got := FactorIDOf([]byte("credential-1"))
	if hex.EncodeToString(got) != want || len(got) != FactorIDSize {
		t.Fatalf("got %x", got)
	}
	if hex.EncodeToString(FactorIDOf([]byte("credential-2"))) == want {
		t.Fatal("another credential, the same factor id")
	}
}
