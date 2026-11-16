package party

import (
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
)

// The refusal for unresolved inputs names the role that was asked for: a
// stake request over a network is not "a payment-key request".
//
// spec: SPO-Xparty-PRE-007, SPO-Xparty-PR-002
func TestCannotResolveInputsNamesTheActualRole(t *testing.T) {
	for _, role := range []custody.Role{custody.RoleStake, custody.RolePoolCold, custody.RolePayment} {
		got := RefuseCannotResolveInputs.Describe(role)
		if !strings.Contains(got, string(role)) {
			t.Errorf("%s: %q does not name the role", role, got)
		}
		if role != custody.RolePayment && strings.Contains(got, "payment") {
			t.Errorf("%s: %q calls it a payment-key request", role, got)
		}
	}
	if strings.Contains(RefuseCannotResolveInputs.String(), "payment") {
		t.Errorf("the generic text still says payment: %q", RefuseCannotResolveInputs.String())
	}
	if RefuseNoKey.Describe(custody.RoleStake) != RefuseNoKey.String() {
		t.Error("a reason that does not depend on the role changed")
	}
}

// AddressPaymentIsScript is false for what it cannot read: false is not a key
// verdict, so no caller may grant one from it alone.
//
// spec: SPO-Xparty-PR-004
func TestAddressPaymentIsScriptFalseIsNotAKeyVerdict(t *testing.T) {
	for _, in := range []string{"", "not bech32", "Ae2tdPwUPEZ5PxKxoyZDgjsKgMWMpTRa4PH3sVgARSGBsWwNBH3qg7cMFsP"} {
		if AddressPaymentIsScript(in) {
			t.Errorf("%q", in)
		}
	}
}
