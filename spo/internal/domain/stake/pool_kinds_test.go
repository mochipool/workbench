package stake

import (
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
)

// The pool certificates are attachments of a transaction: a registration pays
// the pool deposit on a first registration and nothing on an update, and each
// reports the features a signer has to understand.
//
// spec: SPO-05c-INV-009, SPO-07b-INV-002
func TestPoolCertificateKinds(t *testing.T) {
	reg := Spec{Kind: CertPoolRegistration, Pool: chain.PoolID{1}, Deposit: 500}
	if err := reg.Validate(); err != nil || reg.Paid() != 500 || reg.Refunded() != 0 {
		t.Errorf("registration: %v", err)
	}
	if err := (Spec{Kind: CertPoolRegistration}).Validate(); err != nil {
		t.Errorf("a re-registration has no deposit: %v", err)
	}
	ret := Spec{Kind: CertPoolRetirement, Pool: chain.PoolID{1}, Epoch: 9}
	if err := ret.Validate(); err != nil || ret.Paid() != 0 || ret.Refunded() != 0 {
		t.Errorf("retirement: %v", err)
	}
	if err := (Spec{Kind: CertPoolRetirement, Deposit: 1}).Validate(); !errors.Is(err, ErrBadSpec) {
		t.Errorf("a retirement carries no deposit: %v", err)
	}
	if !reg.IsPool() || !ret.IsPool() || (Spec{Kind: CertPoolDelegation}).IsPool() {
		t.Error("IsPool")
	}
	if got := reg.Features(); len(got) != 2 || got[0] != custody.FeatPoolRegistrationOper || got[1] != custody.FeatPoolRegistrationOwner {
		t.Errorf("%v", got)
	}
	if got := ret.Features(); len(got) != 1 || got[0] != custody.FeatPoolRetirement {
		t.Errorf("%v", got)
	}
	if got := (Spec{Kind: CertRegistration}).Features(); len(got) != 1 || got[0] != custody.FeatStakeRegistration {
		t.Errorf("%v", got)
	}
}
