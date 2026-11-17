package custody

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/identity"
)

// holder is a test device for a key: the first byte of the identity says which
// signer answers. A key reference carries no holder (ADR 0010).
type holder byte

const (
	HolderVault    holder = 1
	HolderHardware holder = 2
	HolderRemote   holder = 3
)

func (h holder) String() string { return [...]string{"", "vault", "hardware", "remote"}[h] }

var allRoles = []Role{RolePayment, RoleStake, RolePoolCold, RoleDRep, RoleCommitteeCold, RoleCommitteeHot, RolePolicy, RoleCalidus, RoleCatalystVote}

// A software signer signs a body hash: every role, every operation, any feature.
func software() Profile {
	p := NewProfile("vault")
	for _, r := range allRoles {
		p = p.Allow(r, OpWitnessTx, OpSignMessage, OpExportVKey)
	}
	return p.Allow(RolePoolCold, OpIssueOpCert)
}

// A device that knows payments, staking and pool registration as owner, but
// has no governance support and cannot issue opcerts.
func oldDevice() Profile {
	return NewProfile("old device").
		AllowTx(RolePayment, FeatMultiAssetOutput, FeatWithdrawal, FeatStakeRegistration, FeatStakeDelegation, FeatPoolRegistrationOwner).
		AllowTx(RoleStake, FeatWithdrawal, FeatStakeRegistration, FeatStakeDelegation, FeatPoolRegistrationOwner).
		Allow(RolePayment, OpExportVKey).
		Allow(RoleStake, OpExportVKey)
}

func profiles(k KeyRef) (Profile, error) {
	switch holder(k.Identity.Hash()[0]) {
	case HolderVault:
		return software(), nil
	case HolderHardware:
		return oldDevice(), nil
	}
	return Profile{}, errors.New("no signer is configured for this key")
}

func key(role Role, h holder) KeyRef {
	hash := make([]byte, 28)
	hash[0] = byte(h)
	id, err := identity.NewRef(identity.KindKeyHash, hash)
	if err != nil {
		panic(err)
	}
	return KeyRef{Role: role, Identity: id}
}

func TestSameWorkflowDifferentHolders(t *testing.T) {
	// One workflow: a pool registration with an owner stake witness and a payer.
	slots := func(owner, payer holder) []Slot {
		return []Slot{
			{"owner witness", key(RoleStake, owner), Demand{RoleStake, OpWitnessTx, NewFeatures(FeatPoolRegistrationOwner)}},
			{"fee payer", key(RolePayment, payer), Demand{RolePayment, OpWitnessTx, NewFeatures(FeatPoolRegistrationOwner)}},
		}
	}
	for _, c := range [][2]holder{{HolderVault, HolderVault}, {HolderHardware, HolderVault}, {HolderHardware, HolderHardware}} {
		plan, err := NewPlan(slots(c[0], c[1]), profiles)
		if err != nil || len(plan.Slots()) != 2 {
			t.Errorf("owner=%s payer=%s: %v", c[0], c[1], err)
		}
	}
}

func TestDeviceWithoutAFeatureIsRefusedUpFront(t *testing.T) {
	vote := Demand{RolePayment, OpWitnessTx, NewFeatures(FeatVote, FeatMetadata)}
	// The vault can pay for a vote transaction.
	if _, err := NewPlan([]Slot{{"fee payer", key(RolePayment, HolderVault), vote}}, profiles); err != nil {
		t.Fatal(err)
	}
	// The old device cannot, and the refusal names what is missing.
	_, err := NewPlan([]Slot{{"fee payer", key(RolePayment, HolderHardware), vote}}, profiles)
	var ue *UnsupportedError
	if !errors.As(err, &ue) || len(ue.Problems) != 1 {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "metadata") || !strings.Contains(err.Error(), "vote") || !strings.Contains(err.Error(), "fee payer") {
		t.Fatalf("refusal does not say what is missing: %v", err)
	}
}

func TestEveryProblemIsReportedAtOnce(t *testing.T) {
	_, err := NewPlan([]Slot{
		{"opcert", key(RolePoolCold, HolderHardware), Demand{RolePoolCold, OpIssueOpCert, nil}},
		{"vote", key(RoleDRep, HolderHardware), Demand{RoleDRep, OpWitnessTx, NewFeatures(FeatVote)}},
		{"payer", key(RolePayment, HolderRemote), Demand{RolePayment, OpWitnessTx, nil}},
		{"mismatch", key(RoleStake, HolderVault), Demand{RolePayment, OpWitnessTx, nil}},
	}, profiles)
	var ue *UnsupportedError
	if !errors.As(err, &ue) || len(ue.Problems) != 4 {
		t.Fatalf("want 4 problems, got %v", err)
	}
}

func TestAPlanCannotBeMadeWithoutChecks(t *testing.T) {
	if !(Plan{}).Empty() {
		t.Fatal("zero Plan is not empty")
	}
	if _, err := NewPlan(nil, profiles); err == nil {
		t.Fatal("empty plan accepted")
	}
}

func TestTypedKeysRejectTheWrongRole(t *testing.T) {
	if _, err := As[PoolCold](key(RolePoolCold, HolderVault)); err != nil {
		t.Fatal(err)
	}
	if _, err := As[PoolCold](key(RolePayment, HolderVault)); !errors.Is(err, ErrWrongRole) {
		t.Fatalf("err = %v", err)
	}
}

func TestProfilesAreImmutable(t *testing.T) {
	base := NewProfile("x")
	_ = base.Allow(RolePayment, OpWitnessTx)
	if base.Check(Demand{RolePayment, OpWitnessTx, nil}) == "" {
		t.Fatal("Allow changed the receiver")
	}
}

// A key reference is a role and an identity: it prints both, and it carries no
// holder, owner, device or party (ADR 0010 decision 3). Two references to the
// same key are equal, whoever answers for it.
//
// spec: SPO-Xidentity-IF-001
func TestKeyRefIsRoleAndIdentityOnly(t *testing.T) {
	k := key(RoleStake, HolderVault)
	if got := k.String(); !strings.Contains(got, "stake") || !strings.Contains(got, k.Identity.String()) {
		t.Errorf("String %q", got)
	}
	if k != key(RoleStake, HolderVault) {
		t.Error("the same key is two references")
	}
	if k == key(RoleStake, HolderHardware) || k == key(RolePayment, HolderVault) {
		t.Error("two keys, or one key in two roles, are one reference")
	}
	typ := reflect.TypeOf(k)
	for i := 0; i < typ.NumField(); i++ {
		if n := typ.Field(i).Name; n != "Role" && n != "Identity" {
			t.Errorf("KeyRef has the field %s", n)
		}
	}
}
