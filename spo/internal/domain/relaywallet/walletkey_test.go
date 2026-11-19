package relaywallet_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relaywallet"
)

func vkey(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b + byte(i)
	}
	return k
}

func keyID(t testing.TB, b byte) identity.Ref {
	t.Helper()
	id, err := identity.KeyHashOf(vkey(b))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// Only a payment key or a stake key becomes a wallet key. The loop runs over
// every role custody knows, so a role added later is refused until someone
// changes this test and the constructor on purpose.
//
// spec: SPO-Xrelaybind-SEC-012, SPO-Xrelaybind-OUT-016
func TestOnlyPaymentAndStakeBuildAWalletKey(t *testing.T) {
	id := keyID(t, 1)
	for _, role := range custody.Roles() {
		w, err := relaywallet.FromRef(custody.KeyRef{Role: role, Identity: id})
		want := role == custody.RolePayment || role == custody.RoleStake
		if want {
			if err != nil || w.IsZero() || w.Role() != role {
				t.Errorf("role %s: refused or wrong: %v", role, err)
			}
			continue
		}
		if err == nil || !errors.Is(err, relaywallet.ErrRole) || !w.IsZero() {
			t.Errorf("role %s became a wallet key (err %v)", role, err)
		}
		// the cold roles are refused for being cold, whatever else
		if role.IsCold() && err == nil {
			t.Errorf("cold role %s accepted", role)
		}
	}
	for _, role := range []custody.Role{custody.RolePoolCold, custody.RoleCommitteeCold} {
		if !role.IsCold() {
			t.Errorf("%s is no longer cold: this test names the cold roles", role)
		}
	}
	if _, err := relaywallet.FromRef(custody.KeyRef{Role: custody.Role("future-role"), Identity: id}); err == nil {
		t.Error("an unknown role became a wallet key")
	}
}

// The typed constructors take exactly Key[Payment] and Key[Stake]: a Key of any
// other role does not compile into the call. The test reads the parameter
// types, so a widened signature (a generic or an untyped reference) fails it.
//
// spec: SPO-Xrelaybind-SEC-012, SPO-Xrelaybind-OUT-016
func TestConstructorsTakeOnlyTypedPaymentAndStakeKeys(t *testing.T) {
	for name, tc := range map[string]struct {
		fn   any
		want reflect.Type
	}{
		"FromPayment": {relaywallet.FromPayment, reflect.TypeOf(custody.Key[custody.Payment]{})},
		"FromStake":   {relaywallet.FromStake, reflect.TypeOf(custody.Key[custody.Stake]{})},
	} {
		ft := reflect.TypeOf(tc.fn)
		if ft.NumIn() != 1 || ft.In(0) != tc.want {
			t.Errorf("%s takes %v, want %v", name, ft.In(0), tc.want)
		}
	}
	// no exported field: a composite literal from another package cannot build one
	rt := reflect.TypeOf(relaywallet.WalletKey{})
	for i := 0; i < rt.NumField(); i++ {
		if rt.Field(i).IsExported() {
			t.Errorf("WalletKey has the exported field %s", rt.Field(i).Name)
		}
	}
}

// The typed constructors accept a key made with custody.As and refuse the zero
// Key (anyone can write custody.Key[custody.Payment]{}) and a reference whose
// identity is not a key hash.
//
// spec: SPO-Xrelaybind-OUT-016
func TestTypedConstructorsAcceptRealKeysAndRefuseHollowOnes(t *testing.T) {
	id := keyID(t, 2)
	pk, err := custody.As[custody.Payment](custody.KeyRef{Role: custody.RolePayment, Identity: id})
	if err != nil {
		t.Fatal(err)
	}
	w, err := relaywallet.FromPayment(pk)
	if err != nil || w.IsZero() || w.Role() != custody.RolePayment || w.Ref() != pk.Ref() {
		t.Fatalf("payment: %v %+v", err, w)
	}
	sk, _ := custody.As[custody.Stake](custody.KeyRef{Role: custody.RoleStake, Identity: id})
	w, err = relaywallet.FromStake(sk)
	if err != nil || w.IsZero() || w.Role() != custody.RoleStake {
		t.Fatalf("stake: %v", err)
	}
	if _, err := relaywallet.FromPayment(custody.Key[custody.Payment]{}); !errors.Is(err, relaywallet.ErrRole) {
		t.Errorf("the zero payment key: %v", err)
	}
	if _, err := relaywallet.FromStake(custody.Key[custody.Stake]{}); !errors.Is(err, relaywallet.ErrRole) {
		t.Errorf("the zero stake key: %v", err)
	}
	vrf, err := identity.VRFKeyHashOf(vkey(3))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := relaywallet.FromRef(custody.KeyRef{Role: custody.RolePayment, Identity: vrf}); !errors.Is(err, relaywallet.ErrRole) {
		t.Errorf("a payment reference whose identity is not a key hash: %v", err)
	}
	// every identity kind of 28 bytes other than a key hash (a script hash, a
	// Calidus or Catalyst key hash, ...) is refused with the payment role
	sameSize := 0
	for _, kind := range identity.Kinds() {
		if kind == identity.KindKeyHash || kind.Size() != 28 {
			continue
		}
		ref, err := identity.NewRef(kind, id.Hash())
		if err != nil {
			t.Fatal(err)
		}
		sameSize++
		for _, role := range []custody.Role{custody.RolePayment, custody.RoleStake} {
			if _, err := relaywallet.FromRef(custody.KeyRef{Role: role, Identity: ref}); !errors.Is(err, relaywallet.ErrRole) {
				t.Errorf("a %s identity with the role %s: %v", kind, role, err)
			}
		}
	}
	if sameSize == 0 {
		t.Error("no other identity kind has 28 bytes: the test no longer tests the kind check")
	}
	if _, err := relaywallet.FromRef(custody.KeyRef{Role: custody.RolePayment}); !errors.Is(err, relaywallet.ErrRole) {
		t.Errorf("a payment reference with no identity: %v", err)
	}
	var zero relaywallet.WalletKey
	if !zero.IsZero() {
		t.Error("the zero WalletKey is not zero")
	}
}

// K is the hash in the key identity: Blake2b-224 of the verification key.
//
// spec: SPO-Xrelaybind-OUT-016
func TestKeyHashIsTheIdentityHash(t *testing.T) {
	id := keyID(t, 4)
	w, err := relaywallet.FromRef(custody.KeyRef{Role: custody.RoleStake, Identity: id})
	if err != nil {
		t.Fatal(err)
	}
	if got := w.KeyHash(); string(got[:]) != string(id.Hash()) || got == (relaybind.KeyHash{}) {
		t.Errorf("KeyHash %x, identity hash %x", got, id.Hash())
	}
}

func history(t testing.TB, id identity.Ref, roles ...custody.Role) custody.RoleHistory {
	t.Helper()
	h, err := custody.NewRoleHistory(id, roles[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range roles[1:] {
		if h, err = h.With(r); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

// A key whose role history holds a cold role is refused at use, even though the
// reference says payment or stake. The history only grows (custody.RoleHistory),
// so a key once recorded cold never passes again. A key with no history (never
// imported) passes: that is what the client cannot know.
//
// spec: SPO-Xrelaybind-SEC-013
func TestColdRoleHistoryIsRefusedAtUse(t *testing.T) {
	id := keyID(t, 5)
	w, err := relaywallet.FromRef(custody.KeyRef{Role: custody.RolePayment, Identity: id})
	if err != nil {
		t.Fatal(err)
	}
	// every role in the history: refused exactly when it is cold
	for _, role := range custody.Roles() {
		h := history(t, id, custody.RolePayment, role)
		err := w.CheckHistory(h, true, nil)
		if (role != custody.RolePayment && role != custody.RoleStake) != (err != nil) {
			t.Errorf("history payment+%s: err %v", role, err)
		}
		if role.IsCold() && !errors.Is(err, relaywallet.ErrColdHistory) {
			t.Errorf("history payment+%s: %v is not ErrColdHistory", role, err)
		}
	}
	// a history that starts cold
	if err := w.CheckHistory(history(t, id, custody.RolePoolCold), true, nil); !errors.Is(err, relaywallet.ErrColdHistory) {
		t.Errorf("a pool-cold-first history: %v", err)
	}
	// payment and stake together are fine
	if err := w.CheckHistory(history(t, id, custody.RolePayment, custody.RoleStake), true, nil); err != nil {
		t.Errorf("a payment, stake history: %v", err)
	}
}

// The default is deny: a history that holds any role outside payment and stake
// refuses. The loop runs over every role custody knows, so a role added later is
// refused until this test and the rule are changed on purpose; the cold roles
// keep their own error.
//
// spec: SPO-Xrelaybind-SEC-019
func TestAnyRoleOutsidePaymentAndStakeInTheHistoryIsRefused(t *testing.T) {
	id := keyID(t, 7)
	for _, start := range []custody.Role{custody.RolePayment, custody.RoleStake} {
		w, err := relaywallet.FromRef(custody.KeyRef{Role: start, Identity: id})
		if err != nil {
			t.Fatal(err)
		}
		for _, role := range custody.Roles() {
			okRole := role == custody.RolePayment || role == custody.RoleStake
			for _, h := range []custody.RoleHistory{history(t, id, start, role), history(t, id, role)} {
				err := w.CheckHistory(h, true, nil)
				if okRole != (err == nil) {
					t.Errorf("%s key, history %v: err %v", start, h.Roles(), err)
				}
				if role.IsCold() && !errors.Is(err, relaywallet.ErrColdHistory) {
					t.Errorf("cold role %s: %v is not ErrColdHistory", role, err)
				}
				if !okRole && !role.IsCold() && !errors.Is(err, relaywallet.ErrOtherRoleHistory) {
					t.Errorf("role %s: %v is not ErrOtherRoleHistory", role, err)
				}
			}
		}
		for _, role := range []custody.Role{custody.RoleDRep, custody.RoleCommitteeHot, custody.RolePolicy, custody.RoleKES} {
			if err := w.CheckHistory(history(t, id, start, role), true, nil); !errors.Is(err, relaywallet.ErrOtherRoleHistory) {
				t.Errorf("%s: %v", role, err)
			}
		}
	}
}

// No history at all is refused (fail closed): a key the workspace has no record
// of cannot be told apart from a cold key held elsewhere. The unknown-key variant
// exists only for a caller that says so on purpose.
//
// spec: SPO-Xrelaybind-SEC-020
func TestAKeyWithNoHistoryIsRefusedUnlessAllowedOnPurpose(t *testing.T) {
	id := keyID(t, 8)
	w, _ := relaywallet.FromRef(custody.KeyRef{Role: custody.RolePayment, Identity: id})
	if err := w.CheckHistory(custody.RoleHistory{}, false, nil); !errors.Is(err, relaywallet.ErrNoHistory) {
		t.Errorf("an unknown key: %v", err)
	}
	if err := w.CheckHistoryAllowingUnknown(custody.RoleHistory{}, false, nil); err != nil {
		t.Errorf("an unknown key, allowed on purpose: %v", err)
	}
	boom := errors.New("unreadable")
	if err := w.CheckHistoryAllowingUnknown(custody.RoleHistory{}, false, boom); !errors.Is(err, relaywallet.ErrHistoryUnreadable) {
		t.Errorf("unreadable: %v", err)
	}
	if err := w.CheckHistoryAllowingUnknown(history(t, id, custody.RolePayment, custody.RoleDRep), true, nil); !errors.Is(err, relaywallet.ErrOtherRoleHistory) {
		t.Errorf("a known other-role history: %v", err)
	}
	if err := w.CheckHistoryAllowingUnknown(history(t, id, custody.RolePoolCold), true, nil); !errors.Is(err, relaywallet.ErrColdHistory) {
		t.Errorf("a known cold history: %v", err)
	}
}

// A history that cannot be read, or that belongs to another identity, refuses:
// the cold-key rule fails closed.
//
// spec: SPO-Xrelaybind-SEC-013
func TestUnreadableOrForeignHistoryRefuses(t *testing.T) {
	id := keyID(t, 6)
	w, _ := relaywallet.FromRef(custody.KeyRef{Role: custody.RoleStake, Identity: id})
	boom := errors.New("store unreadable")
	err := w.CheckHistory(custody.RoleHistory{}, false, boom)
	if !errors.Is(err, relaywallet.ErrHistoryUnreadable) || !errors.Is(err, boom) {
		t.Errorf("an unreadable history: %v", err)
	}
	// an error with a history present is still a refusal
	if err := w.CheckHistory(history(t, id, custody.RoleStake), true, boom); !errors.Is(err, relaywallet.ErrHistoryUnreadable) {
		t.Errorf("an error beside a history: %v", err)
	}
	other := history(t, keyID(t, 9), custody.RoleStake)
	if err := w.CheckHistory(other, true, nil); !errors.Is(err, relaywallet.ErrHistoryUnreadable) {
		t.Errorf("another identity's history: %v", err)
	}
}
