package party

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

// mkRotation builds a statement the way adapters/envelope does, with a stand-in
// byte string for the content: both signatures cover it under their own domain.
func mkRotation(old, next keyset, content string) Rotation {
	r := Rotation{Old: old.id.Fingerprint(), New: next.doc("doc-" + content), Created: t0, Expires: t0.Add(24 * time.Hour), Content: []byte(content)}
	copy(r.OldSig[:], ed25519.Sign(old.priv, RotationOldMessage(r.Content)))
	copy(r.NewSig[:], ed25519.Sign(next.priv, RotationNewMessage(r.Content)))
	return r
}

func enrolledOf(k keyset, name string, roles ...Role) Party {
	return Party{Identity: k.id, Fingerprint: k.id.Fingerprint(), Name: name, Roles: roles, Scope: testScope, State: StateActive, EnrolledAt: t0}
}

// A rotation replaces the enrollment: the old record is revoked and renamed,
// the new one active with the old one's name and roles, and the scope only when
// the operator carried it over.
//
// spec: SPO-Xparty-INV-032, SPO-Xparty-PR-006
func TestApplyRotationReplacesTheEnrollment(t *testing.T) {
	old, next := mk(1, "old"), mk(2, "new")
	existing := []Party{enrolledOf(old, "bob", RoleCoordinator, RoleSigner), enrolledOf(mk(9, "other"), "carol", RoleSigner)}
	r := mkRotation(old, next, "stmt")
	retired, np, err := ApplyRotation(r, RotationAcceptance{Confirmation: typed(next.id.Fingerprint()), CarryScope: true}, existing, t0)
	if err != nil {
		t.Fatal(err)
	}
	if retired.Active() || retired.Fingerprint != old.id.Fingerprint() || retired.Name == "bob" || !strings.HasPrefix(retired.Name, "bob~") {
		t.Errorf("retired %+v", retired)
	}
	if nameRE.MatchString(retired.Name) {
		t.Errorf("a retired name %q could be an enrollment name", retired.Name)
	}
	if !np.Active() || np.Name != "bob" || np.Fingerprint != next.id.Fingerprint() || len(np.Roles) != 2 || np.Scope.Pools[0] != "pool1" {
		t.Errorf("new %+v", np)
	}
	// without the operator's yes the scope allows nothing
	_, np, err = ApplyRotation(r, RotationAcceptance{Confirmation: typed(next.id.Fingerprint())}, existing, t0)
	if err != nil || !np.Scope.Empty() {
		t.Errorf("scope carried without a yes: %+v %v", np.Scope, err)
	}
}

// Every refusal leaves the registry alone: a statement naming an identity never
// enrolled, one that replaces an identity already revoked, a replay after the
// rotation was accepted, a wrong or missing confirmation, a forged signature,
// an expired statement, a node key that is another party's.
//
// spec: SPO-Xparty-INV-032, SPO-Xparty-INV-030, SPO-Xparty-PR-006
func TestApplyRotationRefusals(t *testing.T) {
	old, next := mk(1, "old"), mk(2, "new")
	existing := []Party{enrolledOf(old, "bob", RoleSigner)}
	ok := RotationAcceptance{Confirmation: typed(next.id.Fingerprint())}
	r := mkRotation(old, next, "stmt")

	// never enrolled
	stranger := mk(7, "stranger")
	if _, _, err := ApplyRotation(mkRotation(stranger, next, "s"), ok, existing, t0); !errors.Is(err, ErrRotationUnknown) {
		t.Errorf("an identity never enrolled: %v", err)
	}
	// already revoked
	revoked := existing[0]
	revoked.State = StateRevoked
	if _, _, err := ApplyRotation(r, ok, []Party{revoked}, t0); !errors.Is(err, ErrRotationRevoked) {
		t.Errorf("an identity already revoked: %v", err)
	}
	// a replay: accept once, then the same statement against the new registry
	retired, np, err := ApplyRotation(r, ok, existing, t0)
	if err != nil {
		t.Fatal(err)
	}
	after := []Party{retired, np}
	if _, _, err := ApplyRotation(r, ok, after, t0); !errors.Is(err, ErrRotationRevoked) {
		t.Errorf("a replayed statement: %v", err)
	}
	// even if the old identity were somehow active again, the new one is enrolled
	reactivated := retired
	reactivated.State = StateActive
	if _, _, err := ApplyRotation(r, ok, []Party{reactivated, np}, t0); !errors.Is(err, ErrAlreadyEnrolled) {
		t.Errorf("a replay against an enrolled new identity: %v", err)
	}
	// confirmation
	for _, typedText := range []string{"", "aaaa-aaaa-aaaa-aaaa", typed(old.id.Fingerprint())} {
		if _, _, err := ApplyRotation(r, RotationAcceptance{Confirmation: typedText}, existing, t0); !errors.Is(err, ErrConfirmation) {
			t.Errorf("confirmation %q: %v", typedText, err)
		}
	}
	// signatures: each under the other's domain, and a flipped byte
	swapped := r
	swapped.OldSig, swapped.NewSig = r.NewSig, r.OldSig
	forgedOld := r
	copy(forgedOld.OldSig[:], ed25519.Sign(mk(5, "thief").priv, RotationOldMessage(r.Content)))
	wrongDomain := r
	copy(wrongDomain.NewSig[:], ed25519.Sign(next.priv, RotationOldMessage(r.Content)))
	for name, bad := range map[string]Rotation{"swapped": swapped, "old key not the enrolled one": forgedOld, "new key under the old domain": wrongDomain} {
		if _, _, err := ApplyRotation(bad, ok, existing, t0); !errors.Is(err, ErrRotationSignature) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// a document of the new identity that does not verify
	badDoc := r
	badDoc.New.Content = []byte("other")
	if _, _, err := ApplyRotation(badDoc, ok, existing, t0); !errors.Is(err, ErrRotationInvalid) {
		t.Errorf("a new document that does not verify: %v", err)
	}
	// expired
	if _, _, err := ApplyRotation(r, ok, existing, t0.Add(25*time.Hour)); !errors.Is(err, ErrRotationExpired) {
		t.Errorf("an expired statement: %v", err)
	}
	// a window longer than allowed
	long := mkRotation(old, next, "long")
	long.Expires = long.Created.Add(MaxRotationLifetime + time.Second)
	if _, _, err := ApplyRotation(long, ok, existing, t0); !errors.Is(err, ErrRotationInvalid) {
		t.Errorf("a window over the limit: %v", err)
	}
	// to itself
	if _, _, err := ApplyRotation(mkRotation(old, old, "same"), RotationAcceptance{Confirmation: typed(old.id.Fingerprint())}, existing, t0); !errors.Is(err, ErrRotationSame) {
		t.Errorf("old to old: %v", err)
	}
	// a node key that is another party's; the old party's own is fine
	n := NodeKey{4}
	other := enrolledOf(mk(9, "other"), "carol", RoleSigner)
	other.Identity.Node = &n
	next2 := mk(3, "new2")
	next2.id.Node = &n
	if _, _, err := ApplyRotation(mkRotation(old, next2, "n"), RotationAcceptance{Confirmation: typed(next2.id.Fingerprint())}, append([]Party{other}, existing...), t0); !errors.Is(err, ErrNodeKeyInUse) {
		t.Errorf("another party's node key: %v", err)
	}
	oldWithNode := existing[0]
	oldWithNode.Identity.Node = &n
	if _, _, err := ApplyRotation(mkRotation(old, next2, "n"), RotationAcceptance{Confirmation: typed(next2.id.Fingerprint())}, []Party{oldWithNode}, t0); err != nil {
		t.Errorf("the old party's own node key refused: %v", err)
	}
}

// A Rotation is authorised for any active enrolled party and never for an
// inactive one.
//
// spec: SPO-Xparty-INV-010, SPO-Xparty-INV-031
func TestAuthoriseRotation(t *testing.T) {
	p := enrolledOf(mk(1, "a"), "a", RoleSigner)
	if err := Authorise(p, TypeRotation, Concern{}); err != nil {
		t.Errorf("an active signer: %v", err)
	}
	p.State = StateRevoked
	if err := Authorise(p, TypeRotation, Concern{}); !errors.Is(err, ErrNotAuthorised) {
		t.Errorf("a revoked party: %v", err)
	}
	if err := (RotationAnnouncement{}).Validate(); err == nil {
		t.Error("an empty statement is valid")
	}
}
