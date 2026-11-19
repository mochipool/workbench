package party

import (
	"errors"
	"testing"
)

func relayOf(fp Fingerprint) *RelayIdentity {
	return &RelayIdentity{WalletKey: WalletKey{7}, Device: fp, From: 100, Until: 200, Statement: []byte{1}, Key: []byte{2}}
}

// A relay identity belongs to one device: the party's own fingerprint. One that
// names another device, has no wallet key, an unordered window or no evidence is
// refused, at enrollment and at rotation acceptance; nil is no relay identity.
//
// spec: SPO-Xparty-OUT-007, SPO-Xparty-INV-042
func TestCheckRelay(t *testing.T) {
	fp := mk(1, "a").id.Fingerprint()
	if err := CheckRelay(nil, fp); err != nil {
		t.Fatal(err)
	}
	if err := CheckRelay(relayOf(fp), fp); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(r *RelayIdentity){
		"another device":  func(r *RelayIdentity) { r.Device[0] ^= 1 },
		"no wallet key":   func(r *RelayIdentity) { r.WalletKey = WalletKey{} },
		"until = from":    func(r *RelayIdentity) { r.Until = r.From },
		"negative from":   func(r *RelayIdentity) { r.From = -1 },
		"no statement":    func(r *RelayIdentity) { r.Statement = nil },
		"no key evidence": func(r *RelayIdentity) { r.Key = nil },
	} {
		r := relayOf(fp)
		mut(r)
		if err := CheckRelay(r, fp); !errors.Is(err, ErrRelayIdentity) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Enrollment records the relay identity it is given, as a copy; one for another
// device enrolls nothing; and a valid relay identity never stands in for the
// typed fingerprint groups.
//
// spec: SPO-Xparty-OUT-007, SPO-Xparty-PR-007
func TestEnrollWithARelayIdentity(t *testing.T) {
	k := mk(1, "alice")
	fp := k.id.Fingerprint()
	e := Enrollment{Document: k.doc("c"), Name: "alice", Roles: []Role{RoleSigner}, Scope: testScope, Confirmation: typed(fp), Relay: relayOf(fp)}
	p, err := Enroll(e, nil, t0)
	if err != nil {
		t.Fatal(err)
	}
	if p.Relay == nil || p.Relay.WalletKey != (WalletKey{7}) || p.Relay.Device != fp {
		t.Fatalf("relay = %+v", p.Relay)
	}
	e.Relay.Statement[0] = 9
	if p.Relay.Statement[0] != 1 {
		t.Fatal("the record shares the caller's evidence bytes")
	}
	other := e
	other.Relay = relayOf(mk(2, "b").id.Fingerprint())
	if _, err := Enroll(other, nil, t0); !errors.Is(err, ErrRelayIdentity) {
		t.Fatalf("another device's binding: %v", err)
	}
	for _, c := range []string{"", "aaaa-aaaa-aaaa-aaaa"} {
		noTyped := e
		noTyped.Relay = relayOf(fp)
		noTyped.Confirmation = c
		if _, err := Enroll(noTyped, nil, t0); !errors.Is(err, ErrConfirmation) {
			t.Fatalf("typed %q with a valid binding: %v", c, err)
		}
	}
}

// Accepting a rotation without a relay identity clears it (the new identity has
// none); with one it must name the NEW fingerprint.
//
// spec: SPO-Xparty-INV-042
func TestApplyRotationRelayIdentity(t *testing.T) {
	old, next := mk(1, "old"), mk(2, "new")
	bob := enrolledOf(old, "bob", RoleSigner)
	bob.Relay = relayOf(old.id.Fingerprint())
	r := mkRotation(old, next, "stmt")
	conf := typed(next.id.Fingerprint())
	_, np, err := ApplyRotation(r, RotationAcceptance{Confirmation: conf}, []Party{bob}, t0)
	if err != nil || np.Relay != nil {
		t.Fatalf("without a binding: relay %+v, %v", np.Relay, err)
	}
	_, np, err = ApplyRotation(r, RotationAcceptance{Confirmation: conf, Relay: relayOf(next.id.Fingerprint())}, []Party{bob}, t0)
	if err != nil || np.Relay == nil || np.Relay.Device != next.id.Fingerprint() {
		t.Fatalf("with a binding: relay %+v, %v", np.Relay, err)
	}
	if _, _, err := ApplyRotation(r, RotationAcceptance{Confirmation: conf, Relay: relayOf(old.id.Fingerprint())}, []Party{bob}, t0); !errors.Is(err, ErrRelayIdentity) {
		t.Fatalf("a binding of the old identity: %v", err)
	}
}
