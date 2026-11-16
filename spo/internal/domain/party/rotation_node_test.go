package party

import (
	"errors"
	"testing"
)

func withNode(k keyset, n NodeKey) keyset { k.id.Node = &n; return k }

// A party with a tailcat node key can rotate more than once: the revoked
// records of the earlier rotations keep the node key, and only an ACTIVE
// record counts for its uniqueness. The same node key can then also be enrolled
// again under a new name after the party was revoked.
//
// spec: SPO-Xparty-INV-032, SPO-Xparty-INV-018
func TestNodeKeyUniquenessIgnoresRevokedRecords(t *testing.T) {
	n := NodeKey{5, 5}
	a, b, c := withNode(mk(1, "a"), n), withNode(mk(2, "b"), n), withNode(mk(3, "c"), n)
	reg := []Party{enrolledOf(a, "bob", RoleSigner)}
	for i, step := range []struct{ from, to keyset }{{a, b}, {b, c}} {
		retired, next, err := ApplyRotation(mkRotation(step.from, step.to, "s"), RotationAcceptance{Confirmation: typed(step.to.id.Fingerprint())}, reg, t0)
		if err != nil {
			t.Fatalf("rotation %d: %v", i+1, err)
		}
		for j := range reg {
			if reg[j].Fingerprint == retired.Fingerprint {
				reg[j] = retired
			}
		}
		reg = append(reg, next)
	}
	// Enrolling the same node key again while an ACTIVE record holds it is refused.
	d := withNode(mk(4, "d"), n)
	doc := d.doc("doc-d")
	e := Enrollment{Document: doc, Name: "dave", Roles: []Role{RoleSigner}, Confirmation: typed(d.id.Fingerprint())}
	if _, err := Enroll(e, reg, t0); !errors.Is(err, ErrNodeKeyInUse) {
		t.Fatalf("a node key held by an active record: %v", err)
	}
	// Revoke the active one: the key is free again for a new enrollment.
	last := reg[len(reg)-1]
	last.State = StateRevoked
	reg[len(reg)-1] = last
	if _, err := Enroll(e, reg, t0); err != nil {
		t.Fatalf("re-enrolling a node key whose records are all revoked: %v", err)
	}
	// The allow-list holds a node key once, for the active identity only.
	reg2 := append(append([]Party{}, reg...), enrolledOf(d, "dave", RoleSigner))
	if keys := AllowedNodeKeys(reg2); len(keys) != 1 || keys[0] != n {
		t.Errorf("allow-list %v", keys)
	}
	if keys := AllowedNodeKeys(reg); len(keys) != 0 {
		t.Errorf("a node key whose records are all revoked is allowed: %v", keys)
	}
}

// The node key is not part of what a rotation changes: a statement whose new
// identity has another node key, or gains or loses one, is refused.
//
// spec: SPO-Xparty-INV-030, SPO-Xparty-INV-032
func TestApplyRotationRefusesAChangedNodeKey(t *testing.T) {
	n, m := NodeKey{1}, NodeKey{2}
	for name, c := range map[string]struct{ old, new *NodeKey }{
		"another key": {&n, &m}, "gained": {nil, &m}, "lost": {&n, nil},
	} {
		o, nx := mk(1, "o"), mk(2, "n")
		o.id.Node, nx.id.Node = c.old, c.new
		reg := []Party{enrolledOf(o, "bob", RoleSigner)}
		_, _, err := ApplyRotation(mkRotation(o, nx, "s"), RotationAcceptance{Confirmation: typed(nx.id.Fingerprint())}, reg, t0)
		if !errors.Is(err, ErrRotationNodeKey) {
			t.Errorf("%s: %v", name, err)
		}
	}
	o, nx := withNode(mk(1, "o"), n), withNode(mk(2, "n"), n)
	if _, _, err := ApplyRotation(mkRotation(o, nx, "s"), RotationAcceptance{Confirmation: typed(nx.id.Fingerprint())}, []Party{enrolledOf(o, "bob", RoleSigner)}, t0); err != nil {
		t.Errorf("the same node key: %v", err)
	}
}
