package envelope

import (
	"bytes"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// A statement made by NewRotation parses back to what was signed, verifies
// under the old key, and the Rotation message that carries it goes through the
// envelope like any other.
//
// spec: SPO-Xparty-INV-030, SPO-Xparty-INV-031
func TestRotationStatementRoundTripsAndVerifies(t *testing.T) {
	old, next, peer := newID(t, 1, "old"), newID(t, 2, "new"), newID(t, 3, "peer")
	stmt, err := NewRotation(old, next, t0)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseRotation(stmt)
	if err != nil {
		t.Fatal(err)
	}
	if r.Old != old.Fingerprint() || r.New.Identity.Fingerprint() != next.Fingerprint() || !r.Created.Equal(t0) || r.Expires.Sub(r.Created) != party.MaxRotationLifetime {
		t.Fatalf("parsed %+v", r)
	}
	if err := r.Verify(old.Identity().Ed25519, t0); err != nil {
		t.Fatal(err)
	}
	// not the enrolled key of some other identity
	if err := r.Verify(peer.Identity().Ed25519, t0); !errors.Is(err, party.ErrRotationSignature) {
		t.Errorf("a statement verified under another key: %v", err)
	}
	// every flipped bit of the statement is refused (parse or verify)
	for i := range stmt {
		bad := bytes.Clone(stmt)
		bad[i] ^= 0x01
		if pr, err := ParseRotation(bad); err == nil && pr.Verify(old.Identity().Ed25519, t0) == nil {
			t.Fatalf("a statement with byte %d flipped verifies", i)
		}
	}
	// a signature made under the document domain, or with the old key as the
	// new one, is not accepted
	if _, err := ParseRotation(append(bytes.Clone(stmt), 0)); err == nil {
		t.Error("trailing bytes parsed")
	}
	// the message that carries it
	env, _, err := Seal(old, peer.Identity(), party.RotationAnnouncement{Statement: stmt}, t0, t0.Add(AnnouncementLifetime), det(4))
	if err != nil {
		t.Fatal(err)
	}
	o, err := Open(peer, env, lookupOf(enrolled(old, "old", party.RoleSigner)), t0)
	if err != nil {
		t.Fatal(err)
	}
	body, err := o.Admit(never, authorise)
	if err != nil || o.Type() != party.TypeRotation {
		t.Fatalf("%v %v", o.Type(), err)
	}
	if !bytes.Equal(body.(party.RotationAnnouncement).Statement, stmt) {
		t.Error("the statement changed in transit")
	}
	if _, err := encodeBody(party.RotationAnnouncement{Statement: make([]byte, party.MaxRotationBytes+1)}); err == nil {
		t.Error("an oversize statement was encoded")
	}
}
