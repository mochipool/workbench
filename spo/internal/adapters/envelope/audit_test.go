package envelope

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// A refusal before the signature step, including a revoked sender and a
// signature that does not verify, records no sender: the fingerprint is the
// claim of whoever sent the bytes.
// spec: SPO-Xparty-INV-006
func TestRefusalBeforeTheSignatureRecordsNoSender(t *testing.T) {
	a, b, other := newID(t, 1, "a"), newID(t, 2, "b"), newID(t, 3, "other")
	env := sealed(t, a, b.Identity(), goodSpec(t, a, b).bytes(t))

	revoked := enrolled(a, "a", party.RoleCoordinator)
	revoked.State = party.StateRevoked
	_, err := Open(b, env, lookupOf(revoked), t0)
	if !errors.Is(err, ErrSenderRevoked) {
		t.Fatalf("revoked: %v", err)
	}
	if _, _, known := Audit(err); known {
		t.Fatal("a revoked sender's claimed fingerprint was recorded as the sender")
	}

	// An enrolled record of that fingerprint with another signing key: the
	// signature does not verify.
	forged := enrolled(a, "a", party.RoleCoordinator)
	forged.Identity.Ed25519 = other.Identity().Ed25519
	_, err = Open(b, env, lookupOf(forged), t0)
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("forged: %v", err)
	}
	if _, _, known := Audit(err); known {
		t.Fatal("a failed signature was recorded with the claimed sender")
	}
}

// The request carries its auxiliary data and it survives the wire.
// spec: SPO-Xparty-PR-002
func TestAuxDataRoundTrip(t *testing.T) {
	a, b := newID(t, 1, "a"), newID(t, 2, "b")
	req := sampleRequest()
	req.AuxData = []byte{0xa1, 0x01, 0x02}
	raw, err := encodeBody(req)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeBody(party.TypeSigningRequest, raw)
	if err != nil || !bytes.Equal(got.(party.SigningRequest).AuxData, req.AuxData) {
		t.Fatalf("decoded = %+v, %v", got, err)
	}
	req.AuxData = make([]byte, party.MaxAuxDataBytes+1)
	if _, _, err := Seal(a, b.Identity(), req, t0, t0.Add(time.Hour), det(1)); err == nil {
		t.Fatal("sealed auxiliary data over the limit")
	}
}

// One age identity per unlocked identity, however many envelopes it opens.
func TestAgeIdentityIsBuiltOnce(t *testing.T) {
	p := newID(t, 4, "p")
	first, err := p.ageIdentity()
	if err != nil {
		t.Fatal(err)
	}
	second, _ := p.ageIdentity()
	if first != second {
		t.Fatal("the age identity was rebuilt")
	}
}
