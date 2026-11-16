package envelope

import (
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// A Hello has an empty body, travels like any message, and the receiver can
// tell its type before authorisation.
// spec: SPO-Xparty-INV-021
func TestHelloRoundTrip(t *testing.T) {
	signer, coord := newID(t, 31, "signer"), newID(t, 32, "coord")
	env, id, err := Seal(signer, coord.Identity(), party.Hello{}, t0, t0.Add(party.MaxHelloLifetime), det(5))
	if err != nil {
		t.Fatal(err)
	}
	o, err := Open(coord, env, lookupOf(enrolled(signer, "s", party.RoleSigner)), t0)
	if err != nil || o.Type() != party.TypeHello || o.ID() != id {
		t.Fatalf("Open = %v, %v", o, err)
	}
	body, err := o.Admit(func(party.MessageID) (bool, error) { return false, nil },
		func(s party.Party, ty party.Type, b party.Body) error { return party.Authorise(s, ty, party.Concern{}) })
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := body.(party.Hello); !ok {
		t.Fatalf("body = %T", body)
	}
	if party.CheckHelloExpiry(t0, t0.Add(party.MaxHelloLifetime+time.Second)) == nil {
		t.Fatal("a hello that lives past 5 minutes was accepted")
	}
}
