package partystore

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

// The registry's keys are compared byte for byte: a key that differs from a
// field's name only in case (or by Unicode folding, the long s) is refused and
// does not fill the field, at the top and inside the relay identity and the
// scope.
//
// spec: SPO-Xparty-OUT-007
func TestRegistryKeysAreExact(t *testing.T) {
	a := withRelay(t, mkParty(1, "alice"), 1)
	good, _ := json.Marshal([]partyJSON{toJSON(a)})
	s := newMem()
	s.data[recordsRef] = good
	if _, err := load1(t, s); err != nil {
		t.Fatalf("the good record: %v", err)
	}
	for name, in := range map[string][]byte{
		"two spellings of name": bytes.Replace(good, []byte(`"name":"alice"`), []byte(`"name":"alice","Name":"mallory"`), 1),
		"long s":                bytes.Replace(good, []byte(`"state":"active"`), []byte(`"ſtate":"active"`), 1),
		"capital in relay":      bytes.Replace(good, []byte(`"wallet_key"`), []byte(`"Wallet_key"`), 1),
		"capital in scope":      bytes.Replace(good, []byte(`"unscoped"`), []byte(`"UNSCOPED"`), 1),
	} {
		s.data[recordsRef] = in
		if bytes.Equal(in, good) {
			t.Fatalf("%s: the input did not change", name)
		}
		if ps, err := load1(t, s); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: loaded %+v (%v)", name, ps, err)
		}
	}
}
