package ports

import (
	"reflect"
	"testing"
)

// RelayStatementSigner is its own narrow port: MessageSigner does not embed it,
// so everything that holds a MessageSigner, or reaches one through a signer
// directory, carries no way to sign a relay binding or revoke. Asserted on the
// method sets of the interfaces, so re-embedding the port (or adding the methods)
// fails here; the method set of the narrow port itself is two methods.
//
// spec: SPO-Xrelaybind-SEC-022
func TestMessageSignerCarriesNoRelayStatementMethod(t *testing.T) {
	ms := reflect.TypeOf((*MessageSigner)(nil)).Elem()
	rs := reflect.TypeOf((*RelayStatementSigner)(nil)).Elem()
	for _, name := range []string{"SignRelayBinding", "SignRelayRevoke"} {
		if _, ok := ms.MethodByName(name); ok {
			t.Errorf("MessageSigner has %s", name)
		}
		if _, ok := rs.MethodByName(name); !ok {
			t.Errorf("RelayStatementSigner lacks %s", name)
		}
	}
	if ms.Implements(rs) || reflect.TypeOf((*MessageSigner)(nil)).Elem().NumMethod() < 2 {
		t.Error("MessageSigner is, or has become, a RelayStatementSigner")
	}
}
