package hwcli_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/hwcli"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var reservedPayloads = [][]byte{
	[]byte("spo-"),
	[]byte("spo/"),
	[]byte("spo-relay-binding-v1 device 00 from 0 until 3600"),
	[]byte("spo-relay-revoke-v1 device all not-before 5"),
	[]byte("spo/relay-revoke-device/v1"),
}

// The reserved-prefix guard on the hardware message path: the session and the
// lazy signer both refuse a payload that starts with `spo-` or `spo/` before
// the device is touched, and before any hashing (a hashed request is refused
// too). An ordinary message still signs. The lazy signer refuses before it
// opens the session at all.
//
// spec: SPO-Xrelaybind-SEC-016, SPO-Xidentity-SEC-007
func TestHardwareMessagePathsRefuseReservedPayloads(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, "Keystone", "1.7.7")
	s := r.open()
	const path = "1853H/1815H/0H/0H"
	r.export(s, custody.RolePoolCold, "mypool", path)
	key := hwKey(custody.RolePoolCold, "mypool")

	before := r.called("message", "sign")
	for _, p := range reservedPayloads {
		for _, hashed := range []bool{false, true} {
			sm, err := s.SignMessage(ctx, ports.MessageRequest{Key: key, Payload: p, Hashed: hashed})
			if !errors.Is(err, relaybind.ErrReservedPayload) || sm.Sign1 != nil {
				t.Errorf("session, payload %q hashed=%v: %v", p, hashed, err)
			}
		}
	}
	// the guard is first: a raw address (unsupported) and a payment key (not offered) still say reserved
	if _, err := s.SignMessage(ctx, ports.MessageRequest{Key: key, Payload: []byte("spo-x"), Address: []byte{1}}); !errors.Is(err, relaybind.ErrReservedPayload) {
		t.Errorf("session, raw address: %v", err)
	}
	if _, err := s.SignMessage(ctx, ports.MessageRequest{Key: hwKey(custody.RolePayment, "w"), Payload: []byte("spo-x")}); !errors.Is(err, relaybind.ErrReservedPayload) {
		t.Errorf("session, payment key: %v", err)
	}
	if got := r.called("message", "sign"); got != before {
		t.Fatalf("the device was asked to sign %d times for a reserved payload", got-before)
	}

	// lazy: no session is opened for a reserved payload
	fresh := newRig(t, "Keystone", "1.7.7")
	lazy := lazyFor(fresh)
	calls := len(fresh.calls())
	for _, p := range reservedPayloads {
		sm, err := lazy.SignMessage(ctx, ports.MessageRequest{Key: key, Payload: p})
		if !errors.Is(err, relaybind.ErrReservedPayload) || sm.Sign1 != nil {
			t.Errorf("lazy, payload %q: %v", p, err)
		}
	}
	if len(fresh.calls()) != calls || lazy.Err() != nil {
		t.Errorf("the lazy signer touched the tool for a reserved payload: %d calls", len(fresh.calls())-calls)
	}

	// ordinary messages still sign, through both
	for name, sign := range map[string]func(context.Context, ports.MessageRequest) (ports.SignedMessage, error){
		"session": s.SignMessage,
		"lazy":    lazyFor(r).SignMessage,
	} {
		for _, p := range [][]byte{[]byte("hello"), []byte("spo"), []byte("Spo-x"), []byte(" spo-x")} {
			if _, err := sign(ctx, ports.MessageRequest{Key: key, Payload: p}); err != nil {
				t.Errorf("%s: ordinary payload %q refused: %v", name, p, err)
			}
		}
	}
}

// The hardware adapters do not implement the narrow RelayStatementSigner port at
// all (work package 4 adds a real hardware implementation after the real-device
// check), so a MessageSigner that reaches a hardware signer carries no way to
// sign a statement. Asserted at run time on the values and by reflection on the
// method sets of both types; the compile-level part is that MessageSigner no
// longer embeds the port (see the ports test). The profile has no payment or
// stake OpSignMessage row on any vendor, and the unsupported error stays distinct.
//
// spec: SPO-Xrelaybind-PRE-021, SPO-Xrelaybind-SEC-022
func TestHardwareAdaptersDoNotImplementTheRelayStatementPort(t *testing.T) {
	for _, vendor := range []struct{ name, app string }{{"Ledger", "8.0.8"}, {"Keystone", "1.7.7"}, {"Trezor", "2.7.2"}} {
		r := newRig(t, vendor.name, vendor.app)
		s := r.open()
		for name, v := range map[string]any{"session": s, "lazy": lazyFor(r)} {
			if _, ok := v.(ports.RelayStatementSigner); ok {
				t.Errorf("%s %s implements ports.RelayStatementSigner", vendor.name, name)
			}
		}
		for _, role := range []custody.Role{custody.RolePayment, custody.RoleStake} {
			if got := s.Profile().Check(custody.Demand{Role: role, Operation: custody.OpSignMessage}); got == "" {
				t.Errorf("%s offers message signing for a %s key before the device check", vendor.name, role)
			}
		}
	}
	for _, typ := range []reflect.Type{reflect.TypeOf((*hwcli.Session)(nil)), reflect.TypeOf((*hwcli.Lazy)(nil))} {
		for _, name := range []string{"SignRelayBinding", "SignRelayRevoke"} {
			if _, has := typ.MethodByName(name); has {
				t.Errorf("%s has the method %s", typ, name)
			}
		}
	}
	// the generic message routes remain, and the unsupported error is not a refusal of the key or the payload
	var _ ports.MessageSigner = (*hwcli.Session)(nil)
	var _ ports.MessageSigner = (*hwcli.Lazy)(nil)
	if errors.Is(ports.ErrRelayStatementUnsupported, relaybind.ErrReservedPayload) || errors.Is(ports.ErrRelayStatementUnsupported, hwcli.ErrNotSupported) {
		t.Error("ErrRelayStatementUnsupported is not distinct")
	}
}
