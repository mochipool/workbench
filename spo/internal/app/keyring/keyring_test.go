package keyring_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/app/keyring"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/ports"
)

type reader map[ports.Ref][]byte

func (r reader) Get(ref ports.Ref) ([]byte, error) {
	if b, ok := r[ref]; ok {
		return b, nil
	}
	return nil, ports.ErrNotFound
}
func (r reader) Exists(ref ports.Ref) (bool, error) { _, ok := r[ref]; return ok, nil }

func vkey(b byte) []byte {
	return []byte(`{"type":"X","description":"","cborHex":"5820` + strings.Repeat(string("0123456789abcdef"[b%16]), 64) + `"}`)
}

// The resolver turns today's (owner name, role) into the identity of the stored
// verification key, by the constructor of the role, and refuses a name with no
// verification key. The later worker re-implements it over labels.
//
// spec: SPO-Xidentity-IF-002
func TestResolveReadsTheStoredVerificationKey(t *testing.T) {
	r := reader{
		{Name: "w", Kind: ports.AddrVKey}:    vkey(1),
		{Name: "p", Kind: ports.VrfVKey}:     vkey(2),
		{Name: "w", Kind: ports.AddrSKey}:    nil,
		{Name: "h", Kind: ports.AddrVKey}:    vkey(3),
		{Name: "h", Kind: ports.AddrHwsFile}: []byte("{}"),
	}
	k, err := keyring.Resolve(r, custody.RolePayment, "w")
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = 0x11
	}
	want, _ := identity.KeyHashOf(raw)
	if k.Role != custody.RolePayment || k.Identity != want {
		t.Errorf("%v, want key-hash %v", k, want)
	}
	// the VRF key has the VRF hash, not the ledger credential hash
	v, err := keyring.Resolve(r, custody.RoleVRF, "p")
	if err != nil || v.Identity.Kind() != identity.KindVRFKeyHash {
		t.Errorf("%v %v", v, err)
	}
	// no verification key: refused
	if _, err := keyring.Resolve(r, custody.RoleStake, "w"); !errors.Is(err, keyring.ErrUnresolved) {
		t.Errorf("no stake key: %v", err)
	}
	// a key held by neither the vault nor a device is not held
	if _, held, err := keyring.ResolveHeld(r, custody.RolePayment, "w"); err != nil || !held {
		t.Errorf("w: %v %v", held, err)
	}
	if _, held, err := keyring.ResolveHeld(r, custody.RolePayment, "h"); err != nil || !held {
		t.Errorf("a hardware file holds a key: %v %v", held, err)
	}
	delete(r, ports.Ref{Name: "w", Kind: ports.AddrSKey})
	if _, held, err := keyring.ResolveHeld(r, custody.RolePayment, "w"); err != nil || held {
		t.Errorf("no signing key: %v %v", held, err)
	}
}
