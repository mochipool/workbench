package native

import (
	"context"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// fixedIndex is a key index of a fixed set of homes.
type fixedIndex []ports.KeyHome

func (f fixedIndex) Homes(_ context.Context, id identity.Ref) ([]ports.KeyHome, error) {
	var out []ports.KeyHome
	for _, h := range f {
		if h.Identity == id {
			out = append(out, h)
		}
	}
	return out, nil
}

type namedSigner struct{ name string }

func (s namedSigner) Profile() custody.Profile { return custody.NewProfile(s.name) }

func keyID(t *testing.T, b byte) identity.Ref {
	t.Helper()
	id, err := identity.KeyHashOf(append(make([]byte, 31), b))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// With the key held by the vault and by a device, the device answers a
// signature and the vault an operational certificate; the one documented hook
// may reorder them. With neither,
// the directory fails with the error users see for an unavailable holder.
//
// spec: SPO-Xidentity-IF-001, SPO-Xidentity-INV-016
func TestDirectoryPreferenceHardwareThenVaultThenRemote(t *testing.T) {
	id := keyID(t, 1)
	idx := fixedIndex{{Role: custody.RolePayment, Identity: id, HasSecret: true, HasHardware: true}}
	hw := namedSigner{"device"}
	remote := Remote{Party: []byte{1}, Holds: func(r identity.Ref) bool { return r == id }, Signer: namedSigner{"party"}}
	d := Signers{Vault: &stubVault{}, Keys: idx, Hardware: hw, Remotes: []Remote{remote}}
	key := custody.KeyRef{Role: custody.RolePayment, Identity: id}
	conn, err := d.Connected(key)
	if err != nil || len(conn) != 3 || conn[0].Kind != ports.SignerDevice || conn[1].Kind != ports.SignerLocal || conn[2].Kind != ports.SignerCoSigner || !conn[2].Deferred {
		t.Fatalf("%+v %v", conn, err)
	}
	// a signature: the hardware file wins (SPO-Pfiles-INV-002)
	if s, err := d.SignerFor(key); err != nil || s.Profile().Name() != "device" {
		t.Errorf("the device is preferred for a signature: %v %v", s, err)
	}
	// an operational certificate: the software key wins (SPO-04d-INV-004)
	if s, err := d.SignerForOperation(key, custody.OpIssueOpCert); err != nil || s.Profile().Name() == "device" {
		t.Errorf("the vault is preferred for an opcert: %v %v", s, err)
	}
	// both files, no device connected: the hardware file still wins, so the plan
	// refuses rather than falling back to the signing key
	nodev := Signers{Vault: &stubVault{}, Keys: idx}
	if _, err := nodev.SignerFor(key); !errors.Is(err, ports.ErrNoHardwareSigner) {
		t.Errorf("both files, no device: %v", err)
	}
	if _, err := nodev.SignerForOperation(key, custody.OpIssueOpCert); err != nil {
		t.Errorf("an opcert with both files and no device is signed by the vault: %v", err)
	}
	// The hook: an operator preference puts the vault first.
	d.Prefer = func(_ custody.KeyRef, c []ports.ConnectedSigner) []ports.ConnectedSigner {
		return []ports.ConnectedSigner{c[1], c[0]}
	}
	if s, err := d.SignerFor(key); err != nil || s.Profile().Name() == "device" {
		t.Errorf("the preference hook: %v %v", s, err)
	}
	// Nobody holds another key.
	if _, err := d.SignerFor(custody.KeyRef{Role: custody.RolePayment, Identity: keyID(t, 2)}); !errors.Is(err, ports.ErrNoSignerFor) {
		t.Errorf("an unheld key: %v", err)
	}
	// A device key with no device connected is the error users already see.
	d2 := Signers{Vault: &stubVault{}, Keys: fixedIndex{{Role: custody.RolePayment, Identity: id, HasHardware: true}}}
	if _, err := d2.SignerFor(key); !errors.Is(err, ports.ErrNoHardwareSigner) {
		t.Errorf("no hardware signer: %v", err)
	}
}

// The cold-key rule keyed on role history: a key identity recorded in a cold
// role is not demanded of a network remote, whatever role the demand names; the
// carried-file transport is allowed.
//
// spec: SPO-Xidentity-PRE-004
func TestColdRoleIdentityIsNeverDemandedOverANetwork(t *testing.T) {
	id := keyID(t, 7)
	// the same verification key is stored as a payment key and as a pool cold key
	idx := fixedIndex{
		{Role: custody.RolePayment, Identity: id},
		{Role: custody.RolePoolCold, Identity: id},
	}
	holds := func(r identity.Ref) bool { return r == id }
	net := Signers{Keys: idx, Remotes: []Remote{{Party: []byte{1}, Holds: holds, Signer: namedSigner{"net"}, Network: true}}}
	key := custody.KeyRef{Role: custody.RolePayment, Identity: id} // the demand names a payment role
	if _, err := net.Connected(key); !errors.Is(err, ports.ErrColdOverNetwork) {
		t.Fatalf("a cold-history identity over a network: %v", err)
	}
	if _, err := net.SignerFor(key); !errors.Is(err, ports.ErrColdOverNetwork) {
		t.Errorf("SignerFor: %v", err)
	}
	file := Signers{Keys: idx, Remotes: []Remote{{Party: []byte{1}, Holds: holds, Signer: namedSigner{"file"}, Network: false}}}
	if conn, err := file.Connected(key); err != nil || len(conn) != 1 {
		t.Errorf("a carried file may answer: %v %v", conn, err)
	}
	// A key never recorded in a cold role goes over a network.
	other := keyID(t, 8)
	plain := Signers{Keys: fixedIndex{{Role: custody.RolePayment, Identity: other}},
		Remotes: []Remote{{Party: []byte{1}, Holds: func(r identity.Ref) bool { return r == other }, Signer: namedSigner{"net"}, Network: true}}}
	if conn, err := plain.Connected(custody.KeyRef{Role: custody.RolePayment, Identity: other}); err != nil || len(conn) != 1 {
		t.Errorf("a non-cold key over a network: %v %v", conn, err)
	}
	// The history is computed from the stored records by the transitional function.
	h, ok, err := ports.RoleHistoryOf(context.Background(), idx, id)
	if err != nil || !ok || !h.HasColdRole() {
		t.Errorf("role history %v %v %v", h, ok, err)
	}
}

type stubVault struct{}

func (*stubVault) Open(context.Context, ports.Ref) (*secret.Buffer, error) {
	return nil, errors.New("stub")
}

// RoleHistory implements ports.KeyIndex: the roles of the homes the index holds
// for the identity, as a stored history would list them.
func (f fixedIndex) RoleHistory(_ context.Context, id identity.Ref) (custody.RoleHistory, bool, error) {
	var h custody.RoleHistory
	ok := false
	for _, home := range f {
		if home.Identity != id {
			continue
		}
		var err error
		if !ok {
			h, err = custody.NewRoleHistory(id, home.Role)
		} else {
			h, err = h.With(home.Role)
		}
		if err != nil {
			return custody.RoleHistory{}, false, err
		}
		ok = true
	}
	return h, ok, nil
}
