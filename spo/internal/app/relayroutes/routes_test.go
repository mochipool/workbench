package relayroutes_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/partystore"
	"github.com/mochipool/workbench/spo/internal/app/relayroutes"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

var ctx = context.Background()

type hist struct {
	mu    sync.Mutex
	roles map[[28]byte][]custody.Role
	fail  bool
}

func (h *hist) of(_ context.Context, id identity.Ref) (custody.RoleHistory, bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.fail {
		return custody.RoleHistory{}, false, errors.New("index unreadable")
	}
	var k [28]byte
	copy(k[:], id.Hash())
	rs, ok := h.roles[k]
	if !ok {
		return custody.RoleHistory{}, false, nil
	}
	rh, err := custody.NewRoleHistory(id, rs[0])
	for _, r := range rs[1:] {
		rh, _ = rh.With(r)
	}
	return rh, true, err
}

func mkParty(n byte, name string, wallet byte) party.Party {
	k := relayporttest.DeviceKeysOf(n)
	id := party.Identity{Label: name, Ed25519: k.Ed25519, X25519: k.X25519}
	p := party.Party{Identity: id, Fingerprint: id.Fingerprint(), Name: name, Roles: []party.Role{party.RoleSigner}, State: party.StateActive}
	if wallet != 0 {
		p.Relay = &party.RelayIdentity{WalletKey: party.WalletKey(relayporttest.NewWallet(wallet).Key), Device: p.Fingerprint, From: 1, Until: 2,
			Statement: []byte{1}, Key: []byte{1}}
	}
	return p
}

// memRegistry is a registry over a slice: the routes read only List.
type memRegistry struct {
	mu sync.Mutex
	ps []party.Party
}

func (m *memRegistry) List(ports.NamedReader) ([]party.Party, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.ps), nil
}
func (m *memRegistry) ByFingerprint(ports.NamedReader, party.Fingerprint) (party.Party, error) {
	return party.Party{}, ports.ErrNotFound
}
func (m *memRegistry) ByName(ports.NamedReader, string) (party.Party, error) {
	return party.Party{}, ports.ErrNotFound
}

func newTable(t *testing.T, reg ports.PartyReader, h *hist) *relayroutes.Table {
	t.Helper()
	st, err := plainstore.OpenTestnet(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &relayroutes.Table{Store: st, Registry: reg, History: h.of, PoolIDs: noPools}
}

func noPools(context.Context) (map[[28]byte]bool, error) { return nil, nil }

// The route of a party is its wallet key and its own fingerprint; every other
// case is a miss: an unknown fingerprint, a party without a wallet key, a revoked
// party, a key of cold or other role history here, a pool id named in a scope,
// and every party when the history cannot be read.
//
// spec: SPO-Xmailbox-IF-020
func TestResolve(t *testing.T) {
	bob := mkParty(1, "bob", 1)
	nokey := mkParty(2, "nokey", 0)
	gone := mkParty(3, "gone", 3)
	gone.State = party.StateRevoked
	cold := mkParty(4, "cold", 4)
	drep := mkParty(5, "drep", 5)
	poolKey := mkParty(6, "poolkey", 6)
	var pool chain.PoolID
	copy(pool[:], poolKey.Relay.WalletKey[:])
	coord := mkParty(7, "coord", 0)
	coord.Scope = party.Scope{Pools: []string{pool.Bech32()}}
	h := &hist{roles: map[[28]byte][]custody.Role{
		cold.Relay.WalletKey: {custody.RolePayment, custody.RolePoolCold},
		drep.Relay.WalletKey: {custody.RoleDRep},
		bob.Relay.WalletKey:  {custody.RoleStake},
	}}
	reg := &memRegistry{ps: []party.Party{bob, nokey, gone, cold, drep, poolKey, coord}}
	tb := newTable(t, reg, h)
	if _, ok := tb.Resolve(bob.Fingerprint); ok {
		t.Fatal("a route before the first Refresh")
	}
	if _, err := tb.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	r, ok := tb.Resolve(bob.Fingerprint)
	if !ok || r.WalletKey != bob.Relay.WalletKey || r.Device != bob.Fingerprint {
		t.Fatalf("bob: %+v %v", r, ok)
	}
	for _, p := range []party.Party{nokey, gone, cold, drep, poolKey, coord, mkParty(9, "stranger", 9)} {
		if r, ok := tb.Resolve(p.Fingerprint); ok {
			t.Errorf("%s routes to %+v", p.Name, r)
		}
	}
	h.fail = true
	if _, err := tb.Refresh(ctx); err == nil {
		t.Fatal("an unreadable history did not fail the refresh")
	}
	if _, ok := tb.Resolve(bob.Fingerprint); ok {
		t.Fatal("a route survived a failed refresh")
	}
	if _, err := (&relayroutes.Table{Store: tb.Store, Registry: reg}).Refresh(ctx); !errors.Is(err, relayroutes.ErrNoHistory) {
		t.Fatalf("no history source: %v", err)
	}
}

// The expected senders are the wallet keys of the parties that route, in the
// order of their names, once each; Refresh says when the set changed.
//
// spec: SPO-Xmailbox-OUT-096
func TestSendersFollowTheRegistry(t *testing.T) {
	carol, bob := mkParty(2, "carol", 2), mkParty(1, "bob", 1)
	twin := mkParty(3, "bob-server", 1) // the same wallet key as bob
	reg := &memRegistry{ps: []party.Party{carol, bob, twin, mkParty(4, "nokey", 0)}}
	tb := newTable(t, reg, &hist{})
	changed, err := tb.Refresh(ctx)
	if err != nil || !changed {
		t.Fatalf("first refresh: %v %v", changed, err)
	}
	if got := tb.Senders(); len(got) != 2 || got[0] != bob.Relay.WalletKey || got[1] != carol.Relay.WalletKey {
		t.Fatalf("senders %x", got)
	}
	if changed, _ := tb.Refresh(ctx); changed {
		t.Fatal("an unchanged registry reported a change")
	}
	reg.mu.Lock()
	reg.ps = reg.ps[:1]
	reg.mu.Unlock()
	if changed, _ := tb.Refresh(ctx); !changed || len(tb.Senders()) != 1 {
		t.Fatalf("after bob left: %v %x", changed, tb.Senders())
	}
}

// The table reads the real party store.
//
// spec: SPO-Xmailbox-IF-020
func TestTableOverThePartyStore(t *testing.T) {
	st, err := plainstore.OpenTestnet(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tb := &relayroutes.Table{Store: st, Registry: partystore.Registry{}, History: (&hist{}).of, PoolIDs: noPools}
	if changed, err := tb.Refresh(ctx); err != nil || !changed {
		t.Fatalf("the first refresh of an empty registry: changed %v, %v", changed, err)
	}
	if len(tb.Senders()) != 0 {
		t.Fatal("senders from an empty registry")
	}
}
