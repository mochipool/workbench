package relayroutes

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

type listReg struct {
	mu sync.Mutex
	ps []party.Party
}

func (m *listReg) List(ports.NamedReader) ([]party.Party, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.ps), nil
}
func (m *listReg) ByFingerprint(ports.NamedReader, party.Fingerprint) (party.Party, error) {
	return party.Party{}, ports.ErrNotFound
}
func (m *listReg) ByName(ports.NamedReader, string) (party.Party, error) {
	return party.Party{}, ports.ErrNotFound
}

func routed(n byte) party.Party {
	k := relayporttest.DeviceKeysOf(n)
	id := party.Identity{Label: "p", Ed25519: k.Ed25519, X25519: k.X25519}
	p := party.Party{Identity: id, Fingerprint: id.Fingerprint(), Name: string(rune('a' + n)), State: party.StateActive}
	p.Relay = &party.RelayIdentity{WalletKey: party.WalletKey(relayporttest.NewWallet(n).Key), Device: p.Fingerprint, From: 1, Until: 2, Statement: []byte{1}, Key: []byte{1}}
	return p
}

// Two refreshes at once never leave the older table installed: the one that
// read the registry first and finishes last does not replace the newer one
// (run under -race).
//
// spec: SPO-Xmailbox-IF-020, SPO-Xmailbox-OUT-096
func TestConcurrentRefreshKeepsTheNewerTable(t *testing.T) {
	st, err := plainstore.OpenTestnet(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	old, newer := routed(1), routed(2)
	reg := &listReg{ps: []party.Party{old}}
	tb := &Table{Store: st, Registry: reg,
		History: func(context.Context, identity.Ref) (custody.RoleHistory, bool, error) {
			return custody.RoleHistory{}, false, nil
		},
		PoolIDs: func(context.Context) (map[[28]byte]bool, error) { return nil, nil }}
	firstBuilt, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	tb.afterBuild = func() {
		if calls.Add(1) == 1 {
			close(firstBuilt)
			<-release
		}
	}
	done := make(chan error, 1)
	go func() { _, err := tb.Refresh(context.Background()); done <- err }()
	<-firstBuilt // the first refresh read the registry with only "old"
	reg.mu.Lock()
	reg.ps = []party.Party{newer}
	reg.mu.Unlock()
	if _, err := tb.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, ok := tb.Resolve(newer.Fingerprint); !ok {
		t.Fatal("the newer table was replaced by the older one")
	}
	if _, ok := tb.Resolve(old.Fingerprint); ok {
		t.Fatal("the older table is installed")
	}
}
