package mailbox

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"

	"context"
)

type closingDialer struct{ closed atomic.Bool }

func (*closingDialer) Dial(ctx context.Context) (relayport.Stream, party.NodeKey, error) {
	return nil, party.NodeKey{}, ctx.Err()
}
func (d *closingDialer) CloseWithin(time.Duration) error { d.closed.Store(true); return nil }

// Logout is bounded even when a goroutine of the composite does not end at
// Close: it closes the dialers all the same and says that the tunnel did not
// stop, never that it logged out (SPO-Xmailbox-OUT-117, INV-039).
//
// spec: SPO-Xmailbox-OUT-117, SPO-Xmailbox-INV-039
func TestLogoutIsBoundedWhenTheCompositeDoesNotClose(t *testing.T) {
	dev := relayporttest.Device(6)
	w := relayporttest.NewWallet(6)
	st := w.BindingStatement(dev, 1_700_000_000-60, 1_700_000_000+30*24*3600, false)
	c, err := New(Config{Dialer: idleDialer{}, RelayKey: party.NodeKey{1}, NodeKey: party.NodeKey{2}, Self: dev,
		Device:  relayporttest.DeviceKeysOf(6),
		Binding: Binding{Statement: st.Sign1, Key: st.COSEKey},
		Resolve: func(party.Fingerprint) (Route, bool) { return Route{}, false },
		Signer:  idleSigner{}, Clock: wallClock{}})
	if err != nil {
		t.Fatal(err)
	}
	d := &closingDialer{}
	m, err := NewMulti(MultiConfig{Members: []Member{{Name: "one", Client: c, Dialer: d}}})
	if err != nil {
		t.Fatal(err)
	}
	// a goroutine of the composite that does not end with Close (a member's
	// receive stuck in the tunnel library)
	if !m.enter() {
		t.Fatal("closed at once")
	}
	release := make(chan struct{})
	go func() { <-release; m.wg.Done() }()
	began := time.Now()
	err = m.Logout(50 * time.Millisecond)
	if !errors.Is(err, ErrTunnelDidNotStop) {
		t.Fatalf("a logout whose composite did not close: %v", err)
	}
	if d := time.Since(began); d > 5*time.Second {
		t.Fatalf("the logout took %v, past its bound", d)
	}
	if !d.closed.Load() {
		t.Fatal("the dialer was not closed")
	}
	close(release)
	// once it ends, a second logout is clean
	if err := m.Logout(5 * time.Second); err != nil {
		t.Fatalf("the second logout: %v", err)
	}
}
