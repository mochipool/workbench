package mailbox_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

// closable is a fakenet dialer with the CloseWithin of a tunnel dialer.
type closable struct {
	relayport.StreamDialer
	closed atomic.Bool
}

func (c *closable) CloseWithin(time.Duration) error { c.closed.Store(true); return nil }

// sharedBook is a book that fails the test when two clients call it at once.
type sharedBook struct {
	mu      sync.Mutex
	busy    atomic.Bool
	t       *testing.T
	pending []mailbox.Revoke
	results map[mailbox.RevokeOutcome]int
}

func (b *sharedBook) enter() {
	if !b.busy.CompareAndSwap(false, true) {
		b.t.Error("two clients called the book at once")
	}
	time.Sleep(time.Millisecond)
}

func (b *sharedBook) Pending() []mailbox.Revoke {
	b.enter()
	defer b.busy.Store(false)
	return append([]mailbox.Revoke(nil), b.pending...)
}

func (b *sharedBook) Result(r mailbox.Revoke, o mailbox.RevokeOutcome) {
	b.enter()
	defer b.busy.Store(false)
	b.mu.Lock()
	b.results[o]++
	b.mu.Unlock()
}

// Connect makes one client per relay with one binding, one list and one book
// (behind a lock), and the composite over them; SendRevokesTo sends the book's
// revokes to every relay on revoke-only connections; Logout closes the dialers.
//
// spec: SPO-Xmailbox-OUT-107, SPO-Xmailbox-IF-024, SPO-Xmailbox-INV-039
func TestConnectAndSendRevokesToEveryRelay(t *testing.T) {
	w1, w2 := newWorld(t), newWorld(t)
	nb := int64(startTime)
	k := relayporttest.DeviceKeysOf(9)
	rv := mailbox.Revoke{Kind: mailbox.RevokeByDeviceKey, Until: startTime + 86400, Keys: k, NotBefore: nb,
		Signature: relayporttest.DeviceRevokeSignature(t, 9, nb)}
	book := &sharedBook{t: t, pending: []mailbox.Revoke{rv}, results: map[mailbox.RevokeOutcome]int{}}
	d1 := &closable{StreamDialer: w1.net.Dialer(w1.b.node, w1.relay)}
	d2 := &closable{StreamDialer: w2.net.Dialer(w2.b.node, w2.relay)}
	b := w1.b
	m, err := mailbox.Connect(mailbox.DeviceConfig{
		Relays:  []mailbox.Endpoint{{Name: "one", RelayKey: w1.relay.Key, Dialer: d1}, {Name: "two", RelayKey: w2.relay.Key, Dialer: d2}},
		NodeKey: b.node.Key, Self: b.fp, Device: b.keys, Binding: b.binding(), Senders: b.senders, Resolve: w1.resolver(),
		Revokes: book, Signer: b.sg, Clock: w1.clock, Limits: fastLimits(),
	})
	if err != nil {
		t.Fatal(err)
	}
	// a login at both sends the pending revoke first, through the shared book
	sender := newMulti(t, nil, nil, mailbox.Member{Name: "one", Client: w1.client(w1.a)}, mailbox.Member{Name: "two", Client: w2.client(w2.a)})
	env := newEnv(64, 20)
	if err := sender.Send(context.Background(), b.fp, env); err != nil {
		t.Fatal(err)
	}
	if got, err := recvWithin(t, m, 5*time.Second); err != nil || string(got) != string(env) {
		t.Fatalf("receive through Connect: %v", err)
	}
	for _, w := range []*world{w1, w2} {
		ts, err := w.reg.Tombstones(context.Background(), [28]byte{}, relayporttest.Device(9))
		if err != nil || ts.Device != nb {
			t.Fatalf("a relay's device tombstone %+v %v", ts, err)
		}
	}
	if reps, err := m.SendRevokes(context.Background()); err != nil || reps["one"].Count(mailbox.RevokeRecorded) != 1 || reps["two"].Count(mailbox.RevokeRecorded) != 1 {
		t.Fatalf("the composite's revoke-only exchange at two relays: %+v %v", reps, err)
	}
	if err := m.Logout(time.Second); err != nil {
		t.Fatal(err)
	}
	if !d1.closed.Load() || !d2.closed.Load() {
		t.Fatal("logout did not close the dialers")
	}

	// the revoke-only senders, a fresh device revoke
	nb2 := nb + 10
	w1.clock.Advance(10 * time.Second)
	w2.clock.Advance(10 * time.Second)
	rv2 := mailbox.Revoke{Kind: mailbox.RevokeByDeviceKey, Until: startTime + 86400, Keys: relayporttest.DeviceKeysOf(10), NotBefore: nb2,
		Signature: relayporttest.DeviceRevokeSignature(t, 10, nb2)}
	book2 := &sharedBook{t: t, pending: []mailbox.Revoke{rv2}, results: map[mailbox.RevokeOutcome]int{}}
	reps, err := mailbox.SendRevokesTo(context.Background(), []mailbox.Endpoint{
		{Name: "one", RelayKey: w1.relay.Key, Dialer: &closable{StreamDialer: w1.net.Dialer(w1.d.node, w1.relay)}},
		{Name: "two", RelayKey: w2.relay.Key, Dialer: &closable{StreamDialer: w2.net.Dialer(w2.d.node, w2.relay)}},
	}, w1.clock, book2, fastLimits())
	if err != nil || reps["one"].Count(mailbox.RevokeRecorded) != 1 || reps["two"].Count(mailbox.RevokeRecorded) != 1 {
		t.Fatalf("revoke-only sends: %+v %v", reps, err)
	}
	for _, w := range []*world{w1, w2} {
		ts, _ := w.reg.Tombstones(context.Background(), [28]byte{}, relayporttest.Device(10))
		if ts.Device != nb2 {
			t.Fatalf("a relay's tombstone of the second revoke: %+v", ts)
		}
	}
	// one relay down: the other still takes them; both down: an error
	w2.shutdown()
	if _, err := mailbox.SendRevokesTo(context.Background(), []mailbox.Endpoint{
		{Name: "one", RelayKey: w1.relay.Key, Dialer: &closable{StreamDialer: w1.net.Dialer(w1.d.node, w1.relay)}},
		{Name: "two", RelayKey: w2.relay.Key, Dialer: &closable{StreamDialer: w2.net.Dialer(w2.d.node, w2.relay)}},
	}, w1.clock, book2, fastLimits()); err != nil {
		t.Fatalf("one relay down: %v", err)
	}
	w1.shutdown()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := mailbox.SendRevokesTo(ctx, []mailbox.Endpoint{
		{Name: "one", RelayKey: w1.relay.Key, Dialer: &closable{StreamDialer: w1.net.Dialer(w1.d.node, w1.relay)}},
	}, w1.clock, book2, fastLimits()); err == nil {
		t.Fatal("every relay down: no error")
	}
	if _, err := mailbox.Connect(mailbox.DeviceConfig{}); err == nil {
		t.Fatal("Connect with no relay")
	}
	_ = party.Fingerprint{}
}

// relayBook is a RelayRevokeBook that records the outcomes per relay.
type relayBook struct {
	mu      sync.Mutex
	pending []mailbox.Revoke
	at      map[string][]mailbox.RevokeOutcome
	plain   int
}

func (b *relayBook) Pending() []mailbox.Revoke {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]mailbox.Revoke(nil), b.pending...)
}

func (b *relayBook) Result(mailbox.Revoke, mailbox.RevokeOutcome) {
	b.mu.Lock()
	b.plain++
	b.mu.Unlock()
}

func (b *relayBook) ResultAt(relay string, _ mailbox.Revoke, o mailbox.RevokeOutcome) {
	b.mu.Lock()
	b.at[relay] = append(b.at[relay], o)
	b.mu.Unlock()
}

// The revoke-only exchange over several relays tells the book which relay did
// what: the honest relay recorded the revoke, the hostile one answered refused,
// and the relay that is down is named with its own error in its report, so
// the command can say which relay still owes it.
//
// spec: SPO-Xmailbox-IF-026, SPO-Xmailbox-OUT-107
func TestEachRelayReportsItsOwnRevokeOutcome(t *testing.T) {
	w1, w2 := newWorld(t), newWorld(t)
	refuse := newHostile(t, func(s *sconn) {
		s.handshake(hs{revokeStatus: func(_ int, m wire.Message) wire.Message {
			return wire.RevokeResult{RequestID: m.(wire.RevokeByDevice).RequestID, Status: wire.RevokeRefused}
		}})
	})
	nb := int64(startTime)
	rv := mailbox.Revoke{Kind: mailbox.RevokeByDeviceKey, Until: startTime + 86400, Keys: relayporttest.DeviceKeysOf(11), NotBefore: nb,
		Signature: relayporttest.DeviceRevokeSignature(t, 11, nb)}
	book := &relayBook{pending: []mailbox.Revoke{rv}, at: map[string][]mailbox.RevokeOutcome{}}
	w2.shutdown()
	reps, err := mailbox.SendRevokesTo(context.Background(), []mailbox.Endpoint{
		{Name: "one", RelayKey: w1.relay.Key, Dialer: &closable{StreamDialer: w1.net.Dialer(w1.d.node, w1.relay)}},
		{Name: "two", RelayKey: w2.relay.Key, Dialer: &closable{StreamDialer: w2.net.Dialer(w2.d.node, w2.relay)}},
		{Name: "liar", RelayKey: refuse.relay.Key, Dialer: &closable{StreamDialer: refuse.net.Dialer(refuse.me.node, refuse.relay)}},
	}, w1.clock, book, fastLimits())
	if err != nil {
		t.Fatal(err)
	}
	book.mu.Lock()
	defer book.mu.Unlock()
	if got := book.at["one"]; len(got) != 1 || got[0] != mailbox.RevokeRecorded {
		t.Fatalf("relay one: %v", got)
	}
	if got := book.at["liar"]; len(got) != 1 || got[0] != mailbox.RevokeRefused {
		t.Fatalf("the refusing relay: %v", got)
	}
	if len(book.at["two"]) != 0 || reps["two"].Err == nil || reps["one"].Err != nil || reps["liar"].Err != nil {
		t.Fatalf("the relay that is down: %v; errors %v %v %v", book.at["two"], reps["one"].Err, reps["two"].Err, reps["liar"].Err)
	}
	if book.plain != 0 {
		t.Fatalf("%d outcomes reported without the relay's name", book.plain)
	}
	// a plain book still gets every outcome
	plain := &sharedBook{t: t, pending: []mailbox.Revoke{rv}, results: map[mailbox.RevokeOutcome]int{}}
	if _, err := mailbox.SendRevokesTo(context.Background(), []mailbox.Endpoint{
		{Name: "one", RelayKey: w1.relay.Key, Dialer: &closable{StreamDialer: w1.net.Dialer(w1.d.node, w1.relay)}},
	}, w1.clock, plain, fastLimits()); err != nil || plain.results[mailbox.RevokeRecorded] != 1 {
		t.Fatalf("a plain book: %v %v", plain.results, err)
	}
}
