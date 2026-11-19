package relay_test

import (
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/relay"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

// relayportDevice is the fingerprint of a device that no rig binds.
func relayportDevice(n byte) party.Fingerprint { return relayporttest.Device(n) }

// closeOnce closes a gate that a test may already have closed.
func closeOnce(ch chan struct{}) {
	defer func() { _ = recover() }()
	close(ch)
}

// The findings L1, L2 and L3 of the security review of the version 2 session.

// ---- L1: connections per device and per wallet key ----

// loginFrom is the login of p from the tunnel node n (the node key in the signed
// bytes is n's, as the relay requires).
func (r *rig) loginFrom(p *peer, n *fakenet.Node) *conn {
	r.t.Helper()
	c := r.dialNode(p, n, zeroFault)
	c.handshakeWith(authOpt{clientNode: &n.Key})
	return c
}

var probeSeq atomic.Int32

// tryLogin logs p in from a node that was never used before and reports whether
// the relay answered AuthOK. A refused login leaves nothing open.
func (r *rig) tryLogin(p *peer) bool {
	r.t.Helper()
	n := r.extraNode(fmt.Sprintf("probe-%d", probeSeq.Add(1)))
	c := r.dialNode(p, n, zeroFault)
	ch := c.challenge()
	c.send(c.authFrame(ch, authOpt{clientNode: &n.Key}))
	_, ok := c.recv().(mailbox.AuthOKV2)
	return ok
}

// loginRefused is a login from n that the relay answers with the limit code.
func (r *rig) loginRefused(p *peer, n *fakenet.Node) mailbox.Code {
	r.t.Helper()
	c := r.dialNode(p, n, zeroFault)
	return c.loginFails(authOpt{clientNode: &n.Key})
}

// The defaults are the table of ADR 0014 decision 5: 2 a device, 16 a wallet key
// (8 devices of 2), and both can only be tightened.
//
// spec: SPO-Xmailbox-PRE-056
func TestConnectionBoundsAreTheTableAndOnlyTighten(t *testing.T) {
	l := relay.DefaultLimits()
	if l.MaxConnsPerDevice != 2 || l.MaxConnsPerWalletKey != 16 {
		t.Fatalf("defaults %d and %d, want 2 and 16", l.MaxConnsPerDevice, l.MaxConnsPerWalletKey)
	}
	if mailbox.MaxConnsPerWalletKey != mailbox.MaxDevicesPerKey*mailbox.MaxConnsPerDevice {
		t.Fatal("the key bound is not devices times connections")
	}
	for name, set := range map[string]func(*relay.Limits){
		"device 0":   func(l *relay.Limits) { l.MaxConnsPerDevice = 0 },
		"device 3":   func(l *relay.Limits) { l.MaxConnsPerDevice = 3 },
		"key 0":      func(l *relay.Limits) { l.MaxConnsPerWalletKey = 0 },
		"key 17":     func(l *relay.Limits) { l.MaxConnsPerWalletKey = 17 },
		"device -1":  func(l *relay.Limits) { l.MaxConnsPerDevice = -1 },
		"key -1":     func(l *relay.Limits) { l.MaxConnsPerWalletKey = -1 },
		"device big": func(l *relay.Limits) { l.MaxConnsPerDevice = 1 << 30 },
	} {
		l := relay.DefaultLimits()
		set(&l)
		if _, err := l.Validated(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	for name, set := range map[string]func(*relay.Limits){
		"device 1": func(l *relay.Limits) { l.MaxConnsPerDevice = 1 },
		"key 1":    func(l *relay.Limits) { l.MaxConnsPerWalletKey = 1 },
	} {
		l := relay.DefaultLimits()
		set(&l)
		if _, err := l.Validated(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// One device may hold two logged-in connections (the default): the first (one
// under), the second (at the bound) are served, the third (one over) is refused at
// login with the limit code, and a connection that closes gives its place back.
//
// spec: SPO-Xmailbox-PRE-056
func TestConnectionsPerDeviceAreBounded(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.IdleTimeout = 5 * time.Second; l.ConnLifetime = 30 * time.Second }))
	first := r.loginFrom(r.a, r.a.node)
	r.loginFrom(r.a, r.extraNode("alice-2"))
	if code := r.loginRefused(r.a, r.extraNode("alice-3")); code != mailbox.CodeLimit {
		t.Fatalf("the third connection of a device: code %d, want limit", code)
	}
	// another device is not affected
	r.login(r.b)
	// the first one closes: its place is free
	first.s.Close()
	eventually(t, "the place of the closed connection to be free", func() bool { return r.tryLogin(r.a) })
}

// A tighter bound is held at one: the second connection of a device is refused.
//
// spec: SPO-Xmailbox-PRE-056
func TestConnectionsPerDeviceTightened(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.MaxConnsPerDevice = 1 }))
	r.loginFrom(r.a, r.a.node)
	if code := r.loginRefused(r.a, r.extraNode("alice-2")); code != mailbox.CodeLimit {
		t.Fatalf("code %d, want limit", code)
	}
}

// A login that fails after its place was taken (the registry fails) gives the
// place back; so does a session that a revoke closes.
//
// spec: SPO-Xmailbox-PRE-056
func TestConnectionPlaceIsReleasedOnEveryExit(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) {
		l.MaxConnsPerDevice = 1
		l.IdleTimeout = 5 * time.Second
		l.ConnLifetime = 30 * time.Second
	}))
	// the registry fails after the place was taken
	r.hreg.mu.Lock()
	r.hreg.RegisterErr = errors.New("the disk failed")
	r.hreg.mu.Unlock()
	n1 := r.extraNode("alice-1")
	c := r.dialNode(r.a, n1, zeroFault)
	c.loginFails(authOpt{clientNode: &n1.Key})
	r.hreg.mu.Lock()
	r.hreg.RegisterErr = nil
	r.hreg.mu.Unlock()
	eventually(t, "the failed login to give its place back", func() bool { return r.tryLogin(r.a) })
	// a session closed by CloseDevice gives its place back too
	if n := r.srv.CloseDevice(r.a.fp); n != 1 {
		t.Fatalf("closed %d sessions, want 1", n)
	}
	eventually(t, "the closed session to give its place back", func() bool { return r.tryLogin(r.a) })
}

// The devices of one wallet key share a bound: with 3 a key, bob's laptop and
// server hold two and one, and a second connection of the server is refused
// though the server itself holds one of its two places. Releasing one frees it.
//
// spec: SPO-Xmailbox-PRE-056
func TestConnectionsPerWalletKeyAreBounded(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) {
		l.MaxConnsPerWalletKey = 3
		l.IdleTimeout = 5 * time.Second
		l.ConnLifetime = 30 * time.Second
	}))
	laptop := r.addPeer("bob-laptop", r.b.wallet)
	r.bind(laptop)
	r.loginFrom(r.b, r.b.node)                    // one under the key bound
	second := r.loginFrom(r.b, r.extraNode("b2")) // two, the device's own bound
	r.loginFrom(laptop, laptop.node)              // three: at the key bound
	if code := r.loginRefused(laptop, r.extraNode("b3")); code != mailbox.CodeLimit {
		t.Fatalf("a fourth connection of the key: code %d, want limit", code)
	}
	// another wallet key is not affected
	r.login(r.a)
	second.s.Close()
	eventually(t, "the place of the closed connection to be free", func() bool { return r.tryLogin(laptop) })
}

// ---- L2: every put that reaches a decision counts against the put budget ----

// A run of puts answered `unbound` hits the per-minute budget of the sender's
// wallet key: from then on the answer is `busy` whatever the pair, so the
// "(wallet key, device) is bound here?" question cannot be asked faster than the
// budget allows.
//
// spec: SPO-Xmailbox-SEC-070
func TestUnboundPutsCountAgainstThePutBudget(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.MaxPutsPerMinute = 3 }))
	a, _ := r.login(r.a)
	ghost := relayportDevice(7)
	for i := 1; i <= 3; i++ {
		if got := a.putKey(uint32(i), r.c.wkey(), ghost, envelope(40, byte(i))).Status; got != mailbox.StatusUnbound {
			t.Fatalf("put %d to a device that is not bound: status %d, want unbound", i, got)
		}
	}
	if got := a.putKey(4, r.c.wkey(), ghost, envelope(40, 4)).Status; got != mailbox.StatusBusy {
		t.Fatalf("the fourth probe in a minute: status %d, want busy", got)
	}
	// the answer for a pair that does exist is the same now: nothing is learnt
	if got := a.put(5, r.b.fp, envelope(40, 5)).Status; got != mailbox.StatusBusy {
		t.Fatalf("a put to a bound device over the budget: status %d, want busy", got)
	}
	// the window moves with the relay's clock
	r.clock.Advance(time.Minute)
	if got := a.put(6, r.b.fp, envelope(40, 6)).Status; got != mailbox.StatusStored {
		t.Fatalf("after the window: status %d, want stored", got)
	}
}

// A put answered `unavailable` (the registry could not answer about the recipient)
// counts too.
//
// spec: SPO-Xmailbox-SEC-070
func TestUnavailablePutsCountAgainstThePutBudget(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.MaxPutsPerMinute = 2 }))
	a, _ := r.login(r.a)
	r.hreg.failLookup(r.b.fp, errors.New("the registry cannot answer"))
	for i := 1; i <= 2; i++ {
		if got := a.put(uint32(i), r.b.fp, envelope(40, byte(i))).Status; got != mailbox.StatusUnavailable {
			t.Fatalf("put %d: status %d, want unavailable", i, got)
		}
	}
	if got := a.put(3, r.b.fp, envelope(40, 3)).Status; got != mailbox.StatusBusy {
		t.Fatalf("the third put: status %d, want busy", got)
	}
}

// A put over the announced envelope limit (too_large, the connection closes) counts
// against the budget of the wallet key: the next connection of the key has less.
//
// spec: SPO-Xmailbox-SEC-070
func TestTooLargePutsCountAgainstThePutBudget(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.MaxEnvelope = 512; l.MaxPutsPerMinute = 2 }))
	a1, _ := r.login(r.a)
	env := envelope(513, 1)
	a1.write(a1.putHeader(1, r.b.fp, env))
	if m, ok := a1.recv().(mailbox.PutResult); !ok || m.Status != mailbox.StatusTooLarge {
		t.Fatalf("got %#v, want too_large", m)
	}
	a1.expectClosed()
	a2, _ := r.login(r.a)
	if got := a2.put(1, r.b.fp, envelope(50, 2)).Status; got != mailbox.StatusStored {
		t.Fatalf("the second put of the key: status %d, want stored", got)
	}
	if got := a2.put(2, r.b.fp, envelope(50, 3)).Status; got != mailbox.StatusBusy {
		t.Fatalf("the third attempt of the key: status %d, want busy (the too_large put was one)", got)
	}
}

// A put answered `busy` because the device's puts in flight are at their bound
// counts as well.
//
// spec: SPO-Xmailbox-SEC-070
func TestBusyPutsCountAgainstThePutBudget(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.MaxConcurrentPuts = 1; l.MaxPutsPerMinute = 2 }))
	gate := make(chan struct{})
	r.store.arm(func(f *faultStore) { f.Gate = gate })
	a1, _ := r.login(r.a)
	a2, _ := r.login(r.a)
	env := envelope(90, 1)
	a1.write(append(a1.putHeader(1, r.b.fp, env), rawFrame(t, env)...))
	eventually(t, "the first put to reach the store", func() bool { return len(r.store.putCalls()) == 1 })
	if got := a2.put(1, r.b.fp, envelope(90, 2)).Status; got != mailbox.StatusBusy {
		t.Fatalf("second concurrent put: %d, want busy", got)
	}
	close(gate)
	if m, ok := a1.recv().(mailbox.PutResult); !ok || m.Status != mailbox.StatusStored {
		t.Fatalf("got %#v", m)
	}
	r.store.arm(func(f *faultStore) { f.Gate = nil })
	if got := a2.put(2, r.b.fp, envelope(90, 3)).Status; got != mailbox.StatusBusy {
		t.Fatalf("after two attempts: %d, want busy by the minute budget", got)
	}
}

// Every other outcome counts, as it did: bad_hash, duplicate and full each use one
// attempt of the budget.
//
// spec: SPO-Xmailbox-SEC-070
func TestEveryDecidedPutUsesOneAttempt(t *testing.T) {
	for _, tc := range []struct {
		name string
		do   func(t *testing.T, r *rig, a *conn) mailbox.Status
		want mailbox.Status
	}{
		{"bad_hash", func(t *testing.T, r *rig, a *conn) mailbox.Status {
			env := envelope(60, 1)
			a.write(append(a.putHeader(1, r.b.fp, env), rawFrame(t, envelope(60, 9))...))
			return a.recv().(mailbox.PutResult).Status
		}, mailbox.StatusBadHash},
		{"duplicate", func(t *testing.T, r *rig, a *conn) mailbox.Status {
			a.put(1, r.b.fp, envelope(60, 1))
			return a.put(2, r.b.fp, envelope(60, 1)).Status
		}, mailbox.StatusDuplicate},
		{"unbound", func(t *testing.T, r *rig, a *conn) mailbox.Status {
			return a.putKey(1, r.c.wkey(), relayportDevice(5), envelope(60, 1)).Status
		}, mailbox.StatusUnbound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, withLimits(func(l *relay.Limits) { l.MaxPutsPerMinute = 2 }))
			a, _ := r.login(r.a)
			// the duplicate case uses two attempts, the others one
			used := 1
			if tc.name == "duplicate" {
				used = 2
			}
			if got := tc.do(t, r, a); got != tc.want {
				t.Fatalf("status %d, want %d", got, tc.want)
			}
			for i := used; i < 2; i++ {
				if got := a.put(uint32(100+i), r.b.fp, envelope(60, byte(20+i))).Status; got != mailbox.StatusStored {
					t.Fatalf("attempt %d: status %d, want stored", i+1, got)
				}
			}
			if got := a.put(200, r.b.fp, envelope(60, 40)).Status; got != mailbox.StatusBusy {
				t.Fatalf("one attempt too many: status %d, want busy", got)
			}
		})
	}
}

// ---- L3: the stranger book's lock and the store ----

// A store read under the book's lock that honours its context ends at the
// session's own bound (BodyTimeout, the lifetime, the binding's end, whichever is
// first), not at the end of the session: the put is answered `unavailable`.
//
// spec: SPO-Xmailbox-INV-037
func TestStoreReadUnderTheBookLockEndsAtTheSessionsDeadline(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.BodyTimeout = 300 * time.Millisecond }))
	gate := make(chan struct{})
	t.Cleanup(func() { closeOnce(gate) })
	r.store.arm(func(f *faultStore) { f.UsageGate, f.UsageHonoursCtx = gate, true })
	a, _ := r.login(r.a)
	start := time.Now()
	if got := a.put(1, r.b.fp, envelope(50, 1)).Status; got != mailbox.StatusUnavailable {
		t.Fatalf("status %d, want unavailable", got)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("answered after %v", d)
	}
	if n := len(r.list(r.b.fp)); n != 0 {
		t.Fatalf("%d entries stored", n)
	}
}

// An ack, whose stranger accounting is released under the book's lock, is not held
// by a stalled admission either: it is answered at the session's deadline and the
// book repairs itself at the next admission.
//
// spec: SPO-Xmailbox-INV-037
func TestAckDuringAStalledAdmissionIsAnsweredAtItsDeadline(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.BodyTimeout = 300 * time.Millisecond }))
	a, _ := r.login(r.a)
	if got := a.put(1, r.b.fp, envelope(50, 1)).Status; got != mailbox.StatusStored {
		t.Fatalf("put: status %d", got)
	}
	b, _ := r.login(r.b)
	it, _ := b.fetch(1, nil, 16, 0)
	if len(it.Entries) != 1 {
		t.Fatalf("%d entries, want 1", len(it.Entries))
	}
	gate := make(chan struct{})
	t.Cleanup(func() { closeOnce(gate) })
	r.store.arm(func(f *faultStore) { f.UsageGate, f.UsageHonoursCtx = gate, false })
	c, _ := r.login(r.c)
	env := envelope(50, 2)
	c.write(append(c.putHeader(1, r.b.fp, env), rawFrame(t, env)...))
	eventually(t, "the stalled put to hold the lock inside the store", func() bool { return r.store.usageWaits() == 1 })
	start := time.Now()
	if ar := b.ack(2, it.Entries[0].Mid); ar.Deleted != 1 {
		t.Fatalf("deleted %d, want 1", ar.Deleted)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("the ack was answered after %v", d)
	}
	closeOnce(gate)
	c.tryRecv()
}

// A session that waits for the book's lock behind a store that does not honour its
// context (a stalled disk) still gives up at its own bound: the lock is released
// only when the store returns, but nobody else is held past their deadlines by it.
//
// spec: SPO-Xmailbox-INV-037
func TestWaitForTheBookLockEndsAtTheSessionsDeadline(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.BodyTimeout = 300 * time.Millisecond }))
	gate := make(chan struct{})
	t.Cleanup(func() { closeOnce(gate) })
	r.store.arm(func(f *faultStore) { f.UsageGate, f.UsageHonoursCtx = gate, false })
	a, _ := r.login(r.a)
	c, _ := r.login(r.c)
	env := envelope(50, 1)
	a.write(append(a.putHeader(1, r.b.fp, env), rawFrame(t, env)...))
	eventually(t, "the first put to hold the lock inside the store", func() bool { return r.store.usageWaits() == 1 })
	start := time.Now()
	if got := c.put(1, r.b.fp, envelope(50, 2)).Status; got != mailbox.StatusUnavailable {
		t.Fatalf("the put that waited for the lock: status %d, want unavailable", got)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("answered after %v", d)
	}
	closeOnce(gate)
	a.tryRecv() // the stalled put finishes when the store returns
}
