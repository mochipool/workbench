package relay_test

import (
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/relay"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

// closed reports whether n close events have been logged.
func closed(r *rig, n int) func() bool {
	return func() bool { return len(r.ev.of(relay.EventClose)) >= n }
}

func closeReason(r *rig, i int) relay.Reason {
	es := r.ev.of(relay.EventClose)
	if i >= len(es) {
		return "none"
	}
	return es[i].Reason
}

// Requests per connection: the limit is allowed, one more closes.
//
// spec: SPO-Xmailbox-INV-012, SPO-Xmailbox-PRE-023
func TestRequestsPerConnection(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.MaxRequests = 3 }))
	b, _ := r.login(r.b)
	for i := uint32(0); i < 3; i++ {
		b.fetch(i, nil, 1, 0)
	}
	b.send(mailbox.Fetch{RequestID: 3, MaxItems: 1})
	if code := b.expectError(); code != mailbox.CodeLimit {
		t.Fatalf("code %d, want limit", code)
	}
	b.expectClosed()
	eventually(t, "the close event", closed(r, 1))
	if got := closeReason(r, 0); got != relay.ReasonRequests {
		t.Fatalf("reason %q", got)
	}
}

// authFrameLen is the length of any Auth frame (the signature is a fixed-size
// byte string).
func authFrameLen(t *testing.T) int {
	return len(frame(t, mailbox.Auth{Version: 1, Fingerprint: party.Fingerprint{1}, Signature: [64]byte{1}}))
}

// Bytes per connection, counted over header frames: the exact total is
// allowed, one byte under closes at the frame that passes it.
//
// spec: SPO-Xmailbox-INV-012
func TestBytesPerConnectionOverHeaders(t *testing.T) {
	f := len(frame(t, mailbox.Fetch{RequestID: 0, MaxItems: 1}))
	total := uint64(authFrameLen(t) + 2*f)
	for _, tc := range []struct {
		name    string
		max     uint64
		allowed int
	}{{"exactly", total, 2}, {"one under", total - 1, 1}} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, withLimits(func(l *relay.Limits) { l.MaxBytes = tc.max }))
			b, _ := r.login(r.b)
			for i := 0; i < tc.allowed; i++ {
				b.fetch(uint32(i), nil, 1, 0)
			}
			b.send(mailbox.Fetch{RequestID: uint32(tc.allowed), MaxItems: 1})
			if code := b.expectError(); code != mailbox.CodeLimit {
				t.Fatalf("code %d, want limit", code)
			}
		})
	}
}

// Bytes per connection, counted over a raw frame: the relay refuses a body
// that would pass the bound before it reads a byte of it.
//
// spec: SPO-Xmailbox-INV-012
func TestBytesPerConnectionOverABody(t *testing.T) {
	env := envelope(300, 1)
	bobFP := newPeer(fakenet.New(), "bob").fp // the same on every net
	hf0 := frame(t, mailboxPutTo(bobFP, env))
	for _, tc := range []struct {
		name  string
		slack int64
		ok    bool
	}{{"exactly", 0, true}, {"one under", -1, false}} {
		t.Run(tc.name, func(t *testing.T) {
			max := uint64(int64(authFrameLen(t)+len(hf0)+4+len(env)) + tc.slack)
			r := newRig(t, withLimits(func(l *relay.Limits) { l.MaxBytes = max }))
			a, _ := r.login(r.a)
			before := r.read.Load()
			hf := frame(t, mailboxPutTo(r.b.fp, env))
			a.write(append(append([]byte(nil), hf...), rawFrame(t, env)...))
			if tc.ok {
				if m, ok := a.recv().(mailbox.PutResult); !ok || m.Status != mailbox.StatusStored {
					t.Fatalf("got %#v", m)
				}
				return
			}
			if code := a.expectError(); code != mailbox.CodeLimit {
				t.Fatalf("code %d, want limit", code)
			}
			if got := r.read.Load() - before; got != int64(len(hf)) {
				t.Fatalf("the relay read %d bytes, want the header's %d only", got, len(hf))
			}
			if n := len(r.store.putCalls()); n != 0 {
				t.Fatalf("%d store puts", n)
			}
		})
	}
}

func mailboxPutTo(to party.Fingerprint, env []byte) mailbox.Put {
	p, _ := mailbox.NewPutOf(1, to, env)
	return p
}

// Connection lifetime: a request inside it is served, the connection is closed
// when it ends although the idle timeout has not.
//
// spec: SPO-Xmailbox-INV-012
func TestConnectionLifetime(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) {
		l.ConnLifetime = 400 * time.Millisecond
		l.IdleTimeout = 5 * time.Second
		l.HandshakeTimeout = 400 * time.Millisecond
	}))
	b, _ := r.login(r.b)
	b.fetch(1, nil, 1, 0)
	start := time.Now()
	if code := b.expectError(); code != mailbox.CodeLimit {
		t.Fatalf("code %d, want limit", code)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("closed after %v, want about 400ms from connect", d)
	}
	eventually(t, "the close event", closed(r, 1))
	if got := closeReason(r, 0); got != relay.ReasonLifetime {
		t.Fatalf("reason %q", got)
	}
}

// Idle: no frame within the timeout closes the connection.
//
// spec: SPO-Xmailbox-INV-012, SPO-Xmailbox-INV-013
func TestIdleTimeout(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.IdleTimeout = 150 * time.Millisecond }))
	b, _ := r.login(r.b)
	start := time.Now()
	if code := b.expectError(); code != mailbox.CodeLimit {
		t.Fatalf("code %d, want limit", code)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("closed after %v", d)
	}
	eventually(t, "the close event", closed(r, 1))
	if got := closeReason(r, 0); got != relay.ReasonIdle {
		t.Fatalf("reason %q", got)
	}
}

// Live connections per node key: two are allowed, the third is refused with the
// limit code, and the first two go on.
//
// spec: SPO-Xmailbox-INV-012, SPO-Xmailbox-PRE-021
func TestLiveConnectionsPerKey(t *testing.T) {
	r := newRig(t)
	c1, _ := r.login(r.a)
	c2, _ := r.login(r.a)
	c3 := r.dial(r.a)
	if code := c3.expectError(); code != mailbox.CodeLimit {
		t.Fatalf("code %d, want limit", code)
	}
	c3.expectClosed()
	c1.fetch(1, nil, 1, 0)
	c2.fetch(1, nil, 1, 0)
	if got := r.ev.of(relay.EventRejected); len(got) != 1 || got[0].Reason != relay.ReasonLimit {
		t.Fatalf("events %+v", got)
	}
	// another key is not affected
	r.login(r.b)
}

// A closed connection frees its slot.
//
// spec: SPO-Xmailbox-INV-012
func TestClosingAConnectionFreesItsSlot(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.MaxConnsPerKey = 1 }))
	c1, _ := r.login(r.a)
	c1.s.Close()
	eventually(t, "the slot to free", closed(r, 1))
	r.login(r.a)
}

// New connections per key per minute: the limit is allowed and one more is
// refused; the window moves with the relay's clock.
//
// spec: SPO-Xmailbox-INV-012
func TestNewConnectionsPerKeyPerMinute(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.MaxNewConnsPerMinute = 2 }))
	for i := 1; i <= 2; i++ {
		c, _ := r.login(r.a)
		c.s.Close()
		eventually(t, "the close", closed(r, i))
	}
	c3 := r.dial(r.a)
	if code := c3.expectError(); code != mailbox.CodeLimit {
		t.Fatalf("third connection in a minute: code %d, want limit", code)
	}
	r.clock.Advance(59 * time.Second)
	c4 := r.dial(r.a)
	if code := c4.expectError(); code != mailbox.CodeLimit {
		t.Fatalf("after 59 s: code %d, want limit", code)
	}
	r.clock.Advance(time.Second) // exactly a minute after the first two
	r.login(r.a)
	// the bound is per key
	r.login(r.b)
}

// Total live connections.
//
// spec: SPO-Xmailbox-INV-012
func TestTotalConnections(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.MaxConnections = 2 }))
	a, _ := r.login(r.a)
	r.login(r.b)
	c := r.dial(r.c)
	if code := c.expectError(); code != mailbox.CodeLimit {
		t.Fatalf("code %d, want limit", code)
	}
	a.s.Close()
	eventually(t, "the slot to free", closed(r, 1))
	r.login(r.c)
}

// Puts per party per minute: the limit is stored, one more is busy and its
// body is consumed; the window moves with the relay's clock.
//
// spec: SPO-Xmailbox-INV-012
func TestPutsPerMinute(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.MaxPutsPerMinute = 2 }))
	a, _ := r.login(r.a)
	for i := 1; i <= 2; i++ {
		if got := a.put(uint32(i), r.b.fp, envelope(80, byte(i))).Status; got != mailbox.StatusStored {
			t.Fatalf("put %d: %d", i, got)
		}
	}
	if got := a.put(3, r.b.fp, envelope(80, 3)).Status; got != mailbox.StatusBusy {
		t.Fatalf("third put in a minute: %d, want busy", got)
	}
	r.clock.Advance(59 * time.Second)
	if got := a.put(4, r.b.fp, envelope(80, 4)).Status; got != mailbox.StatusBusy {
		t.Fatalf("after 59 s: %d, want busy", got)
	}
	r.clock.Advance(time.Second) // exactly a minute after the first two
	if got := a.put(5, r.b.fp, envelope(80, 4)).Status; got != mailbox.StatusStored {
		t.Fatalf("after the window: %d, want stored", got)
	}
	if n := len(r.list(r.b.fp)); n != 3 {
		t.Fatalf("%d stored, want 3", n)
	}
}

// Concurrent puts per sender, over all its connections: one is held in the
// store, a second is busy and consumed, and the first completes.
//
// spec: SPO-Xmailbox-INV-012
func TestConcurrentPutsPerSender(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.MaxConcurrentPuts = 1 }))
	gate := make(chan struct{})
	r.store.arm(func(f *faultStore) { f.Gate = gate })
	a1, _ := r.login(r.a)
	a2, _ := r.login(r.a)
	env := envelope(90, 1)
	h, _ := mailbox.NewPutOf(1, r.b.fp, env)
	a1.write(append(frame(t, h), rawFrame(t, env)...))
	eventually(t, "the first put to reach the store", func() bool { return len(r.store.putCalls()) == 1 })
	if got := a2.put(1, r.b.fp, envelope(90, 2)).Status; got != mailbox.StatusBusy {
		t.Fatalf("second concurrent put: %d, want busy", got)
	}
	close(gate)
	if m, ok := a1.recv().(mailbox.PutResult); !ok || m.Status != mailbox.StatusStored {
		t.Fatalf("got %#v", m)
	}
	// the slot is free again
	r.store.arm(func(f *faultStore) { f.Gate = nil })
	if got := a2.put(2, r.b.fp, envelope(90, 3)).Status; got != mailbox.StatusStored {
		t.Fatalf("after the first completed: %d", got)
	}
}

// Two concurrent puts are allowed when the bound is two.
//
// spec: SPO-Xmailbox-INV-012
func TestTwoConcurrentPutsAreAllowedAtTheDefault(t *testing.T) {
	r := newRig(t)
	gate := make(chan struct{})
	r.store.arm(func(f *faultStore) { f.Gate = gate })
	a1, _ := r.login(r.a)
	a2, _ := r.login(r.a)
	for i, c := range []*conn{a1, a2} {
		env := envelope(90, byte(i+1))
		h, _ := mailbox.NewPutOf(1, r.b.fp, env)
		c.write(append(frame(t, h), rawFrame(t, env)...))
	}
	eventually(t, "both puts to reach the store", func() bool { return len(r.store.putCalls()) == 2 })
	close(gate)
	for _, c := range []*conn{a1, a2} {
		if m, ok := c.recv().(mailbox.PutResult); !ok || m.Status != mailbox.StatusStored {
			t.Fatalf("got %#v", m)
		}
	}
}

// The quota bounds, each hit exactly: the store decides from the usage and the
// session reports full.
//
// spec: SPO-Xmailbox-OUT-026, SPO-Xmailbox-INV-012
func TestQuotaBoundsAreReportedAsFull(t *testing.T) {
	for _, tc := range []struct {
		name string
		q    func(q *mailbox.Quota)
		size int
	}{
		{"pair entries", func(q *mailbox.Quota) { q.PairEntries = 2 }, 50},
		{"mailbox entries", func(q *mailbox.Quota) { q.MailboxEntries = 2 }, 50},
		{"pair bytes", func(q *mailbox.Quota) { q.PairBytes = 100 }, 50},
		{"mailbox bytes", func(q *mailbox.Quota) { q.MailboxBytes = 100 }, 50},
		{"sender bytes", func(q *mailbox.Quota) { q.SenderBytes = 100 }, 50},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, withQuota(tc.q))
			a, _ := r.login(r.a)
			for i := 1; i <= 2; i++ {
				if got := a.put(uint32(i), r.b.fp, envelope(tc.size, byte(i))).Status; got != mailbox.StatusStored {
					t.Fatalf("put %d: %d, want stored (at the bound)", i, got)
				}
			}
			if got := a.put(3, r.b.fp, envelope(tc.size, 3)).Status; got != mailbox.StatusFull {
				t.Fatalf("one over: %d, want full", got)
			}
			if n := len(r.list(r.b.fp)); n != 2 {
				t.Fatalf("%d entries", n)
			}
			// a duplicate of a stored entry is not full
			if got := a.put(4, r.b.fp, envelope(tc.size, 1)).Status; got != mailbox.StatusDuplicate {
				t.Fatalf("duplicate at the bound: %d", got)
			}
		})
	}
}
