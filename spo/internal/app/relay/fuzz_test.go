package relay_test

import (
	"context"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailboxstore"
	"github.com/mochipool/workbench/spo/internal/app/relay"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

// The fuzz rig's limits: every timer is a few milliseconds, so that an
// iteration that leaves the session waiting for more input ends in tens of
// milliseconds and not in seconds, and the number of bytes the relay may send
// is small, so that the bound the target asserts is the relay's own.
const (
	fuzzTimer     = 20 * time.Millisecond
	fuzzHandshake = 250 * time.Millisecond // the honest handshake of the authed target must not race its timer
	fuzzLifetime  = 400 * time.Millisecond
	fuzzMaxSent   = 32 << 10 // the relay's MaxBytesSent for a fuzzed connection
	fuzzErrorSlop = 16       // the one Error frame a closing session may still send
)

// fuzzSession runs one session against the arbitrary bytes in. With authed the
// bytes follow an honest handshake; without, they are the client's first
// frames. The relay must not panic, must send at most its own egress bound,
// must end the session, and the store must stay within its bounds. The store
// is emptied after each input (and found empty at the start of the next), so
// that one input cannot fill the quota for the ones after it and a counter
// that leaks shows.
func fuzzSession(f *testing.F, authed bool) {
	clock := relayporttest.NewManualClock(1_700_000_000)
	st, _, err := mailboxstore.Open(f.TempDir(), clock)
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { st.Close() })

	// small seeds: frames a session sees
	n0 := fakenet.New()
	a0, b0 := newPeer(n0, "alice"), newPeer(n0, "bob")
	env := envelope(40, 3)
	put, _ := mailbox.NewPutOf(1, b0.fp, env)
	seeds := [][]byte{
		nil,
		{0, 0, 0, 0},
		{0xff, 0xff, 0xff, 0xff},
		frame(f, mailbox.Auth{Version: 1, Fingerprint: a0.fp, Signature: [64]byte{1}}),
		frame(f, mailbox.Fetch{RequestID: 1, MaxItems: 16}),
		frame(f, mailbox.Fetch{RequestID: 1, MaxItems: 16, WaitSeconds: 20}),
		frame(f, mailbox.Ack{RequestID: 2, Mids: []mailbox.Hash{{1}}}),
		append(frame(f, put), rawFrame(f, env)...),
		append(append(frame(f, put), rawFrame(f, env)...), frame(f, mailbox.Fetch{RequestID: 2, MaxItems: 16})...),
		append(frame(f, put), rawFrame(f, env[:20])...),
		frame(f, mailbox.PutResult{RequestID: 1}),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in []byte) {
		// Every seed is small and so is every input: the engine minimises a new
		// interesting input for up to a minute (-fuzzminimizetime), and during
		// that time it counts no execs, which shows as a throughput of 0 for
		// seconds. A large input takes the longest to shrink.
		if len(in) > 512 {
			t.Skip()
		}
		fakenet.CheckLeaks(t)
		n := fakenet.New()
		relayNode := n.Node("relay")
		a, b := newPeer(n, "alice"), newPeer(n, "bob")
		acc := newAccess(a.entry(b.fp), b.entry(a.fp))
		lim := relay.DefaultLimits()
		lim.HandshakeTimeout = fuzzTimer
		if authed {
			lim.HandshakeTimeout = fuzzHandshake
		}
		lim.IdleTimeout = fuzzTimer
		lim.BodyTimeout = fuzzTimer
		lim.WriteTimeout = fuzzTimer
		lim.ConnLifetime = fuzzLifetime
		lim.MaxBytesSent = fuzzMaxSent
		vl, err := lim.Validated()
		if err != nil {
			t.Fatal(err)
		}
		q, _ := mailbox.DefaultQuota().Validated(2)
		for _, p := range []*peer{a, b} { // the store starts empty
			if u, err := st.Usage(context.Background(), p.fp, a.fp); err != nil || u.MailboxEntries != 0 || u.GlobalBytes != 0 {
				t.Fatalf("the store was not empty at the start: %+v, %v", u, err)
			}
		}
		srv, err := relay.New(relay.Config{
			Writer: st, Reader: st, Acker: st, Retractor: st, Usage: st, Access: acc, Clock: clock,
			Rand: &countRand{}, RelayKey: relayNode.Key, Quota: q, Limits: vl,
		})
		if err != nil {
			t.Fatal(err)
		}
		ln, err := n.Listen(relayNode, acc.NodeKeys())
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- srv.Serve(ctx, ln) }()
		defer func() {
			cancel()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("Serve did not return")
			}
			ln.Close()
			for _, p := range []*peer{a, b} { // reset the store for the next input
				if _, err := st.RemoveMailbox(context.Background(), p.fp); err != nil {
					t.Error(err)
				}
			}
		}()

		s, _, err := n.Dialer(a.node, relayNode).Dial(ctx)
		if err != nil {
			t.Fatal(err)
		}
		c := &conn{t: t, s: s, p: a, relayKey: relayNode.Key}
		defer s.Close()
		if authed {
			c.handshake()
		}
		_ = c.tryWrite(in)
		// read until the relay closes or goes quiet: the session ends by its own
		// timers within a few of them
		var got int
		buf := make([]byte, 4096)
		for end := time.Now().Add(20 * fuzzTimer); time.Now().Before(end); {
			s.SetReadDeadline(time.Now().Add(5 * fuzzTimer))
			k, err := s.Read(buf)
			got += k
			if err != nil {
				break
			}
			if got > fuzzMaxSent+fuzzErrorSlop {
				t.Fatalf("the relay sent %d bytes to %d bytes of input; its bound is %d", got, len(in), fuzzMaxSent)
			}
		}
		for _, p := range []*peer{a, b} {
			for _, q := range []*peer{a, b} {
				u, err := st.Usage(context.Background(), p.fp, q.fp)
				if err != nil {
					t.Fatal(err)
				}
				if u.MailboxEntries > mailbox.MaxMailboxEntries || u.MailboxBytes > mailbox.MaxMailboxBytes || u.PairEntries > mailbox.MaxPairEntries {
					t.Fatalf("usage past a bound: %+v", u)
				}
			}
		}
	})
}

// FuzzSessionBeforeAuth: arbitrary bytes as the client's first frames.
//
// spec: SPO-Xmailbox-INV-015
func FuzzSessionBeforeAuth(f *testing.F) { fuzzSession(f, false) }

// FuzzSessionAfterAuth: arbitrary bytes after an honest handshake.
//
// spec: SPO-Xmailbox-INV-015
func FuzzSessionAfterAuth(f *testing.F) { fuzzSession(f, true) }
