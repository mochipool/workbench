package mailbox_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

func sendOnce(c *mailbox.Client) error {
	return c.Send(context.Background(), party.Fingerprint{1}, newEnv(100, 1))
}

func putOK(s *sconn) {
	s.serve(hs{}, func(m wire.Message) bool {
		if p, ok := m.(wire.Put); ok {
			s.send(wire.PutResult{RequestID: p.RequestID, Status: wire.StatusStored})
		}
		return true
	})
}

// The key the dialer reports must be the pinned key: a tunnel that reports
// another key is closed on before the relay's Challenge is read, nothing is
// signed and nothing is sent.
//
// spec: SPO-Xmailbox-PRE-024
func TestDialerKeyMismatchSignsNothing(t *testing.T) {
	h := newHostile(t, putOK)
	other := party.NodeKey{9, 9}
	d := h.net.Dialer(h.me.node, h.relay)
	d.Always(fakenet.Fault{ShowListenerAs: &other})
	c := h.clientVia(d)
	err := sendOnce(c)
	if !errors.Is(err, ports.ErrNoRoute) || !errors.Is(err, mailbox.ErrRelayKey) {
		t.Fatalf("Send = %v, want ErrNoRoute wrapping ErrRelayKey", err)
	}
	if n := len(h.me.sg.calls()); n != 0 {
		t.Fatalf("the signer was called %d times for a peer that is not the pinned relay", n)
	}
	if _, err := c.Receive(ctxFor(t, 500*time.Millisecond)); !errors.Is(err, mailbox.ErrRelayKey) {
		t.Fatalf("Receive = %v, want ErrRelayKey (a misconfiguration is returned, not retried)", err)
	}
	if h.authCount() != 0 {
		t.Fatal("the relay saw an Auth")
	}
}

func ctxFor(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// A Challenge that names another relay key closes the connection before
// anything is signed: the relay sees the client close and never an Auth.
//
// spec: SPO-Xmailbox-PRE-024, SPO-Xmailbox-SEC-029
func TestChallengeWithAnotherRelayKeyClosesWithoutSigning(t *testing.T) {
	other := party.NodeKey{7, 7, 7}
	closed := make(chan bool, 4)
	h := newHostile(t, func(s *sconn) {
		s.challenge(hs{relayKey: &other})
		closed <- s.waitClosed()
	})
	c := h.client()
	err := sendOnce(c)
	if !errors.Is(err, ports.ErrNoRoute) || !errors.Is(err, mailbox.ErrRelayKey) {
		t.Fatalf("Send = %v", err)
	}
	if n := len(h.me.sg.calls()); n != 0 {
		t.Fatalf("signer called %d times", n)
	}
	if !<-closed {
		t.Fatal("the client did not close the connection")
	}
	if h.authCount() != 0 {
		t.Fatal("an Auth reached the relay")
	}
}

// The signer is given the pinned relay key and our own node key, never a value
// from the Challenge, and the signature it returns verifies over exactly those
// values with the nonce and time of that Challenge.
//
// spec: SPO-Xmailbox-SEC-029, SPO-Xmailbox-OUT-040, SPO-Xmailbox-IF-008
func TestSignerGetsThePinnedKeyAndOwnNodeKey(t *testing.T) {
	h := newHostile(t, putOK)
	c := h.client()
	if err := sendOnce(c); err != nil {
		t.Fatal(err)
	}
	calls := h.me.sg.calls()
	if len(calls) != 1 {
		t.Fatalf("signer calls = %d", len(calls))
	}
	got := calls[0]
	if got.relayKey != h.relay.Key {
		t.Fatalf("signer was given relay key %x, not the pinned %x", got.relayKey, h.relay.Key)
	}
	if got.nodeKey != h.me.node.Key {
		t.Fatalf("signer was given node key %x, not our own", got.nodeKey)
	}
	if got.version != 1 {
		t.Fatalf("version = %d", got.version)
	}
	h.mu.Lock()
	rec := h.auths[0]
	h.mu.Unlock()
	if got.nonce != rec.nonce || got.relayTime != rec.relayTime {
		t.Fatal("the signer was not given the nonce and the relay time of the Challenge")
	}
	if rec.auth.Fingerprint != h.me.fp || rec.auth.Version != 1 {
		t.Fatal("Auth does not carry our fingerprint and the chosen version")
	}
	err := wire.VerifyAuth(h.me.id, h.me.node.Key, rec.auth.Signature, wire.AuthParams{Version: 1, RelayKey: h.relay.Key,
		ClientNodeKey: h.me.node.Key, Nonce: rec.nonce, RelayTime: rec.relayTime, Fingerprint: h.me.fp})
	if err != nil {
		t.Fatalf("the relay cannot verify the Auth: %v", err)
	}
}

// A signer that fails ends the handshake: nothing is sent and the failure is
// returned from Receive and, as no route, from Send.
//
// spec: SPO-Xmailbox-PRE-024
func TestSignerFailureEndsTheHandshake(t *testing.T) {
	h := newHostile(t, func(s *sconn) {
		s.challenge(hs{})
		s.waitClosed()
	})
	h.me.sg.err = errors.New("no key")
	c := h.client()
	if err := sendOnce(c); !errors.Is(err, mailbox.ErrSigner) || !errors.Is(err, ports.ErrNoRoute) {
		t.Fatalf("Send = %v", err)
	}
	if h.authCount() != 0 {
		t.Fatal("an Auth was sent although the signer failed")
	}
}

// The relay's time is used only for the skew warning: more than five minutes
// off warns, exactly five does not, an absurd value warns and the handshake
// still completes with the value signed as given.
//
// spec: SPO-Xmailbox-OUT-040, SPO-Xmailbox-OUT-042
func TestRelayTimeOnlyWarns(t *testing.T) {
	const now = 1_700_000_000
	for _, tc := range []struct {
		name string
		rt   int64
		warn bool
	}{
		{"same", now, false},
		{"five minutes ahead", now + 300, false},
		{"five minutes and a second ahead", now + 301, true},
		{"five minutes and a second behind", now - 301, true},
		{"absurd", wire.MaxTime, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHostile(t, func(s *sconn) {
				s.serve(hs{relayTime: tc.rt}, func(m wire.Message) bool {
					if p, ok := m.(wire.Put); ok {
						s.send(wire.PutResult{RequestID: p.RequestID, Status: wire.StatusStored})
					}
					return true
				})
			})
			c := h.client()
			if err := sendOnce(c); err != nil {
				t.Fatalf("a skewed relay clock must not fail the handshake: %v", err)
			}
			ev := h.ev.of(mailbox.EventSkew)
			if tc.warn != (len(ev) == 1) {
				t.Fatalf("skew events = %d, want warning %v", len(ev), tc.warn)
			}
			if tc.warn && ev[0].Skew != max(tc.rt-now, now-tc.rt) {
				t.Fatalf("Skew = %d", ev[0].Skew)
			}
			if got := h.me.sg.calls()[0].relayTime; got != tc.rt {
				t.Fatalf("the signer was given relay time %d, want the Challenge's %d", got, tc.rt)
			}
		})
	}
}

// Every handshake violation: nothing is delivered or sent after it, the
// connection is closed, and it is a protocol error (a misconfiguration or a
// hostile relay), which Receive returns instead of retrying.
//
// spec: SPO-Xmailbox-PRE-024, SPO-Xmailbox-OUT-039
func TestHandshakeViolations(t *testing.T) {
	auth := wire.Auth{Version: 1}
	cases := []struct {
		name   string
		script func(s *sconn)
		is     error
	}{
		{"first frame is a client-only type (Put)", func(s *sconn) {
			s.send(wire.Put{RequestID: 1, Size: 1})
			s.waitClosed()
		}, mailbox.ErrProtocol},
		{"first frame is a client-only type (Auth)", func(s *sconn) { s.send(auth); s.waitClosed() }, mailbox.ErrProtocol},
		{"first frame is PutResult", func(s *sconn) { s.send(wire.PutResult{}); s.waitClosed() }, mailbox.ErrProtocol},
		{"garbage", func(s *sconn) { s.raw([]byte{0, 0, 0, 3, 0xff, 0xff, 0xff}); s.waitClosed() }, mailbox.ErrProtocol},
		{"oversized header claim", func(s *sconn) { s.raw([]byte{0xff, 0xff, 0xff, 0xff}); s.waitClosed() }, mailbox.ErrProtocol},
		{"version range the client cannot speak", func(s *sconn) { s.challenge(hs{min: 2, max: 3}); s.waitClosed() }, mailbox.ErrProtocol},
		{"AuthOK is not AuthOK", func(s *sconn) {
			s.handshake(hs{authOKFunc: func() wire.Message { return wire.PutResult{} }})
			s.waitClosed()
		}, mailbox.ErrProtocol},
		{"AuthOK of another version", func(s *sconn) {
			s.handshake(hs{authOKFunc: func() wire.Message {
				return wire.AuthOK{Version: 2, MaxEnvelope: 1000, MaxEntries: 1, MaxBytes: 1, RetentionSeconds: 1}
			}})
			s.waitClosed()
		}, mailbox.ErrProtocol},
		{"an Error frame instead of the Challenge", func(s *sconn) { s.send(wire.Error{Code: wire.CodeRevoked}); s.waitClosed() }, mailbox.ErrRelayError},
		{"an Error frame instead of AuthOK", func(s *sconn) {
			s.handshake(hs{authOKFunc: func() wire.Message { return wire.Error{Code: wire.CodeAuth} }})
			s.waitClosed()
		}, mailbox.ErrRelayError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHostile(t, tc.script)
			c := h.client()
			err := sendOnce(c)
			if !errors.Is(err, ports.ErrNoRoute) || !errors.Is(err, tc.is) {
				t.Fatalf("Send = %v, want ErrNoRoute wrapping %v", err, tc.is)
			}
			if errors.Is(err, ports.ErrRefusedByTransport) {
				t.Fatal("a handshake failure must not look like a refusal of the item")
			}
			waitFor(t, "the client to close", func() bool { return h.closedCount() == 1 })
			// Receive returns it: nothing is delivered
			c2 := h.client()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			got, rerr := c2.Receive(ctx)
			if !errors.Is(rerr, tc.is) || len(got.Envelope) != 0 {
				t.Fatalf("Receive = (%d bytes, %v), want error %v", len(got.Envelope), rerr, tc.is)
			}
		})
	}
}

// A relay that stalls at each state of the handshake costs the client the
// handshake timeout and no more; the client closes and the failure is no route.
//
// spec: SPO-Xmailbox-OUT-041, SPO-Xmailbox-SEC-027
func TestStallDuringTheHandshake(t *testing.T) {
	for name, script := range map[string]func(s *sconn){
		"no Challenge":  func(s *sconn) { s.waitClosed() },
		"no AuthOK":     func(s *sconn) { s.handshake(hs{noAuthOK: true}); s.waitClosed() },
		"half a header": func(s *sconn) { s.raw([]byte{0, 0, 0, 40, 1, 2}); s.waitClosed() },
	} {
		t.Run(name, func(t *testing.T) {
			h := newHostile(t, script)
			c := h.client()
			t0 := time.Now()
			err := sendOnce(c)
			if d := time.Since(t0); d > 1500*time.Millisecond {
				t.Fatalf("the stalled handshake took %v", d)
			}
			if !errors.Is(err, ports.ErrNoRoute) || !errors.Is(err, mailbox.ErrUnreachable) {
				t.Fatalf("Send = %v, want ErrNoRoute wrapping ErrUnreachable", err)
			}
			waitFor(t, "the client to close", func() bool { return h.closedCount() == 1 })
		})
	}
}

// The relay's limits in AuthOK can only tighten the client's own: an envelope
// above the announced limit is not sent and is refused by the transport, and
// a relay that announces more than the client allows does not loosen it.
//
// spec: SPO-Xmailbox-OUT-040
func TestAuthOKTightensTheEnvelopeLimit(t *testing.T) {
	puts := make(chan wire.Put, 8)
	h := newHostile(t, func(s *sconn) {
		s.serve(hs{maxEnv: 1000}, func(m wire.Message) bool {
			if p, ok := m.(wire.Put); ok {
				puts <- p
				s.send(wire.PutResult{RequestID: p.RequestID, Status: wire.StatusStored})
			}
			return true
		})
	})
	c := h.client()
	if err := c.Send(context.Background(), party.Fingerprint{1}, newEnv(1000, 1)); err != nil {
		t.Fatalf("at the announced limit: %v", err)
	}
	err := c.Send(context.Background(), party.Fingerprint{1}, newEnv(1001, 1))
	if !errors.Is(err, ports.ErrRefusedByTransport) {
		t.Fatalf("one byte over the announced limit = %v, want ErrRefusedByTransport", err)
	}
	if len(puts) != 1 {
		t.Fatalf("%d Puts reached the relay, want only the one at the limit", len(puts))
	}
	// the client's own limit is tighter than what the relay announces
	h2 := newHostile(t, putOK)
	c2 := h2.client(func(cfg *mailbox.Config) { cfg.Limits.MaxEnvelope = 500 })
	if err := c2.Send(context.Background(), party.Fingerprint{1}, newEnv(501, 1)); !errors.Is(err, ports.ErrRefusedByTransport) {
		t.Fatalf("over the client's own limit = %v", err)
	}
	if err := c2.Send(context.Background(), party.Fingerprint{1}, newEnv(500, 1)); err != nil {
		t.Fatalf("at the client's own limit: %v", err)
	}
}

// A limit above the table is refused at construction.
//
// spec: SPO-Xmailbox-IF-009
func TestLimitsAboveTheTableAreRefused(t *testing.T) {
	h := newHostile(t, putOK)
	for name, f := range map[string]func(*mailbox.Limits){
		"envelope": func(l *mailbox.Limits) { l.MaxEnvelope = wire.MaxEnvelopeBytes + 1 },
		"items":    func(l *mailbox.Limits) { l.MaxItems = wire.MaxItemsPerFetch + 1 },
		"wait":     func(l *mailbox.Limits) { l.WaitSeconds = wire.MaxFetchWaitSeconds + 1 },
		"requests": func(l *mailbox.Limits) { l.MaxRequests = wire.MaxRequestsPerConn + 1 },
		"written":  func(l *mailbox.Limits) { l.MaxBytesWritten = wire.MaxBytesPerConn + 1 },
		"read":     func(l *mailbox.Limits) { l.MaxBytesRead = wire.MaxBytesSentPerConn + 1 },
		"lifetime": func(l *mailbox.Limits) { l.ConnLifetime = wire.ConnLifetime + 1 },
		"negative": func(l *mailbox.Limits) { l.IdleTimeout = -1 },
		"dials":    func(l *mailbox.Limits) { l.DialsPerMinute = wire.MaxNewConnsPerKeyPerMinute + 1 },
		"dials<0":  func(l *mailbox.Limits) { l.DialsPerMinute = -1 },
		"backoff":  func(l *mailbox.Limits) { l.BackoffMin, l.BackoffMax = time.Second, time.Millisecond },
	} {
		cfg := mailbox.Config{Dialer: h.net.Dialer(h.me.node, h.relay), RelayKey: h.relay.Key, NodeKey: h.me.node.Key, Self: h.me.fp,
			Signer: h.me.sg, Clock: relayClock(1)}
		f(&cfg.Limits)
		if _, err := mailbox.New(cfg); !errors.Is(err, mailbox.ErrLimits) {
			t.Errorf("%s: New = %v, want ErrLimits", name, err)
		}
	}
	// the ceilings themselves are accepted, and so is the zero value
	ok := mailbox.DefaultLimits()
	if _, err := mailbox.New(mailbox.Config{Dialer: h.net.Dialer(h.me.node, h.relay), RelayKey: h.relay.Key, NodeKey: h.me.node.Key,
		Self: h.me.fp, Signer: h.me.sg, Clock: relayClock(1), Limits: ok}); err != nil {
		t.Fatalf("the table itself: %v", err)
	}
	for name, cfg := range map[string]mailbox.Config{
		"no dialer": {RelayKey: h.relay.Key, NodeKey: h.me.node.Key, Self: h.me.fp, Signer: h.me.sg, Clock: relayClock(1)},
		"no key":    {Dialer: h.net.Dialer(h.me.node, h.relay), NodeKey: h.me.node.Key, Self: h.me.fp, Signer: h.me.sg, Clock: relayClock(1)},
		"no node":   {Dialer: h.net.Dialer(h.me.node, h.relay), RelayKey: h.relay.Key, Self: h.me.fp, Signer: h.me.sg, Clock: relayClock(1)},
		"no self":   {Dialer: h.net.Dialer(h.me.node, h.relay), RelayKey: h.relay.Key, NodeKey: h.me.node.Key, Signer: h.me.sg, Clock: relayClock(1)},
		"no signer": {Dialer: h.net.Dialer(h.me.node, h.relay), RelayKey: h.relay.Key, NodeKey: h.me.node.Key, Self: h.me.fp, Clock: relayClock(1)},
		"no clock":  {Dialer: h.net.Dialer(h.me.node, h.relay), RelayKey: h.relay.Key, NodeKey: h.me.node.Key, Self: h.me.fp, Signer: h.me.sg},
	} {
		if _, err := mailbox.New(cfg); err == nil {
			t.Errorf("%s: New accepted an incomplete configuration", name)
		}
	}
}
