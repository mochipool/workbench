package mailbox_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

func sendOnce(c *mailbox.Client) error {
	return c.Send(context.Background(), party.Fingerprint{1}, newEnv(100, 1))
}

func putOK(s *sconn) {
	s.serve(hs{}, func(m wire.Message) bool {
		if p, ok := m.(wire.PutV2); ok {
			s.send(wire.PutResult{RequestID: p.RequestID, Status: wire.StatusStored})
		}
		return true
	})
}

// The key the dialer reports must be the pinned key: a tunnel that reports
// another key is closed on before the relay's Challenge is read, nothing is
// signed and nothing is sent.
//
// spec: SPO-Xmailbox-PRE-024, SPO-Xmailbox-OUT-089
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
// anything is signed or revoked: the relay sees the client close and never an
// Auth or a Revoke, even with a revoke pending.
//
// spec: SPO-Xmailbox-PRE-024, SPO-Xmailbox-SEC-029, SPO-Xmailbox-OUT-089
func TestChallengeWithAnotherRelayKeyClosesWithoutSigning(t *testing.T) {
	other := party.NodeKey{7, 7, 7}
	closed := make(chan bool, 4)
	h := newHostile(t, func(s *sconn) {
		s.challenge(hs{relayKey: &other})
		closed <- s.waitClosed()
	})
	rs := h.me.wallet.RevokeStatement(party.Fingerprint{9}, false, startTime-10)
	h.book = &testBook{pending: []mailbox.Revoke{{Kind: mailbox.RevokeByWalletKey, Until: h.me.until, Sign1: rs.Sign1, Key: rs.COSEKey}}}
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
	if h.authCount() != 0 || len(h.revokeRecs()) != 0 {
		t.Fatal("an Auth or a Revoke reached a relay that is not the pinned one")
	}
}

// The signer is given the pinned relay key and our own node key, never a value
// from the Challenge, and the signature it returns verifies, at the relay, over
// exactly those values with the nonce and time of that Challenge, the full hash
// of the binding presented and the hash of the canonical sender list presented.
// The Auth carries the device's fingerprint and keys, the binding bytes as given
// and the canonical (sorted, unique) list.
//
// spec: SPO-Xmailbox-SEC-029, SPO-Xmailbox-SEC-071, SPO-Xmailbox-OUT-089, SPO-Xmailbox-IF-017
func TestSignerGetsThePinnedKeyAndOwnNodeKey(t *testing.T) {
	h := newHostile(t, putOK)
	hi, lo, mid := wire.WalletKey{9}, wire.WalletKey{1}, wire.WalletKey{5}
	c := h.client(func(cfg *mailbox.Config) { cfg.Senders = []wire.WalletKey{hi, lo, hi, mid, lo} })
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
	h.mu.Lock()
	rec := h.auths[0]
	h.mu.Unlock()
	if got.nonce != rec.nonce || got.relayTime != rec.relayTime {
		t.Fatal("the signer was not given the nonce and the relay time of the Challenge")
	}
	a := rec.auth
	if a.Fingerprint != h.me.fp || a.Keys != h.me.keys {
		t.Fatal("Auth does not carry our fingerprint and our device keys")
	}
	if !bytes.Equal(a.Sign1, h.me.stmt.Sign1) || !bytes.Equal(a.Key, h.me.stmt.COSEKey) {
		t.Fatal("Auth does not carry the binding as it was given")
	}
	want := []wire.WalletKey{lo, mid, hi}
	if len(a.Senders) != 3 || a.Senders[0] != want[0] || a.Senders[1] != want[1] || a.Senders[2] != want[2] {
		t.Fatalf("Auth senders = %x, want the sorted unique list %x", a.Senders, want)
	}
	sh, err := wire.SendersHash(want)
	if err != nil {
		t.Fatal(err)
	}
	if got.sendersHash != sh {
		t.Fatal("the signer was not given the hash of the canonical sender list")
	}
	st, err := relaybind.ParseStatement(h.me.stmt.Sign1)
	if err != nil {
		t.Fatal(err)
	}
	if got.bindingHash != st.FullHash() {
		t.Fatal("the signer was not given the full hash of the binding presented")
	}
	// the relay verifies the Auth as app/relay does
	err = wire.VerifyAuthV2(a.Keys, h.me.node.Key, a.Signature, wire.AuthV2Params{RelayKey: h.relay.Key,
		ClientNodeKey: h.me.node.Key, Nonce: rec.nonce, RelayTime: rec.relayTime, Fingerprint: h.me.fp,
		BindingHash: st.FullHash(), SendersHash: sh})
	if err != nil {
		t.Fatalf("the relay cannot verify the Auth: %v", err)
	}
	vkey, err := relaybind.ParseCOSEKey(a.Key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := relaybind.VerifyBinding(st, vkey, a.Keys.Fingerprint(), startTime, relaybind.DefaultPolicy()); err != nil {
		t.Fatalf("the relay cannot verify the binding: %v", err)
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
// spec: SPO-Xmailbox-OUT-089, SPO-Xmailbox-OUT-042
func TestRelayTimeOnlyWarns(t *testing.T) {
	const now = startTime
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
					if p, ok := m.(wire.PutV2); ok {
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
// hostile relay), which Receive returns instead of retrying. The version 1
// frames of the former protocol are among them: there is one version.
//
// spec: SPO-Xmailbox-PRE-024, SPO-Xmailbox-PRE-058, SPO-Xmailbox-OUT-039, SPO-Xmailbox-SEC-072
func TestHandshakeViolations(t *testing.T) {
	auth := wire.AuthV2{Sign1: []byte{1}, Key: []byte{1}}
	untilOf := func() int64 { return startTime + 30*24*3600 }
	okLimits := func(until uint64) []any {
		return []any{uint64(wire.MsgAuthOK), uint64(2), uint64(1000), uint64(1), uint64(1), uint64(1), until}
	}
	cases := []struct {
		name   string
		script func(s *sconn)
		is     error
	}{
		{"first frame is a client-only type (Put)", func(s *sconn) {
			s.send(wire.PutV2{RequestID: 1, Size: 1})
			s.waitClosed()
		}, mailbox.ErrProtocol},
		{"first frame is a client-only type (Auth)", func(s *sconn) { s.send(auth); s.waitClosed() }, mailbox.ErrProtocol},
		{"first frame is a client-only type (Revoke)", func(s *sconn) {
			s.send(wire.RevokeByWallet{RequestID: 1, Sign1: []byte{1}, Key: []byte{1}})
			s.waitClosed()
		}, mailbox.ErrProtocol},
		{"first frame is PutResult", func(s *sconn) { s.send(wire.PutResult{}); s.waitClosed() }, mailbox.ErrProtocol},
		{"garbage", func(s *sconn) { s.raw([]byte{0, 0, 0, 3, 0xff, 0xff, 0xff}); s.waitClosed() }, mailbox.ErrProtocol},
		{"oversized header claim", func(s *sconn) { s.raw([]byte{0xff, 0xff, 0xff, 0xff}); s.waitClosed() }, mailbox.ErrProtocol},
		{"a Challenge that offers only version 1", func(s *sconn) { s.challenge(hs{min: 1, max: 1}); s.waitClosed() }, mailbox.ErrProtocol},
		{"version range above what the client speaks", func(s *sconn) { s.challenge(hs{min: 3, max: 4}); s.waitClosed() }, mailbox.ErrProtocol},
		{"a malformed version range", func(s *sconn) {
			s.header([]any{uint64(0), uint64(0), uint64(2), make([]byte, 32), make([]byte, 32), uint64(1)})
			s.waitClosed()
		}, mailbox.ErrProtocol},
		{"AuthOK is not AuthOK", func(s *sconn) {
			s.handshake(hs{authOKFunc: func() wire.Message { return wire.PutResult{} }})
			s.waitClosed()
		}, mailbox.ErrProtocol},
		{"a RevokeResult instead of AuthOK", func(s *sconn) {
			s.handshake(hs{authOKFunc: func() wire.Message { return wire.RevokeResult{RequestID: 1, Status: wire.RevokeRecorded} }})
			s.waitClosed()
		}, mailbox.ErrProtocol},
		{"an AuthOK in the shape of version 1 (no until)", func(s *sconn) {
			s.handshake(hs{noAuthOK: true})
			s.header([]any{uint64(wire.MsgAuthOK), uint64(1), uint64(1000), uint64(1), uint64(1), uint64(1)})
			s.waitClosed()
		}, mailbox.ErrProtocol},
		{"an AuthOK of version 1 with an until", func(s *sconn) {
			s.handshake(hs{noAuthOK: true})
			s.header([]any{uint64(wire.MsgAuthOK), uint64(1), uint64(1000), uint64(1), uint64(1), uint64(1), uint64(untilOf())})
			s.waitClosed()
		}, mailbox.ErrProtocol},
		{"an AuthOK with an until of zero", func(s *sconn) {
			s.handshake(hs{noAuthOK: true})
			s.header(okLimits(0))
			s.waitClosed()
		}, mailbox.ErrProtocol},
		{"an AuthOK with an until beyond the binding's", func(s *sconn) {
			s.handshake(hs{until: untilOf() + 1})
			s.waitClosed()
		}, mailbox.ErrProtocol},
		{"an AuthOK with an until that has passed", func(s *sconn) {
			s.handshake(hs{until: startTime - 1})
			s.waitClosed()
		}, mailbox.ErrProtocol},
		{"an AuthOK that announces nothing it may announce", func(s *sconn) {
			s.handshake(hs{noAuthOK: true})
			s.header([]any{uint64(wire.MsgAuthOK), uint64(2), uint64(0), uint64(1), uint64(1), uint64(1), uint64(untilOf())})
			s.waitClosed()
		}, mailbox.ErrProtocol},
		{"an Error frame with a code of no version", func(s *sconn) { s.header([]any{uint64(wire.MsgError), uint64(8)}); s.waitClosed() }, mailbox.ErrProtocol},
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

// A Challenge that offers only version 1 is refused with the version error of the
// domain behind it, before anything is signed or sent: there is no downgrade.
//
// spec: SPO-Xmailbox-PRE-058, SPO-Xmailbox-SEC-072, SPO-Xmailbox-OUT-050
func TestAChallengeOfVersionOneOnlyIsRefusedAndNothingIsSigned(t *testing.T) {
	h := newHostile(t, func(s *sconn) {
		s.challenge(hs{min: 1, max: 1})
		s.waitClosed()
	})
	err := sendOnce(h.client())
	if !errors.Is(err, mailbox.ErrProtocol) || !errors.Is(err, wire.ErrVersion) {
		t.Fatalf("Send = %v, want ErrProtocol wrapping the domain's ErrVersion", err)
	}
	if n := len(h.me.sg.calls()); n != 0 || h.authCount() != 0 {
		t.Fatalf("%d signatures and %d Auths after a Challenge that offers only version 1", n, h.authCount())
	}
	var failed bool
	for _, e := range h.ev.of(mailbox.EventFailed) {
		failed = failed || e.Reason == mailbox.ReasonVersion
	}
	if !failed {
		t.Fatal("no failure event with the reason version")
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
// spec: SPO-Xmailbox-OUT-089
func TestAuthOKTightensTheEnvelopeLimit(t *testing.T) {
	puts := make(chan wire.PutV2, 8)
	h := newHostile(t, func(s *sconn) {
		s.serve(hs{maxEnv: 1000}, func(m wire.Message) bool {
			if p, ok := m.(wire.PutV2); ok {
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
		cfg := h.config(h.net.Dialer(h.me.node, h.relay))
		cfg.Limits = mailbox.Limits{}
		f(&cfg.Limits)
		if _, err := mailbox.New(cfg); !errors.Is(err, mailbox.ErrLimits) {
			t.Errorf("%s: New = %v, want ErrLimits", name, err)
		}
	}
	// the ceilings themselves are accepted, and so is the zero value
	ok := h.config(h.net.Dialer(h.me.node, h.relay))
	ok.Limits = mailbox.DefaultLimits()
	if _, err := mailbox.New(ok); err != nil {
		t.Fatalf("the table itself: %v", err)
	}
}
