package mailbox_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

// revokeConfig is the configuration of a revoke-only sender on the hostile rig's
// device: a dialer, the pinned relay key, a clock, the limits, the book and the
// events. There is no binding, no signer, no sender list and no resolver.
func (h *hostile) revokeConfig(d relayport.StreamDialer, book mailbox.RevokeBook) mailbox.RevokeConfig {
	cfg := h.config(d)
	return mailbox.RevokeConfig{Dialer: d, RelayKey: h.relay.Key, Clock: cfg.Clock, Revokes: book, Limits: cfg.Limits, Events: h.ev.sink}
}

func (h *hostile) revokeSender(book mailbox.RevokeBook, opts ...func(*mailbox.RevokeConfig)) *mailbox.RevokeSender {
	h.t.Helper()
	cfg := h.revokeConfig(h.net.Dialer(h.me.node, h.relay), book)
	for _, o := range opts {
		o(&cfg)
	}
	s, err := mailbox.NewRevokeSender(cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { s.Close() })
	return s
}

// ownDeviceRevoke is the revoke of p's own device signed by its device key, as
// "forget this device" makes it.
func ownDeviceRevoke(t testing.TB, p *peer, notBefore int64) mailbox.Revoke {
	t.Helper()
	msg, err := relaybind.DeviceRevokeBytes(p.fp, notBefore)
	if err != nil {
		t.Fatal(err)
	}
	var sig [64]byte
	copy(sig[:], ed25519.Sign(p.priv, msg))
	return mailbox.Revoke{Kind: mailbox.RevokeByDeviceKey, Until: p.until, Keys: p.keys, NotBefore: notBefore, Signature: sig}
}

// NewRevokeSender takes no binding, no signer, no sender list and no resolver:
// it needs the dialer, the pinned relay key, a clock and a book, and checks its
// limits and its policy as New does.
//
// spec: SPO-Xmailbox-IF-019
func TestARevokeSenderIsConfiguredWithoutAnIdentity(t *testing.T) {
	h := newHostile(t, putOK)
	for name, edit := range map[string]func(*mailbox.RevokeConfig){
		"no dialer":       func(c *mailbox.RevokeConfig) { c.Dialer = nil },
		"no relay key":    func(c *mailbox.RevokeConfig) { c.RelayKey = party.NodeKey{} },
		"no clock":        func(c *mailbox.RevokeConfig) { c.Clock = nil },
		"no book":         func(c *mailbox.RevokeConfig) { c.Revokes = nil },
		"bad limits":      func(c *mailbox.RevokeConfig) { c.Limits.BackoffMin = -time.Second },
		"a policy beyond": func(c *mailbox.RevokeConfig) { c.Policy = relaybind.Policy{Skew: 301, MaxLifetime: 3600} },
	} {
		cfg := h.revokeConfig(h.net.Dialer(h.me.node, h.relay), &testBook{})
		edit(&cfg)
		if s, err := mailbox.NewRevokeSender(cfg); err == nil {
			s.Close()
			t.Errorf("%s: NewRevokeSender accepted it", name)
		}
	}
}

// A revoke-only sender sends the pending revokes before any login, on a
// connection of its own, and closes it after the last answer: no Auth reaches
// the relay (it has nothing to sign with and no binding to present). It reports
// each outcome, dials nothing when nothing is pending, honours its context and is
// ErrClosed after Close.
//
// spec: SPO-Xmailbox-IF-019, SPO-Xmailbox-OUT-090
func TestARevokeSenderSendsRevokesAndNeverAnAuth(t *testing.T) {
	h := newHostile(t, func(s *sconn) {
		s.handshake(hs{})
		s.waitClosed()
	})
	r1 := walletRevoke(h.me, party.Fingerprint{1}, startTime-10)
	r2, _ := deviceRevoke(t, "two", startTime-5, h.me.until)
	book := &testBook{pending: []mailbox.Revoke{r1, r2}}
	s := h.revokeSender(book)
	rep, err := s.SendRevokes(context.Background())
	if err != nil {
		t.Fatalf("SendRevokes = %v", err)
	}
	if rep.Count(mailbox.RevokeRecorded) != 2 || len(rep.Results) != 2 {
		t.Fatalf("report = %+v, want two recorded", rep)
	}
	if n := len(h.revokeRecs()); n != 2 {
		t.Fatalf("%d revokes reached the relay, want 2", n)
	}
	waitFor(t, "the sender to close the connection", func() bool { return h.closedCount() == 1 })
	if h.authCount() != 0 {
		t.Fatal("a revoke-only sender sent an Auth")
	}
	if len(h.me.sg.calls()) != 0 {
		t.Fatal("something signed")
	}
	// nothing pending: no dial
	book2 := &testBook{}
	if rep, err := h.revokeSender(book2).SendRevokes(context.Background()); err != nil || len(rep.Results) != 0 || h.connCount() != 1 {
		t.Fatalf("SendRevokes with nothing pending = %+v, %v after %d connections", rep, err, h.connCount())
	}
	if _, err := h.revokeSender(book).SendRevokes(canceled()); !errors.Is(err, context.Canceled) {
		t.Fatalf("SendRevokes with a cancelled context = %v", err)
	}
	s.Close()
	if _, err := s.SendRevokes(context.Background()); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("SendRevokes after Close = %v", err)
	}
}

// The revoke-only exchange keeps every check of the handshake: the key the dialer
// reports and the key in the Challenge are the pinned key, the Challenge offers
// version 2, every frame is bounded and checked, a stall costs the handshake
// timeout. Each failure is an error of the call, nothing is sent after it, no
// revoke is dropped and the connection is closed.
//
// spec: SPO-Xmailbox-IF-019, SPO-Xmailbox-PRE-024, SPO-Xmailbox-PRE-058, SPO-Xmailbox-OUT-090
func TestTheRevokeOnlyExchangeAgainstAHostileRelay(t *testing.T) {
	other := party.NodeKey{7, 7, 7}
	answer := func(f func(s *sconn, id uint32)) func(s *sconn) {
		return func(s *sconn) {
			s.challenge(hs{})
			m, err := s.recv()
			if err != nil {
				return
			}
			s.stage, _ = s.stage.AfterRevoke(m)
			s.h.mu.Lock()
			s.h.revokes = append(s.h.revokes, revokeRec{conn: s.n, msg: m})
			s.h.mu.Unlock()
			f(s, m.(wire.RevokeByWallet).RequestID)
			s.waitClosed()
		}
	}
	cases := []struct {
		name    string
		script  func(s *sconn)
		fault   *fakenet.Fault
		is      error
		revokes int // how many reach the relay
	}{
		{"the dialer reports another key", putOK, &fakenet.Fault{ShowListenerAs: &other}, mailbox.ErrRelayKey, 0},
		{"the Challenge names another key", func(s *sconn) { s.challenge(hs{relayKey: &other}); s.waitClosed() }, nil, mailbox.ErrRelayKey, 0},
		{"the Challenge offers only version 1", func(s *sconn) { s.challenge(hs{min: 1, max: 1}); s.waitClosed() }, nil, wire.ErrVersion, 0},
		{"the first frame is not a Challenge", func(s *sconn) { s.send(wire.PutResult{}); s.waitClosed() }, nil, mailbox.ErrProtocol, 0},
		{"an oversized header claim", func(s *sconn) { s.raw([]byte{0xff, 0xff, 0xff, 0xff}); s.waitClosed() }, nil, mailbox.ErrProtocol, 0},
		{"a wrong request id", answer(func(s *sconn, id uint32) { s.send(wire.RevokeResult{RequestID: id + 1, Status: wire.RevokeRecorded}) }), nil, mailbox.ErrProtocol, 1},
		{"a status that does not exist", answer(func(s *sconn, id uint32) { s.header([]any{uint64(wire.MsgRevokeResult), uint64(id), uint64(1)}) }), nil, mailbox.ErrProtocol, 1},
		{"an AuthOK", answer(func(s *sconn, id uint32) {
			s.send(wire.AuthOKV2{MaxEnvelope: 1000, MaxEntries: 1, MaxBytes: 1, RetentionSeconds: 1, Until: startTime + 100})
		}), nil, mailbox.ErrProtocol, 1},
		{"a Challenge again", answer(func(s *sconn, id uint32) { s.challenge(hs{}) }), nil, mailbox.ErrProtocol, 1},
		{"an Error frame", answer(func(s *sconn, id uint32) { s.send(wire.Error{Code: wire.CodeLimit}) }), nil, mailbox.ErrRelayError, 1},
		{"no answer", answer(func(s *sconn, id uint32) {}), nil, mailbox.ErrUnreachable, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHostile(t, tc.script)
			d := h.net.Dialer(h.me.node, h.relay)
			if tc.fault != nil {
				d.Always(*tc.fault)
			}
			book := &testBook{pending: []mailbox.Revoke{walletRevoke(h.me, party.Fingerprint{1}, startTime-10)}}
			s, err := mailbox.NewRevokeSender(h.revokeConfig(d, book))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			t0 := time.Now()
			_, err = s.SendRevokes(context.Background())
			if !errors.Is(err, tc.is) {
				t.Fatalf("SendRevokes = %v, want %v", err, tc.is)
			}
			if d := time.Since(t0); d > 1500*time.Millisecond {
				t.Fatalf("took %v", d)
			}
			if n := len(h.revokeRecs()); n != tc.revokes {
				t.Fatalf("%d revokes reached the relay, want %d", n, tc.revokes)
			}
			if h.authCount() != 0 {
				t.Fatal("an Auth reached the relay")
			}
			for _, o := range book.outcomes() {
				if o.Final() {
					t.Fatalf("outcome %v is final: a failure of the relay must not drop a revoke", o)
				}
			}
			if tc.fault == nil {
				waitFor(t, "the sender to close", func() bool { return h.closedCount() == 1 })
			}
		})
	}
}

// The revoke-only sender is bounded like the client: its own dial limit holds
// (a call beyond it waits, and ends with its context, without a dial), the read
// bound of a connection holds, and Close interrupts an exchange that waits for
// the relay.
//
// spec: SPO-Xmailbox-IF-019, SPO-Xmailbox-OUT-044, SPO-Xmailbox-INV-019
func TestARevokeSenderIsBoundedAndInterruptible(t *testing.T) {
	t.Run("the dial limit", func(t *testing.T) {
		h := newHostile(t, func(s *sconn) { s.handshake(hs{}) })
		cd, d := counting(h)
		book := &testBook{pending: []mailbox.Revoke{walletRevoke(h.me, party.Fingerprint{1}, startTime-10)}}
		cfg := h.revokeConfig(d, book)
		cfg.Limits.DialsPerMinute = 1
		s, err := mailbox.NewRevokeSender(cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if _, err := s.SendRevokes(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := s.SendRevokes(ctxFor(t, 300*time.Millisecond)); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("SendRevokes beyond the dial limit = %v, want its deadline", err)
		}
		if cd.count() != 1 {
			t.Fatalf("%d dials, want 1", cd.count())
		}
	})
	t.Run("the read bound", func(t *testing.T) {
		h := newHostile(t, func(s *sconn) { s.handshake(hs{}); s.waitClosed() }) // an honest answer, past the bound
		ch, err := wire.EncodeV(wire.Version2, wire.Challenge{Min: 2, Max: 2, RelayTime: 1_700_000_000})
		if err != nil {
			t.Fatal(err)
		}
		book := &testBook{pending: []mailbox.Revoke{walletRevoke(h.me, party.Fingerprint{1}, startTime-10)}}
		s := h.revokeSender(book, func(c *mailbox.RevokeConfig) { c.Limits.MaxBytesRead = uint64(4 + len(ch) + 2) })
		if _, err := s.SendRevokes(context.Background()); !errors.Is(err, mailbox.ErrProtocol) {
			t.Fatalf("SendRevokes past the read bound = %v, want ErrProtocol", err)
		}
		var limit bool
		for _, e := range h.ev.of(mailbox.EventFailed) {
			limit = limit || e.Reason == mailbox.ReasonLimit
		}
		if !limit {
			t.Fatal("no failure with the reason limit")
		}
	})
	t.Run("Close interrupts", func(t *testing.T) {
		h := newHostile(t, func(s *sconn) {
			s.challenge(hs{})
			if m, err := s.recv(); err == nil {
				s.h.mu.Lock()
				s.h.revokes = append(s.h.revokes, revokeRec{conn: s.n, msg: m})
				s.h.mu.Unlock()
			}
			s.st.SetReadDeadline(time.Now().Add(15 * time.Second))
			io.Copy(io.Discard, s.st) // never answers; ends when the sender closes
		})
		book := &testBook{pending: []mailbox.Revoke{walletRevoke(h.me, party.Fingerprint{1}, startTime-10)}}
		s := h.revokeSender(book, func(c *mailbox.RevokeConfig) {
			c.Limits.HandshakeTimeout = 10 * time.Second
			c.Limits.OpTimeout = 20 * time.Second
		})
		done := make(chan error, 1)
		go func() { _, err := s.SendRevokes(context.Background()); done <- err }()
		waitFor(t, "the revoke to reach the relay", func() bool { return len(h.revokeRecs()) == 1 })
		t0 := time.Now()
		s.Close()
		select {
		case err := <-done:
			if !errors.Is(err, ports.ErrClosed) {
				t.Fatalf("SendRevokes interrupted by Close = %v, want ErrClosed", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Close did not interrupt the exchange")
		}
		if d := time.Since(t0); d > time.Second {
			t.Fatalf("Close took %v to interrupt", d)
		}
	})
}

// A device whose own binding has lapsed can still send its revokes: the client's
// SendRevokes presents no binding, so it neither checks the binding nor waits
// out the backoff that the refused binding caused, and it signs nothing.
//
// spec: SPO-Xmailbox-OUT-090
func TestALapsedBindingDoesNotStopTheRevokes(t *testing.T) {
	h := newHostile(t, func(s *sconn) { s.handshake(hs{}) })
	clk := newStepClock()
	r := walletRevoke(h.me, party.Fingerprint{1}, startTime-10)
	r.Until = h.me.until + 3600 // the binding it revokes ends after the client's own
	book := &testBook{pending: []mailbox.Revoke{r}}
	c := h.client(func(cfg *mailbox.Config) {
		cfg.Clock = clk
		cfg.Revokes = book
		cfg.Limits.BackoffMin, cfg.Limits.BackoffMax = 10*time.Second, 10*time.Second
		cfg.Limits.OpTimeout = 2 * time.Second
	})
	clk.Advance(time.Duration(h.me.until-startTime+1) * time.Second) // past the end of the client's binding
	if err := sendOnce(c); !errors.Is(err, mailbox.ErrBindingRefused) {
		t.Fatalf("Send with a lapsed binding = %v, want ErrBindingRefused", err)
	}
	t0 := time.Now()
	rep, err := c.SendRevokes(context.Background())
	if err != nil || rep.Count(mailbox.RevokeRecorded) != 1 {
		t.Fatalf("SendRevokes with a lapsed binding = %+v, %v", rep, err)
	}
	if d := time.Since(t0); d > time.Second {
		t.Fatalf("SendRevokes waited %v: the backoff of the refused binding was served", d)
	}
	if h.authCount() != 0 || len(h.me.sg.calls()) != 0 {
		t.Fatal("a login was made")
	}
}

// Against the real relay: a new device that has no binding at all (dave, of
// alice's wallet) sends the wallet-signed revoke of alice's lost device with a
// revoke-only sender. The relay records it, alice's binding is gone, and the lost
// device's next login is refused with the `binding` code.
//
// spec: SPO-Xmailbox-IF-019, SPO-Xmailbox-OUT-090
func TestAnUnboundDeviceRevokesALostOneAtTheRealRelay(t *testing.T) {
	w := newWorld(t)
	book := &testBook{pending: []mailbox.Revoke{walletRevoke(w.a, w.a.fp, startTime)}}
	s, err := mailbox.NewRevokeSender(mailbox.RevokeConfig{Dialer: w.net.Dialer(w.d.node, w.relay), RelayKey: w.relay.Key,
		Clock: w.clock, Revokes: book, Limits: fastLimits(), Events: w.ev.sink})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rep, err := s.SendRevokes(context.Background())
	if err != nil || rep.Count(mailbox.RevokeRecorded) != 1 {
		t.Fatalf("SendRevokes = %+v, %v; want one recorded", rep, err)
	}
	if _, ok, _ := w.reg.Lookup(context.Background(), w.a.fp); ok {
		t.Fatal("the relay still serves the lost device")
	}
	if _, ok, _ := w.reg.Lookup(context.Background(), w.d.fp); ok {
		t.Fatal("the unbound device was bound by sending a revoke")
	}
	lost := w.client(w.a)
	if err := lost.Send(context.Background(), w.b.fp, body(10, 1)); !errors.Is(err, mailbox.ErrBindingRefused) {
		t.Fatalf("the lost device's login = %v, want ErrBindingRefused", err)
	}
}
