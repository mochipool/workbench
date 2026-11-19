package mailbox_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// The relay answers a login with the Error code `binding` (the binding is
// invalid, expired or revoked: a new one must be signed) or `not_allowed` (the
// operator's allow-list does not hold the wallet key). The client does not retry
// in a tight loop: Send is no route wrapping a distinct sentinel with a fixed
// reason class, Receive returns the sentinel, an event says why with the longest
// backoff, nothing is dialled inside the backoff, and the code is not transient
// (it does not satisfy ErrUnreachable). A new binding clears the wait.
//
// spec: SPO-Xmailbox-OUT-092, SPO-Xmailbox-PRE-024
func TestTheLoginCodesBindingAndNotAllowedBackOffAndNameTheRemedy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		code   wire.Code
		is     error
		not    error
		reason mailbox.Reason
	}{
		{"binding", wire.CodeBinding, mailbox.ErrBindingRefused, mailbox.ErrNotAllowed, mailbox.ReasonBinding},
		{"not allowed", wire.CodeNotAllowed, mailbox.ErrNotAllowed, mailbox.ErrBindingRefused, mailbox.ReasonNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHostile(t, func(s *sconn) {
				if s.n == 1 {
					s.handshake(hs{authOKFunc: func() wire.Message { return wire.Error{Code: tc.code} }})
					s.waitClosed()
					return
				}
				putOK(s)
			})
			cd, d := counting(h)
			c := h.clientVia(d, func(cfg *mailbox.Config) {
				cfg.Limits.BackoffMin, cfg.Limits.BackoffMax = 20*time.Millisecond, 400*time.Millisecond
			})
			err := sendOnce(c)
			if !errors.Is(err, ports.ErrNoRoute) || !errors.Is(err, tc.is) || !errors.Is(err, mailbox.ErrRelayError) {
				t.Fatalf("Send = %v, want ErrNoRoute wrapping %v and ErrRelayError", err, tc.is)
			}
			if errors.Is(err, tc.not) || errors.Is(err, mailbox.ErrUnreachable) || errors.Is(err, ports.ErrRefusedByTransport) {
				t.Fatalf("Send = %v: the wrong class", err)
			}
			if got := err.Error(); len(got) < 30 {
				t.Fatalf("%q does not say what to do", got)
			}
			var ev []mailbox.Event
			for _, e := range h.ev.of(mailbox.EventFailed) {
				if e.Reason == tc.reason {
					ev = append(ev, e)
				}
			}
			if len(ev) != 1 || !ev[0].HasCode || ev[0].Code != tc.code || ev[0].Backoff != 400*time.Millisecond {
				t.Fatalf("failure events with the reason %s = %+v, want one with the code and the longest backoff", tc.reason, ev)
			}
			// inside the backoff: no dial, whatever is asked
			dials := cd.count()
			for range 5 {
				if err := sendOnce(c); !errors.Is(err, ports.ErrNoRoute) {
					t.Fatalf("Send in the backoff = %v", err)
				}
			}
			if cd.count() != dials {
				t.Fatalf("%d dials inside the backoff", cd.count()-dials)
			}
			if _, err := c.Receive(ctxFor(t, 100*time.Millisecond)); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Receive inside the backoff = %v, want its own deadline while it waits", err)
			}
			if cd.count() != dials {
				t.Fatal("Receive dialled inside the backoff")
			}
			// a new binding clears the wait: the next Send dials at once and the relay accepts
			if err := c.SetBinding(h.me.rebind(startTime-30, startTime+60*24*3600, false)); err != nil {
				t.Fatal(err)
			}
			if err := sendOnce(c); err != nil {
				t.Fatalf("Send after a new binding = %v", err)
			}
			if cd.count() != dials+1 {
				t.Fatalf("%d dials after SetBinding, want one", cd.count()-dials)
			}
		})
	}
}

// While the backoff after a refused identity runs, a Send still says why: it is
// no route wrapping the same sentinel (ErrBindingRefused or ErrNotAllowed), never
// ErrUnreachable with the reason backoff, and nothing is dialled. That holds for
// the relay's codes `binding` and `not_allowed` and for a binding that expired by
// the client's own clock. A Receive whose context outlasts the backoff returns the
// sentinel too. SetBinding ends it.
//
// spec: SPO-Xmailbox-OUT-092, SPO-Xmailbox-OUT-094
func TestSendDuringTheBackoffStillSaysTheIdentityIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		code   wire.Code // 0: the binding expires by the client's clock
		is     error
		reason mailbox.Reason
	}{
		{"the relay's binding code", wire.CodeBinding, mailbox.ErrBindingRefused, mailbox.ReasonBinding},
		{"the relay's not_allowed code", wire.CodeNotAllowed, mailbox.ErrNotAllowed, mailbox.ReasonNotAllowed},
		{"expired by the client's clock", 0, mailbox.ErrBindingRefused, mailbox.ReasonBindingExpired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHostile(t, func(s *sconn) {
				if tc.code != 0 {
					s.handshake(hs{authOKFunc: func() wire.Message { return wire.Error{Code: tc.code} }})
					s.waitClosed()
					return
				}
				putOK(s)
			})
			clk := newStepClock()
			cd, d := counting(h)
			c := h.clientVia(d, func(cfg *mailbox.Config) {
				cfg.Clock = clk
				cfg.Limits.BackoffMin, cfg.Limits.BackoffMax = 20*time.Millisecond, 300*time.Millisecond
			})
			if tc.code == 0 {
				clk.Advance(time.Duration(h.me.until-startTime+1) * time.Second)
			}
			if err := sendOnce(c); !errors.Is(err, tc.is) {
				t.Fatalf("the first Send = %v, want %v", err, tc.is)
			}
			dials := cd.count()
			for i := range 3 {
				err := sendOnce(c)
				if !errors.Is(err, ports.ErrNoRoute) || !errors.Is(err, tc.is) || errors.Is(err, mailbox.ErrUnreachable) {
					t.Fatalf("Send %d inside the backoff = %v, want ErrNoRoute wrapping %v and not ErrUnreachable", i, err, tc.is)
				}
				if !strings.Contains(err.Error(), string(tc.reason)) {
					t.Fatalf("Send %d inside the backoff = %q, want the reason %s", i, err, tc.reason)
				}
			}
			if cd.count() != dials {
				t.Fatalf("%d dials inside the backoff", cd.count()-dials)
			}
			if _, err := c.Receive(ctxFor(t, 2*time.Second)); !errors.Is(err, tc.is) || errors.Is(err, mailbox.ErrUnreachable) {
				t.Fatalf("Receive across the backoff = %v, want %v", err, tc.is)
			}
		})
	}
}

// The refusal a Send reports inside the backoff is the one that set that backoff:
// when a later failure of another kind (here the relay cuts the next handshake)
// sets the wait, a Send inside it is the unreachable relay again, not the old
// refusal. And a revoke-only exchange, which presents no binding, does not end
// the wait of a refused binding: the next Send still dials nothing.
//
// spec: SPO-Xmailbox-OUT-092, SPO-Xmailbox-OUT-090
func TestTheRefusalReportedInTheBackoffIsTheOneThatSetIt(t *testing.T) {
	t.Run("a later failure replaces it", func(t *testing.T) {
		h := newHostile(t, func(s *sconn) {
			if s.n == 1 {
				s.handshake(hs{authOKFunc: func() wire.Message { return wire.Error{Code: wire.CodeBinding} }})
				s.waitClosed()
				return
			}
			s.challenge(hs{}) // then the connection is cut before the AuthOK
		})
		c := h.client(func(cfg *mailbox.Config) {
			cfg.Limits.BackoffMin, cfg.Limits.BackoffMax = 300*time.Millisecond, 300*time.Millisecond
		})
		if err := sendOnce(c); !errors.Is(err, mailbox.ErrBindingRefused) {
			t.Fatalf("Send = %v", err)
		}
		time.Sleep(350 * time.Millisecond)
		if err := sendOnce(c); errors.Is(err, mailbox.ErrBindingRefused) || !errors.Is(err, mailbox.ErrUnreachable) {
			t.Fatalf("Send on the cut connection = %v, want ErrUnreachable", err)
		}
		err := sendOnce(c)
		if errors.Is(err, mailbox.ErrBindingRefused) || !errors.Is(err, mailbox.ErrUnreachable) || !strings.Contains(err.Error(), string(mailbox.ReasonBackoff)) {
			t.Fatalf("Send inside the backoff of the cut = %v, want ErrUnreachable with the reason backoff", err)
		}
	})
	t.Run("a revoke-only exchange does not end it", func(t *testing.T) {
		h := newHostile(t, func(s *sconn) {
			s.handshake(hs{authOKFunc: func() wire.Message { return wire.Error{Code: wire.CodeBinding} }})
			s.waitClosed()
		})
		book := &testBook{pending: []mailbox.Revoke{walletRevoke(h.me, party.Fingerprint{1}, startTime-10)}}
		cd, d := counting(h)
		c := h.clientVia(d, func(cfg *mailbox.Config) {
			cfg.Revokes = book
			cfg.Limits.BackoffMin, cfg.Limits.BackoffMax = 5*time.Second, 5*time.Second
		})
		if err := sendOnce(c); !errors.Is(err, mailbox.ErrBindingRefused) {
			t.Fatalf("Send = %v", err)
		}
		if _, err := c.SendRevokes(context.Background()); err != nil {
			t.Fatalf("SendRevokes = %v", err)
		}
		dials := cd.count()
		if err := sendOnce(c); !errors.Is(err, mailbox.ErrBindingRefused) {
			t.Fatalf("Send after the revokes = %v, want the refusal still", err)
		}
		if cd.count() != dials {
			t.Fatal("the revoke-only exchange ended the wait of the refused binding: the Send dialled")
		}
	})
}

// Receive returns the sentinel of a refused binding or of a key that is not
// allowed, and does not retry it (it is not transient).
//
// spec: SPO-Xmailbox-OUT-092
func TestReceiveReturnsABindingRefusalWithoutRetrying(t *testing.T) {
	for name, code := range map[string]wire.Code{"binding": wire.CodeBinding, "not allowed": wire.CodeNotAllowed} {
		t.Run(name, func(t *testing.T) {
			h := newHostile(t, func(s *sconn) {
				s.handshake(hs{authOKFunc: func() wire.Message { return wire.Error{Code: code} }})
				s.waitClosed()
			})
			c := h.client()
			_, err := c.Receive(ctxFor(t, 2*time.Second))
			want := mailbox.ErrBindingRefused
			if code == wire.CodeNotAllowed {
				want = mailbox.ErrNotAllowed
			}
			if !errors.Is(err, want) || errors.Is(err, mailbox.ErrUnreachable) {
				t.Fatalf("Receive = %v, want %v", err, want)
			}
			if h.connCount() != 1 {
				t.Fatalf("%d connections: the refusal was retried", h.connCount())
			}
		})
	}
}

// The same codes in the middle of a session (the relay ends a session whose
// binding was revoked or has ended with the `binding` code) are the same
// sentinels.
//
// spec: SPO-Xmailbox-OUT-092
func TestTheBindingCodeInTheMiddleOfASessionIsTheSameRefusal(t *testing.T) {
	h := newHostile(t, func(s *sconn) {
		if !s.handshake(hs{}) {
			return
		}
		if _, _, err := s.readPut(); err != nil {
			return
		}
		s.send(wire.Error{Code: wire.CodeBinding})
		s.waitClosed()
	})
	err := sendOnce(h.client())
	if !errors.Is(err, ports.ErrNoRoute) || !errors.Is(err, mailbox.ErrBindingRefused) {
		t.Fatalf("Send = %v, want ErrNoRoute wrapping ErrBindingRefused", err)
	}
	h2 := newHostile(t, func(s *sconn) {
		s.serve(hs{}, func(m wire.Message) bool {
			if _, ok := m.(wire.Fetch); ok {
				s.send(wire.Error{Code: wire.CodeBinding})
				s.waitClosed()
				return false
			}
			return true
		})
	})
	if _, err := h2.client().Receive(ctxFor(t, 2*time.Second)); !errors.Is(err, mailbox.ErrBindingRefused) {
		t.Fatalf("Receive = %v, want ErrBindingRefused", err)
	}
}

// The other login failures keep their old classes: `auth` is an error of the
// relay (not transient, not a binding problem), `limit` and `shutting down` are
// transient, none is the binding sentinel.
//
// spec: SPO-Xmailbox-OUT-092, SPO-Xmailbox-OUT-038
func TestOtherLoginCodesAreNotTheBindingSentinels(t *testing.T) {
	for _, code := range []wire.Code{wire.CodeVersion, wire.CodeAuth, wire.CodeProtocol, wire.CodeLimit, wire.CodeRevoked, wire.CodeShuttingDown} {
		h := newHostile(t, func(s *sconn) {
			s.handshake(hs{authOKFunc: func() wire.Message { return wire.Error{Code: code} }})
			s.waitClosed()
		})
		err := sendOnce(h.client())
		if !errors.Is(err, ports.ErrNoRoute) || !errors.Is(err, mailbox.ErrRelayError) {
			t.Fatalf("code %d: Send = %v", code, err)
		}
		if errors.Is(err, mailbox.ErrBindingRefused) || errors.Is(err, mailbox.ErrNotAllowed) {
			t.Fatalf("code %d: Send = %v is a binding sentinel", code, err)
		}
	}
}

// Against the real relay: a binding the relay refuses (here: the relay's clock is
// past its end while the client's is not, so the client's own check passes) is the
// `binding` code, and the sentinel. The relay says nothing more.
//
// spec: SPO-Xmailbox-OUT-092
func TestTheRealRelayRefusesAnExpiredBindingWithTheBindingCode(t *testing.T) {
	w := newWorld(t)
	w.clock.Advance(time.Duration(w.a.until-startTime+10) * time.Second) // the relay's clock is past the end
	ca := w.clientVia(w.a, w.net.Dialer(w.a.node, w.relay), func(cfg *mailbox.Config) { cfg.Clock = relayClock(startTime) })
	err := ca.Send(context.Background(), w.b.fp, body(10, 1))
	if !errors.Is(err, ports.ErrNoRoute) || !errors.Is(err, mailbox.ErrBindingRefused) {
		t.Fatalf("Send = %v, want ErrNoRoute wrapping ErrBindingRefused", err)
	}
}

// Logging in again needs no wallet: the client holds the binding as bytes and
// presents the same ones on every connection, signing only with the device key
// through the typed signer, once per connection. After the relay ended the first
// connection the second login presents the identical binding and a fresh
// signature (the relay's nonce differs).
//
// spec: SPO-Xmailbox-OUT-089, SPO-Xmailbox-SEC-071
func TestALoginAgainPresentsTheSameBindingAndNeedsNoWallet(t *testing.T) {
	h := newHostile(t, func(s *sconn) {
		s.serve(hs{}, func(m wire.Message) bool {
			if p, ok := m.(wire.PutV2); ok {
				s.send(wire.PutResult{RequestID: p.RequestID, Status: wire.StatusStored})
				return s.n != 1
			}
			return true
		})
	})
	c := h.client()
	for i := range 2 {
		if err := c.Send(context.Background(), party.Fingerprint{1}, newEnv(20, byte(i))); err != nil {
			t.Fatal(err)
		}
	}
	h.mu.Lock()
	a1, a2 := h.auths[0], h.auths[1]
	h.mu.Unlock()
	if !bytes.Equal(a1.auth.Sign1, a2.auth.Sign1) || !bytes.Equal(a1.auth.Key, a2.auth.Key) || a1.auth.Keys != a2.auth.Keys {
		t.Fatal("the second login did not present the same binding")
	}
	if a1.auth.Signature == a2.auth.Signature || a1.nonce == a2.nonce {
		t.Fatal("the signature or the nonce repeated")
	}
	if n := len(h.me.sg.calls()); n != 2 {
		t.Fatalf("%d signer calls for two logins", n)
	}
}

// The recipe of the package documentation for "forget this device", against the
// real relay: the device handles its queue (receives and acks), books the revoke
// of its own device signed by its device key, sends it with SendRevokes (a
// connection of its own, no login), and closes. The relay recorded it: the
// binding is gone and the device's next login, with the same binding, is refused
// with the `binding` code. After Close every call is ErrClosed.
//
// spec: SPO-Xmailbox-INV-038, SPO-Xmailbox-OUT-090
func TestLogoutRecipeForgetThisDevice(t *testing.T) {
	w := newWorld(t)
	book := &testBook{}
	ca := w.client(w.a, func(cfg *mailbox.Config) { cfg.Revokes = book })
	cb := w.client(w.b)
	if err := cb.Send(context.Background(), w.a.fp, body(50, 1)); err != nil {
		t.Fatal(err)
	}
	// 1. alice handles her queue
	if b := recv(t, ca); !bytes.Equal(b, body(50, 1)) {
		t.Fatal("alice did not receive the envelope")
	}
	if err := ca.Ack(); err != nil {
		t.Fatal(err)
	}
	// 2. she books the revoke of her own device, signed by its key, and sends it
	book.mu.Lock()
	book.pending = []mailbox.Revoke{ownDeviceRevoke(t, w.a, startTime)}
	book.mu.Unlock()
	rep, err := ca.SendRevokes(context.Background())
	if err != nil || rep.Count(mailbox.RevokeRecorded) != 1 {
		t.Fatalf("SendRevokes = %+v, %v; want one recorded", rep, err)
	}
	// 3. she logs out
	ca.Close()
	if err := ca.Send(context.Background(), w.b.fp, body(10, 2)); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("Send after Close = %v", err)
	}
	if _, err := ca.SendRevokes(context.Background()); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("SendRevokes after Close = %v", err)
	}
	// the relay forgot the device: its next login is refused
	if _, ok, _ := w.reg.Lookup(context.Background(), w.a.fp); ok {
		t.Fatal("the relay still serves the forgotten device")
	}
	again := w.client(w.a)
	if err := again.Send(context.Background(), w.b.fp, body(10, 3)); !errors.Is(err, mailbox.ErrBindingRefused) {
		t.Fatalf("the forgotten device's next login = %v, want ErrBindingRefused", err)
	}
	if _, ok, _ := w.reg.Lookup(context.Background(), w.b.fp); !ok {
		t.Fatal("bob's binding went with alice's revoke")
	}
}

// Logout after revoking another device from a bound client: Close ends the
// connection (a dial, a handshake, a long-poll, a put), drops the queue, and
// leaves the binding and the pending revokes alone (the client holds nothing of
// the book). Bob handles his queue, sends a wallet-signed revoke of alice's
// device with SendRevokes, then closes; after Close every later call is
// ErrClosed, SetBinding and SetSenders included, and no dial is made.
//
// spec: SPO-Xmailbox-INV-038, SPO-Xmailbox-INV-019
func TestABoundClientRevokesAnotherDeviceThenLogsOut(t *testing.T) {
	w := newWorld(t)
	rv := walletRevoke(w.a, w.a.fp, startTime)
	book := &testBook{}
	ca := w.client(w.a)
	cb := w.client(w.b, func(cfg *mailbox.Config) { cfg.Revokes = book })
	if err := ca.Send(context.Background(), w.b.fp, body(50, 1)); err != nil {
		t.Fatal(err)
	}
	// bob handles his queue, then revokes alice's device from his own client
	if b := recv(t, cb); !bytes.Equal(b, body(50, 1)) {
		t.Fatal("bob did not receive the envelope")
	}
	if err := cb.Ack(); err != nil {
		t.Fatal(err)
	}
	book.mu.Lock()
	book.pending = []mailbox.Revoke{rv}
	book.mu.Unlock()
	if _, err := cb.SendRevokes(context.Background()); err != nil {
		t.Fatalf("SendRevokes = %v", err)
	}
	if _, ok, _ := w.reg.Lookup(context.Background(), w.a.fp); ok {
		t.Fatal("the relay still serves the revoked device")
	}
	cb.Close()
	if err := cb.Send(context.Background(), w.a.fp, body(10, 2)); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("Send after Close = %v", err)
	}
	if _, err := cb.Receive(context.Background()); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("Receive after Close = %v", err)
	}
	if _, err := cb.SendRevokes(context.Background()); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("SendRevokes after Close = %v", err)
	}
	cb.SetSenders([]wire.WalletKey{wk(1)}) // harmless
	if err := cb.SetBinding(w.b.binding()); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("SetBinding after Close = %v", err)
	}
}
