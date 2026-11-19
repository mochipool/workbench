package mailbox_test

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

// The binding is checked locally, at construction, as the relay would check it,
// so that a client never dials with a binding the relay would refuse: it must
// parse (statement and key), verify, be for this device, be inside its window on
// the client's clock and inside the policy's lifetime. Each check is the only
// thing that refuses in its case.
//
// spec: SPO-Xmailbox-PRE-057, SPO-Xmailbox-IF-016
func TestTheBindingIsValidatedAtConstruction(t *testing.T) {
	h := newHostile(t, putOK)
	me := h.me
	good := me.binding()
	other := relayporttest.NewWallet(9)
	for _, tc := range []struct {
		name string
		edit func(cfg *mailbox.Config)
		is   error // the relaybind sentinel behind it, when there is one
	}{
		{"an empty statement", func(c *mailbox.Config) { c.Binding.Statement = nil }, nil},
		{"an empty key", func(c *mailbox.Config) { c.Binding.Key = nil }, nil},
		{"a statement that does not parse", func(c *mailbox.Config) { c.Binding.Statement = []byte{1, 2, 3} }, relaybind.ErrBadEncoding},
		{"a key that does not parse", func(c *mailbox.Config) { c.Binding.Key = []byte{1, 2, 3} }, relaybind.ErrBadEncoding},
		{"a key that is not the signer's", func(c *mailbox.Config) { c.Binding.Key = other.COSEKey() }, relaybind.ErrBadSignature},
		{"a signature that does not verify", func(c *mailbox.Config) {
			c.Binding.Statement = bytes.Clone(good.Statement)
			c.Binding.Statement[len(c.Binding.Statement)-1] ^= 1
		}, relaybind.ErrBadSignature},
		{"a binding of another device", func(c *mailbox.Config) {
			s := me.wallet.BindingStatement(party.Fingerprint{9}, me.from, me.until, false)
			c.Binding = mailbox.Binding{Statement: s.Sign1, Key: s.COSEKey}
		}, relaybind.ErrDeviceMismatch},
		{"an expired binding", func(c *mailbox.Config) { c.Clock = relayClock(me.until + 1) }, relaybind.ErrExpired},
		{"a binding not valid yet", func(c *mailbox.Config) { c.Clock = relayClock(me.from - 301) }, relaybind.ErrNotYetValid},
		{"a lifetime above the policy", func(c *mailbox.Config) { c.Policy = relaybind.Policy{Skew: 300, MaxLifetime: 24 * 3600} }, relaybind.ErrLifetime},
		{"a binding that is not a binding (a revoke)", func(c *mailbox.Config) {
			s := me.wallet.RevokeStatement(me.fp, false, startTime)
			c.Binding = mailbox.Binding{Statement: s.Sign1, Key: s.COSEKey}
		}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := h.config(h.net.Dialer(h.me.node, h.relay))
			tc.edit(&cfg)
			c, err := mailbox.New(cfg)
			if err == nil {
				c.Close()
				t.Fatal("New accepted the binding")
			}
			if !errors.Is(err, mailbox.ErrBindingInvalid) {
				t.Fatalf("New = %v, want ErrBindingInvalid", err)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Fatalf("New = %v, want it to wrap %v", err, tc.is)
			}
		})
	}
	// the window edges are inside: valid at from - skew and at until
	for name, now := range map[string]int64{"at from minus the skew": me.from - 300, "at until": me.until} {
		cfg := h.config(h.net.Dialer(h.me.node, h.relay))
		cfg.Clock = relayClock(now)
		c, err := mailbox.New(cfg)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		c.Close()
	}
	// a tightened policy within the lifetime is accepted
	cfg := h.config(h.net.Dialer(h.me.node, h.relay))
	cfg.Policy = relaybind.Policy{Skew: 300, MaxLifetime: me.until - me.from}
	if c, err := mailbox.New(cfg); err != nil {
		t.Fatalf("a lifetime equal to the policy's: %v", err)
	} else {
		c.Close()
	}
}

// The rest of the configuration: the fingerprint is the device keys', the device
// keys are set, the resolver and the signer are there, the margin is not
// negative, and a good one is accepted and says until when the binding runs, so
// that the caller can renew.
//
// spec: SPO-Xmailbox-IF-016, SPO-Xmailbox-IF-009
func TestTheConfigurationIsCheckedAndTheBindingsEndIsExposed(t *testing.T) {
	h := newHostile(t, putOK)
	for name, edit := range map[string]func(*mailbox.Config){
		"no dialer":                 func(c *mailbox.Config) { c.Dialer = nil },
		"no key":                    func(c *mailbox.Config) { c.RelayKey = party.NodeKey{} },
		"no node":                   func(c *mailbox.Config) { c.NodeKey = party.NodeKey{} },
		"no self":                   func(c *mailbox.Config) { c.Self = party.Fingerprint{} },
		"no signer":                 func(c *mailbox.Config) { c.Signer = nil },
		"no clock":                  func(c *mailbox.Config) { c.Clock = nil },
		"no resolver":               func(c *mailbox.Config) { c.Resolve = nil },
		"no device keys":            func(c *mailbox.Config) { c.Device = wire.DeviceKeys{} },
		"a fingerprint that is not": func(c *mailbox.Config) { c.Self[0] ^= 1 },
		"a negative margin":         func(c *mailbox.Config) { c.RenewMargin = -time.Second },
		"a policy above the ADR's":  func(c *mailbox.Config) { c.Policy = relaybind.Policy{Skew: 301, MaxLifetime: 3600} },
	} {
		cfg := h.config(h.net.Dialer(h.me.node, h.relay))
		edit(&cfg)
		if c, err := mailbox.New(cfg); err == nil {
			c.Close()
			t.Errorf("%s: New accepted an invalid configuration", name)
		}
	}
	c := h.client()
	if got := c.BindingUntil(); got != h.me.until {
		t.Fatalf("BindingUntil = %d, want %d", got, h.me.until)
	}
}

// SetBinding takes a new binding that passes the same checks and the next
// connection presents it: the connection that is open is left alone (no
// reconnect), the signer is asked only when a connection is made, and the client
// signs nothing with a wallet key itself. A binding that does not pass changes
// nothing.
//
// spec: SPO-Xmailbox-OUT-094, SPO-Xmailbox-IF-018, SPO-Xmailbox-SEC-071
func TestARenewedBindingIsPresentedAtTheNextConnection(t *testing.T) {
	h := newHostile(t, func(s *sconn) {
		var until int64 // the first login presents the original binding, the next the renewed one
		if s.n > 1 {
			until = startTime + 120*24*3600
		}
		s.serve(hs{until: until}, func(m wire.Message) bool {
			if p, ok := m.(wire.PutV2); ok {
				s.send(wire.PutResult{RequestID: p.RequestID, Status: wire.StatusStored})
				return s.n != 1 // the first connection ends after its put
			}
			return true
		})
	})
	c := h.client()
	if err := sendOnce(c); err != nil {
		t.Fatal(err)
	}
	renewed := h.me.rebind(startTime-30, startTime+120*24*3600, false)
	if err := c.SetBinding(renewed); err != nil {
		t.Fatalf("SetBinding = %v", err)
	}
	if got := c.BindingUntil(); got != startTime+120*24*3600 {
		t.Fatalf("BindingUntil = %d after the renewal", got)
	}
	if n := len(h.me.sg.calls()); n != 1 {
		t.Fatalf("the signer was asked %d times after SetBinding, want only the login's", n)
	}
	if h.connCount() != 1 {
		t.Fatal("SetBinding made a connection")
	}
	time.Sleep(40 * time.Millisecond) // the relay ended the first connection
	if err := sendOnce(c); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	second := h.auths[1].auth
	h.mu.Unlock()
	if !bytes.Equal(second.Sign1, renewed.Statement) || !bytes.Equal(second.Key, renewed.Key) {
		t.Fatal("the next connection did not present the renewed binding")
	}
	if got := h.me.sg.calls()[1].bindingHash; got != bindingHash(t, renewed) {
		t.Fatal("the login was not signed over the renewed binding")
	}
	// a binding that is not good changes nothing
	for name, b := range map[string]mailbox.Binding{
		"another device": {Statement: h.me.wallet.BindingStatement(party.Fingerprint{9}, startTime-30, startTime+3600*48, false).Sign1, Key: renewed.Key},
		"expired":        h.me.rebind(startTime-7200, startTime-3601, false),
		"garbage":        {Statement: []byte{1}, Key: []byte{2}},
		"an older one":   h.me.rebind(startTime-31, startTime+3600*48, false), // from before the one held
	} {
		if err := c.SetBinding(b); !errors.Is(err, mailbox.ErrBindingInvalid) {
			t.Errorf("%s: SetBinding = %v, want ErrBindingInvalid", name, err)
		}
	}
	if got := c.BindingUntil(); got != startTime+120*24*3600 {
		t.Fatalf("a refused binding changed BindingUntil to %d", got)
	}
	// a binding from the same moment is not older
	if err := c.SetBinding(h.me.rebind(startTime-30, startTime+100*24*3600, true)); err != nil {
		t.Fatalf("a binding with the same from: %v", err)
	}
	c.Close()
	if err := c.SetBinding(renewed); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("SetBinding after Close = %v, want ErrClosed", err)
	}
}

// What SetBinding takes besides a renewal, as PRE-057 says: a binding with the same
// `from` and an earlier `until` replaces the one held (the relay takes it too: it
// is not older), so BindingUntil moves back and the next login presents it; a
// binding of the same device under another wallet key is taken when its `from`
// is not earlier than the held one's (the relay moves the device to that key),
// and refused when it is (the client is stricter than the relay here: it compares
// `from` whatever the key).
//
// spec: SPO-Xmailbox-PRE-057, SPO-Xmailbox-OUT-094
func TestSetBindingWithTheSameFromOrAnotherWalletKey(t *testing.T) {
	h := newHostile(t, func(s *sconn) {
		s.serve(hs{until: startTime + 10*24*3600}, func(m wire.Message) bool {
			if p, ok := m.(wire.PutV2); ok {
				s.send(wire.PutResult{RequestID: p.RequestID, Status: wire.StatusStored})
			}
			return true
		})
	})
	c := h.client()
	shorter := h.me.rebind(h.me.from, startTime+10*24*3600, false)
	if err := c.SetBinding(shorter); err != nil {
		t.Fatalf("SetBinding with the same from and an earlier until = %v", err)
	}
	if got := c.BindingUntil(); got != startTime+10*24*3600 {
		t.Fatalf("BindingUntil = %d, want the earlier until", got)
	}
	if err := sendOnce(c); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	presented := h.auths[0].auth.Sign1
	h.mu.Unlock()
	if !bytes.Equal(presented, shorter.Statement) {
		t.Fatal("the login did not present the binding with the earlier until")
	}
	other := relayporttest.NewWallet(9)
	earlier := other.BindingStatement(h.me.fp, h.me.from-1, startTime+20*24*3600, false)
	if err := c.SetBinding(mailbox.Binding{Statement: earlier.Sign1, Key: earlier.COSEKey}); !errors.Is(err, mailbox.ErrBindingInvalid) {
		t.Fatalf("SetBinding under another key with an earlier from = %v, want ErrBindingInvalid", err)
	}
	moved := other.BindingStatement(h.me.fp, h.me.from, startTime+20*24*3600, false)
	if err := c.SetBinding(mailbox.Binding{Statement: moved.Sign1, Key: moved.COSEKey}); err != nil {
		t.Fatalf("SetBinding under another key = %v", err)
	}
	if got := c.BindingUntil(); got != startTime+20*24*3600 {
		t.Fatalf("BindingUntil = %d after the binding under another key", got)
	}
}

// When the binding in use is within the renewal margin of its end and no newer
// one was set, the client says so when it connects: an event with the end. The
// margin is 14 days by default and configurable; exactly at the margin it says
// so, one second before it does not; a newer binding silences it.
//
// spec: SPO-Xmailbox-OUT-094
func TestTheClientSaysWhenTheBindingNearsItsEnd(t *testing.T) {
	endsIn := func(d time.Duration) *hostile {
		h := newHostile(t, putOK)
		h.me.until = startTime + int64(d/time.Second)
		h.me.stmt = h.me.wallet.BindingStatement(h.me.fp, h.me.from, h.me.until, false)
		return h
	}
	renewals := func(h *hostile) []mailbox.Event { return h.ev.of(mailbox.EventRenew) }
	t.Run("inside the default margin", func(t *testing.T) {
		h := endsIn(10 * 24 * time.Hour)
		if err := sendOnce(h.client()); err != nil {
			t.Fatal(err)
		}
		ev := renewals(h)
		if len(ev) != 1 || ev[0].Until != h.me.until {
			t.Fatalf("renewal events = %+v, want one naming the end of the binding", ev)
		}
	})
	t.Run("exactly at the margin", func(t *testing.T) {
		h := endsIn(14 * 24 * time.Hour)
		sendOnce(h.client())
		if len(renewals(h)) != 1 {
			t.Fatal("no event with the binding exactly at the margin")
		}
	})
	t.Run("one second before the margin", func(t *testing.T) {
		h := endsIn(14*24*time.Hour + time.Second)
		sendOnce(h.client())
		if len(renewals(h)) != 0 {
			t.Fatal("an event although the binding is outside the margin")
		}
	})
	t.Run("a configured margin", func(t *testing.T) {
		h := endsIn(3 * time.Hour)
		sendOnce(h.client(func(c *mailbox.Config) { c.RenewMargin = time.Hour }))
		if len(renewals(h)) != 0 {
			t.Fatal("an event outside the configured margin")
		}
		h2 := endsIn(3 * time.Hour)
		sendOnce(h2.client(func(c *mailbox.Config) { c.RenewMargin = 3 * time.Hour }))
		if len(renewals(h2)) != 1 {
			t.Fatal("no event at the configured margin")
		}
	})
	t.Run("a newer binding silences it", func(t *testing.T) {
		h := endsIn(10 * 24 * time.Hour)
		c := h.client()
		if err := c.SetBinding(h.me.rebind(startTime-30, startTime+90*24*3600, false)); err != nil {
			t.Fatal(err)
		}
		if err := sendOnce(c); err != nil {
			t.Fatal(err)
		}
		if n := len(renewals(h)); n != 0 {
			t.Fatalf("%d events although a newer binding was set", n)
		}
	})
}

// A binding that has expired by the client's own clock is never presented: the
// client does not dial, Send is no route wrapping ErrBindingRefused (a new
// binding must be signed), Receive returns it, and a new binding given to
// SetBinding makes the next attempt dial. The relay's own refusal, the `binding`
// code, is the same sentinel.
//
// spec: SPO-Xmailbox-OUT-094, SPO-Xmailbox-OUT-092, SPO-Xmailbox-PRE-057
func TestAnExpiredBindingIsNeverPresented(t *testing.T) {
	var untilNow atomic.Int64 // what the relay says in AuthOK
	h := newHostile(t, func(s *sconn) {
		s.serve(hs{until: untilNow.Load()}, func(m wire.Message) bool {
			if p, ok := m.(wire.PutV2); ok {
				s.send(wire.PutResult{RequestID: p.RequestID, Status: wire.StatusStored})
			}
			return true
		})
	})
	untilNow.Store(h.me.until)
	clk := newStepClock()
	cd, d := counting(h)
	c := h.clientVia(d, func(cfg *mailbox.Config) { cfg.Clock = clk })
	if err := sendOnce(c); err != nil {
		t.Fatal(err)
	}
	c.Close()
	c = h.clientVia(d, func(cfg *mailbox.Config) { cfg.Clock = clk })
	clk.Advance(time.Duration(h.me.until-startTime+1) * time.Second) // past the end of the binding
	dials := cd.count()
	err := sendOnce(c)
	if !errors.Is(err, ports.ErrNoRoute) || !errors.Is(err, mailbox.ErrBindingRefused) || errors.Is(err, mailbox.ErrUnreachable) {
		t.Fatalf("Send = %v, want ErrNoRoute wrapping ErrBindingRefused", err)
	}
	if cd.count() != dials {
		t.Fatal("the client dialled with an expired binding")
	}
	var failed []mailbox.Event
	for _, e := range h.ev.of(mailbox.EventFailed) {
		if e.Reason == mailbox.ReasonBindingExpired {
			failed = append(failed, e)
		}
	}
	if len(failed) != 1 {
		t.Fatalf("failure events with the reason binding_expired = %d, want 1", len(failed))
	}
	if _, err := c.Receive(ctxFor(t, 300*time.Millisecond)); !errors.Is(err, mailbox.ErrBindingRefused) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Receive = %v, want ErrBindingRefused (or its deadline while it backs off)", err)
	}
	if cd.count() != dials {
		t.Fatal("Receive dialled with an expired binding")
	}
	// a new binding, valid now, is presented
	renewed := h.me.rebind(h.me.until, h.me.until+30*24*3600, false)
	if err := c.SetBinding(renewed); err != nil {
		t.Fatalf("SetBinding = %v", err)
	}
	untilNow.Store(h.me.until + 30*24*3600) // the relay now records the renewed binding
	if err := sendOnce(c); err != nil {
		t.Fatalf("Send with the renewed binding = %v", err)
	}
	if cd.count() != dials+1 {
		t.Fatalf("%d dials, want one more than before", cd.count())
	}
	h.mu.Lock()
	got := h.auths[len(h.auths)-1].auth.Sign1
	h.mu.Unlock()
	if !bytes.Equal(got, renewed.Statement) {
		t.Fatal("the renewed binding was not presented")
	}
}

// A clock that was stepped back after construction makes the binding not valid
// yet (the relay would refuse it with the `binding` code): the client does not
// dial, and says so with the same sentinel and the reason `binding`.
//
// spec: SPO-Xmailbox-OUT-094
func TestABindingNotValidYetByTheClientsClockIsNotPresented(t *testing.T) {
	h := newHostile(t, putOK)
	clk := newStepClock()
	cd, d := counting(h)
	c := h.clientVia(d, func(cfg *mailbox.Config) { cfg.Clock = clk })
	clk.Advance(-time.Hour) // from - skew is now in the future
	err := sendOnce(c)
	if !errors.Is(err, ports.ErrNoRoute) || !errors.Is(err, mailbox.ErrBindingRefused) || errors.Is(err, mailbox.ErrUnreachable) {
		t.Fatalf("Send = %v, want ErrNoRoute wrapping ErrBindingRefused", err)
	}
	if cd.count() != 0 {
		t.Fatal("the client dialled with a binding that is not valid yet")
	}
	var found bool
	for _, e := range h.ev.of(mailbox.EventFailed) {
		found = found || e.Reason == mailbox.ReasonBinding
	}
	if !found {
		t.Fatal("no failure event with the reason binding")
	}
	clk.Advance(time.Hour) // the clock is right again: the same binding is presented
	time.Sleep(100 * time.Millisecond)
	if err := sendOnce(c); err != nil {
		t.Fatalf("Send once the clock is right = %v", err)
	}
}

// The connection does not outlive the binding as the relay recorded it: a
// connection whose AuthOK says the binding ends soon is not used past that end
// (the relay closes it then), and the client opens a new one that presents what it
// holds.
//
// spec: SPO-Xmailbox-OUT-089
func TestAConnectionEndsWhereTheRelayRecordedTheBindingToEnd(t *testing.T) {
	h := newHostile(t, func(s *sconn) {
		s.serve(hs{until: startTime + 1}, func(m wire.Message) bool {
			if p, ok := m.(wire.PutV2); ok {
				s.send(wire.PutResult{RequestID: p.RequestID, Status: wire.StatusStored})
			}
			return true
		})
	})
	clk := newStepClock()
	c := h.client(func(cfg *mailbox.Config) { cfg.Clock = clk; cfg.Limits.IdleTimeout = 5 * time.Second })
	if err := sendOnce(c); err != nil {
		t.Fatal(err)
	}
	if err := sendOnce(c); err != nil {
		t.Fatal(err)
	}
	if h.connCount() != 2 {
		t.Fatalf("%d connections, want 2: a connection recorded to end in a second is not reused", h.connCount())
	}
	ev := h.ev.of(mailbox.EventReconnect)
	if len(ev) != 1 || ev[0].Reason != mailbox.ReasonLifetime {
		t.Fatalf("reconnect events = %+v, want one with the reason lifetime", ev)
	}
}
