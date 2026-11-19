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
	"github.com/mochipool/workbench/spo/internal/ports"
)

func body(n int, tag byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7) ^ tag
	}
	return b
}

// A sends to B through the real relay and the real store; B receives, handles
// and acks; B answers; A receives the answer.
//
// spec: SPO-Xmailbox-IF-009, SPO-Xmailbox-OUT-035, SPO-Xmailbox-OUT-036, SPO-Xmailbox-OUT-037
func TestTwoPartiesThroughTheRealRelay(t *testing.T) {
	w := newWorld(t)
	ca, cb := w.client(w.a), w.client(w.b)
	var _ ports.EnvelopeSender = ca
	var _ ports.EnvelopeAcker = cb
	if tr := ca.Transport(); tr.Kind() != ports.ViaNetwork || tr.Sender() == nil {
		t.Fatalf("Transport = kind %v", tr.Kind())
	}
	req := body(3000, 1)
	if err := ca.Send(context.Background(), w.b.fp, req); err != nil {
		t.Fatalf("Send: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := cb.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Via() != ports.ViaNetwork || !bytes.Equal(got.Envelope, req) {
		t.Fatalf("delivered via %v, %d bytes", got.Via(), len(got.Envelope))
	}
	if err := cb.Ack(); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	// the entry is gone: B's next fetch sees nothing
	qctx, qcancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer qcancel()
	if g, err := cb.Receive(qctx); err == nil {
		t.Fatalf("an acked envelope was delivered again (%d bytes)", len(g.Envelope))
	}
	resp := body(700, 2)
	if err := cb.Send(context.Background(), w.a.fp, resp); err != nil {
		t.Fatalf("response: %v", err)
	}
	if b := recv(t, ca); !bytes.Equal(b, resp) {
		t.Fatal("the response arrived changed")
	}
}

// A put the relay refuses (here its store reports that the recipient's mailbox
// was removed, which the session answers `refused`) is refused, and the client
// says so with the transport sentinel.
//
// spec: SPO-Xmailbox-OUT-038, SPO-Xmailbox-OUT-091
func TestAPutTheRelayRefusesIsRefusedByTransport(t *testing.T) {
	w := newWorld(t)
	ca := w.client(w.a)
	w.store.mu.Lock()
	w.store.deny = w.c.fp
	w.store.mu.Unlock()
	err := ca.Send(context.Background(), w.c.fp, body(10, 3))
	if !errors.Is(err, ports.ErrRefusedByTransport) {
		t.Fatalf("Send to a recipient the relay refuses = %v, want ErrRefusedByTransport", err)
	}
	if errors.Is(err, ports.ErrNoRoute) {
		t.Fatal("a refusal must not look like no route")
	}
	if ev := w.ev.of(mailbox.EventRefused); len(ev) != 1 {
		t.Fatalf("refusal events = %d, want 1", len(ev))
	}
	// the same connection serves the next put
	if err := ca.Send(context.Background(), w.b.fp, body(10, 4)); err != nil {
		t.Fatalf("a refusal must not end the session: %v", err)
	}
}

// A put to a device that has no binding to the wallet key the sender names is
// `unbound`: the client says no route (the item stays queued, because the
// recipient may bind later) with the reason class `unbound`, and the session goes
// on. The same answer holds for a device that was never bound and for a device
// bound under another wallet key.
//
// spec: SPO-Xmailbox-OUT-091, SPO-Xmailbox-OUT-038
func TestAPutToAnUnboundDeviceIsNoRouteAndTheSessionGoesOn(t *testing.T) {
	w := newWorld(t)
	ca := w.client(w.a)
	var never party.Fingerprint
	never[0] = 9
	w.routes[never] = mailbox.Route{WalletKey: w.b.wkey(), Device: never}
	other := party.Fingerprint{7}
	w.routes[other] = mailbox.Route{WalletKey: w.a.wkey(), Device: w.c.fp} // c is bound, but under its own key
	for name, to := range map[string]party.Fingerprint{"never bound": never, "bound under another key": other} {
		err := ca.Send(context.Background(), to, body(10, 3))
		if !errors.Is(err, ports.ErrNoRoute) || errors.Is(err, ports.ErrRefusedByTransport) {
			t.Fatalf("%s: Send = %v, want ErrNoRoute and not a refusal", name, err)
		}
	}
	ev := w.ev.of(mailbox.EventNoRoute)
	if len(ev) != 2 || ev[0].Reason != mailbox.ReasonUnbound || ev[1].Reason != mailbox.ReasonUnbound || ev[0].Status != wire.StatusUnbound {
		t.Fatalf("no-route events = %+v, want two with the reason unbound", ev)
	}
	if err := ca.Send(context.Background(), w.b.fp, body(10, 4)); err != nil {
		t.Fatalf("an unbound answer must not end the session: %v", err)
	}
	if n := len(w.ev.of(mailbox.EventReconnect)); n != 0 {
		t.Fatalf("%d reconnects: the session was not kept", n)
	}
}

// A route whose device is not set means the party fingerprint the item is
// addressed by: the put reaches that device's mailbox.
//
// spec: SPO-Xmailbox-OUT-091, SPO-Xmailbox-IF-016
func TestARouteWithNoDeviceIsAddressedToThePartyFingerprint(t *testing.T) {
	w := newWorld(t)
	ca := w.client(w.a, func(cfg *mailbox.Config) {
		cfg.Resolve = func(to party.Fingerprint) (mailbox.Route, bool) {
			return mailbox.Route{WalletKey: w.b.wkey()}, to == w.b.fp
		}
	})
	if err := ca.Send(context.Background(), w.b.fp, body(10, 3)); err != nil {
		t.Fatalf("Send = %v", err)
	}
	if w.pairEntries() != 1 {
		t.Fatal("the put did not reach the recipient's mailbox")
	}
}

// A recipient without a wallet key (the resolver says so) is no route with a
// clear reason, and nothing is dialled: a party reachable by file or direct
// connection only is never looked up at a relay.
//
// spec: SPO-Xmailbox-OUT-091, SPO-Xmailbox-IF-016
func TestARecipientWithoutAWalletKeyIsNoRouteAndNothingIsDialled(t *testing.T) {
	w := newWorld(t)
	cd := &worldCountDialer{inner: w.net.Dialer(w.a.node, w.relay)}
	ca := w.clientVia(w.a, cd, func(cfg *mailbox.Config) {
		inner := cfg.Resolve
		cfg.Resolve = func(to party.Fingerprint) (mailbox.Route, bool) {
			if to == w.c.fp {
				// enrolled without a wallet key: the boolean says so, whatever the route holds
				return mailbox.Route{WalletKey: w.c.wkey(), Device: w.c.fp}, false
			}
			return inner(to)
		}
	})
	err := ca.Send(context.Background(), w.c.fp, body(10, 3))
	if !errors.Is(err, ports.ErrNoRoute) || errors.Is(err, ports.ErrRefusedByTransport) {
		t.Fatalf("Send = %v, want ErrNoRoute", err)
	}
	if cd.n.Load() != 0 {
		t.Fatalf("%d dials for a recipient with no wallet key", cd.n.Load())
	}
	if ev := w.ev.of(mailbox.EventNoRoute); len(ev) != 1 || ev[0].Reason != mailbox.ReasonNoWalletKey || ev[0].To != w.c.fp {
		t.Fatalf("no-route events = %+v", ev)
	}
	// a resolver that answers a zero wallet key is the same
	cb := w.clientVia(w.b, cd, func(cfg *mailbox.Config) {
		cfg.Resolve = func(party.Fingerprint) (mailbox.Route, bool) { return mailbox.Route{}, true }
	})
	if err := cb.Send(context.Background(), w.a.fp, body(10, 3)); !errors.Is(err, ports.ErrNoRoute) || cd.n.Load() != 0 {
		t.Fatalf("Send with a zero wallet key = %v after %d dials", err, cd.n.Load())
	}
}
