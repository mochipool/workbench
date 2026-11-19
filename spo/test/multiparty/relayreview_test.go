package multiparty

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/app/relayself"
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/test/fakenet"
	"github.com/mochipool/workbench/spo/test/multiparty/partyrig"
)

// The end-to-end checks of the security review of ADR 0014 work package 10,
// over relays started through relayhost.Start: a relay that was down when a
// device forgot itself is completed later without a binding, and refuses the
// revoked binding afterwards (M1); a request put again over two relays is
// delivered once and answered from the stored response, never signed or
// counted twice (M2).

func listRelays(t *testing.T, d *device, relays ...*hostedRelay) {
	t.Helper()
	for _, r := range relays {
		buf, err := ports.TakeSecret([]byte("tailcat-address-" + r.node.Name))
		if err != nil {
			t.Fatal(err)
		}
		err = relayself.AddRelay(ctx, d.ws.Store, relayself.Relay{Name: r.node.Name, Key: r.node.Key}, buf)
		buf.Destroy()
		if err != nil {
			t.Fatal(err)
		}
	}
}

func fastClientLimits() mailbox.Limits {
	l := mailbox.DefaultLimits()
	l.WaitSeconds, l.MinPoll = 1, 5*time.Millisecond
	l.BackoffMin, l.BackoffMax = 10*time.Millisecond, 80*time.Millisecond
	l.OpTimeout = 2 * time.Second
	return l
}

// loginWith logs d in at one relay with a binding, as a fresh client does,
// and returns the error of a short receive (nil for a login that worked).
func loginWith(t *testing.T, n *fakenet.Net, d *device, r *hostedRelay, b *relayself.Binding) error {
	t.Helper()
	id := d.local.Identity()
	c, err := mailbox.New(mailbox.Config{Dialer: n.Dialer(d.node, r.node), RelayKey: r.node.Key, NodeKey: d.node.Key, Self: id.Fingerprint(),
		Device: wire.DeviceKeys{Ed25519: id.Ed25519, X25519: id.X25519}, Binding: mailbox.Binding{Statement: b.Statement, Key: b.Key},
		Resolve: func(party.Fingerprint) (mailbox.Route, bool) { return mailbox.Route{}, false },
		Signer:  d.local.(relayport.AuthSigner), Clock: d.ws.Clock, Limits: fastClientLimits()})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	_, err = c.Receive(rctx)
	if errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	return err
}

// A relay down when bob forgets his device: the revoke is recorded at the relay
// that is up and owed to the other, the binding is deleted all the same, and
// the relay that was down still takes the revoked binding (the risk the review
// found). Brought back, the revoke-only send, which needs no binding, completes
// it; nothing is owed any more, and that relay refuses a login with the revoked
// binding. With every relay down nothing is recorded and both owe it.
//
// spec: SPO-Xmailbox-OUT-111, SPO-Xmailbox-OUT-109, SPO-Xmailbox-OUT-107
func TestARelayDownAtForgetIsCompletedLater(t *testing.T) {
	fakenet.CheckLeaks(t)
	n := fakenet.New()
	cn, bn := n.Node("coord"), n.Node("bob")
	w := newWorldOpt(t, worldOpt{nodeB: &bn.Key, nodeC: &cn.Key})
	bob := newDevice(t, w.B, bn, 31)
	bob.bind(t)
	r1 := startHostedRelay(t, n, "relay-one", w.clock, bn)
	r2 := startHostedRelay(t, n, "relay-two", w.clock, bn)
	listRelays(t, bob, r1, r2)
	book := &swapBook{}
	bc := bob.multiClient(t, n, book, nil, r1, r2)
	rctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	bc.Receive(rctx) //nolint:errcheck // a login at both relays
	cancel()
	st, err := bob.self.Load(ctx)
	if err != nil || st.Binding == nil {
		t.Fatal(err)
	}
	old := *st.Binding

	// relay two is down for bob during the forget
	bob.dialer("relay-two").Always(fakenet.Fault{Refuse: true})
	w.clock.Advance(time.Second)
	got, err := bob.self.ForgetRevoke(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, err := bob.self.Book(ctx)
	if err != nil {
		t.Fatal(err)
	}
	book.set(b)
	reps, err := bc.SendRevokes(ctx)
	if err != nil || reps["relay-two"].Err == nil || reps["relay-one"].Err != nil {
		t.Fatalf("the revoke with relay two down: %v; %v %v", err, reps["relay-one"].Err, reps["relay-two"].Err)
	}
	if err := b.Save(ctx); err != nil {
		t.Fatal(err)
	}
	if err := bc.Logout(time.Second); err != nil {
		t.Fatal(err)
	}
	if err := bob.self.DropBinding(ctx); err != nil {
		t.Fatal(err)
	}
	s, err := bob.self.Status(ctx)
	if err != nil || s.Owed["relay-one"] != 0 || s.Owed["relay-two"] != 1 || s.Binding != nil {
		t.Fatalf("after the forget: owed %v, binding %v, %v", s.Owed, s.Binding, err)
	}
	if s.Revokes[0].ID != relayself.ShortID(got) {
		t.Fatal("the owed revoke is not the forget's")
	}

	// relay two is back: it still takes the revoked binding until it gets the revoke
	bob.dialer("relay-two").Always(fakenet.Fault{})
	if err := loginWith(t, n, bob, r2, &old); err != nil {
		t.Fatalf("relay two before the revoke reached it: %v", err)
	}
	if err := loginWith(t, n, bob, r1, &old); !errors.Is(err, ports.ErrIdentityRefused) {
		t.Fatalf("relay one, which recorded the revoke: %v", err)
	}

	// every relay down: the revoke-only send records nothing
	sender := func(down bool) func(context.Context, relayport.RevokeBook) (map[string]error, error) {
		return func(ctx context.Context, book relayport.RevokeBook) (map[string]error, error) {
			var eps []mailbox.Endpoint
			for _, r := range []*hostedRelay{r1, r2} {
				d := n.Dialer(bn, r.node)
				if down {
					d.Always(fakenet.Fault{Refuse: true})
				}
				eps = append(eps, mailbox.Endpoint{Name: r.node.Name, RelayKey: r.node.Key, Dialer: closableDialer{d}})
			}
			reps, err := mailbox.SendRevokesTo(ctx, eps, w.clock, book, fastClientLimits())
			out := map[string]error{}
			for name, r := range reps {
				out[name] = r.Err
			}
			return out, err
		}
	}
	bob.self.Send = sender(true)
	rep, err := bob.self.SendPending(ctx)
	if err == nil || rep.Relays["relay-one"] == nil || rep.Relays["relay-two"] == nil {
		t.Fatalf("every relay down: %+v %v", rep, err)
	}
	if s, _ := bob.self.Status(ctx); s.Owed["relay-two"] != 1 || s.Owed["relay-one"] != 0 {
		t.Fatalf("every relay down changed what is owed: %v", s.Owed)
	}

	// the completion: revoke-only, no binding, no signer
	bob.self.Send = sender(false)
	if _, err := bob.self.SendPending(ctx); err != nil {
		t.Fatal(err)
	}
	if s, _ := bob.self.Status(ctx); len(s.Owed) != 0 {
		t.Fatalf("still owed after the completion: %v", s.Owed)
	}
	if err := loginWith(t, n, bob, r2, &old); !errors.Is(err, ports.ErrIdentityRefused) {
		t.Fatalf("relay two after the completion takes the revoked binding: %v", err)
	}
}

// recSender records the envelopes the coordinator hands its transport.
type recSender struct {
	ports.EnvelopeSender
	mu   sync.Mutex
	sent [][]byte
}

func (r *recSender) Send(ctx context.Context, to party.Fingerprint, env []byte) error {
	r.mu.Lock()
	r.sent = append(r.sent, append([]byte(nil), env...))
	r.mu.Unlock()
	return r.EnvelopeSender.Send(ctx, to, env)
}

// The outbox's re-put of an answered request over two relays (or a relay that
// replays it): bob's composite delivers it once (the second relay's copy is
// held back as a copy), his signer answers it from the stored response without
// signing again (SPO-Xparty-INV-017), and the coordinator, given that response
// again, counts nothing twice and submits nothing more (SPO-Xparty-INV-041).
//
// spec: SPO-Xmailbox-OUT-110, SPO-Xparty-INV-017, SPO-Xparty-INV-041
func TestARePutRequestIsAnsweredOnceFromTheStoredResponse(t *testing.T) {
	fakenet.CheckLeaks(t)
	n := fakenet.New()
	cn, bn := n.Node("coord"), n.Node("bob")
	w := newWorldOpt(t, worldOpt{nodeB: &bn.Key, nodeC: &cn.Key})
	coord, bob := newDevice(t, w.C, cn, 32), newDevice(t, w.B, bn, 33)
	coord.bind(t)
	bob.bind(t)
	coord.enrollRelay(t, "bobparty", bob)
	bob.enrollRelay(t, "coordinator", coord)
	r1 := startHostedRelay(t, n, "relay-one", w.clock, cn, bn)
	r2 := startHostedRelay(t, n, "relay-two", w.clock, cn, bn)
	cc := coord.multiClient(t, n, &swapBook{}, nil, r1, r2)
	bc := bob.multiClient(t, n, &swapBook{}, nil, r1, r2)
	for _, c := range []*mailbox.Multi{cc, bc} {
		rctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		c.Receive(rctx) //nolint:errcheck // a login at both relays
		cancel()
	}
	w.open()
	cs := w.coordinator()
	rec := &recSender{EnvelopeSender: cc}
	if _, err := cs.RequestSignatures(ctx, multisig.RequestInput{Ref: poolRef, Purpose: "register mypool"}, ports.NetworkTransport(rec)); err != nil {
		t.Fatal(err)
	}
	if len(rec.sent) != 1 {
		t.Fatalf("%d envelopes sent for one request", len(rec.sent))
	}
	request := rec.sent[0]
	pump := func(ws *partyrig.Workspace, c *mailbox.Multi, h multisig.Handler) []string {
		t.Helper()
		var eff []string
		if err := (multisig.Pump{Outbox: ws.Outbox(), Send: c.Transport(), Receive: c, Handle: h, Idle: 1200 * time.Millisecond,
			Handled: func(r multisig.Handled) { eff = append(eff, r.Effect) }}).Run(ctx); err != nil {
			t.Fatal(err)
		}
		return eff
	}
	bobSigner := w.bobSigner()
	if eff := pump(w.B, bc, bobSigner.Handle); len(eff) != 1 || eff[0] != "stored" {
		t.Fatalf("bob's first effects %v", eff)
	}
	w.reviewAndApprove(bobSigner)
	pump(w.B, bc, bobSigner.Handle) // the response goes out
	cEff := pump(w.C, cc, cs.Handle)
	filled := 0
	for _, e := range cEff {
		if e == "filled" {
			filled++
		}
	}
	if filled != 1 || w.sub.count() != 1 {
		t.Fatalf("the coordinator's effects %v, submitted %d", cEff, w.sub.count())
	}
	responses := countResponses(t, w.B)
	if responses != 1 {
		t.Fatalf("%d approvals before the re-put", responses)
	}

	// the same request bytes again, at both relays
	if err := cc.Send(ctx, w.B.Identity.Fingerprint, request); err != nil {
		t.Fatal(err)
	}
	bEff := pump(w.B, bc, bobSigner.Handle)
	resent := 0
	for _, e := range bEff {
		switch e {
		case "response-resent":
			resent++
		case "closed": // the coordinator's CollectionClosed after the submission
		default:
			t.Fatalf("bob's effects of the re-put: %v", bEff)
		}
	}
	if resent != 1 {
		t.Fatalf("bob's effects of the re-put over two relays: %v (want one answer from the stored response)", bEff)
	}
	if got := countResponses(t, w.B); got != responses {
		t.Fatalf("bob's stored responses went from %d to %d: the re-put was answered anew", responses, got)
	}
	cEff = pump(w.C, cc, cs.Handle)
	for _, e := range cEff {
		if e == "filled" {
			t.Fatalf("the response given again filled the slot again: %v", cEff)
		}
	}
	if w.sub.count() != 1 {
		t.Fatalf("submitted %d times", w.sub.count())
	}
}

// countResponses is how many times bob's signer approved, and so signed, a
// request: a request answered anew would be a second approval.
func countResponses(t *testing.T, ws *partyrig.Workspace) int {
	t.Helper()
	var n int
	if err := ws.Store.View(ctx, func(r ports.NamedReader) error {
		evs, err := multisig.Events(r)
		for _, e := range evs {
			if e.Kind == "request-approved" {
				n++
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return n
}
