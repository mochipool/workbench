package multiparty

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/app/relayloop"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/test/fakenet"
	"github.com/mochipool/workbench/spo/test/multiparty/partyrig"
)

// serialHost is an executor host as the TUI's: one goroutine runs the store
// steps one at a time, and a step not started when its poster gives up is
// dropped.
type serialHost struct {
	mu      sync.Mutex
	jobs    chan func()
	reports []relayloop.State
	quit    chan struct{}
	done    chan struct{}
}

func newSerialHost() *serialHost {
	h := &serialHost{jobs: make(chan func(), 16), quit: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(h.done)
		for {
			select {
			case j := <-h.jobs:
				j()
			case <-h.quit:
				return
			}
		}
	}()
	return h
}

func (h *serialHost) stop() { close(h.quit); <-h.done }

func (h *serialHost) Post(ctx context.Context, job func(context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var mu sync.Mutex
	started, dropped := false, false
	res := make(chan error, 1)
	h.jobs <- func() {
		mu.Lock()
		if dropped {
			mu.Unlock()
			return
		}
		started = true
		mu.Unlock()
		res <- job(ctx)
	}
	select {
	case err := <-res:
		return err
	case <-ctx.Done():
		mu.Lock()
		if !started {
			dropped = true
			mu.Unlock()
			return ctx.Err()
		}
		mu.Unlock()
		return <-res
	}
}

func (h *serialHost) Report(s relayloop.State) {
	h.mu.Lock()
	h.reports = append(h.reports, s)
	h.mu.Unlock()
}

func (h *serialHost) last() relayloop.State {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.reports[len(h.reports)-1]
}

// The relay session over the real relays (ADR 0014 work package 9): bob logs in
// through relayloop.Serve on an executor host, receives the coordinator's
// request in the background and hands it to his signer by a store step, logs
// out (the composite and its dialers closed, the identity destroyed), and logs
// in again in the same process, where the next request arrives; no goroutine
// of either session is left, and the guarded buffers are back to their count
// before the login. The close here is the test's own (the composite's Logout
// and the identity's Destroy); the command line's real close (the book saved
// through the host, Logout, the identity destroyed) is driven by the real login
// command in adapters/cli (TestTheRealLoginCloseUnderAHostLeavesNothing).
//
// spec: SPO-Xmailbox-IF-027, SPO-Xmailbox-OUT-116, SPO-Xmailbox-SEC-083, SPO-Xmailbox-INV-040
func TestARelaySessionLogsOutAndLogsInAgainOverTheRelays(t *testing.T) {
	fakenet.CheckLeaks(t)
	n := fakenet.New()
	cn, bn := n.Node("coord"), n.Node("bob")
	w := newWorldOpt(t, worldOpt{nodeB: &bn.Key, nodeC: &cn.Key})
	coord, bob := newDevice(t, w.C, cn, 31), newDevice(t, w.B, bn, 32)
	coord.bind(t)
	bob.bind(t)
	coord.enrollRelay(t, "bobparty", bob)
	bob.enrollRelay(t, "coordinator", coord)
	r1 := startHostedRelay(t, n, "relay-one", w.clock, cn, bn)
	r2 := startHostedRelay(t, n, "relay-two", w.clock, cn, bn)
	cc := coord.multiClient(t, n, &swapBook{}, nil, r1, r2)
	w.open()
	cs := w.coordinator()
	bobSigner := w.bobSigner()

	session := func(handled chan<- string) (stop func() error, local ports.LocalIdentity) {
		li, err := w.B.Kit.Local(ctx)
		if err != nil {
			t.Fatal(err)
		}
		bob.local = li
		bc := bob.multiClient(t, n, &swapBook{}, nil, r1, r2)
		h := newSerialHost()
		st := relayloop.NewStatus(h)
		sctx, cancel := context.WithCancel(ctx)
		ended := make(chan error, 1)
		var out lockedWriter
		go func() {
			_, err := relayloop.Serve(sctx, st, func() (*relayloop.Exchange, func() error, error) {
				ob := w.B.Outbox()
				e := &relayloop.Exchange{
					Client: bc, Host: h, Tell: relayloop.New(&out, []byte("bob's binding"), func(err error) error { return err }), Status: st,
					Flush: func(ctx context.Context) (int, error) { return ob.Flush(ctx, bc.Transport()) },
					Handle: func(ctx context.Context, rcv ports.Received) (relayloop.Handled, error) {
						r, err := bobSigner.Handle(ctx, rcv)
						if err == nil {
							handled <- r.Effect
						}
						return relayloop.Handled{Refused: r.Refused, HasSender: r.HasSender}, err
					},
					Sync:   func(context.Context) error { return nil },
					Rearm:  ob.Rearm,
					Window: 300 * time.Millisecond, SyncEvery: time.Hour, RearmEvery: time.Hour,
				}
				return e, func() error {
					err := bc.Logout(time.Second)
					li.Destroy()
					return err
				}, nil
			})
			ended <- err
		}()
		return func() error {
			cancel()
			err := <-ended
			h.stop()
			if p := h.last().Phase; err == nil && p != relayloop.PhaseLoggedOut {
				t.Fatalf("a clean logout ended in phase %s", p)
			}
			return err
		}, li
	}

	handled := make(chan string, 4)
	before := secret.Budget().Live // before the login
	stop, li := session(handled)
	if _, err := cs.RequestSignatures(ctx, multisig.RequestInput{Ref: poolRef, Purpose: "register mypool"}, cc.Transport()); err != nil {
		t.Fatal(err)
	}
	select {
	case eff := <-handled:
		if eff != "stored" {
			t.Fatalf("bob's signer: %s", eff)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the session did not receive the request")
	}
	if err := stop(); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if got := secret.Budget().Live; got != before {
		t.Fatalf("%d guarded buffers live after the logout, %d before the login: a buffer of the session was not destroyed", got, before)
	}
	if _, err := li.(relayport.AuthSigner).SignMailboxAuth(cn.Key, bn.Key, [32]byte{}, 1, [32]byte{}, [32]byte{}); err == nil {
		t.Fatal("the destroyed identity still signs a login")
	}

	// a new login in the same process: the coordinator's next request arrives
	stop2, _ := session(handled)
	if _, err := cs.RequestSignatures(ctx, multisig.RequestInput{Ref: poolRef, Purpose: "register mypool", Renew: true}, cc.Transport()); err != nil {
		t.Fatal(err)
	}
	select {
	case eff := <-handled:
		if eff == "" {
			t.Fatal("no effect")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the second session did not receive the request")
	}
	if err := stop2(); err != nil {
		t.Fatalf("second logout: %v", err)
	}
	if err := cc.Logout(time.Second); err != nil && !errors.Is(err, ports.ErrClosed) {
		t.Fatal(err)
	}
}

// A logged-in session over the relays whose outbox holds a request for a pool
// cold key (sealed for a file that was down) puts nothing of it: the session's
// flushes are the outbox's Flush over the composite, whose cold-key rule keeps
// the item; the mailbox client is never asked for a route to the cold slot's
// party, and the session counts nothing sent.
//
// spec: SPO-Xmailbox-SEC-082, SPO-Xmailbox-SEC-084, SPO-Xparty-PRE-004
func TestALoggedInSessionPutsNoColdKeyRequest(t *testing.T) {
	rw := newRelayWorld(t, true)
	w, coord := rw.w, rw.coord
	cc := coord.client(t, rw.n, rw.relayNode)
	cs := w.coordinator()
	cert, err := w.led.BuildPoolRetirement(pool.RetirementSpec{Pool: w.otherID, Epoch: 20})
	if err != nil {
		t.Fatal(err)
	}
	body := partyrig.Body(t, 1000+500, cert.Attachment(0))
	ref, err := cs.Open(ctx, multisig.OpenRequest{Name: "retire-other", Body: body, TTL: 1500, Slots: []pool.Slot{{Name: "otherpool.node", Role: custody.RolePoolCold,
		KeyHash: txbuild.KeyHash(w.otherID), PartyFingerprint: w.C.FingerprintOf("bobparty")}}})
	if err != nil {
		t.Fatal(err)
	}
	down := partyrig.NewPipe(ports.ViaFile)
	down.Down = true
	if _, err := cs.RequestSignatures(ctx, multisig.RequestInput{Ref: ref}, down.Transport()); err != nil {
		t.Fatal(err)
	}
	h := newSerialHost()
	defer h.stop()
	st := relayloop.NewStatus(h)
	sctx, cancel := context.WithCancel(ctx)
	ob := w.C.Outbox()
	var out lockedWriter
	flushes := 0
	_, err = relayloop.Serve(sctx, st, func() (*relayloop.Exchange, func() error, error) {
		return &relayloop.Exchange{
			Client: cc, Host: h, Tell: relayloop.New(&out, []byte("coord's binding"), func(err error) error { return err }), Status: st,
			Flush: func(ctx context.Context) (int, error) {
				flushes++
				if flushes == 3 {
					cancel()
				}
				return ob.Flush(ctx, cc.Transport())
			},
			Handle: func(context.Context, ports.Received) (relayloop.Handled, error) { return relayloop.Handled{}, nil },
			Sync:   func(context.Context) error { return nil },
			Rearm:  ob.Rearm,
			Window: 50 * time.Millisecond, SyncEvery: time.Hour, RearmEvery: time.Hour,
		}, func() error { return nil }, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if s := h.last(); s.Sent != 0 || flushes < 3 {
		t.Fatalf("the session sent %d in %d flushes", s.Sent, flushes)
	}
	if len(coord.lookups()) != 0 {
		t.Fatalf("lookups %v: nothing was to be put", coord.lookups())
	}
	cold := 0
	for _, it := range outboxItems(t, w.C) {
		if it.ColdKey && !it.Sent {
			cold++
		}
	}
	if cold != 1 {
		t.Fatalf("%d cold items still queued, want 1", cold)
	}
}

type lockedWriter struct {
	mu sync.Mutex
	b  []byte
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.b = append(l.b, p...)
	return len(p), nil
}
