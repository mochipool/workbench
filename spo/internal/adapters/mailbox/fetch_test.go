package mailbox_test

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// page is what the scripted relay sends for one Fetch.
type page struct {
	envs  [][]byte
	more  bool
	mids  []wire.Hash // announced ids; the hashes of envs when nil
	sizes []uint32    // announced sizes; the lengths of envs when nil
}

func (p page) header(id uint32) wire.Items {
	it := wire.Items{RequestID: id, More: p.more}
	for i, e := range p.envs {
		mid, size := wire.HashOf(e), uint32(len(e))
		if p.mids != nil {
			mid = p.mids[i]
		}
		if p.sizes != nil {
			size = p.sizes[i]
		}
		it.Entries = append(it.Entries, wire.Item{Mid: mid, Size: size})
	}
	return it
}

// fetchScript answers each Fetch with f(request) and then the frames f wants.
func fetchScript(o hs, f func(s *sconn, req wire.Fetch) bool) func(s *sconn) {
	return func(s *sconn) {
		s.serve(o, func(m wire.Message) bool {
			if req, ok := m.(wire.Fetch); ok {
				return f(s, req)
			}
			return true
		})
	}
}

func goodPage(s *sconn, req wire.Fetch, p page) {
	s.send(p.header(req.RequestID))
	for _, e := range p.envs {
		s.frame(e)
	}
}

func receiveErr(t *testing.T, c *mailbox.Client, d time.Duration) (ports.Received, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return c.Receive(ctx)
}

// A page that is honest is delivered, each envelope after its hash was
// verified, as a network delivery; the request carries what the client asked
// for.
//
// spec: SPO-Xmailbox-OUT-036
func TestFetchDeliversAVerifiedPage(t *testing.T) {
	envs := [][]byte{newEnv(10, 1), newEnv(5000, 2), newEnv(1, 3)}
	reqs := make(chan wire.Fetch, 8)
	h := newHostile(t, fetchScript(hs{}, func(s *sconn, req wire.Fetch) bool {
		reqs <- req
		goodPage(s, req, page{envs: envs})
		return true
	}))
	c := h.client()
	for i, want := range envs {
		got, err := receiveErr(t, c, 3*time.Second)
		if err != nil {
			t.Fatalf("Receive %d: %v", i, err)
		}
		if got.Via() != ports.ViaNetwork || !bytes.Equal(got.Envelope, want) {
			t.Fatalf("Receive %d: via %v, %d bytes", i, got.Via(), len(got.Envelope))
		}
	}
	req := <-reqs
	if req.After != nil || req.MaxItems != wire.MaxItemsPerFetch || req.WaitSeconds != 1 {
		t.Fatalf("the first Fetch asked %+v", req)
	}
}

// When a page says there is more, the next fetch resumes after the last id of
// the page; after a page with no more, from the start.
//
// spec: SPO-Xmailbox-OUT-036
func TestFetchResumesAfterThePageWhenThereIsMore(t *testing.T) {
	e1, e2 := newEnv(10, 1), newEnv(10, 2)
	reqs := make(chan wire.Fetch, 8)
	n := 0
	h := newHostile(t, fetchScript(hs{}, func(s *sconn, req wire.Fetch) bool {
		reqs <- req
		n++
		switch n {
		case 1:
			goodPage(s, req, page{envs: [][]byte{e1}, more: true})
		case 2:
			goodPage(s, req, page{envs: [][]byte{e2}})
		default:
			goodPage(s, req, page{})
		}
		return true
	}))
	c := h.client()
	receiveErr(t, c, 2*time.Second)
	receiveErr(t, c, 2*time.Second)
	receiveErr(t, c, 300*time.Millisecond) // an empty page, then the next fetch from the start
	r1, r2, r3 := <-reqs, <-reqs, <-reqs
	if r1.After != nil {
		t.Fatal("the first fetch was not from the start")
	}
	if r2.After == nil || *r2.After != wire.HashOf(e1) {
		t.Fatalf("the second fetch resumed at %v, want after the first page's last id", r2.After)
	}
	if r3.After != nil {
		t.Fatal("after a page with no more the fetch must start again")
	}
}

// Every violation of the Items reply: nothing from the page is delivered, the
// connection is closed, the error is a protocol error, and the relay still
// holds the entries (the client acked nothing).
//
// spec: SPO-Xmailbox-OUT-039, SPO-Xmailbox-SEC-028
func TestItemsViolations(t *testing.T) {
	good := newEnv(300, 1)
	other := newEnv(300, 2)
	big := newEnv(2000, 3)
	cases := []struct {
		name   string
		client func(*mailbox.Config)
		reply  func(s *sconn, req wire.Fetch)
		is     error // besides ErrProtocol
	}{
		{"wrong request id", nil, func(s *sconn, req wire.Fetch) {
			s.send(wire.Items{RequestID: req.RequestID + 7})
		}, nil},
		{"more items than the request's max", func(c *mailbox.Config) { c.Limits.MaxItems = 2 }, func(s *sconn, req wire.Fetch) {
			goodPage(s, req, page{envs: [][]byte{newEnv(5, 1), newEnv(5, 2), newEnv(5, 3)}})
		}, nil},
		{"an item above the client's limit", func(c *mailbox.Config) { c.Limits.MaxEnvelope = 1000 }, func(s *sconn, req wire.Fetch) {
			goodPage(s, req, page{envs: [][]byte{big}})
		}, nil},
		{"an item above the limit the relay announced", nil, func(s *sconn, req wire.Fetch) {
			goodPage(s, req, page{envs: [][]byte{newEnv(1001, 4)}})
		}, nil},
		{"a repeated mid", nil, func(s *sconn, req wire.Fetch) {
			mid := wire.HashOf(good)
			s.header([]any{uint64(6), uint64(req.RequestID), []any{[]any{mid[:], uint64(len(good))}, []any{mid[:], uint64(len(good))}}, false})
			s.frame(good)
			s.frame(good)
		}, nil},
		{"a wrong hash", nil, func(s *sconn, req wire.Fetch) {
			goodPage(s, req, page{envs: [][]byte{other}, mids: []wire.Hash{wire.HashOf(good)}})
		}, wire.ErrHash},
		{"a wrong hash after a good item", nil, func(s *sconn, req wire.Fetch) {
			goodPage(s, req, page{envs: [][]byte{good, other}, mids: []wire.Hash{wire.HashOf(good), wire.HashOf(good[:10])}})
		}, wire.ErrHash},
		{"a raw frame prefix that differs from the header", nil, func(s *sconn, req wire.Fetch) {
			s.send(page{envs: [][]byte{good}}.header(req.RequestID))
			s.frame(good[:len(good)-1])
		}, wire.ErrSize},
		{"the body is shorter than announced", nil, func(s *sconn, req wire.Fetch) {
			s.send(page{envs: [][]byte{good}}.header(req.RequestID))
			p, _ := wire.RawFramePrefix(uint32(len(good)))
			s.raw(append(p[:], good[:100]...))
			s.st.Close()
		}, nil},
		{"a client-only frame as the reply", nil, func(s *sconn, req wire.Fetch) {
			s.send(wire.Ack{RequestID: req.RequestID, Mids: []wire.Hash{{1}}})
		}, wire.ErrDirection},
		{"a PutResult as the reply", nil, func(s *sconn, req wire.Fetch) {
			s.send(wire.PutResult{RequestID: req.RequestID})
		}, nil},
		{"more is set with no item", nil, func(s *sconn, req wire.Fetch) {
			s.header([]any{uint64(6), uint64(req.RequestID), []any{}, true})
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHostile(t, func(s *sconn) {
				s.serve(hs{maxEnv: 1000}, func(m wire.Message) bool {
					if req, ok := m.(wire.Fetch); ok {
						tc.reply(s, req)
						s.waitClosed()
					}
					return false
				})
			})
			var opts []func(*mailbox.Config)
			if tc.client != nil {
				opts = append(opts, tc.client)
			}
			c := h.client(opts...)
			got, err := receiveErr(t, c, 2*time.Second)
			if len(got.Envelope) != 0 {
				t.Fatalf("an envelope of %d bytes was delivered from a violating page", len(got.Envelope))
			}
			if tc.name == "the body is shorter than announced" {
				// a cut stream: transient, retried until the context ends
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("Receive = %v", err)
				}
				return
			}
			if !errors.Is(err, mailbox.ErrProtocol) {
				t.Fatalf("Receive = %v, want ErrProtocol", err)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Fatalf("Receive = %v, want it to wrap %v", err, tc.is)
			}
			waitFor(t, "the client to close", func() bool { return h.closedCount() >= 1 })
			var found bool
			for _, e := range h.ev.of(mailbox.EventFailed) {
				found = found || e.Reason == mailbox.ReasonProtocol || e.Reason == mailbox.ReasonHash || e.Reason == mailbox.ReasonLimit
			}
			if !found {
				t.Fatalf("no failure event with a protocol class: %+v", h.ev.all())
			}
		})
	}
}

// A hash mismatch is never delivered, and an honest page that follows on a new
// connection is.
//
// spec: SPO-Xmailbox-SEC-028
func TestABadHashIsNotDeliveredButTheNextGoodPageIs(t *testing.T) {
	good, bad := newEnv(300, 1), newEnv(300, 2)
	n := 0
	h := newHostile(t, fetchScript(hs{}, func(s *sconn, req wire.Fetch) bool {
		n++
		if n == 1 {
			goodPage(s, req, page{envs: [][]byte{bad}, mids: []wire.Hash{wire.HashOf(good)}})
			return false
		}
		goodPage(s, req, page{envs: [][]byte{good}})
		return true
	}))
	c := h.client()
	if got, err := receiveErr(t, c, 2*time.Second); !errors.Is(err, wire.ErrHash) || len(got.Envelope) != 0 {
		t.Fatalf("Receive = (%d bytes, %v), want the hash error", len(got.Envelope), err)
	}
	got, err := receiveErr(t, c, 3*time.Second)
	if err != nil || !bytes.Equal(got.Envelope, good) {
		t.Fatalf("the honest page after it: %v", err)
	}
	if h.connCount() != 2 {
		t.Fatalf("connections = %d, want a new one after the violation", h.connCount())
	}
}

// A claim of a large item that is above the limit costs the client no
// allocation of that size: the check is on the header, before the body.
//
// spec: SPO-Xmailbox-SEC-027
func TestAnOversizedClaimAllocatesNothing(t *testing.T) {
	h := newHostile(t, fetchScript(hs{maxEnv: 1000}, func(s *sconn, req wire.Fetch) bool {
		s.send(wire.Items{RequestID: req.RequestID, Entries: []wire.Item{{Mid: wire.Hash{1}, Size: wire.MaxEnvelopeBytes}}})
		s.waitClosed()
		return false
	}))
	c := h.client()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := receiveErr(t, c, 2*time.Second)
	runtime.ReadMemStats(&after)
	if !errors.Is(err, mailbox.ErrProtocol) {
		t.Fatalf("Receive = %v", err)
	}
	if d := after.TotalAlloc - before.TotalAlloc; d > 900<<10 {
		t.Fatalf("the client allocated %d bytes for a claim of %d that it refuses", d, wire.MaxEnvelopeBytes)
	}
}

// What the relay sends is bounded per connection: a relay that keeps sending
// valid pages is never read past the client's read bound on one connection. The
// client rotates the connection before a page could pass the bound (an honest
// relay's egress bound is larger than a tighter client's), and each new
// connection is counted by the dial limiter.
//
// spec: SPO-Xmailbox-SEC-027, SPO-Xmailbox-OUT-045
func TestEndlessPagesRotateTheConnectionAtTheReadBound(t *testing.T) {
	env := newEnv(4000, 1)
	var mu sync.Mutex
	most := 0 // the most fetches one connection served
	h := newHostile(t, func(s *sconn) {
		served := 0
		fetchScript(hs{}, func(s *sconn, req wire.Fetch) bool {
			served++
			mu.Lock()
			most = max(most, served)
			mu.Unlock()
			goodPage(s, req, page{envs: [][]byte{env}, more: true})
			return true
		})(s)
	})
	cd, d := counting(h)
	// the bound fits the handshake and two pages, not three
	c := h.clientVia(d, func(cfg *mailbox.Config) { cfg.Limits.MaxBytesRead = 9000; cfg.Limits.MaxItems = 1 })
	for i := range 6 {
		got, err := receiveErr(t, c, 2*time.Second)
		if err != nil {
			t.Fatalf("Receive %d: %v (a tighter read bound than the relay's must rotate the connection, not fail)", i, err)
		}
		if !bytes.Equal(got.Envelope, env) {
			t.Fatal("a delivered envelope changed")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if most > 2 {
		t.Fatalf("one connection served %d fetches: the third page would pass the bound of 9000 and must not be asked for", most)
	}
	if cd.count() < 3 || cd.count() > 5 {
		t.Fatalf("%d dials for six pages of two a connection, want 3 to 5", cd.count())
	}
}

// The bound counts the headers too: a relay whose handshake alone is above the
// client's read bound is refused.
//
// spec: SPO-Xmailbox-SEC-027
func TestTheReadBoundCountsHeaders(t *testing.T) {
	h := newHostile(t, putOK)
	c := h.client(func(cfg *mailbox.Config) { cfg.Limits.MaxBytesRead = 60 })
	err := sendOnce(c)
	if !errors.Is(err, mailbox.ErrProtocol) || !errors.Is(err, ports.ErrNoRoute) {
		t.Fatalf("Send = %v, want ErrNoRoute wrapping ErrProtocol", err)
	}
	var found bool
	for _, e := range h.ev.of(mailbox.EventFailed) {
		found = found || e.Reason == mailbox.ReasonLimit
	}
	if !found {
		t.Fatal("no failure event of the class limit")
	}
}

// A relay that stalls in the middle of a body is cut at the body deadline: the
// client closes, backs off and tries again instead of waiting for ever.
//
// spec: SPO-Xmailbox-SEC-027, SPO-Xmailbox-OUT-041
func TestAStallMidBodyIsCutAtTheBodyDeadline(t *testing.T) {
	env := newEnv(300, 1)
	h := newHostile(t, fetchScript(hs{}, func(s *sconn, req wire.Fetch) bool {
		s.send(page{envs: [][]byte{env}}.header(req.RequestID))
		p, _ := wire.RawFramePrefix(uint32(len(env)))
		s.raw(append(p[:], env[:50]...))
		<-s.h.ctx.Done() // a stall, not a close
		return false
	}))
	c := h.client()
	got, err := receiveErr(t, c, 2*time.Second)
	if len(got.Envelope) != 0 || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Receive = (%d bytes, %v)", len(got.Envelope), err)
	}
	if h.connCount() < 2 {
		t.Fatalf("connections = %d: the stalled body was waited for until the context ended", h.connCount())
	}
}

// A relay that never answers the long-poll costs one reply timeout; the client
// closes, backs off, dials again and keeps trying until its context ends. It
// does not block for ever.
//
// spec: SPO-Xmailbox-OUT-041, SPO-Xmailbox-SEC-027
func TestARelayThatNeverAnswersTheLongPoll(t *testing.T) {
	h := newHostile(t, fetchScript(hs{}, func(s *sconn, req wire.Fetch) bool {
		<-s.h.ctx.Done() // silent until the test ends: only the client's deadline can end the wait
		return false
	}))
	c := h.client()
	t0 := time.Now()
	_, err := receiveErr(t, c, 3500*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Receive = %v, want its context's deadline", err)
	}
	if d := time.Since(t0); d > 4500*time.Millisecond {
		t.Fatalf("Receive overran its context by %v", d-3500*time.Millisecond)
	}
	if h.connCount() < 2 {
		t.Fatalf("connections = %d: the client did not reconnect after the timeout", h.connCount())
	}
}

// A transient Error frame (limit, shutting down) is waited out and the next
// page delivered; another code is returned.
//
// spec: SPO-Xmailbox-OUT-036
func TestFetchErrorFrames(t *testing.T) {
	env := newEnv(20, 1)
	n := 0
	h := newHostile(t, fetchScript(hs{}, func(s *sconn, req wire.Fetch) bool {
		n++
		if n == 1 {
			s.send(wire.Error{Code: wire.CodeShuttingDown})
			return false
		}
		goodPage(s, req, page{envs: [][]byte{env}})
		return true
	}))
	got, err := receiveErr(t, h.client(), 3*time.Second)
	if err != nil || !bytes.Equal(got.Envelope, env) {
		t.Fatalf("after a shutting-down frame: %v", err)
	}
	h2 := newHostile(t, fetchScript(hs{}, func(s *sconn, req wire.Fetch) bool {
		s.send(wire.Error{Code: wire.CodeRevoked})
		return false
	}))
	if _, err := receiveErr(t, h2.client(), 2*time.Second); !errors.Is(err, mailbox.ErrRelayError) {
		t.Fatalf("revoked = %v, want ErrRelayError", err)
	}
}

// A relay that answers empty at once, with no wait, does not make the client
// spin: fetches are spaced by at least MinPoll.
//
// spec: SPO-Xmailbox-OUT-041
func TestQuickEmptyRepliesDoNotSpin(t *testing.T) {
	reqs := make(chan struct{}, 1000)
	h := newHostile(t, fetchScript(hs{}, func(s *sconn, req wire.Fetch) bool {
		reqs <- struct{}{}
		goodPage(s, req, page{})
		return true
	}))
	c := h.client(func(cfg *mailbox.Config) { cfg.Limits.MinPoll = 100 * time.Millisecond })
	receiveErr(t, c, 550*time.Millisecond)
	if n := len(reqs); n < 3 || n > 7 {
		t.Fatalf("%d fetches in 550 ms with a 100 ms minimum spacing", n)
	}
}

// Receive honours its context at once, also in a long-poll, and Close ends a
// blocked Receive.
//
// spec: SPO-Xmailbox-INV-016
func TestReceiveHonoursContextAndClose(t *testing.T) {
	h := newHostile(t, fetchScript(hs{}, func(s *sconn, req wire.Fetch) bool { <-s.h.ctx.Done(); return false }))
	c := h.client(func(cfg *mailbox.Config) { cfg.Limits.IdleTimeout = 30 * time.Second })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := c.Receive(ctx); done <- err }()
	waitFor(t, "the long-poll", func() bool { return h.connCount() == 1 })
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Receive = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Receive did not end after its context was cancelled")
	}
	go func() { _, err := c.Receive(context.Background()); done <- err }()
	time.Sleep(100 * time.Millisecond)
	c.Close()
	select {
	case err := <-done:
		if !errors.Is(err, ports.ErrClosed) {
			t.Fatalf("Receive after Close = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not end a blocked Receive")
	}
	if err := sendOnce(c); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("Send after Close = %v", err)
	}
	if err := c.Ack(); err != nil {
		t.Fatalf("Ack of nothing after Close = %v", err)
	}
}

// The long-poll never outlasts the caller's deadline, so a Receive that times
// out does not leave a request waiting at the relay (and abandon its
// connection): the wait is whole seconds that fit with half a second to spare.
//
// spec: SPO-Xmailbox-OUT-036
func TestTheLongPollFitsTheCallersDeadline(t *testing.T) {
	var mu sync.Mutex
	var waits []uint
	h := newHostile(t, fetchScript(hs{}, func(s *sconn, req wire.Fetch) bool {
		mu.Lock()
		waits = append(waits, req.WaitSeconds)
		mu.Unlock()
		goodPage(s, req, page{})
		return true
	}))
	c := h.client(func(cfg *mailbox.Config) { cfg.Limits.WaitSeconds = 20; cfg.Limits.MinPoll = 100 * time.Millisecond })
	receiveErr(t, c, 3200*time.Millisecond)
	mu.Lock()
	first := waits[0]
	waits = nil
	mu.Unlock()
	if first != 2 {
		t.Fatalf("a Receive with 3.2 s left asked the relay to wait %d s, want 2", first)
	}
	receiveErr(t, c, 1400*time.Millisecond)
	mu.Lock()
	for _, w := range waits {
		if w != 0 {
			t.Fatalf("a Receive with 1.4 s left asked the relay to wait %d s, want 0", w)
		}
	}
	mu.Unlock()
	if h.connCount() != 1 {
		t.Fatalf("connections = %d: a Receive that timed out must not abandon its connection", h.connCount())
	}
}
