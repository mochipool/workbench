package objmailbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
	"github.com/mochipool/workbench/spo/test/s3stand"
)

// The findings of the security review of the object mailbox (H1, M1 to M5,
// L1 to L4), each as the request sequence that showed it.

// hooked forwards every request to the client, counts the requests in flight
// and the DELETEs, and lets a test take over the DELETEs.
type hooked struct {
	objects
	inflight atomic.Int64
	deletes  atomic.Int64
	del      func(ctx context.Context, n int64, key string) (s3client.DeleteResult, error)
	put      func(in s3client.PutInput) // called before the PUT is forwarded
}

func (h *hooked) Put(ctx context.Context, in s3client.PutInput) (s3client.PutResult, error) {
	h.inflight.Add(1)
	defer h.inflight.Add(-1)
	if h.put != nil {
		h.put(in)
	}
	return h.objects.Put(ctx, in)
}

func (h *hooked) Get(ctx context.Context, in s3client.GetInput) (s3client.Object, error) {
	h.inflight.Add(1)
	defer h.inflight.Add(-1)
	return h.objects.Get(ctx, in)
}

func (h *hooked) Delete(ctx context.Context, key string) (s3client.DeleteResult, error) {
	h.inflight.Add(1)
	defer h.inflight.Add(-1)
	n := h.deletes.Add(1)
	if h.del != nil {
		return h.del(ctx, n, key)
	}
	return h.objects.Delete(ctx, key)
}

// hookedStore opens a store on e's bucket through a hooked client.
func hookedStore(t *testing.T, e *env, cfg Config) (*Store, *hooked) {
	t.Helper()
	h := &hooked{objects: e.client}
	s, _, err := open(ctxFor(t, 5*time.Second), cfg, h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, h
}

type putRes struct {
	o   relayport.MailboxOutcome
	err error
}

func goPut(t *testing.T, s *Store, ctx context.Context, rcpt, sender [20]byte, b []byte) chan putRes {
	t.Helper()
	done := make(chan putRes, 1)
	q := quota(t)
	go func() {
		o, err := s.Put(ctx, putOf(rcpt, sender, b, q), bytes.NewReader(b))
		done <- putRes{o, err}
	}()
	return done
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// H1. A storm of SlowDown answers on many puts never ends the writer: each put
// is told ErrOutcomeUnknown (unavailable, counted by the host as unanswered),
// not ErrAuthorityLost; its key is held (counted, not listed); the store goes on.
//
// spec: SPO-Xobjstore-OUT-702, SPO-Xobjstore-INV-702, SPO-Xobjstore-OUT-706
func TestReviewH1AStormOfSlowDownsDoesNotEndTheWriter(t *testing.T) {
	e, s, _ := newStore(t)
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Op: s3stand.OpPut, Status: 503, Code: "SlowDown"})
	var wg sync.WaitGroup
	errs := make([]error, 6)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b := body(100, byte(i))
			_, errs[i] = s.Put(context.Background(), putOf(fp(byte(0x10+i)), sendB, b, quota(t)), bytes.NewReader(b))
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if isLost(err) || !isUnknown(err) {
			t.Fatalf("put %d under a storm of 503s = %v; want ErrOutcomeUnknown and not ErrAuthorityLost", i, err)
		}
		if u := use(t, s, fp(byte(0x10+i)), sendB); u.MailboxEntries != 1 || len(list(t, s, fp(byte(0x10+i)))) != 0 {
			t.Fatalf("put %d: usage %+v; a key that may land is counted and not listed", i, u)
		}
	}
	e.srv.ClearFaults()
	mustStore(t, s, rcptC, sendB, body(10, 1))
}

// H1. A PUT the store applies after the client gave up: the put is told
// ErrOutcomeUnknown and not ErrAuthorityLost, the key stays counted while it may
// land, a sweep before its deadline deletes it and keeps it counted, and only a
// deletion confirmed after the deadline frees it.
//
// spec: SPO-Xobjstore-OUT-706, SPO-Xobjstore-INV-704
func TestReviewH1ALateLandingIsSweptAndNeverUndercounted(t *testing.T) {
	clk := relayporttest.NewManualClock(t0)
	e := newEnv(t, clk)
	cfg := e.config()
	cfg.RequestTimeout = 300 * time.Millisecond
	s := e.openWith(t, cfg)
	b := body(80, 2)
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultApplyLate, Op: s3stand.OpPut, Count: 1, Delay: time.Second})
	if _, err := doPut(t, s, rcptA, sendB, b); isLost(err) || !isUnknown(err) {
		t.Fatalf("a put applied late = %v; want ErrOutcomeUnknown and not ErrAuthorityLost", err)
	}
	if u := use(t, s, rcptA, sendB); u.MailboxEntries != 1 {
		t.Fatalf("usage %+v while the PUT may land", u)
	}
	if _, err := s.Sweep(context.Background(), mailbox.MaxRetentionSeconds); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the late PUT to land", func() bool { return len(e.objectKeys(t)) == 1 })
	if u := use(t, s, rcptA, sendB); u.MailboxEntries != 1 || len(list(t, s, rcptA)) != 0 {
		t.Fatalf("usage %+v after the late PUT landed; it is counted and not listed", u)
	}
	if _, err := s.Sweep(context.Background(), mailbox.MaxRetentionSeconds); err != nil {
		t.Fatal(err)
	}
	if len(e.objectKeys(t)) != 0 || use(t, s, rcptA, sendB).MailboxEntries != 1 {
		t.Fatal("a sweep before the deadline did not delete the landed key, or freed it")
	}
	clk.Advance(LandingWindow + time.Second)
	if _, err := s.Sweep(context.Background(), mailbox.MaxRetentionSeconds); err != nil {
		t.Fatal(err)
	}
	if u := use(t, s, rcptA, sendB); u != (mailbox.Usage{}) {
		t.Fatalf("usage %+v after a deletion confirmed past the deadline", u)
	}
}

// H1. The held keys are bounded, for a mailbox and for the store: a put that
// finds a bound reached answers busy, reads nothing and sends nothing, and the
// writer goes on. A retry of a held put by its sender is a new put under a new
// key; when the held one lands too, the next load keeps the earlier and dooms
// the later (at least once).
//
// spec: SPO-Xobjstore-OUT-706
func TestReviewH1HeldKeysAreBounded(t *testing.T) {
	e := newEnv(t, newClockAt(t0))
	cfg := e.config()
	cfg.maxHeldBox, cfg.maxHeld, cfg.backoff = 2, 3, time.Millisecond
	s := e.openWith(t, cfg)
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Op: s3stand.OpPut, Status: 503, Code: "SlowDown"})
	hold := func(r byte, tag byte) {
		t.Helper()
		if _, err := doPut(t, s, fp(r), sendB, body(10, tag)); isLost(err) || !isUnknown(err) {
			t.Fatalf("put %d = %v", tag, err)
		}
	}
	busy := func(name string, r byte) {
		t.Helper()
		cr := &countingReader{r: bytes.NewReader(body(10, 9))}
		puts := e.puts()
		o, err := s.Put(context.Background(), putOf(fp(r), sendB, body(10, 9), quota(t)), cr)
		if o != relayport.MailboxBusy || err != nil || cr.n != 0 || e.puts() != puts {
			t.Fatalf("%s: Put = %v, %v, %d bytes read, %d PUTs", name, o, err, cr.n, e.puts()-puts)
		}
	}
	hold(0xA1, 1)
	hold(0xA1, 2)
	busy("the mailbox's bound", 0xA1) // two held of the store's three
	hold(0xC3, 3)
	busy("the store's bound", 0xD4)
	e.srv.ClearFaults()
	if u := use(t, s, rcptA, sendB); u.MailboxEntries != 2 || len(list(t, s, rcptA)) != 0 {
		t.Fatalf("usage %+v; both held keys are counted and not listed", u) // and the writer goes on
	}
}

// M1. A put revoked after its PUT whose own deletion is not confirmed: it is
// told ErrMailboxRevoked and ErrOutcomeUnknown, its object is doomed (counted,
// not listed) and a later sweep deletes it and frees it.
//
// spec: SPO-Xobjstore-OUT-702, SPO-Xobjstore-INV-704
func TestReviewM1ARevokedPutWhoseDeleteFails(t *testing.T) {
	e, s, _ := newStore(t)
	b := body(70, 3)
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultApplyLate, Op: s3stand.OpPut, Count: 1, Delay: 300 * time.Millisecond})
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Op: s3stand.OpDelete, Status: 500, Code: "InternalError"})
	done := goPut(t, s, context.Background(), rcptA, sendB, b)
	waitFor(t, "the PUT", func() bool { return e.puts() > 0 })
	if _, err := s.RemoveMailbox(context.Background(), rcptA); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if !errors.Is(r.err, relayport.ErrMailboxRevoked) || !isUnknown(r.err) || isLost(r.err) {
		t.Fatalf("a revoked put whose deletion failed = %v", r.err)
	}
	if u := use(t, s, rcptA, sendB); u.MailboxEntries != 1 || len(list(t, s, rcptA)) != 0 {
		t.Fatalf("usage %+v; the object is counted and not listed", u)
	}
	e.srv.ClearFaults()
	if _, err := s.Sweep(context.Background(), mailbox.MaxRetentionSeconds); err != nil {
		t.Fatal(err)
	}
	if u := use(t, s, rcptA, sendB); u != (mailbox.Usage{}) || len(e.objectKeys(t)) != 0 {
		t.Fatalf("usage %+v, %d objects after the sweep", u, len(e.objectKeys(t)))
	}
}

// M2. A put confirmed only after a retry may still land again after its entry
// was acked (an earlier attempt applied late): the ack's confirmed deletion
// keeps the key counted until its window ends.
//
// spec: SPO-Xobjstore-OUT-706, SPO-Xobjstore-OUT-704
func TestReviewM2AnAckWithinTheWindowOfARetriedPut(t *testing.T) {
	e, s, clk := newStore(t)
	b := body(40, 1)
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Op: s3stand.OpPut, Count: 1, Status: 503, Code: "SlowDown"})
	mustStore(t, s, rcptA, sendB, b)
	if ok, err := s.Remove(context.Background(), rcptA, mailbox.HashOf(b)); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if u := use(t, s, rcptA, sendB); u.MailboxEntries != 1 || len(list(t, s, rcptA)) != 0 {
		t.Fatalf("usage %+v after the ack of a retried put; it stays counted in its window", u)
	}
	clk.Advance(LandingWindow + time.Second)
	if _, err := s.Sweep(context.Background(), mailbox.MaxRetentionSeconds); err != nil {
		t.Fatal(err)
	}
	if u := use(t, s, rcptA, sendB); u != (mailbox.Usage{}) {
		t.Fatalf("usage %+v after the window", u)
	}
}

// M2. A put after a restart is under another key than the same entry put
// before it, at the same arrival: a late request of the old process cannot
// reach it. The arrival is not below the load's time.
//
// spec: SPO-Xobjstore-OUT-707
func TestReviewM2KeysDifferAcrossARestart(t *testing.T) {
	e, s, clk := newStore(t)
	m := body(30, 5)
	mustStore(t, s, rcptA, sendB, m)
	k1, _ := e.objectOf(t, rcptA, sendB, m)
	if ok, err := s.Remove(context.Background(), rcptA, mailbox.HashOf(m)); !ok || err != nil {
		t.Fatal(ok, err)
	}
	s2 := e.reopen(t, s)
	mustStore(t, s2, rcptA, sendB, m)
	k2, _ := e.objectOf(t, rcptA, sendB, m)
	if k1 == "" || k2 == "" || k1 == k2 {
		t.Fatalf("keys %q and %q", k1, k2)
	}
	if es := list(t, s2, rcptA); es[0].Arrival < t0 {
		t.Fatalf("an arrival %d below the load's time %d", es[0].Arrival, t0)
	}
	clk.Advance(-5 * time.Second) // stepped back below the load's time
	mustStore(t, s2, rcptC, sendB, m)
	if es := list(t, s2, rcptC); es[0].Arrival < t0 {
		t.Fatalf("an arrival %d below the load's time %d", es[0].Arrival, t0)
	}
}

// M1. A put answered ErrMailboxRevoked has nothing stored and nothing listed,
// whatever the removal's context did.
//
// spec: SPO-Xobjstore-OUT-702, SPO-Xmailbox-INV-009
func TestReviewM1RevokedMeansNothingStored(t *testing.T) {
	check := func(t *testing.T, e *env, s *Store, r putRes, rn int, rerr error) {
		t.Helper()
		listed := len(list(t, s, rcptA))
		switch {
		case errors.Is(r.err, relayport.ErrMailboxRevoked):
			if n := len(e.objectKeys(t)); n != 0 || listed != 0 {
				t.Fatalf("RemoveMailbox = %d, %v; the put was told ErrMailboxRevoked and %d objects are stored, %d listed", rn, rerr, n, listed)
			}
		case r.err == nil && r.o == relayport.MailboxStored:
			if listed != 1 {
				t.Fatalf("a stored put is not listed")
			}
		default:
			t.Fatalf("put = %v, %v", r.o, r.err)
		}
	}
	t.Run("an ended context", func(t *testing.T) {
		e, s, _ := newStore(t)
		e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultApplyLate, Op: s3stand.OpPut, Count: 1, Delay: 300 * time.Millisecond})
		done := goPut(t, s, context.Background(), rcptA, sendB, body(70, 3))
		waitFor(t, "the PUT", func() bool { return e.puts() > 0 })
		ended, cancel := context.WithCancel(context.Background())
		cancel()
		n, err := s.RemoveMailbox(ended, rcptA)
		r := <-done
		check(t, e, s, r, n, err)
		if !errors.Is(err, ErrNotSent) || r.err != nil {
			t.Fatalf("RemoveMailbox on an ended context = %v, and the put = %v; it revokes nothing", err, r.err)
		}
	})
	t.Run("a context that ends during the wait", func(t *testing.T) {
		e, s, _ := newStore(t)
		e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultApplyLate, Op: s3stand.OpPut, Count: 1, Delay: 500 * time.Millisecond})
		done := goPut(t, s, context.Background(), rcptA, sendB, body(70, 3))
		waitFor(t, "the PUT", func() bool { return e.puts() > 0 })
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		start := time.Now()
		n, err := s.RemoveMailbox(ctx, rcptA)
		if took := time.Since(start); took > 300*time.Millisecond {
			t.Fatalf("RemoveMailbox waited %v for the recipient's exclusion past its context", took)
		}
		check(t, e, s, <-done, n, err)
	})
}

// M2. A DELETE the store applies late (a duplicate of an ack's request whose
// answer was lost) never removes a later entry: a key is never used twice.
//
// spec: SPO-Xobjstore-IF-701, SPO-Xobjstore-OUT-704
func TestReviewM2ALateDeleteDoesNotHitANewerEntry(t *testing.T) {
	e := newEnv(t, newClockAt(t0))
	late, lateDone := make(chan struct{}), make(chan error, 1)
	s, h := hookedStore(t, e, e.config())
	h.del = func(ctx context.Context, n int64, key string) (s3client.DeleteResult, error) {
		if n != 1 {
			return e.client.Delete(ctx, key)
		}
		if _, err := e.client.Delete(ctx, key); err != nil {
			return s3client.DeleteResult{}, err
		}
		go func() {
			<-late
			c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := e.client.Delete(c, key)
			lateDone <- err
		}()
		return s3client.DeleteResult{}, errors.Join(s3client.ErrOutcomeUnknown, errors.New("the answer was lost"))
	}
	m := body(60, 4)
	mustStore(t, s, rcptA, sendB, m)
	if ok, err := s.Remove(context.Background(), rcptA, mailbox.HashOf(m)); !ok || err != nil {
		t.Fatalf("Remove = %v, %v", ok, err)
	}
	mustStore(t, s, rcptA, sendB, m) // the same sender, the same bytes, the same second
	close(late)
	if err := <-lateDone; err != nil {
		t.Fatal(err)
	}
	if got, err := readEntry(t, s, rcptA, mailbox.HashOf(m)); err != nil || !bytes.Equal(got, m) {
		t.Fatalf("a put answered stored was removed by a late DELETE of the entry acked before it: %v", err)
	}
}

// M2. The arrival of a mailbox never goes back: not after an ack (the mailbox
// is empty), not with a clock stepped back.
//
// spec: SPO-Xobjstore-OUT-707
func TestReviewM2ArrivalsNeverRepeat(t *testing.T) {
	_, s, clk := newStore(t)
	clk.Advance(10 * time.Second)
	m1 := body(10, 1)
	mustStore(t, s, rcptA, sendB, m1)
	if ok, err := s.Remove(context.Background(), rcptA, mailbox.HashOf(m1)); !ok || err != nil {
		t.Fatal(ok, err)
	}
	clk.Advance(-10 * time.Second)
	mustStore(t, s, rcptA, sendB, body(10, 2))
	if es := list(t, s, rcptA); es[0].Arrival <= t0+10 {
		t.Fatalf("an arrival after an ack and a clock stepped back is %d; the acked entry had %d", es[0].Arrival, t0+10)
	}
}

// M2. A load sets each mailbox's mark from its listed arrivals: a put after a
// restart in the same second is stamped after the newest listed one.
//
// spec: SPO-Xobjstore-OUT-707, SPO-Xmailbox-OUT-022
func TestReviewM2ALoadSetsTheMark(t *testing.T) {
	e, s, _ := newStore(t)
	mustStore(t, s, rcptA, sendB, body(10, 1))
	mustStore(t, s, rcptA, sendB, body(10, 2)) // t0+1
	s2 := e.reopen(t, s)
	mustStore(t, s2, rcptA, sendB, body(10, 3))
	if es := list(t, s2, rcptA); len(es) != 3 || es[2].Arrival != t0+2 {
		t.Fatalf("after a restart: %+v", es)
	}
}

// M3. A late write that pushed a mailbox past the entry bound does not stop the
// relay from starting: the entries past it are doomed (counted, swept, noted).
//
// spec: SPO-Xobjstore-PRE-701, SPO-Xobjstore-OUT-701
func TestReviewM3PastTheEntryBoundAtLoad(t *testing.T) {
	e := newEnv(t, newClockAt(t0+1000))
	for i := range mailbox.MaxMailboxEntries + 1 {
		b := body(3, byte(i))
		b[1], b[2] = byte(i>>8), byte(i)
		e.adminPut(t, keyOf(rcptA, sendB, t0+int64(i), b), b)
	}
	s, notes, err := Open(ctxFor(t, 10*time.Second), e.config())
	if err != nil {
		t.Fatalf("Open over 257 entries in one mailbox = %v", err)
	}
	defer s.Close()
	if n := len(list(t, s, rcptA)); n != mailbox.MaxMailboxEntries || use(t, s, rcptA, sendB).MailboxEntries != 257 || len(notes) == 0 {
		t.Fatalf("listed %d, notes %q", n, notes)
	}
	if _, err := s.Sweep(context.Background(), mailbox.MaxRetentionSeconds); err != nil {
		t.Fatal(err)
	}
	if n := len(e.objectKeys(t)); n != mailbox.MaxMailboxEntries {
		t.Fatalf("%d objects after the sweep", n)
	}
}

// M4. Once the loss is known nothing more is sent, inside a loop too.
//
// spec: SPO-Xobjstore-INV-702
func TestReviewM4NothingIsSentAfterTheLoss(t *testing.T) {
	e := newEnv(t, newClockAt(t0))
	var s *Store
	s, h := hookedStore(t, e, e.config())
	for i := range 4 {
		mustStore(t, s, rcptA, sendB, body(10, byte(i)))
	}
	h.del = func(ctx context.Context, n int64, key string) (s3client.DeleteResult, error) {
		if n == 1 {
			s.lose(fmt.Errorf("%w: a concurrent call learned the loss", relayport.ErrAuthorityLost))
		}
		return e.client.Delete(ctx, key)
	}
	if _, err := s.RemoveMailbox(context.Background(), rcptA); !isLost(err) || h.deletes.Load() != 1 {
		t.Fatalf("RemoveMailbox after the loss was learned at its first DELETE = %v, with %d DELETEs", err, h.deletes.Load())
	}
}

// M4. A loss learned while a put's PUT is in flight: no read-back, no second
// PUT is sent.
//
// spec: SPO-Xobjstore-INV-702
func TestReviewM4NothingIsSentAfterTheLossInsideAPut(t *testing.T) {
	e := newEnv(t, newClockAt(t0))
	var s *Store
	s, h := hookedStore(t, e, e.config())
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Op: s3stand.OpPut, Status: 503, Code: "SlowDown"})
	h.put = func(s3client.PutInput) {
		s.lose(fmt.Errorf("%w: a concurrent call learned the loss", relayport.ErrAuthorityLost))
	}
	_, err := doPut(t, s, rcptA, sendB, body(10, 1))
	if !isLost(err) || e.count(s3stand.OpGet) != 0 || e.puts() != 3 {
		t.Fatalf("a put that learned the loss during its PUT = %v, with %d GETs and %d PUT attempts (one call)", err, e.count(s3stand.OpGet), e.puts())
	}
}

// M4. Close sends nothing more and returns only when no request is in flight.
//
// spec: SPO-Xobjstore-INV-702
func TestReviewM4CloseDrains(t *testing.T) {
	t.Run("nothing after Close", func(t *testing.T) {
		e := newEnv(t, newClockAt(t0))
		var s *Store
		s, h := hookedStore(t, e, e.config())
		for i := range 4 {
			mustStore(t, s, rcptA, sendB, body(10, byte(i)))
		}
		h.del = func(ctx context.Context, n int64, key string) (s3client.DeleteResult, error) {
			if n == 1 {
				go s.Close()
				waitFor(t, "Close", func() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.closed })
			}
			return e.client.Delete(ctx, key)
		}
		s.RemoveMailbox(context.Background(), rcptA)
		if n := h.deletes.Load(); n != 1 {
			t.Fatalf("%d DELETEs; Close came during the first", n)
		}
	})
	t.Run("Close waits", func(t *testing.T) {
		e := newEnv(t, newClockAt(t0))
		s, h := hookedStore(t, e, e.config())
		m := body(10, 1)
		mustStore(t, s, rcptA, sendB, m)
		e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStallBeforeHeaders, Op: s3stand.OpGet, Count: 1, Delay: 300 * time.Millisecond})
		go s.Open(context.Background(), rcptA, mailbox.HashOf(m))
		waitFor(t, "the GET", func() bool { return h.inflight.Load() == 1 })
		s.Close()
		if n := h.inflight.Load(); n != 0 {
			t.Fatalf("Close returned with %d requests in flight", n)
		}
	})
}

// M5. The wait for a recipient's exclusion ends with the caller's context: an
// ack, a retract (L4) and a put (L3) whose context ends while a put of the same
// recipient is in flight return at once, send nothing, keep no reservation, and
// say so with an error the host does not count as unanswered.
//
// spec: SPO-Xobjstore-OUT-704, SPO-Xobjstore-PRE-702
func TestReviewM5TheExclusionWaitEndsWithTheContext(t *testing.T) {
	setup := func(t *testing.T) (*env, *Store, []byte) {
		e, s, _ := newStore(t)
		m := body(10, 1)
		mustStore(t, s, rcptA, sendB, m)
		e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultApplyLate, Op: s3stand.OpPut, Count: 1, Delay: 500 * time.Millisecond})
		goPut(t, s, context.Background(), rcptA, sendD, body(20, 2))
		waitFor(t, "the PUT", func() bool { return e.puts() == 2 })
		return e, s, m
	}
	notCounted := func(t *testing.T, err error) {
		t.Helper()
		if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || isUnknown(err) {
			t.Fatalf("err = %v; want an error the host does not count as unanswered", err)
		}
	}
	t.Run("ack", func(t *testing.T) {
		e, s, m := setup(t)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		dels, start := e.count(s3stand.OpDelete), time.Now()
		_, err := s.Remove(ctx, rcptA, mailbox.HashOf(m))
		if took := time.Since(start); took > 300*time.Millisecond || e.count(s3stand.OpDelete) != dels {
			t.Fatalf("an ack waited %v for the exclusion past its context, %d DELETEs", took, e.count(s3stand.OpDelete)-dels)
		}
		notCounted(t, err)
	})
	t.Run("retract", func(t *testing.T) {
		e, s, m := setup(t)
		gone, cancel := context.WithCancel(context.Background())
		cancel()
		dels, start := e.count(s3stand.OpDelete), time.Now()
		_, err := s.Retract(gone, rcptA, sendB, mailbox.HashOf(m))
		if took := time.Since(start); took > 300*time.Millisecond || e.count(s3stand.OpDelete) != dels {
			t.Fatalf("a retract waited %v for the exclusion with a cancelled context, %d DELETEs", took, e.count(s3stand.OpDelete)-dels)
		}
		notCounted(t, err)
	})
	t.Run("put", func(t *testing.T) {
		e, s, _ := setup(t)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, err := s.Put(ctx, putOf(rcptA, sendB, body(30, 3), quota(t)), bytes.NewReader(body(30, 3)))
		if took := time.Since(start); took > 300*time.Millisecond || e.puts() != 2 {
			t.Fatalf("a put waited %v for the exclusion past its context, %d PUTs", took, e.puts()-2)
		}
		notCounted(t, err)
		if u := use(t, s, rcptA, sendB); u.PairEntries != 1 {
			t.Fatalf("usage %+v; the put keeps a reservation", u)
		}
	})
	t.Run("a context that ends with the last byte", func(t *testing.T) {
		e, s, _ := newStore(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		b := body(100, 4)
		_, err := s.Put(ctx, putOf(rcptA, sendB, b, quota(t)), &cancelling{r: bytes.NewReader(b), cancel: cancel})
		notCounted(t, err)
		if e.puts() != 0 || use(t, s, rcptA, sendB) != (mailbox.Usage{}) {
			t.Fatalf("%d PUTs, usage %+v", e.puts(), use(t, s, rcptA, sendB))
		}
	})
	t.Run("a body cut by the context", func(t *testing.T) {
		_, s, _ := newStore(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		b := body(100_000, 4)
		_, err := s.Put(ctx, putOf(rcptA, sendB, b, quota(t)), &cancelling{r: bytes.NewReader(b), cancel: cancel})
		notCounted(t, err)
	})
}

// cancelling cancels its context after the first read.
type cancelling struct {
	r      *bytes.Reader
	cancel func()
}

func (c *cancelling) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.cancel()
	return n, err
}

// M5. A removal gives the recipient's exclusion up between its deletes: a put
// to the same recipient is not held for the whole removal.
//
// spec: SPO-Xobjstore-OUT-704
func TestReviewM5ARemovalYieldsBetweenDeletes(t *testing.T) {
	e, s, _ := newStore(t)
	for i := range 4 {
		mustStore(t, s, rcptA, sendB, body(10, byte(i)))
	}
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultApplyLate, Op: s3stand.OpDelete, Delay: 150 * time.Millisecond})
	removed := make(chan time.Time, 1)
	go func() {
		s.RemoveMailbox(context.Background(), rcptA)
		removed <- time.Now()
	}()
	waitFor(t, "the first DELETE", func() bool { return e.count(s3stand.OpDelete) >= 1 })
	mustStore(t, s, rcptA, sendD, body(20, 9))
	put := time.Now()
	if r := <-removed; put.After(r) {
		t.Fatal("a put waited for the whole removal of its recipient's mailbox")
	}
}

// L1. A put whose PUT is confirmed after Close is stored, and says so.
//
// spec: SPO-Xobjstore-OUT-702
func TestReviewL1APutConfirmedAfterCloseIsStored(t *testing.T) {
	e, s, _ := newStore(t)
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultApplyLate, Op: s3stand.OpPut, Count: 1, Delay: 300 * time.Millisecond})
	done := goPut(t, s, context.Background(), rcptA, sendB, body(10, 1))
	waitFor(t, "the PUT", func() bool { return e.puts() > 0 })
	s.Close()
	if r := <-done; r.err != nil || r.o != relayport.MailboxStored {
		t.Fatalf("a put whose PUT was confirmed after Close = %v, %v; it is stored", r.o, r.err)
	}
}

// L2. A sweep that fails on one mailbox goes on with the others.
//
// spec: SPO-Xobjstore-OUT-704
func TestReviewL2ASweepGoesOnPastAFailingMailbox(t *testing.T) {
	e, s, clk := newStore(t)
	mustStore(t, s, rcptA, sendB, body(10, 1))
	mustStore(t, s, rcptC, sendB, body(10, 2))
	clk.Advance(time.Hour)
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Op: s3stand.OpDelete, Status: 403, Code: "AccessDenied", Count: 1, Key: mailboxPrefix(testNode) + strings.Repeat("a1", 20)})
	n, err := s.Sweep(context.Background(), 1)
	if err == nil || n != 1 || len(list(t, s, rcptC)) != 0 {
		t.Fatalf("Sweep = %d, %v; rcptC lists %d", n, err, len(list(t, s, rcptC)))
	}
}

// Info. The lease clock must carry a monotonic reading: one that does not is
// refused at Open.
//
// spec: SPO-Xobjstore-IF-701
func TestReviewALeaseClockWithoutAMonotonicReadingIsRefused(t *testing.T) {
	e := newEnv(t, newClockAt(t0))
	cfg := Config{Client: e.client, NodeKey: testNode, Lease: e.lease, Clock: e.clock, LeaseClock: e.lclock, RequestTimeout: time.Second}
	if s, _, err := Open(ctxFor(t, 5*time.Second), cfg); err == nil {
		s.Close()
		t.Fatal("a lease clock without a monotonic reading was accepted")
	}
	cfg.LeaseClock = clockFunc(time.Now)
	s, _, err := Open(ctxFor(t, 5*time.Second), cfg)
	if err != nil {
		t.Fatalf("Open with time.Now as the lease clock = %v", err)
	}
	s.Close()
}
