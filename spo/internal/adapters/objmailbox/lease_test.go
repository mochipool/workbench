package objmailbox

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/test/s3stand"
)

// The lease bounds every request. A lease that lapses while a put reads its
// body, or before an ack, sends nothing (no PUT, no DELETE is recorded): the
// caller is told ErrAuthorityLost and memory is as it was. A request in flight
// at the lease end is cut at the lease end, not at the request timeout. A
// lease whose loss the holder learned (Lost closed) sends nothing either.
//
// spec: SPO-Xobjstore-INV-703
func TestALapsedLeaseSendsNothing(t *testing.T) {
	term := 20 * time.Second // the lease stand's duration minus margin
	t.Run("mid-put", func(t *testing.T) {
		e, s, _ := newStore(t)
		b := body(100, 1)
		g := newGated(b)
		done := make(chan error, 1)
		go func() {
			_, err := s.Put(context.Background(), putOf(rcptA, sendB, b, quota(t)), g)
			done <- err
		}()
		<-g.started
		puts := e.puts()
		e.lclock.Advance(term + time.Second)
		close(g.gate)
		if err := <-done; !isLost(err) {
			t.Fatalf("a put whose lease lapsed while it read its body = %v", err)
		}
		if n := e.puts() - puts; n != 0 {
			t.Fatalf("%d PUTs were sent after the lease end", n)
		}
		if k, _ := e.objectOf(t, rcptA, sendB, b); k != "" {
			t.Fatal("the entry is stored")
		}
	})
	t.Run("mid-ack", func(t *testing.T) {
		e, s, _ := newStore(t)
		b := body(100, 1)
		mustStore(t, s, rcptA, sendB, b)
		e.lclock.Advance(term + time.Second)
		dels := e.count(s3stand.OpDelete)
		if ok, err := s.Remove(context.Background(), rcptA, mailbox.HashOf(b)); !isLost(err) {
			t.Fatalf("an ack after the lease end = %v, %v", ok, err)
		}
		if n := e.count(s3stand.OpDelete) - dels; n != 0 {
			t.Fatalf("%d DELETEs were sent after the lease end", n)
		}
		if k, _ := e.objectOf(t, rcptA, sendB, b); k == "" {
			t.Fatal("the entry is gone")
		}
		for name, f := range map[string]func() error{
			"Retract":       func() error { _, err := s.Retract(context.Background(), rcptA, sendB, mailbox.HashOf(b)); return err },
			"RemoveMailbox": func() error { _, err := s.RemoveMailbox(context.Background(), rcptA); return err },
			"Sweep":         func() error { _, err := s.Sweep(context.Background(), 0); return err },
			"Open":          func() error { _, err := s.Open(context.Background(), rcptA, mailbox.HashOf(b)); return err },
			"List":          func() error { _, _, err := s.List(context.Background(), rcptA, nil, 1); return err },
		} {
			if err := f(); !isLost(err) {
				t.Errorf("%s after the lease end = %v", name, err)
			}
		}
		if n := e.count(s3stand.OpDelete) + e.count(s3stand.OpGet) - dels; n != 0 {
			t.Fatalf("%d requests after the lease end", n)
		}
	})
	t.Run("a request in flight at the lease end", func(t *testing.T) {
		// the lease clock is a manual one: it is moved to the lease end while
		// the PUT is in flight, as time.Now would have moved
		e, s, _ := newStore(t)
		e.lclock.Advance(term - 300*time.Millisecond)
		e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStallBeforeHeaders, Op: s3stand.OpPut, Delay: 5 * time.Second})
		start := time.Now()
		done := goPut(t, s, context.Background(), rcptA, sendB, body(10, 1))
		waitFor(t, "the PUT", func() bool { return e.puts() > 0 })
		e.lclock.Advance(300 * time.Millisecond)
		r := <-done
		if took := time.Since(start); took > 1500*time.Millisecond {
			t.Fatalf("a PUT in flight at the lease end took %v; its deadline is the lease end", took)
		}
		if !isLost(r.err) || !isUnknown(r.err) {
			t.Fatalf("Put = %v", r.err)
		}
	})
	t.Run("a loss the lease saw", func(t *testing.T) {
		e, s, _ := newStore(t)
		e.stand.Steal()
		if err := e.lease.Renew(context.Background()); !errors.Is(err, relayport.ErrAuthorityLost) {
			t.Fatal(err)
		}
		n := len(e.srv.Records())
		if _, err := doPut(t, s, rcptA, sendB, body(10, 1)); !isLost(err) || len(e.srv.Records()) != n {
			t.Fatalf("a put after the lease was taken = %v, %d requests", err, len(e.srv.Records())-n)
		}
	})
	t.Run("open needs the lease", func(t *testing.T) {
		e := newEnv(t, newClockAt(t0))
		e.lclock.Advance(term + time.Second)
		if _, _, err := Open(ctxFor(t, time.Second), e.config()); !isLost(err) || len(e.srv.Records()) != 0 {
			t.Fatalf("Open with a lapsed lease = %v, %d requests", err, len(e.srv.Records()))
		}
	})
}

// A put holds its body only in one of relayport.MaxHeldBodies slots: with
// every slot held by a put that is reading its body, the next one waits for a
// slot until its context ends, reads nothing and stores nothing, and says so
// with ErrNotSent and not the context's error (the host does not count it as
// unanswered); when a slot is freed the next put goes on.
//
// spec: SPO-Xobjstore-PRE-702
func TestAtMost64BodiesAreHeld(t *testing.T) {
	_, s, _ := newStore(t)
	var wg sync.WaitGroup
	gates := make([]*gatedReader, relayport.MaxHeldBodies)
	errs := make([]error, len(gates))
	for i := range gates {
		b := body(64, byte(i))
		gates[i] = newGated(b)
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = s.Put(context.Background(), putOf(fp(byte(i)), sendB, b, quota(t)), gates[i])
		}()
	}
	for _, g := range gates {
		<-g.started
	}
	b := body(64, 200)
	cr := &countingReader{r: strings.NewReader(string(b))}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := s.Put(ctx, putOf(rcptA, sendD, b, quota(t)), cr); !errors.Is(err, ErrNotSent) || errors.Is(err, context.DeadlineExceeded) || cr.n != 0 {
		t.Fatalf("the 65th put = %v, after reading %d bytes", err, cr.n)
	}
	if u := use(t, s, rcptA, sendD); u.PairEntries != 0 {
		t.Fatalf("a put that found no slot holds a reservation: %+v", u)
	}
	close(gates[0].gate)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	if o, err := s.Put(ctx2, putOf(rcptA, sendD, b, quota(t)), strings.NewReader(string(b))); err != nil || o != relayport.MailboxStored {
		t.Fatalf("a put after a slot was freed = %v, %v", o, err)
	}
	for _, g := range gates[1:] {
		close(g.gate)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
}

// Open holds the bodies it read in at most MaxOpenBodies slots, each freed
// when its reader is closed: with every slot held, the next Open waits until
// its context ends and sends nothing.
//
// spec: SPO-Xobjstore-PRE-702
func TestAtMost64OpenBodiesAreHeld(t *testing.T) {
	e, s, _ := newStore(t)
	b := body(20, 1)
	mustStore(t, s, rcptA, sendB, b)
	var held []interface{ Close() error }
	for range MaxOpenBodies {
		rc, err := s.Open(context.Background(), rcptA, mailbox.HashOf(b))
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, rc)
	}
	gets := e.count(s3stand.OpGet)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := s.Open(ctx, rcptA, mailbox.HashOf(b)); !errors.Is(err, context.DeadlineExceeded) || e.count(s3stand.OpGet) != gets {
		t.Fatalf("Open with every slot held = %v, %d GETs", err, e.count(s3stand.OpGet)-gets)
	}
	held[0].Close()
	held[0].Close() // a second Close frees nothing more
	rc, err := s.Open(context.Background(), rcptA, mailbox.HashOf(b))
	if err != nil {
		t.Fatalf("Open after a reader was closed = %v", err)
	}
	held[0] = rc
	ctx2, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel2()
	if _, err := s.Open(ctx2, rcptA, mailbox.HashOf(b)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a second Close freed a second slot: %v", err)
	}
	for _, rc := range held[1:] {
		rc.Close()
	}
}

// A put whose context ends while its PUT is in flight is settled by the
// request deadline, not by its context: the PUT that lands is the entry.
//
// spec: SPO-Xobjstore-OUT-702
func TestAPutIsSettledByItsRequestDeadline(t *testing.T) {
	e, s, _ := newStore(t)
	b := body(30, 2)
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultApplyLate, Op: s3stand.OpPut, Count: 1, Delay: 400 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if o, err := s.Put(ctx, putOf(rcptA, sendB, b, quota(t)), strings.NewReader(string(b))); o != relayport.MailboxStored || err != nil {
		t.Fatalf("Put = %v, %v", o, err)
	}
}

// Puts, fetches, acks, retracts and sweeps of several mailboxes at once (run
// under -race): at the end the listing and the counters agree, every listed
// entry opens to its bytes, and a restart loads the same.
//
// spec: SPO-Xobjstore-INV-701
func TestConcurrentOperations(t *testing.T) {
	e, s, clk := newStore(t)
	rcpts := []party.Fingerprint{fp(1), fp(2), fp(3)}
	senders := []party.Fingerprint{fp(11), fp(12), fp(13)}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for w := range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 20 {
				r, x := rcpts[(w+i)%3], senders[w%3]
				b := body(50+w*7+i, byte(w*31+i))
				o, err := s.Put(context.Background(), putOf(r, x, b, quota(t)), strings.NewReader(string(b)))
				if err != nil {
					t.Errorf("put: %v", err)
					return
				}
				if o == relayport.MailboxStored && i%3 == 0 {
					if _, err := s.Remove(context.Background(), r, mailbox.HashOf(b)); err != nil {
						t.Errorf("remove: %v", err)
					}
				}
				if i%5 == 0 {
					if _, err := s.Retract(context.Background(), r, x, mailbox.HashOf(b)); err != nil {
						t.Errorf("retract: %v", err)
					}
				}
			}
		}()
	}
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, r := range rcpts {
					es, _, err := s.List(context.Background(), r, nil, mailbox.MaxMailboxEntries)
					if err != nil {
						t.Errorf("list: %v", err)
						return
					}
					for _, en := range es {
						rc, err := s.Open(context.Background(), r, en.Mid)
						if err == nil {
							rc.Close()
						} else if !errors.Is(err, relayport.ErrMailboxNotFound) {
							t.Errorf("open: %v", err)
						}
					}
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 5 {
			clk.Advance(time.Second)
			if _, err := s.Sweep(context.Background(), 3); err != nil {
				t.Errorf("sweep: %v", err)
			}
		}
	}()
	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
	check := func(s *Store) string {
		var out []string
		for _, r := range rcpts {
			es := list(t, s, r)
			for i := 1; i < len(es); i++ {
				if es[i].Arrival <= es[i-1].Arrival {
					t.Fatalf("arrivals %d then %d: not strictly increasing (SPO-Xmailbox-OUT-022)", es[i-1].Arrival, es[i].Arrival)
				}
			}
			var bytes uint64
			for _, en := range es {
				bytes += uint64(en.Size)
				got, err := readEntry(t, s, r, en.Mid)
				if err != nil || mailbox.HashOf(got) != en.Mid {
					t.Fatalf("a listed entry does not open to its bytes: %v", err)
				}
			}
			u := use(t, s, r, senders[0])
			if u.MailboxEntries != uint64(len(es)) || u.MailboxBytes != bytes {
				t.Fatalf("listing (%d, %d bytes) and counters %+v disagree", len(es), bytes, u)
			}
			out = append(out, fmt.Sprint(es))
		}
		return strings.Join(out, "\n")
	}
	before := check(s)
	if after := check(e.reopen(t, s)); after != before {
		t.Fatalf("after a restart:\n%s\nwant\n%s", after, before)
	}
}

// The requests each operation makes, for the request-cost guard: a put is one
// PUT, a fetch one GET, an ack one DELETE per copy, a retract one DELETE, a
// mailbox removal and a sweep one DELETE per entry, a load one LIST per page
// of 1000 keys and nothing else.
//
// spec: SPO-Xobjstore-OUT-705
func TestRequestsPerOperation(t *testing.T) {
	e, s, clk := newStore(t)
	counts := func() map[string]int {
		m := map[string]int{}
		for _, r := range e.srv.Records() {
			m[r.Op]++
		}
		return m
	}
	step := func(name string, want map[string]int, f func()) {
		t.Helper()
		before := counts()
		f()
		after := counts()
		for _, op := range []string{s3stand.OpPut, s3stand.OpGet, s3stand.OpHead, s3stand.OpDelete, s3stand.OpList} {
			if d := after[op] - before[op]; d != want[op] {
				t.Errorf("%s: %d %s requests, want %d", name, d, op, want[op])
			}
		}
	}
	m := body(100, 1)
	step("put", map[string]int{s3stand.OpPut: 1}, func() { mustStore(t, s, rcptA, sendB, m) })
	step("duplicate", nil, func() { doPut(t, s, rcptA, sendB, m) })
	step("put of a second copy", map[string]int{s3stand.OpPut: 1}, func() { mustStore(t, s, rcptA, sendD, m) })
	step("list", nil, func() { list(t, s, rcptA) })
	step("fetch", map[string]int{s3stand.OpGet: 1}, func() { readEntry(t, s, rcptA, mailbox.HashOf(m)) })
	step("ack of two copies", map[string]int{s3stand.OpDelete: 2}, func() { s.Remove(context.Background(), rcptA, mailbox.HashOf(m)) })
	for i := range 3 {
		mustStore(t, s, rcptC, sendB, body(10, byte(i)))
	}
	step("retract", map[string]int{s3stand.OpDelete: 1}, func() { s.Retract(context.Background(), rcptC, sendB, mailbox.HashOf(body(10, 0))) })
	step("remove-mailbox of two", map[string]int{s3stand.OpDelete: 2}, func() { s.RemoveMailbox(context.Background(), rcptC) })
	for i := range 5 {
		mustStore(t, s, rcptA, sendB, body(10, byte(i)))
	}
	clk.Advance(time.Hour)
	step("sweep of five", map[string]int{s3stand.OpDelete: 5}, func() { s.Sweep(context.Background(), 60) })
	for i := range 5 {
		mustStore(t, s, rcptA, sendB, body(10, byte(i)))
	}
	s.Close()
	cfg := e.config()
	cfg.pageSize = 2
	step("load of five keys in pages of two", map[string]int{s3stand.OpList: 3}, func() { e.openWith(t, cfg) })
}
