package objmailbox

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/test/s3stand"
)

var errCrash = errors.New("the process died before it saw the answer")

// crashing forwards requests to the client until its budget is spent: the
// request that spends it reaches the store and its answer is never seen, as
// when the process dies while it waits; every later request is never sent.
type crashing struct {
	objects
	mu   sync.Mutex
	left int
}

func (c *crashing) next() (send, crashed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.left < 0:
		return false, true
	case c.left == 0:
		c.left = -1
		return true, true
	}
	c.left--
	return true, false
}

func (c *crashing) Put(ctx context.Context, in s3client.PutInput) (s3client.PutResult, error) {
	send, crashed := c.next()
	if send {
		r, err := c.objects.Put(ctx, in)
		if !crashed {
			return r, err
		}
	}
	return s3client.PutResult{}, errCrash
}

func (c *crashing) Delete(ctx context.Context, key string) (s3client.DeleteResult, error) {
	send, crashed := c.next()
	if send {
		r, err := c.objects.Delete(ctx, key)
		if !crashed {
			return r, err
		}
	}
	return s3client.DeleteResult{}, errCrash
}

// A crash at every step of a put and of a mailbox removal leaves what the
// directory store would: the next load lists an entry exactly when its PUT
// reached the store (the directory store: when its file was linked), and after
// a removal cut short at its k-th deletion, the entries not yet deleted.
//
// spec: SPO-Xobjstore-INV-703
func TestACrashAtEveryStepLeavesWhatTheDirectoryStoreWould(t *testing.T) {
	ctx := context.Background()
	for _, k := range []int{-1, 0} { // -1: dead before the PUT is sent; 0: dead while it is answered
		e := newEnv(t, newClockAt(t0))
		s, _, err := open(ctxFor(t, 5*time.Second), e.config(), &crashing{objects: e.client, left: k})
		if err != nil {
			t.Fatal(err)
		}
		b := body(50, 1)
		if o, err := doPut(t, s, rcptA, sendB, b); err == nil || o == relayport.MailboxStored {
			t.Fatalf("a put that crashed = %v, %v", o, err)
		}
		s2 := e.reopen(t, s)
		if n := len(list(t, s2, rcptA)); n != k+1 {
			t.Fatalf("crash at step %d of a put: the next load lists %d entries", k, n)
		}
	}
	for k := range 4 {
		e := newEnv(t, newClockAt(t0))
		s := e.open(t)
		for i := range 3 {
			mustStore(t, s, rcptA, sendB, body(10, byte(i)))
		}
		s.Close()
		c, _, err := open(ctxFor(t, 5*time.Second), e.config(), &crashing{objects: e.client, left: k})
		if err != nil {
			t.Fatal(err)
		}
		c.RemoveMailbox(ctx, rcptA)
		s2 := e.reopen(t, c)
		want := 3 - k - 1
		if k == 3 {
			want = 0 // three deletions sent and answered
		}
		if n := len(list(t, s2, rcptA)); n != want {
			t.Fatalf("a removal that crashed at its deletion %d: the next load lists %d entries, want %d", k, n, want)
		}
		if u := use(t, s2, rcptA, sendB); u.MailboxEntries != uint64(want) {
			t.Fatalf("usage %+v", u)
		}
	}
}

// A mailbox removal while a put's PUT is in flight: the put is told
// ErrMailboxRevoked, never listed, and deletes what its PUT wrote before it
// answers.
//
// spec: SPO-Xobjstore-OUT-702
func TestRemoveMailboxWhileAPutIsInFlight(t *testing.T) {
	e, s, _ := newStore(t)
	b := body(70, 3)
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultApplyLate, Op: s3stand.OpPut, Count: 1, Delay: 300 * time.Millisecond})
	done := make(chan error, 1)
	go func() {
		_, err := doPut(t, s, rcptA, sendB, b)
		done <- err
	}()
	for e.puts() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := s.RemoveMailbox(context.Background(), rcptA); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, relayport.ErrMailboxRevoked) {
		t.Fatalf("a put whose mailbox was removed while its PUT was in flight = %v", err)
	}
	if k, _ := e.objectOf(t, rcptA, sendB, b); k != "" {
		t.Fatal("the removal left what the PUT wrote")
	}
	if u := use(t, s, rcptA, sendB); u != (mailbox.Usage{}) || len(list(t, s, rcptA)) != 0 {
		t.Fatalf("usage %+v", u)
	}
}
