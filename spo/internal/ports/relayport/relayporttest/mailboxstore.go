package relayporttest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// ManualClock is a relayport.Clock that only moves when a test says so.
type ManualClock struct {
	mu sync.Mutex
	t  time.Time
}

// NewManualClock starts at unix second sec.
func NewManualClock(sec int64) *ManualClock { return &ManualClock{t: time.Unix(sec, 0)} }

// Now implements relayport.Clock.
func (c *ManualClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }

// Advance moves the clock forward.
func (c *ManualClock) Advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// MailboxFixture is one store under test. Reopen, when set, closes the store
// and opens a new one on the same storage with the same clock; a store with no
// persistence leaves it nil.
type MailboxFixture struct {
	Store  relayport.MailboxStore
	Reopen func(t *testing.T) relayport.MailboxStore
}

func mbFP(b byte) party.Fingerprint {
	var f party.Fingerprint
	for i := range f {
		f[i] = b
	}
	return f
}

func mbBody(n int, tag byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7) ^ tag
	}
	if n > 0 {
		b[0] = tag
	}
	return b
}

// countingReader serves a finite body and counts how much was read from it.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func mbPut(s relayport.MailboxWriter, rcpt, sender party.Fingerprint, body []byte, q mailbox.ValidQuota) (relayport.MailboxOutcome, error) {
	return s.Put(context.Background(), relayport.MailboxPut{
		Recipient: rcpt, Sender: sender, Mid: mailbox.HashOf(body), Size: uint32(len(body)), Quota: q,
	}, bytes.NewReader(body))
}

// tight is a valid quota with the given figures; the rest are the table's.
func tight(f func(q *mailbox.Quota)) mailbox.ValidQuota {
	q := mailbox.DefaultQuota()
	f(&q)
	v, err := q.Validated(1)
	if err != nil {
		panic(err)
	}
	return v
}

func mustOutcome(t *testing.T, got relayport.MailboxOutcome, err error, want relayport.MailboxOutcome) {
	t.Helper()
	if err != nil || got != want {
		t.Fatalf("Put = %v, %v; want outcome %v", got, err, want)
	}
}

func usage(t *testing.T, s relayport.MailboxUsageReader, rcpt, sender party.Fingerprint) mailbox.Usage {
	t.Helper()
	u, err := s.Usage(context.Background(), rcpt, sender)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func listAll(t *testing.T, s relayport.MailboxReader, rcpt party.Fingerprint) []relayport.MailboxEntry {
	t.Helper()
	es, more, err := s.List(context.Background(), rcpt, nil, mailbox.MaxMailboxEntries)
	if err != nil || more {
		t.Fatalf("List = %d entries, more %v, %v", len(es), more, err)
	}
	return es
}

// RunMailboxStore runs the contract of relayport.MailboxStore against stores made
// by mk, a fresh one per subtest. mk registers its own cleanup with t and gives
// the store the clock it is passed.
//
// spec: SPO-Xmailbox-IF-001
func RunMailboxStore(t *testing.T, mk func(t *testing.T, clock relayport.Clock) MailboxFixture) {
	const t0 = 1_700_000_000
	A, B, C := mbFP(0xA1), mbFP(0xB2), mbFP(0xC3)
	loose := tight(func(*mailbox.Quota) {})
	ctx := context.Background()
	fresh := func(t *testing.T) (MailboxFixture, *ManualClock) {
		clk := NewManualClock(t0)
		return mk(t, clk), clk
	}

	// spec: SPO-Xmailbox-OUT-013
	t.Run("StoredThenDuplicate", func(t *testing.T) {
		f, _ := fresh(t)
		body := mbBody(100, 1)
		o, err := mbPut(f.Store, A, B, body, loose)
		mustOutcome(t, o, err, relayport.MailboxStored)
		before := usage(t, f.Store, A, B)
		o, err = mbPut(f.Store, A, B, body, loose)
		mustOutcome(t, o, err, relayport.MailboxDuplicate)
		if after := usage(t, f.Store, A, B); after != before {
			t.Fatalf("a duplicate changed the usage: %+v then %+v", before, after)
		}
		if n := len(listAll(t, f.Store, A)); n != 1 {
			t.Fatalf("%d entries after a duplicate, want 1", n)
		}
		// the same bytes to another recipient is a separate entry
		o, err = mbPut(f.Store, C, B, body, loose)
		mustOutcome(t, o, err, relayport.MailboxStored)
	})

	// The duplicate and busy answers are per (recipient, sender, mid): a second
	// sender putting the same bytes is stored, learns nothing and is charged for
	// its own entry. The recipient's ack of the id removes every copy.
	//
	// spec: SPO-Xmailbox-OUT-021
	t.Run("DuplicateIsPerSender", func(t *testing.T) {
		f, _ := fresh(t)
		body := mbBody(100, 13)
		mid := mailbox.HashOf(body)
		o, err := mbPut(f.Store, A, B, body, loose)
		mustOutcome(t, o, err, relayport.MailboxStored)
		o, err = mbPut(f.Store, A, C, body, loose)
		mustOutcome(t, o, err, relayport.MailboxStored)
		o, err = mbPut(f.Store, A, C, body, loose)
		mustOutcome(t, o, err, relayport.MailboxDuplicate)
		es := listAll(t, f.Store, A)
		if len(es) != 1 || es[0].Sender != B || es[0].Mid != mid {
			t.Fatalf("entries = %+v, want the one message, as its first stored copy (from B)", es)
		}
		if u := usage(t, f.Store, A, C); u.PairEntries != 1 || u.PairBytes != 100 || u.MailboxEntries != 2 || u.SenderBytes != 100 {
			t.Fatalf("usage = %+v: each sender is charged for its own entry", u)
		}
		rc, err := f.Store.Open(ctx, A, mid)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(rc)
		rc.Close()
		if !bytes.Equal(got, body) {
			t.Fatal("Open of an id held for two senders did not return the bytes")
		}
		// a listing that resumes after the id does not return the id again
		first, _, _ := f.Store.List(ctx, A, nil, 1)
		page, more, err := f.Store.List(ctx, A, &first[0].Mid, 8)
		if err != nil || len(page) != 0 || more {
			t.Fatalf("after the id: %+v, %v, %v; both copies are the one message", page, more, err)
		}
		if ok, err := f.Store.Remove(ctx, A, mid); err != nil || !ok {
			t.Fatalf("Remove = %v, %v", ok, err)
		}
		if n := len(listAll(t, f.Store, A)); n != 0 {
			t.Fatalf("an ack left %d copies", n)
		}
		if u := usage(t, f.Store, A, B); u != (mailbox.Usage{}) {
			t.Fatalf("usage after the ack = %+v", u)
		}
	})

	// The id names one message to the recipient: a listing shows it once, at the
	// place of its first stored copy, whatever was stored between the copies. A
	// listing that pages by one entry ends, and every page encodes as Items.
	//
	// spec: SPO-Xmailbox-OUT-021
	t.Run("OneEntryPerIdWhenCopiesAreNotAdjacent", func(t *testing.T) {
		f, _ := fresh(t)
		m, x, y := mbBody(100, 31), mbBody(101, 32), mbBody(102, 33)
		for _, p := range []struct {
			s party.Fingerprint
			b []byte
		}{{C, m}, {C, x}, {B, m}, {B, y}} {
			o, err := mbPut(f.Store, A, p.s, p.b, loose)
			mustOutcome(t, o, err, relayport.MailboxStored)
		}
		want := []mailbox.Hash{mailbox.HashOf(m), mailbox.HashOf(x), mailbox.HashOf(y)}
		var got []mailbox.Hash
		var after *mailbox.Hash
		for i := 0; ; i++ {
			if i > 6 {
				t.Fatalf("paging by one entry did not end: %v", got)
			}
			page, more, err := f.Store.List(ctx, A, after, 1)
			if err != nil || len(page) > 1 {
				t.Fatalf("page = %+v, %v", page, err)
			}
			for _, e := range page {
				got = append(got, e.Mid)
			}
			if !more {
				break
			}
			a := page[0].Mid
			after = &a
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("paged by one = %v, want each id once, in order of first copy: %v", got, want)
		}
		full := listAll(t, f.Store, A)
		seen := map[mailbox.Hash]bool{}
		var items []mailbox.Item
		for _, e := range full {
			if seen[e.Mid] {
				t.Fatalf("a full page repeats %v", e.Mid)
			}
			seen[e.Mid] = true
			items = append(items, mailbox.Item{Mid: e.Mid, Size: e.Size})
		}
		if len(full) != 3 || full[0].Sender != C {
			t.Fatalf("full = %+v, want three entries with the first copy of the repeated id (from C)", full)
		}
		if _, err := mailbox.Encode(mailbox.Items{RequestID: 1, Entries: items}); err != nil {
			t.Fatalf("a listing does not encode as Items: %v", err)
		}
		// resuming after each id gives what follows its first copy
		for i, w := range want {
			page, more, err := f.Store.List(ctx, A, &w, 8)
			if err != nil || more || len(page) != len(want)-1-i {
				t.Fatalf("after %d: %+v, %v, %v", i, page, more, err)
			}
		}
		if u := usage(t, f.Store, A, B); u.MailboxEntries != 4 {
			t.Fatalf("usage %+v: every copy is charged", u)
		}
		// an ack removes every copy
		if ok, err := f.Store.Remove(ctx, A, want[0]); err != nil || !ok {
			t.Fatalf("Remove = %v, %v", ok, err)
		}
		if es := listAll(t, f.Store, A); len(es) != 2 || es[0].Mid != want[1] || es[1].Mid != want[2] {
			t.Fatalf("after the ack: %+v", es)
		}
		if u := usage(t, f.Store, A, B); u.MailboxEntries != 2 || u.PairEntries != 1 {
			t.Fatalf("usage after the ack %+v: both copies are gone", u)
		}
	})

	// spec: SPO-Xmailbox-INV-009
	t.Run("RemoveMailboxCancelsAPutInFlight", func(t *testing.T) {
		f, _ := fresh(t)
		body := mbBody(100, 14)
		gate, started := make(chan struct{}), make(chan struct{})
		r := &gatedBody{r: bytes.NewReader(body), gate: gate, started: started}
		type res struct {
			o   relayport.MailboxOutcome
			err error
		}
		done := make(chan res, 1)
		go func() {
			o, err := f.Store.Put(ctx, relayport.MailboxPut{Recipient: A, Sender: B, Mid: mailbox.HashOf(body), Size: 100, Quota: loose}, r)
			done <- res{o, err}
		}()
		<-started
		if _, err := f.Store.RemoveMailbox(ctx, A); err != nil {
			t.Fatal(err)
		}
		close(gate)
		got := <-done
		if !errors.Is(got.err, relayport.ErrMailboxRevoked) || got.o == relayport.MailboxStored {
			t.Fatalf("a put in flight when its mailbox was removed = %v, %v; want ErrMailboxRevoked", got.o, got.err)
		}
		if n := len(listAll(t, f.Store, A)); n != 0 {
			t.Fatalf("%d entries in a removed mailbox", n)
		}
		if u := usage(t, f.Store, A, B); u != (mailbox.Usage{}) {
			t.Fatalf("usage %+v", u)
		}
		o, err := mbPut(f.Store, A, B, body, loose)
		mustOutcome(t, o, err, relayport.MailboxStored)
	})

	t.Run("DuplicateCostsNoQuotaEvenWhenFull", func(t *testing.T) {
		f, _ := fresh(t)
		q := tight(func(q *mailbox.Quota) { q.MailboxEntries = 1; q.PairEntries = 1 })
		body := mbBody(50, 2)
		o, err := mbPut(f.Store, A, B, body, q)
		mustOutcome(t, o, err, relayport.MailboxStored)
		o, err = mbPut(f.Store, A, B, body, q)
		mustOutcome(t, o, err, relayport.MailboxDuplicate) // not Full
	})

	t.Run("ReadBack", func(t *testing.T) {
		f, clk := fresh(t)
		body := mbBody(70000, 3)
		o, err := mbPut(f.Store, A, B, body, loose)
		mustOutcome(t, o, err, relayport.MailboxStored)
		es := listAll(t, f.Store, A)
		if len(es) != 1 {
			t.Fatalf("%d entries", len(es))
		}
		e := es[0]
		if e.Mid != mailbox.HashOf(body) || e.Size != uint32(len(body)) || e.Sender != B || e.Arrival != clk.Now().Unix() {
			t.Fatalf("entry = %+v", e)
		}
		rc, err := f.Store.Open(ctx, A, e.Mid)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(rc)
		rc.Close()
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("read back %d bytes, err %v", len(got), err)
		}
		if _, err := f.Store.Open(ctx, B, e.Mid); !errors.Is(err, relayport.ErrMailboxNotFound) {
			t.Fatalf("Open of another recipient's entry = %v, want ErrMailboxNotFound", err)
		}
		if es := listAll(t, f.Store, B); len(es) != 0 {
			t.Fatalf("another recipient lists %d entries", len(es))
		}
	})

	t.Run("ListOrderAndPaging", func(t *testing.T) {
		f, clk := fresh(t)
		var want []mailbox.Hash
		for i := range 5 {
			body := mbBody(10+i, byte(10+i))
			o, err := mbPut(f.Store, A, B, body, loose)
			mustOutcome(t, o, err, relayport.MailboxStored)
			want = append(want, mailbox.HashOf(body))
			clk.Advance(2 * time.Second)
		}
		es := listAll(t, f.Store, A)
		for i := range es {
			if es[i].Mid != want[i] {
				t.Fatalf("entry %d is %v, want arrival order %v", i, es[i].Mid, want[i])
			}
		}
		var got []mailbox.Hash
		var after *mailbox.Hash
		for range 10 {
			page, more, err := f.Store.List(ctx, A, after, 2)
			if err != nil || len(page) > 2 {
				t.Fatalf("page = %d, %v", len(page), err)
			}
			for _, e := range page {
				got = append(got, e.Mid)
			}
			if !more {
				break
			}
			a := page[len(page)-1].Mid
			after = &a
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("paged = %v, want %v", got, want)
		}
		// exactly limit entries left is not "more"
		last, more, err := f.Store.List(ctx, A, &want[2], 2)
		if err != nil || len(last) != 2 || more {
			t.Fatalf("the last two entries with limit 2: %d entries, more %v, %v", len(last), more, err)
		}
		if page, more, _ := f.Store.List(ctx, A, &want[1], 2); len(page) != 2 || !more {
			t.Fatalf("three left with limit 2: %d entries, more %v", len(page), more)
		}
		// an unknown after starts from the start
		unknown := mailbox.HashOf([]byte("not here"))
		page, _, err := f.Store.List(ctx, A, &unknown, 16)
		if err != nil || len(page) != 5 {
			t.Fatalf("after unknown: %d entries, %v", len(page), err)
		}
		if _, _, err := f.Store.List(ctx, A, nil, 0); err == nil {
			t.Fatal("a limit of 0 was accepted")
		}
		if _, _, err := f.Store.List(ctx, A, nil, mailbox.MaxMailboxEntries+1); err == nil {
			t.Fatal("a limit over the mailbox bound was accepted")
		}
	})

	// spec: SPO-Xmailbox-OUT-014
	t.Run("RemoveIsScopedAndFinal", func(t *testing.T) {
		f, _ := fresh(t)
		body := mbBody(40, 4)
		mid := mailbox.HashOf(body)
		for _, r := range []party.Fingerprint{A, C} {
			o, err := mbPut(f.Store, r, B, body, loose)
			mustOutcome(t, o, err, relayport.MailboxStored)
		}
		if ok, err := f.Store.Remove(ctx, B, mid); err != nil || ok {
			t.Fatalf("Remove from a mailbox that never had it = %v, %v", ok, err)
		}
		if n := len(listAll(t, f.Store, A)) + len(listAll(t, f.Store, C)); n != 2 {
			t.Fatalf("%d entries left after a foreign Remove", n)
		}
		if ok, err := f.Store.Remove(ctx, A, mid); err != nil || !ok {
			t.Fatalf("Remove = %v, %v", ok, err)
		}
		if ok, _ := f.Store.Remove(ctx, A, mid); ok {
			t.Fatal("a second Remove reported a deletion")
		}
		if _, err := f.Store.Open(ctx, A, mid); !errors.Is(err, relayport.ErrMailboxNotFound) {
			t.Fatalf("Open after Remove = %v", err)
		}
		if len(listAll(t, f.Store, C)) != 1 {
			t.Fatal("Remove touched another recipient's copy")
		}
		if u := usage(t, f.Store, A, B); u.MailboxEntries != 0 || u.MailboxBytes != 0 || u.PairEntries != 0 || u.PairBytes != 0 {
			t.Fatalf("usage after Remove = %+v", u)
		}
		// no tombstone: the same bytes are stored again
		o, err := mbPut(f.Store, A, B, body, loose)
		mustOutcome(t, o, err, relayport.MailboxStored)
	})

	// Retract takes back one sender's own put and nothing else: another sender's
	// copy of the same id stays listed and readable, and the counters of the
	// retracted copy alone go. A cancelled context does not stop it.
	//
	// spec: SPO-Xmailbox-OUT-031
	t.Run("RetractIsSenderScoped", func(t *testing.T) {
		f, _ := fresh(t)
		body := mbBody(100, 21)
		mid := mailbox.HashOf(body)
		for _, s := range []party.Fingerprint{B, C} { // B's copy is the first stored one
			o, err := mbPut(f.Store, A, s, body, loose)
			mustOutcome(t, o, err, relayport.MailboxStored)
		}
		other := mbBody(50, 22)
		o, err := mbPut(f.Store, A, B, other, loose)
		mustOutcome(t, o, err, relayport.MailboxStored)
		gone, cancel := context.WithCancel(ctx)
		cancel()
		if ok, err := f.Store.Retract(gone, A, B, mid); err != nil || !ok {
			t.Fatalf("Retract = %v, %v", ok, err)
		}
		es := listAll(t, f.Store, A)
		if len(es) != 2 || es[0].Mid != mid || es[0].Sender != C || es[1].Mid != mailbox.HashOf(other) {
			t.Fatalf("after retracting B's copy the listing is %+v, want C's copy and the other entry", es)
		}
		rc, err := f.Store.Open(ctx, A, mid)
		if err != nil {
			t.Fatalf("the other sender's copy cannot be opened: %v", err)
		}
		got, _ := io.ReadAll(rc)
		rc.Close()
		if !bytes.Equal(got, body) {
			t.Fatal("the other sender's copy has other bytes")
		}
		if u := usage(t, f.Store, A, B); u.PairEntries != 1 || u.PairBytes != 50 || u.MailboxEntries != 2 || u.MailboxBytes != 150 || u.SenderBytes != 50 {
			t.Fatalf("usage of the retracting sender %+v: only its own copy goes", u)
		}
		if u := usage(t, f.Store, A, C); u.PairEntries != 1 || u.PairBytes != 100 || u.SenderBytes != 100 {
			t.Fatalf("usage of the other sender %+v: unchanged", u)
		}
		// nothing to retract, or not the caller's: no change
		for _, c := range []struct {
			name         string
			rcpt, sender party.Fingerprint
			mid          mailbox.Hash
		}{
			{"already retracted", A, B, mid},
			{"never put by this sender", A, party.Fingerprint{9}, mid},
			{"another recipient", C, B, mid},
			{"unknown id", A, B, mailbox.HashOf([]byte("none"))},
		} {
			if ok, err := f.Store.Retract(ctx, c.rcpt, c.sender, c.mid); err != nil || ok {
				t.Fatalf("%s: Retract = %v, %v; want false", c.name, ok, err)
			}
		}
		if len(listAll(t, f.Store, A)) != 2 {
			t.Fatal("a Retract that found nothing changed the mailbox")
		}
		// no tombstone: the sender can put the same bytes again, as a new entry
		o, err = mbPut(f.Store, A, B, body, loose)
		mustOutcome(t, o, err, relayport.MailboxStored)
		// the last copy: the entry and the mailbox's usage are gone
		for _, s := range []party.Fingerprint{B, C} {
			if ok, err := f.Store.Retract(ctx, A, s, mid); err != nil || !ok {
				t.Fatalf("Retract of %v's copy = %v, %v", s[:1], ok, err)
			}
		}
		if _, err := f.Store.Open(ctx, A, mid); !errors.Is(err, relayport.ErrMailboxNotFound) {
			t.Fatalf("Open after the last copy was retracted = %v", err)
		}
		if es := listAll(t, f.Store, A); len(es) != 1 || es[0].Mid != mailbox.HashOf(other) {
			t.Fatalf("listing %+v", es)
		}
		if ok, err := f.Store.Retract(ctx, A, B, mailbox.HashOf(other)); err != nil || !ok {
			t.Fatal(ok, err)
		}
		if u := usage(t, f.Store, A, B); u != (mailbox.Usage{}) {
			t.Fatalf("usage after everything was retracted: %+v", u)
		}
	})

	t.Run("RemoveMailbox", func(t *testing.T) {
		f, _ := fresh(t)
		for i := range 3 {
			o, err := mbPut(f.Store, A, B, mbBody(20, byte(i)), loose)
			mustOutcome(t, o, err, relayport.MailboxStored)
		}
		o, err := mbPut(f.Store, C, B, mbBody(20, 9), loose)
		mustOutcome(t, o, err, relayport.MailboxStored)
		n, err := f.Store.RemoveMailbox(ctx, A)
		if err != nil || n != 3 {
			t.Fatalf("RemoveMailbox = %d, %v", n, err)
		}
		if len(listAll(t, f.Store, A)) != 0 || len(listAll(t, f.Store, C)) != 1 {
			t.Fatal("RemoveMailbox did not remove exactly the one mailbox")
		}
		if u := usage(t, f.Store, A, B); u.MailboxEntries != 0 || u.PairBytes != 0 || u.SenderBytes != 20 || u.GlobalBytes != 20 {
			t.Fatalf("usage = %+v", u)
		}
		if n, err := f.Store.RemoveMailbox(ctx, A); err != nil || n != 0 {
			t.Fatalf("RemoveMailbox of an empty mailbox = %d, %v", n, err)
		}
	})

	// spec: SPO-Xmailbox-PRE-011, SPO-Xmailbox-OUT-020
	t.Run("HashAndSizeMismatchStoreNothing", func(t *testing.T) {
		f, _ := fresh(t)
		body := mbBody(64, 5)
		mid := mailbox.HashOf(body)
		cases := []struct {
			name string
			p    relayport.MailboxPut
			body []byte
			want error
			// read is how many bytes of body the store must have taken: exactly
			// the declared size, never one more (the rest is the next frame)
			read int
		}{
			{"wrong hash", relayport.MailboxPut{Mid: mailbox.HashOf([]byte("other")), Size: 64}, body, mailbox.ErrHash, 64},
			{"short", relayport.MailboxPut{Mid: mid, Size: 65}, body, mailbox.ErrSize, 64},
			{"long", relayport.MailboxPut{Mid: mid, Size: 63}, body, mailbox.ErrHash, 63},
		}
		for _, c := range cases {
			c.p.Recipient, c.p.Sender, c.p.Quota = A, B, loose
			cr := &countingReader{r: bytes.NewReader(c.body)}
			o, err := f.Store.Put(ctx, c.p, cr)
			if !errors.Is(err, c.want) || o == relayport.MailboxStored {
				t.Fatalf("%s: Put = %v, %v; want %v", c.name, o, err, c.want)
			}
			if cr.n != c.read {
				t.Fatalf("%s: %d bytes were read, want exactly %d", c.name, cr.n, c.read)
			}
			if n := len(listAll(t, f.Store, A)); n != 0 {
				t.Fatalf("%s: %d entries visible", c.name, n)
			}
			if u := usage(t, f.Store, A, B); u != (mailbox.Usage{}) {
				t.Fatalf("%s: usage %+v, want zero", c.name, u)
			}
		}
		o, err := mbPut(f.Store, A, B, body, loose)
		mustOutcome(t, o, err, relayport.MailboxStored)
	})

	// The store takes exactly Size bytes: a stream that holds the body and the
	// next frame still holds the next frame. A body that ends early is an error
	// that wraps io.ErrUnexpectedEOF.
	//
	// spec: SPO-Xmailbox-OUT-020, SPO-Xmailbox-PRE-017
	t.Run("PutReadsExactlyTheDeclaredSize", func(t *testing.T) {
		f, _ := fresh(t)
		body := mbBody(300, 11)
		trailer := []byte("the next frame")
		r := bytes.NewReader(append(append([]byte{}, body...), trailer...))
		o, err := f.Store.Put(ctx, relayport.MailboxPut{Recipient: A, Sender: B, Mid: mailbox.HashOf(body), Size: 300, Quota: loose}, r)
		mustOutcome(t, o, err, relayport.MailboxStored)
		if rest, _ := io.ReadAll(r); !bytes.Equal(rest, trailer) {
			t.Fatalf("%q is left on the stream, want %q", rest, trailer)
		}
		short := mbBody(300, 12)
		o, err = f.Store.Put(ctx, relayport.MailboxPut{Recipient: A, Sender: B, Mid: mailbox.HashOf(short), Size: 300, Quota: loose}, bytes.NewReader(short[:100]))
		if !errors.Is(err, io.ErrUnexpectedEOF) || o == relayport.MailboxStored {
			t.Fatalf("a body that ends early = %v, %v; want io.ErrUnexpectedEOF", o, err)
		}
	})

	t.Run("TooLargeReadsNothing", func(t *testing.T) {
		f, _ := fresh(t)
		for _, size := range []uint32{0, mailbox.MaxEnvelopeBytes + 1, 1 << 31} {
			cr := &countingReader{r: io.LimitReader(zeros{}, 4096)} // finite and small
			o, err := f.Store.Put(ctx, relayport.MailboxPut{Recipient: A, Sender: B, Size: size, Quota: loose}, cr)
			mustOutcome(t, o, err, relayport.MailboxTooLarge)
			if cr.n != 0 {
				t.Fatalf("size %d: %d bytes were read", size, cr.n)
			}
		}
		// at the bound it is accepted
		o, err := mbPut(f.Store, A, B, mbBody(mailbox.MaxEnvelopeBytes, 6), loose)
		mustOutcome(t, o, err, relayport.MailboxStored)
	})

	// spec: SPO-Xmailbox-OUT-013
	t.Run("QuotaBoundsDecideBeforeReading", func(t *testing.T) {
		type tc struct {
			name  string
			q     mailbox.ValidQuota
			setup func(t *testing.T, s relayport.MailboxStore)
			rcpt  party.Fingerprint
			send  party.Fingerprint
			size  int
			// bytes: the bound is a byte bound, so a put one byte smaller fits
			bytes bool
		}
		fill := func(rcpt, sender party.Fingerprint, n, size int, tag byte) func(t *testing.T, s relayport.MailboxStore) {
			return func(t *testing.T, s relayport.MailboxStore) {
				for i := range n {
					o, err := mbPut(s, rcpt, sender, mbBody(size, tag+byte(i)), tight(func(*mailbox.Quota) {}))
					mustOutcome(t, o, err, relayport.MailboxStored)
				}
			}
		}
		cases := []tc{
			{"mailbox entries", tight(func(q *mailbox.Quota) { q.MailboxEntries = 2 }), fill(A, B, 2, 10, 20), A, C, 10, false},
			{"pair entries", tight(func(q *mailbox.Quota) { q.PairEntries = 2 }), fill(A, B, 2, 10, 30), A, B, 10, false},
			{"mailbox bytes", tight(func(q *mailbox.Quota) { q.MailboxBytes = 100 }), fill(A, B, 1, 60, 40), A, C, 41, true},
			{"pair bytes", tight(func(q *mailbox.Quota) { q.PairBytes = 100 }), fill(A, B, 1, 60, 50), A, B, 41, true},
			{"sender bytes across recipients", tight(func(q *mailbox.Quota) { q.SenderBytes = 100 }), fill(C, B, 1, 60, 60), A, B, 41, true},
			{"global bytes", tight(func(q *mailbox.Quota) { q.SenderBytes = 100; q.GlobalBytes = 100 }), fill(C, B, 1, 60, 70), A, mbFP(0xD4), 41, true},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				f, _ := fresh(t)
				c.setup(t, f.Store)
				// just at the bound is stored (size - 1 fits), just over is full
				before := usage(t, f.Store, c.rcpt, c.send)
				body := mbBody(c.size, 99)
				cr := &countingReader{r: bytes.NewReader(body)}
				o, err := f.Store.Put(ctx, relayport.MailboxPut{Recipient: c.rcpt, Sender: c.send, Mid: mailbox.HashOf(body), Size: uint32(len(body)), Quota: c.q}, cr)
				mustOutcome(t, o, err, relayport.MailboxFull)
				if cr.n != 0 {
					t.Fatalf("%d bytes were read for a put that is over a bound", cr.n)
				}
				if usage(t, f.Store, c.rcpt, c.send) != before {
					t.Fatal("a full put changed the usage")
				}
				if c.bytes {
					o, err = mbPut(f.Store, c.rcpt, c.send, mbBody(c.size-1, 98), c.q)
					mustOutcome(t, o, err, relayport.MailboxStored)
				}
			})
		}
	})

	// A put needs a validated quota: the zero ValidQuota, the only one that
	// was not checked, stores nothing and wraps mailbox.ErrQuota. (A quota that
	// fails Validate cannot become a ValidQuota; the domain tests cover that.)
	t.Run("QuotaItselfIsChecked", func(t *testing.T) {
		f, _ := fresh(t)
		if o, err := mbPut(f.Store, A, B, mbBody(10, 1), mailbox.ValidQuota{}); !errors.Is(err, mailbox.ErrQuota) || o == relayport.MailboxStored {
			t.Fatalf("an unvalidated quota was accepted: %v, %v", o, err)
		}
		if es := listAll(t, f.Store, A); len(es) != 0 {
			t.Fatalf("%d entries stored", len(es))
		}
	})

	t.Run("UsageCounters", func(t *testing.T) {
		f, _ := fresh(t)
		put := func(r, s party.Fingerprint, n int, tag byte) mailbox.Hash {
			b := mbBody(n, tag)
			o, err := mbPut(f.Store, r, s, b, loose)
			mustOutcome(t, o, err, relayport.MailboxStored)
			return mailbox.HashOf(b)
		}
		put(A, B, 10, 1)
		put(A, B, 20, 2)
		put(A, C, 30, 3)
		m4 := put(C, B, 40, 4)
		want := map[string]mailbox.Usage{
			"A,B": {MailboxEntries: 3, MailboxBytes: 60, PairEntries: 2, PairBytes: 30, SenderBytes: 70, GlobalBytes: 100},
			"A,C": {MailboxEntries: 3, MailboxBytes: 60, PairEntries: 1, PairBytes: 30, SenderBytes: 30, GlobalBytes: 100},
			"C,B": {MailboxEntries: 1, MailboxBytes: 40, PairEntries: 1, PairBytes: 40, SenderBytes: 70, GlobalBytes: 100},
		}
		check := func(when string) {
			for k, w := range want {
				r, s := map[byte]party.Fingerprint{'A': A, 'B': B, 'C': C}[k[0]], map[byte]party.Fingerprint{'A': A, 'B': B, 'C': C}[k[2]]
				if got := usage(t, f.Store, r, s); got != w {
					t.Fatalf("%s %s: usage = %+v, want %+v", when, k, got, w)
				}
			}
		}
		check("after puts")
		if ok, err := f.Store.Remove(ctx, C, m4); err != nil || !ok {
			t.Fatal(ok, err)
		}
		want["A,B"] = mailbox.Usage{MailboxEntries: 3, MailboxBytes: 60, PairEntries: 2, PairBytes: 30, SenderBytes: 30, GlobalBytes: 60}
		want["A,C"] = mailbox.Usage{MailboxEntries: 3, MailboxBytes: 60, PairEntries: 1, PairBytes: 30, SenderBytes: 30, GlobalBytes: 60}
		want["C,B"] = mailbox.Usage{SenderBytes: 30, GlobalBytes: 60}
		check("after Remove")
	})

	t.Run("SweepUsesTheRetentionRule", func(t *testing.T) {
		f, clk := fresh(t)
		const retention = 100
		var bodies [][]byte
		for i := range 4 {
			b := mbBody(10, byte(i))
			bodies = append(bodies, b)
			o, err := mbPut(f.Store, A, B, b, loose)
			mustOutcome(t, o, err, relayport.MailboxStored)
			clk.Advance(30 * time.Second) // arrivals at 0, 30, 60, 90
		}
		// now = 120: ages 120, 90, 60, 30; retention 100: only the first is due
		n, err := f.Store.Sweep(ctx, retention)
		if err != nil || n != 1 {
			t.Fatalf("Sweep = %d, %v; want 1", n, err)
		}
		clk.Advance(10 * time.Second) // now = 130: ages 100 (exactly the retention), 70, 40
		n, err = f.Store.Sweep(ctx, retention)
		if err != nil || n != 1 {
			t.Fatalf("Sweep at the boundary = %d, %v; want 1", n, err)
		}
		if es := listAll(t, f.Store, A); len(es) != 2 || es[0].Mid != mailbox.HashOf(bodies[2]) {
			t.Fatalf("left %+v", es)
		}
		if u := usage(t, f.Store, A, B); u.MailboxEntries != 2 || u.GlobalBytes != 20 {
			t.Fatalf("usage after sweep = %+v", u)
		}
		// a retention above the maximum behaves as the maximum, zero expires everything
		clk.Advance(time.Duration(mailbox.MaxRetentionSeconds) * time.Second)
		if n, err := f.Store.Sweep(ctx, mailbox.MaxRetentionSeconds*10); err != nil || n != 2 {
			t.Fatalf("Sweep with a retention above the maximum = %d, %v; want 2", n, err)
		}
	})

	// spec: SPO-Xmailbox-INV-008
	t.Run("ConcurrentPutsOfOneEntry", func(t *testing.T) {
		f, _ := fresh(t)
		body := mbBody(2000, 7)
		var wg sync.WaitGroup
		out := make([]relayport.MailboxOutcome, 16)
		errs := make([]error, 16)
		for i := range out {
			wg.Add(1)
			go func() {
				defer wg.Done()
				out[i], errs[i] = mbPut(f.Store, A, B, body, loose)
			}()
		}
		wg.Wait()
		stored := 0
		for i, o := range out {
			if errs[i] != nil {
				t.Fatalf("put %d: %v", i, errs[i])
			}
			switch o {
			case relayport.MailboxStored:
				stored++
			case relayport.MailboxDuplicate, relayport.MailboxBusy:
			default:
				t.Fatalf("put %d: outcome %v", i, o)
			}
		}
		if stored != 1 {
			t.Fatalf("%d puts of one entry were stored, want exactly 1", stored)
		}
		if n := len(listAll(t, f.Store, A)); n != 1 {
			t.Fatalf("%d entries", n)
		}
		if u := usage(t, f.Store, A, B); u.MailboxEntries != 1 || u.MailboxBytes != 2000 {
			t.Fatalf("usage = %+v", u)
		}
	})

	t.Run("ConcurrentPutsRespectTheBound", func(t *testing.T) {
		f, _ := fresh(t)
		q := tight(func(q *mailbox.Quota) { q.MailboxEntries = 3 })
		var wg sync.WaitGroup
		var mu sync.Mutex
		stored := 0
		for i := range 12 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				o, err := mbPut(f.Store, A, B, mbBody(500, byte(i)), q)
				if err != nil {
					t.Error(err)
					return
				}
				if o == relayport.MailboxStored {
					mu.Lock()
					stored++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if stored != 3 || len(listAll(t, f.Store, A)) != 3 {
			t.Fatalf("%d stored, %d listed; the bound is 3", stored, len(listAll(t, f.Store, A)))
		}
	})

	t.Run("CancelledContextStoresNothing", func(t *testing.T) {
		f, _ := fresh(t)
		c, cancel := context.WithCancel(ctx)
		cancel()
		body := mbBody(30, 8)
		o, err := f.Store.Put(c, relayport.MailboxPut{Recipient: A, Sender: B, Mid: mailbox.HashOf(body), Size: 30, Quota: loose}, bytes.NewReader(body))
		if err == nil || o == relayport.MailboxStored {
			t.Fatalf("Put on a cancelled context = %v, %v", o, err)
		}
		if len(listAll(t, f.Store, A)) != 0 || usage(t, f.Store, A, B) != (mailbox.Usage{}) {
			t.Fatal("a cancelled put left something")
		}
	})

	t.Run("CancelDuringTheBodyStoresNothing", func(t *testing.T) {
		f, _ := fresh(t)
		c, cancel := context.WithCancel(ctx)
		defer cancel()
		b := mbBody(200_000, 8)
		r := &cancelAfter{r: bytes.NewReader(b), after: 50_000, cancel: cancel}
		o, err := f.Store.Put(c, relayport.MailboxPut{Recipient: A, Sender: B, Mid: mailbox.HashOf(b), Size: uint32(len(b)), Quota: loose}, r)
		if err == nil || o == relayport.MailboxStored {
			t.Fatalf("Put cancelled during the body = %v, %v", o, err)
		}
		if r.n > 50_000+256<<10 {
			t.Fatalf("%d bytes were read after the cancel", r.n)
		}
		if len(listAll(t, f.Store, A)) != 0 || usage(t, f.Store, A, B) != (mailbox.Usage{}) {
			t.Fatal("a cancelled put left something")
		}
	})

	t.Run("StateSurvivesReopen", func(t *testing.T) {
		f, clk := fresh(t)
		if f.Reopen == nil {
			t.Skip("the store keeps no state across a reopen")
		}
		b1, b2 := mbBody(33, 1), mbBody(44, 2)
		for _, b := range [][]byte{b1, b2} {
			o, err := mbPut(f.Store, A, B, b, loose)
			mustOutcome(t, o, err, relayport.MailboxStored)
			clk.Advance(time.Second)
		}
		o, err := mbPut(f.Store, C, B, b1, loose)
		mustOutcome(t, o, err, relayport.MailboxStored)
		wantA, wantC := listAll(t, f.Store, A), listAll(t, f.Store, C)
		wantU := usage(t, f.Store, A, B)
		s2 := f.Reopen(t)
		if got := listAll(t, s2, A); fmt.Sprint(got) != fmt.Sprint(wantA) {
			t.Fatalf("after reopen A lists %+v, want %+v", got, wantA)
		}
		if got := listAll(t, s2, C); fmt.Sprint(got) != fmt.Sprint(wantC) {
			t.Fatalf("after reopen C lists %+v", got)
		}
		if got := usage(t, s2, A, B); got != wantU {
			t.Fatalf("usage after reopen %+v, want %+v", got, wantU)
		}
		o, err = mbPut(s2, A, B, b1, loose)
		mustOutcome(t, o, err, relayport.MailboxDuplicate)
	})

	t.Run("ClosedStoreRefuses", func(t *testing.T) {
		f, _ := fresh(t)
		if err := f.Store.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := mbPut(f.Store, A, B, mbBody(10, 1), loose); !errors.Is(err, relayport.ErrMailboxClosed) {
			t.Fatalf("Put after Close = %v", err)
		}
		if _, _, err := f.Store.List(ctx, A, nil, 1); !errors.Is(err, relayport.ErrMailboxClosed) {
			t.Fatalf("List after Close = %v", err)
		}
		if _, err := f.Store.Remove(ctx, A, mailbox.Hash{}); !errors.Is(err, relayport.ErrMailboxClosed) {
			t.Fatalf("Remove after Close = %v", err)
		}
		if _, err := f.Store.Retract(ctx, A, B, mailbox.Hash{}); !errors.Is(err, relayport.ErrMailboxClosed) {
			t.Fatalf("Retract after Close = %v", err)
		}
		if _, err := f.Store.Open(ctx, A, mailbox.Hash{}); !errors.Is(err, relayport.ErrMailboxClosed) {
			t.Fatalf("Open after Close = %v", err)
		}
		if _, err := f.Store.RemoveMailbox(ctx, A); !errors.Is(err, relayport.ErrMailboxClosed) {
			t.Fatalf("RemoveMailbox after Close = %v", err)
		}
		if _, err := f.Store.Sweep(ctx, 10); !errors.Is(err, relayport.ErrMailboxClosed) {
			t.Fatalf("Sweep after Close = %v", err)
		}
		if _, err := f.Store.Usage(ctx, A, B); !errors.Is(err, relayport.ErrMailboxClosed) {
			t.Fatalf("Usage after Close = %v", err)
		}
	})
}

// gatedBody blocks its first Read until gate closes and tells started when it
// is reached: a put whose body is slow.
type gatedBody struct {
	r       io.Reader
	gate    chan struct{}
	started chan struct{}
	once    sync.Once
}

func (g *gatedBody) Read(p []byte) (int, error) {
	g.once.Do(func() { close(g.started); <-g.gate })
	return g.r.Read(p)
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }

// cancelAfter cancels a context once after bytes have been read from it.
type cancelAfter struct {
	r      io.Reader
	n      int
	after  int
	cancel context.CancelFunc
}

func (c *cancelAfter) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	if c.n >= c.after {
		c.cancel()
	}
	return n, err
}
