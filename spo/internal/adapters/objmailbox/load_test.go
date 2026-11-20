package objmailbox

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/test/s3stand"
)

// A second instance loads what the first stored from one listing, with no GET:
// the order of every mailbox, every counter and the pair accounting are the
// same, a duplicate is still a duplicate, and an arrival stamped one second
// after the newest (two puts in one second) keeps its place.
//
// spec: SPO-Xobjstore-OUT-701, SPO-Xobjstore-IF-701
func TestRestartRebuildsOrderQuotaAndPairs(t *testing.T) {
	e, s, clk := newStore(t)
	m1, m2, m3, m4 := body(100, 1), body(200, 2), body(300, 3), body(50, 4)
	mustStore(t, s, rcptA, sendB, m1)
	mustStore(t, s, rcptA, sendD, m2) // the same second: stamped one later
	clk.Advance(5 * time.Second)
	mustStore(t, s, rcptA, sendD, m1) // a second sender's copy of m1
	mustStore(t, s, rcptC, sendB, m3)
	clk.Advance(time.Second)
	mustStore(t, s, rcptA, sendB, m4)
	type snap struct {
		a, c []relayport.MailboxEntry
		u    map[string]mailbox.Usage
	}
	take := func(s *Store) snap {
		u := map[string]mailbox.Usage{}
		for _, r := range []party.Fingerprint{rcptA, rcptC} {
			for _, x := range []party.Fingerprint{sendB, sendD} {
				u[fmt.Sprintf("%x%x", r[:1], x[:1])] = use(t, s, r, x)
			}
		}
		return snap{list(t, s, rcptA), list(t, s, rcptC), u}
	}
	before := take(s)
	gets := e.count(s3stand.OpGet)
	s2 := e.reopen(t, s)
	after := take(s2)
	if fmt.Sprint(before) != fmt.Sprint(after) {
		t.Fatalf("after a restart:\n%+v\nwant\n%+v", after, before)
	}
	if n := e.count(s3stand.OpGet) - gets; n != 0 {
		t.Fatalf("the load made %d GETs; it rebuilds from the listing alone", n)
	}
	if o, err := doPut(t, s2, rcptA, sendD, m1); err != nil || o != relayport.MailboxDuplicate {
		t.Fatalf("a put of a stored entry after the restart = %v, %v", o, err)
	}
	if before.a[1].Arrival != t0+1 {
		t.Fatalf("the second put of one second was stamped %d", before.a[1].Arrival)
	}
}

// What the load refuses, as the directory store refuses a directory
// (SPO-Xmailbox-SEC-005, SEC-007): a key below the mailbox prefix that is not an
// entry name, and an object of size 0. Keys outside the mailbox prefix (the
// lease, another relay's prefix) are not listed and change nothing.
//
// spec: SPO-Xobjstore-PRE-701
func TestLoadRefusesWhatAMailboxDoesNotHold(t *testing.T) {
	p := mailboxPrefix(testNode)
	r, x := strings.Repeat("a1", 20), strings.Repeat("b2", 20)
	mid := strings.Repeat("0f", 32)
	good := fmt.Sprintf("%s%s/%020d-%s-%s", p, r, t0, mid, x)
	for _, c := range []struct {
		name, key string
		size      int
	}{
		{"a stray name", p + "notes.txt", 10},
		{"a key at the recipient level", p + r, 10},
		{"upper-case hex", p + strings.ToUpper(r) + good[len(p)+40:], 10},
		{"a short arrival", fmt.Sprintf("%s%s/%019d-%s-%s", p, r, t0, mid, x), 10},
		{"an arrival over int64", fmt.Sprintf("%s%s/%s-%s-%s", p, r, "99999999999999999999", mid, x), 10},
		{"a trailing segment", good + "/x", 10},
		{"a wrong separator", strings.Replace(good, "-", "_", 1), 10},
		{"a temporary name", p + r + "/.tmp-0123456789abcdef", 10},
		{"an empty object", good, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, nil)
			e.clock = e.lclock
			e.adminPut(t, good[:len(p)]+strings.Repeat("c3", 20)+good[len(p)+40:], body(10, 1)) // a good entry too
			e.adminPut(t, c.key, body(c.size, 2))
			_, _, err := Open(ctxFor(t, 5*time.Second), e.config())
			if !errors.Is(err, relayport.ErrMailboxCorrupt) {
				t.Fatalf("Open over %q = %v; want ErrMailboxCorrupt", c.key, err)
			}
		})
	}
	// outside the prefix: ignored
	e := newEnv(t, nil)
	e.clock = e.lclock
	e.adminPut(t, "relays/"+testNode+"/lease", []byte("lease"))
	e.adminPut(t, "relays/"+strings.Repeat("cd", 32)+"/mailbox/"+r+"/x", []byte("other relay"))
	s := e.open(t)
	if u := use(t, s, fp(0xa1), fp(0xb2)); u != (mailbox.Usage{}) {
		t.Fatalf("usage %+v from objects outside the prefix", u)
	}
}

// A listing that claims an object of more than an envelope, or more than the
// bounds of objects and of names in a mailbox (the bounds of what the index
// allocates), is refused at the entry that passes the bound, before anything
// more is read. More mailboxes than an access list has parties is not refused
// (a late write can leave them; the objects bound covers their index), and the
// allocation of a load of 1025 mailboxes stays under 32 MiB (the listing pages
// and the index). An entry past the entry bound of its mailbox is doomed, not
// refused (TestReviewM3PastTheEntryBoundAtLoad).
//
// spec: SPO-Xobjstore-PRE-701, SPO-Xobjstore-SEC-701
func TestLoadBounds(t *testing.T) {
	t.Run("a size over an envelope", func(t *testing.T) {
		e := newEnv(t, nil)
		e.clock = e.lclock
		k := keyOf(rcptA, sendB, t0, []byte("x"))
		doc := `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>` + workBucket + `</Name><Prefix>` + mailboxPrefix(testNode) + `</Prefix><KeyCount>1</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>` +
			`<Contents><Key>` + k + `</Key><LastModified>2024-01-01T00:00:00.000Z</LastModified><ETag>"e"</ETag><Size>1099511627776</Size><StorageClass>STANDARD</StorageClass></Contents></ListBucketResult>`
		e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultRawBody, Op: s3stand.OpList, Body: []byte(doc)})
		_, _, err := Open(ctxFor(t, 5*time.Second), e.config())
		if !errors.Is(err, relayport.ErrMailboxCorrupt) || !strings.Contains(err.Error(), "1099511627776 bytes") {
			t.Fatalf("Open over a listed size of 1 TiB = %v", err)
		}
	})
	t.Run("objects", func(t *testing.T) {
		e := newEnv(t, nil)
		e.clock = e.lclock
		for i := range 11 {
			e.adminPut(t, keyOf(rcptA, sendB, t0+int64(i), body(5, byte(i))), body(5, byte(i)))
		}
		cfg := e.config()
		cfg.maxObjects, cfg.pageSize = 10, 4
		_, _, err := Open(ctxFor(t, 5*time.Second), cfg)
		if !errors.Is(err, relayport.ErrMailboxCorrupt) || !strings.Contains(err.Error(), "more than 10 objects") {
			t.Fatalf("Open over 11 objects with a bound of 10 = %v", err)
		}
		if n := e.count(s3stand.OpList); n != 3 {
			t.Fatalf("%d listing pages; the 11th key is on the third page of 4", n)
		}
		if MaxObjects != mailbox.MaxAccessListParties*2*mailbox.MaxMailboxEntries {
			t.Fatalf("MaxObjects = %d", MaxObjects)
		}
	})
	t.Run("names in one mailbox", func(t *testing.T) {
		e := newEnv(t, nil)
		e.clock = e.lclock
		b := body(3, 1)
		for i := range 5 { // one entry and four later duplicates
			e.adminPut(t, keyOf(rcptA, sendB, t0+int64(i), b), b)
		}
		cfg := e.config()
		cfg.maxNames = 4
		_, _, err := Open(ctxFor(t, 5*time.Second), cfg)
		if !errors.Is(err, relayport.ErrMailboxCorrupt) || !strings.Contains(err.Error(), "more than 4 objects") {
			t.Fatalf("Open over 5 names in one mailbox with a bound of 4 = %v", err)
		}
	})
	t.Run("mailboxes", func(t *testing.T) {
		e := newEnv(t, nil)
		e.clock = e.lclock
		const n = mailbox.MaxAccessListParties + 1
		for i := range n {
			var r party.Fingerprint
			r[0], r[1] = byte(i>>8), byte(i)
			e.adminPut(t, keyOf(r, sendB, t0, []byte{1}), []byte{1})
		}
		runtime.GC()
		var m0, m1 runtime.MemStats
		runtime.ReadMemStats(&m0)
		s, _, err := Open(ctxFor(t, 10*time.Second), e.config())
		runtime.ReadMemStats(&m1)
		if err != nil {
			t.Fatalf("Open over %d mailboxes = %v", n, err)
		}
		defer s.Close()
		if a := m1.TotalAlloc - m0.TotalAlloc; a > 32<<20 {
			t.Fatalf("a load of %d mailboxes allocated %d bytes", n, a)
		}
		if u := use(t, s, party.Fingerprint{4, 0}, sendB); u.GlobalBytes != n {
			t.Fatalf("usage %+v", u)
		}
	})
}

// Of two objects with one sender and id, the load keeps the earlier as the
// entry and the later as doomed: not listed, counted in every quota, deleted by
// the next sweep, which then frees it. The directory store deletes the later
// file at open instead; the object store sends no write while it loads.
//
// spec: SPO-Xobjstore-OUT-701
func TestLoadKeepsTheEarlierOfTwoDuplicates(t *testing.T) {
	clk := newClockAt(t0 + 100)
	e := newEnv(t, clk)
	b := body(40, 9)
	early, late := keyOf(rcptA, sendB, t0, b), keyOf(rcptA, sendB, t0+50, b)
	e.adminPut(t, late, b)
	e.adminPut(t, early, b)
	s, notes, err := Open(ctxFor(t, 5*time.Second), e.config())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if len(notes) != 1 || !strings.Contains(notes[0], late) {
		t.Fatalf("notes %q", notes)
	}
	es := list(t, s, rcptA)
	if len(es) != 1 || es[0].Arrival != t0 {
		t.Fatalf("listed %+v; want the earlier copy only", es)
	}
	if u := use(t, s, rcptA, sendB); u.MailboxEntries != 2 || u.MailboxBytes != 80 {
		t.Fatalf("usage %+v; both objects are stored and counted", u)
	}
	if n, err := s.Sweep(context.Background(), mailbox.MaxRetentionSeconds); err != nil || n != 0 {
		t.Fatalf("Sweep = %d, %v; the doomed copy is not counted as swept", n, err)
	}
	if _, ok := e.stored(late); ok {
		t.Fatal("the sweep left the later duplicate")
	}
	if _, ok := e.stored(early); !ok {
		t.Fatal("the sweep deleted the entry")
	}
	if u := use(t, s, rcptA, sendB); u.MailboxEntries != 1 || u.MailboxBytes != 40 {
		t.Fatalf("usage after the sweep %+v", u)
	}
}

// Lying listings at load. A stale or omitting listing loses entries from
// memory (not listed, not counted) until the next load, and a put of the same
// bytes is a new entry; a listing that shows an object that is gone shows a
// ghost that the first Open drops (ErrMailboxNotFound, still counted until the
// sweep deletes it); a listing that repeats a key across pages is refused; a
// listed size that is not the object's is found at Open (ErrMailboxCorrupt).
//
// spec: SPO-Xobjstore-OUT-701, SPO-Xobjstore-OUT-703
func TestLyingListingsAtLoad(t *testing.T) {
	t.Run("stale", func(t *testing.T) {
		e, s, clk := newStore(t)
		m1, m2 := body(10, 1), body(20, 2)
		mustStore(t, s, rcptA, sendB, m1)
		e.srv.Snapshot()
		clk.Advance(time.Second)
		mustStore(t, s, rcptA, sendB, m2)
		e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStaleList, Op: s3stand.OpList, Count: 1})
		s2 := e.reopen(t, s)
		if es := list(t, s2, rcptA); len(es) != 1 || es[0].Mid != mailbox.HashOf(m1) {
			t.Fatalf("after a stale listing: %+v", es)
		}
		if u := use(t, s2, rcptA, sendB); u.MailboxEntries != 1 {
			t.Fatalf("usage %+v; the unlisted entry is not counted", u)
		}
		clk.Advance(time.Second)
		mustStore(t, s2, rcptA, sendB, m2) // stored again, under a new name
		s3 := e.reopen(t, s2)
		if u := use(t, s3, rcptA, sendB); u.MailboxEntries != 3 || len(list(t, s3, rcptA)) != 2 {
			t.Fatalf("an honest load after: usage %+v, %d listed (the second copy is doomed)", u, len(list(t, s3, rcptA)))
		}
	})
	t.Run("omitted", func(t *testing.T) {
		e, s, _ := newStore(t)
		mustStore(t, s, rcptA, sendB, body(10, 1))
		mustStore(t, s, rcptC, sendB, body(10, 2))
		e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultOmitKey, Op: s3stand.OpList, Key: mailboxPrefix(testNode) + strings.Repeat("c3", 20), Count: 1})
		s2 := e.reopen(t, s)
		if len(list(t, s2, rcptC)) != 0 || len(list(t, s2, rcptA)) != 1 {
			t.Fatal("an omitted key was loaded, or another was lost")
		}
	})
	t.Run("a ghost", func(t *testing.T) {
		e, s, _ := newStore(t)
		m := body(10, 1)
		mustStore(t, s, rcptA, sendB, m)
		e.srv.Snapshot()
		if ok, err := s.Remove(context.Background(), rcptA, mailbox.HashOf(m)); !ok || err != nil {
			t.Fatal(ok, err)
		}
		e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStaleList, Op: s3stand.OpList, Count: 1})
		s2 := e.reopen(t, s)
		if len(list(t, s2, rcptA)) != 1 {
			t.Fatal("the stale listing's ghost is not loaded")
		}
		if _, err := readEntry(t, s2, rcptA, mailbox.HashOf(m)); !errors.Is(err, relayport.ErrMailboxNotFound) {
			t.Fatalf("Open of a ghost = %v", err)
		}
		if len(list(t, s2, rcptA)) != 0 {
			t.Fatal("the ghost is still listed after its Open")
		}
		if u := use(t, s2, rcptA, sendB); u.MailboxEntries != 1 {
			t.Fatalf("usage %+v; a ghost stays counted until the sweep", u)
		}
		if _, err := s2.Sweep(context.Background(), mailbox.MaxRetentionSeconds); err != nil {
			t.Fatal(err)
		}
		if u := use(t, s2, rcptA, sendB); u != (mailbox.Usage{}) {
			t.Fatalf("usage after the sweep %+v", u)
		}
	})
	t.Run("a repeated key across pages", func(t *testing.T) {
		e, s, clk := newStore(t)
		for i := range 3 {
			mustStore(t, s, rcptA, sendB, body(10, byte(i)))
			clk.Advance(time.Second)
		}
		s.Close()
		e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultRepeatKey, Op: s3stand.OpList})
		cfg := e.config()
		cfg.pageSize = 2
		_, _, err := Open(ctxFor(t, 5*time.Second), cfg)
		if !errors.Is(err, s3client.ErrBadListing) {
			t.Fatalf("Open over a listing that repeats a key = %v", err)
		}
	})
	t.Run("sizes that disagree with the object", func(t *testing.T) {
		for _, n := range []int{50, 200} {
			e, s, _ := newStore(t)
			m := body(100, 1)
			mustStore(t, s, rcptA, sendB, m)
			e.srv.Snapshot()
			k, _ := e.objectOf(t, rcptA, sendB, m)
			e.srv.AdminPutVersion(workBucket, k, body(n, 1))
			e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStaleList, Op: s3stand.OpList, Count: 1})
			s2 := e.reopen(t, s)
			if es := list(t, s2, rcptA); len(es) != 1 || es[0].Size != 100 {
				t.Fatalf("listed %+v", es)
			}
			if _, err := readEntry(t, s2, rcptA, mailbox.HashOf(m)); !errors.Is(err, relayport.ErrMailboxCorrupt) {
				t.Fatalf("Open of an object of %d bytes listed as 100 = %v", n, err)
			}
			if len(list(t, s2, rcptA)) != 1 {
				t.Fatal("a damaged entry is dropped; the directory store keeps it")
			}
		}
	})
}

func newClockAt(sec int64) relayport.Clock {
	return clockFunc(func() time.Time { return time.Unix(sec, 0) })
}

type clockFunc func() time.Time

func (f clockFunc) Now() time.Time { return f() }
