//go:build unix

package mailboxstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

// A far-future arrival (one bad clock reading, more than MaxRetentionSeconds
// ahead of now) is not copied onto later puts: the next Sweep would remove them
// unread.
//
// spec: SPO-Xmailbox-OUT-022
func TestAFarFutureClockReadingIsNotCopiedOntoLaterPuts(t *testing.T) {
	clk := relayporttest.NewManualClock(t0)
	s := openAt(t, newDir(t), clk)
	clk.Advance(40 * 24 * time.Hour)
	bad := body(30, 1)
	put(t, s, rcptA, sndC, bad)
	clk.Advance(-40 * 24 * time.Hour) // the clock is right again
	good := body(31, 2)
	put(t, s, rcptA, sndC, good)
	for _, e := range entries(t, s, rcptA) {
		if e.Mid == mailbox.HashOf(good) && e.Arrival != t0 {
			t.Fatalf("a put with a right clock was stamped %d, want %d", e.Arrival, int64(t0))
		}
	}
	n, err := s.Sweep(context.Background(), 7*24*3600)
	if err != nil || n != 1 {
		t.Fatalf("Sweep = %d, %v; want only the far-future entry", n, err)
	}
	es := entries(t, s, rcptA)
	if len(es) != 1 || es[0].Mid != mailbox.HashOf(good) {
		t.Fatalf("after the sweep: %+v", es)
	}
}

// Arrival is strictly increasing within a mailbox, so the names are totally
// ordered: the listing is the same while the store runs and after a reopen, and
// a client that pages across a restart skips nothing.
//
// spec: SPO-Xmailbox-OUT-022
func TestSameSecondEntriesListTheSameAfterAReopen(t *testing.T) {
	root := newDir(t)
	clk := relayporttest.NewManualClock(t0)
	s := openAt(t, root, clk)
	bx, by := body(50, 1), body(60, 2)
	if hx, hy := mailbox.HashOf(bx), mailbox.HashOf(by); slices.Compare(hx[:], hy[:]) < 0 {
		bx, by = by, bx // mid(X) > mid(Y)
	}
	x, y := mailbox.HashOf(bx), mailbox.HashOf(by)
	put(t, s, rcptA, sndC, bx)
	put(t, s, rcptA, sndC, by) // the same second
	es := entries(t, s, rcptA)
	if len(es) != 2 || es[0].Mid != x || es[1].Mid != y || es[1].Arrival <= es[0].Arrival {
		t.Fatalf("entries = %+v, want X then Y with increasing arrivals", es)
	}
	s.Close()
	s2 := openAt(t, root, clk)
	page, more, err := s2.List(context.Background(), rcptA, &x, 8)
	if err != nil || more || len(page) != 1 || page[0].Mid != y {
		t.Fatalf("List(after=X) after a reopen = %+v, %v, %v; want Y", page, more, err)
	}
	if es2 := entries(t, s2, rcptA); !slices.Equal(es, es2) {
		t.Fatalf("the listing changed across a reopen:\n%+v\n%+v", es, es2)
	}
}

// A mailbox whose newest arrival is the last second of the range refuses a put
// rather than name an entry beyond it.
//
// spec: SPO-Xmailbox-OUT-022
func TestAPutThatWouldPassTheTopOfTheRangeIsRefused(t *testing.T) {
	clk := relayporttest.NewManualClock(mailbox.MaxTime)
	s := openAt(t, newDir(t), clk)
	put(t, s, rcptA, sndC, body(10, 1))
	b := body(11, 2)
	o, err := s.Put(context.Background(), putOf(rcptA, sndC, b), bytes.NewReader(b))
	if err == nil || o == relayport.MailboxStored {
		t.Fatalf("Put = %v, %v; want a refusal", o, err)
	}
	if es := entries(t, s, rcptA); len(es) != 1 {
		t.Fatalf("%d entries", len(es))
	}
	if u, _ := s.Usage(context.Background(), rcptA, sndC); u.MailboxEntries != 1 || u.MailboxBytes != 10 {
		t.Fatalf("a refused put leaked a reservation: %+v", u)
	}
	// another mailbox is not affected
	if o := put(t, s, rcptB, sndC, b); o != relayport.MailboxStored {
		t.Fatalf("put to another mailbox = %v", o)
	}
}

// A planted name with an arrival above MaxTime is not counted as the newest
// when the clock is within a retention of it: the put is stored at the clock,
// not refused for want of a later second.
//
// spec: SPO-Xmailbox-OUT-022
func TestAnArrivalAboveMaxTimeIsNotTheNewest(t *testing.T) {
	root := newDir(t)
	clk := relayporttest.NewManualClock(mailbox.MaxTime - 10*24*3600)
	s := openAt(t, root, clk)
	put(t, s, rcptA, sndC, body(10, 1))
	s.Close()
	names, _ := filepath.Glob(filepath.Join(root, "mailbox", "*", "*"))
	if len(names) != 1 {
		t.Fatalf("%v", names)
	}
	base := filepath.Base(names[0])
	planted := fmt.Sprintf("%020d", int64(mailbox.MaxTime)+5) + base[20:]
	if err := os.Rename(names[0], filepath.Join(filepath.Dir(names[0]), planted)); err != nil {
		t.Fatal(err)
	}
	s2 := openAt(t, root, clk)
	b := body(11, 2)
	if o := put(t, s2, rcptA, sndC, b); o != relayport.MailboxStored {
		t.Fatalf("Put = %v", o)
	}
	for _, e := range entries(t, s2, rcptA) {
		if e.Mid == mailbox.HashOf(b) && e.Arrival != mailbox.MaxTime-10*24*3600 {
			t.Fatalf("stamped %d", e.Arrival)
		}
	}
}

// Open returns the first stored copy of an id, the one the listing shows: a
// damaged first copy is the one that fails, a damaged later copy is not read.
//
// spec: SPO-Xmailbox-OUT-021
func TestOpenReadsTheFirstStoredCopy(t *testing.T) {
	root := newDir(t)
	s := openAt(t, root, relayporttest.NewManualClock(t0))
	b := body(100, 9)
	put(t, s, rcptA, sndC, b) // first
	put(t, s, rcptA, fp(0xD4), b)
	names, _ := filepath.Glob(filepath.Join(root, "mailbox", "*", "0*"))
	sort.Strings(names) // arrival order
	if len(names) != 2 {
		t.Fatalf("%v", names)
	}
	mid := mailbox.HashOf(b)
	if err := os.Truncate(names[1], 5); err != nil { // the later copy
		t.Fatal(err)
	}
	rc, err := s.Open(context.Background(), rcptA, mid)
	if err != nil {
		t.Fatalf("Open with a damaged later copy: %v", err)
	}
	rc.Close()
	if err := os.Truncate(names[0], 5); err != nil { // the first copy
		t.Fatal(err)
	}
	if _, err := s.Open(context.Background(), rcptA, mid); !errors.Is(err, relayport.ErrMailboxCorrupt) {
		t.Fatalf("Open with a damaged first copy = %v, want ErrMailboxCorrupt", err)
	}
}
