package objmailbox

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/test/s3stand"
)

// Each fault of the stand-in at the put: what the caller is told and what
// memory holds. A put is stored only when the store holds its bytes at its
// key: confirmed by the answer, or by a read-back after a lost or uncertain
// answer or a conflict. A read-back that shows nothing under the key (or that
// cannot tell) sends the identical PUT again; a conflict with nothing under the
// key is then stored by the next PUT. A put that stays unconfirmed is held when
// one of its PUTs may still land: ErrOutcomeUnknown and not ErrAuthorityLost,
// counted in the quota and not listed, and the store goes on. A refusal that
// is not a conflict (a body damaged on the way, a deny), and conflicts that
// keep coming with nothing under the key, are a store failure and nothing
// more. Only other bytes under the key end the writer
// (TestPutOverAnotherWritersObject).
//
// spec: SPO-Xobjstore-OUT-702, SPO-Xobjstore-OUT-706, SPO-Xobjstore-INV-702
func TestPutUnderEachFault(t *testing.T) {
	type want struct{ stored, held bool }
	for _, c := range []struct {
		name   string
		faults []s3stand.Fault
		want   want
	}{
		{"lost response after the commit", []s3stand.Fault{{Kind: s3stand.FaultLoseResponse, Op: s3stand.OpPut, Count: 1}}, want{stored: true}},
		{"commit then 500", []s3stand.Fault{{Kind: s3stand.FaultCommitThenStatus, Op: s3stand.OpPut, Count: 1, Status: 500, Code: "InternalError"}}, want{stored: true}},
		{"commit then 500 on every attempt", []s3stand.Fault{{Kind: s3stand.FaultCommitThenStatus, Op: s3stand.OpPut, Status: 500, Code: "InternalError"}}, want{stored: true}},
		{"applied twice", []s3stand.Fault{{Kind: s3stand.FaultApplyTwice, Op: s3stand.OpPut, Count: 1}}, want{stored: true}},
		{"a lying checksum header", []s3stand.Fault{{Kind: s3stand.FaultWrongChecksum, Op: s3stand.OpPut, Count: 1}}, want{stored: true}},
		{"a lying ETag", []s3stand.Fault{{Kind: s3stand.FaultWrongETag, Op: s3stand.OpPut, Count: 1}}, want{stored: true}},
		{"412 with nothing under the key", []s3stand.Fault{{Kind: s3stand.FaultStatus, Op: s3stand.OpPut, Count: 1, Status: 412, Code: "PreconditionFailed"}}, want{stored: true}},
		{"404", []s3stand.Fault{{Kind: s3stand.FaultStatus, Op: s3stand.OpPut, Count: 1, Status: 404, Code: "NoSuchKey"}}, want{stored: true}},
		{"409", []s3stand.Fault{{Kind: s3stand.FaultStatus, Op: s3stand.OpPut, Count: 1, Status: 409, Code: "ConditionalRequestConflict"}}, want{stored: true}},
		{"503 on one call, then an answer", []s3stand.Fault{{Kind: s3stand.FaultStatus, Op: s3stand.OpPut, Count: 3, Status: 503, Code: "SlowDown"}}, want{stored: true}},
		{"503 on every attempt", []s3stand.Fault{{Kind: s3stand.FaultStatus, Op: s3stand.OpPut, Status: 503, Code: "SlowDown"}}, want{held: true}},
		{"lost responses and a read-back that cannot tell", []s3stand.Fault{
			{Kind: s3stand.FaultStatus, Op: s3stand.OpPut, Status: 503, Code: "SlowDown"},
			{Kind: s3stand.FaultStatus, Op: s3stand.OpGet, Status: 403, Code: "AccessDenied"},
		}, want{held: true}},
		{"412 every time with nothing under the key", []s3stand.Fault{{Kind: s3stand.FaultStatus, Op: s3stand.OpPut, Status: 412, Code: "PreconditionFailed"}}, want{}},
		{"a body damaged on the way", []s3stand.Fault{{Kind: s3stand.FaultCorruptInTransit, Op: s3stand.OpPut, Count: 1}}, want{}},
		{"a deny", []s3stand.Fault{{Kind: s3stand.FaultStatus, Op: s3stand.OpPut, Count: 1, Status: 403, Code: "AccessDenied"}}, want{}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, s, _ := newStore(t)
			b := body(500, 7)
			for _, f := range c.faults {
				e.srv.Inject(f)
			}
			o, err := doPut(t, s, rcptA, sendB, b)
			e.srv.ClearFaults()
			if (o == relayport.MailboxStored && err == nil) != c.want.stored || isLost(err) || isUnknown(err) != c.want.held {
				t.Fatalf("Put = %v, %v; want %+v", o, err, c.want)
			}
			if !c.want.stored && err == nil {
				t.Fatal("a put that was not stored reported no error")
			}
			_, got := e.objectOf(t, rcptA, sendB, b)
			switch {
			case c.want.stored:
				if !bytes.Equal(got, b) {
					t.Fatal("the store does not hold the bytes of a stored put")
				}
				if es := list(t, s, rcptA); len(es) != 1 || use(t, s, rcptA, sendB).MailboxBytes != 500 {
					t.Fatalf("memory after a stored put: %+v", es)
				}
				return
			case c.want.held:
				if u := use(t, s, rcptA, sendB); u.MailboxEntries != 1 || u.MailboxBytes != 500 || len(list(t, s, rcptA)) != 0 {
					t.Fatalf("a held put: usage %+v; it is counted and not listed", u)
				}
			default:
				if u := use(t, s, rcptA, sendB); u != (mailbox.Usage{}) || len(list(t, s, rcptA)) != 0 {
					t.Fatalf("memory holds an entry that was refused: %+v", u)
				}
			}
			mustStore(t, s, rcptA, sendB, b) // the store goes on
		})
	}
}

// Another writer's object at the key a put takes: the same bytes are this
// entry (stored), other bytes end the writer, and from then on every call of
// the store answers ErrAuthorityLost without a request.
//
// spec: SPO-Xobjstore-OUT-702, SPO-Xobjstore-INV-702
func TestPutOverAnotherWritersObject(t *testing.T) {
	e := newEnv(t, newClockAt(t0))
	s, h := hookedStore(t, e, e.config())
	b := body(64, 3)
	var key string
	h.put = func(in s3client.PutInput) {
		if key == "" {
			key = in.Key
			e.adminPut(t, key, b)
		}
	}
	if o, err := doPut(t, s, rcptA, sendB, b); o != relayport.MailboxStored || err != nil {
		t.Fatalf("a put over its own bytes = %v, %v", o, err)
	}
	c := body(64, 4)
	key = ""
	h.put = func(in s3client.PutInput) {
		if key == "" {
			key = in.Key
			e.adminPut(t, key, body(64, 5))
		}
	}
	if o, err := doPut(t, s, rcptC, sendB, c); !isLost(err) || isUnknown(err) || o == relayport.MailboxStored {
		t.Fatalf("a put over other bytes = %v, %v; want ErrAuthorityLost", o, err)
	}
	n := len(e.srv.Records())
	if _, err := s.Usage(context.Background(), rcptA, sendB); !isLost(err) {
		t.Fatalf("Usage after the authority is lost = %v", err)
	}
	if _, err := doPut(t, s, rcptC, sendB, body(10, 1)); !isLost(err) || len(e.srv.Records()) != n {
		t.Fatalf("a put after the loss = %v, with %d requests", err, len(e.srv.Records())-n)
	}
}

// A PUT the store applies after the client gave up: the caller is told
// ErrOutcomeUnknown and not ErrAuthorityLost, the key is held (counted, not
// listed), and the next load finds the entry once it landed: at least once
// (ADR 0015 decision 5, "A mailbox entry created").
//
// spec: SPO-Xobjstore-OUT-706, SPO-Xobjstore-INV-703
func TestPutAppliedLate(t *testing.T) {
	e, s, _ := newStore(t)
	cfg := e.config()
	cfg.RequestTimeout = 300 * time.Millisecond
	s.Close()
	s = e.openWith(t, cfg)
	b := body(80, 2)
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultApplyLate, Op: s3stand.OpPut, Count: 1, Delay: time.Second})
	o, err := doPut(t, s, rcptA, sendB, b)
	if isLost(err) || !isUnknown(err) || o == relayport.MailboxStored {
		t.Fatalf("a put applied late = %v, %v", o, err)
	}
	if u := use(t, s, rcptA, sendB); u.MailboxEntries != 1 || len(list(t, s, rcptA)) != 0 {
		t.Fatalf("usage %+v while the PUT may land", u)
	}
	waitFor(t, "the late PUT to land", func() bool { k, _ := e.objectOf(t, rcptA, sendB, b); return k != "" })
	s2 := e.reopen(t, s)
	if es := list(t, s2, rcptA); len(es) != 1 || es[0].Mid != mailbox.HashOf(b) {
		t.Fatalf("the next load lists %+v", es)
	}
}

// Each fault at the fetch. An object that is gone is ErrMailboxNotFound and no
// longer listed (it stays counted until the sweep); one that is longer, shorter
// or other than the entry (a store that kept damaged bytes) is
// ErrMailboxCorrupt and stays listed, as the directory store keeps a damaged
// file; a body cut short on the way or a 5xx is a store failure; lying
// headers change nothing, because the bytes are checked against the id.
//
// spec: SPO-Xobjstore-OUT-703
func TestOpenUnderEachFault(t *testing.T) {
	for _, c := range []struct {
		name    string
		atPut   bool
		fault   s3stand.Fault
		ok      bool
		want    error
		listed  bool
		counted bool
	}{
		{"gone", false, s3stand.Fault{Kind: s3stand.FaultStatus, Status: 404, Code: "NoSuchKey"}, false, relayport.ErrMailboxNotFound, false, true},
		{"truncated on the way", false, s3stand.Fault{Kind: s3stand.FaultTruncateBody}, false, nil, true, true},
		{"a false length", false, s3stand.Fault{Kind: s3stand.FaultClaimLength, Size: 1 << 30}, false, relayport.ErrMailboxCorrupt, true, true},
		{"oversized", false, s3stand.Fault{Kind: s3stand.FaultOversizeBody, Size: 64 << 10}, false, relayport.ErrMailboxCorrupt, true, true},
		{"500 on every attempt", false, s3stand.Fault{Kind: s3stand.FaultStatus, Status: 500, Code: "InternalError", Count: -1}, false, nil, true, true},
		{"one 500, then the retry", false, s3stand.Fault{Kind: s3stand.FaultStatus, Status: 500, Code: "InternalError"}, true, nil, true, true},
		{"damaged bytes kept by the store", true, s3stand.Fault{Kind: s3stand.FaultAcceptBadChecksum}, false, relayport.ErrMailboxCorrupt, true, true},
		{"a lying checksum header", false, s3stand.Fault{Kind: s3stand.FaultWrongChecksum}, true, nil, true, true},
		{"a lying ETag", false, s3stand.Fault{Kind: s3stand.FaultWrongETag}, true, nil, true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, s, _ := newStore(t)
			b := body(4000, 9)
			f := c.fault
			if f.Count == -1 {
				f.Count = 0 // for ever
			} else {
				f.Count = 1
			}
			if c.atPut {
				f.Op = s3stand.OpPut
				e.srv.Inject(f)
			}
			mustStore(t, s, rcptA, sendB, b)
			if !c.atPut {
				f.Op = s3stand.OpGet
				e.srv.Inject(f)
			}
			got, err := readEntry(t, s, rcptA, mailbox.HashOf(b))
			e.srv.ClearFaults()
			switch {
			case c.ok:
				if err != nil || !bytes.Equal(got, b) {
					t.Fatalf("Open = %d bytes, %v", len(got), err)
				}
			case c.want != nil:
				if !errors.Is(err, c.want) {
					t.Fatalf("Open = %v; want %v", err, c.want)
				}
			default:
				if err == nil || errors.Is(err, relayport.ErrMailboxNotFound) || errors.Is(err, relayport.ErrMailboxCorrupt) || isLost(err) {
					t.Fatalf("Open = %v; want a store failure", err)
				}
			}
			if l := len(list(t, s, rcptA)) == 1; l != c.listed {
				t.Fatalf("listed %v, want %v", l, c.listed)
			}
			if n := use(t, s, rcptA, sendB).MailboxEntries == 1; n != c.counted {
				t.Fatalf("counted %v, want %v", n, c.counted)
			}
		})
	}
}

// Each fault at the delete of an ack. A delete confirmed by its answer, or by
// a read that finds no such key after a lost answer, frees the entry. One whose
// outcome stays unknown makes it doomed: no longer listed, still counted
// (its bytes may be stored), an error that wraps ErrOutcomeUnknown; the next
// load lists it again (at least once: the recipient may get it twice), and the
// next sweep deletes it and frees it. A refusal leaves the entry listed and
// counted. A delete of an object someone else removed is a success.
//
// spec: SPO-Xobjstore-OUT-704, SPO-Xobjstore-INV-704
func TestAckUnderEachFault(t *testing.T) {
	type want struct {
		freed, listed, unknown, failed bool
	}
	for _, c := range []struct {
		name   string
		faults []s3stand.Fault
		want   want
	}{
		{"lost response", []s3stand.Fault{{Kind: s3stand.FaultLoseResponse, Op: s3stand.OpDelete, Count: 1}}, want{freed: true}},
		{"commit then 500 on every attempt", []s3stand.Fault{{Kind: s3stand.FaultCommitThenStatus, Op: s3stand.OpDelete, Status: 500, Code: "InternalError"}}, want{freed: true}},
		{"500 and still there", []s3stand.Fault{{Kind: s3stand.FaultStatus, Op: s3stand.OpDelete, Status: 500, Code: "InternalError"}}, want{unknown: true, failed: true}},
		{"lost and a read that cannot tell", []s3stand.Fault{
			{Kind: s3stand.FaultStatus, Op: s3stand.OpDelete, Status: 503, Code: "SlowDown"},
			{Kind: s3stand.FaultStatus, Op: s3stand.OpGet, Status: 403, Code: "AccessDenied"},
		}, want{unknown: true, failed: true}},
		{"a deny", []s3stand.Fault{{Kind: s3stand.FaultStatus, Op: s3stand.OpDelete, Status: 403, Code: "AccessDenied"}}, want{listed: true, failed: true}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, s, _ := newStore(t)
			b := body(300, 5)
			mustStore(t, s, rcptA, sendB, b)
			for _, f := range c.faults {
				e.srv.Inject(f)
			}
			ok, err := s.Remove(context.Background(), rcptA, mailbox.HashOf(b))
			e.srv.ClearFaults()
			if !ok || (err != nil) != c.want.failed || isUnknown(err) != c.want.unknown || isLost(err) {
				t.Fatalf("Remove = %v, %v; want %+v", ok, err, c.want)
			}
			if l := len(list(t, s, rcptA)) == 1; l != c.want.listed {
				t.Fatalf("listed %v", l)
			}
			freed := use(t, s, rcptA, sendB) == (mailbox.Usage{})
			if freed != c.want.freed {
				t.Fatalf("freed %v", freed)
			}
			k, _ := e.objectOf(t, rcptA, sendB, b)
			if there := k != ""; there == c.want.freed {
				t.Fatalf("the object is there: %v, and the quota freed: %v", there, freed)
			}
			if !c.want.unknown {
				return
			}
			// at least once: a restart before the sweep lists it again
			s2 := e.reopen(t, s)
			if len(list(t, s2, rcptA)) != 1 {
				t.Fatal("an entry whose delete did not land is not listed after a restart")
			}
			if ok, err := s2.Remove(context.Background(), rcptA, mailbox.HashOf(b)); !ok || err != nil {
				t.Fatal(ok, err)
			}
			if u := use(t, s2, rcptA, sendB); u != (mailbox.Usage{}) {
				t.Fatalf("usage %+v", u)
			}
		})
	}
	t.Run("doomed then swept", func(t *testing.T) {
		e, s, _ := newStore(t)
		b := body(300, 5)
		mustStore(t, s, rcptA, sendB, b)
		e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Op: s3stand.OpDelete, Status: 500, Code: "InternalError"})
		if _, err := s.Remove(context.Background(), rcptA, mailbox.HashOf(b)); !isUnknown(err) {
			t.Fatal(err)
		}
		if _, err := s.Sweep(context.Background(), mailbox.MaxRetentionSeconds); !isUnknown(err) {
			t.Fatalf("a sweep that cannot delete the doomed object = %v", err)
		}
		if use(t, s, rcptA, sendB).MailboxEntries != 1 {
			t.Fatal("a doomed object was freed while the store still holds it")
		}
		e.srv.ClearFaults()
		if n, err := s.Sweep(context.Background(), mailbox.MaxRetentionSeconds); n != 0 || err != nil {
			t.Fatal(n, err)
		}
		if u := use(t, s, rcptA, sendB); u != (mailbox.Usage{}) {
			t.Fatalf("usage after the sweep %+v", u)
		}
		if k, _ := e.objectOf(t, rcptA, sendB, b); k != "" {
			t.Fatal("the sweep left the doomed object")
		}
	})
	t.Run("a 404 is taken as gone", func(t *testing.T) {
		e, s, _ := newStore(t)
		b := body(30, 6)
		mustStore(t, s, rcptA, sendB, b)
		e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Op: s3stand.OpDelete, Status: 404, Code: "NoSuchKey", Count: 1})
		if ok, err := s.Remove(context.Background(), rcptA, mailbox.HashOf(b)); !ok || err != nil {
			t.Fatal(ok, err)
		}
		if u := use(t, s, rcptA, sendB); u != (mailbox.Usage{}) {
			t.Fatalf("usage %+v after a 404", u)
		}
		// the store said there was no such key and kept it: the next load lists it
		if len(list(t, e.reopen(t, s), rcptA)) != 1 {
			t.Fatal("a store that lied about a deletion: its object is not loaded again")
		}
	})
	t.Run("a mailbox removal deletes the doomed objects too", func(t *testing.T) {
		e, s, clk := newStore(t)
		b, c := body(30, 6), body(40, 7)
		mustStore(t, s, rcptA, sendB, b)
		clk.Advance(time.Second)
		mustStore(t, s, rcptA, sendB, c)
		e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Op: s3stand.OpDelete, Status: 500, Code: "InternalError"})
		if _, err := s.Remove(context.Background(), rcptA, mailbox.HashOf(b)); !isUnknown(err) {
			t.Fatal(err)
		}
		e.srv.ClearFaults()
		if n, err := s.RemoveMailbox(context.Background(), rcptA); n != 1 || err != nil {
			t.Fatalf("RemoveMailbox = %d, %v; the doomed object is not counted", n, err)
		}
		if u := use(t, s, rcptA, sendB); u != (mailbox.Usage{}) {
			t.Fatalf("usage %+v", u)
		}
		if len(e.objectKeys(t)) != 0 {
			t.Fatalf("left %v", e.objectKeys(t))
		}
	})
	t.Run("a new arrival is after a doomed one", func(t *testing.T) {
		e, s, clk := newStore(t)
		clk.Advance(10 * time.Second)
		b := body(30, 6)
		mustStore(t, s, rcptA, sendB, b)
		e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Op: s3stand.OpDelete, Status: 500, Code: "InternalError"})
		if _, err := s.Remove(context.Background(), rcptA, mailbox.HashOf(b)); !isUnknown(err) {
			t.Fatal(err)
		}
		e.srv.ClearFaults()
		c := body(30, 7)
		mustStore(t, s, rcptA, sendD, c) // the clock has not moved: one second after the doomed one
		if es := list(t, s, rcptA); len(es) != 1 || es[0].Arrival != t0+11 {
			t.Fatalf("listed %+v; a new entry is stamped after every object of the mailbox", es)
		}
	})
	t.Run("already deleted by someone else", func(t *testing.T) {
		e, s, _ := newStore(t)
		b := body(30, 6)
		mustStore(t, s, rcptA, sendB, b)
		k, _ := e.objectOf(t, rcptA, sendB, b)
		if _, err := e.client.Delete(ctxFor(t, time.Second), k); err != nil {
			t.Fatal(err)
		}
		if ok, err := s.Remove(context.Background(), rcptA, mailbox.HashOf(b)); !ok || err != nil {
			t.Fatal(ok, err)
		}
		if ok, err := s.Remove(context.Background(), rcptA, mailbox.HashOf(b)); ok || err != nil {
			t.Fatalf("a second Remove = %v, %v", ok, err)
		}
	})
	t.Run("remove-mailbox and sweep stop at the first refusal", func(t *testing.T) {
		e, s, clk := newStore(t)
		for i := range 3 {
			mustStore(t, s, rcptA, sendB, body(10, byte(i)))
			clk.Advance(time.Second)
		}
		e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Op: s3stand.OpDelete, Status: 403, Code: "AccessDenied", Count: 1})
		n, err := s.RemoveMailbox(context.Background(), rcptA)
		if err == nil || n != 0 || len(list(t, s, rcptA)) != 3 {
			t.Fatalf("RemoveMailbox with a refused first delete = %d, %v, %d listed", n, err, len(list(t, s, rcptA)))
		}
		e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Op: s3stand.OpDelete, Status: 403, Code: "AccessDenied", Count: 1})
		clk.Advance(time.Hour)
		n, err = s.Sweep(context.Background(), 1)
		if err == nil || n != 0 || len(list(t, s, rcptA)) != 3 {
			t.Fatalf("Sweep with a refused first delete = %d, %v", n, err)
		}
		if n, err := s.Sweep(context.Background(), 1); n != 3 || err != nil {
			t.Fatal(n, err)
		}
	})
}
