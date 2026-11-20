package objlease

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/test/s3stand"
)

// The tests of a store that answers 5xx or does not answer (ADR 0015, "Changes
// after the review of work package 10"): a renewal whose outcome is unknown and
// whose read-back cannot tell is kept pending, not given up; only the same
// bytes with the same If-Match are sent again; the lease is not extended until
// one copy is confirmed, and it ends at the end of the last confirmed renewal.

// leasePuts are the principal's puts of the lease from its n-th request on, as
// the stand-in answered them.
func (e *env) leasePuts(principal string, from int) []s3stand.Record {
	var out []s3stand.Record
	for _, r := range e.requests(principal)[from:] {
		if r.Op == s3stand.OpPut && r.Key == leaseKey {
			out = append(out, r)
		}
	}
	return out
}

// putLog is a store that keeps every put the lease makes (its bytes and its
// condition) and, after the put that arm names (1-based), fails the next
// blind reads and read-backs with a 503: a read-back that cannot tell, without
// touching the reads before it.
type putLog struct {
	Store
	mu         sync.Mutex
	puts       []s3client.PutInput
	arm, blind int
	blindLeft  int
}

func (p *putLog) Put(ctx context.Context, in s3client.PutInput) (s3client.PutResult, error) {
	c := in
	c.Body = bytes.Clone(in.Body)
	p.mu.Lock()
	p.puts = append(p.puts, c)
	n := len(p.puts)
	p.mu.Unlock()
	res, err := p.Store.Put(ctx, in)
	p.mu.Lock()
	if n == p.arm {
		p.blindLeft = p.blind
	}
	p.mu.Unlock()
	return res, err
}

func (p *putLog) blinded() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.blindLeft > 0 {
		p.blindLeft--
		return true
	}
	return false
}

var errBlind = &s3client.StatusError{Op: "get", Status: http.StatusServiceUnavailable, Code: "SlowDown"}

func (p *putLog) Get(ctx context.Context, in s3client.GetInput) (s3client.Object, error) {
	if p.blinded() {
		return s3client.Object{}, errBlind
	}
	return p.Store.Get(ctx, in)
}

func (p *putLog) ReadBack(ctx context.Context, key string, body []byte) (s3client.ReadBack, error) {
	if p.blinded() {
		return s3client.ReadBack{State: s3client.ReadBackCannotTell}, errBlind
	}
	return p.Store.ReadBack(ctx, key, body)
}

// from is the log's puts from the n-th on.
func (p *putLog) from(n int) []s3client.PutInput {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]s3client.PutInput(nil), p.puts[n:]...)
}

func (p *putLog) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.puts)
}

// logged is a lease of the env over a putLog, and its principal.
func (e *env) logged(mod func(*Config)) (*Lease, *putLog, string) {
	e.t.Helper()
	c, id := e.client("")
	pl := &putLog{Store: c}
	return e.leaseOn(pl, mod), pl, id
}

// oneWrite checks that puts are at least min copies of one write: the same
// bytes and the same condition (If-Match on the ETag of the record before it,
// or If-None-Match).
func oneWrite(t *testing.T, puts []s3client.PutInput, min int) {
	t.Helper()
	if len(puts) < min {
		t.Fatalf("%d puts, want at least %d", len(puts), min)
	}
	for i, p := range puts {
		if p.IfMatch == "" && !p.IfNoneMatch {
			t.Fatalf("put %d is not conditional: %+v", i, p)
		}
		if !bytes.Equal(p.Body, puts[0].Body) || p.IfMatch != puts[0].IfMatch || p.IfNoneMatch != puts[0].IfNoneMatch {
			t.Fatalf("put %d is not a copy of the first:\n%s(If-Match %s)\nfirst:\n%s(If-Match %s)", i, p.Body, p.IfMatch, puts[0].Body, puts[0].IfMatch)
		}
	}
}

// slowDown is a 503 SlowDown on op of the lease ("" for every op).
func slowDown(op string) s3stand.Fault {
	return s3stand.Fault{Kind: s3stand.FaultStatus, Op: op, Key: leaseKey, Status: 503, Code: "SlowDown"}
}

func wantPending(t *testing.T, l *Lease, err error, what string) {
	t.Helper()
	if err == nil || errors.Is(err, relayport.ErrAuthorityLost) || !held(l) || isClosed(l.Lost()) {
		t.Fatalf("%s: %v, held %v; want a failed renewal that leaves the lease held", what, err, held(l))
	}
}

// A storm of 503 answers to the renewal and to its read-back: each renewal
// fails without a loss and the lease keeps the end of the last confirmed one;
// every renewal sends the same bytes with the same If-Match; when the store
// answers again the copy lands, and the lease holds from that copy's sending
// (it got a 200: it is the copy that was applied).
//
// spec: SPO-Xobjstore-IF-104, SPO-Xobjstore-PRE-101, SPO-Xobjstore-OUT-304
func TestARenewalRidesOutA503Storm(t *testing.T) {
	for _, opaque := range []bool{false, true} {
		e := newInitEnv(t, opaque)
		a, pl, aid := e.logged(nil)
		acquire(t, a)
		first, _ := a.Until()
		from, pfrom := len(e.requests(aid)), pl.count()
		e.srv.Inject(slowDown(s3stand.OpPut))
		e.srv.Inject(slowDown(s3stand.OpGet))
		for i := range 3 {
			e.clock.Advance(time.Second)
			wantPending(t, a, a.Renew(ctxT(t, 5*time.Second)), "a renewal in a 503 storm")
			if until, _ := a.Until(); !until.Equal(first) {
				t.Fatalf("renewal %d: an unconfirmed renewal moved the lease end to %v from %v", i, until, first)
			}
		}
		e.srv.ClearFaults()
		e.clock.Advance(time.Second)
		sent := e.clock.Now()
		if err := a.Renew(ctxT(t, 5*time.Second)); err != nil {
			t.Fatalf("the renewal after the storm: %v", err)
		}
		if until, ok := a.Until(); !ok || !until.Equal(sent.Add(DefaultTimes().Term())) {
			t.Fatalf("the lease ends at %v, want the sending of the copy that landed plus the term, %v", until, sent.Add(DefaultTimes().Term()))
		}
		if got := e.stored(); got.Counter != 3 || got.Holder != a.holder {
			t.Fatalf("stored %+v, want the one renewal", got)
		}
		puts := pl.from(pfrom)
		oneWrite(t, puts, 4)
		if st := e.leasePuts(aid, from); st[len(st)-1].Status != http.StatusOK {
			t.Fatalf("the last copy was answered %d", st[len(st)-1].Status)
		}
		// the next renewal is a new write, on the ETag of the one confirmed
		pfrom = pl.count()
		e.clock.Advance(time.Second)
		if err := a.Renew(ctxT(t, 5*time.Second)); err != nil {
			t.Fatalf("the next renewal: %v", err)
		}
		if got := e.stored(); got.Counter != 4 {
			t.Fatalf("stored %+v after the next renewal", got)
		}
		if next := pl.from(pfrom); len(next) != 1 || next[0].IfMatch == puts[0].IfMatch || bytes.Equal(next[0].Body, puts[0].Body) {
			t.Fatalf("the next renewal %+v is not a new write after %+v", next, puts[0])
		}
	}
}

// A renewal that landed although its answer was a 503 or was lost, with a
// read-back that cannot tell: the lease is not extended; the next renewal sends
// the same bytes with the same If-Match, which the store refuses (412, its ETag
// moved on to the copy that landed); that refusal is read back, shows the
// pending bytes, and settles the renewal as applied. The lease then holds from
// the FIRST copy's sending: the read-back does not say which copy landed, and
// the first is the earliest that can have.
//
// spec: SPO-Xobjstore-IF-104, SPO-Xobjstore-PRE-101
func TestALandedRenewalIsSettledByAReadBack(t *testing.T) {
	for name, fault := range map[string]s3stand.Fault{
		"commit then 503": {Kind: s3stand.FaultCommitThenStatus, Status: 503, Code: "ServiceUnavailable"},
		"lost response":   {Kind: s3stand.FaultLoseResponse},
	} {
		t.Run(name, func(t *testing.T) {
			e := newInitEnv(t, true)
			a, pl, aid := e.logged(nil)
			acquire(t, a)
			old, _ := a.Until()
			from, pfrom := len(e.requests(aid)), pl.count()
			fault.Op, fault.Key, fault.Count = s3stand.OpPut, leaseKey, 1
			e.srv.Inject(fault)
			e.srv.Inject(slowDown(s3stand.OpGet))
			e.clock.Advance(time.Second)
			firstSent := e.clock.Now()
			wantPending(t, a, a.Renew(ctxT(t, 5*time.Second)), "a renewal that landed, with a read-back that cannot tell")
			if until, _ := a.Until(); !until.Equal(old) {
				t.Fatalf("the unconfirmed renewal moved the lease end to %v from %v", until, old)
			}
			if got := e.stored(); got.Counter != 3 || got.Holder != a.holder {
				t.Fatalf("stored %+v: the fault did not land the renewal", got)
			}
			e.srv.ClearFaults()
			e.clock.Advance(2 * time.Second)
			if err := a.Renew(ctxT(t, 5*time.Second)); err != nil {
				t.Fatalf("the resent renewal: %v", err)
			}
			if until, ok := a.Until(); !ok || !until.Equal(firstSent.Add(DefaultTimes().Term())) {
				t.Fatalf("the lease ends at %v, want the first copy's sending plus the term, %v", until, firstSent.Add(DefaultTimes().Term()))
			}
			if got := e.stored(); got.Counter != 3 {
				t.Fatalf("stored %+v: the settled renewal was written again", got)
			}
			oneWrite(t, pl.from(pfrom), 2)
			if st := e.leasePuts(aid, from); st[len(st)-1].Status != http.StatusPreconditionFailed {
				t.Fatalf("the resent copy was answered %d, want 412", st[len(st)-1].Status)
			}
			e.clock.Advance(time.Second)
			if err := a.Renew(ctxT(t, 5*time.Second)); err != nil {
				t.Fatalf("the next renewal on the read-back's ETag: %v", err)
			}
			if got := e.stored(); got.Counter != 4 {
				t.Fatalf("stored %+v after the next renewal", got)
			}
		})
	}
}

// A store that answers 503 for ever: every renewal fails without a loss and
// sends the same bytes again; the lease holds to the end of the last confirmed
// renewal and not a moment longer; at that end it is lost, and nothing more is
// sent.
//
// spec: SPO-Xobjstore-IF-104, SPO-Xobjstore-OUT-304
func TestA503OutageEndsTheLeaseAtItsEnd(t *testing.T) {
	e := newInitEnv(t, false)
	a, pl, aid := e.logged(nil)
	acquire(t, a)
	end, _ := a.Until()
	pfrom := pl.count()
	e.srv.Inject(slowDown(""))
	term := DefaultTimes().Term()
	for range 3 {
		e.clock.Advance(term / 4)
		wantPending(t, a, a.Renew(ctxT(t, 5*time.Second)), "a renewal in a 503 outage")
	}
	oneWrite(t, pl.from(pfrom), 3)
	e.clock.Advance(end.Sub(e.clock.Now()) - time.Millisecond)
	if until, ok := a.Until(); !ok || !until.Equal(end) || isClosed(a.Lost()) {
		t.Fatalf("a millisecond before the end: until %v held %v; want held to %v", until, ok, end)
	}
	e.clock.Advance(time.Millisecond)
	if held(a) || !isClosed(a.Lost()) {
		t.Fatal("the lease is held at its end")
	}
	n := len(e.requests(aid))
	wantLost(t, a, a.Renew(t.Context()), "a renewal at the end")
	if err := a.Release(t.Context()); err != nil {
		t.Fatalf("Release after the end: %v", err)
	}
	if len(e.requests(aid)) != n {
		t.Fatal("a request was sent after the end")
	}
}

// Another holder takes the lease while a renewal is pending: the next copy is
// refused (412), or fails again, and the read-back shows the other record: a
// loss at once. Every copy of the pending renewal was the same bytes on the
// ETag of the holder's last confirmed record, none was applied, the other
// record stays, and the lost holder sends nothing more.
//
// spec: SPO-Xobjstore-IF-104, SPO-Xobjstore-INV-102, SPO-Xobjstore-PRE-101
func TestATakeOverDuringAPendingRenewalIsALoss(t *testing.T) {
	for _, putsFail := range []bool{false, true} {
		t.Run(map[bool]string{false: "the store answers again", true: "the puts still fail"}[putsFail], func(t *testing.T) {
			e := newInitEnv(t, false)
			a, pl, aid := e.logged(nil)
			acquire(t, a)
			from, pfrom := len(e.requests(aid)), pl.count()
			e.srv.Inject(slowDown(""))
			e.clock.Advance(time.Second)
			wantPending(t, a, a.Renew(ctxT(t, 5*time.Second)), "a renewal in a 503 outage")
			other, err := Encode(Record{Node: nodeKey, Holder: strings.Repeat("e", 32), Generation: 9, Counter: 9, Duration: 30 * time.Second, Margin: 10 * time.Second, State: StateHeld})
			if err != nil {
				t.Fatal(err)
			}
			e.srv.AdminPutVersion(workBucket, leaseKey, other)
			e.srv.ClearFaults()
			if putsFail {
				e.srv.Inject(slowDown(s3stand.OpPut))
			}
			e.clock.Advance(time.Second)
			wantLost(t, a, a.Renew(ctxT(t, 5*time.Second)), "a pending renewal after a take-over")
			if b, _ := e.srv.Current(workBucket, leaseKey); string(b) != string(other) {
				t.Fatal("the other holder's record was replaced")
			}
			oneWrite(t, pl.from(pfrom), 2)
			for _, p := range e.leasePuts(aid, from) {
				if p.Status == http.StatusOK {
					t.Fatalf("a copy was applied: %+v", p)
				}
			}
			n := len(e.requests(aid))
			_ = a.Renew(t.Context())
			_ = a.Release(t.Context())
			if len(e.requests(aid)) != n {
				t.Fatal("the lost holder sent requests")
			}
		})
	}
}

// A take answered 503 (its outcome unknown, the read-back showing the released
// record it was conditional on) does not end Acquire: the waiter holds
// nothing, goes on reading, and sends the same take again (the same bytes, the
// same If-Match) while the object is unchanged; when the store answers, the
// take lands and the lease is held.
//
// spec: SPO-Xobjstore-IF-103, SPO-Xobjstore-PRE-101
func TestATakeKeepsTryingThrough503(t *testing.T) {
	e := newInitEnv(t, false)
	e.srv.Inject(slowDown(s3stand.OpPut))
	a, pl, _ := e.logged(nil)
	done := background(ctxT(t, 10*time.Second), a)
	waitFor(t, "two takes", func() bool { return pl.count() >= 2 })
	if !quiet(done) || held(a) {
		t.Fatal("a take answered 503 ended Acquire or held")
	}
	e.srv.ClearFaults()
	arrives(t, done, "the take after the 503s")
	if got := e.stored(); got.Holder != a.holder || got.Generation != 2 || got.Counter != 2 {
		t.Fatalf("stored %+v", got)
	}
	oneWrite(t, pl.from(0), 3)
}

// A take that landed although its answer was a 503, with a read-back that
// cannot tell: the next read shows the waiter's own bytes, and the take is
// confirmed from its sending.
//
// spec: SPO-Xobjstore-IF-103, SPO-Xobjstore-PRE-101
func TestATakeThatLandedUnderA503IsHeld(t *testing.T) {
	e := newInitEnv(t, false)
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultCommitThenStatus, Op: s3stand.OpPut, Key: leaseKey, Status: 503, Code: "ServiceUnavailable", Count: 1})
	a, pl, _ := e.logged(nil)
	pl.arm, pl.blind = 1, 2 // the read-back and the next read cannot tell
	sent := e.clock.Now()
	acquire(t, a)
	if until, ok := a.Until(); !ok || !until.Equal(sent.Add(DefaultTimes().Term())) {
		t.Fatalf("until %v held %v", until, ok)
	}
	if got := e.stored(); got.Holder != a.holder || got.Counter != 2 {
		t.Fatalf("stored %+v", got)
	}
	if pl.count() != 1 || pl.blindLeft != 0 {
		t.Fatalf("%d takes, %d blind reads left: want one take settled by a later read", pl.count(), pl.blindLeft)
	}
}

// A release whose answer was lost is read back: the released record is there,
// and Release reports it released.
//
// spec: SPO-Xobjstore-IF-105, SPO-Xobjstore-PRE-101
func TestAReleaseWhoseAnswerWasLostIsReadBack(t *testing.T) {
	e := newInitEnv(t, false)
	a, _ := e.lease(nil)
	acquire(t, a)
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultLoseResponse, Op: s3stand.OpPut, Key: leaseKey, Count: 1})
	if err := a.Release(ctxT(t, 5*time.Second)); err != nil {
		t.Fatalf("a release whose answer was lost: %v", err)
	}
	if got := e.stored(); got.State != StateReleased || held(a) {
		t.Fatalf("stored %+v", got)
	}
}

// A release while a renewal is pending is made on the last confirmed ETag; when
// the pending renewal landed first, the release is refused and Release says the
// lease lapses (it is not released, and it was not taken by another holder).
//
// spec: SPO-Xobjstore-IF-105
func TestAReleaseAfterALandedPendingRenewalLapses(t *testing.T) {
	e := newInitEnv(t, false)
	a, aid := e.lease(nil)
	acquire(t, a)
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultCommitThenStatus, Op: s3stand.OpPut, Key: leaseKey, Status: 503, Code: "ServiceUnavailable", Count: 1})
	e.srv.Inject(slowDown(s3stand.OpGet))
	e.clock.Advance(time.Second)
	wantPending(t, a, a.Renew(ctxT(t, 5*time.Second)), "a renewal that landed, with a read-back that cannot tell")
	e.srv.ClearFaults()
	from := len(e.requests(aid))
	if err := a.Release(ctxT(t, 5*time.Second)); err == nil || !isClosed(a.Lost()) || held(a) {
		t.Fatalf("a release refused after a pending renewal landed: %v", err)
	}
	if got := e.stored(); got.State != StateHeld || got.Holder != a.holder || got.Counter != 3 {
		t.Fatalf("stored %+v", got)
	}
	if puts := e.leasePuts(aid, from); len(puts) != 1 || puts[0].Status != http.StatusPreconditionFailed {
		t.Fatalf("the release sent %+v", puts)
	}
}
