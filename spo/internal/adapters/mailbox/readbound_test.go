package mailbox_test

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// A client whose read bound is tighter than the relay's egress bound works
// against an honest relay: a page that would pass the bound is cut at the last
// whole envelope that fits, the connection is replaced, and the next fetch
// resumes after it. Every envelope arrives; the dials stay few.
//
// spec: SPO-Xmailbox-OUT-045, SPO-Xmailbox-SEC-027
func TestATighterReadBoundWorksAgainstAnHonestRelay(t *testing.T) {
	w := newWorld(t)
	ca := w.client(w.a)
	cd := &worldCountDialer{inner: w.net.Dialer(w.b.node, w.relay)}
	cb := w.clientVia(w.b, cd, func(cfg *mailbox.Config) { cfg.Limits.MaxBytesRead = 4000 })
	want := map[string]bool{}
	for i := range 6 {
		e := newEnv(1000, byte(i+1))
		want[string(e)] = true
		if err := ca.Send(context.Background(), w.b.fp, e); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 6 {
		got := recv(t, cb)
		if !want[string(got)] {
			t.Fatalf("Receive %d: an envelope nobody sent", i)
		}
		delete(want, string(got))
	}
	if cd.n.Load() > 4 {
		t.Fatalf("%d dials for six envelopes of a thousand bytes with a bound of 4000", cd.n.Load())
	}
	if cd.most.Load() > 4000 {
		t.Fatalf("the client read %d bytes from one connection, the bound is 4000", cd.most.Load())
	}
}

// A page whose first envelope does not fit in what is left of the connection's
// read bound, though it would on a new connection, is not a failure: the
// connection is replaced and the same fetch is asked again, counted by the dial
// limit; the first page on the old connection is already delivered.
//
// spec: SPO-Xmailbox-OUT-045
func TestAPageThatDoesNotFitTheRestOfTheBoundIsAskedAgainOnANewConnection(t *testing.T) {
	e1, e2 := newEnv(2000, 1), newEnv(5000, 2)
	h := newHostile(t, fetchScript(hs{}, func(s *sconn, req wire.Fetch) bool {
		if req.After == nil {
			goodPage(s, req, page{envs: [][]byte{e1}, more: true})
		} else {
			goodPage(s, req, page{envs: [][]byte{e2}})
		}
		return true
	}))
	cd, d := counting(h)
	c := h.clientVia(d, func(cfg *mailbox.Config) { cfg.Limits.MaxBytesRead = 7000 })
	for i, want := range [][]byte{e1, e2} {
		got, err := receiveErr(t, c, 3*time.Second)
		if err != nil || !bytes.Equal(got.Envelope, want) {
			t.Fatalf("Receive %d: %v", i, err)
		}
	}
	if cd.count() != 2 {
		t.Fatalf("%d dials, want 2: one replacement", cd.count())
	}
	if n := len(h.ev.of(mailbox.EventFailed)); n != 0 {
		t.Fatalf("%d failure events for a rotation", n)
	}
}

type worldCountDialer struct {
	inner relayport.StreamDialer
	n     atomic.Int64
	most  atomic.Int64 // the most bytes the client read from one connection
}

func (d *worldCountDialer) Dial(ctx context.Context) (relayport.Stream, party.NodeKey, error) {
	d.n.Add(1)
	st, key, err := d.inner.Dial(ctx)
	if err != nil {
		return st, key, err
	}
	return &readCounting{Stream: st, d: d}, key, nil
}

// readCounting counts what the client reads from one stream: the read bound is
// about these bytes.
type readCounting struct {
	relayport.Stream
	d *worldCountDialer
	n atomic.Int64
}

func (r *readCounting) Read(p []byte) (int, error) {
	n, err := r.Stream.Read(p)
	if total := r.n.Add(int64(n)); total > r.d.most.Load() {
		r.d.most.Store(total)
	}
	return n, err
}
