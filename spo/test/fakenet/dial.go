package fakenet

import (
	"context"
	"sync"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// Fault is what goes wrong with one stream. The zero Fault is a healthy
// stream. Byte counts are of bytes a writer has handed the stream, per
// direction, so a fault happens at the same byte in every run.
type Fault struct {
	// Refuse makes Dial fail with ErrRefused.
	Refuse bool
	// CutClientToServer and CutServerToClient drop the connection once that
	// many bytes have been accepted in that direction: the bytes before the cut
	// are delivered, then both ends fail with ErrCut.
	CutClientToServer, CutServerToClient *int64
	// StallClientToServer and StallServerToClient stop delivery after that many
	// bytes: the reader blocks until its deadline or its own Close.
	StallClientToServer, StallServerToClient *int64
	// OneByte makes every Read return at most one byte.
	OneByte bool
	// ShowListenerAs is the node key the dialer is told the listener has;
	// ShowDialerAs is the key the listener is told the dialer has. They model a
	// tunnel that reports a key other than the real one.
	ShowListenerAs, ShowDialerAs *party.NodeKey
}

// Int64 is a helper for the pointer fields of Fault.
func Int64(n int64) *int64 { return &n }

// Dialer dials one listener node from one node.
type Dialer struct {
	net      *Net
	from, to *Node
	mu       sync.Mutex
	plan     []Fault
	always   Fault
}

// Dialer makes a dialer from one node to the listener on another.
func (n *Net) Dialer(from, to *Node) *Dialer { return &Dialer{net: n, from: from, to: to} }

// Plan queues faults for the next dials, one per dial in order. A dial with an
// empty queue gets the Always fault.
func (d *Dialer) Plan(f ...Fault) {
	d.mu.Lock()
	d.plan = append(d.plan, f...)
	d.mu.Unlock()
}

// Always sets the fault of every dial the Plan does not cover.
func (d *Dialer) Always(f Fault) {
	d.mu.Lock()
	d.always = f
	d.mu.Unlock()
}

func (d *Dialer) next() Fault {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.plan) > 0 {
		f := d.plan[0]
		d.plan = d.plan[1:]
		return f
	}
	return d.always
}

// Dial implements relayport.StreamDialer. The key it returns is the listener's, as
// the fake tunnel reports it.
func (d *Dialer) Dial(ctx context.Context) (relayport.Stream, party.NodeKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, party.NodeKey{}, err
	}
	f := d.next()
	if f.Refuse {
		return nil, party.NodeKey{}, ErrRefused
	}
	d.net.mu.Lock()
	l := d.net.listeners[d.to.Name]
	size := d.net.buffer
	d.net.mu.Unlock()
	if l == nil {
		return nil, party.NodeKey{}, ErrNoListener
	}
	l.mu.Lock()
	closed, allowed := l.closed, l.allowed[d.from.Key]
	l.mu.Unlock()
	switch {
	case closed:
		return nil, party.NodeKey{}, ErrNoListener
	case !allowed:
		return nil, party.NodeKey{}, ErrNotAllowed
	}
	client, server := newPair(size, f)
	seenByListener, seenByDialer := d.from.Key, d.to.Key
	if f.ShowDialerAs != nil {
		seenByListener = *f.ShowDialerAs
	}
	if f.ShowListenerAs != nil {
		seenByDialer = *f.ShowListenerAs
	}
	select {
	case l.backlog <- &pending{conn: server, key: seenByListener}:
	case <-ctx.Done():
		client.Close()
		server.Close()
		return nil, party.NodeKey{}, ctx.Err()
	case <-l.done:
		client.Close()
		server.Close()
		return nil, party.NodeKey{}, ErrNoListener
	}
	if l.isClosed() { // closed while the dial was being queued
		l.drain()
	}
	return client, seenByDialer, nil
}
