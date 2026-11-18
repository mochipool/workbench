// Package fakenet is an in-process fake tunnel for the relay's stream ports
// (ADR 0013, work package 2). It has named nodes with node keys, a listener
// per node with an allow-list, dial and accept, and deterministic fault
// injection. There are no sockets and no goroutines of its own: a blocked
// operation waits in the goroutine of its caller, and ends at its deadline or
// when the stream or the listener closes. Buffers are bounded.
//
// It is a test support package: nothing outside tests imports it.
package fakenet

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// Errors.
var (
	ErrRefused        = errors.New("fakenet: connection refused")
	ErrNotAllowed     = errors.New("fakenet: the dialer's node key is not in the listener's allow-list")
	ErrNoListener     = errors.New("fakenet: no listener on that node")
	ErrListenerClosed = fmt.Errorf("fakenet: listener closed: %w", relayport.ErrListenerClosed)
	// ErrTemporary is a retryable accept failure (relayport.ErrAcceptRetry): what
	// FailAccept injects.
	ErrTemporary = fmt.Errorf("fakenet: accept failed: %w", relayport.ErrAcceptRetry)
	ErrCut       = errors.New("fakenet: connection cut")
	ErrClosed    = errors.New("fakenet: stream closed")
)

const (
	// DefaultBuffer is the bytes one direction of a stream holds.
	DefaultBuffer = 64 << 10
	// Backlog is how many dials a listener holds before Dial waits.
	Backlog = 8
)

// Node is a named machine with a node key.
type Node struct {
	Name string
	Key  party.NodeKey
}

// Net is one fake tunnel.
type Net struct {
	mu        sync.Mutex
	nodes     map[string]*Node
	listeners map[string]*Listener
	buffer    int
}

// New makes an empty network.
func New() *Net {
	return &Net{nodes: map[string]*Node{}, listeners: map[string]*Listener{}, buffer: DefaultBuffer}
}

// SetBuffer sets the bytes each direction of later streams holds (at least 1).
func (n *Net) SetBuffer(size int) {
	n.mu.Lock()
	n.buffer = max(size, 1)
	n.mu.Unlock()
}

// Node returns the node of that name, making it on first use. Its key is
// derived from the name, so it is the same in every run.
func (n *Net) Node(name string) *Node {
	n.mu.Lock()
	defer n.mu.Unlock()
	if nd, ok := n.nodes[name]; ok {
		return nd
	}
	nd := &Node{Name: name, Key: party.NodeKey(sha256.Sum256([]byte("fakenet node " + name)))}
	n.nodes[name] = nd
	return nd
}

var (
	_ relayport.StreamListener = (*Listener)(nil)
	_ relayport.StreamDialer   = (*Dialer)(nil)
	_ relayport.Stream         = (*Conn)(nil)
)

// Listener is the accepting end on one node.
type Listener struct {
	net     *Net
	node    *Node
	mu      sync.Mutex
	allowed map[party.NodeKey]bool
	backlog chan *pending
	done    chan struct{}
	closed  bool
	// failures are returned, one for each call, by the next Accepts (FailAccept).
	failures []error
	kick     chan struct{}
}

// FailAccept makes the next len(errs) calls of Accept return those errors, in
// order, before anything is accepted: a listener that fails transiently
// (ErrTemporary) or for good (any other error). The queue is bounded by what a
// test puts in it.
func (l *Listener) FailAccept(errs ...error) {
	l.mu.Lock()
	l.failures = append(l.failures, errs...)
	l.mu.Unlock()
	select { // wake an Accept that is already waiting
	case l.kick <- struct{}{}:
	default:
	}
}

func (l *Listener) nextFailure() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.failures) == 0 {
		return nil
	}
	err := l.failures[0]
	l.failures = l.failures[1:]
	return err
}

type pending struct {
	conn *Conn
	key  party.NodeKey // what the listener is told about the dialer
}

// Listen starts a listener on node. Only the node keys in allowed may dial it;
// an empty list admits nobody (concern T2: the allow-list fails closed).
func (n *Net) Listen(on *Node, allowed []party.NodeKey) (*Listener, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if old, ok := n.listeners[on.Name]; ok && !old.isClosed() {
		return nil, errors.New("fakenet: the node already has a listener")
	}
	l := &Listener{net: n, node: on, backlog: make(chan *pending, Backlog), done: make(chan struct{}), kick: make(chan struct{}, 1)}
	l.setAllowedLocked(allowed)
	n.listeners[on.Name] = l
	return l, nil
}

func (l *Listener) setAllowedLocked(keys []party.NodeKey) {
	l.allowed = make(map[party.NodeKey]bool, len(keys))
	for _, k := range keys {
		l.allowed[k] = true
	}
}

// SetAllowed replaces the allow-list for later dials. Streams already open stay.
func (l *Listener) SetAllowed(keys []party.NodeKey) {
	l.mu.Lock()
	l.setAllowedLocked(keys)
	l.mu.Unlock()
}

func (l *Listener) isClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed
}

// Accept implements relayport.StreamListener.
func (l *Listener) Accept(ctx context.Context) (relayport.Stream, party.NodeKey, error) {
	if l.isClosed() {
		return nil, party.NodeKey{}, ErrListenerClosed
	}
	for {
		if err := l.nextFailure(); err != nil {
			return nil, party.NodeKey{}, err
		}
		select {
		case p := <-l.backlog:
			return p.conn, p.key, nil
		case <-ctx.Done():
			return nil, party.NodeKey{}, ctx.Err()
		case <-l.done:
			return nil, party.NodeKey{}, ErrListenerClosed
		case <-l.kick: // FailAccept: look at the queue again
		}
	}
}

// Close stops the listener and closes the streams still waiting to be accepted.
func (l *Listener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	close(l.done)
	l.mu.Unlock()
	l.drain()
	return nil
}

// drain closes the streams waiting to be accepted.
func (l *Listener) drain() {
	for {
		select {
		case p := <-l.backlog:
			p.conn.Close()
		default:
			return
		}
	}
}
