package partyrig

import (
	"context"
	"sync"

	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Pipe is an in-memory one-way transport that reports itself as Kind. It
// carries bytes and looks at nothing, like a transport. It is a sender and a
// receiver.
type Pipe struct {
	Kind ports.TransportKind
	mu   sync.Mutex
	q    [][]byte
	// Down makes Send fail with ports.ErrNoRoute: the peer is not connected.
	Down bool
	// Sent counts what was handed over.
	Sent int
	cond chan struct{}
}

// NewPipe makes a pipe of the kind.
func NewPipe(kind ports.TransportKind) *Pipe {
	return &Pipe{Kind: kind, cond: make(chan struct{}, 1024)}
}

// Send implements ports.EnvelopeSender.
func (p *Pipe) Send(_ context.Context, _ party.Fingerprint, env []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.Down {
		return ports.ErrNoRoute
	}
	p.q = append(p.q, append([]byte(nil), env...))
	p.Sent++
	p.cond <- struct{}{}
	return nil
}

// Receive implements ports.EnvelopeReceiver.
func (p *Pipe) Receive(ctx context.Context) ([]byte, ports.TransportKind, error) {
	select {
	case <-p.cond:
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	b := p.q[0]
	p.q = p.q[1:]
	return b, p.Kind, nil
}

// Take removes and returns everything queued.
func (p *Pipe) Take() [][]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.q
	p.q = nil
	for range out {
		<-p.cond
	}
	return out
}

// Put adds an envelope as if it had been sent.
func (p *Pipe) Put(env []byte) { _ = p.Send(context.Background(), party.Fingerprint{}, env) }

// Transport is the pipe as the sending side of multisig.
func (p *Pipe) Transport() multisig.Transport { return ports.NewTransport(p, p.Kind) }
