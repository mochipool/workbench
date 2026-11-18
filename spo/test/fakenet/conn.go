package fakenet

import (
	"io"
	"os"
	"sync"
	"time"
)

// pipe is one direction of a stream: a bounded ring buffer with the faults of
// its writer's side. The writer blocks while the ring is full and the reader
// while it is empty; both end at their deadline or when a side closes.
type pipe struct {
	mu   sync.Mutex
	wake chan struct{} // closed and replaced on every change: a broadcast

	ring []byte // allocated at the first write, size bytes
	size int
	r, n int   // read index and bytes held
	in   int64 // bytes accepted so far
	out  int64 // bytes read so far

	cutAt, stallAt int64 // -1: none
	oneByte        bool

	cut     bool // the connection was dropped
	wClosed bool // the writer closed: the reader sees EOF after the data
	rClosed bool // the reader closed: writes fail
	rdl     time.Time
	wdl     time.Time
	peer    *pipe // the other direction, cut together with this one
}

func newPipe(size int) *pipe {
	return &pipe{size: size, wake: make(chan struct{}), cutAt: -1, stallAt: -1}
}

// broadcast wakes every goroutine waiting on the pipe. mu is held.
func (p *pipe) broadcast() {
	close(p.wake)
	p.wake = make(chan struct{})
}

func expired(dl time.Time) bool { return !dl.IsZero() && !time.Now().Before(dl) }

// wait releases mu until something changes or dl passes, and takes it again.
// It reports false when dl has passed.
func (p *pipe) wait(dl time.Time) bool {
	ch := p.wake
	var tc <-chan time.Time
	if !dl.IsZero() {
		d := time.Until(dl)
		if d <= 0 {
			return false
		}
		tm := time.NewTimer(d)
		defer tm.Stop()
		tc = tm.C
	}
	p.mu.Unlock()
	select {
	case <-ch:
	case <-tc:
	}
	p.mu.Lock()
	return true
}

// markCut records the drop on this direction.
func (p *pipe) markCut() {
	p.mu.Lock()
	if !p.cut {
		p.cut = true
		p.broadcast()
	}
	p.mu.Unlock()
}

func (p *pipe) write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(b) == 0 {
		return 0, nil
	}
	written := 0
	for {
		if written == len(b) && written > 0 {
			return written, nil
		}
		switch {
		case p.cut:
			return written, ErrCut
		case p.wClosed || p.rClosed:
			return written, ErrClosed
		case expired(p.wdl):
			return written, os.ErrDeadlineExceeded
		}
		free := p.size - p.n
		if free == 0 {
			if !p.wait(p.wdl) {
				return written, os.ErrDeadlineExceeded
			}
			continue
		}
		k := min(len(b)-written, free)
		if p.cutAt >= 0 {
			k = min(k, int(p.cutAt-p.in))
		}
		if p.ring == nil {
			p.ring = make([]byte, p.size)
		}
		w := (p.r + p.n) % p.size
		c := copy(p.ring[w:], b[written:written+k])
		copy(p.ring, b[written+c:written+k])
		p.n += k
		p.in += int64(k)
		written += k
		p.broadcast()
		if p.cutAt >= 0 && p.in >= p.cutAt { // the drop: both directions, at this byte
			p.cut = true
			peer := p.peer
			p.mu.Unlock()
			peer.markCut()
			p.mu.Lock()
		}
	}
}

func (p *pipe) read(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for {
		switch {
		case p.rClosed:
			return 0, ErrClosed
		case expired(p.rdl):
			return 0, os.ErrDeadlineExceeded
		case len(b) == 0:
			return 0, nil
		}
		stalled := p.stallAt >= 0 && p.out >= p.stallAt
		avail := p.n
		if p.stallAt >= 0 {
			avail = min(avail, int(max(p.stallAt-p.out, 0)))
		}
		if avail > 0 {
			k := min(len(b), avail)
			if p.oneByte {
				k = 1
			}
			c := copy(b[:k], p.ring[p.r:min(p.r+p.n, p.size)])
			if c < k {
				copy(b[c:k], p.ring[:k-c])
			}
			p.r = (p.r + k) % p.size
			p.n -= k
			p.out += int64(k)
			p.broadcast()
			return k, nil
		}
		switch {
		case p.cut:
			return 0, ErrCut
		case stalled:
			// a black hole: only the deadline or our own Close ends it
		case p.wClosed:
			return 0, io.EOF
		}
		if !p.wait(p.rdl) {
			return 0, os.ErrDeadlineExceeded
		}
	}
}

func (p *pipe) closeWriter() {
	p.mu.Lock()
	if !p.wClosed {
		p.wClosed = true
		p.broadcast()
	}
	p.mu.Unlock()
}

func (p *pipe) closeReader() {
	p.mu.Lock()
	if !p.rClosed {
		p.rClosed = true
		p.broadcast()
	}
	p.mu.Unlock()
}

func (p *pipe) setReadDeadline(t time.Time) {
	p.mu.Lock()
	p.rdl = t
	p.broadcast()
	p.mu.Unlock()
}

func (p *pipe) setWriteDeadline(t time.Time) {
	p.mu.Lock()
	p.wdl = t
	p.broadcast()
	p.mu.Unlock()
}

// Conn is one end of a stream.
type Conn struct{ rd, wr *pipe }

func newPair(size int, f Fault) (client, server *Conn) {
	c2s, s2c := newPipe(size), newPipe(size)
	c2s.peer, s2c.peer = s2c, c2s
	if f.CutClientToServer != nil {
		c2s.cutAt = *f.CutClientToServer
	}
	if f.CutServerToClient != nil {
		s2c.cutAt = *f.CutServerToClient
	}
	if f.StallClientToServer != nil {
		c2s.stallAt = *f.StallClientToServer
	}
	if f.StallServerToClient != nil {
		s2c.stallAt = *f.StallServerToClient
	}
	c2s.oneByte, s2c.oneByte = f.OneByte, f.OneByte
	if c2s.cutAt == 0 || s2c.cutAt == 0 { // cut before the first byte
		c2s.cut, s2c.cut = true, true
	}
	return &Conn{rd: s2c, wr: c2s}, &Conn{rd: c2s, wr: s2c}
}

// Read implements relayport.Stream.
func (c *Conn) Read(b []byte) (int, error) { return c.rd.read(b) }

// Write implements relayport.Stream.
func (c *Conn) Write(b []byte) (int, error) { return c.wr.write(b) }

// Close ends both directions at this end. It is safe to call twice.
func (c *Conn) Close() error { c.wr.closeWriter(); c.rd.closeReader(); return nil }

// SetDeadline sets both deadlines.
func (c *Conn) SetDeadline(t time.Time) error {
	c.rd.setReadDeadline(t)
	c.wr.setWriteDeadline(t)
	return nil
}

// SetReadDeadline sets the read deadline; the zero time clears it.
func (c *Conn) SetReadDeadline(t time.Time) error { c.rd.setReadDeadline(t); return nil }

// SetWriteDeadline sets the write deadline; the zero time clears it.
func (c *Conn) SetWriteDeadline(t time.Time) error { c.wr.setWriteDeadline(t); return nil }
