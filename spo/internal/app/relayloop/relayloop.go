// Package relayloop is the shared state of one exchange over the relays (spo
// party serve and connect with --transport mailbox): the operator output, the
// binding in use, and the pacing of junk. The exchange loop and the composite's
// member goroutines (its event callback) both use it, so everything here is
// guarded by one lock. It is a package of its own, outside the command tree,
// so that it runs under the race detector, which the command tree's tests do
// not (ADR 0014 work package 10, review finding L2).
package relayloop

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// remedies remembers, per binding statement, that the remedy of a refused
// identity was told in this process (SPO-Xmailbox-OUT-108).
var remedies sync.Map

// TellRemedyOnce tells the remedy of a refused identity once per binding
// statement per process, through say, and reports whether it told it now. An
// error that is not a refused identity is not told.
//
// spec: SPO-Xmailbox-OUT-108
func TellRemedyOnce(say func(format string, args ...any), statement []byte, err error, remedy func(error) error) bool {
	if !errors.Is(err, ports.ErrIdentityRefused) {
		return false
	}
	if _, loaded := remedies.LoadOrStore(sha256.Sum256(statement), true); loaded {
		return false
	}
	say("relay: %v\n", remedy(err))
	return true
}

// Teller is the error output of one exchange and the binding it uses.
type Teller struct {
	mu        sync.Mutex
	w         io.Writer
	statement []byte
	remedy    func(error) error
	told      map[string]string // a failure's kind -> the text told last
}

// New makes the teller of an exchange that writes to w, uses the binding
// statement and adds remedy to a refused identity.
func New(w io.Writer, statement []byte, remedy func(error) error) *Teller {
	return &Teller{w: w, statement: append([]byte(nil), statement...), remedy: remedy, told: map[string]string{}}
}

// Printf writes one message; the writes of every goroutine are serialised.
//
// spec: SPO-Xmailbox-OUT-108
func (t *Teller) Printf(format string, args ...any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	fmt.Fprintf(t.w, format, args...)
}

// SetStatement records the binding in use after a renewal.
func (t *Teller) SetStatement(statement []byte) {
	t.mu.Lock()
	t.statement = append([]byte(nil), statement...)
	t.mu.Unlock()
}

// Statement is the binding in use.
func (t *Teller) Statement() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]byte(nil), t.statement...)
}

// Remedy tells the remedy of a refused identity once per binding statement in
// this process (TellRemedyOnce with the binding in use).
//
// spec: SPO-Xmailbox-OUT-108
func (t *Teller) Remedy(err error) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return TellRemedyOnce(func(f string, a ...any) { fmt.Fprintf(t.w, f, a...) }, t.statement, err, t.remedy)
}

// Failure tells a failure of one kind ("receiving", "sending") when it is new:
// a failure that persists is told once, and again only when its text changes or
// after Clear.
//
// spec: SPO-Xmailbox-OUT-108
func (t *Teller) Failure(kind string, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	text := err.Error()
	if t.told[kind] == text {
		return
	}
	t.told[kind] = text
	fmt.Fprintf(t.w, "%s: %s\n", kind, text)
}

// Clear forgets the failure of a kind after a success, so the next is told.
func (t *Teller) Clear(kind string) {
	t.mu.Lock()
	delete(t.told, kind)
	t.mu.Unlock()
}

// Pacer bounds the work that envelopes refused before their sender was known
// (junk, which anything on the path can make up) cause in an exchange: Burst
// of them pass at once, and each one beyond waits for a token that comes back
// at one per Every. It is used by one goroutine.
type Pacer struct {
	Burst int
	Every time.Duration
	Now   func() time.Time

	tokens float64
	last   time.Time
	primed bool
}

// Defaults of a Pacer.
const (
	DefaultJunkBurst = 64
	DefaultJunkEvery = time.Second
)

// Junk notes one envelope refused before its sender was known and returns how
// long the loop waits before it fetches the next (zero while tokens are left).
//
// spec: SPO-Xmailbox-OUT-112
func (p *Pacer) Junk() time.Duration {
	if p.Burst <= 0 {
		p.Burst = DefaultJunkBurst
	}
	if p.Every <= 0 {
		p.Every = DefaultJunkEvery
	}
	if p.Now == nil {
		p.Now = time.Now
	}
	now := p.Now()
	if !p.primed {
		p.tokens, p.last, p.primed = float64(p.Burst), now, true
	}
	p.tokens = min(float64(p.Burst), p.tokens+float64(now.Sub(p.last))/float64(p.Every))
	p.last = now
	p.tokens--
	if p.tokens >= 0 {
		return 0
	}
	return time.Duration(-p.tokens * float64(p.Every))
}
