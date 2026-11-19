package mailbox

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// Several relays (ADR 0013, "Owner decisions"; ADR 0014 work package 10). A
// device is configured with a list of independent relays: it sends to all of
// them and fetches from all of them. Multi is that composite over one Client per
// relay. It is a ports.EnvelopeSender, EnvelopeReceiver and EnvelopeContextAcker
// with a network transport, so the application cannot tell several relays from
// one, or a relay from a direct path.
//
//   - Send puts to every relay at once; delivered means stored by at least one.
//     After the first stored, the others have SendGrace to answer.
//   - Receive fetches from every relay at once, one goroutine per relay, so a
//     relay that is down, stalls or floods holds the others back in nothing. An
//     envelope is identified by its hash, and the composite counts, per hash,
//     the puts it delivered and the copies each relay had acknowledged: a copy
//     from a relay that has had fewer copies of that hash acknowledged than were
//     delivered is the second copy of a put already delivered (served by another
//     relay) and is acknowledged there and not delivered; any other is a new put
//     (the outbox's re-put of the same bytes) and is delivered
//     (SPO-Xmailbox-OUT-110). The copies of the delivered one go with its
//     acknowledgement.
//   - A relay whose receive fails is paused alone, with a backoff of its own.
//
// Logout of a device over several relays is Logout (Close, then each member's
// dialer with CloseWithin), then the destruction of the local identity.

// MaxRelays is the most relays a device uses at once.
const MaxRelays = 8

// Defaults of MultiConfig.
const (
	DefaultSendGrace   = 3 * time.Second
	DefaultAckedMemory = 4096
	DefaultAckedWindow = 10 * time.Minute
	defaultMultiBackMn = time.Second
	defaultMultiBackMx = 2 * time.Minute
)

// ErrTunnelDidNotStop is what Logout returns when a member's tunnel dialer did
// not stop within the bound: the engine that holds the node key may still be up
// and registered, so a logout must say "tunnel did not stop", never "logged out".
var ErrTunnelDidNotStop = errors.New("mailbox: tunnel did not stop")

// ClosableDialer is a member's tunnel dialer as logout needs it.
type ClosableDialer interface {
	relayport.StreamDialer
	CloseWithin(d time.Duration) error
}

// Member is one relay of a Multi: its name (the device's own name for it), its
// client, and the dialer the client dials with (for Logout; optional).
type Member struct {
	Name   string
	Client *Client
	Dialer ClosableDialer
}

// MultiEventKind names what a MultiEvent reports.
type MultiEventKind string

// The kinds.
const (
	MultiSend    MultiEventKind = "send"
	MultiReceive MultiEventKind = "receive"
	MultiAck     MultiEventKind = "ack"
	MultiRevokes MultiEventKind = "revokes"
)

// MultiOutcome is the outcome of one member in a MultiEvent.
type MultiOutcome string

// The outcomes.
const (
	OutcomeStored    MultiOutcome = "stored"
	OutcomeNoRoute   MultiOutcome = "no_route"
	OutcomeRefused   MultiOutcome = "refused"
	OutcomeIdentity  MultiOutcome = "identity_refused"
	OutcomeAbandoned MultiOutcome = "abandoned"
	OutcomeClosed    MultiOutcome = "closed"
	OutcomeContext   MultiOutcome = "context"
	OutcomeFailed    MultiOutcome = "failed"
	OutcomeDuplicate MultiOutcome = "duplicate"
	OutcomeAcked     MultiOutcome = "acked"
)

// MultiEvent is one member's outcome. It carries the member's name, the class
// of the outcome and, for a receive, the envelope's hash and the pause: no text
// a relay chose (Err is the member client's own error, for the caller's remedy
// logic, and is not printed by this package).
type MultiEvent struct {
	Relay   string
	Kind    MultiEventKind
	Outcome MultiOutcome
	Mid     wire.Hash
	Backoff time.Duration
	Err     error
}

// MultiConfig configures a Multi.
type MultiConfig struct {
	Members []Member
	// SendGrace is how long the other members have after the first stored a
	// send; zero is DefaultSendGrace.
	SendGrace time.Duration
	// AckedMemory and AckedWindow bound the memory of acknowledged hashes: the
	// last AckedMemory hashes, each for AckedWindow after its last
	// acknowledgement (zero: 4096 and 10 minutes). Only a second copy of a put
	// already delivered is held back, never a new put, so the window delays
	// nothing; past it a late copy is delivered once more, which the application
	// tolerates (SPO-Xparty-INV-017).
	AckedMemory int
	AckedWindow time.Duration
	// BackoffMin and BackoffMax bound the pause of a member whose receive failed
	// (zero: 1 s and 2 min).
	BackoffMin, BackoffMax time.Duration
	// Events receives each member's outcomes; nil drops them. It is called
	// without a lock of the Multi held and must not call it.
	Events func(MultiEvent)
}

// held is an envelope one member fetched and the composite has not delivered.
type held struct {
	rcv ports.Received
	mid wire.Hash
}

type member struct {
	idx  int
	name string
	c    *Client
	d    ClosableDialer

	// guarded by Multi.mu
	running bool
	held    *held
	err     error // the last failure of a receive, until a success
	fails   int
	paused  time.Time // no new receive before
}

// Multi is the composite of several relays.
type Multi struct {
	cfg     MultiConfig
	members []*member

	// lifeMu makes the closed check and wg.Add one step, and the setting of
	// closed another, so that no goroutine is added once Close waits on wg
	// (SPO-Xmailbox-INV-039).
	lifeMu   sync.Mutex
	closed   atomic.Bool // written under lifeMu
	closedCh chan struct{}
	once     sync.Once
	base     context.Context // ends at Close
	stop     context.CancelFunc
	wg       sync.WaitGroup

	wake chan struct{} // one place: a member's receive ended

	mu       sync.Mutex
	next     int // round robin over members with a held envelope
	cur      *delivery
	acked    map[wire.Hash]*ackRecord
	ackedOrd []wire.Hash
}

// ackRecord is what the composite knows of one hash (SPO-Xmailbox-OUT-110):
// how many puts of it were delivered, and how many copies each member had
// acknowledged (never more than the deliveries).
type ackRecord struct {
	at        time.Time // the last acknowledgement
	delivered uint32
	copies    [MaxRelays]uint32
}

// enter adds one goroutine of the composite unless it is closed.
func (m *Multi) enter() bool {
	m.lifeMu.Lock()
	defer m.lifeMu.Unlock()
	if m.closed.Load() {
		return false
	}
	m.wg.Add(1)
	return true
}

// delivery is the envelope the last Receive returned and the members it came
// from (with its copies).
type delivery struct {
	mid  wire.Hash
	from []*member
}

var (
	_ ports.EnvelopeSender       = (*Multi)(nil)
	_ ports.EnvelopeContextAcker = (*Multi)(nil)
)

func validRelayName(s string) bool {
	if len(s) < 1 || len(s) > 32 {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-' && i > 0:
		default:
			return false
		}
	}
	return true
}

// NewMulti checks the members and makes the composite. It dials nothing.
//
// spec: SPO-Xmailbox-IF-024
func NewMulti(cfg MultiConfig) (*Multi, error) {
	if len(cfg.Members) == 0 || len(cfg.Members) > MaxRelays {
		return nil, fmt.Errorf("mailbox: %d relays; a device uses 1 to %d", len(cfg.Members), MaxRelays)
	}
	names, clients := map[string]bool{}, map[*Client]bool{}
	m := &Multi{cfg: cfg, closedCh: make(chan struct{}), wake: make(chan struct{}, 1), acked: map[wire.Hash]*ackRecord{}}
	for i, mb := range cfg.Members {
		switch {
		case !validRelayName(mb.Name):
			return nil, fmt.Errorf("mailbox: the relay name %q is not 1 to 32 of a-z, 0-9 and '-'", mb.Name)
		case names[mb.Name]:
			return nil, fmt.Errorf("mailbox: the relay name %q is given twice", mb.Name)
		case mb.Client == nil:
			return nil, fmt.Errorf("mailbox: the relay %q has no client", mb.Name)
		case clients[mb.Client]:
			return nil, fmt.Errorf("mailbox: the relay %q has the client of another", mb.Name)
		}
		names[mb.Name], clients[mb.Client] = true, true
		m.members = append(m.members, &member{idx: i, name: mb.Name, c: mb.Client, d: mb.Dialer})
	}
	if m.cfg.SendGrace <= 0 {
		m.cfg.SendGrace = DefaultSendGrace
	}
	if m.cfg.AckedMemory <= 0 {
		m.cfg.AckedMemory = DefaultAckedMemory
	}
	if m.cfg.AckedWindow <= 0 {
		m.cfg.AckedWindow = DefaultAckedWindow
	}
	if m.cfg.BackoffMin <= 0 {
		m.cfg.BackoffMin = defaultMultiBackMn
	}
	if m.cfg.BackoffMax < m.cfg.BackoffMin {
		m.cfg.BackoffMax = max(defaultMultiBackMx, m.cfg.BackoffMin)
	}
	m.base, m.stop = context.WithCancel(context.Background())
	return m, nil
}

// Transport is the composite as the sending side of multisig: a network.
func (m *Multi) Transport() ports.Transport { return ports.NetworkTransport(m) }

func (m *Multi) emit(e MultiEvent) {
	if m.cfg.Events != nil {
		m.cfg.Events(e)
	}
}

func (m *Multi) signal() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// outcomeOf classes a member's send error.
func outcomeOf(err error, abandoned bool) MultiOutcome {
	switch {
	case err == nil:
		return OutcomeStored
	case abandoned:
		return OutcomeAbandoned
	case errors.Is(err, ports.ErrClosed):
		return OutcomeClosed
	case errors.Is(err, ports.ErrIdentityRefused):
		return OutcomeIdentity
	case errors.Is(err, ports.ErrRefusedByTransport):
		return OutcomeRefused
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return OutcomeContext
	case errors.Is(err, ports.ErrNoRoute):
		return OutcomeNoRoute
	}
	return OutcomeFailed
}

// Send puts envelope to every relay (SPO-Xmailbox-OUT-104).
func (m *Multi) Send(ctx context.Context, to party.Fingerprint, envelope []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.closed.Load() {
		return ports.ErrClosed
	}
	if len(envelope) == 0 || len(envelope) > wire.MaxEnvelopeBytes {
		return ports.ErrEnvelopeSize
	}
	env := append([]byte(nil), envelope...) // the members may still write it after a grace
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		mb  *member
		err error
	}
	res := make(chan result, len(m.members))
	for _, mb := range m.members {
		if !m.enter() {
			res <- result{mb, ports.ErrClosed}
			continue
		}
		go func() {
			defer m.wg.Done()
			res <- result{mb, mb.c.Send(sctx, to, env)}
		}()
	}
	var grace <-chan time.Time
	got := map[*member]MultiOutcome{}
	errs := map[*member]error{}
	stored := false
	for len(got) < len(m.members) {
		select {
		case r := <-res:
			o := outcomeOf(r.err, false)
			got[r.mb], errs[r.mb] = o, r.err
			m.emit(MultiEvent{Relay: r.mb.name, Kind: MultiSend, Outcome: o, Err: r.err})
			if r.err == nil && !stored {
				stored = true
				t := time.NewTimer(m.cfg.SendGrace)
				defer t.Stop()
				grace = t.C
			}
		case <-grace:
			// the rest are abandoned: their sends end with the context
			cancel()
			for _, mb := range m.members {
				if _, ok := got[mb]; !ok {
					got[mb] = OutcomeAbandoned
					m.emit(MultiEvent{Relay: mb.name, Kind: MultiSend, Outcome: OutcomeAbandoned})
				}
			}
		}
	}
	if stored {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	count := map[MultiOutcome]int{}
	for _, o := range got {
		count[o]++
	}
	n := len(m.members)
	switch {
	case count[OutcomeClosed] == n:
		return ports.ErrClosed
	case count[OutcomeRefused] == n:
		return fmt.Errorf("%w: every relay refused it", ports.ErrRefusedByTransport)
	case count[OutcomeIdentity] == n:
		for _, mb := range m.members {
			return errs[mb] // the first member's refusal: it says why and what to do
		}
	}
	return fmt.Errorf("%w: no relay stored it (%s)", ports.ErrNoRoute, summary(m.members, got))
}

func summary(ms []*member, got map[*member]MultiOutcome) string {
	s := ""
	for i, mb := range ms {
		if i > 0 {
			s += ", "
		}
		s += mb.name + ": " + string(got[mb])
	}
	return s
}

// Held is how many fetched envelopes wait in the composite (for tests).
func (m *Multi) Held() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, mb := range m.members {
		if mb.held != nil {
			n++
		}
	}
	return n
}

// Remembered is how many hashes the composite remembers (for tests).
func (m *Multi) Remembered() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.acked)
}

// record is what is remembered of mid, or nil when it is not remembered or its
// window has passed. m.mu is held.
func (m *Multi) record(mid wire.Hash, now time.Time) *ackRecord {
	r := m.acked[mid]
	if r == nil || now.Sub(r.at) >= m.cfg.AckedWindow {
		return nil
	}
	return r
}

// isCopy reports whether the envelope mb serves with hash mid is a second copy
// of a put already delivered: mb has had fewer copies of mid acknowledged than
// were delivered (SPO-Xmailbox-OUT-110). m.mu is held.
func (m *Multi) isCopy(mid wire.Hash, mb *member, now time.Time) bool {
	r := m.record(mid, now)
	return r != nil && r.copies[mb.idx] < r.delivered
}

// delivered records one delivery of mid, forgetting the oldest hash beyond the
// bound. m.mu is held.
func (m *Multi) delivered(mid wire.Hash, now time.Time) {
	r := m.acked[mid]
	switch {
	case r == nil:
		r = &ackRecord{}
		m.acked[mid] = r
		m.ackedOrd = append(m.ackedOrd, mid)
		for len(m.ackedOrd) > m.cfg.AckedMemory {
			delete(m.acked, m.ackedOrd[0])
			m.ackedOrd = m.ackedOrd[1:]
		}
	case now.Sub(r.at) >= m.cfg.AckedWindow:
		*r = ackRecord{} // its window passed: counted afresh
	}
	r.at = now
	r.delivered++
}

// copyAcked records that mb acknowledged one copy of mid. A count never passes
// the deliveries: a copy acknowledged while another of the same put was in
// flight is not a put of its own. m.mu is held.
func (m *Multi) copyAcked(mid wire.Hash, mb *member, now time.Time) {
	if r := m.record(mid, now); r != nil && r.copies[mb.idx] < r.delivered {
		r.copies[mb.idx]++
		r.at = now
	}
}

// Receive returns the next envelope from any relay (SPO-Xmailbox-OUT-105).
func (m *Multi) Receive(ctx context.Context) (ports.Received, error) {
	for {
		if err := ctx.Err(); err != nil {
			return ports.Received{}, err
		}
		if m.closed.Load() {
			return ports.Received{}, ports.ErrClosed
		}
		now := time.Now()
		m.mu.Lock()
		m.cur = nil // a Receive without an Ack: nothing was acknowledged
		type dup struct {
			mb  *member
			mid wire.Hash
		}
		var dups []dup
		var out *held
		n := len(m.members)
		for i := 0; i < n && out == nil; i++ {
			mb := m.members[(m.next+i)%n]
			h := mb.held
			if h == nil {
				continue
			}
			mb.held = nil
			if m.isCopy(h.mid, mb, now) {
				dups = append(dups, dup{mb, h.mid})
				mb.running = true // busy with the acknowledgement of the copy
				continue
			}
			out = h
			m.next = (m.next + i + 1) % n
			m.cur = &delivery{mid: h.mid, from: []*member{mb}}
			for _, o := range m.members {
				if o != mb && o.held != nil && o.held.mid == h.mid {
					m.cur.from = append(m.cur.from, o)
					o.held = nil
				}
			}
		}
		for _, d := range dups {
			m.ackCopy(d.mb, d.mid)
		}
		if out != nil {
			m.mu.Unlock()
			return out.rcv, nil
		}
		wait, err := m.startReceives(ctx, now)
		m.mu.Unlock()
		if err != nil {
			// every member failed and is paused: the answer waits out the
			// shortest pause, so a loop over Receive does not spin
			return ports.Received{}, m.failedAfter(ctx, wait, err)
		}
		var timer <-chan time.Time
		if wait > 0 {
			t := time.NewTimer(wait)
			timer = t.C
			defer t.Stop()
		}
		select {
		case <-m.wake:
		case <-timer:
		case <-ctx.Done():
			return ports.Received{}, ctx.Err()
		case <-m.closedCh:
			return ports.Received{}, ports.ErrClosed
		}
	}
}

// failedAfter waits until the shortest pause of the failed members ends, the
// caller's deadline comes, the caller cancels or the composite closes, and
// returns err (the caller's cancel and Close as themselves).
func (m *Multi) failedAfter(ctx context.Context, wait time.Duration, err error) error {
	if wait <= 0 {
		return err
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.Canceled) {
			return ctx.Err()
		}
	case <-m.closedCh:
		return ports.ErrClosed
	}
	return err
}

// ackCopy acknowledges, at the member that served it, the second copy of a put
// already delivered, on a goroutine of its own; the member is busy until it
// ends. m.mu is held.
func (m *Multi) ackCopy(mb *member, mid wire.Hash) {
	if !m.enter() {
		mb.running = false
		return
	}
	go func() {
		defer m.wg.Done()
		ctx, cancel := context.WithTimeout(m.base, 2*time.Second)
		err := mb.c.AckContext(ctx)
		cancel()
		m.mu.Lock()
		mb.running = false
		if err == nil {
			m.copyAcked(mid, mb, time.Now())
		}
		m.mu.Unlock()
		m.emit(MultiEvent{Relay: mb.name, Kind: MultiReceive, Outcome: OutcomeDuplicate, Err: err})
		m.signal()
	}()
}

// startReceives starts a receive on every member that is idle and not paused,
// and returns how long until a paused member may start again (0: none is
// paused). It returns an error when every member has failed and nothing is
// running or held. m.mu is held.
func (m *Multi) startReceives(ctx context.Context, now time.Time) (time.Duration, error) {
	var wait time.Duration
	running := 0
	for _, mb := range m.members {
		switch {
		case mb.running:
			running++
			continue
		case mb.held != nil:
			continue
		case now.Before(mb.paused):
			if d := mb.paused.Sub(now); wait == 0 || d < wait {
				wait = d
			}
			continue
		}
		if !m.receiveOn(ctx, mb) {
			return 0, ports.ErrClosed
		}
		running++
	}
	if running > 0 {
		return wait, nil
	}
	var first, identity error
	for _, mb := range m.members {
		if mb.held != nil || mb.err == nil {
			return wait, nil
		}
		if first == nil {
			first = fmt.Errorf("mailbox: relay %s: %w", mb.name, mb.err)
		}
		if identity == nil && errors.Is(mb.err, ports.ErrIdentityRefused) {
			identity = mb.err
		}
	}
	allIdentity := true
	for _, mb := range m.members {
		if !errors.Is(mb.err, ports.ErrIdentityRefused) {
			allIdentity = false
		}
	}
	if allIdentity {
		return wait, identity
	}
	return wait, first
}

// receiveOn runs one receive of a member until the caller's deadline: a caller
// with a deadline does not cut a long-poll short by returning (the member keeps
// it until then), one without cancels it at its own end. It reports false, and
// starts nothing, when the composite is closed. m.mu is held.
func (m *Multi) receiveOn(ctx context.Context, mb *member) bool {
	if !m.enter() {
		return false
	}
	mb.running = true
	rctx, cancel := context.WithCancel(m.base)
	if dl, ok := ctx.Deadline(); ok {
		var c2 context.CancelFunc
		rctx, c2 = context.WithDeadline(rctx, dl)
		prev := cancel
		cancel = func() { c2(); prev() }
	} else {
		stop := context.AfterFunc(ctx, cancel)
		prev := cancel
		cancel = func() { stop(); prev() }
	}
	go func() {
		defer m.wg.Done()
		defer cancel()
		r, err := mb.c.Receive(rctx)
		ended := rctx.Err() != nil
		m.mu.Lock()
		mb.running = false
		var ev *MultiEvent
		switch {
		case err == nil:
			mb.held = &held{rcv: r, mid: wire.HashOf(r.Envelope)}
			mb.err, mb.fails, mb.paused = nil, 0, time.Time{}
		case ended || m.closed.Load():
			// the caller's deadline or Close: not a failure of the relay
		default:
			mb.err = err
			mb.fails = min(mb.fails+1, 30)
			d := m.cfg.BackoffMin
			for i := 1; i < mb.fails && d < m.cfg.BackoffMax; i++ {
				d *= 2
			}
			d = min(d, m.cfg.BackoffMax)
			mb.paused = time.Now().Add(d)
			ev = &MultiEvent{Relay: mb.name, Kind: MultiReceive, Outcome: outcomeOf(err, false), Backoff: d, Err: err}
			if ev.Outcome == OutcomeNoRoute || ev.Outcome == OutcomeStored {
				ev.Outcome = OutcomeFailed
			}
		}
		m.mu.Unlock()
		if ev != nil {
			m.emit(*ev)
		}
		m.signal()
	}()
	return true
}

// Ack acknowledges the envelope of the last Receive (AckContext with no
// deadline but each member's own).
func (m *Multi) Ack() error { return m.AckContext(context.Background()) }

// AckContext acknowledges the envelope of the last Receive at every member it
// came from and at every member holding a copy, and counts it: one delivery of
// its hash, and one copy acknowledged at each member whose acknowledgement
// succeeded (SPO-Xmailbox-OUT-106, OUT-110). A member whose acknowledgement
// failed is not counted, so the copy it serves again is held back as a copy. It
// returns nil when one member's acknowledgement succeeded.
func (m *Multi) AckContext(ctx context.Context) error {
	if m.closed.Load() {
		return ports.ErrClosed
	}
	m.mu.Lock()
	d := m.cur
	m.cur = nil
	if d == nil {
		m.mu.Unlock()
		return nil
	}
	for _, mb := range m.members {
		if mb.held != nil && mb.held.mid == d.mid {
			d.from = append(d.from, mb)
			mb.held = nil
		}
	}
	m.delivered(d.mid, time.Now())
	m.mu.Unlock()
	errs := make([]error, len(d.from))
	var wg sync.WaitGroup
	for i, mb := range d.from {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = mb.c.AckContext(ctx)
			o := OutcomeAcked
			if errs[i] != nil {
				o = OutcomeFailed
			}
			m.emit(MultiEvent{Relay: mb.name, Kind: MultiAck, Outcome: o, Mid: d.mid, Err: errs[i]})
		}()
	}
	wg.Wait()
	m.mu.Lock()
	now := time.Now()
	for i, mb := range d.from {
		if errs[i] == nil {
			m.copyAcked(d.mid, mb, now)
		}
	}
	m.mu.Unlock()
	for _, err := range errs {
		if err == nil {
			return nil
		}
	}
	return fmt.Errorf("mailbox: no relay took the acknowledgement: %w", errors.Join(errs...))
}

// SetBinding gives every member the renewed binding. The members check it the
// same way; a binding the first refuses is given to none.
func (m *Multi) SetBinding(b Binding) error {
	if m.closed.Load() {
		return ports.ErrClosed
	}
	for _, mb := range m.members {
		if err := mb.c.SetBinding(b); err != nil {
			return err
		}
	}
	return nil
}

// SetSenders gives every member the expected-sender set.
func (m *Multi) SetSenders(list []wire.WalletKey) {
	for _, mb := range m.members {
		mb.c.SetSenders(list)
	}
}

// SendRevokes runs the revoke-only exchange on every member at once
// (SPO-Xmailbox-OUT-107) and returns each member's report, with the member's
// own error in its Err. It fails only when every member failed. The members
// share one book: give them LockedBook (and ForRelay, which Connect does, so
// that the book learns which relay recorded what).
func (m *Multi) SendRevokes(ctx context.Context) (map[string]RevokeReport, error) {
	if m.closed.Load() {
		return nil, ports.ErrClosed
	}
	reps := make([]RevokeReport, len(m.members))
	errs := make([]error, len(m.members))
	var wg sync.WaitGroup
	for i, mb := range m.members {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reps[i], errs[i] = mb.c.SendRevokes(ctx)
			o := OutcomeStored
			if errs[i] != nil {
				o = OutcomeFailed
			}
			m.emit(MultiEvent{Relay: mb.name, Kind: MultiRevokes, Outcome: o, Err: errs[i]})
		}()
	}
	wg.Wait()
	out := map[string]RevokeReport{}
	ok := false
	for i, mb := range m.members {
		reps[i].Err = errs[i]
		out[mb.name] = reps[i]
		if errs[i] == nil {
			ok = true
		}
	}
	if ok {
		return out, nil
	}
	return out, fmt.Errorf("mailbox: no relay took the revokes: %w", errors.Join(errs...))
}

// Close closes every member, ends every receive and send in flight, and returns
// after the composite's goroutines have ended (SPO-Xmailbox-INV-039).
func (m *Multi) Close() error {
	m.once.Do(func() {
		m.lifeMu.Lock()
		m.closed.Store(true) // no goroutine is added after this
		m.lifeMu.Unlock()
		close(m.closedCh)
		m.stop()
		for _, mb := range m.members {
			mb.c.Close()
		}
		m.wg.Wait()
		m.mu.Lock()
		for _, mb := range m.members {
			if mb.held != nil {
				clear(mb.held.rcv.Envelope)
				mb.held = nil
			}
		}
		m.cur = nil
		m.mu.Unlock()
	})
	return nil
}

// Logout closes the composite and then every member's dialer with CloseWithin,
// at once. A dialer that does not stop within the bound is ErrTunnelDidNotStop:
// the caller says "tunnel did not stop" and exits non-zero.
func (m *Multi) Logout(within time.Duration) error {
	m.Close()
	errs := make([]error, len(m.members))
	var wg sync.WaitGroup
	for i, mb := range m.members {
		if mb.d == nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := mb.d.CloseWithin(within); err != nil {
				errs[i] = fmt.Errorf("relay %s: %w", mb.name, err)
			}
		}()
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("%w: %w", ErrTunnelDidNotStop, err)
	}
	return nil
}

// lockedBook serialises a RevokeBook that several clients share.
type lockedBook struct {
	mu sync.Mutex
	b  RevokeBook
}

// LockedBook wraps b so that the members of a Multi (or several revoke-only
// senders) may share it.
func LockedBook(b RevokeBook) RevokeBook {
	if b == nil {
		return nil
	}
	return &lockedBook{b: b}
}

func (l *lockedBook) Pending() []Revoke {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Pending()
}

func (l *lockedBook) Result(r Revoke, o RevokeOutcome) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.b.Result(r, o)
}

// ResultAt passes the relay's name on when the wrapped book takes it.
func (l *lockedBook) ResultAt(relay string, r Revoke, o RevokeOutcome) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if rb, ok := l.b.(relayport.RelayRevokeBook); ok {
		rb.ResultAt(relay, r, o)
		return
	}
	l.b.Result(r, o)
}

// relayBook is a book as one relay's client sees it: its outcomes are reported
// with the relay's name.
type relayBook struct {
	relay string
	b     RevokeBook
}

func (r relayBook) Pending() []Revoke { return r.b.Pending() }

func (r relayBook) Result(rv Revoke, o RevokeOutcome) {
	if rb, ok := r.b.(relayport.RelayRevokeBook); ok {
		rb.ResultAt(r.relay, rv, o)
		return
	}
	r.b.Result(rv, o)
}

// ForRelay is b as the client of the named relay sees it: Pending is b's, and
// each outcome goes to b.ResultAt with the relay's name when b is a
// relayport.RelayRevokeBook (to b.Result otherwise). Connect and SendRevokesTo
// give each relay's client the shared book this way (SPO-Xmailbox-IF-026).
func ForRelay(b RevokeBook, relay string) RevokeBook {
	if b == nil {
		return nil
	}
	return relayBook{relay: relay, b: b}
}
