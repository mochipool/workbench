// Package relaystore is the store tool of the stateless relay (ADR 0015 work
// package 9): init-store, store verify, store inspect, store repair and
// migrate-store over the two buckets of one relay identity (decision 3).
//
// Every operation is a function that takes its dependencies explicitly (Deps:
// the two bucket clients, the node key, the clocks, the lease times) and
// returns a typed report; Render* writes a report as plain text, which never
// holds a secret or an envelope body. Main is the command line the relay
// binary dispatches to.
//
// The tool writes only what each operation says it writes, conditionally,
// under the identity's lease when a relay could otherwise be writing (repair,
// a migration into an initialised identity, the store's markers by
// objregistry.Open with InitIdentity), and never:
//
//   - an unconditional put;
//   - a simple delete in the registry bucket (but the policy probes under
//     selftest/);
//   - a delete of an object version whose lock has not ended;
//   - a tombstone lower than the one stored, or a delete of any tombstone
//     version;
//   - a delete of the lease object;
//   - a delete in a directory store it migrates from.
//
// It is an adapter, not a use case: it works on the object adapters' own
// layout (objregistry, objlease, objmailbox, s3client), which the layering
// rule lets no package under internal/app import. It imports no os: the
// directory relay is read through DirSource (adapters/relaydir), the terminal
// through a Confirm function, both given by the binary.
package relaystore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objlease"
	"github.com/mochipool/workbench/spo/internal/adapters/objregistry"
	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// DefaultRequestTimeout bounds one store request of the tool.
const DefaultRequestTimeout = 10 * time.Second

// Deps are what every operation needs.
type Deps struct {
	// Registry is the client of the registry bucket (versioned, Object Lock);
	// Working the client of the working bucket (unversioned).
	Registry, Working *s3client.Client
	// NodeKey is the relay identity's node public key: the prefix
	// relays/<64 hex>/ in both buckets.
	NodeKey [32]byte
	// Mode is the deployment's Object Lock mode (compliance when empty;
	// governance for a test deployment only, ADR 0015 decision 10).
	Mode s3client.Mode
	// Clock is the relay's clock: time.Now in production, whose readings carry
	// a monotonic part, which the lease and the mailbox adapter need.
	Clock relayport.Clock
	// Wall is the lease's wall clock (nil: Clock's reading without its
	// monotonic part, objlease's default).
	Wall func() time.Time
	// LeaseTimes and LeaseTick are the lease's (objlease.DefaultTimes and
	// objlease.DefaultTick when zero).
	LeaseTimes objlease.Times
	LeaseTick  time.Duration
	// LeaseWait bounds the wait for the lease (default: the take-after time,
	// the drain, two polls and a request: 75 s at the defaults). A lease a live
	// relay renews is never taken, so the wait ends and the operation is
	// refused (ErrLeaseHeld).
	LeaseWait time.Duration
	// RequestTimeout bounds one request (DefaultRequestTimeout when zero).
	RequestTimeout time.Duration
	// Core is the registry configuration objregistry.Open checks bindings with
	// (relayregistry.DefaultConfig when zero).
	Core relayregistry.Config
	// Rand is the source of mailbox nonces and probe names (crypto/rand when nil).
	Rand io.Reader

	// hook is a test seam: called at each named step of a migration and of
	// init-store; an error stops the operation there, as a crash would.
	hook func(step string) error
}

// The errors an operation refuses with.
var (
	// ErrForeign: a marker or the lease names another relay identity, or the
	// bucket holds an object at the marker's or the lease's name that is not
	// one of this tool's.
	ErrForeign = errors.New("the store is not this relay identity's")
	// ErrEmptied: a marker is missing while the identity holds state or a
	// marker elsewhere (ADR 0015 decision 2, "An empty store is a full
	// rollback"). init-store never marks such a store.
	ErrEmptied = errors.New("the store looks emptied or rolled back: a marker is missing while the identity holds state")
	// ErrLeaseHeld: a relay renews the lease, so it runs; stop it first.
	ErrLeaseHeld = errors.New("a relay of this identity holds the lease (it was renewed while the tool waited); stop it first")
	// ErrLeaseUnreadable: the lease object is not a record of this identity;
	// repair --action lease overwrites it with a released record.
	ErrLeaseUnreadable = errors.New("the lease object is unreadable or names another identity")
	// ErrNotCarried: a migration did not carry everything a relay would enforce.
	ErrNotCarried = errors.New("the migration did not carry everything; the markers were not written, so no relay starts on the store; run it again")
	// ErrSelfTest: a bucket failed the self-test.
	ErrSelfTest = errors.New("a bucket failed the self-test")
	// ErrMigrationRecord: the working bucket holds a migration record where
	// the operation needs none (a migration complete but for its deletion, or
	// one in progress); the error says which and what to run.
	ErrMigrationRecord = errors.New("the working bucket holds a migration record")
)

// session is one operation's view of the identity.
type session struct {
	d       Deps
	rc, wc  *s3client.Client
	node    [32]byte
	nodeHex string
	prefix  string
	mode    s3client.Mode
	reqMax  time.Duration
	clock   relayport.Clock
	rnd     io.Reader
	times   objlease.Times

	lease     *objlease.Lease // nil: no lease held; set and cleared only between requests
	mu        sync.Mutex      // guards lastRenew and the renewal (reads run concurrently)
	lastRenew time.Time
}

func newSession(d Deps) (*session, error) {
	switch {
	case d.Registry == nil || d.Working == nil:
		return nil, errors.New("the store tool needs a client for each bucket")
	case d.Clock == nil:
		return nil, errors.New("the store tool needs a clock")
	case d.Mode != "" && d.Mode != s3client.Compliance && d.Mode != s3client.Governance:
		return nil, fmt.Errorf("the retention mode %q is not COMPLIANCE or GOVERNANCE", d.Mode)
	case d.NodeKey == [32]byte{}:
		return nil, errors.New("the store tool needs the relay's node key")
	}
	s := &session{d: d, rc: d.Registry, wc: d.Working, node: d.NodeKey, nodeHex: hex.EncodeToString(d.NodeKey[:]),
		prefix: objregistry.Prefix(d.NodeKey), mode: d.Mode, reqMax: d.RequestTimeout, clock: d.Clock, rnd: d.Rand, times: d.LeaseTimes}
	if s.mode == "" {
		s.mode = s3client.Compliance
	}
	if s.reqMax <= 0 {
		s.reqMax = DefaultRequestTimeout
	}
	if s.rnd == nil {
		s.rnd = rand.Reader
	}
	if s.times == (objlease.Times{}) {
		s.times = objlease.DefaultTimes()
	}
	return s, nil
}

func (s *session) now() time.Time { return s.clock.Now() }

func (s *session) step(name string) error {
	if s.d.hook != nil {
		return s.d.hook(name)
	}
	return nil
}

// rq is the context of one request: under the lease when one is held (the
// lease is renewed first when a quarter of its term has passed since the last
// renewal), else bounded by the request timeout.
func (s *session) rq(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if s.lease == nil {
		c, cancel := context.WithTimeout(ctx, s.reqMax)
		return c, cancel, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.now().Sub(s.lastRenew) >= s.times.RenewEvery() {
		sent := s.now()
		rctx, cancel := context.WithTimeout(ctx, s.times.RequestTimeout)
		err := s.lease.Renew(rctx)
		cancel()
		if err != nil && errors.Is(err, relayport.ErrAuthorityLost) {
			return nil, nil, err
		}
		if err == nil {
			s.lastRenew = sent
		}
	}
	return relayport.RequestContext(ctx, s.lease, s.now(), s.reqMax)
}

// takeLease acquires the identity's lease through objlease: a released lease
// at once, a held one only after it was seen unchanged for the take-after time
// and drained, an absent one as lapsed. A relay that renews it is never
// displaced: the bounded wait ends and the operation is refused.
func (s *session) takeLease(ctx context.Context) error {
	l, err := objlease.New(objlease.Config{Store: s.wc, NodeKey: s.nodeHex, Clock: s.clock, Wall: s.d.Wall, Times: s.times, Tick: s.d.LeaseTick})
	if err != nil {
		return err
	}
	wait := s.d.LeaseWait
	if wait <= 0 {
		wait = s.times.TakeAfter() + s.times.Drain + 2*s.times.Poll + s.times.RequestTimeout
	}
	actx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	if err := l.Acquire(actx); err != nil {
		switch {
		case errors.Is(err, objlease.ErrUnreadable), errors.Is(err, objlease.ErrForeignLease):
			return fmt.Errorf("%w: %w", ErrLeaseUnreadable, err)
		case errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil:
			return fmt.Errorf("%w (waited %v): %v", ErrLeaseHeld, wait, err)
		}
		return err
	}
	s.lease, s.lastRenew = l, s.now()
	return nil
}

// releaseLease gives the lease up; a release whose outcome is unknown lets it
// lapse, which a later relay waits out.
func (s *session) releaseLease(ctx context.Context) error {
	if s.lease == nil {
		return nil
	}
	l := s.lease
	s.lease = nil
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.times.RequestTimeout)
	defer cancel()
	return l.Release(rctx)
}

// randHex is n random bytes as hex, for a probe's name.
func (s *session) randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(s.rnd, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Verdict is the result of one check.
type Verdict int

// The verdicts.
const (
	OK Verdict = iota
	Warning
	Failure
	NotVerifiable
)

func (v Verdict) String() string {
	names := [...]string{"ok", "warning", "FAILURE", "not verifiable"}
	if v < 0 || int(v) >= len(names) {
		return fmt.Sprintf("verdict(%d)", int(v))
	}
	return names[v]
}

// Check is one named check and what it found.
type Check struct {
	Name    string
	Verdict Verdict
	Detail  string
}

func failed(cs []Check) bool {
	for _, c := range cs {
		if c.Verdict == Failure {
			return true
		}
	}
	return false
}
