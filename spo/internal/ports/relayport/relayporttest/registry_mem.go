package relayporttest

import (
	"context"
	"fmt"
	"sync"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// MemRegistry is the in-memory reference of relayport.Registry: the rules of
// relayregistry.Core and no storage. The session tests use it. It passes
// RunRegistry except for the cases that need a reopen, which it cannot do.
//
// It locks as the durable adapter does: wmu serialises the writers, which make a
// plan with only wmu held, so the eviction guard it calls is called with no lock
// of the readers held (the guard may read the registry; it must not call a
// writer); mu guards the memory, taken for reading by a reader and for writing by
// a writer only to apply an operation.
//
// It carries out a revoke and a sweep as a durable adapter must (ADR 0015
// decision 3): the drops that make room first, each on its own, a refused one
// held back (DropFaults), then the revoke planned with the room that is there.
type MemRegistry struct {
	wmu     sync.Mutex
	mu      sync.RWMutex
	core    *relayregistry.Core
	clock   relayport.Clock
	closed  bool
	drops   *DropFaults
	unknown *UnknownFaults
	learnt  []relayregistry.TombstoneValue // guarded by mu
}

// WithDropFaults makes every drop of a tombstone consult f first: a drop that f
// refuses is not made. It returns m.
func (m *MemRegistry) WithDropFaults(f *DropFaults) *MemRegistry {
	m.drops = f
	return m
}

// WithUnknownFaults makes every write of a tombstone consult f first: a write
// that f answers with an unknown outcome is applied with Core.ApplyUnknown. It
// returns m.
func (m *MemRegistry) WithUnknownFaults(f *UnknownFaults) *MemRegistry {
	m.unknown = f
	return m
}

// Learn puts tombstones in the registry's storage as another writer would: the
// next RefreshTombstones finds them.
func (m *MemRegistry) Learn(ts []relayregistry.TombstoneValue) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.learnt = append(m.learnt, ts...)
}

// take is what storage answers to op: nil when it takes it.
func (m *MemRegistry) take(op relayregistry.Op) error {
	if op.Kind == relayregistry.OpDeleteTombstone && m.drops != nil {
		return m.drops.Try()
	}
	if op.Kind == relayregistry.OpPutTombstone && m.unknown != nil {
		return m.unknown.Try()
	}
	return nil
}

// hold records a refused drop.
func (m *MemRegistry) hold(op relayregistry.Op, now int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.core.Hold(op.Tomb, now+relayregistry.HoldSeconds)
}

// execute carries out a plan as a durable adapter does: each operation is
// taken by storage and applied, one whose outcome is unknown is applied with
// Core.ApplyUnknown and stops the plan. It returns what was applied and what
// was unknown.
func (m *MemRegistry) execute(ops []relayregistry.Op) (applied, unknown []relayregistry.Op, err error) {
	for _, op := range ops {
		if err := m.take(op); err != nil {
			m.mu.Lock()
			if m.core.ApplyUnknown(op) {
				unknown = append(unknown, op)
			}
			m.mu.Unlock()
			return applied, unknown, err
		}
		m.apply([]relayregistry.Op{op})
		applied = append(applied, op)
	}
	return applied, nil, nil
}

// settle reads back what is unconfirmed (here: asks storage to take it again)
// and gives the answer to the core, as an adapter's sweep and refresh do. It
// returns an error wrapping relayport.ErrAuthorityLost once one is overdue.
func (m *MemRegistry) settle(now int64) error {
	m.mu.RLock()
	us := m.core.Unconfirmed()
	m.mu.RUnlock()
	for _, u := range us {
		rb := relayregistry.ReadBackApplied
		if m.take(u.Op) != nil {
			rb = relayregistry.ReadBackCannotTell
		}
		m.mu.Lock()
		_, _, err := m.core.Settle(u, rb, now)
		m.mu.Unlock()
		if err != nil {
			return fmt.Errorf("%w: %w", relayport.ErrAuthorityLost, err)
		}
	}
	return nil
}

// RefreshTombstones implements relayport.TombstoneRefresher: it settles what is
// unconfirmed and merges what Learn put in storage.
func (m *MemRegistry) RefreshTombstones(ctx context.Context) (relayregistry.MergeResult, error) {
	now, err := m.begin(ctx)
	if err != nil {
		return relayregistry.MergeResult{}, err
	}
	defer m.wmu.Unlock()
	if err := m.settle(now); err != nil {
		return relayregistry.MergeResult{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ts := m.learnt
	m.learnt = nil
	return m.core.MergeTombstones(ts, now), nil
}

// SaveRates implements relayport.RateSaver: the reference keeps no storage, so
// there is nothing to save.
func (m *MemRegistry) SaveRates(ctx context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, err := m.read(ctx)
	return err
}

var _ relayport.Registry = (*MemRegistry)(nil)

// NewMemRegistry returns an empty registry with the configuration cfg.
func NewMemRegistry(cfg relayregistry.Config, clock relayport.Clock) (*MemRegistry, error) {
	c, err := relayregistry.NewCore(cfg)
	if err != nil {
		return nil, err
	}
	return &MemRegistry{core: c, clock: clock}, nil
}

// read is for a reader holding mu.RLock.
func (m *MemRegistry) read(ctx context.Context) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if m.closed {
		return 0, relayport.ErrRegistryClosed
	}
	return m.clock.Now().Unix(), nil
}

// begin takes the writers' lock; the caller unlocks.
func (m *MemRegistry) begin(ctx context.Context) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	m.wmu.Lock()
	m.mu.RLock()
	closed := m.closed
	m.mu.RUnlock()
	if closed {
		m.wmu.Unlock()
		return 0, relayport.ErrRegistryClosed
	}
	return m.clock.Now().Unix(), nil
}

func (m *MemRegistry) apply(ops []relayregistry.Op) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, op := range ops {
		m.core.Apply(op)
	}
}

func (m *MemRegistry) refused(err error) {
	m.mu.Lock()
	m.core.CountRefusal(err)
	m.mu.Unlock()
}

func (m *MemRegistry) Lookup(ctx context.Context, d party.Fingerprint) (relayregistry.Entry, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now, err := m.read(ctx)
	if err != nil {
		return relayregistry.Entry{}, false, err
	}
	e, ok := m.core.Lookup(d, now)
	return e, ok, nil
}

func (m *MemRegistry) Devices(ctx context.Context, k relaybind.KeyHash) ([]relayregistry.Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now, err := m.read(ctx)
	if err != nil {
		return nil, err
	}
	return m.core.Devices(k, now), nil
}

func (m *MemRegistry) Tombstones(ctx context.Context, k relaybind.KeyHash, d party.Fingerprint) (relaybind.Tombstones, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, err := m.read(ctx); err != nil {
		return relaybind.Tombstones{}, err
	}
	return m.core.Tombstones(k, d), nil
}

func (m *MemRegistry) ExpectedSenders(ctx context.Context, d party.Fingerprint) ([]mailbox.WalletKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now, err := m.read(ctx)
	if err != nil {
		return nil, err
	}
	return m.core.Senders(d, now), nil
}

func (m *MemRegistry) Register(ctx context.Context, p relayregistry.Presented) (relayregistry.RegisterResult, error) {
	now, err := m.begin(ctx)
	if err != nil {
		return relayregistry.RegisterResult{}, err
	}
	defer m.wmu.Unlock()
	plan, err := m.core.PlanRegister(p, now)
	if err != nil {
		m.refused(err)
		return relayregistry.RegisterResult{}, err
	}
	m.apply(plan.Ops)
	return plan.Result, plan.Warn
}

func (m *MemRegistry) Revoke(ctx context.Context, r relayregistry.RevokeRecord) (relayregistry.RevokeResult, error) {
	now, err := m.begin(ctx)
	if err != nil {
		return relayregistry.RevokeResult{}, err
	}
	defer m.wmu.Unlock()
	for _, op := range m.core.PlanRoom(r, now) {
		if m.take(op) != nil {
			m.hold(op, now)
			continue
		}
		m.apply([]relayregistry.Op{op})
	}
	plan, err := m.core.PlanRevoke(r, now)
	if err != nil {
		m.refused(err)
		return relayregistry.RevokeResult{}, err
	}
	applied, unknown, err := m.execute(plan.Ops)
	if err != nil {
		return relayregistry.PartialRevoke(plan, applied, unknown), err
	}
	return plan.Result, plan.Warn
}

func (m *MemRegistry) SetExpectedSenders(ctx context.Context, d party.Fingerprint, s []mailbox.WalletKey) error {
	now, err := m.begin(ctx)
	if err != nil {
		return err
	}
	defer m.wmu.Unlock()
	plan, err := m.core.PlanSetSenders(d, s, now)
	if err != nil {
		return err
	}
	m.apply(plan.Ops)
	return nil
}

func (m *MemRegistry) Sweep(ctx context.Context) (relayregistry.SweepResult, error) {
	now, err := m.begin(ctx)
	if err != nil {
		return relayregistry.SweepResult{}, err
	}
	defer m.wmu.Unlock()
	if err := m.settle(now); err != nil {
		return relayregistry.SweepResult{}, err
	}
	plan := m.core.PlanSweep(now)
	res := plan.Result
	for _, op := range plan.Ops {
		if m.take(op) != nil {
			m.hold(op, now)
			res.Held++
			res.Tombstones--
			continue
		}
		m.apply([]relayregistry.Op{op})
	}
	return res, nil
}

func (m *MemRegistry) Stats(ctx context.Context) (relayregistry.Stats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now, err := m.read(ctx)
	if err != nil {
		return relayregistry.Stats{}, err
	}
	return m.core.Stats(now), nil
}

// Close makes every later call return relayport.ErrRegistryClosed.
func (m *MemRegistry) Close() error {
	m.wmu.Lock()
	defer m.wmu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}
