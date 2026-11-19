package relayporttest

import (
	"context"
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
type MemRegistry struct {
	wmu    sync.Mutex
	mu     sync.RWMutex
	core   *relayregistry.Core
	clock  relayport.Clock
	closed bool
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
	plan, err := m.core.PlanRevoke(r, now)
	if err != nil {
		m.refused(err)
		return relayregistry.RevokeResult{}, err
	}
	m.apply(plan.Ops)
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
	plan := m.core.PlanSweep(now)
	m.apply(plan.Ops)
	return plan.Result, nil
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
