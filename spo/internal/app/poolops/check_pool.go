package poolops

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals of CheckPoolOnChain.
var (
	// ErrPoolUnresolved: the reference names no pool id.
	ErrPoolUnresolved = errors.New("the reference is neither a pool id nor the name of a pool with an id file or a descriptor")
	// ErrBadPoolID: a stored or given pool id is not valid.
	ErrBadPoolID = errors.New("invalid pool id")
)

// PoolStatus is the answer of CheckPoolOnChain.
type PoolStatus string

// Statuses. Unknown is a provider that did not answer: it is never reported
// as NotRegistered.
const (
	StatusNotRegistered PoolStatus = "not registered"
	StatusRegistered    PoolStatus = "registered"
	StatusRetiring      PoolStatus = "retiring"
	StatusRetired       PoolStatus = "retired"
	StatusUnknown       PoolStatus = "unknown"
)

// CheckPoolOnChain reads whether a pool is registered (upstream 05e). It is a
// read model: it returns a structured state instead of an exit code that
// differs per mode (SPO-05e-MODE-001, SPO-05e-MODE-002).
type CheckPoolOnChain struct {
	Store ports.NamedStore
	// Pools is the provider; nil in offline mode, which refuses
	// (SPO-05e-PRE-001).
	Pools ports.PoolStateReader
}

// PoolCheck is what the chain says.
type PoolCheck struct {
	PoolID chain.PoolID
	Bech32 string
	Status PoolStatus
	// State has the details the provider gave when the pool is registered,
	// retiring or retired.
	State  chain.PoolState
	Source chain.Source
	// Why explains StatusUnknown.
	Why string
}

// Registered is the predicate the workbench uses: the pool is on chain and
// not retired.
func (c PoolCheck) Registered() bool {
	return c.Status == StatusRegistered || c.Status == StatusRetiring
}

// Run resolves the reference and queries the provider.
//
// spec: SPO-05e-IF-001, SPO-05e-IF-002, SPO-05e-PRE-001, SPO-05e-PRE-002, SPO-05e-IN-001, SPO-05e-INV-001,
// spec: SPO-05e-EXT-001, SPO-05e-MODE-001, SPO-05e-MODE-002
func (uc CheckPoolOnChain) Run(ctx context.Context, ref string) (PoolCheck, error) {
	if ref == "" {
		return PoolCheck{}, errors.New("a pool reference is needed")
	}
	if uc.Pools == nil {
		return PoolCheck{}, fmt.Errorf("%w: checking a pool needs a node or Koios (offline mode cannot)", ErrNoChainReader)
	}
	var id chain.PoolID
	if err := uc.Store.View(ctx, func(r ports.NamedReader) error {
		var err error
		id, err = resolvePool(r, ref)
		return err
	}); err != nil {
		return PoolCheck{}, err
	}
	out := PoolCheck{PoolID: id, Bech32: id.Bech32(), Source: uc.Pools.Source()}
	rd, err := uc.Pools.PoolState(ctx, id)
	if err != nil {
		return out, fmt.Errorf("the pool state from %s: %w", uc.Pools.Source(), err)
	}
	switch {
	case rd.IsUnknown():
		out.Status, out.Why = StatusUnknown, rd.Why()
	case rd.IsNone():
		out.Status = StatusNotRegistered
	default:
		out.State, _ = rd.Get()
		switch out.State.Status {
		case chain.PoolRetiring:
			out.Status = StatusRetiring
		case chain.PoolRetired:
			out.Status = StatusRetired
		default:
			out.Status = StatusRegistered
		}
	}
	return out, nil
}

// resolvePool follows the order of SPO-05e-IN-001, first match wins.
func resolvePool(r ports.NamedReader, ref string) (chain.PoolID, error) {
	lower := strings.ToLower(ref)
	if w, err := stake.ParsePoolWord(lower); err == nil && w.IsID {
		return w.Pool, nil
	} else if err != nil {
		return chain.PoolID{}, fmt.Errorf("%w: %v", ErrBadPoolID, err)
	}
	name := strings.TrimPrefix(ref, "./")
	for _, suf := range []string{".json", ".id", ".id-bech", ".pool"} {
		name = strings.TrimSuffix(name, suf)
	}
	if name == "" || strings.ContainsAny(name, "/\\") {
		return chain.PoolID{}, fmt.Errorf("%w: %q", ErrPoolUnresolved, ref)
	}
	text := func(k ports.Kind) (string, bool, error) {
		b, err := r.Get(ports.NamedRef{Name: name, Kind: k})
		if errors.Is(err, ports.ErrNotFound) {
			return "", false, nil
		}
		return firstLine(b), err == nil, err
	}
	if s, ok, err := text(ports.PoolIDBechFile); err != nil {
		return chain.PoolID{}, err
	} else if ok {
		id, err := chain.ParsePoolBech32(s)
		if err != nil {
			// Upstream prints and goes on with an empty id (SPO-05e-INV-001).
			return chain.PoolID{}, fmt.Errorf("%w: %s.pool.id-bech: %v", ErrBadPoolID, name, err)
		}
		return id, nil
	}
	if s, ok, err := text(ports.PoolIDFile); err != nil {
		return chain.PoolID{}, err
	} else if ok {
		w, err := stake.ParsePoolWord(strings.ToLower(s))
		if err != nil || !w.IsID {
			return chain.PoolID{}, fmt.Errorf("%w: %s.pool.id does not hold a pool id", ErrBadPoolID, name)
		}
		return w.Pool, nil
	}
	if b, err := r.Get(ports.NamedRef{Name: name, Kind: ports.PoolDescriptor}); err == nil {
		d, err := pool.ParseDescriptor(b)
		if err != nil {
			return chain.PoolID{}, err
		}
		for _, f := range []string{"poolIDbech", "poolID"} {
			if v := d.Text(f); v != "" {
				if w, err := stake.ParsePoolWord(strings.ToLower(v)); err == nil && w.IsID {
					return w.Pool, nil
				}
			}
		}
		return chain.PoolID{}, fmt.Errorf("%w: %s.pool.json holds no valid id", ErrBadPoolID, name)
	} else if !errors.Is(err, ports.ErrNotFound) {
		return chain.PoolID{}, err
	}
	return chain.PoolID{}, fmt.Errorf("%w: %q", ErrPoolUnresolved, ref)
}
