// Package poolops holds the use cases of the pool-operations context.
package poolops

import (
	"context"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ErrKesKeyExists means key files for the next KES number are already stored.
var ErrKesKeyExists = errors.New("a KES key with the next number already exists")

// GenerateKesKey creates the KES key pair for the next operational
// certificate (upstream 04c_genKESKeys).
type GenerateKesKey struct {
	Store  ports.Store
	KeyGen ports.KesKeyGenerator
}

// KesKeyGenerated is the result: the new key's number and its verification
// key. The signing key is never part of a result.
type KesKeyGenerated struct {
	Pool   string
	Number int
	VKey   []byte
}

// Run generates key number `next` for the pool and advances the current
// counter to it. All artefacts are written together or not at all.
func (uc GenerateKesKey) Run(ctx context.Context, poolName string) (KesKeyGenerated, error) {
	// Check before generating, so a refusal costs nothing and creates nothing.
	var number int
	if err := uc.Store.View(ctx, func(r ports.Reader) error {
		var err error
		_, number, err = plan(r, poolName)
		return err
	}); err != nil {
		return KesKeyGenerated{}, err
	}

	pair, err := uc.KeyGen.GenerateKES(ctx)
	if err != nil {
		return KesKeyGenerated{}, fmt.Errorf("generate KES key: %w", err)
	}
	defer pair.SKey.Destroy()

	err = uc.Store.Update(ctx, func(w ports.Writer) error {
		// Re-check inside the transaction: the state may have moved.
		state, n, err := plan(w, poolName)
		if err != nil {
			return err
		}
		if n != number {
			return ports.ErrConflict
		}
		if err := w.Put(ports.Ref{Name: poolName, Kind: ports.KesVKey, Num: n}, pair.VKey); err != nil {
			return err
		}
		if err := w.PutSecret(ports.Ref{Name: poolName, Kind: ports.KesSKey, Num: n}, pair.SKey); err != nil {
			return err
		}
		cur, _ := state.Current()
		if err := w.Put(ports.Ref{Name: poolName, Kind: ports.KesCounter}, pool.FormatCounter(cur)); err != nil {
			return err
		}
		return w.Put(ports.Ref{Name: poolName, Kind: ports.KesCounterNext}, pool.FormatCounter(state.NextNumber()))
	})
	if err != nil {
		return KesKeyGenerated{}, err
	}
	return KesKeyGenerated{Pool: poolName, Number: number, VKey: pair.VKey}, nil
}

// plan loads the KES state, applies the refusals and returns the state after
// generation with the number of the key to generate.
func plan(r ports.Reader, poolName string) (pool.KesState, int, error) {
	current, err := readCounter(r, ports.Ref{Name: poolName, Kind: ports.KesCounter})
	if err != nil {
		return pool.KesState{}, 0, err
	}
	next, err := readCounter(r, ports.Ref{Name: poolName, Kind: ports.KesCounterNext})
	if err != nil {
		return pool.KesState{}, 0, err
	}
	state, n, err := pool.NewKesState(current, next).Generate()
	if err != nil {
		return pool.KesState{}, 0, err
	}
	for _, k := range []ports.Kind{ports.KesVKey, ports.KesSKey} {
		exists, err := r.Exists(ports.Ref{Name: poolName, Kind: k, Num: n})
		if err != nil {
			return pool.KesState{}, 0, err
		}
		if exists {
			return pool.KesState{}, 0, fmt.Errorf("%w: number %d", ErrKesKeyExists, n)
		}
	}
	return state, n, nil
}

func readCounter(r ports.Reader, ref ports.Ref) (*int, error) {
	b, err := r.Get(ref)
	if errors.Is(err, ports.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	n, err := pool.ParseCounter(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ref, err)
	}
	return &n, nil
}
