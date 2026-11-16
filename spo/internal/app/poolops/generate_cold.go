package poolops

import (
	"context"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ErrColdKeyExists means a cold key artefact of the pool is already stored
// (SPO-04a-PRE-001).
var ErrColdKeyExists = errors.New("cold key artefacts already exist for this pool")

// ErrVrfKeyExists means a VRF key of the pool is already stored
// (SPO-04b-PRE-001).
var ErrVrfKeyExists = errors.New("VRF key artefacts already exist for this pool")

// GenerateColdKeys creates the pool's cold key pair and its operational
// certificate issue counter at 0 (upstream 04a_genNodeKeys, software keys).
//
// The key type argument of the script becomes explicit: the signing key is
// always held in the store (upstream `cli`; the store's own protection
// replaces `enc`, which is not ported at generation, as for 04c). A
// hardware holder is refused up front by the generation plan.
type GenerateColdKeys struct {
	Store  ports.Store
	KeyGen ports.ColdKeyGenerator
}

// GenerateColdKeysRequest names the pool and who holds the signing key.
type GenerateColdKeysRequest struct {
	Pool   string
	Holder custody.Holder // empty means the vault
}

// ColdKeysGenerated is the result. It carries no signing key.
type ColdKeysGenerated struct {
	Pool   string
	PoolID chain.PoolID
	VKey   []byte // the cold verification key envelope
}

// Run generates the cold keys. The `.vkey`, `.skey` and the counter are
// written together or not at all.
func (uc GenerateColdKeys) Run(ctx context.Context, req GenerateColdKeysRequest) (ColdKeysGenerated, error) {
	if _, err := custody.PlanGeneration(custody.KeyRef{Role: custody.RolePoolCold, Holder: req.Holder, Owner: req.Pool}); err != nil {
		return ColdKeysGenerated{}, err
	}
	// Check before generating, so a refusal creates nothing.
	if err := uc.Store.View(ctx, func(r ports.Reader) error { return coldPlan(r, req.Pool) }); err != nil {
		return ColdKeysGenerated{}, err
	}
	pair, err := uc.KeyGen.GenerateCold(ctx)
	if err != nil {
		return ColdKeysGenerated{}, fmt.Errorf("generate cold key: %w", err)
	}
	defer pair.SKey.Destroy()

	env, err := pool.ParseEnvelope(pair.VKey)
	if err != nil {
		return ColdKeysGenerated{}, err
	}
	raw, err := env.Key32()
	if err != nil {
		return ColdKeysGenerated{}, err
	}
	counter := pool.IssueCounter{Next: 0}
	copy(counter.ColdVKey[:], raw)
	id, err := chain.PoolIDOf(raw)
	if err != nil {
		return ColdKeysGenerated{}, err
	}

	err = uc.Store.Update(ctx, func(w ports.Writer) error {
		// Re-check inside the transaction: the state may have moved.
		if err := coldPlan(w, req.Pool); err != nil {
			return err
		}
		if err := w.Put(ports.Ref{Name: req.Pool, Kind: ports.NodeVKey}, pair.VKey); err != nil {
			return err
		}
		if err := w.PutSecret(ports.Ref{Name: req.Pool, Kind: ports.NodeSKey}, pair.SKey); err != nil {
			return err
		}
		return w.Put(ports.Ref{Name: req.Pool, Kind: ports.NodeCounter}, counter.Envelope())
	})
	if err != nil {
		return ColdKeysGenerated{}, err
	}
	return ColdKeysGenerated{Pool: req.Pool, PoolID: id, VKey: pair.VKey}, nil
}

// coldPlan refuses when any of the four artefacts exists, the hardware
// signing file included (SPO-04a-PRE-001).
func coldPlan(r ports.Reader, poolName string) error {
	return refuseExisting(r, ErrColdKeyExists, poolName,
		ports.NodeVKey, ports.NodeSKey, ports.NodeHwsFile, ports.NodeCounter)
}

func refuseExisting(r ports.Reader, sentinel error, name string, kinds ...ports.Kind) error {
	for _, k := range kinds {
		ref := ports.Ref{Name: name, Kind: k}
		exists, err := r.Exists(ref)
		if err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("%w: %s", sentinel, ref)
		}
	}
	return nil
}
