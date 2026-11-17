package poolops

import (
	"context"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/app/hwkeys"
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
// hardware holder is planned against the device profile (Ledger or Keystone
// only, SPO-04a-EXT-003) and exported through Hardware; with no Hardware wired
// it is refused up front by the generation plan.
type GenerateColdKeys struct {
	Store  ports.Store
	KeyGen ports.ColdKeyGenerator
	// Hardware exports the cold key of a hardware holder; nil keeps the
	// upfront refusal.
	Hardware ports.HardwareKeyExporter
}

// GenerateColdKeysRequest names the pool and who holds the signing key.
type GenerateColdKeysRequest struct {
	Pool  string
	Place custody.Placement // empty means the vault
	// Index is the cold key index of the hardware path 1853H/1815H/0H/<Index>H
	// (SPO-04a-IF-003, SPO-04a-INV-002); a hardware holder only.
	Index uint32
}

// ColdKeysGenerated is the result. It carries no signing key.
type ColdKeysGenerated struct {
	Pool   string
	PoolID chain.PoolID
	VKey   []byte // the cold verification key envelope
}

// Run generates the cold keys. The `.vkey`, `.skey` and the counter are
// written together or not at all.
//
// spec: SPO-04a-IF-001, SPO-04a-IF-003, SPO-04a-PRE-001, SPO-04a-INV-002, SPO-04a-EXT-003, SPO-04a-EXT-004
func (uc GenerateColdKeys) Run(ctx context.Context, req GenerateColdKeysRequest) (ColdKeysGenerated, error) {
	onDevice := req.Place == custody.PlaceHardware
	if !onDevice && req.Index != 0 {
		return ColdKeysGenerated{}, errors.New("the cold key index is for a hardware key")
	}
	if req.Index > 2147483647 {
		return ColdKeysGenerated{}, errors.New("the cold key index is at most 2147483647")
	}
	if _, err := hwkeys.Plan(uc.Hardware, req.Place, custody.RolePoolCold); err != nil {
		return ColdKeysGenerated{}, err
	}
	// Check before generating, so a refusal creates nothing.
	if err := uc.Store.View(ctx, func(r ports.Reader) error { return coldPlan(r, req.Pool) }); err != nil {
		return ColdKeysGenerated{}, err
	}
	var pair ports.KeyPair
	var hwsfile []byte
	if onDevice {
		hk, err := hwkeys.Export(ctx, uc.Hardware, custody.RolePoolCold, hwkeys.Options{Index: req.Index})
		if err != nil {
			return ColdKeysGenerated{}, err
		}
		pair.VKey, hwsfile = hk.VKey, hk.SigningFile
	} else {
		var err error
		if pair, err = uc.KeyGen.GenerateCold(ctx); err != nil {
			return ColdKeysGenerated{}, fmt.Errorf("generate cold key: %w", err)
		}
		defer pair.SKey.Destroy()
	}

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
		if onDevice {
			if err := w.Put(ports.Ref{Name: req.Pool, Kind: ports.NodeHwsFile}, hwsfile); err != nil {
				return err
			}
		} else if err := w.PutSecret(ports.Ref{Name: req.Pool, Kind: ports.NodeSKey}, pair.SKey); err != nil {
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
