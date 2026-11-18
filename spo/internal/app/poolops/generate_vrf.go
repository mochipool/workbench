package poolops

import (
	"context"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// GenerateVrfKeys creates the pool's VRF key pair (upstream 04b_genVRFKeys,
// software keys). The signing key goes into the store; `enc` is not ported
// at generation (same decision as 04c).
type GenerateVrfKeys struct {
	Store  ports.NamedStore
	KeyGen ports.VrfKeyGenerator
}

// GenerateVrfKeysRequest names the pool and who holds the signing key.
type GenerateVrfKeysRequest struct {
	Pool  string
	Place custody.Placement // empty means the vault
}

// VrfKeysGenerated is the result. It carries no signing key.
type VrfKeysGenerated struct {
	Pool string
	VKey []byte
}

// Run generates the pair. Both files are written together or not at all.
func (uc GenerateVrfKeys) Run(ctx context.Context, req GenerateVrfKeysRequest) (VrfKeysGenerated, error) {
	if _, err := custody.PlanGeneration(req.Place, custody.RoleVRF); err != nil {
		return VrfKeysGenerated{}, err
	}
	if err := uc.Store.View(ctx, func(r ports.NamedReader) error { return vrfPlan(r, req.Pool) }); err != nil {
		return VrfKeysGenerated{}, err
	}
	pair, err := uc.KeyGen.GenerateVRF(ctx)
	if err != nil {
		return VrfKeysGenerated{}, fmt.Errorf("generate VRF key: %w", err)
	}
	defer pair.SKey.Destroy()

	err = uc.Store.Update(ctx, func(w ports.NamedWriter) error {
		if err := vrfPlan(w, req.Pool); err != nil {
			return err
		}
		if err := w.Put(ports.NamedRef{Name: req.Pool, Kind: ports.VrfVKey}, pair.VKey); err != nil {
			return err
		}
		return w.PutSecret(ports.NamedRef{Name: req.Pool, Kind: ports.VrfSKey}, pair.SKey)
	})
	if err != nil {
		return VrfKeysGenerated{}, err
	}
	return VrfKeysGenerated{Pool: req.Pool, VKey: pair.VKey}, nil
}

func vrfPlan(r ports.NamedReader, poolName string) error {
	return refuseExisting(r, ErrVrfKeyExists, poolName, ports.VrfVKey, ports.VrfSKey)
}
