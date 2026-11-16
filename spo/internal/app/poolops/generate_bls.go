package poolops

import (
	"context"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ErrBLSKeyExists means a BLS key of the pool is already stored
// (SPO-04f-PRE-001); upstream exits 2.
var ErrBLSKeyExists = errors.New("BLS key artefacts already exist for this pool")

// ErrBLSHolder: the BLS signing key lives in the sealed store only; there is
// no hardware profile for it.
var ErrBLSHolder = errors.New("a BLS key can only be generated into the local store")

// GenerateBLSKeys creates the pool's BLS key pair (upstream 04f_genBLSKeys,
// testnet tree only), which `05a` needs in the registration certificate from
// protocol version 12 on (SPO-Pfiles-OUT-016). Like 04b it is mode
// independent and never touches the chain. The era is not an argument: the
// native generator has no era (SPO-04f-INV-001's `dijkstra` is the cli's
// way to reach the command), and whether the network profile has BLS keys at
// all is the composition's gate. `enc` is not ported at generation (same
// decision as 04c): the signing key goes into the sealed store.
type GenerateBLSKeys struct {
	Store  ports.Store
	KeyGen ports.BLSKeyGenerator
}

// GenerateBLSKeysRequest names the pool and who holds the signing key.
type GenerateBLSKeysRequest struct {
	Pool   string
	Holder custody.Holder // empty or the vault
}

// BLSKeysGenerated is the result. It carries no signing key.
type BLSKeysGenerated struct {
	Pool string
	VKey []byte
}

// Run generates the pair. Both files are written together or not at all.
func (uc GenerateBLSKeys) Run(ctx context.Context, req GenerateBLSKeysRequest) (BLSKeysGenerated, error) {
	if req.Holder != "" && req.Holder != custody.HolderVault {
		return BLSKeysGenerated{}, fmt.Errorf("%w (asked for %s)", ErrBLSHolder, req.Holder)
	}
	if err := uc.Store.View(ctx, func(r ports.Reader) error { return blsPlan(r, req.Pool) }); err != nil {
		return BLSKeysGenerated{}, err
	}
	pair, err := uc.KeyGen.GenerateBLS(ctx)
	if err != nil {
		return BLSKeysGenerated{}, fmt.Errorf("generate BLS key: %w", err)
	}
	defer pair.SKey.Destroy()

	err = uc.Store.Update(ctx, func(w ports.Writer) error {
		if err := blsPlan(w, req.Pool); err != nil {
			return err
		}
		if err := w.Put(ports.Ref{Name: req.Pool, Kind: ports.BLSVKey}, pair.VKey); err != nil {
			return err
		}
		return w.PutSecret(ports.Ref{Name: req.Pool, Kind: ports.BLSSKey}, pair.SKey)
	})
	if err != nil {
		return BLSKeysGenerated{}, err
	}
	return BLSKeysGenerated{Pool: req.Pool, VKey: pair.VKey}, nil
}

func blsPlan(r ports.Reader, poolName string) error {
	return refuseExisting(r, ErrBLSKeyExists, poolName, ports.BLSVKey, ports.BLSSKey)
}
