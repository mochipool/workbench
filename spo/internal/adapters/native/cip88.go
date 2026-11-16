package native

import (
	"context"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// SignCip88 implements ports.Cip88Signer: the pool cold key signs the CIP-88
// version 2 payload hash as a CIP-8 COSE_Sign1 whose protected address is the
// pool id. The key's hash must be the registration's pool id. A normal and an
// extended cold key both work (cardano-signer takes either).
func (v VaultSignatures) SignCip88(ctx context.Context, key custody.Key[custody.PoolCold], reg cose.Cip88) (ports.Registration, error) {
	lk, err := v.openKey(ctx, key.Ref())
	if err != nil {
		return ports.Registration{}, err
	}
	defer wipe(lk.SKey)
	if h := cose.Blake2b224(lk.VKey); h != reg.PoolID {
		return ports.Registration{}, errors.New("the cold signing key is not the pool's key: its hash is not the registration's pool id")
	}
	sig, err := signWith(lk, reg.ToBeSigned())
	if err != nil {
		return ports.Registration{}, fmt.Errorf("sign the registration: %w", err)
	}
	return ports.Registration{CBOR: reg.Metadata(lk.VKey, sig), JSON: reg.MetadataJSON(lk.VKey, sig)}, nil
}
