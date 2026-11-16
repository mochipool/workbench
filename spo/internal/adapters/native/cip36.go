package native

import (
	"context"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// SignCip36 implements ports.Cip36Signer: the stake key signs blake2b-256 of
// the registration payload and the metadata is assembled by domain/cose in
// the layout cardano-signer writes. The key must be the registration's stake
// key.
func (v VaultSignatures) SignCip36(ctx context.Context, key custody.Key[custody.Stake], reg cose.Cip36) (ports.Registration, error) {
	if err := reg.Validate(); err != nil {
		return ports.Registration{}, err
	}
	lk, err := v.openKey(ctx, key.Ref())
	if err != nil {
		return ports.Registration{}, err
	}
	defer wipe(lk.SKey)
	if string(lk.VKey) != string(reg.StakePub[:]) {
		return ports.Registration{}, errors.New("the stake signing key is not the registration's stake key")
	}
	h := reg.SigningHash()
	sig, err := signWith(lk, h[:])
	if err != nil {
		return ports.Registration{}, fmt.Errorf("sign the registration: %w", err)
	}
	return ports.Registration{CBOR: reg.Metadata(sig), JSON: reg.MetadataJSON(sig)}, nil
}
