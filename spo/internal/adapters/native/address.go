package native

import (
	"fmt"

	"github.com/blinklabs-io/gouroboros/ledger/common"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// BuildAddress implements ports.AddressBuilder: an enterprise address when
// stake is nil, else a base address of two key credentials.
//
// spec: SPO-02-EXT-004, SPO-03a-EXT-005
func (Ledger) BuildAddress(network uint8, payment txbuild.KeyHash, stake *txbuild.KeyHash) (chain.Address, error) {
	var a common.Address
	var err error
	if stake == nil {
		a, err = common.NewAddressFromParts(common.AddressTypeKeyNone, network, payment[:], nil)
	} else {
		a, err = common.NewAddressFromParts(common.AddressTypeKeyKey, network, payment[:], stake[:])
	}
	if err != nil {
		return "", fmt.Errorf("address: %w", err)
	}
	return chain.Address(a.String()), nil
}

// BuildStakeAddress implements ports.AddressBuilder.
//
// spec: SPO-03a-EXT-005
func (Ledger) BuildStakeAddress(network uint8, stake txbuild.KeyHash) (chain.StakeAddress, error) {
	a, err := common.NewAddressFromParts(common.AddressTypeNoneKey, network, nil, stake[:])
	if err != nil {
		return "", fmt.Errorf("stake address: %w", err)
	}
	return chain.StakeAddress(a.String()), nil
}

var _ ports.AddressBuilder = Ledger{}
