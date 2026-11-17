package wallet

import (
	"context"
	"strings"

	"github.com/mochipool/workbench/spo/internal/app/keyring"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// hardwareChangeKeys are the hardware keys declared to the device as the owners
// of the change output: the payment key and, when `<wallet>.staking.hwsfile`
// exists next to a `<wallet>.payment` account, the stake key (SPO-Ptx-INV-009,
// SPO-01sendLovelaces-EXT-002). nil for a payment key held elsewhere.
// The caller asks only when the signer it connected is a device.
func hardwareChangeKeys(ctx context.Context, st ports.Store, payName string, pay custody.KeyRef) []custody.KeyRef {
	keys := []custody.KeyRef{pay}
	stem := strings.TrimSuffix(payName, ".payment")
	if stem == payName || st == nil {
		return keys
	}
	_ = st.View(ctx, func(r ports.Reader) error {
		if ok, err := r.Exists(ports.Ref{Name: stem, Kind: ports.StakingHwsFile}); err == nil && ok {
			if sk, err := keyring.Resolve(r, custody.RoleStake, stem); err == nil {
				keys = append(keys, sk)
			}
		}
		return nil
	})
	return keys
}
