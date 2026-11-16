package wallet

import (
	"context"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// hardwareChangeKeys are the hardware keys declared to the device as the owners
// of the change output: the payment key and, when `<wallet>.staking.hwsfile`
// exists next to a `<wallet>.payment` account, the stake key (SPO-Ptx-INV-009,
// SPO-01sendLovelaces-EXT-002). nil for a payment key held elsewhere.
func hardwareChangeKeys(ctx context.Context, st ports.Store, pay custody.KeyRef) []custody.KeyRef {
	if pay.Holder != custody.HolderHardware {
		return nil
	}
	keys := []custody.KeyRef{pay}
	stem := strings.TrimSuffix(pay.Owner, ".payment")
	if stem == pay.Owner || st == nil {
		return keys
	}
	_ = st.View(ctx, func(r ports.Reader) error {
		if ok, err := r.Exists(ports.Ref{Name: stem, Kind: ports.StakingHwsFile}); err == nil && ok {
			keys = append(keys, custody.KeyRef{Role: custody.RoleStake, Holder: custody.HolderHardware, Owner: stem})
		}
		return nil
	})
	return keys
}
