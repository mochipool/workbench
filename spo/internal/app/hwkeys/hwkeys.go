// Package hwkeys is the one place where the key-generation use cases meet a
// hardware wallet (ADR 0008). A generator plans with Plan before it reads or
// writes anything: with no hardware exporter wired a hardware holder is
// refused exactly as before (custody.PlanGeneration); with one, the plan
// decides against the profile of the device, so a vendor that cannot hold the
// role (Trezor and a pool cold key) is refused before any device prompt. Export
// then runs `address key-gen` on the device at the path the specs give
// (custody.HardwarePath). The adapter already rewrites the verification key's
// description to the hardware marker of SPO-Pfiles-INV-001; nothing here
// repeats it.
package hwkeys

import (
	"context"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Options select the derivation path of one key (custody.HardwarePath).
type Options struct {
	// Account and Index are the wallet account and the key or address index
	// where the path has them (payment, DRep, committee keys, Catalyst voting
	// key: both; stake key: the account; pool cold key: the index only; policy
	// key: neither).
	Account, Index uint32
	// Multisig selects the 1854H purpose of `hwmulti` for a payment key
	// (SPO-02-EXT-003, SPO-03a-INV-001).
	Multisig bool
}

// Plan plans the generation of keys before anything is generated or written.
// hw may be nil: a hardware holder is then refused by the plan with the
// message of custody.PlanGeneration.
//
// spec: SPO-Chw-PRE-001, SPO-Chw-PRE-003
func Plan(hw ports.HardwareKeyExporter, keys ...custody.KeyRef) (custody.Plan, error) {
	if hw == nil {
		return custody.PlanGeneration(keys...)
	}
	return custody.PlanGenerationWith(func(custody.KeyRef) (custody.Profile, error) { return hw.Profile(), nil }, keys...)
}

// Hardware reports whether the key is held by a hardware wallet.
func Hardware(k custody.KeyRef) bool { return k.Holder == custody.HolderHardware }

// Export makes the key on the device. The caller has planned it with Plan.
func Export(ctx context.Context, hw ports.HardwareKeyExporter, key custody.KeyRef, opt Options) (ports.HardwareKey, error) {
	if hw == nil {
		return ports.HardwareKey{}, ports.ErrNoHardwareSigner
	}
	path, err := custody.HardwarePath(key.Role, opt.Account, opt.Index, opt.Multisig)
	if err != nil {
		return ports.HardwareKey{}, err
	}
	hk, err := hw.ExportHardwareKey(ctx, key, path)
	if err != nil {
		return ports.HardwareKey{}, fmt.Errorf("export the %s key from the hardware wallet: %w", key.Role, err)
	}
	return hk, nil
}
