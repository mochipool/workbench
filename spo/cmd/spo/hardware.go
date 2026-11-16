package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/adahandle"
	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/hwcli"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/handles"
	"github.com/mochipool/workbench/spo/internal/domain/handle"
	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// waitHint is what a device that does not answer is waiting for. The words are
// the instruction of SPO-Chw-PR-001.
const waitHint = "Connect and unlock your device and open the Cardano app"

// wireHardware gives the Env the hardware wallet: one lazily opened session of
// the pinned cardano-hw-cli, as exporter, canonicalizer and policy-id asker,
// and returns it as the signer of hardware keys (nil when there is none, so the
// signer directory refuses a hardware key with ports.ErrNoHardwareSigner). The
// device is not opened here, not even to describe the environment: the first
// call that needs it (a command's plan) opens it.
func wireHardware(env *cli.Env, store ports.Store, o cli.WireOptions, errw io.Writer) ports.Signer {
	why := ""
	switch {
	case o.Toolchain == nil || len(o.Tools) == 0:
		why = "this binary runs without a toolchain manifest, so it cannot locate cardano-hw-cli: run the packaged binary (nix run .#spo)"
	case !hasTool(o.Tools, ports.CardanoHWCLI):
		why = "the release set of this binary has no cardano-hw-cli, so no hardware wallet can be used"
	case !o.HaveConfig:
		why = "the hardware wallet needs the network of the workspace (spo.toml): create the workspace with: spo init --network <name>"
	}
	var network hwcli.Network
	if why == "" {
		if o.Config.Network == "mainnet" {
			network = hwcli.Network{Mainnet: true}
		} else if m, err := strconv.ParseUint(o.Preset.Magic, 10, 32); err == nil && m != 0 {
			network = hwcli.Network{Magic: uint32(m)}
		} else {
			why = fmt.Sprintf("the network %q has no testnet magic to give the hardware wallet", o.Config.Network)
		}
	}
	if why != "" {
		env.Absent(cli.CapHardware, why)
		return nil
	}
	cfg := hwcli.Config{
		Toolchain: o.Toolchain, Runner: execx.OS{}, TxID: native.Ledger{}.TransactionID, PolicyID: native.Ledger{}.PolicyID, Network: network,
		OnWait: func(w hwcli.Wait) {
			fmt.Fprintf(errw, "%s (waited %s, giving up in %s)\n", waitHint, w.Elapsed.Round(time.Second), w.Remaining.Round(time.Second))
		},
		OnWarning: func(s string) { fmt.Fprintf(errw, "hardware wallet tool: %s\n", s) },
	}
	if store != nil {
		cfg.Files = hwcli.StoreFiles{Store: store}
	}
	if h := o.Config.Hardware; h != nil {
		if h.WaitSeconds > 0 {
			cfg.Timeout = time.Duration(h.WaitSeconds) * time.Second
		}
		cfg.MinLedger, cfg.MinTrezor, cfg.MinKeystone = h.MinLedger, h.MinTrezor, h.MinKeystone
	}
	ctx := o.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	lazy := hwcli.NewLazy(ctx, cfg)
	env.Hardware, env.Canonicalizer, env.PolicyIDer = lazy, lazy, lazy
	return lazy
}

func hasTool(tools []ports.ToolName, t ports.ToolName) bool {
	for _, x := range tools {
		if x == t {
			return true
		}
	}
	return false
}

// handlePolicy is the ADA Handle policy of the network: the current one on
// every network the workspace can name; the legacy one is for the legacy
// network only (SPO-Caddr-INV-009).
func handlePolicy(o cli.WireOptions) [28]byte {
	id := handle.PolicyCurrent
	if o.Config.Network == "legacy" {
		id = handle.PolicyLegacy
	}
	p, _ := handle.Policy(id)
	return p
}

// wireHandles composes the handle resolver of light mode: Koios answers who
// holds the handle's asset, and the Handle API (a third party, whose word is
// checked against the chain) answers sub-handles. There is no sync gate in
// light mode (SPO-Caddr-MODE-001): that is for the node's own mode.
func wireHandles(env *cli.Env, o cli.WireOptions, src any, addrs ports.AddressInspector) {
	holders, ok1 := src.(ports.AssetHolderReader)
	datums, ok2 := src.(ports.AssetDatumReader)
	utxos, ok3 := src.(ports.UtxoReader)
	if !ok1 || !ok2 || !ok3 {
		env.Absent(cli.CapAdaHandle, "the chain provider cannot say who holds an asset")
		return
	}
	r := handles.Resolver{Policy: handlePolicy(o), Mainnet: o.Config.Network == "mainnet",
		Holders: holders, Datums: datums, Utxos: utxos, Addresses: addrs}
	url := o.Preset.HandleURL
	if o.Config.Handles != nil && o.Config.Handles.URL != "" {
		url = o.Config.Handles.URL
	}
	if url != "" {
		d, err := adahandle.New(adahandle.Config{BaseURL: url, Network: o.Config.Network})
		if err != nil {
			env.Absent(cli.CapAdaHandle, "the Handle API in spo.toml is unusable: "+err.Error())
			return
		}
		r.Directory = d
		env.Endpoints[string(d.Source())] = url
	}
	env.Handles = r
}

// mapError turns the typed errors of the hardware adapter into what the
// operator should do next. The cli package maps those of app and ports; it may
// not import an adapter, so the ones hwcli declares are mapped here.
func mapError(err error) error {
	var msg string
	switch {
	case errors.Is(err, hwcli.ErrNoDevice):
		msg = err.Error() + "\nNo device answered in time. Connect it, unlock it and open the Cardano app, then run the command again. To wait longer, set wait_seconds in the [hardware] section of spo.toml. Nothing was signed, submitted or stored"
	case errors.Is(err, hwcli.ErrDeviceTooOld):
		msg = err.Error() + "\nUpdate the Cardano app (and the firmware) on the device, then run the command again. The minimums are in the [hardware] section of spo.toml (min_ledger, min_trezor, min_keystone); lowering one is your decision and is not checked here. Nothing was signed, submitted or stored"
	case errors.Is(err, hwcli.ErrRejected):
		msg = err.Error() + "\nYou declined on the device, so nothing was signed, submitted or stored. Run the command again and approve on the device only after checking what it shows"
	case errors.Is(err, hwcli.ErrDisconnected):
		msg = err.Error() + "\nThe device went away during the action. Reconnect it, unlock it, open the Cardano app and run the command again. Nothing was submitted; a key generated on the device was not stored"
	case errors.Is(err, hwcli.ErrExpertModeRequired):
		msg = err.Error() + "\nEnable expert mode in the device's Cardano app, then run the command again with --allow-unrestricted (you are asked to confirm; the flag alone allows nothing). Nothing was signed, submitted or stored"
	case errors.Is(err, hwcli.ErrToolUnavailable):
		msg = err.Error() + "\nThe release set's cardano-hw-cli did not start or failed its version gate. Check it with: spo toolchain check"
	case errors.Is(err, hwcli.ErrUnsupportedVendor):
		msg = err.Error() + "\nOnly Ledger, Trezor and Keystone devices are supported"
	default:
		return err
	}
	return cli.Explain(err, msg)
}
