package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/genesisfile"
	"github.com/mochipool/workbench/spo/internal/adapters/koios"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/adapters/offline"
	"github.com/mochipool/workbench/spo/internal/adapters/systemclock"
	"github.com/mochipool/workbench/spo/internal/adapters/transferfile"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// chainCaps are the capabilities that depend on the mode.
var chainCaps = []cli.Cap{cli.CapTip, cli.CapSync, cli.CapOpCertCount, cli.CapParams, cli.CapUtxos, cli.CapRewards, cli.CapPools, cli.CapDReps, cli.CapCrossCheck, cli.CapSubmit, cli.CapQueue}

// wire builds the Env of a command: the local capabilities every mode has,
// then the chain capabilities the mode and provider can supply. What a mode
// cannot supply stays nil with the reason, so a command that needs it is
// refused when it starts. store may be nil: the signers then cannot release
// keys, which is enough to describe the environment. Nothing here touches
// the network.
func wire(store ports.Store, o cli.WireOptions) (*cli.Env, error) {
	env := &cli.Env{Mode: o.Mode, Endpoints: map[string]string{}}

	var vault ports.Vault
	if store != nil {
		v, ok := store.(ports.Vault)
		if !ok {
			env.Absent(cli.CapSigners, "the store cannot release signing keys to a signer")
		}
		vault = v
	}
	if store == nil || vault != nil {
		for _, s := range []ports.Signer{native.VaultSigner{Vault: vault}} {
			if err := ports.CheckSigner(s); err != nil {
				return nil, err
			}
			env.SignerKinds = append(env.SignerKinds, s)
		}
		env.Signers = native.Signers{Vault: vault}
	}

	env.KesKeys, env.VrfKeys = native.KeyGen{}, native.KeyGen{}
	soft := native.SoftwareKeys{}
	env.ColdKeys, env.PaymentKeys, env.StakeKeys = soft, soft, soft
	env.Mnemonics, env.WalletDeriver = soft, soft
	clock := systemclock.Clock{}
	env.Clock = clock
	led := native.Ledger{}
	env.AddressInspector, env.MinOutputCalculator, env.FeeEstimator = led, led, led
	env.TxBodyBuilder, env.TxAssembler = led, led
	env.Addresses = led
	env.Certs, env.CertDecoder = led, led
	env.NetworkID = ports.NetworkTestnet
	if o.Config.Network == "mainnet" {
		env.NetworkID = ports.NetworkMainnet
	}
	var genesis genesisfile.Shelley
	if o.Genesis.Shelley != "" {
		genesis = genesisfile.Shelley{Path: o.Genesis.Shelley}
		env.Genesis = genesis
	}

	none := func(why string) {
		for _, c := range chainCaps {
			env.Absent(c, why)
		}
	}
	switch o.Mode {
	case "":
		// No mode: every chain capability keeps the generic reason.
	case cli.ModeOffline:
		wireOffline(env, o, clock, genesis)
	case cli.ModeLight:
		if o.Config.Koios == nil {
			none("no chain provider is configured: spo provider set koios")
			break
		}
		if err := wireLight(env, o); err != nil {
			return nil, err
		}
	case cli.ModeOnline:
		none("online mode needs a cardano-node socket adapter, which is not built yet; use mode light (Koios), or pass --offline")
	default:
		none(fmt.Sprintf("mode %q is not one of online, light, offline", o.Mode))
	}
	return env, nil
}

func wireOffline(env *cli.Env, o cli.WireOptions, clock ports.Clock, genesis genesisfile.Shelley) {
	switch {
	case env.Genesis == nil:
		env.Absent(cli.CapTip, "offline mode computes the slot from the clock and the Shelley genesis, which is not available (see genesis)")
	default:
		tip := offline.Tip{Clock: clock, Genesis: genesis}
		switch {
		case o.Genesis.ByronEpochs > 0 && o.Genesis.Byron == "":
			env.Absent(cli.CapTip, fmt.Sprintf("the network has %d Byron epochs, so the offline slot needs a Byron genesis: none is bundled with this binary; pass --byron-genesis FILE", o.Genesis.ByronEpochs))
		case o.Genesis.ByronEpochs > 0:
			byron, err := genesisfile.ReadByron(o.Genesis.Byron, o.Genesis.ByronEpochs)
			if err != nil {
				env.Absent(cli.CapTip, err.Error())
				break
			}
			tip.Byron = &byron
			env.Tip = tip
		default:
			env.Tip = tip
		}
	}
	env.OpCertCounters = offline.Counters{}
	env.AllowUnverified = true

	env.Absent(cli.CapSync, "offline mode has no chain to check the sync of")
	env.Absent(cli.CapSubmit, "offline mode has no transaction submitter; queue to a transfer file instead")
	if st, err := os.Stat(o.TransferFile); err == nil && st.Mode().IsRegular() {
		f := &transferfile.File{Path: o.TransferFile}
		env.Utxos, env.Params, env.Queue = f, f, f
		// The snapshot answers reward accounts, and whatever else the
		// transfer-file adapter implements today (type assertions, so a new
		// interface is picked up without more wiring).
		env.Rewards = f
		env.Pools, _ = any(f).(ports.PoolStateReader)
		env.DReps, _ = any(f).(ports.DRepStateReader)
		env.Absent(cli.CapPools, "the offline transfer file holds no pool registration state; checks of a pool are skipped only when the command is given --allow-unverified")
		env.Absent(cli.CapDReps, "the offline transfer file has no DRep state")
		env.Absent(cli.CapCrossCheck, noCrossCheck(string(f.Source())))
		return
	}
	why := fmt.Sprintf("offline mode reads this from an offline transfer file and %s does not exist; create it on the online machine (01_workOffline.sh new), copy it here, or pass --transfer-file PATH", o.TransferFile)
	env.Absent(cli.CapUtxos, why)
	env.Absent(cli.CapParams, why)
	env.Absent(cli.CapQueue, why)
	env.Absent(cli.CapRewards, why)
	env.Absent(cli.CapPools, why)
	env.Absent(cli.CapDReps, why)
	env.Absent(cli.CapCrossCheck, why)
}

// noCrossCheck is the reason there is no second reward-account source: no
// adapter pair gives two independent answers today, so a read of the "harmful
// if false" class rests on the one source, and the operator acknowledges that
// with --single-source (ADR 0006).
func noCrossCheck(primary string) string {
	return "there is no second independent reward-account source besides " + primary + ", so reads that need corroboration are refused unless the command is given --single-source"
}

func wireLight(env *cli.Env, o cli.WireOptions) error {
	url := o.Config.Koios.URL
	if url == "" {
		url = o.Preset.KoiosURL
	}
	if url == "" {
		return errors.New("light mode needs a Koios endpoint: the network has no public one; set url in the [koios] section of spo.toml")
	}
	k, err := koios.New(koios.Config{BaseURL: url, Network: o.Config.Network, Token: o.Token})
	if err != nil {
		return err
	}
	env.Tip, env.Sync, env.OpCertCounters = k, k, k
	env.Utxos, env.Rewards, env.Submitter = k, k, k
	// The Koios adapter implements these when it gains the methods.
	env.Pools, _ = any(k).(ports.PoolStateReader)
	env.DReps, _ = any(k).(ports.DRepStateReader)
	env.Absent(cli.CapPools, "the Koios adapter does not read pool registration state yet")
	env.Absent(cli.CapDReps, "the Koios adapter does not read DRep state yet")
	env.Absent(cli.CapCrossCheck, noCrossCheck(string(k.Source())))
	env.Endpoints[string(k.Source())] = url
	// Upstream light mode takes the protocol parameters from the hosted
	// light-mode parameters file, not from Koios (SPO-Clight-EXT-001).
	if o.Preset.LightParametersURL != "" {
		lp, err := koios.NewLightParameters(koios.LightConfig{URL: o.Preset.LightParametersURL, Magic: o.Preset.Magic})
		if err != nil {
			return err
		}
		env.Params = lp
		env.Endpoints[string(lp.Source())] = o.Preset.LightParametersURL
	} else {
		env.Params = k
	}
	env.Absent(cli.CapQueue, "light mode submits through the provider; there is no queue")
	return nil
}
