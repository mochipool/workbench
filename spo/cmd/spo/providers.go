package main

import (
	"errors"

	"github.com/mochipool/workbench/spo/internal/adapters/blockfrost"
	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/config"
	"github.com/mochipool/workbench/spo/internal/adapters/httpfetch"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// Provider kinds are wired here, one per section of spo.toml. A third kind (a
// node socket, "n2c") is added by giving it a case in providerKinds and a
// layer below; the schema, the order and the cross-check rule do not change.

// wireLightProviders wires light mode from the configured providers
// (ADR 0006). Koios, when configured, is wired as before; Blockfrost is then
// either the only provider (it answers what it can and the rest is absent with
// the reason) or the second source of the reads of the harmful class, or, when
// the operator's order puts it first, the provider that answers while Koios is
// the second source. Two readers of one provider never form a pair.
func wireLightProviders(env *cli.Env, o cli.WireOptions) error {
	cfg := toConfig(o.Config)
	haveKoios := o.Config.Koios != nil
	if haveKoios {
		if err := wireLight(env, o); err != nil {
			return err
		}
	}
	if o.Config.Blockfrost == nil {
		env.Absent(cli.CapPoolCross, noCrossCheck("the provider"))
		return nil
	}
	bf, err := newBlockfrost(o, cfg)
	if err != nil {
		return err
	}
	env.Endpoints[string(bf.Source())] = cfg.BlockfrostURL()
	if !haveKoios {
		wireBlockfrostOnly(env, o, bf)
		return nil
	}
	// Both are configured: the operator's order says which answers first. The
	// readers wireLight set are Koios's; each pair is (answering, second).
	rewards, pools, dreps := env.Rewards, env.Pools, env.DReps
	if cfg.Providers()[0] == config.KindBlockfrost {
		env.Tip, env.Utxos, env.Submitter = bf, bf, bf
		env.OwnUtxos = bf
		env.Rewards, env.Pools, env.DReps = bf, bf, bf
		env.CrossCheck, env.PoolCross, env.DRepCross = rewards, pools, dreps
		if o.Preset.LightParametersURL == "" { // else the hosted document answers, as upstream's light mode does
			env.Params = bf
		}
	} else {
		env.CrossCheck, env.PoolCross, env.DRepCross = bf, bf, bf
	}
	return env.CheckIndependentSources()
}

func newBlockfrost(o cli.WireOptions, cfg config.Config) (*blockfrost.Client, error) {
	url := cfg.BlockfrostURL()
	if url == "" {
		return nil, errors.New("the Blockfrost provider needs an endpoint: the network has no public one; set url in the [blockfrost] section of spo.toml")
	}
	var tok *secret.Buffer
	if o.Tokens != nil {
		tok = o.Tokens[config.KindBlockfrost]
	}
	bf, err := blockfrost.New(blockfrost.Config{BaseURL: url, Network: o.Config.Network, Token: tok})
	if err != nil {
		return nil, err
	}
	return bf, nil
}

// noOpCertSource is why the opcert counter is absent when no configured
// provider reads it.
const noOpCertSource = "no configured provider reads the operational certificate counter (the Blockfrost API has none); add Koios with: spo provider set koios"

// wireBlockfrostOnly wires the readers a Blockfrost-compatible provider
// answers and records why each other chain capability is absent. Nothing is
// wired that the adapter cannot answer, so a command that needs the opcert
// counter or the constitution is refused when it starts, naming the provider.
func wireBlockfrostOnly(env *cli.Env, o cli.WireOptions, bf *blockfrost.Client) {
	env.Tip, env.Params = bf, bf
	env.Utxos, env.Rewards, env.Submitter = bf, bf, bf
	env.OwnUtxos = bf
	env.Pools, env.DReps = bf, bf
	env.AnchorFetcher = httpfetch.Fetcher{Limit: anchorLimit}
	env.Metadata = httpfetch.Fetcher{Limit: pool.MaxMetadataBytes}
	src := string(bf.Source())
	const second = "only one provider is configured, so reads that need corroboration are refused unless the command is given --single-source; add Koios with: spo provider set koios"
	env.Absent(cli.CapCrossCheck, second)
	env.Absent(cli.CapPoolCross, second)
	env.Absent(cli.CapSync, src+" has no sync check")
	env.Absent(cli.CapOpCertCount, noOpCertSource)
	env.Absent(cli.CapCalidusRead, "the Calidus registrations are read through Koios; add it with: spo provider set koios")
	env.Absent(cli.CapPollQuestion, "SPO polls are read through Koios; add it with: spo provider set koios")
	env.Absent(cli.CapPoolInfo, "the pool import reads Koios; add it with: spo provider set koios")
	env.Absent(cli.CapPoolUpdates, "the pool import reads Koios; add it with: spo provider set koios")
	env.Absent(cli.CapConstitution, "the Blockfrost API has no constitution endpoint")
	env.Absent(cli.CapLastEnacted, "the Blockfrost adapter does not read the last enacted governance action")
	env.Absent(cli.CapStakeDist, "light mode computes no tally from stake distributions")
	wireRegistry(env, o)
	wireHandles(env, o, bf, native.Ledger{})
	governanceReaders(env, nil, "the Blockfrost adapter reads no governance state yet (committee, actions, last enacted action, stake distribution, epoch); add Koios with: spo provider set koios")
	env.Absent(cli.CapQueue, "light mode submits through the provider; there is no queue")
	env.Absent(cli.CapAttach, "light mode submits through the provider; there is no transfer file to attach to")
}
