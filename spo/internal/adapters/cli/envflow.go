package cli

import (
	"context"
	"errors"
	"fmt"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// TransferFileName is the default offline transfer file, in the workspace
// directory.
const TransferFileName = "offlineTransfer.json"

// chainFlags are the flags of a command that may consult the chain or a
// transfer file. A command registers them with addChainFlags.
type chainFlags struct {
	offline     bool
	shelley     string
	byron       string
	byronEpochs uint64
	transfer    string
}

func addChainFlags(cmd *cobra.Command, f *chainFlags, transfer bool) {
	cmd.Flags().BoolVar(&f.offline, "offline", false, "do not consult the chain, whatever the workspace mode; the current slot comes from the clock")
	cmd.Flags().StringVar(&f.shelley, "shelley-genesis", "", "path of the Shelley genesis file (default: the one bundled for the workspace's network)")
	cmd.Flags().StringVar(&f.byron, "byron-genesis", "", "path of the Byron genesis file (default: the one bundled for the workspace's network)")
	cmd.Flags().Uint64Var(&f.byronEpochs, "byron-to-shelley-epochs", 0, "Byron epochs before the hard fork (default: the network's preset; mainnet 208, preprod 4, preview 0)")
	if transfer {
		cmd.Flags().StringVar(&f.transfer, "transfer-file", "", "offline transfer file to read UTxOs and parameters from and to queue to (default: "+TransferFileName+" in the workspace directory); offline mode only")
	}
}

// wireOptions resolves the options of Wire for a command. It reads
// spo.toml, when there is one, and asks nothing of the operator.
func (a *app) wireOptions(cmd *cobra.Command, f *chainFlags, needConfig bool) (WireOptions, string, error) {
	var cfg WorkspaceConfig
	err := os.ErrNotExist
	if a.d.Config.Load != nil {
		cfg, err = a.d.Config.Load(a.workspace)
	}
	haveCfg := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return WireOptions{}, "", err
	}
	if !haveCfg && needConfig {
		return WireOptions{}, "", fmt.Errorf("%s has no %s; create the workspace with: spo init --network <name>", a.workspace, configFile)
	}
	o := WireOptions{Ctx: cmd.Context(), Workspace: a.workspace, Config: cfg, HaveConfig: haveCfg, Offline: f.offline, Toolchain: a.d.Toolchain, Tools: a.d.Tools}
	switch {
	case f.offline:
		o.Mode = ModeOffline
	case haveCfg:
		o.Mode = cfg.Mode
	}
	var genesisWhy string
	if haveCfg {
		if a.d.Config.Preset != nil {
			if p, ok := a.d.Config.Preset(cfg.Network); ok {
				o.Preset = p
			}
		}
	}
	o.Genesis = GenesisOverrides{Shelley: f.shelley, Byron: f.byron}
	if o.Genesis.Shelley == "" && haveCfg && a.d.Genesis != nil {
		if s, b, ok := a.d.Genesis(cfg.Network); ok {
			o.Genesis.Shelley = s
			if o.Genesis.Byron == "" {
				o.Genesis.Byron = b
			}
		}
	}
	if o.Genesis.Shelley == "" {
		if haveCfg {
			genesisWhy = fmt.Sprintf("no Shelley genesis for %s: this binary has no bundled genesis (it runs without a toolchain manifest); pass --shelley-genesis FILE", cfg.Network)
		} else {
			genesisWhy = "--shelley-genesis is required: there is no configured network to take a bundled genesis from"
		}
	}
	o.Genesis.ByronEpochs = f.byronEpochs
	if !cmd.Flags().Changed("byron-to-shelley-epochs") && haveCfg {
		o.Genesis.ByronEpochs = o.Preset.ByronToShelleyEpochs
	}
	o.TransferFile = f.transfer
	if o.TransferFile == "" {
		o.TransferFile = filepath.Join(a.workspace, TransferFileName)
	}
	return o, genesisWhy, nil
}

// envSpec is what a command declares about its environment.
type envSpec struct {
	flags *chainFlags
	// needs are stated first: the command fails before any prompt or effect
	// when one is missing, with one error naming them all.
	needs []Need
	// config makes a missing spo.toml an error.
	config bool
	// extras are the extra-parameter flags of the command: parsed before the
	// workspace is opened, their needs checked with the others, and the
	// message passphrase asked for after the needs are met.
	extras *extraFlags
	// local is for a command that reads and writes only public files (the
	// transfer file) and needs neither the store nor a passphrase: it runs
	// without opening the workspace.
	local bool
	// sealed makes the command refuse --upstream-layout before anything is
	// built or asked: it needs the sealed workspace (party identities and
	// their keys live in it).
	sealed bool
}

// withEnv resolves the command's environment, checks its needs, opens the
// workspace and runs fn. The needs are checked on an Env built without the
// store, so a command that cannot run here fails before the passphrase is
// asked for.
func (a *app) withEnv(cmd *cobra.Command, spec envSpec, fn func(ctx context.Context, s *session, env *Env, o WireOptions) error) error {
	ctx := cmd.Context()
	if a.d.Wire == nil {
		return errors.New("this build has no environment wiring")
	}
	if spec.sealed && a.upstream {
		return errors.New("this command works on a sealed workspace; it does not apply with --upstream-layout (party identities and their keys live in the sealed store)")
	}
	if spec.extras != nil {
		if err := spec.extras.parse(); err != nil {
			return err
		}
		spec.needs = append(append([]Need(nil), spec.needs...), spec.extras.needs()...)
	}
	flags := spec.flags
	if flags == nil {
		flags = &chainFlags{}
	}
	o, genesisWhy, err := a.wireOptions(cmd, flags, spec.config)
	if err != nil {
		return err
	}
	probe, err := a.d.Wire(nil, o)
	if err != nil {
		return err
	}
	defer probe.Close()
	probe.Absent(CapGenesis, genesisWhy)
	if err := probe.Require(spec.needs...); err != nil {
		return err
	}

	if spec.local {
		return fn(ctx, &session{}, probe, o)
	}
	s, err := a.open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	if (o.Mode == ModeLight || o.Mode == ModeOnline) && s.Sealed != nil {
		tok, err := a.loadToken(cmd, s, "koios")
		if err != nil {
			return err
		}
		if tok != nil {
			defer tok.Destroy()
			o.Token = tok
		}
		if o.Config.Blockfrost != nil {
			rec := o.Config.Blockfrost.TokenRecord
			if rec == "" {
				rec = "blockfrost"
			}
			btok, err := a.loadToken(cmd, s, rec)
			if err != nil {
				return err
			}
			if btok != nil {
				defer btok.Destroy()
				o.Tokens = map[string]*secret.Buffer{"blockfrost": btok}
			}
		}
	}
	env, err := a.d.Wire(s.Store, o)
	if err != nil {
		return err
	}
	defer env.Close()
	env.Absent(CapGenesis, genesisWhy)
	if err := env.Require(spec.needs...); err != nil {
		return err
	}
	if spec.extras != nil && len(spec.extras.records) > 0 {
		mf, err := newRecordFiles(s.Store, spec.extras.records, env.MetadataFiles)
		if err != nil {
			return err
		}
		env.MetadataFiles = mf
	}
	if spec.extras != nil {
		pass, err := a.messagePassphrase(ctx, spec.extras)
		if err != nil {
			return err
		}
		spec.extras.pass = pass
		defer func() { pass.Destroy(); spec.extras.pass = nil }()
	}
	return fn(ctx, s, env, o)
}
