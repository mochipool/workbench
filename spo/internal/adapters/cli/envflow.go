package cli

import (
	"context"
	"errors"
	"fmt"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"os"
	"path/filepath"
	"time"

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
	// The wait after a submission (addSubmitFlags; SPO-Xconfirm-IF-005).
	wait        bool
	waitDepth   uint64
	waitTimeout time.Duration
	// noWait is --no-wait of a command that leaves a pending record
	// (envSpec.settles): such a command waits by default.
	noWait bool
}

// DefaultWaitTimeout is how long --wait waits when --wait-timeout is not given.
const DefaultWaitTimeout = 5 * time.Minute

// MaxWaitTimeout is the longest --wait-timeout accepted.
const MaxWaitTimeout = 24 * time.Hour

// addSubmitFlags is addChainFlags for a command that submits a transaction:
// it adds --wait, --wait-confirmations and --wait-timeout. withEnv runs the
// wait after the command's own work, on every transaction the command
// submitted, so a command adds the flags here and does nothing else
// (SPO-Xconfirm-IF-005).
func addSubmitFlags(cmd *cobra.Command, f *chainFlags, transfer bool) {
	addChainFlags(cmd, f, transfer)
	addWaitFlags(cmd, f)
}

// addSettleFlags is addSubmitFlags for a command that leaves a pending record
// (an asset mint or burn, a pool registration or retirement): the command waits
// for confirmation by default and applies the record when it is confirmed, so
// --wait is accepted and redundant; --no-wait skips the wait
// (SPO-Xconfirm-IF-006).
func addSettleFlags(cmd *cobra.Command, f *chainFlags, transfer bool) {
	addChainFlags(cmd, f, transfer)
	addWaitFlags(cmd, f) // --wait is redundant here, and accepted so a script that passes it still works
	cmd.Flags().BoolVar(&f.noWait, "no-wait", false, "do not wait for the transaction to be confirmed: the record stays pending until spo tx settle applies it (this command waits by default in light and online mode)")
}

// addWaitFlags adds only the wait flags, for a command that registers its
// chain flags another way.
func addWaitFlags(cmd *cobra.Command, f *chainFlags) {
	cmd.Flags().BoolVar(&f.wait, "wait", false, "after submitting, wait until the transaction is in a block on every configured provider (light and online mode; never resubmits; Ctrl-C stops waiting, not the transaction)")
	addWaitDepthFlags(cmd, f)
}

func addWaitDepthFlags(cmd *cobra.Command, f *chainFlags) {
	cmd.Flags().Uint64Var(&f.waitDepth, "wait-confirmations", 1, "with --wait: confirmations to wait for (blocks on top of, and including, the one that holds the transaction)")
	cmd.Flags().DurationVar(&f.waitTimeout, "wait-timeout", DefaultWaitTimeout, "with --wait: how long to wait before giving up (the transaction may still be included)")
}

// checkWaitFlags refuses a --wait that cannot work, before anything is asked.
// A command that waits by default (settles) takes the depth and timeout flags
// without --wait and refuses --no-wait with them.
func (f *chainFlags) checkWaitFlags(cmd *cobra.Command, settles bool) error {
	changed := func(n string) bool { fl := cmd.Flags().Lookup(n); return fl != nil && fl.Changed }
	if f.noWait && (f.wait || changed("wait-confirmations") || changed("wait-timeout")) {
		return errors.New("--no-wait cannot be combined with --wait, --wait-confirmations or --wait-timeout")
	}
	if !f.wait && !settles {
		for _, n := range []string{"wait-confirmations", "wait-timeout"} {
			if changed(n) {
				return fmt.Errorf("--%s has no effect without --wait", n)
			}
		}
		return nil
	}
	if f.waitDepth == 0 {
		return errors.New("--wait-confirmations must be at least 1")
	}
	if f.waitTimeout <= 0 || f.waitTimeout > MaxWaitTimeout {
		return fmt.Errorf("--wait-timeout must be more than 0 and at most %s", MaxWaitTimeout)
	}
	return nil
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
	// settles marks a command that leaves a pending record (a mint, a burn, a
	// pool registration or retirement): in light and online mode it waits for
	// confirmation by default and applies the record when confirmed; --no-wait
	// skips that. Where no provider can say where a transaction is, it does not
	// wait and says how to settle later.
	settles bool
	// settlesIfPending is `offline execute`: it waits by default only when the
	// entry it submitted carries a pending update (the command decides after
	// the submit and sets session.lateWait).
	settlesIfPending bool
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
	if err := flags.checkWaitFlags(cmd, spec.settles || spec.settlesIfPending); err != nil {
		return err
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
	// A command that leaves a pending record waits by default, where a provider
	// can say where a transaction is; where none can, it does not wait and says
	// how to settle later. An explicit --wait is a need like any other.
	var notWaiting string
	if spec.settles && !flags.wait && !flags.noWait && (o.Mode == ModeLight || o.Mode == ModeOnline) {
		if probe.Has(CapTxStatus) {
			flags.wait = true
		} else {
			notWaiting = probe.Reason(CapTxStatus)
		}
	}
	if flags.wait { // the wait needs a provider that says where a transaction is
		spec.needs = append(append([]Need(nil), spec.needs...), CapTxStatus)
	}
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
	env, err := a.d.Wire(s.Anchored, o)
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
	rec := recordSubmits(env)
	s.rec = rec
	s.waiting = flags.wait
	s.canWait = env.Has(CapTxStatus)
	if notWaiting != "" {
		fmt.Fprintf(a.d.Err, "Not waiting for confirmation: %s. The record stays pending; apply it with: spo tx settle\n", shown(notWaiting))
	}
	a.settleHooks(rec, s, env)
	before := a.pendingIDs(ctx, s, notWaiting != "")
	if err := fn(ctx, s, env, o); err != nil {
		return err
	}
	if notWaiting != "" {
		a.printNotWaited(ctx, s, before)
	}
	if flags.wait || (s.lateWait && !flags.noWait && s.canWait) {
		return a.waitAfterSubmit(ctx, env, flags, rec)
	}
	return nil
}
