package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func (a *app) initCommand() *cobra.Command {
	var (
		network string
		mode    string
		rkFD    int
		yes     bool
	)
	cmd := &cobra.Command{
		Use:   "init --network <mainnet|preprod|preview> [--mode online|light|offline]",
		Short: "Create a sealed workspace in the workspace directory",
		Long: `Create workspace.spo (the sealed store) and spo.toml (non-secret settings).

The passphrase is asked for twice without echo, or read from --passphrase-fd.
A recovery key is shown once: write it down, then type back its last group.
With --passphrase-fd and --recovery-key-fd the key is written to that
descriptor instead and nothing is shown.

Mode light names Koios, a third-party service, as the chain provider and asks
you to confirm that first. Mode offline configures no provider.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if a.upstream {
				return errors.New("init creates a sealed workspace; --upstream-layout does not apply")
			}
			if network == "" {
				return errors.New("--network is required (mainnet, preprod or preview)")
			}
			preset, err := a.requirePreset(network)
			if err != nil {
				return err
			}
			switch mode {
			case ModeOnline, ModeLight, ModeOffline:
			default:
				return fmt.Errorf("--mode %q is not one of online, light, offline", mode)
			}
			if cmd.Flags().Changed("recovery-key-fd") {
				if !a.passphraseFDSet() {
					return errors.New("--recovery-key-fd needs --passphrase-fd: the recovery key is only taken off the terminal for non-interactive use")
				}
			} else {
				rkFD = -1
			}
			if exists(a.workspaceFile()) || exists(a.configPath()) {
				return fmt.Errorf("%s already holds a workspace (%s or %s exists); init never replaces one", a.workspace, WorkspaceFile, configFile)
			}

			cfg := WorkspaceConfig{Network: preset.Name, Mode: mode}
			if mode == ModeLight {
				ok, err := a.confirmProvider(cmd, "koios", preset.KoiosURL, yes)
				if err != nil {
					return err
				}
				if !ok {
					return errors.New("no provider was confirmed, so no light-mode workspace was created; use --mode offline, or run init again and answer y")
				}
				cfg.Koios = &KoiosConfig{URL: preset.KoiosURL}
			}

			pass, err := a.newPassphrase(ctx, a.passFD, "--passphrase-fd")
			if err != nil {
				return err
			}
			defer pass.Destroy()

			if err := os.MkdirAll(a.workspace, 0o700); err != nil {
				return err
			}
			if err := a.d.Config.Create(a.workspace, cfg); err != nil {
				return err
			}
			recovery, err := a.d.Sealed.Init(a.workspaceFile(), pass)
			if err != nil {
				os.Remove(a.configPath())
				return err
			}
			defer recovery.Destroy()
			fmt.Fprintf(a.d.Out, "Created workspace in %s: network %s, mode %s.\n", a.workspace, cfg.Network, cfg.Mode)
			return a.deliverRecoveryKey(ctx, recovery, rkFD)
		},
	}
	cmd.Flags().StringVar(&network, "network", "", "mainnet, preprod or preview")
	cmd.Flags().StringVar(&mode, "mode", ModeOffline, "online (node socket; not built yet), light (Koios) or offline")
	cmd.Flags().IntVar(&rkFD, "recovery-key-fd", -1, "write the recovery key to this file descriptor instead of showing it (needs --passphrase-fd)")
	cmd.Flags().BoolVar(&yes, "yes", false, "answer yes to the provider confirmation (the statement is still printed)")
	return cmd
}

func (a *app) configPath() string { return a.workspace + string(os.PathSeparator) + configFile }

// providerStatement says what a chain provider learns (ADR 0006).
func providerStatement(name, url string) string {
	return fmt.Sprintf(`Provider: %s at %s

This is a third-party service, not run by you. With it configured, every
query tells it which pools, addresses and stake addresses you are interested
in, every transaction you submit through it, and the network address your
requests come from. It never receives your keys or your passphrase.

Its answers cannot be checked here. The tool treats a failed or unreadable
answer as "unknown", never as "nothing found", and stops where a wrong answer
could do harm.
`, name, url)
}

// confirmProvider prints the privacy statement and asks the operator to
// confirm. The default is no.
func (a *app) confirmProvider(cmd *cobra.Command, name, url string, yes bool) (bool, error) {
	fmt.Fprint(a.d.Out, providerStatement(name, url))
	return a.confirm(cmd.Context(), fmt.Sprintf("Use %s for this workspace?", name), yes)
}
