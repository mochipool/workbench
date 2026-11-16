package cli

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func (a *app) providerCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "provider", Short: "Chain provider settings"}

	var (
		endpoint string
		yes      bool
	)
	set := &cobra.Command{
		Use:   "set koios [--url URL]",
		Short: "Name Koios as the chain provider of this workspace",
		Long: `Name Koios as the chain provider. The default endpoint is the network's public
Koios API; --url overrides it. The privacy statement is printed and you must
confirm before anything is written.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if args[0] != "koios" {
				return fmt.Errorf("unknown provider %q; the only chain provider is koios", args[0])
			}
			cfg, err := a.loadConfig()
			if err != nil {
				return err
			}
			preset, err := a.requirePreset(cfg.Network)
			if err != nil {
				return err
			}
			target := preset.KoiosURL
			if endpoint != "" {
				u, err := url.Parse(endpoint)
				if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
					return errors.New("--url must be an absolute http(s) URL")
				}
				target = strings.TrimSuffix(endpoint, "/")
			}
			ok, err := a.confirmProvider(cmd, "koios", target, yes)
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("not confirmed; nothing was changed")
			}
			cfg.Koios = &KoiosConfig{URL: target}
			if err := a.d.Config.Save(a.workspace, cfg); err != nil {
				return err
			}
			fmt.Fprintf(a.d.Out, "Koios (%s) is the chain provider of this workspace.\n", target)
			return nil
		},
	}
	set.Flags().StringVar(&endpoint, "url", "", "Koios API root (default: the network's public endpoint)")
	set.Flags().BoolVar(&yes, "yes", false, "answer yes to the confirmation (the statement is still printed)")
	cmd.AddCommand(set)

	token := &cobra.Command{Use: "token", Short: "API tokens of chain providers"}
	var tokenFD int
	tset := &cobra.Command{
		Use:   "set koios [--token-fd N]",
		Short: "Store the Koios API token in the sealed workspace",
		Long: `Read the Koios API token without echo, or from --token-fd, and store it as a
secret record in the sealed workspace. It is not written to spo.toml and is
never printed.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.checkTokenCommand(args[0]); err != nil {
				return err
			}
			s, err := a.openSealed(cmd.Context())
			if err != nil {
				return err
			}
			defer s.Close()
			var tok *secret.Buffer
			if cmd.Flags().Changed("token-fd") {
				tok, err = readFDSecret(tokenFD, "the token")
			} else {
				tok, err = a.term.ReadSecret(cmd.Context(), "Koios API token: ")
				if errors.Is(err, ErrNoTerminal) {
					err = errors.New("no terminal to ask for the token on; give it on a file descriptor with --token-fd N")
				}
			}
			if err != nil {
				return err
			}
			defer tok.Destroy()
			if tok.Len() == 0 {
				return errors.New("the token is empty")
			}
			if err := s.Store.Update(cmd.Context(), func(w ports.Writer) error { return w.PutSecret(tokenRef(args[0]), tok) }); err != nil {
				return err
			}
			fmt.Fprintln(a.d.Out, "The Koios API token is stored in the workspace.")
			return nil
		},
	}
	tset.Flags().IntVar(&tokenFD, "token-fd", -1, "read the token from this inherited file descriptor")
	tclear := &cobra.Command{
		Use:   "clear koios",
		Short: "Remove the stored Koios API token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.checkTokenCommand(args[0]); err != nil {
				return err
			}
			s, err := a.openSealed(cmd.Context())
			if err != nil {
				return err
			}
			defer s.Close()
			err = s.Store.Update(cmd.Context(), func(w ports.Writer) error { return w.Delete(tokenRef(args[0])) })
			if errors.Is(err, ports.ErrNotFound) {
				fmt.Fprintln(a.d.Out, "No token was stored.")
				return nil
			}
			if err != nil {
				return err
			}
			fmt.Fprintln(a.d.Out, "The Koios API token was removed.")
			return nil
		},
	}
	token.AddCommand(tset, tclear)
	cmd.AddCommand(token)
	return cmd
}

func (a *app) checkTokenCommand(provider string) error {
	if provider != "koios" {
		return fmt.Errorf("unknown provider %q; the only chain provider is koios", provider)
	}
	if !providerTokenKind.Known() {
		return errors.New("storing provider tokens needs an artefact kind (provider.token, secret) that ports does not define yet; nothing was read")
	}
	return nil
}

func (a *app) modeCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "mode", Short: "The workspace's mode of operation"}
	cmd.AddCommand(&cobra.Command{
		Use:   "set <online|light|offline>",
		Short: "Change the mode in spo.toml",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := a.loadConfig()
			if err != nil {
				return err
			}
			switch args[0] {
			case ModeOnline, ModeLight, ModeOffline:
			default:
				return fmt.Errorf("mode %q is not one of online, light, offline", args[0])
			}
			cfg.Mode = args[0]
			if err := a.d.Config.Save(a.workspace, cfg); err != nil {
				return err
			}
			fmt.Fprintf(a.d.Out, "Mode is now %s.\n", cfg.Mode)
			return nil
		},
	})
	return cmd
}

func (a *app) capabilitiesCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "capabilities",
		Short: "List what this workspace's configuration can do, and what it cannot and why",
		Long: `Print the capabilities of the environment commands run in: which chain
capabilities exist and which provider supplies each, which are absent and
why, and the signers. It is computed from the same environment the commands
use, without the network and without opening the workspace.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := a.loadConfig()
			if err != nil {
				return err
			}
			if a.d.Wire == nil {
				return errors.New("capabilities are not available in this build")
			}
			o, genesisWhy, err := a.wireOptions(cmd, &chainFlags{}, true)
			if err != nil {
				return err
			}
			env, err := a.d.Wire(nil, o)
			if err != nil {
				return err
			}
			env.Absent(CapGenesis, genesisWhy)
			w := a.d.Out
			fmt.Fprintf(w, "Workspace %s: network %s, mode %s\n\nChain capabilities:\n", a.workspace, cfg.Network, cfg.Mode)
			chainCaps := []Cap{CapTip, CapSync, CapOpCertCount, CapParams, CapUtxos, CapRewards, CapPools, CapDReps, CapCrossCheck, CapSubmit, CapQueue, CapCalidusRead, CapAdaHandle, CapPollQuestion}
			chainCaps = append(chainCaps, GovernanceChainCaps...)
			var absent []Cap
			for _, c := range chainCaps {
				if !env.Has(c) {
					absent = append(absent, c)
					continue
				}
				src := env.Source(c)
				if src == "" {
					src = "local"
				}
				line := fmt.Sprintf("  %-20s %s", c, src)
				if ep := env.Endpoints[src]; ep != "" {
					line += " (" + ep + ")"
				}
				fmt.Fprintln(w, line)
			}
			if len(absent) > 0 {
				fmt.Fprintln(w, "\nNot available:")
				for _, c := range absent {
					fmt.Fprintf(w, "  %-20s %s\n", c, env.Reason(c))
				}
			}
			fmt.Fprintln(w, "\nLocal:")
			local := append([]Cap{CapClock, CapGenesis, CapKesKeys, CapVrfKeys, CapColdKeys, CapPaymentKeys, CapStakeKeys, CapMnemonics, CapDeriver, CapAddressMake, CapAddress, CapMinOut, CapFees, CapBodies, CapAssemble, CapCerts, CapCertDecode, CapPoolCerts, CapPoolCertDecode, CapMetaHash, CapTxID, CapTxView, CapMetaFiles, CapMsgEncrypt, CapPolicyID, CapKeyCrypto, CapVKeyDerive, CapCalidusKeys, CapVotingKeys, CapSignatures, CapBundle, CapEras, CapFileSink, CapAttach, CapMetaFetch, CapTickers, CapHardware, CapBLSKeys}, GovernanceLocalCaps...)
			for _, c := range local {
				if env.Has(c) {
					fmt.Fprintf(w, "  %-20s yes\n", c)
				} else {
					fmt.Fprintf(w, "  %-20s no: %s\n", c, env.Reason(c))
				}
			}
			fmt.Fprintln(w, "\nSigners:")
			if len(env.SignerKinds) == 0 {
				fmt.Fprintln(w, "  none")
			}
			for _, s := range env.SignerKinds {
				name, lines := signerProfile(s)
				fmt.Fprintf(w, "  %s\n", name)
				for _, l := range lines {
					fmt.Fprintf(w, "    %s\n", l)
				}
			}
			return nil
		},
	}
}
