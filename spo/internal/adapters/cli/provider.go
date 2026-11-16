package cli

import (
	"errors"
	"fmt"
	"net"
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
		timeout  int
	)
	set := &cobra.Command{
		Use:   "set <koios|blockfrost> [--url URL]\n  spo provider set node <socket path | tcp://host:port> [--timeout-seconds N]",
		Short: "Name a chain provider of this workspace",
		Long: `Name the node's socket ("node": a cardano-node's UNIX socket, or that socket
forwarded over TCP), Koios, or a Blockfrost-compatible service (Blockfrost
itself, or a self-hosted Dingo) as a chain provider.

The node is your own: nothing is sent to a third party and there is no
confirmation to give. Node-to-client has no authentication and no encryption,
so a tcp:// address that is not loopback is accepted with a warning: tunnel
the socket (SSH, a VPN) and give the loopback end. Online mode (spo mode set
online) reads everything from the node; with a node and a web provider
configured, a web provider is asked in online mode only when you name it in
"spo provider order". This mode has never been run against a real node; see
docs/development/node-socket-checklist.md.

The default endpoint of Koios is the
network's public API; --url overrides it. Blockfrost's default is the public
service of the network, and its project id is stored with
"spo provider token set blockfrost". The privacy statement is printed and you
must confirm before anything is written.

With both configured, the first in the order of preference
("spo provider order") answers reads and the other is the second source that
the reads of the harmful class (reward balance, pool registration, DRep
deposit) are checked against: without --single-source, those commands need it
to agree. The two must be different providers.`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if args[0] != "koios" && args[0] != "blockfrost" && args[0] != "node" {
				return fmt.Errorf("unknown provider %q; the chain providers are node, koios and blockfrost", args[0])
			}
			if args[0] == "node" {
				return a.setNodeProvider(cmd, args[1:], timeout)
			}
			if len(args) != 1 {
				return fmt.Errorf("%s takes no address; use --url to override its endpoint", args[0])
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
			if args[0] == "blockfrost" {
				target = "https://cardano-" + cfg.Network + ".blockfrost.io/api/v0"
			}
			if endpoint != "" {
				u, err := url.Parse(endpoint)
				if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
					return errors.New("--url must be an absolute http(s) URL")
				}
				target = strings.TrimSuffix(endpoint, "/")
			}
			ok, err := a.confirmProvider(cmd, args[0], target, yes)
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("not confirmed; nothing was changed")
			}
			if args[0] == "blockfrost" {
				bf := &BlockfrostConfig{}
				if cfg.Blockfrost != nil {
					bf.TokenRecord = cfg.Blockfrost.TokenRecord
				}
				if endpoint != "" {
					bf.URL = target
				}
				cfg.Blockfrost = bf
			} else {
				cfg.Koios = &KoiosConfig{URL: target}
			}
			if err := a.d.Config.Save(a.workspace, cfg); err != nil {
				return err
			}
			fmt.Fprintf(a.d.Out, "%s (%s) is a chain provider of this workspace.\n", args[0], target)
			return nil
		},
	}
	set.Flags().StringVar(&endpoint, "url", "", "API root (default: the network's public endpoint)")
	set.Flags().BoolVar(&yes, "yes", false, "answer yes to the confirmation (the statement is still printed)")
	set.Flags().IntVar(&timeout, "timeout-seconds", 0, "node only: bound each operation against the node (default 30)")
	cmd.AddCommand(set)

	order := &cobra.Command{
		Use:   "order <node|koios|blockfrost>...",
		Short: "Set the order of preference among the configured providers",
		Long: `Name the providers in the order they are asked. The first answers reads; the
next one is the second source of the reads that need corroboration. Every name
must be a provider that is configured, and none may be named twice: a second
source must be a different provider.

In online mode the node answers every read it can, and a web provider (koios,
blockfrost) is asked only if it is named here: it then supplies what the node
cannot (asset holders, metadata) and is the second source of the reads that
need corroboration. Without the name, no address leaves the machine.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := a.loadConfig()
			if err != nil {
				return err
			}
			cfg.Order = args
			if err := a.d.Config.Save(a.workspace, cfg); err != nil {
				return err
			}
			fmt.Fprintf(a.d.Out, "Order of preference: %s.\n", strings.Join(args, ", "))
			return nil
		},
	}
	cmd.AddCommand(order)

	token := &cobra.Command{Use: "token", Short: "API tokens of chain providers"}
	var tokenFD int
	tset := &cobra.Command{
		Use:   "set <koios|blockfrost> [--token-fd N]",
		Short: "Store a provider's API token (Blockfrost: the project id) in the sealed workspace",
		Long: `Read the provider's API token without echo, or from --token-fd, and store it as a
secret record in the sealed workspace. It is not written to spo.toml and is
never printed.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.checkTokenCommand(args[0]); err != nil {
				return err
			}
			rec, err := a.tokenRecord(args[0])
			if err != nil {
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
				tok, err = a.term.ReadSecret(cmd.Context(), providerTitle(args[0])+" API token: ")
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
			if err := s.Store.Update(cmd.Context(), func(w ports.Writer) error { return w.PutSecret(tokenRef(rec), tok) }); err != nil {
				return err
			}
			fmt.Fprintf(a.d.Out, "The %s API token is stored in the workspace.\n", providerTitle(args[0]))
			return nil
		},
	}
	tset.Flags().IntVar(&tokenFD, "token-fd", -1, "read the token from this inherited file descriptor")
	tclear := &cobra.Command{
		Use:   "clear <koios|blockfrost>",
		Short: "Remove a stored provider API token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.checkTokenCommand(args[0]); err != nil {
				return err
			}
			rec, err := a.tokenRecord(args[0])
			if err != nil {
				return err
			}
			s, err := a.openSealed(cmd.Context())
			if err != nil {
				return err
			}
			defer s.Close()
			err = s.Store.Update(cmd.Context(), func(w ports.Writer) error { return w.Delete(tokenRef(rec)) })
			if errors.Is(err, ports.ErrNotFound) {
				fmt.Fprintln(a.d.Out, "No token was stored.")
				return nil
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(a.d.Out, "The %s API token was removed.\n", providerTitle(args[0]))
			return nil
		},
	}
	token.AddCommand(tset, tclear)
	cmd.AddCommand(token)
	return cmd
}

// setNodeProvider names the node socket: spo provider set node ADDRESS.
func (a *app) setNodeProvider(cmd *cobra.Command, args []string, timeout int) error {
	if len(args) != 1 {
		return errors.New("name the node's socket: spo provider set node <socket path | unix:PATH | tcp://host:port>")
	}
	addr := strings.TrimSpace(args[0])
	if err := checkNodeAddress(addr); err != nil {
		return err
	}
	if timeout < 0 || timeout > 600 {
		return errors.New("--timeout-seconds is 1 to 600")
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	cfg.Node = &NodeConfig{Address: addr, TimeoutSeconds: timeout}
	if err := a.d.Config.Save(a.workspace, cfg); err != nil {
		return err
	}
	fmt.Fprintf(a.d.Out, "The node at %s is a chain provider of this workspace. It is not contacted until a command reads the chain.\n", addr)
	if a.d.NodeAddressWarning != nil {
		if w := a.d.NodeAddressWarning(addr); w != "" {
			fmt.Fprintln(a.d.Err, w)
		}
	}
	if cfg.Mode != ModeOnline {
		fmt.Fprintf(a.d.Out, "The workspace mode is %s; spo mode set online makes the node the only source of chain reads.\n", cfg.Mode)
	}
	return nil
}

// checkNodeAddress accepts a socket path, unix:PATH or tcp://host:port. The
// adapter parses it again when it connects.
func checkNodeAddress(addr string) error {
	switch {
	case addr == "":
		return errors.New("the node address is empty")
	case strings.ContainsAny(addr, "\r\n\x00"):
		return errors.New("the node address has a control character")
	case strings.HasPrefix(addr, "tcp://"):
		if _, _, err := net.SplitHostPort(strings.TrimPrefix(addr, "tcp://")); err != nil {
			return fmt.Errorf("tcp address %q: want tcp://host:port", addr)
		}
	case strings.HasPrefix(addr, "unix:"):
		if strings.TrimLeft(strings.TrimPrefix(strings.TrimPrefix(addr, "unix:"), "//"), "/") == "" {
			return fmt.Errorf("unix address %q names no path", addr)
		}
	case strings.Contains(addr, "://"):
		return fmt.Errorf("address scheme in %q is not supported; use a socket path or tcp://host:port", addr)
	}
	return nil
}

func providerTitle(provider string) string {
	if provider == "blockfrost" {
		return "Blockfrost"
	}
	return "Koios"
}

// tokenRecord is the name of the Secret record that holds a provider's token:
// the provider's own name, or for Blockfrost the one spo.toml gives.
func (a *app) tokenRecord(provider string) (string, error) {
	if provider != "blockfrost" {
		return provider, nil
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return "", err
	}
	if cfg.Blockfrost != nil && cfg.Blockfrost.TokenRecord != "" {
		return cfg.Blockfrost.TokenRecord, nil
	}
	return provider, nil
}

func (a *app) checkTokenCommand(provider string) error {
	if provider == "node" {
		return errors.New("the node socket has no API token")
	}
	if provider != "koios" && provider != "blockfrost" {
		return fmt.Errorf("unknown provider %q; the chain providers are koios and blockfrost", provider)
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
			defer env.Close()
			env.Absent(CapGenesis, genesisWhy)
			w := a.d.Out
			fmt.Fprintf(w, "Workspace %s: network %s, mode %s\n\nChain capabilities:\n", a.workspace, cfg.Network, cfg.Mode)
			chainCaps := []Cap{CapTip, CapSync, CapOpCertCount, CapParams, CapUtxos, CapRewards, CapPools, CapDReps, CapCrossCheck, CapPoolCross, CapOpCertCross, CapSubmit, CapQueue, CapCalidusRead, CapAdaHandle, CapPollQuestion, CapTokenRegistry, CapPoolInfo, CapPoolUpdates}
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
			local := append([]Cap{CapClock, CapGenesis, CapKesKeys, CapVrfKeys, CapColdKeys, CapPaymentKeys, CapStakeKeys, CapMnemonics, CapDeriver, CapAddressMake, CapAddress, CapMinOut, CapFees, CapBodies, CapAssemble, CapCerts, CapCertDecode, CapPoolCerts, CapPoolCertDecode, CapMetaHash, CapTxID, CapTxView, CapMetaFiles, CapMsgEncrypt, CapPolicyID, CapKeyCrypto, CapVKeyDerive, CapCalidusKeys, CapVotingKeys, CapVotingQR, CapSignatures, CapBundle, CapEras, CapFileSink, CapAttach, CapMetaFetch, CapTickers, CapHardware, CapBLSKeys, CapRegistrySigning, CapLogoFiles, CapVKeyEnvelope, CapVrfVKey}, GovernanceLocalCaps...)
			for _, c := range local {
				if env.Has(c) {
					fmt.Fprintf(w, "  %-20s yes\n", c)
				} else {
					fmt.Fprintf(w, "  %-20s no: %s\n", c, env.Reason(c))
				}
			}
			if env.AnchorFetcher != nil || env.Metadata != nil {
				fmt.Fprintln(w, "\nNetwork reads to hosts the chain names:")
				fmt.Fprintln(w, "  anchor documents and pool metadata are fetched from the URL a chain record gives, in every mode that")
				fmt.Fprintln(w, "  fetches them, including online mode (the node does not hold them). That host learns your address and the")
				fmt.Fprintln(w, "  time of the request. The command prints the host before its first such fetch.")
			}
			if env.SameHostOK {
				fmt.Fprintln(w, "\nProvider independence:")
				fmt.Fprintln(w, "  same_host_ok = true: two sources of a cross-check may share a host. The check no longer shows that they")
				fmt.Fprintln(w, "  are different operators with different chain followers.")
				if n := env.SharedHostNote(); n != "" {
					fmt.Fprintln(w, "  In use now: "+shown(n)+".")
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
