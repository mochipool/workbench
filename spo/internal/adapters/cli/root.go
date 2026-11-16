// Package cli is the command-line UI adapter. It parses arguments and calls
// use cases; it holds no behaviour of its own (concern U1).
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/poolops"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Deps is what the composition root hands to the command tree.
type Deps struct {
	Version   string
	Release   string
	Toolchain ports.Toolchain
	Tools     []ports.ToolName
	Out       io.Writer
	Err       io.Writer

	// OpenStore opens the workspace. upstreamLayout selects the plain
	// directory in upstream's file layout, where signing keys are not sealed.
	OpenStore func(dir string, upstreamLayout bool) (ports.Store, error)
	KeyGen    ports.KesKeyGenerator

	// OfflineOpCert wires the ports IssueOperationalCertificate needs for a
	// machine that does not consult the chain. byronEpochs is the number of
	// Byron epochs before the hard fork; byronGenesis may be empty when it
	// is 0.
	OfflineOpCert func(store ports.Store, o OfflineOptions) (OpCertWiring, error)
}

// OfflineOptions are the genesis inputs of offline mode.
type OfflineOptions struct {
	ShelleyGenesis string
	ByronGenesis   string
	ByronEpochs    uint64
}

// OpCertWiring is the set of ports a composition root provides.
type OpCertWiring struct {
	Signers  ports.SignerDirectory
	Tip      ports.TipReader
	Genesis  ports.GenesisReader
	Counters ports.OpCertCounterReader
	Clock    ports.Clock
}

// NewRoot builds the command tree.
func NewRoot(d Deps) *cobra.Command {
	root := &cobra.Command{
		Use:           "spo",
		Short:         "Stake pool operations from one binary, with sealed keys and multi-party signing",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(d.Out)
	root.SetErr(d.Err)

	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the binary version and release set",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintf(d.Out, "spo %s (release set %s)\n", d.Version, d.Release)
			return nil
		},
	})

	tc := &cobra.Command{Use: "toolchain", Short: "Inspect the pinned external tools"}
	tc.AddCommand(&cobra.Command{
		Use:   "check",
		Short: "Locate every external tool and apply the version gates",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return checkToolchain(cmd.Context(), d)
		},
	})
	root.AddCommand(tc)

	var workspace string
	var upstreamLayout bool
	root.PersistentFlags().StringVarP(&workspace, "workspace", "C", ".", "workspace directory")
	root.PersistentFlags().BoolVar(&upstreamLayout, "upstream-layout", false,
		"use a directory in the upstream scripts' file layout; signing keys are stored unsealed, as upstream stores them")

	poolCmd := &cobra.Command{Use: "pool", Short: "Pool keys, certificates and registration"}
	kesCmd := &cobra.Command{Use: "kes", Short: "KES key rotation"}
	kesCmd.AddCommand(&cobra.Command{
		Use:   "generate <pool>",
		Short: "Generate the KES key pair for the next operational certificate",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := d.OpenStore(workspace, upstreamLayout)
			if err != nil {
				return err
			}
			res, err := poolops.GenerateKesKey{Store: store, KeyGen: d.KeyGen}.Run(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			// The verification key is public. The signing key is never shown.
			fmt.Fprintf(d.Out, "Generated KES key %03d for pool %s.\n%s\n", res.Number, res.Pool, res.VKey)
			return nil
		},
	})
	poolCmd.AddCommand(kesCmd)
	poolCmd.AddCommand(opcertCommand(d, &workspace, &upstreamLayout))
	root.AddCommand(poolCmd)
	return root
}

func checkToolchain(ctx context.Context, d Deps) error {
	names := append([]ports.ToolName(nil), d.Tools...)
	sort.Slice(names, func(i, j int) bool { return names[i] < names[j] })
	if len(names) == 0 {
		// No manifest: ask for any tool so the caller sees why.
		_, err := d.Toolchain.Tool(ctx, ports.CardanoCLI)
		return err
	}
	failed := 0
	for _, n := range names {
		tool, err := d.Toolchain.Tool(ctx, n)
		if err != nil {
			failed++
			fmt.Fprintf(d.Out, "FAIL  %-15s %v\n", n, err)
			continue
		}
		v := tool.Version
		if v == "" {
			v = "-"
		}
		fmt.Fprintf(d.Out, "ok    %-15s %-10s %s\n", n, v, tool.Path)
	}
	if failed > 0 {
		return fmt.Errorf("%d tool(s) failed the release-set gates", failed)
	}
	return nil
}

func opcertCommand(d Deps, workspace *string, upstreamLayout *bool) *cobra.Command {
	cmd := &cobra.Command{Use: "opcert", Short: "Operational certificates"}

	var (
		counter     uint64
		offline     bool
		shelley     string
		byron       string
		byronEpochs uint64
	)
	issue := &cobra.Command{
		Use:   "issue <pool>",
		Short: "Issue the operational certificate for the waiting KES key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !offline {
				return errors.New("checking the counter against the chain is not wired yet; pass --offline to issue without the check")
			}
			if shelley == "" {
				return errors.New("--shelley-genesis is required")
			}
			if byronEpochs > 0 && byron == "" {
				return errors.New("--byron-to-shelley-epochs above 0 needs --byron-genesis")
			}
			if d.OfflineOpCert == nil {
				return errors.New("offline operation is not available in this build")
			}
			store, err := d.OpenStore(*workspace, *upstreamLayout)
			if err != nil {
				return err
			}
			w, err := d.OfflineOpCert(store, OfflineOptions{ShelleyGenesis: shelley, ByronGenesis: byron, ByronEpochs: byronEpochs})
			if err != nil {
				return err
			}
			var opts poolops.IssueOptions
			if cmd.Flags().Changed("counter") {
				opts.CounterOverride = &counter
			}
			res, err := poolops.IssueOperationalCertificate{
				Store: store, Signers: w.Signers, Tip: w.Tip, Genesis: w.Genesis,
				Counters: w.Counters, Clock: w.Clock, AllowUnverified: true,
			}.Run(cmd.Context(), args[0], opts)
			if err != nil {
				return err
			}
			fmt.Fprintf(d.Out, "Issued operational certificate %s.node-%03d.opcert with counter %d for KES period %d.\n",
				res.Pool, res.KesNumber, res.Counter, res.KesPeriod)
			fmt.Fprintf(d.Out, "KES key %03d expires in period %d, about %s.\n",
				res.KesNumber, res.Expiry.ExpireKESPeriod, res.Expiry.ExpireKESDate.Local().Format(pool.ExpireDateLayout))
			if !res.Verified {
				fmt.Fprintln(d.Out, "The counter was not checked against the chain (offline). Check it on an online machine before use.")
			}
			return nil
		},
	}
	issue.Flags().Uint64Var(&counter, "counter", 0, "issue with this counter instead of the stored one (also creates a missing counter file)")
	issue.Flags().BoolVar(&offline, "offline", false, "do not consult the chain; the current slot comes from the clock")
	issue.Flags().StringVar(&shelley, "shelley-genesis", "", "path of the Shelley genesis file")
	issue.Flags().StringVar(&byron, "byron-genesis", "", "path of the Byron genesis file (offline mode on a network with a Byron era)")
	issue.Flags().Uint64Var(&byronEpochs, "byron-to-shelley-epochs", 0, "Byron epochs before the hard fork (mainnet 208, preprod 4, preview 0)")
	cmd.AddCommand(issue)

	var value uint64
	newCounter := &cobra.Command{
		Use:   "new-counter <pool>",
		Short: "Create the issue counter of a pool that has none",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := d.OpenStore(*workspace, *upstreamLayout)
			if err != nil {
				return err
			}
			if err := (poolops.CreateIssueCounter{Store: store}).Run(cmd.Context(), args[0], value); err != nil {
				return err
			}
			fmt.Fprintf(d.Out, "Created the issue counter of pool %s at %d.\n", args[0], value)
			return nil
		},
	}
	newCounter.Flags().Uint64Var(&value, "value", 0, "the next issue number")
	cmd.AddCommand(newCounter)
	return cmd
}
