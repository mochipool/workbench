// Package cli is the command-line UI adapter. It parses arguments and calls
// use cases; it holds no behaviour of its own (concern U1).
package cli

import (
	"context"
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// NewRoot builds the command tree.
func NewRoot(d Deps) *cobra.Command {
	a := newApp(d)
	root := &cobra.Command{
		Use:           "spo",
		Short:         "Stake pool operations from one binary, with sealed keys and multi-party signing",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(d.Out)
	root.SetErr(d.Err)

	root.PersistentFlags().StringVarP(&a.workspace, "workspace", "C", ".", "workspace directory (holds "+WorkspaceFile+" and "+configFile+")")
	root.PersistentFlags().BoolVar(&a.upstream, "upstream-layout", false,
		"use a plain directory in the upstream scripts' file layout instead of a sealed workspace; signing keys are stored unsealed, as upstream stores them")
	root.PersistentFlags().IntVar(&a.passFD, "passphrase-fd", -1,
		"read the workspace passphrase from this inherited file descriptor (trailing newline stripped) instead of prompting; there is no passphrase flag or variable")

	root.PersistentFlags().BoolVar(&a.acceptRollback, "accept-rollback", false,
		"open a workspace file that is older than its recorded state (a deliberate restore of an older backup); never saved, and a warning is printed when used")

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

	root.AddCommand(a.initCommand(), a.storeCommand(), a.providerCommand(), a.modeCommand(), a.capabilitiesCommand())

	poolCmd := &cobra.Command{Use: "pool", Short: "Pool keys, certificates and registration"}
	poolCmd.AddCommand(a.poolKeysCommand(), a.vrfCommand(), a.kesCommand(), a.opcertCommand(),
		a.poolDescriptorCommand(), a.poolCertCommand(), a.poolMetadataCommand(), a.poolRegisterCommand(), a.poolWitnessCommand(),
		a.poolStatusCommand(), a.poolRetireCertCommand(), a.poolRetireCommand())
	root.AddCommand(poolCmd)
	root.AddCommand(a.walletCommand(), a.stakeCommand(), a.offlineCommand(), a.addressCommand())
	root.AddCommand(a.drepCommand(), a.committeeCommand(), a.voteCommand(), a.actionCommand())
	explainAll(root)
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
