// Package cli is the command-line UI adapter. It parses arguments and calls
// use cases; it holds no behaviour of its own (concern U1).
package cli

import (
	"context"
	"fmt"
	"io"
	"sort"

	"github.com/spf13/cobra"

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
