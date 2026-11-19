// Package cli is the command-line UI adapter. It parses arguments and calls
// use cases; it holds no behaviour of its own (concern U1).
package cli

import (
	"context"
	"fmt"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
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
		// A descriptor that is to receive a secret must be a pipe or a socket,
		// and is refused before the command does anything (secretout.go).
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.layoutRefuse(cmd); err != nil {
				return err
			}
			if err := a.checkUnlockScope(cmd); err != nil {
				return err
			}
			return checkSecretOutFlags(cmd)
		},
	}
	root.SetOut(d.Out)
	root.SetErr(d.Err)

	root.PersistentFlags().StringVarP(&a.workspace, "workspace", "C", ".", "workspace directory (holds "+WorkspaceFile+" and "+configFile+")")
	// The plain-directory workspace exists only in a build that wires it
	// (tag plainlayout) and in tests; the release binary has no such flag.
	if d.OpenUpstream != nil {
		root.PersistentFlags().BoolVar(&a.upstream, "upstream-layout", false,
			"TEST BUILD ONLY: use a plain directory in the upstream scripts' file layout instead of a sealed workspace; signing keys are stored unsealed")
	}
	root.PersistentFlags().StringVar(&a.layPin, "pin", "",
		"with -C naming a sealed layout (a directory with heads/ and no workspace file): the pin of the layout, which is opened read-only and is never trusted by its directory alone: <workspace id>:layout:<sequence>:<head hash> (what \"store convert --to-layout\" printed) or <workspace id>:ck:<checkpoint key hash>[:<minimum sequence>]. Some commands have a --pin of their own")
	root.PersistentFlags().IntVar(&a.passFD, "passphrase-fd", -1,
		"read the workspace passphrase from this inherited file descriptor (trailing newline stripped) instead of prompting; there is no passphrase flag or variable")

	root.PersistentFlags().IntVar(&a.coldFD, "cold-passphrase-fd", -1,
		"read the cold-key passphrase (the sub-key of cold-role keys under the standard policy; not the workspace passphrase) from this inherited file descriptor instead of prompting")
	root.PersistentFlags().IntVar(&a.newColdFD, "new-cold-passphrase-fd", -1,
		"read the NEW cold-key passphrase of a rotation from this inherited file descriptor instead of prompting")
	root.PersistentFlags().StringVar(&a.unlock, "unlock", "",
		"how to unlock the workspace: passphrase, fido2 (a daily authenticator), backend (a composite slot of a Vault or KMS factor AND its passphrase or authenticator) or recovery-composite (the recovery key typed at a prompt AND the second authenticator) (default: the passphrase when the workspace has a passphrase slot, else fido2)")
	root.PersistentFlags().StringVar(&a.fido2Device, "fido2-device", "", "the FIDO2 authenticator to use (a device path as fido2-token -L prints it); default: the only one connected")
	root.PersistentFlags().IntVar(&a.fido2PinFD, "fido2-pin-fd", -1, "read the authenticator PIN from this inherited file descriptor instead of prompting")
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
		a.poolBLSCommand(), a.poolStatusCommand(), a.poolRetireCertCommand(), a.poolRetireCommand(), a.poolCalidusCommand(),
		a.poolImportCommand(), a.poolExportInfoCommand(),
		a.renameCommand(identity.OwnerPool, "pool"), a.mergeCommand(identity.OwnerPool, "pool"))
	root.AddCommand(poolCmd)
	root.AddCommand(a.walletCommand(), a.stakeCommand(), a.offlineCommand(), a.addressCommand(), a.txCommand())
	root.AddCommand(a.drepCommand(), a.committeeCommand(), a.voteCommand(), a.actionCommand())
	assetCmd := a.assetCommand()
	assetCmd.AddCommand(a.assetMetaCommand())
	root.AddCommand(a.policyCommand(), assetCmd, a.workspaceCommand(), a.keyCommand(), a.catalystCommand(), a.pollCommand(), a.partyCommand(), a.nodeCommand())
	mapErr := d.MapError
	explainAll(root, func(err error) error {
		if mapErr != nil {
			err = mapErr(err)
		}
		return a.explainOwnSession(err)
	})
	a.cleanupAfterEveryCommand(root)
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
