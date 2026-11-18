package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
)

// renameCommand is `<kind> rename <old> <new>`: it gives an owner another name.
// A name is a label (ADR 0010 decision 2), so one label record is replaced and no
// other record of the workspace is touched: the keys, the descriptor, the
// certificates and the counters of the owner stay as they are, and so does every
// reference between objects, which names identities. Nothing is asked for beyond
// the workspace passphrase.
//
// spec: SPO-Xidentity-IF-003
func (a *app) renameCommand(kind identity.OwnerKind, noun string) *cobra.Command {
	return &cobra.Command{
		Use:   "rename <old> <new>",
		Short: "Give a " + noun + " another name",
		Long: "Give the " + noun + " <old> the name <new>. The name is only a label: the keys and every other\n" +
			"record of the " + noun + " are untouched. A name that another " + noun + " has is refused.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			ctx := cmd.Context()
			s, err := a.open(ctx)
			if err != nil {
				return err
			}
			defer s.closeInto(&err)
			if err = s.Anchored.Update(ctx, func(w ports.Writer) error {
				return labels.Rename(w, kind, args[0], args[1])
			}); err != nil {
				return fmt.Errorf("rename %s %s: %w", noun, args[0], err)
			}
			fmt.Fprintf(a.d.Out, "The %s %s is now named %s.\n", noun, args[0], args[1])
			return nil
		},
	}
}

// mergeCommand is `<kind> merge <name> --from DIR [--as NAME]`: the residual case
// of ADR 0010 decision 2. An upstream directory holds the same keys under another
// anchor than this workspace chose (a wallet made stake-only here, which later
// gained a payment key, has its stake key hash as anchor; the directory's wallet
// has the payment key hash). An import refuses it, showing both. Merge, run by
// the operator, keeps this workspace's anchor and records the directory's as an
// alias, when the two owners have identical member sets.
//
// spec: SPO-Xidentity-IF-004
func (a *app) mergeCommand(kind identity.OwnerKind, noun string) *cobra.Command {
	var from, as string
	cmd := &cobra.Command{
		Use:   "merge <name> --from DIR [--as NAME]",
		Short: "Declare a " + noun + " of an upstream directory the same as one of this workspace",
		Long: "Two owners with identical member sets are one owner. Merge keeps the anchor this workspace\n" +
			"has for the " + noun + " <name> and records the anchor of the " + noun + " --as NAME (default: the same name) of the\n" +
			"upstream directory --from as an alias, so an import that carries it resolves to <name>.\n" +
			"Owners whose member sets differ cannot be merged: add the missing member to one of them first.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			if from == "" {
				return fmt.Errorf("merge needs --from DIR, the upstream directory that holds the other %s", noun)
			}
			if a.d.OpenUpstreamSource == nil {
				return fmt.Errorf("merge is not available in this build")
			}
			if as == "" {
				as = args[0]
			}
			ctx := cmd.Context()
			src, err := a.d.OpenUpstreamSource(from)
			if err != nil {
				return err
			}
			listing, err := src.List(ctx)
			if err != nil {
				return err
			}
			var derived *labels.Derived
			if err := src.View(ctx, func(r ports.NamedReader) error {
				var e error
				derived, e = labels.Derive(r, listing.Entries)
				return e
			}); err != nil {
				return err
			}
			other, ok := derived.Owner(kind, as)
			if !ok {
				return fmt.Errorf("%s holds no %s %q with a key that anchors it", from, noun, as)
			}
			s, err := a.open(ctx)
			if err != nil {
				return err
			}
			defer s.closeInto(&err)
			if err = s.Anchored.Update(ctx, func(w ports.Writer) error { return labels.Merge(w, kind, args[0], other) }); err != nil {
				return fmt.Errorf("merge %s %s: %w", noun, args[0], err)
			}
			fmt.Fprintf(a.d.Out, "The %s %s now also stands for the anchor %s of %q in %s.\n", noun, args[0], other.Anchor, as, from)
			return nil
		},
	}
	cmd.Flags().StringVar(&from, "from", "", "the upstream directory that holds the other "+noun)
	cmd.Flags().StringVar(&as, "as", "", "the name of the other "+noun+" in the directory (default: <name>)")
	return cmd
}
