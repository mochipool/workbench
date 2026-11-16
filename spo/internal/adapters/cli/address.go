package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/query"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

func (a *app) addressCommand() *cobra.Command {
	var flags chainFlags
	cmd := &cobra.Command{
		Use:   "address <name|address> [--offline] [--transfer-file PATH]",
		Short: "Show the UTxOs, assets and rewards of an address",
		Long: `Show what an address holds: for a payment address its UTxOs with lovelace and
native assets (with CIP-14 fingerprints) and the totals; for a stake address
its registration deposit, rewards, pool and vote delegation. <name> is a stored
address (NAME, or NAME.staking for the stake address); an address is used as
given. Every fact is printed with the source that stated it.

In offline mode the answer comes from the offline transfer file, which is a
snapshot: the date of the snapshot is printed and the answer is that old.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec := envSpec{flags: &flags, needs: []Need{CapAddress, OneOf(CapUtxos, CapRewards)}}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, o WireOptions) error {
				uc := query.QueryAddress{Store: s.Store, Addresses: env.AddressInspector, Utxos: env.Utxos,
					Rewards: env.Rewards, Pools: env.Pools, Sync: env.Sync, Handles: env.Handles}
				if o.Mode == ModeOffline {
					// The answer is a snapshot: have the use case say how old.
					uc.Snapshot = env.Bundle
				}
				rep, err := uc.Run(ctx, args[0])
				if err != nil {
					return err
				}
				printAddressReport(a.d.Out, rep)
				return nil
			})
		},
	}
	addChainFlags(cmd, &flags, true)
	return cmd
}

func assetName(policy, nameHex, nameText string) string {
	n := policy
	if nameHex != "" {
		n += "." + nameHex
	}
	if nameText != "" {
		n += " (" + shown(nameText) + ")"
	}
	return n
}

func printAddressReport(w io.Writer, r query.AddressReport) {
	src := "[" + string(r.Source) + "]"
	name := ""
	if r.Name != "" {
		name = shown(r.Name) + " "
	}
	fmt.Fprintf(w, "%s address %s%s\n", map[string]string{"payment": "Payment", "stake": "Stake"}[r.Kind], name, r.Address)
	if h := r.Handle; h != nil {
		fmt.Fprintf(w, "  ADA Handle   %s resolved to %s (%s handle, verified against the chain: %s)\n", shown(h.Handle), r.Address, shown(string(h.Kind)), shown(h.VerifiedBy))
	}
	if r.FromSnapshot || r.SnapshotDate != "" {
		used := "unused"
		if r.SnapshotUsed {
			used = "used"
		}
		fmt.Fprintf(w, "  snapshot     as of %s (%s); this is not the chain as it is now\n", shown(r.SnapshotDate), used)
	}
	fmt.Fprintf(w, "  source       %s\n", shown(string(r.Source)))
	switch r.Kind {
	case "payment":
		fmt.Fprintf(w, "  UTxOs        %d  %s\n", len(r.Utxos), src)
		for _, u := range r.Utxos {
			fmt.Fprintf(w, "    %s  %s\n", u.Ref, lovelaceText(u.Lovelace))
			for _, as := range u.Assets {
				fmt.Fprintf(w, "      + %d %s\n", as.Quantity, assetName(as.Policy, as.NameHex, as.NameText))
			}
			if u.HasDatumHash {
				fmt.Fprintf(w, "      datum hash %s\n", shown(u.DatumHash))
			}
		}
		fmt.Fprintf(w, "  total        %s  %s\n", lovelaceText(r.TotalLovelace), src)
		if len(r.Assets) > 0 {
			fmt.Fprintf(w, "  assets       %d type(s)\n", len(r.Assets))
			for _, as := range r.Assets {
				fmt.Fprintf(w, "    %d %s\n      fingerprint %s\n", as.Quantity, assetName(as.Policy, as.NameHex, as.NameText), shown(as.Fingerprint))
			}
		}
	case "stake":
		fmt.Fprintf(w, "  deposit      %s  %s\n", readingText(r.Deposit, "none", lovelaceText), src)
		fmt.Fprintf(w, "  rewards      %s  %s\n", lovelaceText(r.Rewards), src)
		fmt.Fprintf(w, "  pool         %s  %s\n", readingText(r.Pool, "not delegated", func(p chain.PoolID) string { return p.Bech32() }), src)
		if st, ok := r.PoolInfo.Get(); ok {
			fmt.Fprintf(w, "               %s (%s)\n", shown(st.Ticker), shown(st.Name))
		}
		fmt.Fprintf(w, "  vote         %s  %s\n", readingText(r.VoteDelegation, "no vote delegation", shown), src)
		fmt.Fprintf(w, "  gov deposits %s  %s\n", readingText(r.GovDeposits, "none", func(g []chain.GovActionDeposit) string {
			if len(g) == 0 {
				return "none"
			}
			s := ""
			for i, d := range g {
				if i > 0 {
					s += ", "
				}
				s += fmt.Sprintf("%s %s", d.Action, lovelaceText(d.Amount))
			}
			return s
		}), src)
	}
}
