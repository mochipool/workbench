package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/wallet"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// terminalConfirmer implements ports.Confirmer on the Terminal: it shows
// the summary the use case provides and asks, default No.
type terminalConfirmer struct{ a *app }

func (c terminalConfirmer) Confirm(ctx context.Context, sum ports.TxSummary) (bool, error) {
	if sum.Kind == "" || sum.Kind == "payment" {
		printTxSummary(c.a.d.Out, sum)
	} else {
		printStakeSummary(c.a.d.Out, sum)
	}
	ans, err := c.a.term.ReadLine(ctx, "Sign and "+routeVerb(sum.Route)+" this transaction? [y/N] ")
	if errors.Is(err, ErrNoTerminal) {
		return false, errors.New("no terminal to ask on; pass --yes to approve without asking")
	}
	if err != nil {
		return false, err
	}
	ans = strings.ToLower(strings.TrimSpace(ans))
	return ans == "y" || ans == "yes", nil
}

func routeVerb(route string) string {
	if route == "queue" {
		return "queue"
	}
	return "submit"
}

func lovelaceText(l chain.Lovelace) string {
	return fmt.Sprintf("%d.%06d ADA (%d lovelace)", uint64(l)/1_000_000, uint64(l)%1_000_000, uint64(l))
}

// printTxSummary writes what a payment does. It holds names, addresses,
// amounts and the transaction id, and no key material.
func printTxSummary(w io.Writer, s ports.TxSummary) {
	fmt.Fprintf(w, "\nPayment\n")
	if s.SourceAddr != "" {
		fmt.Fprintf(w, "  from         %s (%s)\n", s.Source, s.SourceAddr)
	} else {
		fmt.Fprintf(w, "  from         %s\n", s.Source)
	}
	if s.DestAddr != "" {
		fmt.Fprintf(w, "  to           %s (%s)\n", s.Destination, s.DestAddr)
	} else {
		fmt.Fprintf(w, "  to           %s\n", s.Destination)
	}
	fmt.Fprintf(w, "  amount       %s\n", s.Amount)
	fmt.Fprintf(w, "  inputs       %d\n", s.Inputs)
	for i, o := range s.Outputs {
		var label string
		switch {
		case s.DestAddr != "" && o.Address == s.DestAddr:
			label = "to destination"
		case s.DestAddr != "":
			label = "change"
		case i == 0:
			label = "to destination"
		default:
			label = "change"
		}
		fmt.Fprintf(w, "  %-14s %s  %s\n", label, o.Address, lovelaceText(o.Lovelace))
		for _, as := range o.Assets {
			name := fmt.Sprintf("%x", as.Asset.Policy[:])
			if len(as.Asset.Name) > 0 {
				name += fmt.Sprintf(".%x", as.Asset.Name)
			}
			fmt.Fprintf(w, "  %-14s   + %d %s\n", "", as.Quantity, name)
		}
	}
	fmt.Fprintf(w, "  fee          %s\n", lovelaceText(s.Fee))
	fmt.Fprintf(w, "  valid until  slot %d\n", s.TTL)
	for _, m := range s.Message {
		fmt.Fprintf(w, "  message      %s\n", m)
	}
	if s.Size > 0 {
		fmt.Fprintf(w, "  size         %d bytes\n", s.Size)
	}
	fmt.Fprintf(w, "  tx id        %s\n", s.TxID)
	if s.Route != "" {
		fmt.Fprintf(w, "  route        %s\n", s.Route)
	}
	fmt.Fprintln(w)
}

func (a *app) walletCommand() *cobra.Command {
	w := &cobra.Command{Use: "wallet", Short: "Payment wallets"}
	var (
		messages []string
		yes      bool
		flags    chainFlags
	)
	send := &cobra.Command{
		Use:   "send <from> <to> <amount> [--message TEXT]... [--yes] [--transfer-file PATH]",
		Short: "Send lovelace (and every asset of the source) from a stored wallet",
		Long: `Build, sign and send a payment. <from> names a stored wallet; <to> is a stored
address name or a payment address; <amount> is a number of lovelace, ALL or
ALLFUNDS (everything), or MIN (the least the destination can take). Every UTxO
of the source is spent; the change returns to it.

The summary is shown and you are asked before anything is signed; the default
answer is No. --yes approves without asking (the summary is still printed).

Offline mode reads the UTxOs and the protocol parameters from the offline
transfer file (--transfer-file, default ` + TransferFileName + ` in the workspace directory)
and appends the signed transaction to it for an online machine to submit.
Light mode submits through the chain provider. --message adds a CIP-20 line
(at most 64 bytes; repeatable).`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec := envSpec{flags: &flags, config: true, needs: []Need{
				CapSigners, CapGenesis, CapTip, CapParams, CapUtxos,
				CapAddress, CapMinOut, CapFees, CapBodies, CapAssemble,
				OneOf(CapSubmit, CapQueue),
			}}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, o WireOptions) error {
				uc := wallet.SendLovelaces{
					Store: s.Store, Signers: env.Signers, Utxos: env.Utxos, Params: env.Params, Tip: env.Tip,
					Addresses: env.AddressInspector, Min: env.MinOutputCalculator, Fees: env.FeeEstimator,
					Bodies: env.TxBodyBuilder, Assembler: env.TxAssembler, Confirmer: terminalConfirmer{a},
					Submitter: env.Submitter, Queue: env.Queue, NetworkID: env.NetworkID,
				}
				if env.Submitter != nil && env.Queue != nil {
					// The use case takes exactly one; a mode that has a
					// provider submits.
					uc.Queue = nil
				}
				if yes {
					uc.Approval = wallet.ApprovalSkip
				}
				req := wallet.SendRequest{Source: args[0], Destination: args[1], Amount: args[2], Message: messages}
				res, err := uc.Run(ctx, req)
				if err != nil {
					if errors.Is(err, wallet.ErrDeclined) {
						return fmt.Errorf("%w: nothing was signed, submitted or queued", err)
					}
					return err
				}
				if res.ApprovalSkipped {
					printTxSummary(a.d.Out, ports.TxSummary{
						Kind: "payment", Source: args[0], Destination: res.Destination, Amount: req.Amount,
						Inputs: res.Inputs, Outputs: res.Outputs, Fee: res.Fee, TTL: res.TTL, Message: messages,
						Size: res.Size, TxID: res.TxID, Route: routeOf(res),
					})
				}
				switch {
				case res.Submitted:
					fmt.Fprintf(a.d.Out, "Submitted transaction %s through %s.\n", res.TxID, env.Source(CapSubmit))
				case res.Queued:
					fmt.Fprintf(a.d.Out, "Queued transaction %s in %s. Submit it from an online machine.\n", res.TxID, o.TransferFile)
				}
				return nil
			})
		},
	}
	send.Flags().StringArrayVar(&messages, "message", nil, "CIP-20 message line, at most 64 bytes (repeatable)")
	send.Flags().BoolVar(&yes, "yes", false, "approve without asking (the summary is still printed)")
	addChainFlags(send, &flags, true)
	w.AddCommand(a.walletNewCommand(), send, a.claimRewardsCommand())
	return w
}

func routeOf(r wallet.SendResult) string {
	if r.Queued {
		return "queue"
	}
	return "submit"
}
