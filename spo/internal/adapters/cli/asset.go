package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	appassets "github.com/mochipool/workbench/spo/internal/app/assets"
	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/app/wallet"
	"github.com/mochipool/workbench/spo/internal/domain/assets"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// assetTxNeeds are the needs of every asset transaction.
func assetTxNeeds(extra ...Need) []Need { return stakeTxNeeds(extra...) }

// selectionWords turns the `<asset>[=amount]` arguments into the one word of
// upstream's grammar, `asset amount|asset amount`, for assets.ParseSelections.
// The reference and the amount keep their upstream forms; nothing is judged
// here.
func selectionWords(args []string) string {
	parts := make([]string, 0, len(args))
	for _, a := range args {
		ref, amount, has := strings.Cut(a, "=")
		if has {
			parts = append(parts, ref+" "+amount)
		} else {
			parts = append(parts, ref)
		}
	}
	return strings.Join(parts, "|")
}

func (a *app) walletSendAssetsCommand() *cobra.Command {
	var (
		messages []string
		yes      bool
		sum      bool
		flags    chainFlags
		extra    extraFlags
	)
	cmd := &cobra.Command{
		Use:   "send-assets <from> <to> <asset>[=amount]... [--lovelace N] [--sum-duplicates] [--yes] [--transfer-file PATH]",
		Short: "Send native assets (with the lovelace they need) from a stored wallet",
		Long: `Send native assets from a stored wallet to a stored address or a payment
address. Each <asset> names what to send, with its amount after an equals sign:

  <policy hex>.<name>=100      an asset by policy id and name
  <policy+name hex>=100         an asset by its hex id
  asset1...=100                 an asset by its CIP-14 fingerprint
  <policy hex>.<prefix>*=ALL    every asset of a policy whose name starts so
  <name>.asset=100              the asset of a stored asset record (spo asset mint)
  ALLASSETS or FORCEADA         every asset of the inputs

The amount is a positive number or ALL. An asset named twice is refused unless
--sum-duplicates adds the amounts. The outputs carry the lovelace the ledger
requires; --lovelace N sends at least that much with the assets. The summary is
shown and you are asked before anything is signed (default No; --yes approves).

Extra parameters are flags, as for spo wallet send: --message, --metadata-file,
--encrypt-messages, --utxo-limit, --only-utxo-with-asset, --skip-utxo-with-asset,
--input; and --keep-policy ID for ALLASSETS.`,
		Args: cobra.MinimumNArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			sels, err := assets.ParseSelections(selectionWords(args[2:]), "")
			if err != nil {
				return err
			}
			spec := envSpec{flags: &flags, config: true, extras: &extra, needs: assetTxNeeds()}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, o WireOptions) error {
				uc := wallet.SendAssets{
					Store: s.Store, Signers: env.Signers, Utxos: env.Utxos, Params: env.Params, Tip: env.Tip,
					Addresses: env.AddressInspector, Min: env.MinOutputCalculator, Fees: env.FeeEstimator,
					Bodies: env.TxBodyBuilder, Assembler: env.TxAssembler, Confirmer: terminalConfirmer{a},
					Submitter: env.Submitter, Queue: env.Queue, NetworkID: env.NetworkID,
					Files: env.MetadataFiles, Encrypter: env.MsgEncrypter, Canonicalizer: env.Canonicalizer, Handles: env.Handles,
				}
				if env.Submitter != nil && env.Queue != nil {
					uc.Queue = nil
				}
				if yes {
					uc.Approval = wallet.ApprovalSkip
				}
				res, err := uc.Run(ctx, wallet.SendAssetsRequest{Source: args[0], Destination: args[1], Selections: sels,
					SumDuplicates: sum, Message: messages, Extras: extra.ex, Passphrase: extra.pass})
				if err != nil {
					if errors.Is(err, wallet.ErrDeclined) {
						return fmt.Errorf("%w: nothing was signed, submitted or queued", err)
					}
					return err
				}
				for _, w := range res.Warnings {
					fmt.Fprintf(a.d.Out, "Warning: %s\n", w)
				}
				if res.ApprovalSkipped {
					printStakeSummary(a.d.Out, ports.TxSummary{Kind: "asset payment", Source: args[0], Destination: res.Destination,
						Amount: fmt.Sprintf("%d asset type(s)", len(res.Sent)), Inputs: res.Inputs, Outputs: res.Outputs, Fee: res.Fee,
						TTL: res.TTL, Message: messages, Size: res.Size, TxID: res.TxID, Route: routeName(res.Queued)})
				}
				printSent(a.d.Out, res.Sent)
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
	cmd.Flags().StringArrayVar(&messages, "message", nil, "CIP-20 message line, at most 64 bytes (repeatable)")
	cmd.Flags().BoolVar(&yes, "yes", false, "approve without asking (the summary is still printed)")
	cmd.Flags().BoolVar(&sum, "sum-duplicates", false, "add up the amounts of an asset that is named more than once (default: refuse)")
	extra.add(cmd, &messages, extraAssets)
	addSubmitFlags(cmd, &flags, true)
	return cmd
}

func printSent(w io.Writer, sent []chain.AssetAmount) {
	for _, s := range sent {
		fmt.Fprintf(w, "Sent %d %s\n", s.Quantity, assetText(s.Asset))
	}
}

// ---- policy ----

func (a *app) policyCommand() *cobra.Command {
	p := &cobra.Command{Use: "policy", Short: "Native asset minting policies"}
	var (
		lifetime uint64
		flags    chainFlags
		hw       hardwareFlags
	)
	newCmd := &cobra.Command{
		Use:   "new <name> [--lifetime SLOTS]",
		Short: "Create a minting policy: a key, the script that requires its signature, the policy id",
		Long: `Create the policy <name>: a signing key (kept in the workspace like every
key), the native script that requires its signature, and the policy id. With
--lifetime SLOTS the script also expires that many slots after the current
slot, which needs the chain's clock (offline: the system clock and the
genesis); without it the policy never expires. The signing key never appears
on the screen; mint and burn use it from the workspace.

--hardware makes the policy key on a hardware wallet (path 1855H/1815H/0H) and
asks the device for the policy id, which must equal the id computed from the
script. ` + hardwareUntested,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := hw.validate(cmd); err != nil {
				return err
			}
			needs := []Need{CapPaymentKeys, CapPolicyID}
			if hw.on {
				needs = []Need{CapHardware, CapPolicyID}
			}
			if lifetime > 0 {
				needs = append(needs, CapGenesis, CapTip)
			}
			spec := envSpec{flags: &flags, config: lifetime > 0, needs: needs}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				if hw.on {
					a.noteDevice()
				}
				res, err := appassets.GeneratePolicy{Store: s.Store, KeyGen: env.PaymentKeys, Policies: env.PolicyIDs, Tip: env.Tip,
					Hardware: env.Hardware, PolicyIDer: env.PolicyIDer}.
					Run(ctx, appassets.GeneratePolicyRequest{Name: args[0], Lifetime: lifetime, Holder: hw.holder()})
				if err != nil {
					return err
				}
				w := a.d.Out
				fmt.Fprintf(w, "Created the policy %s.\n  policy id   %s\n  key hash    %s\n", res.Name, res.PolicyID, res.KeyHash)
				if res.Limited {
					fmt.Fprintf(w, "  valid until slot %d\n", res.Expiry)
				} else {
					fmt.Fprintln(w, "  valid       without a time limit")
				}
				return nil
			})
		},
	}
	newCmd.Flags().Uint64Var(&lifetime, "lifetime", 0, "make the policy expire this many slots from now (default: never)")
	hw.add(newCmd, 0)
	addChainFlags(newCmd, &flags, false)
	p.AddCommand(newCmd)
	return p
}

// ---- asset ----

func (a *app) assetCommand() *cobra.Command {
	c := &cobra.Command{Use: "asset", Short: "Mint and burn native assets, and show their records"}
	c.AddCommand(a.assetMintBurnCommand(false), a.assetMintBurnCommand(true), a.assetShowCommand(), a.assetSettleCommand())
	return c
}

func (a *app) assetMintBurnCommand(burn bool) *cobra.Command {
	var (
		messages []string
		yes      bool
		flags    chainFlags
		extra    extraFlags
	)
	verb, past := "mint", "minted"
	if burn {
		verb, past = "burn", "burned"
	}
	cmd := &cobra.Command{
		Use:   verb + " <policy.asset> <amount> <payer> [--yes] [--transfer-file PATH]",
		Short: strings.ToUpper(verb[:1]) + verb[1:] + " an amount of an asset under a stored policy",
		Long: `<policy.asset> is the policy name, a dot and the asset name (letters and
digits, or {hex}). <amount> is a positive number. <payer> names the stored
address that pays the fee and receives the asset. The policy key and the
payer's key sign. The summary is shown and you are asked before anything is
signed (default No; --yes approves).

The asset record <policy>.<asset> keeps what was ` + past + `. With a transaction that is
sent at once the record is updated then. A transaction that is only queued
(offline mode) leaves the record as it is: the update waits in the workspace
under the transaction's id and also travels in the queue entry of the transfer
file. spo offline execute applies it on the machine that submits it when that
machine holds the record; the submission is recorded in the transfer file's
history, and on the machine that queued the mint spo asset settle applies it
once the file is carried back. Show it with: spo asset show <policy.asset>.

The extra parameters are flags: --message, --metadata-file, --encrypt-messages
and --input TXHASH#IX.`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			needs := assetTxNeeds(CapPolicyID, CapClock)
			spec := envSpec{flags: &flags, config: true, extras: &extra, needs: needs}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, o WireOptions) error {
				base := appassets.Base{
					Store: s.Store, Signers: env.Signers, Utxos: env.Utxos, Params: env.Params, Tip: env.Tip,
					Addresses: env.AddressInspector, Policies: env.PolicyIDs, Min: env.MinOutputCalculator, Fees: env.FeeEstimator,
					Bodies: env.TxBodyBuilder, Assembler: env.TxAssembler, Confirmer: terminalConfirmer{a},
					Submitter: env.Submitter, Queue: env.Queue, Clock: env.Clock, NetworkID: env.NetworkID,
					Files: env.MetadataFiles, Encrypter: env.MsgEncrypter, Canonicalizer: env.Canonicalizer,
				}
				if env.Submitter != nil && env.Queue != nil {
					base.Queue = nil
				}
				if yes {
					base.Approval = txflow.ApprovalSkip
				}
				req := appassets.Request{Asset: args[0], Amount: args[1], Payer: args[2], Message: messages, Extras: extra.ex, Passphrase: extra.pass}
				var res appassets.Result
				var err error
				if burn {
					res, err = appassets.BurnAsset{Base: base}.Run(ctx, req)
				} else {
					res, err = appassets.MintAsset{Base: base}.Run(ctx, req)
				}
				if err != nil {
					if errors.Is(err, txflow.ErrDeclined) {
						return fmt.Errorf("%w: nothing was signed, submitted or queued", err)
					}
					if res.TxID != (chain.TxID{}) {
						a.reportAsset(verb, args, res, env, o, messages)
					}
					return err
				}
				a.reportAsset(verb, args, res, env, o, messages)
				return nil
			})
		},
	}
	cmd.Flags().StringArrayVar(&messages, "message", nil, "CIP-20 message line, at most 64 bytes (repeatable)")
	cmd.Flags().BoolVar(&yes, "yes", false, "approve without asking (the summary is still printed)")
	extra.add(cmd, &messages, extraMint)
	addSubmitFlags(cmd, &flags, true)
	return cmd
}

func (a *app) reportAsset(verb string, args []string, res appassets.Result, env *Env, o WireOptions, messages []string) {
	w := a.d.Out
	if res.ApprovalSkipped {
		printStakeSummary(w, ports.TxSummary{Kind: "asset " + verb, Source: args[2], Destination: args[2],
			Amount: args[1] + " " + args[0], Inputs: res.Inputs, Outputs: res.Outputs, Fee: res.Fee, TTL: res.TTL,
			Message: messages, Size: res.Size, TxID: res.TxID, Route: routeName(res.Queued)})
	}
	switch {
	case res.Submitted:
		fmt.Fprintf(w, "Submitted transaction %s through %s.\n", res.TxID, env.Source(CapSubmit))
	case res.Queued:
		fmt.Fprintf(w, "Queued transaction %s in %s. Submit it from an online machine.\n", res.TxID, o.TransferFile)
	}
	switch {
	case res.RecordUpdated:
		fmt.Fprintf(w, "Updated the asset record %s.\n", res.Record)
	case res.RecordPending:
		fmt.Fprintf(w, "The asset record %s is updated when spo offline execute submits this transaction.\n", res.Record)
	}
}

func (a *app) assetShowCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "show <policy.asset>",
		Short: "Show the record of an asset: what was minted and burned",
		Long: `Print the asset record <policy>.<asset>. Its "minted" is the amount minted minus
the amount burned, as far as this workspace knows: a mint or burn that is only
queued is not counted until it has been submitted. The record holds no secret.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ref, err := assets.ParseRef(args[0])
			if err != nil {
				return err
			}
			if _, err := appassets.PolicyName(ref.Policy); err != nil {
				return err
			}
			if _, err := assets.ParseName(ref.Asset); err != nil {
				return err
			}
			rec := assets.RecordName(ref.Policy, ref.Asset)
			return a.withEnv(cmd, envSpec{}, func(ctx context.Context, s *session, _ *Env, _ WireOptions) error {
				var b []byte
				err := s.Store.View(ctx, func(r ports.Reader) error {
					var e error
					b, e = r.Get(ports.Ref{Name: rec, Kind: ports.AssetFile})
					return e
				})
				if errors.Is(err, ports.ErrNotFound) {
					fmt.Fprintf(a.d.Out, "No record for %s: nothing was minted or burned yet. A queued transaction counts when spo offline execute has submitted it.\n", rec)
					return nil
				}
				if err != nil {
					return err
				}
				r, err := assets.ParseRecord(b)
				if err != nil {
					return fmt.Errorf("%s: %w", rec, err)
				}
				fmt.Fprintf(a.d.Out, "Asset record %s\n", rec)
				_, err = a.d.Out.Write(r.Marshal())
				return err
			})
		},
	}
}

func (a *app) assetSettleCommand() *cobra.Command {
	var tf string
	var dry, discard bool
	cmd := &cobra.Command{
		Use:   "settle [--dry-run] [--transfer-file PATH]",
		Short: "Apply the results of submitted mints and burns to the asset records",
		Long: `Read the history of the transfer file that came back from the online machine
and apply, to the asset records of this workspace, each queued mint or burn
that spo offline execute submitted. Each update is applied once: a second run
changes nothing.

A queued mint or burn that this transfer file knows nothing about (neither
queued nor submitted) is reported and kept: the file may be the wrong one. If
its transaction was removed with spo offline clear transactions, pass
--discard-unmatched to drop the update; it is never applied. One that is still
in the queue waits. --dry-run shows what would happen and changes nothing.

Run it on the machine that holds the policy key and the asset record, with the
transfer file that was carried back.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f := chainFlags{transfer: tf}
			spec := envSpec{flags: &f, config: true, needs: []Need{CapBundle, CapClock}}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, o WireOptions) error {
				uc := appassets.SettleFromBundle{Store: s.Store, Bundle: env.Bundle, Clock: env.Clock, DiscardUnmatched: discard}
				if l, ok := any(s.Store).(ports.SourceLister); ok {
					uc.Lister = l
				} else if s.Sealed != nil {
					if l, ok := any(s.Sealed).(ports.SourceLister); ok {
						uc.Lister = l
					}
				}
				var res appassets.SettleResult
				var err error
				if dry {
					res, err = uc.Plan(ctx)
				} else {
					res, err = uc.Run(ctx)
				}
				if err != nil {
					if errors.Is(err, appassets.ErrNoTransferFile) {
						return fmt.Errorf("%w (%s)", err, o.TransferFile)
					}
					return err
				}
				w := a.d.Out
				verb := map[bool]string{false: "Applied", true: "Would apply"}[dry]
				for _, x := range res.Applied {
					fmt.Fprintf(w, "%s %s to the asset record %s (transaction %s).\n", verb, shown(fmt.Sprint(x.Action)), shown(x.Record), shown(fmt.Sprint(x.TxID)))
				}
				for _, x := range res.Discarded {
					fmt.Fprintf(w, "Notice: the transaction %s (%s on %s) is not in the queue and was not submitted: its update is %s, never applied.\n",
						shown(fmt.Sprint(x.TxID)), shown(fmt.Sprint(x.Action)), shown(x.Record), map[bool]string{false: "discarded", true: "to be discarded"}[dry])
				}
				for _, x := range res.Unmatched {
					fmt.Fprintf(w, "Unmatched: %s knows nothing of the transaction %s (%s on %s). Its update is kept. If the transaction was cleared from the queue, run again with --discard-unmatched.\n",
						o.TransferFile, shown(fmt.Sprint(x.TxID)), shown(fmt.Sprint(x.Action)), shown(x.Record))
				}
				for _, x := range res.Waiting {
					fmt.Fprintf(w, "Waiting: the transaction %s (%s on %s) is still queued.\n", shown(fmt.Sprint(x.TxID)), shown(fmt.Sprint(x.Action)), shown(x.Record))
				}
				if res.NoListing {
					fmt.Fprintln(w, "Note: this workspace cannot list its pending updates, so updates of removed transactions were not looked for.")
				}
				if len(res.Applied)+len(res.Discarded)+len(res.Waiting)+len(res.Unmatched) == 0 {
					fmt.Fprintf(w, "Nothing to settle: %s reports no submitted update that waits in this workspace.\n", o.TransferFile)
				}
				return nil
			})
		},
	}
	addTransferFlag(cmd, &tf)
	cmd.Flags().BoolVar(&dry, "dry-run", false, "show what would be applied or discarded, change nothing")
	cmd.Flags().BoolVar(&discard, "discard-unmatched", false, "drop pending updates whose transaction this transfer file does not know (use after clearing the queue)")
	return cmd
}
