package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/stake"
	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/app/wallet"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	stk "github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Help text of the two policy flags. They never default to on: each one
// names exactly what it gives up.
const (
	allowUnverifiedHelp = "go on when a chain check cannot be made (no reader in this mode, or the source does not know the answer): " +
		"the stake address registration state, the pool or DRep registration. A wrong answer only makes the ledger reject the transaction. " +
		"The summary lists every check that was skipped"
	singleSourceHelp = "accept a read that rests on ONE chain source: the reward balance, the deposit or the pool registration, " +
		"with no second independent source to corroborate it. A false answer from one provider can cost the deposit or the rewards. " +
		"The summary says the read rested on a single source"
)

// stakeFlags are the flags the stake transaction commands share.
type stakeFlags struct {
	chain    chainFlags
	messages []string
	// extra are the extra-parameter flags of the commands that put a
	// transaction on the chain with a certificate (metadata files, encryption).
	extra extraFlags
	yes   bool
	payer string
	// stored makes a delegation use the certificate already stored.
	stored bool

	allowUnverified bool
	singleSource    bool
	// hasAllow and hasSingle say which policy flags the command offers, for
	// the hint of a refusal.
	hasAllow, hasSingle bool
}

func (f *stakeFlags) add(cmd *cobra.Command, payer, allow, single bool) {
	cmd.Flags().StringArrayVar(&f.messages, "message", nil, "CIP-20 message line, at most 64 bytes (repeatable)")
	cmd.Flags().BoolVar(&f.yes, "yes", false, "approve without asking (the summary is still printed)")
	if payer {
		cmd.Flags().StringVar(&f.payer, "payer", "", "name of the stored address that pays the fee")
	}
	if allow {
		f.hasAllow = true
		cmd.Flags().BoolVar(&f.allowUnverified, "allow-unverified", false, allowUnverifiedHelp)
	}
	if single {
		f.hasSingle = true
		cmd.Flags().BoolVar(&f.singleSource, "single-source", false, singleSourceHelp)
	}
	addSubmitFlags(cmd, &f.chain, true)
}

func (f *stakeFlags) policy() stake.SourcePolicy {
	if f.singleSource {
		return stake.SingleSourceAcknowledged
	}
	return stake.RequireCorroboration
}

// hint adds to a refusal the flag that would let the operator go on, and
// what it gives up. A flag the operator already gave is not suggested.
func (f *stakeFlags) hint(err error) error {
	if err == nil {
		return nil
	}
	var h string
	switch {
	case errors.Is(err, stake.ErrDeclined):
		return fmt.Errorf("%w: nothing was signed, submitted or queued", err)
	case f.hasSingle && !f.singleSource && errors.Is(err, stake.ErrSingleSource):
		h = "pass --single-source to go on with one source: a false answer from one provider can cost the deposit or the rewards; the summary will say so"
	case f.hasAllow && !f.allowUnverified && (errors.Is(err, stake.ErrNoChainReader) || errors.Is(err, stake.ErrUnverified) || errors.Is(err, stk.ErrUnknown)):
		h = "pass --allow-unverified to go on without that check (an unchecked answer only makes the ledger reject the transaction); the summary lists every check that was skipped"
	default:
		return err
	}
	return &explained{msg: err.Error() + "\n" + h, err: err}
}

// stakeTxNeeds are the needs of every stake transaction.
func stakeTxNeeds(extra ...Need) []Need {
	return append([]Need{
		CapSigners, CapGenesis, CapTip, CapParams, CapUtxos,
		CapAddress, CapMinOut, CapFees, CapBodies, CapAssemble,
		OneOf(CapSubmit, CapQueue),
	}, extra...)
}

// pipeline is the shared tail of a transaction use case: exactly one of
// the submitter and the queue (a mode that has a provider submits).
func (a *app) pipeline(s *session, env *Env, yes bool) txflow.Pipeline {
	p := txflow.Pipeline{
		Signers: env.Signers, Min: env.MinOutputCalculator, Fees: env.FeeEstimator, Bodies: env.TxBodyBuilder,
		Assembler: env.TxAssembler, Confirmer: terminalConfirmer{a}, Submitter: env.Submitter, Queue: env.Queue,
		Canonicalizer: env.Canonicalizer,
	}
	if n := env.SharedHostNote(); n != "" {
		p.SourceNotes = []string{n}
	}
	if p.Submitter != nil && p.Queue != nil {
		p.Queue = nil
	}
	if yes {
		p.Approval = txflow.ApprovalSkip
	}
	return p
}

func (a *app) stakeBase(s *session, env *Env, yes bool) stake.Base {
	return stake.Base{
		Store: s.Store, Addresses: env.AddressInspector, Params: env.Params, Tip: env.Tip, Utxos: env.Utxos,
		Pipeline: a.pipeline(s, env, yes), NetworkID: env.NetworkID,
		Files: env.MetadataFiles, Encrypter: env.MsgEncrypter,
	}
}

// outcome is what a stake transaction command reports.
type outcome struct {
	kind    string
	account string
	payer   string
	stake.Result
	// stored are the artefacts written, by name.
	stored []ports.NamedRef
}

// stakeWallet is the wallet name a stake name is kept under: the use cases
// accept `name` and `name.staking` for the same account.
func stakeWallet(s string) string {
	return strings.TrimSuffix(strings.TrimPrefix(s, "./"), ".staking")
}

func artefact(r ports.NamedRef) string { return r.Name + "." + string(r.Kind) }

// report prints what happened after a transaction was sent or queued. With
// --yes no summary was shown before, so it is printed here, with what the
// use case returned.
func (a *app) report(o outcome, f *stakeFlags, env *Env, wo WireOptions) {
	w := a.d.Out
	if o.ApprovalSkipped {
		sum := ports.TxSummary{
			Kind: o.kind, Account: o.account, Source: o.payer, Inputs: o.Inputs, Outputs: o.Outputs, Fee: o.Fee, TTL: o.TTL, Message: f.messages,
			Size: o.Size, TxID: o.TxID, Route: routeName(o.Queued), Deposit: o.Deposit, Refund: o.Refund,
			Sources: o.Sources, SingleSource: o.SingleSource, Unchecked: o.Unchecked,
		}
		if n := env.SharedHostNote(); n != "" && len(o.Sources) >= 2 {
			sum.Notes = []string{n}
		}
		printStakeSummary(w, sum)
	}
	switch {
	case o.Submitted:
		fmt.Fprintf(w, "Submitted transaction %s through %s.\n", o.TxID, env.Source(CapSubmit))
	case o.Queued:
		fmt.Fprintf(w, "Queued transaction %s in %s. Submit it from an online machine.\n", o.TxID, wo.TransferFile)
	}
	for _, r := range o.stored {
		fmt.Fprintf(w, "Stored %s.\n", artefact(r))
	}
}

func routeName(queued bool) string {
	if queued {
		return "queue"
	}
	return "submit"
}

// printStakeSummary writes what a stake operation does: the account, the
// attachments, the money that moves, and what the facts rest on. It holds
// names, addresses and amounts, and no key material.
func printStakeSummary(w io.Writer, s ports.TxSummary) {
	title := s.Kind
	if title != "" {
		title = strings.ToUpper(title[:1]) + title[1:]
	}
	fmt.Fprintf(w, "\n%s\n", title)
	if s.Account != "" {
		fmt.Fprintf(w, "  account      %s\n", shownAny(s.Account))
	}
	if s.StakeAddr != "" {
		fmt.Fprintf(w, "  stake addr   %s\n", shownAny(s.StakeAddr))
	}
	if s.Source != "" {
		if s.SourceAddr != "" {
			fmt.Fprintf(w, "  paid by      %s (%s)\n", shownAny(s.Source), shownAny(s.SourceAddr))
		} else {
			fmt.Fprintf(w, "  paid by      %s\n", shownAny(s.Source))
		}
	}
	if s.Destination != "" {
		if s.DestAddr != "" {
			fmt.Fprintf(w, "  to           %s (%s)\n", shownAny(s.Destination), shownAny(s.DestAddr))
		} else {
			fmt.Fprintf(w, "  to           %s\n", shownAny(s.Destination))
		}
	}
	if s.Amount != "" {
		fmt.Fprintf(w, "  amount       %s\n", shownAny(s.Amount))
	}
	for _, at := range s.Attachments {
		fmt.Fprintf(w, "  attaches     %s\n", shown(at))
	}
	if s.Withdrawal > 0 {
		fmt.Fprintf(w, "  withdrawal   %s\n", lovelaceText(s.Withdrawal))
	}
	if s.Deposit > 0 {
		fmt.Fprintf(w, "  deposit      %s (paid)\n", lovelaceText(s.Deposit))
	}
	if s.Refund > 0 {
		fmt.Fprintf(w, "  refund       %s (returned)\n", lovelaceText(s.Refund))
	}
	if s.Inputs > 0 {
		fmt.Fprintf(w, "  inputs       %d\n", s.Inputs)
	}
	for i, o := range s.Outputs {
		label := "output"
		if i == len(s.Outputs)-1 {
			label = "change"
		}
		fmt.Fprintf(w, "  %-12s %s  %s\n", label, shownAny(o.Address), lovelaceText(o.Lovelace))
		for _, as := range o.Assets {
			fmt.Fprintf(w, "  %-12s   + %d %s\n", "", as.Quantity, assetText(as.Asset))
		}
	}
	fmt.Fprintf(w, "  fee          %s\n", lovelaceText(s.Fee))
	if s.TTL > 0 {
		fmt.Fprintf(w, "  valid until  slot %d\n", s.TTL)
	}
	for _, m := range s.Message {
		fmt.Fprintf(w, "  message      %s\n", shown(shownAny(m)))
	}
	if s.Size > 0 {
		fmt.Fprintf(w, "  size         %d bytes\n", s.Size)
	}
	fmt.Fprintf(w, "  tx id        %s\n", shownAny(s.TxID))
	if s.Route != "" {
		fmt.Fprintf(w, "  route        %s\n", shownAny(s.Route))
	}
	if len(s.Sources) > 0 {
		names := make([]string, len(s.Sources))
		for i, src := range s.Sources {
			names[i] = shown(string(src))
		}
		fmt.Fprintf(w, "  checked via  %s\n", strings.Join(names, ", "))
	}
	if s.SingleSource {
		fmt.Fprintf(w, "  WARNING      a read this transaction rests on came from ONE source, acknowledged with --single-source; a false answer can cost the deposit or the rewards\n")
	}
	for _, u := range s.Unchecked {
		fmt.Fprintf(w, "  NOT CHECKED  %s\n", shown(u))
	}
	for _, n := range s.Notes {
		fmt.Fprintf(w, "  NOTE         %s\n", shown(n))
	}
	fmt.Fprintln(w)
}

func (a *app) stakeCommand() *cobra.Command {
	st := &cobra.Command{Use: "stake", Short: "Stake addresses: register, delegate, vote-delegate, deregister, status"}
	st.AddCommand(a.stakeRegisterCommand(), a.stakeDelegationCertCommand(), a.stakeDelegateCommand(),
		a.stakeVoteCertCommand(), a.stakeVoteDelegateCommand(), a.stakeDeregisterCommand(), a.stakeStatusCommand())
	return st
}

// ---- register ---------------------------------------------------------------

func (a *app) stakeRegisterCommand() *cobra.Command {
	var f stakeFlags
	cmd := &cobra.Command{
		Use:   "register <stake-name> <payer-name> [--message TEXT]... [--yes] [--allow-unverified] [--transfer-file PATH]",
		Short: "Register a stake address on the chain (pays the key deposit)",
		Long: `Register the stake address of a stored wallet. <payer-name> names the stored
address that pays the fee and the key deposit of the protocol parameters. The
stake key and the payment key sign.

The summary (account, stake address, deposit, sources, checks not made) is
shown and you are asked before anything is signed; the default answer is No.
The certificate is stored as <stake-name>.staking.cert only after the
transaction was sent or queued.

Whether the address is already registered is checked when the chain says so.
Offline, the transfer file holds only addresses that were registered when it
was made, so the answer is unknown and the command refuses until you pass
--allow-unverified.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec := envSpec{flags: &f.chain, config: true, needs: stakeTxNeeds(CapCerts), extras: &f.extra}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, wo WireOptions) error {
				uc := stake.RegisterStakeAddress{Base: a.stakeBase(s, env, f.yes), Certs: env.Certs, Rewards: env.Rewards, AllowUnverified: f.allowUnverified}
				res, err := uc.Run(ctx, stake.RegisterRequest{Stake: args[0], Payer: args[1], Message: f.messages, Extras: f.extra.ex, Passphrase: f.extra.pass})
				if err != nil {
					return f.hint(err)
				}
				a.report(outcome{kind: "stake registration", account: args[0], payer: args[1], Result: res,
					stored: []ports.NamedRef{{Name: stakeWallet(args[0]), Kind: ports.StakingCert}}}, &f, env, wo)
				return nil
			})
		},
	}
	f.add(cmd, false, true, false)
	f.extra.add(cmd, &f.messages, extraCert)
	return cmd
}

// ---- delegation -----------------------------------------------------------------

func (a *app) stakeDelegationCertCommand() *cobra.Command {
	var f stakeFlags
	cmd := &cobra.Command{
		Use:   "delegation-cert <pool-id|pool-name> <delegator-name>",
		Short: "Make the pool delegation certificate of a stake account (no chain, no transaction)",
		Long: `Make the certificate that delegates the stake key of <delegator-name> to a
pool and store it as <delegator-name>.deleg.cert, replacing an earlier one.
<pool> is a pool id (hex or pool1...) or the name of a stored pool. Nothing is
checked on the chain and nothing is sent: spo stake delegate --stored-cert puts
the stored certificate on the chain.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec := envSpec{flags: &f.chain, config: true, needs: []Need{CapCerts}}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				res, err := stake.GenerateDelegationCertificate{Store: s.Store, Certs: env.Certs}.Run(ctx, stake.DelegationRequest{Pool: args[0], Delegator: args[1]})
				if err != nil {
					return err
				}
				fmt.Fprintf(a.d.Out, "Stored %s.\n", artefact(res.Ref))
				return nil
			})
		},
	}
	addChainFlags(cmd, &f.chain, false)
	return cmd
}

func (a *app) stakeDelegateCommand() *cobra.Command {
	var f stakeFlags
	cmd := &cobra.Command{
		Use:   "delegate <delegator-name> <pool-id|pool-name> [--payer NAME] [--message TEXT]... [--yes] [--allow-unverified] [--single-source]\n  spo stake delegate <delegator-name> --stored-cert [--payer NAME] ...",
		Short: "Delegate a stake account to a pool",
		Long: `Make the delegation certificate (as spo stake delegation-cert) and put it on
the chain. The fee is paid by --payer, default <delegator-name>.payment (the
payment address that wallet new --stake makes). No deposit is paid.

--stored-cert skips the first step and uses the <delegator-name>.deleg.cert
already stored; then no pool is given.

The pool's registration is a read where a false answer is costly, so it needs a
second source or --single-source; a mode that cannot read pools at all needs
--allow-unverified, and the summary lists the check as not made.`,
		Args: func(cmd *cobra.Command, args []string) error {
			if f.stored {
				return cobra.ExactArgs(1)(cmd, args)
			}
			return cobra.ExactArgs(2)(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			needs := stakeTxNeeds(CapCertDecode, CapAddressMake)
			if !f.stored {
				needs = append(needs, CapCerts)
			}
			spec := envSpec{flags: &f.chain, config: true, needs: needs, extras: &f.extra}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, wo WireOptions) error {
				var stored []ports.NamedRef
				if !f.stored {
					gen, err := stake.GenerateDelegationCertificate{Store: s.Store, Certs: env.Certs}.Run(ctx, stake.DelegationRequest{Pool: args[1], Delegator: args[0]})
					if err != nil {
						return err
					}
					stored = append(stored, gen.Ref)
				}
				uc := stake.RegisterPoolDelegation{
					Base: a.stakeBase(s, env, f.yes), Certs: env.CertDecoder, Builder: env.Addresses,
					Pools: env.Pools, PoolCross: env.PoolCross, Rewards: env.Rewards, Sources: f.policy(), OnSingle: a.singleSourceHook(s, "spo stake delegate"), AllowUnverified: f.allowUnverified,
				}
				res, err := uc.Run(ctx, stake.DelegationRegisterRequest{Delegator: args[0], Payer: payerOr(f.payer, args[0]), Message: f.messages, Extras: f.extra.ex, Passphrase: f.extra.pass})
				if err != nil {
					return f.hint(err)
				}
				a.report(outcome{kind: "pool delegation", account: args[0], payer: payerOr(f.payer, args[0]), Result: res, stored: stored}, &f, env, wo)
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&f.stored, "stored-cert", false, "use the stored <delegator-name>.deleg.cert (made by spo stake delegation-cert) instead of making one")
	f.add(cmd, true, true, true)
	f.extra.add(cmd, &f.messages, extraCert)
	return cmd
}

// payerOr is the paying address of a delegation: --payer, else the payment
// address `wallet new --stake` makes with the stake account, <name>.payment.
func payerOr(flag, name string) string {
	if flag != "" {
		return flag
	}
	return stakeWallet(name) + ".payment"
}

// ---- vote delegation ------------------------------------------------------------

func (a *app) stakeVoteCertCommand() *cobra.Command {
	var f stakeFlags
	cmd := &cobra.Command{
		Use:   "vote-delegation-cert <drep-id|always-abstain|always-no-confidence> <delegator-name>",
		Short: "Make the vote delegation certificate of a stake account (no transaction)",
		Long: `Make the certificate that delegates the votes of <delegator-name> and store it
as <delegator-name>.vote-deleg.cert. The target is a DRep id, the name of a
stored DRep, always-abstain or always-no-confidence. The DRep is not checked
and nothing is sent: spo stake vote-delegate --stored-cert puts it on the chain.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec := envSpec{flags: &f.chain, config: true, needs: []Need{CapCerts}}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				res, err := stake.GenerateVoteDelegationCertificate{Store: s.Store, Certs: env.Certs, Params: env.Params}.
					Run(ctx, stake.VoteDelegationRequest{Target: args[0], Delegator: args[1]})
				if err != nil {
					return err
				}
				fmt.Fprintf(a.d.Out, "Stored %s.\n", artefact(res.Ref))
				return nil
			})
		},
	}
	addChainFlags(cmd, &f.chain, false)
	return cmd
}

func (a *app) stakeVoteDelegateCommand() *cobra.Command {
	var f stakeFlags
	cmd := &cobra.Command{
		Use:   "vote-delegate <delegator-name> <drep-id|always-abstain|always-no-confidence> [--payer NAME] [--message TEXT]... [--yes] [--allow-unverified]\n  spo stake vote-delegate <delegator-name> --stored-cert [--payer NAME] ...",
		Short: "Delegate the votes of a stake account to a DRep or a predefined choice",
		Long: `Make the vote delegation certificate (as spo stake vote-delegation-cert) and
put it on the chain. The fee is paid by --payer, default <delegator-name>.payment
(the payment address that wallet new --stake makes). A DRep must be registered; always-abstain and
always-no-confidence need no check.

--stored-cert uses the <delegator-name>.vote-deleg.cert already stored; then no
target is given.

A mode that cannot read DRep or stake address state needs --allow-unverified;
the summary lists each check that was not made.`,
		Args: func(cmd *cobra.Command, args []string) error {
			if f.stored {
				return cobra.ExactArgs(1)(cmd, args)
			}
			return cobra.ExactArgs(2)(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			needs := stakeTxNeeds(CapCertDecode, CapAddressMake)
			if !f.stored {
				needs = append(needs, CapCerts)
			}
			spec := envSpec{flags: &f.chain, config: true, needs: needs, extras: &f.extra}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, wo WireOptions) error {
				var stored []ports.NamedRef
				if !f.stored {
					gen, err := stake.GenerateVoteDelegationCertificate{Store: s.Store, Certs: env.Certs, Params: env.Params}.
						Run(ctx, stake.VoteDelegationRequest{Target: args[1], Delegator: args[0]})
					if err != nil {
						return f.hint(err)
					}
					stored = append(stored, gen.Ref)
				}
				uc := stake.RegisterVoteDelegation{
					Base: a.stakeBase(s, env, f.yes), Certs: env.CertDecoder, Builder: env.Addresses,
					DReps: env.DReps, Rewards: env.Rewards, AllowUnverified: f.allowUnverified,
				}
				res, err := uc.Run(ctx, stake.DelegationRegisterRequest{Delegator: args[0], Payer: payerOr(f.payer, args[0]), Message: f.messages, Extras: f.extra.ex, Passphrase: f.extra.pass})
				if err != nil {
					return f.hint(err)
				}
				a.report(outcome{kind: "vote delegation", account: args[0], payer: payerOr(f.payer, args[0]), Result: res, stored: stored}, &f, env, wo)
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&f.stored, "stored-cert", false, "use the stored <delegator-name>.vote-deleg.cert (made by spo stake vote-delegation-cert) instead of making one")
	f.add(cmd, true, true, false)
	f.extra.add(cmd, &f.messages, extraCert)
	return cmd
}

// ---- deregister ------------------------------------------------------------------

func (a *app) stakeDeregisterCommand() *cobra.Command {
	var f stakeFlags
	cmd := &cobra.Command{
		Use:   "deregister <stake-name> <payer-name> [--message TEXT]... [--yes] [--single-source] [--transfer-file PATH]",
		Short: "Deregister a stake address and take back the key deposit",
		Long: `Make the deregistration certificate (carrying the key deposit the chain holds)
and put it on the chain. <payer-name> pays the fee; the deposit is refunded to
it. The account must be registered, hold no rewards and have no governance
deposit open.

The reward balance and the refund rest on one read of the account, where a
false answer can cost the deposit or the rewards. It needs a second
independent provider to agree (spo provider set blockfrost), or --single-source
to go on with one. Providers that disagree are refused whatever the flag. The
summary names the sources and says when it was one.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec := envSpec{flags: &f.chain, config: true, needs: stakeTxNeeds(CapCerts, CapCertDecode, CapRewards), extras: &f.extra}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, wo WireOptions) error {
				gen, err := stake.GenerateDeregistrationCertificate{
					Store: s.Store, Addresses: env.AddressInspector, Certs: env.Certs, Account: env.Rewards, CrossCheck: env.CrossCheck,
					Sources: f.policy(), OnSingle: a.singleSourceHook(s, "spo stake deregister"), NetworkID: env.NetworkID,
				}.Run(ctx, args[0])
				if err != nil {
					return f.hint(err)
				}
				uc := stake.DeregisterStakeAddress{
					Base: a.stakeBase(s, env, f.yes), Certs: env.CertDecoder, Account: env.Rewards, CrossCheck: env.CrossCheck, Sources: f.policy(),
					OnSingle: a.singleSourceHook(s, "spo stake deregister"),
				}
				res, err := uc.Run(ctx, stake.RegisterRequest{Stake: args[0], Payer: args[1], Message: f.messages, Extras: f.extra.ex, Passphrase: f.extra.pass})
				if err != nil {
					return f.hint(err)
				}
				a.report(outcome{kind: "stake deregistration", account: args[0], payer: args[1], Result: res, stored: []ports.NamedRef{gen.Ref}}, &f, env, wo)
				return nil
			})
		},
	}
	f.add(cmd, false, false, true)
	f.extra.add(cmd, &f.messages, extraCert)
	return cmd
}

// ---- status -------------------------------------------------------------------------

// ErrStakeNotRegistered is returned by `stake status` after it printed that
// the address is not registered: like upstream's 03c it ends unsuccessfully,
// so a script can branch on it.
var ErrStakeNotRegistered = errors.New("the stake address is not registered")

func (a *app) stakeStatusCommand() *cobra.Command {
	var f chainFlags
	cmd := &cobra.Command{
		Use:   "status <stake-name|stake-address> [--transfer-file PATH]",
		Short: "Show the on-chain state of a stake address",
		Long: `Read the state of a stake address (a stored name or an address) from the
chain provider, or from the offline transfer file offline, and print it with
the source of each fact. An unknown answer is an error, never "not
registered". An address that is not registered is printed as such and the
command then fails, as upstream's 03c does.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec := envSpec{flags: &f, config: true, needs: []Need{CapAddress, CapRewards}}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				st, err := stake.CheckStakeAddress{Store: s.Store, Addresses: env.AddressInspector, Account: env.Rewards, Pools: env.Pools, NetworkID: env.NetworkID}.Run(ctx, args[0])
				if err != nil {
					return err
				}
				printStakeStatus(a.d.Out, st, env.Source(CapPools))
				if !st.Registered {
					return ErrStakeNotRegistered
				}
				return nil
			})
		},
	}
	addChainFlags(cmd, &f, true)
	return cmd
}

func readingText[T any](r chain.Reading[T], none string, show func(T) string) string {
	if v, ok := r.Get(); ok {
		return shown(show(v))
	}
	if r.IsNone() {
		return none
	}
	if r.IsUnknown() && r.Why() != "" {
		return "not stated (" + shown(r.Why()) + ")"
	}
	return "not stated by the source"
}

func printStakeStatus(w io.Writer, st stake.StakeStatus, poolSource string) {
	src := "[" + string(st.Source) + "]"
	fmt.Fprintf(w, "Stake address %s\n", st.Address)
	if !st.Registered {
		fmt.Fprintf(w, "  registered    no %s\n", src)
		return
	}
	fmt.Fprintf(w, "  registered    yes %s\n", src)
	fmt.Fprintf(w, "  deposit       %s %s\n", readingText(st.Deposit, "none", lovelaceText), src)
	fmt.Fprintf(w, "  rewards       %s %s\n", lovelaceText(st.Rewards), src)
	fmt.Fprintf(w, "  pool          %s %s\n", readingText(st.Pool, "not delegated", func(p chain.PoolID) string { return p.Bech32() }), src)
	if pi, ok := st.PoolInfo.Get(); ok {
		name := strings.TrimSpace(pi.Ticker + " " + pi.Name)
		if name != "" {
			if poolSource == "" {
				poolSource = "pool provider"
			}
			fmt.Fprintf(w, "  pool name     %s [%s]\n", shown(name), shown(poolSource))
		}
	}
	fmt.Fprintf(w, "  vote          %s %s\n", readingText(st.VoteDelegation, "none", shown), src)
	fmt.Fprintf(w, "  gov deposits  %s %s\n", readingText(st.GovDeposits, "none", func(d []chain.GovActionDeposit) string {
		if len(d) == 0 {
			return "none"
		}
		var parts []string
		for _, x := range d {
			parts = append(parts, fmt.Sprintf("%s: %s", x.Action, lovelaceText(x.Amount)))
		}
		return strings.Join(parts, "; ")
	}), src)
}

// ---- claim rewards ----------------------------------------------------------------------

func (a *app) claimRewardsCommand() *cobra.Command {
	var f stakeFlags
	cmd := &cobra.Command{
		Use:   "claim-rewards <stake-name> <destination> [--payer NAME] [--message TEXT]... [--metadata-file FILE]... [--encrypt-messages] [--yes] [--transfer-file PATH]",
		Short: "Withdraw the whole reward balance of a stake account to an address",
		Long: `Withdraw all the rewards of <stake-name> to <destination>, a stored address name
or an address. The fee is paid by --payer; when it is not given, the
destination pays if it is a stored address. The stake key and the payment key
sign. The balance is the one read at the start of the run; a stale balance
only makes the ledger reject the transaction, so one source is enough.

Offline, the balance comes from the transfer file, which must hold the stake
address (01_workOffline add).`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec := envSpec{flags: &f.chain, config: true, needs: stakeTxNeeds(CapRewards), extras: &f.extra}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, wo WireOptions) error {
				p := a.pipeline(s, env, f.yes)
				uc := wallet.ClaimRewards{
					Store: s.Store, Signers: env.Signers, Utxos: env.Utxos, Params: env.Params, Tip: env.Tip, Addresses: env.AddressInspector,
					Min: env.MinOutputCalculator, Fees: env.FeeEstimator, Bodies: env.TxBodyBuilder, Assembler: env.TxAssembler,
					Confirmer: p.Confirmer, Rewards: env.Rewards, Submitter: p.Submitter, Queue: p.Queue, NetworkID: env.NetworkID,
					Files: env.MetadataFiles, Encrypter: env.MsgEncrypter, Canonicalizer: env.Canonicalizer, Handles: env.Handles,
				}
				if f.yes {
					uc.Approval = wallet.ApprovalSkip
				}
				res, err := uc.Run(ctx, wallet.ClaimRequest{Stake: args[0], Destination: args[1], Payer: f.payer, Message: f.messages,
					Extras: f.extra.ex, Passphrase: f.extra.pass})
				if err != nil {
					return f.hint(err)
				}
				if res.ApprovalSkipped {
					printStakeSummary(a.d.Out, ports.TxSummary{
						Kind: "rewards withdrawal", Account: args[0], Source: res.Payer, Destination: res.Destination, Withdrawal: res.Withdrawn,
						Inputs: res.Inputs, Outputs: res.Outputs, Fee: res.Fee, TTL: res.TTL, Message: f.messages, Size: res.Size,
						TxID: res.TxID, Route: routeName(res.Queued), Sources: []chain.Source{res.Source},
					})
				}
				switch {
				case res.Submitted:
					fmt.Fprintf(a.d.Out, "Submitted transaction %s through %s.\n", res.TxID, env.Source(CapSubmit))
				case res.Queued:
					fmt.Fprintf(a.d.Out, "Queued transaction %s in %s. Submit it from an online machine.\n", res.TxID, wo.TransferFile)
				}
				return nil
			})
		},
	}
	f.add(cmd, true, false, false)
	f.extra.add(cmd, &f.messages, extraCert)
	return cmd
}
