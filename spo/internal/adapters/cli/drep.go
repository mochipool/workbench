package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/governance"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func (a *app) drepCommand() *cobra.Command {
	keys := govGroup("keys", "DRep keys", a.drepKeysGenerateCommand())
	return govGroup("drep", "DReps: keys, register or update, status, retire",
		keys, a.drepRegisterCommand(), a.drepStatusCommand(), a.drepRetireCommand())
}

// drepStem is the name a DRep is stored under: the use cases accept
// `name`, `name.drep` and `name.id` for the same DRep.
func drepStem(s string) string {
	return strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(s, "./"), ".id"), ".drep")
}

// payerStem is the name of a payer without `.addr`.
func payerStem(s string) string { return strings.TrimSuffix(strings.TrimPrefix(s, "./"), ".addr") }

func (a *app) drepKeysGenerateCommand() *cobra.Command {
	return a.govKeyCommand(
		"generate <name> [--mnemonic | --mnemonic-in-fd N] [--account N] [--index N]",
		"Generate the DRep key pair and its id",
		`Generate the DRep's key pair and store <name>.drep.vkey, <name>.drep.skey and
<name>.drep.id in the workspace. The signing key is sealed in the workspace and
never shown; the three spellings of the DRep id are printed.

--mnemonic derives the key (CIP-1852, role 3) from a fresh 24-word phrase stored
sealed in the workspace and not shown; --mnemonic-in-fd N derives it from a phrase
read from file descriptor N. --account and --index select the path.`,
		false, keyNeeds(CapDRepKeys),
		func(ctx context.Context, s *session, env *Env, req governance.GenerateKeysRequest, fresh bool) error {
			res, err := governance.GenerateDRepKeys{Store: s.Store, Keys: env.DRepKeys, Deriver: env.GovDeriver, Mnemonics: env.Mnemonics, Params: env.Params, Hardware: env.Hardware}.Run(ctx, req)
			if err != nil {
				return err
			}
			w := a.d.Out
			fmt.Fprintf(w, "Generated the DRep keys of %s.\nDRep id (CIP-105) %s\nDRep id (CIP-129) %s\nDRep id (hex)     %s\n", res.Name, res.IDs.Legacy, res.IDs.CIP129, res.IDs.Hex)
			a.mnemonicNotice(res.MnemonicStored && fresh)
			return nil
		})
}

// drepDetails are the lines of the confirmation that name the DRep and what the
// certificate carries, read from the workspace's public files.
func (a *app) drepDetails(ctx context.Context, s *session, env *Env, f *govFlags, drep string) (details, notes []string) {
	if id := readPublic(ctx, s.Store, ports.Ref{Name: drepStem(drep), Kind: ports.DRepID}); id != nil {
		details = append(details, "DRep id       "+firstLineText(id))
	}
	switch {
	case f.anchorURL == "":
		details = append(details, "anchor        none")
	default:
		hash := f.anchorHash
		switch {
		case env.AnchorFetcher != nil:
			hash = "computed from the downloaded document"
		case hash == "":
			hash = "(missing)"
		}
		details = append(details, "anchor url   "+f.anchorURL, "anchor hash  "+hash)
		if env.AnchorVerifier == nil {
			notes = append(notes, "the anchor document is not checked against CIP-119 (--anchor-unverified: no verifier in this build)")
		}
	}
	return details, notes
}

func firstLineText(b []byte) string {
	line, _, _ := strings.Cut(string(b), "\n")
	return strings.TrimSpace(line)
}

func (a *app) drepRegisterCommand() *cobra.Command {
	var f govFlags
	cmd := &cobra.Command{
		Use:   "register <name> <payer> [--anchor-url URL --anchor-hash HEX] [--anchor-unverified] [--allow-anchor-clear] [--message TEXT]... [--yes] [--transfer-file PATH]",
		Short: "Register a DRep, or update its anchor (pays the DRep deposit on registration)",
		Long: `Register the stored DRep <name>, paid by the stored address <payer>, or update
it when the chain says it is registered: the use case reads the DRep state and
decides, and an unknown answer is refused. A registration pays the protocol's
dRepDeposit; an update pays none. The payment key and the DRep key sign.

The anchor is optional. With --anchor-url the document is downloaded and hashed
where this mode can (light), and its own hash replaces --anchor-hash; offline
both flags are required together and the hash is recorded as given. The
document would be checked against CIP-119; this build has no verifier, so a
run with an anchor is refused unless you pass --anchor-unverified, which accepts
that the document structure and author signatures were not verified; the summary
says so. An update without an anchor of a DRep that has one on chain is refused
unless --allow-anchor-clear.

The certificate is stored as <name>.drep-reg.cert only after the transaction
was sent or queued. Offline, the DRep must be in the transfer file
(01_workOffline add-drep).`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec := envSpec{flags: &f.chain, config: true, needs: govTxNeeds(CapCerts, CapDReps), extras: &f.extra}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, wo WireOptions) error {
				unrestricted, err := a.unrestrictedConsent(ctx, f.unrestricted)
				if err != nil {
					return err
				}
				details, notes := a.drepDetails(ctx, s, env, &f, args[0])
				uc := governance.RegisterDRep{Base: a.govBase(s, env, &f, govConfirmer{a: a, details: details, notes: notes}),
					Certs: env.Certs, DReps: env.DReps, Anchors: governance.AnchorSource{Fetcher: env.AnchorFetcher},
					Verifier: env.AnchorVerifier, AnchorUnverifiedAcknowledged: f.anchorUnverified}
				res, err := uc.Run(ctx, governance.RegisterDRepRequest{DRep: args[0], Payer: args[1], URL: f.anchorURL, Hash: f.anchorHash,
					Message: f.messages, Extras: f.extra.ex, Passphrase: f.extra.pass, AllowAnchorClear: f.allowAnchorClear, Unrestricted: unrestricted})
				if err != nil {
					return f.hint(err)
				}
				kind := "DRep update"
				if res.Deposit > 0 {
					kind = "DRep registration"
				}
				a.govReport(govOutcome{kind: kind, account: drepStem(args[0]), payer: payerStem(args[1]), res: res, details: details, notes: notes,
					stored: []ports.Ref{{Name: drepStem(args[0]), Kind: ports.DRepRegCert}}}, &f, env, wo)
				return nil
			})
		},
	}
	f.add(cmd, govOpts{tx: true, anchor: true, unverified: true, anchorClear: true, unrestricted: true, anchorOfWhat: "the DRep (CIP-119)"})
	return cmd
}

func (a *app) drepRetireCommand() *cobra.Command {
	var f govFlags
	cmd := &cobra.Command{
		Use:   "retire <name> <payer> [--single-source] [--message TEXT]... [--yes] [--transfer-file PATH]",
		Short: "Retire a DRep and reclaim its deposit",
		Long: `Retire the registered DRep <name>, paid by the stored address <payer>, and
reclaim its deposit. The refund is the deposit in the on-chain DRep state, not
the one of the protocol parameters, and it is read from the chain: "not
registered" or an unknown answer is an error.

A wrong refund can cost the deposit, so a second independent source must agree
when the workspace has one (capability drep-state-crosscheck: a second
provider, spo provider set blockfrost). Without one the command is refused
unless you pass --single-source, which accepts the one source; the summary then
says the refund rests on one source. Providers that disagree are refused
whatever the flag.

The certificate is stored as <name>.drep-ret.cert only after the transaction
was sent or queued.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec := envSpec{flags: &f.chain, config: true, needs: govTxNeeds(CapCerts, CapDReps), extras: &f.extra}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, wo WireOptions) error {
				unrestricted, err := a.unrestrictedConsent(ctx, f.unrestricted)
				if err != nil {
					return err
				}
				var details []string
				if id := readPublic(ctx, s.Store, ports.Ref{Name: drepStem(args[0]), Kind: ports.DRepID}); id != nil {
					details = append(details, "DRep id       "+firstLineText(id))
				}
				uc := governance.RetireDRep{Base: a.govBase(s, env, &f, govConfirmer{a: a, details: details}),
					Certs: env.Certs, DReps: env.DReps, CrossCheck: env.DRepCross, Sources: f.policy(), OnSingle: a.singleSourceHook(s, "spo drep retire")}
				res, err := uc.Run(ctx, governance.RetireDRepRequest{DRep: args[0], Payer: args[1], Message: f.messages, Extras: f.extra.ex, Passphrase: f.extra.pass, Unrestricted: unrestricted})
				if err != nil {
					return f.hint(err)
				}
				a.govReport(govOutcome{kind: "DRep retirement", account: drepStem(args[0]), payer: payerStem(args[1]), res: res, details: details,
					stored: []ports.Ref{{Name: drepStem(args[0]), Kind: ports.DRepRetCert}}}, &f, env, wo)
				return nil
			})
		},
	}
	f.add(cmd, govOpts{tx: true, single: true, unrestricted: true})
	return cmd
}

func (a *app) drepStatusCommand() *cobra.Command {
	var f govFlags
	cmd := &cobra.Command{
		Use:   "status <name|id> [--anchor-unverified]",
		Short: "What the chain says about a DRep: registered, expired or not registered",
		Long: `Read the DRep state from the chain and print whether the DRep is registered,
registered but expired, or not registered, with its deposit, anchor, expiry and
delegated stake and the source of each. <name|id> is a stored DRep, a DRep id
(drep1..., CIP-105 or CIP-129, or drep_script1...) or 56 hex digits.

When the DRep has an anchor and this mode downloads documents, the document is
hashed and compared with the registered hash. It is not checked against
CIP-119 (no verifier in this build), so the check is refused unless you pass
--anchor-unverified, which accepts that the document structure and author
signatures were not verified.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec := envSpec{flags: &f.chain, config: true, needs: []Need{CapDReps}}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				uc := governance.CheckDRep{Store: s.Store, DReps: env.DReps, Epoch: env.Epochs, Anchors: governance.AnchorSource{Fetcher: env.AnchorFetcher},
					Verifier: env.AnchorVerifier, AnchorUnverifiedAcknowledged: f.anchorUnverified}
				rep, err := uc.Run(ctx, args[0])
				if err != nil {
					return f.hint(err)
				}
				w := a.d.Out
				fmt.Fprintf(w, "DRep %s\n  id (CIP-105)  %s\n  id (CIP-129)  %s\n  id (hex)      %s\n", rep.Standing, rep.IDs.Legacy, rep.IDs.CIP129, rep.IDs.Hex)
				fmt.Fprintf(w, "  source        %s\n", shown(string(rep.Source)))
				if rep.EpochKnown {
					fmt.Fprintf(w, "  epoch         %d\n", rep.Epoch)
				} else {
					fmt.Fprintf(w, "  epoch         unknown: %s; whether the DRep is expired is not assessed\n", shown(rep.EpochWhy))
				}
				if rep.Standing != "not registered" {
					fmt.Fprintf(w, "  deposit       %s\n", lovelaceText(rep.State.Deposit))
					if e, ok := rep.State.Expiry.Get(); ok {
						fmt.Fprintf(w, "  expires       epoch %d\n", e)
					} else if rep.State.Expiry.IsUnknown() {
						fmt.Fprintf(w, "  expires       unknown: %s\n", shown(rep.State.Expiry.Why()))
					}
					if d, ok := rep.State.DelegatedStake.Get(); ok {
						fmt.Fprintf(w, "  stake         %s\n", lovelaceText(d))
					} else if rep.State.DelegatedStake.IsUnknown() {
						fmt.Fprintf(w, "  stake         unknown: %s\n", shown(rep.State.DelegatedStake.Why()))
					}
					fmt.Fprintf(w, "  anchor        %s\n", anchorText(rep.Anchor))
					c := rep.AnchorCheck
					switch {
					case rep.Anchor.IsZero() && rep.State.AnchorURL == "":
					case !c.Checked:
						fmt.Fprintf(w, "  anchor check  %s\n", shown(c.Reason))
					case c.Reason != "":
						fmt.Fprintf(w, "  anchor check  %s\n", shown(c.Reason))
					case c.HashMatch:
						fmt.Fprintf(w, "  anchor check  the document hashes to the registered hash\n")
					}
					if c.Unverified != "" {
						fmt.Fprintf(w, "  NOT CHECKED   %s\n", shown(c.Unverified))
					}
				}
				return nil
			})
		},
	}
	f.add(cmd, govOpts{unverified: true, chainOnly: true})
	return cmd
}
