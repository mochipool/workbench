package cli

import (
	"context"
	"fmt"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/governance"
	dgov "github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func (a *app) committeeCommand() *cobra.Command {
	keys := govGroup("keys", "Committee member keys", a.committeeKeysCommand(true), a.committeeKeysCommand(false))
	return govGroup("committee", "Constitutional committee member: keys, hot-key authorisation, status, resignation",
		keys, a.committeeAuthorizeCommand(), a.committeeStatusCommand(), a.committeeResignCommand(),
		a.renameCommand(identity.OwnerCommittee, "committee member"), a.mergeCommand(identity.OwnerCommittee, "committee member"))
}

func committeeStem(s string) string {
	s = strings.TrimSuffix(strings.TrimPrefix(s, "./"), ".hash")
	return strings.TrimSuffix(strings.TrimSuffix(s, ".cc-cold"), ".cc-hot")
}

func (a *app) committeeKeysCommand(cold bool) *cobra.Command {
	use, short, role, gen, fileKind, roleNo := "generate-hot <name> [--replace] [--mnemonic | --mnemonic-in-fd N] [--account N] [--index N]",
		"Generate a committee hot key pair and its hash", "hot", CapComHotKeys, "cc-hot", "5"
	if cold {
		use, short, role, gen, fileKind, roleNo = "generate-cold <name> [--mnemonic | --mnemonic-in-fd N] [--account N] [--index N]",
			"Generate a committee cold key pair and its hash", "cold", CapComColdKeys, "cc-cold", "4"
	}
	long := fmt.Sprintf(`Generate a committee member's %s key pair and store <name>.%s.vkey, .skey and
.hash in the workspace. The signing key is sealed in the workspace and never shown;
the hash and the committee ids are printed.

--mnemonic derives the key (CIP-1852, role %s) from a fresh 24-word phrase stored
sealed in the workspace and not shown; --mnemonic-in-fd N derives it from a phrase
read from file descriptor N.`, role, fileKind, roleNo)
	if !cold {
		long += `

An existing hot key is refused unless you pass --replace, which deletes the old
key, its signing key and its files first (upstream asks, with the default No).`
	}
	return a.govKeyCommand(use, short, long, !cold, keyNeeds(gen),
		func(ctx context.Context, s *session, env *Env, req governance.GenerateKeysRequest, fresh bool) error {
			var res governance.CommitteeKeysGenerated
			var err error
			if cold {
				res, err = governance.GenerateCommitteeColdKeys{Store: s.Store, Keys: env.ComColdKeys, Deriver: env.GovDeriver, Mnemonics: env.Mnemonics, Params: env.Params, Hardware: env.Hardware}.Run(ctx, req)
			} else {
				res, err = governance.GenerateCommitteeHotKeys{Store: s.Store, Keys: env.ComHotKeys, Deriver: env.GovDeriver, Mnemonics: env.Mnemonics, Params: env.Params, Hardware: env.Hardware}.Run(ctx, req)
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(a.d.Out, "Generated the committee %s keys of %s.\nid (CIP-105) %s\nid (CIP-129) %s\nhash        %s\n", role, res.Name, res.IDs.Legacy, res.IDs.CIP129, res.IDs.Hex)
			a.mnemonicNotice(res.MnemonicStored && fresh)
			return nil
		})
}

func (a *app) committeeAuthorizeCommand() *cobra.Command {
	var f govFlags
	cmd := &cobra.Command{
		Use:   "authorize <cold> <hot> <payer> [--message TEXT]... [--yes]",
		Short: "Authorise a hot key for a committee cold key on the chain",
		Long: `Authorise the stored hot key <hot> to act for the cold key <cold>, paid by the
stored address <payer>. The payment key and the cold key sign; the hot key never
signs. No deposit. The committee state is read from the chain: a resigned cold
key and the hot key that is already authorised are refused, and an unknown
answer is refused.

This workflow needs the chain and cannot queue a transaction for an offline
machine. The certificate is stored as <hot>.cc-hot.cert after the transaction
was sent.`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec := envSpec{flags: &f.chain, config: true, needs: govTxNeeds(CapCerts, CapCommittee), extras: &f.extra}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, wo WireOptions) error {
				var details []string
				for _, d := range []struct {
					label string
					ref   ports.NamedRef
				}{{"cold key hash", ports.NamedRef{Name: committeeStem(args[0]), Kind: ports.CCColdHash}}, {"hot key hash ", ports.NamedRef{Name: committeeStem(args[1]), Kind: ports.CCHotHash}}} {
					if b := readPublic(ctx, s.Store, d.ref); b != nil {
						details = append(details, d.label+" "+firstLineText(b))
					}
				}
				uc := governance.AuthorizeCommitteeHotKey{Base: a.govBase(s, env, &f, govConfirmer{a: a, details: details}), Certs: env.Certs, Committee: env.Committee}
				res, err := uc.Run(ctx, governance.AuthorizeRequest{Cold: args[0], Hot: args[1], Payer: args[2], Message: f.messages, Extras: f.extra.ex, Passphrase: f.extra.pass})
				if err != nil {
					return f.hint(err)
				}
				a.govReport(govOutcome{kind: "committee hot key authorisation", account: committeeStem(args[0]), payer: payerStem(args[2]), res: res, details: details,
					stored: []ports.NamedRef{{Name: committeeStem(args[1]), Kind: ports.CCHotCert}}}, &f, env, wo)
				return nil
			})
		},
	}
	f.add(cmd, govOpts{tx: true})
	return cmd
}

func (a *app) committeeResignCommand() *cobra.Command {
	var f govFlags
	cmd := &cobra.Command{
		Use:   "resign <cold> <payer> [--anchor-url URL --anchor-hash HEX] [--anchor-unverified] [--message TEXT]... [--yes]",
		Short: "Resign a committee cold key on the chain",
		Long: `Resign the stored cold key <cold>, paid by the stored address <payer>. The
payment key and the cold key sign. The member must be on the chain (a key that
is not is refused, and so is an unknown answer); a key that already resigned is
resigned again, as upstream does, and the result says so.

The optional anchor needs --anchor-url and, where the document cannot be
fetched, --anchor-hash. The document would be checked against CIP-100; this
build has no verifier, so a run with an anchor is refused unless you pass
--anchor-unverified, which accepts that it was not checked; the summary says so. This workflow needs the chain
and cannot queue a transaction for an offline machine. The certificate is stored
as <cold>.cc-cold-ret.cert after the transaction was sent.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec := envSpec{flags: &f.chain, config: true, needs: govTxNeeds(CapCerts, CapCommittee), extras: &f.extra}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, wo WireOptions) error {
				var details, notes []string
				if b := readPublic(ctx, s.Store, ports.NamedRef{Name: committeeStem(args[0]), Kind: ports.CCColdHash}); b != nil {
					details = append(details, "cold key hash "+firstLineText(b))
				}
				if f.anchorURL == "" {
					details = append(details, "anchor        none")
				} else {
					hash := f.anchorHash
					if env.AnchorFetcher != nil {
						hash = "computed from the downloaded document"
					}
					details = append(details, "anchor url   "+f.anchorURL, "anchor hash  "+hash)
					if env.AnchorVerifier == nil {
						notes = append(notes, "the anchor document is not checked against CIP-100 (--anchor-unverified: no verifier in this build)")
					}
				}
				uc := governance.ResignCommitteeColdKey{Base: a.govBase(s, env, &f, govConfirmer{a: a, details: details, notes: notes}), Certs: env.Certs,
					Committee: env.Committee, Anchors: governance.AnchorSource{Fetcher: env.AnchorFetcher},
					Verifier: env.AnchorVerifier, AnchorUnverifiedAcknowledged: f.anchorUnverified}
				res, err := uc.Run(ctx, governance.ResignRequest{Cold: args[0], Payer: args[1], URL: f.anchorURL, Hash: f.anchorHash, Message: f.messages, Extras: f.extra.ex, Passphrase: f.extra.pass})
				if err != nil {
					return f.hint(err)
				}
				a.govReport(govOutcome{kind: "committee cold key resignation", account: committeeStem(args[0]), payer: payerStem(args[1]), res: res, details: details, notes: notes,
					stored: []ports.NamedRef{{Name: committeeStem(args[0]), Kind: ports.CCColdRetCert}}}, &f, env, wo)
				return nil
			})
		},
	}
	f.add(cmd, govOpts{tx: true, anchor: true, unverified: true, anchorOfWhat: "the resignation (CIP-100)"})
	return cmd
}

func (a *app) committeeStatusCommand() *cobra.Command {
	var f govFlags
	cmd := &cobra.Command{
		Use:   "status <name|hash|id>",
		Short: "What the chain says about a committee cold or hot credential",
		Long: `Look up a committee credential on the chain: a stored cold or hot key by name,
a 56-digit hash, or a cc_cold1.../cc_hot1... id. The same hash is tried as a key
and as a script credential, as the cold key and then as an authorised hot key.
"Not a member" is a positive answer; a provider that failed or did not say is an
error. Needs the chain: it is refused offline.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec := envSpec{flags: &f.chain, config: true, needs: []Need{CapCommittee}}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, wo WireOptions) error {
				rep, err := governance.CheckCommittee{Store: s.Store, Committee: env.Committee, Offline: wo.Mode == ModeOffline}.Run(ctx, args[0])
				if err != nil {
					return f.hint(err)
				}
				w := a.d.Out
				fmt.Fprintf(w, "Committee credential %s\n  id (CIP-105)  %s\n  id (CIP-129)  %s\n  source        %s\n", rep.IDs.Hex, rep.IDs.Legacy, rep.IDs.CIP129, shown(string(rep.Source)))
				if len(rep.Matches) == 0 {
					fmt.Fprintln(w, "  not a committee member, as a cold key or as an authorised hot key")
				}
				for _, m := range rep.Matches {
					role := "cold key of a member"
					if m.ByHot {
						role = "authorised hot key of the member with cold key " + credText(m.Member.Cold)
					}
					fmt.Fprintf(w, "  %s\n    authorisation %s\n", role, shown(fmt.Sprint(m.Member.Auth)))
					if m.Member.Auth == dgov.HotAuthorized {
						fmt.Fprintf(w, "    hot key       %s\n", credText(m.Member.Hot))
					}
					if m.Member.Status != "" {
						fmt.Fprintf(w, "    status        %s\n", shown(fmt.Sprint(m.Member.Status)))
					}
					if e, ok := m.Member.Expiry.Get(); ok {
						fmt.Fprintf(w, "    expires       epoch %d\n", e)
					}
					if m.Member.NextChange != "" {
						fmt.Fprintf(w, "    next epoch    %s\n", shown(fmt.Sprint(m.Member.NextChange)))
					}
				}
				return nil
			})
		},
	}
	f.add(cmd, govOpts{chainOnly: true})
	return cmd
}
