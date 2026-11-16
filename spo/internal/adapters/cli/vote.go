package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/governance"
	dgov "github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func (a *app) voteCommand() *cobra.Command {
	return govGroup("vote", "Votes: create vote files, submit them, tally",
		a.voteCreateCommand(), a.voteSubmitCommand(), a.voteTallyCommand())
}

// fixedChooser answers every action with the decision the operator typed on
// the command line, so an explicit action id never prompts.
type fixedChooser struct{ d dgov.Decision }

func (c fixedChooser) Choose(context.Context, governance.ActionView) (governance.Choice, error) {
	return governance.Choice{Decision: c.d}, nil
}

// terminalChooser asks per action, for `vote create <voter> all`. The default
// answer is cancel.
type terminalChooser struct{ a *app }

func (c terminalChooser) Choose(ctx context.Context, v governance.ActionView) (governance.Choice, error) {
	w := c.a.d.Out
	id := v.State.ID.Hex()
	fmt.Fprintf(w, "\nAction %s\n  kind          %s\n  anchor        %s\n", id, v.State.Kind, anchorText(v.State.Anchor))
	if v.Title != "" {
		fmt.Fprintf(w, "  title         %s\n", v.Title)
	}
	fmt.Fprintf(w, "  deposit       %s\n  expires after epoch %d\n", lovelaceText(v.State.Deposit), v.State.ExpiresAfter)
	if v.Earlier != "" {
		fmt.Fprintf(w, "  your earlier vote on it: %s\n", v.Earlier)
	}
	ans, err := c.a.term.ReadLine(ctx, "Vote [yes/no/abstain/skip/cancel] (default cancel): ")
	if errors.Is(err, ErrNoTerminal) {
		return governance.Choice{}, errors.New("no terminal to ask on; give the action id and the decision on the command line")
	}
	if err != nil {
		return governance.Choice{}, err
	}
	switch strings.ToLower(strings.TrimSpace(ans)) {
	case "y", "yes":
		return governance.Choice{Decision: dgov.Yes}, nil
	case "n", "no":
		return governance.Choice{Decision: dgov.No}, nil
	case "a", "abstain":
		return governance.Choice{Decision: dgov.Abstain}, nil
	case "s", "skip":
		return governance.Choice{Skip: true}, nil
	}
	return governance.Choice{Cancel: true}, nil
}

func parseDecision(s string) (dgov.Decision, error) {
	switch strings.ToLower(s) {
	case "yes":
		return dgov.Yes, nil
	case "no":
		return dgov.No, nil
	case "abstain":
		return dgov.Abstain, nil
	}
	return "", fmt.Errorf("the decision is yes, no or abstain, not %q", s)
}

func (a *app) voteCreateCommand() *cobra.Command {
	var f govFlags
	cmd := &cobra.Command{
		Use:   "create <voter> <action-id|all> [yes|no|abstain] [--anchor-url URL --anchor-hash HEX] [--anchor-unverified]",
		Short: "Write a vote file for a governance action (no transaction)",
		Long: `Write the vote file of a DRep, committee hot key or pool for an open
governance action: <name>_<yymmddHHMMSS>.drep.vote, .cc-hot.vote or .pool.vote.
<voter> is the stored name; the files <voter>.drep.vkey, .cc-hot.vkey and
.node.vkey are tried in that order. With an action id (<txid>#<index> or
gov_action1...) and a decision nothing is asked: the action must be open on the
chain and the voter's role must be allowed to vote on its kind. With "all" and
no decision you are asked per open action (yes, no, abstain, skip, cancel;
the default is cancel).

The action, the epoch and the protocol parameters come from the chain, so the
command is refused offline: vote files are made on an online or light machine,
and "spo vote submit" queues them offline.

An anchor is optional. The vote's and the action's anchor documents would be
checked against CIP-100/108; this build has no verifier, so the command is
refused unless you pass --anchor-unverified, which accepts that the documents
were not checked and records the hash as given.`,
		Args: cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			all := strings.EqualFold(args[1], "all")
			var chooser governance.Chooser
			switch {
			case all && len(args) == 3:
				return errors.New("a decision is given with one action id; with `all` you are asked per action")
			case all:
				chooser = terminalChooser{a}
			case len(args) != 3:
				return errors.New("give the decision: yes, no or abstain")
			default:
				d, err := parseDecision(args[2])
				if err != nil {
					return err
				}
				chooser = fixedChooser{d}
			}
			spec := envSpec{flags: &f.chain, config: true, needs: []Need{CapGovActions, CapParams, CapEpoch, CapClock, CapVoteFiles}}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, wo WireOptions) error {
				uc := governance.GenerateVote{Store: s.Store, Votes: env.VoteFiles, Actions: env.GovActions, Params: env.Params, Epoch: env.Epochs, Clock: env.Clock,
					Chooser: chooser, Anchors: governance.AnchorSource{Fetcher: env.AnchorFetcher}, Verifier: env.AnchorVerifier,
					AnchorUnverifiedAcknowledged: f.anchorUnverified, Offline: wo.Mode == ModeOffline}
				res, err := uc.Run(ctx, governance.GenerateVoteRequest{Voter: args[0], Action: args[1], URL: f.anchorURL, Hash: f.anchorHash})
				if err != nil {
					return f.hint(err)
				}
				w := a.d.Out
				for _, d := range res.Decisions {
					fmt.Fprintf(w, "Decision: %s.\n", d)
				}
				if f.anchorUnverified && (f.anchorURL != "" || env.AnchorFetcher != nil) {
					fmt.Fprintf(w, "NOT CHECKED %s.\n", anchorUnverifiedNote)
				}
				for _, vw := range res.Files {
					fmt.Fprintf(w, "Stored %s: %s vote %s on %s.\n", artefact(vw.Ref), vw.Vote.Voter.Role, vw.Vote.Decision, vw.Vote.Action.Hex())
				}
				if res.Skipped > 0 {
					fmt.Fprintf(w, "Skipped %d action(s).\n", res.Skipped)
				}
				if res.Cancelled {
					fmt.Fprintln(w, "Cancelled; the files written so far stay.")
				}
				if len(res.Files) > 0 {
					fmt.Fprintln(w, "Submit them with: spo vote submit <payer> <vote-file>...")
				}
				return nil
			})
		},
	}
	f.add(cmd, govOpts{anchor: true, unverified: true, chainOnly: true, anchorOfWhat: "the vote (CIP-100)"})
	return cmd
}

func voteDetails(ctx context.Context, s *session, env *Env, files []string) []string {
	var out []string
	for _, f := range files {
		base := strings.TrimPrefix(f, "./")
		for _, k := range []ports.Kind{ports.VoteDRepFile, ports.VoteCCHotFile, ports.VotePoolFile} {
			stem, ok := strings.CutSuffix(base, "."+string(k))
			if !ok {
				continue
			}
			raw := readPublic(ctx, s.Store, ports.Ref{Name: stem, Kind: k})
			if raw == nil {
				break
			}
			vf, err := env.VoteFiles.DecodeVoteFile(raw)
			if err != nil {
				break
			}
			v := vf.Vote
			line := fmt.Sprintf("%s vote %s on %s", v.Voter.Role, v.Decision, v.Action.Hex())
			if c, err := v.Action.CIP129(); err == nil {
				line += " (" + c + ")"
			}
			out = append(out, line, "  anchor "+anchorText(v.Anchor))
		}
	}
	return out
}

func (a *app) voteSubmitCommand() *cobra.Command {
	var f govFlags
	var voter string
	cmd := &cobra.Command{
		Use:   "submit <payer> <vote-file>... [--voter NAME] [--message TEXT]... [--yes] [--transfer-file PATH]",
		Short: "Put vote files on the chain in one transaction",
		Long: `Build one transaction that carries the votes of the given vote files
(<name>_<yymmddHHMMSS>.drep.vote, .cc-hot.vote or .pool.vote), paid by the stored
address <payer>. The payment key and the voter's key sign. All files must carry
the same voter, an action may occur in one file only, and the voter key must
match the voter of the files. The voter's key is derived from the files: the
stored key of the files' role whose hash is the voter in them, looked up under
the part of each file name before its time stamp. Pass --voter NAME to name the
key yourself where the file names do not say.

No check is made against the chain state: the ledger rejects a vote that is not
allowed. The summary lists each vote as voter role, action id and decision with
its anchor.`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			files := args[1:]
			spec := envSpec{flags: &f.chain, config: true, needs: govTxNeeds(CapVoteFiles), extras: &f.extra}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, wo WireOptions) error {
				unrestricted, err := a.unrestrictedConsent(ctx, f.unrestricted)
				if err != nil {
					return err
				}
				details := voteDetails(ctx, s, env, files)
				uc := governance.RegisterVote{Base: a.govBase(s, env, &f, govConfirmer{a: a, details: details}), Votes: env.VoteFiles}
				res, err := uc.Run(ctx, governance.RegisterVoteRequest{Voter: voter, Payer: args[0], Files: files, Message: f.messages, Extras: f.extra.ex, Passphrase: f.extra.pass, Unrestricted: unrestricted})
				if err != nil {
					if voter == "" && errors.Is(err, governance.ErrNoVoterKey) {
						return &explained{msg: err.Error() + "\npass --voter NAME to name the stored key that signs the votes", err: err}
					}
					return f.hint(err)
				}
				a.govReport(govOutcome{kind: "vote", account: res.Summary.Account, payer: payerStem(args[0]), res: res, details: details}, &f, env, wo)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&voter, "voter", "", "name of the voter whose key signs (default: the stored key whose hash is the voter of the vote files, found by the file names)")
	f.add(cmd, govOpts{tx: true, unrestricted: true})
	return cmd
}

// ---- tally -----------------------------------------------------------------------------

func pctText(p dgov.Pct) string {
	if p == dgov.NoThreshold {
		return "no threshold"
	}
	return fmt.Sprintf("%d.%02d %%", int64(p)/100, int64(p)%100)
}

func (a *app) printBody(name string, b dgov.BodyTally) {
	w := a.d.Out
	if !b.Applies {
		fmt.Fprintf(w, "  %-10s does not vote on this action\n", name)
		return
	}
	th := pctText(b.Threshold)
	if b.ThresholdKey != "" {
		th += " (" + b.ThresholdKey + ")"
	}
	fmt.Fprintf(w, "  %-10s %s yes, threshold %s: %s\n", name, pctText(b.Pct), th, b.Verdict)
}

func (a *app) voteTallyCommand() *cobra.Command {
	var f govFlags
	cmd := &cobra.Command{
		Use:   "tally [all | <action-id> | <voter> | <stake-account> | <action-kind>]...",
		Short: "Show the percentages and thresholds of the open governance actions",
		Long: `Read the open governance actions and the protocol parameters and show for
each matching action the DRep, pool and committee percentages, the thresholds
they are measured against and the verdict. Where the mode has the DRep and pool
stake distribution and the committee (online) the percentages are computed here;
in light mode they are the provider's own voting summary of the action
(Koios proposal_voting_summary), as upstream's light mode takes them, and only the
thresholds are computed here from the protocol parameters and the committee
quorum. The words filter: an action id, a stored voter or voter hash
(shows its answer), a stored stake account or address (the deposit return), an
action kind, or "all" (the default).

This is a read model: it is a projection of the chain state computed here,
nothing is decided on it and no transaction is gated by it. Every reader that
fails or does not know is an error, never a silent zero. The sources are
printed. It is refused offline.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				args = []string{"all"}
			}
			spec := envSpec{flags: &f.chain, config: true, needs: []Need{CapGovActions, OneOf(CapStakeDist, CapVotingSummary), CapParams, CapEpoch}}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, wo WireOptions) error {
				filter, err := governance.ParseQueryWords(ctx, s.Store, args)
				if err != nil {
					return err
				}
				uc := governance.QueryVote{Store: s.Store, Actions: env.GovActions, Dists: env.StakeDists, Summaries: env.Summaries, Params: env.Params, Epoch: env.Epochs, Offline: wo.Mode == ModeOffline}
				rep, err := uc.Run(ctx, filter)
				if err != nil {
					return f.hint(err)
				}
				w := a.d.Out
				fmt.Fprintf(w, "Epoch %d, protocol major version %d.\n", rep.Epoch, rep.Major)
				how := "stake distribution"
				if rep.FromSummary {
					how = "percentages are the provider's voting summary"
				}
				fmt.Fprintf(w, "Sources: governance state %s; %s %s; protocol parameters %s; epoch %s.\n",
					nameOf(env.Source(CapGovActions)), how, nameOf(string(rep.TallySource)), nameOf(env.Source(CapParams)), nameOf(env.Source(CapEpoch)))
				fmt.Fprintln(w, "This is a projection of the chain state: nothing is decided or gated by it.")
				if len(rep.Tallies) == 0 {
					fmt.Fprintln(w, "No open governance action matches.")
				}
				for _, t := range rep.Tallies {
					fmt.Fprintf(w, "\nAction %s\n  kind       %s\n  anchor     %s\n  expires    after epoch %d\n", t.Action.ID.Hex(), t.Action.Kind, anchorText(t.Action.Anchor), t.Action.ExpiresAfter)
					a.printBody("DReps", t.DRep)
					a.printBody("Pools", t.Pool)
					a.printBody("Committee", t.Committee)
					fmt.Fprintf(w, "  result     %s\n", t.Result)
					if ans, ok := rep.Answers[t.Action.ID]; ok {
						if ans == "" {
							ans = "not voted"
						}
						fmt.Fprintf(w, "  the voter  %s\n", ans)
					}
				}
				return nil
			})
		},
	}
	f.add(cmd, govOpts{chainOnly: true})
	return cmd
}

func nameOf(s string) string {
	if s == "" {
		return "local"
	}
	return s
}
