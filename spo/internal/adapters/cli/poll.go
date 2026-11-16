package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	apoll "github.com/mochipool/workbench/spo/internal/app/poll"
	"github.com/mochipool/workbench/spo/internal/app/wallet"
)

// pollNeeds are what reading a poll takes.
var pollNeeds = []Need{CapPollQuestion}

func (a *app) pollCommand() *cobra.Command {
	c := &cobra.Command{Use: "poll", Short: "SPO polls (CIP-94): show, answer, submit"}
	c.AddCommand(a.pollShowCommand(), a.pollAnswerCommand(), a.pollSubmitCommand())
	return c
}

func (a *app) showPoll(o WireOptions, env *Env) apoll.ShowPoll {
	return apoll.ShowPoll{Questions: env.Polls, Offline: o.Mode == ModeOffline}
}

func printPoll(a *app, v apoll.View) {
	w := a.d.Out
	fmt.Fprintf(w, "Poll %s [%s]\n  question hash  %x\n\n%s\n\n", v.TxID, v.Source, v.Hash[:], v.Text)
	for i, o := range v.Options {
		fmt.Fprintf(w, "  %d  %s\n", i, o)
	}
	fmt.Fprintln(w, "\nThe question is what the chain provider reported; an answer commits to its hash.")
}

func (a *app) pollShowCommand() *cobra.Command {
	var cf chainFlags
	cmd := &cobra.Command{
		Use:   "show <txhash>",
		Short: "Show the question and numbered options of the poll a transaction published",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec := envSpec{flags: &cf, config: true, local: true, needs: pollNeeds}
			return a.withEnv(cmd, spec, func(ctx context.Context, _ *session, env *Env, o WireOptions) error {
				v, err := a.showPoll(o, env).Run(ctx, args[0])
				if err != nil {
					return err
				}
				printPoll(a, v)
				return nil
			})
		},
	}
	addChainFlags(cmd, &cf, false)
	return cmd
}

// choosePollOption takes the option from the flag, or asks for it.
func (a *app) choosePollOption(ctx context.Context, v apoll.View, flag int, given bool) (int, error) {
	if given {
		return flag, nil
	}
	ans, err := a.term.ReadLine(ctx, fmt.Sprintf("Option number (0 to %d): ", len(v.Options)-1))
	if errors.Is(err, ErrNoTerminal) {
		return 0, errors.New("no terminal to ask on; pass --option N")
	}
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(ans))
	if err != nil {
		return 0, fmt.Errorf("%q is not an option number", strings.TrimSpace(ans))
	}
	return n, nil
}

func (a *app) pollAnswerCommand() *cobra.Command {
	var (
		cf     chainFlags
		option int
		out    string
		yes    bool
	)
	cmd := &cobra.Command{
		Use:   "answer <txhash> [--option N] [--out FILE] [--yes]",
		Short: "Write the answer metadata file for one option of a poll",
		Long: `Show the poll, take the option (--option N, or asked for), confirm it (default
No; --yes answers the confirmation) and write the CIP-94 answer metadata to FILE
(default spopoll_<question hash>.cbor in the current directory; an existing file
is not replaced). Send it with: spo poll submit.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			given := cmd.Flags().Changed("option")
			spec := envSpec{flags: &cf, config: true, local: true, needs: pollNeeds}
			return a.withEnv(cmd, spec, func(ctx context.Context, _ *session, env *Env, o WireOptions) error {
				show := a.showPoll(o, env)
				v, err := show.Run(ctx, args[0])
				if err != nil {
					return err
				}
				printPoll(a, v)
				n, err := a.choosePollOption(ctx, v, option, given)
				if err != nil {
					return err
				}
				ans, v, err := apoll.BuildPollAnswer{Show: show}.Run(ctx, args[0], n)
				if err != nil {
					return err
				}
				ok, err := a.confirm(ctx, fmt.Sprintf("Answer option %d, %q?", n, v.Options[n]), yes)
				if err != nil {
					return err
				}
				if !ok {
					return errors.New("not confirmed: no answer file was written")
				}
				path := out
				if path == "" {
					path = ans.FileName
				}
				f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
				if err != nil {
					return err
				}
				if _, err := f.Write(ans.CBOR); err != nil {
					f.Close()
					os.Remove(path)
					return err
				}
				if err := f.Close(); err != nil {
					return err
				}
				fmt.Fprintf(a.d.Out, "Wrote %s: option %d of the question %s.\nSend it with: spo poll submit <payer> <destination> <amount> <pool> --metadata-file %s\n", path, n, ans.HashHex, path)
				return nil
			})
		},
	}
	cmd.Flags().IntVar(&option, "option", 0, "the option number to answer (default: asked)")
	cmd.Flags().StringVar(&out, "out", "", "file to write (default spopoll_<hash>.cbor)")
	cmd.Flags().BoolVar(&yes, "yes", false, "answer yes to the confirmation of the option")
	addChainFlags(cmd, &cf, false)
	return cmd
}

func (a *app) pollSubmitCommand() *cobra.Command {
	var (
		f      poolFlags
		pollTx string
		option int
	)
	cmd := &cobra.Command{
		Use:   "submit <payer> <destination> <amount> <pool> [--poll TXHASH [--option N] | --metadata-file ANSWER] [--yes]",
		Short: "Send a poll answer: a payment that carries it and that the pool's cold key co-signs",
		Long: `Send the answer to an SPO poll as a payment (like spo wallet send) from <payer>
to <destination> of <amount>, with the answer as metadata and the cold key of
<pool> as a required signer, so the answer is attributable to the pool. The
answer is either built here (--poll TXHASH, with --option N or asked for) or a
file written by spo poll answer (--metadata-file FILE). A message does not count
as an answer. The cold key must be a key in the workspace: a cold key on a
hardware wallet is refused. The summary is shown and you are asked before
anything is signed (default No); the extra parameters of wallet send apply.`,
		Args: cobra.ExactArgs(4),
		RunE: func(cmd *cobra.Command, args []string) error {
			needs := []Need{CapSigners, CapGenesis, CapTip, CapParams, CapUtxos, CapAddress, CapMinOut, CapFees, CapBodies, CapAssemble, OneOf(CapSubmit, CapQueue)}
			if pollTx != "" {
				needs = append(needs, CapPollQuestion)
			}
			spec := envSpec{flags: &f.chain, config: true, extras: &f.extra, needs: needs}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, o WireOptions) error {
				req := apoll.SubmitRequest{Payer: args[0], Destination: args[1], Amount: args[2], Pool: args[3],
					Message: f.messages, Extras: f.extra.ex, Passphrase: f.extra.pass}
				if pollTx != "" {
					show := a.showPoll(o, env)
					v, err := show.Run(ctx, pollTx)
					if err != nil {
						return err
					}
					printPoll(a, v)
					n, err := a.choosePollOption(ctx, v, option, cmd.Flags().Changed("option"))
					if err != nil {
						return err
					}
					ans, _, err := apoll.BuildPollAnswer{Show: show}.Run(ctx, pollTx, n)
					if err != nil {
						return err
					}
					req.Answer = &ans
				}
				uc := apoll.SubmitPollAnswer{Send: a.sendLovelaces(s, env, f.yes)}
				res, err := uc.Run(ctx, req)
				if err != nil {
					if errors.Is(err, apoll.ErrNoAnswer) {
						return &explained{msg: err.Error() + "\ngive --poll TXHASH (the answer is built here) or --metadata-file FILE (from: spo poll answer)", err: err}
					}
					if errors.Is(err, wallet.ErrDeclined) {
						return fmt.Errorf("%w: nothing was signed, submitted or queued", err)
					}
					return f.hint(err)
				}
				fmt.Fprintf(a.d.Out, "Answer for pool %s (pool id %s, signer %s).\n", req.Pool, res.PoolID.Bech32(), res.SignerHex)
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
	cmd.Flags().StringVar(&pollTx, "poll", "", "build the answer here for the poll published by this transaction")
	cmd.Flags().IntVar(&option, "option", 0, "the option number to answer with --poll (default: asked)")
	cmd.Flags().StringArrayVar(&f.messages, "message", nil, "CIP-20 message line, at most 64 bytes (repeatable)")
	cmd.Flags().BoolVar(&f.yes, "yes", false, "approve the transaction without asking (the summary is still printed)")
	f.extra.add(cmd, &f.messages, extraSend)
	addChainFlags(cmd, &f.chain, true)
	return cmd
}
