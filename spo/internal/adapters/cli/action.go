package cli

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/governance"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	dgov "github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func (a *app) actionCommand() *cobra.Command {
	return govGroup("action", "Governance actions: create action files, submit them",
		a.actionCreateCommand(), a.actionSubmitCommand())
}

// actionKinds maps the words of the command line to the kinds.
var actionKinds = []struct {
	word string
	kind dgov.ActionKind
}{
	{"info", dgov.InfoAction},
	{"no-confidence", dgov.NoConfidenceAction},
	{"update-committee", dgov.UpdateCommittee},
	{"new-constitution", dgov.NewConstitution},
	{"hard-fork", dgov.HardForkInitiation},
	{"treasury-withdrawal", dgov.TreasuryWithdrawals},
	{"parameter-change", dgov.ParameterChange},
}

func actionKindWords() string {
	var w []string
	for _, k := range actionKinds {
		w = append(w, k.word)
	}
	return strings.Join(w, ", ")
}

// actionFlags are the kind-specific flags of `action create`.
type actionFlags struct {
	amount           uint64
	to               string
	version          string
	threshold        string
	addKeys, addScrs []string
	remKeys, remScrs []string
	termEpoch        uint64
	constitutionURL  string
	constitutionHash string
	params           []string
}

// forKind says which flags the kind uses; a flag of another kind is refused
// by name rather than ignored.
func (af *actionFlags) check(cmd *cobra.Command, kind dgov.ActionKind) error {
	use := map[string][]dgov.ActionKind{
		"amount": {dgov.TreasuryWithdrawals}, "to": {dgov.TreasuryWithdrawals},
		"version":   {dgov.HardForkInitiation},
		"threshold": {dgov.UpdateCommittee}, "add-key": {dgov.UpdateCommittee}, "add-script": {dgov.UpdateCommittee},
		"remove-key": {dgov.UpdateCommittee}, "remove-script": {dgov.UpdateCommittee}, "term-epoch": {dgov.UpdateCommittee},
		"constitution-url": {dgov.NewConstitution}, "constitution-hash": {dgov.NewConstitution},
		"param": {dgov.ParameterChange},
	}
	for name, kinds := range use {
		if !cmd.Flags().Changed(name) {
			continue
		}
		ok := false
		for _, k := range kinds {
			ok = ok || k == kind
		}
		if !ok {
			return fmt.Errorf("--%s does not apply to a %s action", name, kind)
		}
	}
	return nil
}

func (af *actionFlags) add(cmd *cobra.Command) {
	f := cmd.Flags()
	f.Uint64Var(&af.amount, "amount", 0, "treasury-withdrawal: the amount in lovelace")
	f.StringVar(&af.to, "to", "", "treasury-withdrawal: the receiving stake address (default: the deposit-return address)")
	f.StringVar(&af.version, "version", "", "hard-fork: the target protocol version, MAJOR or MAJOR.MINOR")
	f.StringVar(&af.threshold, "threshold", "", "update-committee: the new committee threshold, a fraction (2/3) or a decimal (0.67)")
	f.StringArrayVar(&af.addKeys, "add-key", nil, "update-committee: a member to add, 56-digit key hash (repeatable)")
	f.StringArrayVar(&af.addScrs, "add-script", nil, "update-committee: a member to add, 56-digit script hash (repeatable)")
	f.StringArrayVar(&af.remKeys, "remove-key", nil, "update-committee: a member to remove, 56-digit key hash (repeatable)")
	f.StringArrayVar(&af.remScrs, "remove-script", nil, "update-committee: a member to remove, 56-digit script hash (repeatable)")
	f.Uint64Var(&af.termEpoch, "term-epoch", 0, "update-committee: the epoch the terms of the added members end (default: the current epoch plus committeeMaxTermLength)")
	f.StringVar(&af.constitutionURL, "constitution-url", "", "new-constitution: the URL of the constitution document")
	f.StringVar(&af.constitutionHash, "constitution-hash", "", "new-constitution: its blake2b-256 hash, 64 hex digits (replaced by the document's own hash where it is fetched)")
	f.StringArrayVar(&af.params, "param", nil, "parameter-change: NAME=VALUE (repeatable); the file for it is not built yet")
}

func parseVersion(s string) (dgov.Version, error) {
	maj, min, _ := strings.Cut(s, ".")
	var v dgov.Version
	var err error
	if v.Major, err = strconv.ParseUint(maj, 10, 64); err != nil {
		return v, fmt.Errorf("--version %q: want MAJOR or MAJOR.MINOR", s)
	}
	if min != "" {
		if v.Minor, err = strconv.ParseUint(min, 10, 64); err != nil {
			return v, fmt.Errorf("--version %q: want MAJOR or MAJOR.MINOR", s)
		}
	}
	return v, nil
}

func (a *app) actionCreateCommand() *cobra.Command {
	var f govFlags
	var af actionFlags
	cmd := &cobra.Command{
		Use:   "create <kind> <return> --anchor-url URL [--anchor-hash HEX] [--anchor-unverified] [kind flags]",
		Short: "Write a governance action file (no transaction)",
		Long: `Write the action file <return>_<kind>_<yymmddHHMMSS>.action of a governance
action. <kind> is one of: ` + actionKindWords() + `.
<return> is the stored stake account (or a stake address) the proposal deposit
is returned to. The anchor (--anchor-url, a CIP-108 document) is required.

Kind flags: treasury-withdrawal takes --amount and optionally --to;
hard-fork takes --version; update-committee takes --threshold, --add-key,
--add-script, --remove-key, --remove-script and --term-epoch; new-constitution
takes --constitution-url and --constitution-hash. A parameter-change file is
not built yet and is refused with that message.

The protocol parameters come from the chain or, offline, from the transfer file.
A kind reads only what it needs: the last enacted action for the kinds that name
a previous action (no-confidence, update-committee, new-constitution, hard-fork,
parameter-change), the constitution's guardrails script for treasury withdrawals
and parameter changes, the current epoch for the terms of update-committee. An
info action needs no chain reader, so it also runs offline.

The anchor document would be checked against CIP-108; this build has no
verifier, so a fetched document is refused unless you pass --anchor-unverified,
which accepts that it was not checked (the hash is recorded as given). Treasury
withdrawals and parameter changes need the constitution's guardrails script when
they are submitted; the file is written and "action submit" says what is
missing.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var kind dgov.ActionKind
			for _, k := range actionKinds {
				if args[0] == k.word {
					kind = k.kind
				}
			}
			if kind == "" {
				return fmt.Errorf("unknown action kind %q: one of %s", args[0], actionKindWords())
			}
			if err := af.check(cmd, kind); err != nil {
				return err
			}
			req := governance.GenerateActionRequest{Return: args[1], Kind: kind, URL: f.anchorURL, Hash: f.anchorHash,
				Amount: chain.Lovelace(af.amount), Addr: af.to, Threshold: af.threshold,
				AddKeys: af.addKeys, AddScripts: af.addScrs, RemKeys: af.remKeys, RemScripts: af.remScrs, Epoch: af.termEpoch,
				ConstitutionURL: af.constitutionURL, ConstitutionHash: af.constitutionHash}
			if kind == dgov.HardForkInitiation {
				v, err := parseVersion(af.version)
				if err != nil {
					return err
				}
				req.Version = v
			}
			for _, p := range af.params {
				n, v, ok := strings.Cut(p, "=")
				if !ok || n == "" {
					return fmt.Errorf("--param %q: want NAME=VALUE", p)
				}
				req.Params = append(req.Params, dgov.ParamChange{Name: n, Value: v})
			}
			// Each kind asks only for the readers it needs: an info action needs no
			// chain reader at all, so it also runs offline from a snapshot.
			needs := []Need{CapParams, CapClock, CapActionFiles}
			if _, ok := dgov.PurposeOf(kind); ok {
				needs = append(needs, CapLastEnacted)
			}
			if kind == dgov.TreasuryWithdrawals || kind == dgov.ParameterChange {
				needs = append(needs, CapConstitution)
			}
			if kind == dgov.UpdateCommittee {
				needs = append(needs, CapEpoch)
			}
			spec := envSpec{flags: &f.chain, config: true, needs: needs}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				uc := governance.GenerateAction{Store: s.Store, Actions: env.ActionFiles, Params: env.Params, Epoch: env.Epochs,
					Constitution: env.Constitution, LastEnacted: env.LastEnacted, Clock: env.Clock,
					Anchors: governance.AnchorSource{Fetcher: env.AnchorFetcher}, Verifier: env.AnchorVerifier,
					AnchorUnverifiedAcknowledged: f.anchorUnverified, NetworkID: env.NetworkID}
				res, err := uc.Run(ctx, req)
				if err != nil {
					if errors.Is(err, governance.ErrParameterChangeUnsupported) {
						return fmt.Errorf("%w\na parameter-change action file cannot be written yet: this build does not encode the protocol parameter update; no file was written", err)
					}
					return f.hint(err)
				}
				w := a.d.Out
				for _, d := range res.Decisions {
					fmt.Fprintf(w, "Decision: %s.\n", d)
				}
				if f.anchorUnverified && (f.anchorURL != "") {
					fmt.Fprintf(w, "NOT CHECKED %s.\n", anchorUnverifiedNote)
				}
				for _, l := range actionLines(res.Action) {
					fmt.Fprintf(w, "  %s\n", l)
				}
				fmt.Fprintf(w, "Stored %s.\n", artefact(res.Ref))
				if res.NeedsGuardrails {
					fmt.Fprintln(w, "This kind needs the constitution's guardrails script when it is submitted; `spo action submit` will say what is missing.")
				}
				return nil
			})
		},
	}
	f.add(cmd, govOpts{anchor: true, unverified: true, chainOnly: true, anchorOfWhat: "the action (CIP-108)"})
	af.add(cmd)
	return cmd
}

// actionLines describe one action in plain terms: kind, deposit, return
// address, anchor and the fields of the kind.
func actionLines(act dgov.Action) []string {
	out := []string{
		fmt.Sprintf("%s proposal", act.Kind),
		"deposit " + lovelaceText(act.Deposit) + ", returned to " + string(act.Return),
		"anchor  " + anchorText(act.Anchor),
	}
	switch act.Kind {
	case dgov.HardForkInitiation:
		out = append(out, fmt.Sprintf("hard fork to protocol version %d.%d", act.Version.Major, act.Version.Minor))
	case dgov.TreasuryWithdrawals:
		for _, w := range act.Withdrawals {
			out = append(out, fmt.Sprintf("withdraws %s to %s", lovelaceText(w.Amount), w.Account))
		}
	case dgov.NewConstitution:
		out = append(out, "constitution "+anchorText(act.Constitution))
	case dgov.UpdateCommittee:
		out = append(out, fmt.Sprintf("new threshold %d/%d", act.Threshold.Num, act.Threshold.Den))
		for _, m := range act.Add {
			out = append(out, fmt.Sprintf("adds %s, term ends epoch %d", credText(m.Cold), m.Epoch))
		}
		for _, m := range act.Remove {
			out = append(out, "removes "+credText(m))
		}
	case dgov.ParameterChange:
		for _, p := range act.Params {
			out = append(out, fmt.Sprintf("sets %s = %s", p.Name, p.Value))
		}
	}
	if act.Prev != nil {
		out = append(out, "follows the last enacted action "+act.Prev.Hex())
	}
	return out
}

func (a *app) actionSubmitCommand() *cobra.Command {
	var f govFlags
	cmd := &cobra.Command{
		Use:   "submit <payer> <action-file>... [--allow-unverified] [--message TEXT]... [--yes] [--transfer-file PATH]",
		Short: "Put governance action files on the chain in one transaction (pays the proposal deposits)",
		Long: `Build one transaction that carries the proposals of the given action files
(<name>_<yymmddHHMMSS>.action, with or without the extension), paid by the stored
address <payer>; the change is the inputs minus the fee and the deposits. Only the
payment key signs. The validity is the tip plus 25000 slots.

The deposit-return stake address of each proposal must be registered. Where the
chain cannot say (no reader in this mode, or the source does not know) the command
is refused unless you pass --allow-unverified; the summary lists the check that
was skipped. A wrong answer only makes the ledger reject the transaction.

Treasury withdrawals and parameter changes carry the constitution's guardrails
script, with collateral and the script's execution units, which this build does not
evaluate: the command checks everything else and refuses, printing what is missing.
The summary lists each proposal with its kind, deposit, return address and anchor,
and the ids the proposals will have are printed after submission.`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			files := args[1:]
			spec := envSpec{flags: &f.chain, config: true, needs: govTxNeeds(CapActionFiles)}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, wo WireOptions) error {
				var details []string
				for _, name := range files {
					stem := strings.TrimSuffix(strings.TrimPrefix(name, "./"), ".action")
					raw := readPublic(ctx, s.Store, ports.Ref{Name: stem, Kind: ports.GovActionFile})
					if raw == nil {
						continue
					}
					af, err := env.ActionFiles.DecodeActionFile(raw)
					if err != nil {
						continue
					}
					for i, l := range actionLines(af.Action) {
						if i == 0 {
							l = stem + ": " + l
						} else {
							l = "  " + l
						}
						details = append(details, l)
					}
				}
				uc := governance.RegisterAction{Base: a.govBase(s, env, &f, govConfirmer{a: a, details: details}), Actions: env.ActionFiles,
					Rewards: env.Rewards, AllowUnverified: f.allowUnverified}
				res, err := uc.Run(ctx, governance.RegisterActionRequest{Payer: args[0], Files: files, Message: f.messages})
				if err != nil {
					var ge *governance.GuardrailsError
					if errors.As(err, &ge) {
						return guardrailsMessage(ge)
					}
					return f.hint(err)
				}
				var ids []string
				for i, id := range res.IDs {
					ids = append(ids, fmt.Sprintf("Proposal %d will be action %s (%s).", i+1, id.Hex, id.CIP129))
				}
				a.govReport(govOutcome{kind: "governance action proposal", payer: payerStem(args[0]), res: res.Result, details: details, extra: ids}, &f, env, wo)
				return nil
			})
		},
	}
	f.add(cmd, govOpts{tx: true, allow: true})
	return cmd
}

// guardrailsMessage prints exactly what a guardrails proposal is missing.
func guardrailsMessage(e *governance.GuardrailsError) error {
	var kinds []string
	for _, k := range e.Kinds {
		kinds = append(kinds, string(k))
	}
	msg := "the proposal cannot be built: " + strings.Join(kinds, ", ") + " must carry the constitution's guardrails script, and this build does not evaluate it.\nWhat is missing:\n"
	for _, m := range e.Missing {
		msg += "  - " + m + "\n"
	}
	msg += "Nothing was signed, submitted or queued."
	return &explained{msg: msg, err: e}
}
