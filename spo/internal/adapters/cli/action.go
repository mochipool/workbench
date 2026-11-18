package cli

import (
	"context"
	"encoding/json"
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
	costModelFile    string
	allowCMLength    bool
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
		"param": {dgov.ParameterChange}, "cost-model-file": {dgov.ParameterChange}, "allow-cost-model-length-change": {dgov.ParameterChange},
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
	f.BoolVar(&af.allowCMLength, "allow-cost-model-length-change", false, allowCMLengthHelp)
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
	f.StringArrayVar(&af.params, "param", nil, "parameter-change: NAME=VALUE (repeatable); the names are listed in the help of this command")
	f.StringVar(&af.costModelFile, "cost-model-file", "", "parameter-change: a JSON file {\"PlutusV1\": [...], \"PlutusV2\": [...], \"PlutusV3\": [...]} of the cost models to set (the languages in it)")
}

const allowCMLengthHelp = "parameter-change: accept a cost model with another number of values than the current one in the provider's parameters (a new Plutus version's model does); without it the command is refused"

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
takes --constitution-url and --constitution-hash; parameter-change takes
--param NAME=VALUE (repeatable) and --cost-model-file. The parameters are the 41
of upstream's 25a, plus three that cardano-cli offers and upstream does not
(cost models, and the execution-unit limits of a transaction and of a block):
` + paramHelp() + `
Values are checked by type: integers by the width of the ledger's type (a
NATURAL is not zero), rationals as an integer, a decimal (0.0577) or a fraction
(2/3), at most 1 except ref-script-cost-per-byte. The pool-voting-threshold-*
parameters (5), the drep-voting-threshold-* parameters (10) and the two
price-execution-* parameters are given all together or not at all. The summary
lists every parameter set with the value it has now when the chain's parameters
document gives it, and the value it will have.

The protocol parameters come from the chain or, offline, from the transfer file.
A kind reads only what it needs: the last enacted action for the kinds that name
a previous action (no-confidence, update-committee, new-constitution, hard-fork,
parameter-change), the constitution's guardrails script for treasury withdrawals
and parameter changes, the current epoch for the terms of update-committee. An
info action needs no chain reader, so it also runs offline.

The anchor document would be checked against CIP-108; this build has no
verifier, so a fetched document is refused unless you pass --anchor-unverified,
which accepts that it was not checked (the hash is recorded as given). Treasury
withdrawals and parameter changes carry the constitution's guardrails script hash
and need the script itself when they are submitted ("action submit").`,
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
				ConstitutionURL: af.constitutionURL, ConstitutionHash: af.constitutionHash, AllowCostModelLengthChange: af.allowCMLength}
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
			if af.costModelFile != "" {
				needs = append(needs, CapMetaFiles)
			}
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
				if af.costModelFile != "" {
					b, err := env.MetadataFiles.ReadMetadataFile(af.costModelFile)
					if err != nil {
						return fmt.Errorf("--cost-model-file: %w", err)
					}
					req.Params = append(req.Params, dgov.ParamChange{Name: "cost-models", Value: string(b)})
				}
				uc := governance.GenerateAction{Store: s.Store, Actions: env.ActionFiles, Params: env.Params, Epoch: env.Epochs,
					Constitution: env.Constitution, LastEnacted: env.LastEnacted, Clock: env.Clock,
					Anchors: governance.AnchorSource{Fetcher: env.AnchorFetcher}, Verifier: env.AnchorVerifier,
					AnchorUnverifiedAcknowledged: f.anchorUnverified, NetworkID: env.NetworkID}
				res, err := uc.Run(ctx, req)
				if err != nil {
					return f.hint(err)
				}
				w := a.d.Out
				for _, d := range res.Decisions {
					fmt.Fprintf(w, "Decision: %s.\n", shown(fmt.Sprint(d)))
				}
				if f.anchorUnverified && (f.anchorURL != "") {
					fmt.Fprintf(w, "NOT CHECKED %s.\n", anchorUnverifiedNote)
				}
				for _, l := range actionLines(res.Action, res.ParamDiffs) {
					fmt.Fprintf(w, "  %s\n", shown(l))
				}
				fmt.Fprintf(w, "Stored %s.\n", artefact(res.Ref))
				if res.NeedsGuardrails {
					if res.Action.Guardrails != nil {
						fmt.Fprintf(w, "The file carries the constitution's guardrails script hash %x: `spo action submit` attaches the script, which needs a provider that evaluates it.\n", res.Action.Guardrails[:])
					} else {
						fmt.Fprintln(w, "The constitution names no guardrails script: the file carries none.")
					}
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
//
// For a parameter change every parameter is listed with the value it will have
// and, when diffs say so, the value it has now; with no diffs (no parameters
// document was available) the new values are listed and the old are said to be
// unknown.
func actionLines(act dgov.Action, diffs []dgov.ParamDiff) []string {
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
			out = append(out, fmt.Sprintf("withdraws %s to %s", lovelaceText(w.Amount), shown(fmt.Sprint(w.Account))))
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
		if diffs == nil {
			diffs = dgov.DescribeParams(act.Params, nil)
		}
		out = append(out, fmt.Sprintf("changes %d protocol parameter(s):", len(diffs)))
		for _, d := range diffs {
			out = append(out, "  "+d.Line())
		}
	}
	if act.Guardrails != nil && (act.Kind == dgov.ParameterChange || act.Kind == dgov.TreasuryWithdrawals) {
		out = append(out, fmt.Sprintf("guardrails script %x (the proposal needs it as a witness)", act.Guardrails[:]))
	}
	if act.Prev != nil {
		out = append(out, "follows the last enacted action "+act.Prev.Hex())
	}
	return out
}

func (a *app) actionSubmitCommand() *cobra.Command {
	var f govFlags
	var guardrailsScript string
	var allowCMLength bool
	cmd := &cobra.Command{
		Use:   "submit <payer> <action-file>... [--guardrails-script FILE] [--allow-unverified] [--message TEXT]... [--yes] [--transfer-file PATH]",
		Short: "Put governance action files on the chain in one transaction (pays the proposal deposits)",
		Long: `Build one transaction that carries the proposals of the given action files
(<name>_<yymmddHHMMSS>.action, with or without the extension), paid by the stored
address <payer>; the change is the inputs minus the fee and the deposits. Only the
payment key signs. The validity is the tip plus 25000 slots.

The deposit-return stake address of each proposal must be registered. Where the
chain cannot say (no reader in this mode, or the source does not know) the command
is refused unless you pass --allow-unverified; the summary lists the check that
was skipped. A wrong answer only makes the ledger reject the transaction.

A treasury withdrawal or parameter change must carry the constitution's guardrails
script when the constitution names one. Then the transaction also carries the
script (--guardrails-script, default ` + governance.DefaultGuardrailsScriptFile + `) as a witness with a
"proposing" redeemer for each such proposal, sets one of your UTxOs aside as
collateral (no tokens, 5 to 10 ADA; it is not an input and it is forfeited if the
script fails on chain) and pays the script's execution units in the fee. The
script's hash must equal the constitution's, which is read from the chain, and the
action files must carry it; otherwise the command is refused. This build does not
run Plutus: the execution units come from a provider that evaluates the
transaction (light mode with Koios), and a provider that cannot say, or reports a
failure, ends the command before anything is signed. Offline mode cannot do it.
Action files that need the script must come before those that do not. A hardware
wallet cannot pay for a governance action. The summary lists the script hash, the
units of each redeemer, the collateral and the provider that evaluated them.

The summary lists each proposal with its kind, deposit, return address and anchor
(a parameter change with each parameter, old and new value), and the ids the
proposals will have are printed after submission.`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			files := args[1:]
			needs := govTxNeeds(CapActionFiles)
			// The file name carries the kind (25a's naming, SPO-25a-OUT-006), so a
			// command that will need the evaluator says so before any prompt. A
			// renamed file is caught later, when it has been read, before anything
			// is signed.
			if namesGuardrailKind(files) {
				needs = append(needs, CapConstitution, CapTxEvaluator, CapMetaFiles)
			}
			spec := envSpec{flags: &f.chain, config: true, needs: needs, extras: &f.extra}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, wo WireOptions) error {
				var details []string
				var oldParams json.RawMessage
				loaded := false
				guard := false
				for _, name := range files {
					stem := strings.TrimSuffix(strings.TrimPrefix(name, "./"), ".action")
					raw := readPublic(ctx, s.Store, ports.NamedRef{Name: stem, Kind: ports.GovActionFile})
					if raw == nil {
						continue
					}
					af, err := env.ActionFiles.DecodeActionFile(raw)
					if err != nil {
						continue
					}
					var diffs []dgov.ParamDiff
					if af.Action.Kind == dgov.ParameterChange {
						if !loaded && env.Params != nil {
							loaded = true
							if p, err := env.Params.ProtocolParameters(ctx); err == nil {
								oldParams = p.Raw
							}
						}
						diffs = dgov.DescribeParams(af.Action.Params, oldParams)
					}
					guard = guard || af.Action.Kind == dgov.ParameterChange || af.Action.Kind == dgov.TreasuryWithdrawals
					for i, l := range actionLines(af.Action, diffs) {
						if i == 0 {
							l = stem + ": " + l
						} else {
							l = "  " + l
						}
						details = append(details, l)
					}
				}
				if guard {
					// Again, now the kinds are known: still before any prompt.
					if err := env.Require(CapConstitution, CapTxEvaluator, CapMetaFiles); err != nil {
						return err
					}
				}
				uc := governance.RegisterAction{Base: a.govBase(s, env, &f, govConfirmer{a: a, details: details}), Actions: env.ActionFiles,
					Rewards: env.Rewards, AllowUnverified: f.allowUnverified, Constitution: env.Constitution, Evaluator: env.TxEvaluator}
				res, err := uc.Run(ctx, governance.RegisterActionRequest{Payer: args[0], Files: files, Message: f.messages, Extras: f.extra.ex, Passphrase: f.extra.pass,
					GuardrailsScript: guardrailsScript, AllowCostModelLengthChange: allowCMLength})
				if err != nil {
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
	cmd.Flags().BoolVar(&allowCMLength, "allow-cost-model-length-change", false, allowCMLengthHelp)
	cmd.Flags().StringVar(&guardrailsScript, "guardrails-script", "", "the constitution's guardrails script, a PlutusScriptV3 .plutus file (default "+governance.DefaultGuardrailsScriptFile+"); read only when a proposal needs it")
	return cmd
}

// namesGuardrailKind reports whether an action file name says it is a treasury
// withdrawal or a parameter change (`<stake>_<kind>_<ts>.action`).
func namesGuardrailKind(files []string) bool {
	for _, f := range files {
		l := strings.ToLower(f)
		if strings.Contains(l, "treasurywithdrawals") || strings.Contains(l, "parameterchange") {
			return true
		}
	}
	return false
}

// paramHelp lists the parameter names for the help text.
func paramHelp() string {
	var sb strings.Builder
	line := "  "
	for _, n := range dgov.ParamNames() {
		if len(line)+len(n)+2 > 78 {
			sb.WriteString(strings.TrimRight(line, " ") + "\n")
			line = "  "
		}
		line += n + ", "
	}
	sb.WriteString(strings.TrimSuffix(strings.TrimRight(line, " "), ",") + ".")
	return sb.String()
}
