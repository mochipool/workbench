package governance

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// The guardrails variant of 25b (SPO-25b-EXT-001 to SPO-25b-EXT-008): when the
// constitution names a guardrails script, a treasury withdrawal or parameter
// change proposal must carry it as a witness with a `proposing` redeemer, the
// payer sets aside a collateral UTxO, and the execution units of the script
// are part of the fee and of the script-data hash.
//
// This build runs no Plutus script. The execution units come from a
// ports.TxEvaluator (a provider that evaluates the transaction); the use case
// iterates: a body with the units found so far, evaluate it, take the larger
// units, until the body that is built is the one evaluated. The answer rests on
// that provider and the summary says so. Upstream evaluates the units on a
// dummy body with a fee of 200000 and builds the final body with them
// (SPO-25b-EXT-001, SPO-25b-EXT-005); evaluating the body that is signed is
// stricter.

// Refusals of the guardrails variant.
var (
	// ErrScriptMismatch: the guardrails script of the proposal, of the local
	// file and of the constitution do not agree (SPO-25b-PRE-014: upstream
	// prints the two hashes and exits 0).
	ErrScriptMismatch = errors.New("the guardrails script does not match the constitution's")
	// ErrEvaluationUnknown: the provider did not say what the script costs.
	ErrEvaluationUnknown = errors.New("the execution units of the guardrails script could not be determined")
	// ErrEvaluationUnsettled: the units kept growing between evaluations.
	ErrEvaluationUnsettled = errors.New("the execution units did not settle after repeated evaluation")
	// ErrProposalOrder: a proposal without the script comes before one that
	// needs it.
	ErrProposalOrder = errors.New("a proposal that needs the guardrails script must not come after one that does not")
	// ErrUnitsLimit: the units exceed the transaction's limit.
	ErrUnitsLimit = errors.New("the execution units exceed the maximum of a transaction")
)

// guardrailRedeemer is the redeemer data of a guardrails proposal: the empty
// map, cardano-cli's `--proposal-redeemer-value {}` (SPO-25b-EXT-001). The
// constitution's script is checked by the ledger against the proposal; this
// build does not know what the script does with its redeemer.
var guardrailRedeemer = []byte{0xa0}

const maxEvaluations = 4

// DefaultGuardrailsScriptFile is upstream's default of `guardrailsScriptFile`.
const DefaultGuardrailsScriptFile = "./guardrails-script.plutus"

// plutusRun is the guardrails part of a transaction run.
type plutusRun struct {
	script    txbuild.Script
	params    txbuild.PlutusParams
	positions []uint32 // proposals that need the script, by position in the body
	evaluator ports.TxEvaluator
	// constitution is the source of the constitution's script hash.
	constitution chain.Source
	report       *GuardrailReport
}

// GuardrailReport says what the guardrails part of a transaction came to.
type GuardrailReport struct {
	ScriptHash [28]byte
	Evaluator  chain.Source
	// Constitution is where the script hash of the constitution was read.
	Constitution chain.Source
	Collateral   chain.Utxo
	// AtRisk is the most the ledger takes if the script fails: the total
	// collateral as read back from the body that is signed, not the figure of
	// any provider.
	AtRisk chain.Lovelace
	// Redeemers carry the evaluated units; ScriptFee is their price, part of
	// the fee.
	Redeemers []txbuild.Redeemer
	ScriptFee chain.Lovelace
	// Evaluations is the number of times the provider was asked.
	Evaluations int
}

// Lines are the summary lines the operator confirms.
func (g GuardrailReport) Lines() []string {
	out := []string{fmt.Sprintf("guardrails script %x, the constitution's (read from %s), attached to %d proposal(s)", g.ScriptHash[:], g.Constitution, len(g.Redeemers))}
	for _, r := range g.Redeemers {
		out = append(out, fmt.Sprintf("  redeemer for proposal %d (proposing, data {}): memory %d, steps %d", r.Index+1, r.Units.Mem, r.Units.Steps))
	}
	out = append(out,
		fmt.Sprintf("script fee %d lovelace, part of the fee", g.ScriptFee),
		fmt.Sprintf("collateral at risk: at most %d lovelace (the total collateral of the body; the rest of %s#%d returns to the payer)", g.AtRisk, g.Collateral.TxID, g.Collateral.Index))
	return out
}

// Notes are what was not verified.
func (g GuardrailReport) Notes() []string {
	return []string{fmt.Sprintf("the guardrails script was NOT evaluated by this program: its execution units come from %s (asked %d time(s)); units that are too low make the script fail on chain and cost the collateral", g.Evaluator, g.Evaluations)}
}

// needsGuardrails reports whether the kind carries the constitution's
// guardrails script as its policy.
func needsGuardrails(k governance.ActionKind) bool {
	return k == governance.TreasuryWithdrawals || k == governance.ParameterChange
}

// guardrails decides the variant and prepares it: it reads the constitution,
// requires the proposals' script hash, the local script and the constitution's
// to agree, and returns nil when no proposal needs a script (a constitution
// without one and files without one: the plain variant).
//
// spec: SPO-25b-INV-006, SPO-25b-PRE-012, SPO-25b-PRE-014, SPO-25b-EXT-004, SPO-25b-IN-004, SPO-25b-IN-005
func (uc RegisterAction) guardrails(ctx context.Context, props []txbuild.ProposalAttachment, params chain.ProtocolParameters, scriptFile string) (*plutusRun, error) {
	need := false
	for _, p := range props {
		need = need || needsGuardrails(p.Action.Kind)
	}
	if !need {
		return nil, nil
	}
	if uc.Constitution == nil {
		return nil, fmt.Errorf("the constitution's guardrails script hash, which a treasury withdrawal or parameter change must match: %w", ErrNoChainReader)
	}
	cr, err := uc.Constitution.Constitution(ctx)
	if err != nil {
		return nil, fmt.Errorf("the constitution from %s: %w", uc.Constitution.Source(), err)
	}
	cons, ok := cr.Get()
	if !ok {
		why := "the provider has no constitution"
		if cr.IsUnknown() {
			why = cr.Why()
		}
		return nil, fmt.Errorf("%w: the constitution from %s: %s", ErrUnverified, uc.Constitution.Source(), why)
	}
	var positions []uint32
	for i, p := range props {
		if !needsGuardrails(p.Action.Kind) {
			continue
		}
		have, want := p.Action.Guardrails, cons.Script
		switch {
		case have == nil && want == nil:
			continue
		case have == nil:
			return nil, fmt.Errorf("%w: proposal %d (%s) carries no guardrails script hash but the constitution names %x: write the action file again (action create) so it carries it",
				ErrScriptMismatch, i+1, p.Action.Kind, want[:])
		case want == nil:
			return nil, fmt.Errorf("%w: proposal %d (%s) carries the script hash %x but the constitution read from %s has no guardrails script: write the action file again",
				ErrScriptMismatch, i+1, p.Action.Kind, have[:], uc.Constitution.Source())
		case *have != *want:
			return nil, fmt.Errorf("%w: proposal %d (%s) carries the script hash %x, the constitution's is %x: write the action file again",
				ErrScriptMismatch, i+1, p.Action.Kind, have[:], want[:])
		}
		positions = append(positions, uint32(i))
	}
	if len(positions) == 0 {
		return nil, nil
	}
	// The ledger numbers a proposing redeemer by the proposal's position in the
	// body. cardano-cli 11.2.3 numbers it among the proposals that have a script
	// (observed in the parity tests), which differs when a proposal without one
	// comes first; no body is built whose index the two readings dispute.
	for n, pos := range positions {
		if uint32(n) != pos {
			return nil, fmt.Errorf("%w: proposal %d needs it and an earlier proposal does not: list the action files that need the script first", ErrProposalOrder, pos+1)
		}
	}
	if uc.Evaluator == nil {
		return nil, fmt.Errorf("the execution units of the guardrails script (this build runs no Plutus script): %w", ErrNoChainReader)
	}
	if uc.Files == nil {
		return nil, fmt.Errorf("the guardrails script file: %w", ErrNoChainReader)
	}
	if scriptFile == "" {
		scriptFile = DefaultGuardrailsScriptFile
	}
	raw, err := uc.Files.ReadMetadataFile(scriptFile)
	if err != nil {
		return nil, fmt.Errorf("the guardrails script %s (download the constitution's script and give its path): %w", scriptFile, err)
	}
	script, err := txbuild.ParseScriptFile(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", scriptFile, err)
	}
	if script.Hash != *cons.Script {
		return nil, fmt.Errorf("%w: %s hashes to %x, the constitution (read from %s) names %x", ErrScriptMismatch, scriptFile, script.Hash[:], uc.Constitution.Source(), cons.Script[:])
	}
	pp, err := txbuild.ParsePlutusParams(params.Raw)
	if err != nil {
		return nil, err
	}
	return &plutusRun{script: script, params: pp, positions: positions, evaluator: uc.Evaluator, constitution: uc.Constitution.Source(), report: &GuardrailReport{}}, nil
}

// attach puts the script, its redeemers (with no units yet) and the collateral
// on the draft.
func (pr *plutusRun) attach(d txbuild.Draft, collateral []chain.Utxo) (txbuild.Draft, error) {
	reds := make([]txbuild.Redeemer, len(pr.positions))
	for i, pos := range pr.positions {
		reds[i] = txbuild.Redeemer{Tag: txbuild.RedeemProposing, Index: pos, Data: guardrailRedeemer}
	}
	return d.WithPlutus(txbuild.PlutusAttachment{Script: pr.script, Redeemers: reds, Collateral: collateral, CostModel: pr.params.CostModelV3, CollateralPercent: pr.params.CollateralPercent})
}

// scriptFees adds the price of the execution units to the size fee: the fee of
// a transaction with a script is the linear fee of its size plus the price of
// the units (SPO-25b-EXT-005; the oracle compares it with calculate-min-fee).
type scriptFees struct {
	ports.FeeEstimator
	extra chain.Lovelace
}

func (s scriptFees) EstimateFee(p chain.ProtocolParameters, body txbuild.TxBody, witnesses uint) (chain.Lovelace, error) {
	f, err := s.FeeEstimator.EstimateFee(p, body, witnesses)
	if err != nil {
		return 0, err
	}
	return f + s.extra, nil
}

// executeScripted is Pipeline.Execute for a draft with a Plutus attachment.
func (b Base) executeScripted(ctx context.Context, in txflow.Input, pr *plutusRun) (txflow.Result, error) {
	if in.Prepared.Hardware() {
		return txflow.Result{}, ErrHardwarePayer
	}
	if in.Draft.Plutus == nil {
		return txflow.Result{}, fmt.Errorf("%w: no Plutus attachment", ErrMisconfigured)
	}
	att := *in.Draft.Plutus
	units := att.TotalUnits()
	var built txflow.Built
	var cur txflow.Input
	var scriptFee chain.Lovelace
	evals := 0
	settled := false
	for round := 0; round < maxEvaluations && !settled; round++ {
		a, err := att.WithUnits(units)
		if err != nil {
			return txflow.Result{}, err
		}
		if scriptFee, err = pr.params.Prices.Fee(units...); err != nil {
			return txflow.Result{}, err
		}
		pipe := b.Pipeline
		pipe.Fees = scriptFees{FeeEstimator: b.Pipeline.Fees, extra: scriptFee}
		cur = in
		cur.Draft.Plutus = &a
		if built, err = pipe.BuildCtx(ctx, cur); err != nil {
			return txflow.Result{}, err
		}
		got, err := pr.evaluate(ctx, built.Balanced.Body.CBOR, a.Redeemers)
		evals++
		if err != nil {
			return txflow.Result{}, err
		}
		settled = true
		for i := range units {
			if !got[i].Within(units[i]) {
				settled = false
			}
			units[i] = units[i].Max(got[i])
		}
	}
	if !settled {
		return txflow.Result{}, ErrEvaluationUnsettled
	}
	final := *cur.Draft.Plutus
	if err := checkUnitsLimit(final.TotalUnits(), pr.params.MaxTx); err != nil {
		return txflow.Result{}, err
	}
	if err := txbuild.CheckCollateral(final.Collateral, built.Balanced.Spec.Fee, pr.params.CollateralPercent); err != nil {
		return txflow.Result{}, err
	}
	risk := built.Balanced.Body.CollateralAtRisk
	if risk == nil {
		return txflow.Result{}, fmt.Errorf("%w: the body that would be signed states no total collateral, so the whole of the collateral would be forfeit if the script fails", ErrMisconfigured)
	}
	*pr.report = GuardrailReport{ScriptHash: pr.script.Hash, Evaluator: pr.evaluator.Source(), Constitution: pr.constitution,
		Collateral: final.Collateral[0], AtRisk: *risk, Redeemers: final.Redeemers, ScriptFee: scriptFee, Evaluations: evals}
	cur.Summary.Attachments = append(append([]string(nil), cur.Summary.Attachments...), pr.report.Lines()...)
	cur.Summary.Unchecked = append(append([]string(nil), cur.Summary.Unchecked...), pr.report.Notes()...)
	cur.Summary.Sources = append(append([]chain.Source(nil), cur.Summary.Sources...), pr.evaluator.Source())

	skipped, err := b.Pipeline.Confirm(ctx, cur, built)
	if err != nil {
		return txflow.Result{}, err
	}
	bal := built.Balanced
	ws, err := cur.Prepared.SignWith(ctx, bal.Body, nil)
	if err != nil {
		return txflow.Result{}, err
	}
	var witnesses []txbuild.Witness
	for _, sw := range ws {
		if err := txbuild.VerifyWitness(bal.Body, sw.Witness, sw.Slot.Hash); err != nil {
			return txflow.Result{}, fmt.Errorf("witness for the %s key of %s: %w", sw.Slot.Key.Role, sw.Slot.Key.Owner, err)
		}
		witnesses = append(witnesses, sw.Witness)
	}
	spec := bal.Spec
	return b.Pipeline.Deliver(ctx, cur, bal.Body, &spec, witnesses, skipped)
}

// evaluate asks the provider for the units of every redeemer of the body and
// returns them in the order of the redeemers. A script that failed, an answer
// the provider did not give, a redeemer it left out and one it added are
// refusals: none is zero units.
func (pr *plutusRun) evaluate(ctx context.Context, tx []byte, reds []txbuild.Redeemer) ([]txbuild.ExUnits, error) {
	rd, err := pr.evaluator.EvaluateTx(ctx, tx)
	if err != nil {
		if errors.Is(err, ports.ErrScriptFailed) {
			return nil, fmt.Errorf("%w: nothing was signed: submitting this transaction would cost the collateral: %v", ports.ErrScriptFailed, err)
		}
		return nil, fmt.Errorf("evaluate the guardrails script with %s: %w", pr.evaluator.Source(), err)
	}
	list, ok := rd.Get()
	if !ok {
		why := "no answer"
		if rd.IsUnknown() {
			why = rd.Why()
		}
		return nil, fmt.Errorf("%w: %s: %s", ErrEvaluationUnknown, pr.evaluator.Source(), why)
	}
	got := make([]txbuild.ExUnits, len(reds))
	seen := make([]bool, len(reds))
	for _, e := range list {
		found := false
		for i, r := range reds {
			if r.Tag == e.Tag && r.Index == e.Index {
				if seen[i] {
					return nil, fmt.Errorf("%w: %s evaluated redeemer %d twice", ErrEvaluationUnknown, pr.evaluator.Source(), e.Index)
				}
				got[i], seen[i], found = e.Units, true, true
			}
		}
		if !found {
			return nil, fmt.Errorf("%w: %s evaluated a redeemer (purpose %d, index %d) the transaction does not have", ErrEvaluationUnknown, pr.evaluator.Source(), e.Tag, e.Index)
		}
	}
	var missing []string
	for i, ok := range seen {
		if !ok {
			missing = append(missing, fmt.Sprint(reds[i].Index+1))
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%w: %s gave no units for proposal(s) %s", ErrEvaluationUnknown, pr.evaluator.Source(), strings.Join(missing, ", "))
	}
	return got, nil
}

// checkUnitsLimit refuses units that exceed the transaction's limit. The sum is
// checked for overflow (two redeemers of 2^63 would otherwise wrap to zero) and
// a limit that the parameters do not state is a refusal, not a skipped check.
func checkUnitsLimit(units []txbuild.ExUnits, max txbuild.ExUnits) error {
	if max == (txbuild.ExUnits{}) {
		return fmt.Errorf("%w: the protocol parameters do not state maxTxExecutionUnits, so the execution units cannot be checked against it", ErrUnitsLimit)
	}
	var sum txbuild.ExUnits
	for _, u := range units {
		var carryMem, carrySteps bool
		sum.Mem, carryMem = addU64(sum.Mem, u.Mem)
		sum.Steps, carrySteps = addU64(sum.Steps, u.Steps)
		if carryMem || carrySteps {
			return fmt.Errorf("%w: the units of the redeemers add up to more than 64 bits", ErrUnitsLimit)
		}
	}
	if !sum.Within(max) {
		return fmt.Errorf("%w: memory %d, steps %d against %d and %d", ErrUnitsLimit, sum.Mem, sum.Steps, max.Mem, max.Steps)
	}
	return nil
}

// addU64 is a+b and whether it overflowed.
func addU64(a, b uint64) (uint64, bool) {
	s := a + b
	return s, s < a
}
