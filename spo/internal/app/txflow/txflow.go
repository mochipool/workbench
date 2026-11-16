// Package txflow runs the shared transaction pipeline of the stake use
// cases (spec/upstream/patterns/Ptx.md, stages 6 to 12) over a draft the
// use case has built: fee and balance, the one body, the signing plan, the
// confirmation, the witnesses, the assembly and the submission or the queue.
//
// SendLovelaces (app/wallet) was written first and carries its own copy of
// these stages; the rules are the same and the tests of both cite the same
// ids. A use case reads its inputs and runs its own pre-checks, then hands
// the draft to Execute; nothing here knows what a certificate means beyond
// the features and witnesses the draft states.
package txflow

import (
	"context"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals of the pipeline.
var (
	// ErrNoSigner: a signer of the plan cannot witness transactions.
	ErrNoSigner = errors.New("a signer of the plan cannot witness transactions")
	// ErrNoConfirmer: confirmation is required and no Confirmer is wired.
	ErrNoConfirmer = errors.New("the transaction needs confirmation and no confirmer is configured; set the approval policy explicitly to skip it")
	// ErrDeclined: the operator did not approve; nothing was signed,
	// submitted or queued.
	ErrDeclined = errors.New("the transaction was not approved")
	// ErrMisconfigured: the composition is wrong (a programming error).
	ErrMisconfigured = errors.New("the transaction pipeline is not wired correctly")
)

// ApprovalPolicy says how the final confirmation is obtained. Skipping it
// is explicit and recorded in the result (SPO-Ptx-SEC-003). The values are
// those of wallet.ApprovalPolicy.
type ApprovalPolicy int

const (
	// ApprovalAsk asks the Confirmer. It is the zero value.
	ApprovalAsk ApprovalPolicy = iota
	// ApprovalSkip proceeds without asking: the audited replacement of
	// upstream's ENV_SKIP_PROMPT=YES.
	ApprovalSkip
)

// Pipeline holds the ports of stages 6 to 12. Exactly one of Submitter and
// Queue is set.
type Pipeline struct {
	Signers   ports.SignerDirectory
	Min       ports.MinOutputCalculator
	Fees      ports.FeeEstimator
	Bodies    ports.TxBodyBuilder
	Assembler ports.TxAssembler
	Confirmer ports.Confirmer
	Submitter ports.TxSubmitter
	Queue     ports.TxQueue
	Approval  ApprovalPolicy
}

// Slot is one signature of the workflow: the key reference and the key hash
// the witness must prove.
type Slot struct {
	Label string
	Key   custody.KeyRef
	Hash  txbuild.KeyHash
	// Features, when set, replaces the draft's features for this slot's
	// demand: a pool registration asks the cold key's signer for the
	// operator mode and an owner's signer for the owner mode.
	Features custody.Features
}

// Check refuses a pipeline that is not wired for exactly one route.
func (p Pipeline) Check() error {
	if (p.Submitter == nil) == (p.Queue == nil) {
		return fmt.Errorf("%w: exactly one of Submitter and Queue must be set", ErrMisconfigured)
	}
	if p.Signers == nil || p.Min == nil || p.Fees == nil || p.Bodies == nil || p.Assembler == nil {
		return fmt.Errorf("%w: a ledger or signer port is missing", ErrMisconfigured)
	}
	return nil
}

// Route is "queue" or "submit".
func (p Pipeline) Route() string {
	if p.Queue != nil {
		return "queue"
	}
	return "submit"
}

// Prepared is a signing plan with the witnessers it resolved.
type Prepared struct {
	Plan custody.Plan
	// Pending are the slots PreparePartial left to another holder.
	Pending   []Slot
	slots     []Slot
	witnesser []ports.TxWitnesser
}

// Prepare builds the signing plan from the draft's features, before the
// body is finalised, shown or confirmed (ADR 0008). A slot whose holder has
// no signer in the directory, or a signer that cannot meet the demand (a
// hardware wallet today), refuses here and nothing has been written. The
// count of slots is the workflow's fixed witness count (SPO-Ptx-INV-006) and
// every stake key the draft requires must have a slot.
//
// spec: SPO-Ptx-INV-006, SPO-Ptx-PRE-006
func (p Pipeline) Prepare(draft txbuild.Draft, slots []Slot, witnesses uint) (Prepared, error) {
	return p.PreparePartial(draft, slots, witnesses, nil)
}

// PreparePartial is Prepare for a workflow whose slots may be signed
// elsewhere: a slot for which pending returns true is not planned here (no
// signer is looked up for it) and is listed in Prepared.Pending. The count of
// slots is still the fee's witness count, and every required stake key still
// has a slot. The pool registration uses it when a holder is remote and the
// caller allows a collection with an open slot.
//
// spec: SPO-Ptx-INV-006, SPO-Xparty-PRE-003
func (p Pipeline) PreparePartial(draft txbuild.Draft, slots []Slot, witnesses uint, pending func(Slot) bool) (Prepared, error) {
	if uint(len(slots)) != witnesses {
		return Prepared{}, fmt.Errorf("%w: %d signatures planned, the fee is estimated for %d", ErrMisconfigured, len(slots), witnesses)
	}
	feats, err := draft.Features()
	if err != nil {
		return Prepared{}, err
	}
	for _, k := range draft.RequiredStakeKeys() {
		found := false
		for _, s := range slots {
			if s.Key.Role == custody.RoleStake && s.Hash == txbuild.KeyHash(k) {
				found = true
			}
		}
		if !found {
			return Prepared{}, fmt.Errorf("%w: no signature is planned for the required stake key %x", ErrMisconfigured, k[:])
		}
	}
	var local, remote []Slot
	for _, s := range slots {
		if pending != nil && pending(s) {
			remote = append(remote, s)
		} else {
			local = append(local, s)
		}
	}
	slots = local
	cs := make([]custody.Slot, len(slots))
	for i, s := range slots {
		f := feats
		if s.Features != nil {
			f = s.Features
		}
		cs[i] = custody.Slot{Label: s.Label, Key: s.Key, Demand: custody.Demand{Role: s.Key.Role, Operation: custody.OpWitnessTx, Features: f}}
	}
	var plan custody.Plan
	if len(cs) > 0 {
		if plan, err = ports.PlanSignatures(p.Signers, cs); err != nil {
			return Prepared{}, err
		}
	}
	out := Prepared{Plan: plan, slots: slots, Pending: remote}
	for _, s := range slots {
		signer, err := p.Signers.SignerFor(s.Key)
		if err != nil {
			return Prepared{}, err
		}
		w, ok := signer.(ports.TxWitnesser)
		if !ok {
			return Prepared{}, fmt.Errorf("%w: the %s key of %s", ErrNoSigner, s.Key.Role, s.Key.Owner)
		}
		out.witnesser = append(out.witnesser, w)
	}
	return out, nil
}

// Input is what Execute works from.
type Input struct {
	Draft     txbuild.Draft
	Params    chain.ProtocolParameters
	TTL       uint64
	Prepared  Prepared
	Witnesses uint
	// Summary is the operator's view; Execute fills in the figures of the
	// balanced body (inputs, outputs, fee, TTL, size, id, route).
	Summary ports.TxSummary
	// Queued is the queue entry; Execute fills in the signed transaction.
	Queued ports.QueuedTx
	// SkipSizeCheck leaves the size check out (nobody sets it today:
	// 01_claimRewards skips it upstream, SPO-01claimRewards-INV-005, and
	// the port does not).
	SkipSizeCheck bool
}

// Result is what happened.
type Result struct {
	TxID            chain.TxID
	Fee             chain.Lovelace
	TTL             uint64
	Outputs         []txbuild.Output
	Inputs          int
	Size            int
	SignedTx        []byte
	Submitted       bool
	Queued          bool
	ApprovalSkipped bool
}

// Built is a balanced body that passed the size estimate.
type Built struct {
	Balanced      txbuild.Balanced
	EstimatedSize int
}

// SlotWitness is a witness produced for a planned slot, not yet verified.
type SlotWitness struct {
	Slot    Slot
	Witness txbuild.Witness
}

// Sign asks the signer of every planned (not pending) slot for its witness
// over the body. Nothing is verified here: the pool collection verifies every
// witness, local or remote, on the one path that fills a slot.
func (p Prepared) Sign(ctx context.Context, body txbuild.TxBody) ([]SlotWitness, error) {
	var out []SlotWitness
	for i, slot := range p.slots {
		w, err := p.witnesser[i].Witness(ctx, slot.Key, body)
		if err != nil {
			return nil, fmt.Errorf("witness for the %s key of %s: %w", slot.Key.Role, slot.Key.Owner, err)
		}
		out = append(out, SlotWitness{Slot: slot, Witness: w})
	}
	return out, nil
}

// Build runs stages 6 to 8: fee and balance, the one body, and the size
// estimate. Nothing is confirmed, signed or sent. The pool use cases call
// it, then collect witnesses in their own collection, then Deliver.
//
// spec: SPO-Ptx-EXT-001, SPO-Ptx-EXT-002, SPO-Ptx-INV-005, SPO-Ptx-INV-006, SPO-Ptx-INV-007, SPO-Ptx-PRE-002, SPO-Ptx-PRE-007
func (p Pipeline) Build(in Input) (Built, error) {
	if err := p.Check(); err != nil {
		return Built{}, err
	}
	bal, err := in.Draft.Balance(in.TTL, txbuild.Ledger{
		MinOutput: func(o txbuild.Output) (chain.Lovelace, error) { return p.Min.MinOutput(in.Params, o) },
		Fee: func(b txbuild.TxBody) (chain.Lovelace, error) {
			return p.Fees.EstimateFee(in.Params, b, in.Witnesses)
		},
		Build: p.Bodies.BuildBody,
	})
	if err != nil {
		return Built{}, err
	}
	est, err := p.Fees.EstimateSize(bal.Body, in.Witnesses)
	if err != nil {
		return Built{}, err
	}
	if !in.SkipSizeCheck {
		if err := txbuild.CheckSize(est, in.Params.MaxTxSize); err != nil {
			return Built{}, err
		}
	}
	return Built{Balanced: bal, EstimatedSize: est}, nil
}

// Confirm asks for the approval of the built body (stage 11), or records
// that the policy skips it. It returns whether the confirmation was skipped.
//
// spec: SPO-Ptx-PR-002, SPO-Ptx-PR-003
func (p Pipeline) Confirm(ctx context.Context, in Input, b Built) (skipped bool, err error) {
	switch p.Approval {
	case ApprovalSkip:
		return true, nil
	case ApprovalAsk:
		if p.Confirmer == nil {
			return false, ErrNoConfirmer
		}
		bal := b.Balanced
		sum := in.Summary
		sum.Inputs, sum.Outputs, sum.Fee, sum.TTL = len(bal.Spec.Inputs), bal.Spec.Outputs, bal.Spec.Fee, bal.Spec.TTL
		sum.Message, sum.Size, sum.TxID, sum.Route = bal.Spec.Message, b.EstimatedSize, bal.Body.ID, p.Route()
		yes, err := p.Confirmer.Confirm(ctx, sum)
		if err != nil {
			return false, fmt.Errorf("confirmation: %w", err)
		}
		if !yes {
			return false, ErrDeclined
		}
		return false, nil
	}
	return false, fmt.Errorf("%w: unknown approval policy %d", ErrMisconfigured, p.Approval)
}

// Deliver assembles the body with the witnesses it is given, checks the
// signed size, and submits or queues exactly that transaction (stages 10 and
// 12). The witnesses must already be verified against the body. spec may be
// nil when the body was built by an earlier run: the result then carries no
// fee or outputs.
//
// spec: SPO-Ptx-PRE-007, SPO-Ptx-INV-010, SPO-Ptx-MODE-008, SPO-Ptx-MODE-010
func (p Pipeline) Deliver(ctx context.Context, in Input, body txbuild.TxBody, spec *txbuild.BodySpec, witnesses []txbuild.Witness, skipped bool) (Result, error) {
	if err := p.Check(); err != nil {
		return Result{}, err
	}
	signed, err := p.Assembler.Assemble(body, witnesses)
	if err != nil {
		return Result{}, err
	}
	if signed.ID != body.ID {
		return Result{}, errors.New("the assembled transaction has a different id from the confirmed body")
	}
	if !in.SkipSizeCheck {
		if err := txbuild.CheckSize(len(signed.CBOR), in.Params.MaxTxSize); err != nil {
			return Result{}, err
		}
	}
	res := Result{TxID: signed.ID, Size: len(signed.CBOR), SignedTx: signed.CBOR, ApprovalSkipped: skipped}
	if spec != nil {
		res.Fee, res.TTL, res.Outputs, res.Inputs = spec.Fee, spec.TTL, spec.Outputs, len(spec.Inputs)
	}
	if p.Queue != nil {
		q := in.Queued
		q.Tx = signed
		if err := p.Queue.Enqueue(ctx, q); err != nil {
			return Result{}, fmt.Errorf("queue the transaction: %w", err)
		}
		res.Queued = true
		return res, nil
	}
	id, err := p.Submitter.Submit(ctx, signed.CBOR)
	if err != nil {
		return Result{}, fmt.Errorf("submit: %w", err)
	}
	if id != signed.ID {
		return Result{}, fmt.Errorf("the provider answered transaction id %s for %s", id, signed.ID)
	}
	res.Submitted = true
	return res, nil
}

// Execute runs stages 6 to 12: fee and balance, the one body, the size
// check, the confirmation, the witnesses (each verified against the body and
// the key hash of its slot), the assembly, and the submission or the queue
// entry of exactly what was confirmed.
//
// spec: SPO-Ptx-EXT-001, SPO-Ptx-EXT-002, SPO-Ptx-INV-005, SPO-Ptx-INV-006, SPO-Ptx-INV-007, SPO-Ptx-INV-010,
// spec: SPO-Ptx-PRE-002, SPO-Ptx-PRE-007, SPO-Ptx-PR-002, SPO-Ptx-PR-003, SPO-Ptx-MODE-008, SPO-Ptx-MODE-010
func (p Pipeline) Execute(ctx context.Context, in Input) (Result, error) {
	built, err := p.Build(in)
	if err != nil {
		return Result{}, err
	}
	skipped, err := p.Confirm(ctx, in, built)
	if err != nil {
		return Result{}, err
	}
	bal := built.Balanced

	var witnesses []txbuild.Witness
	for i, slot := range in.Prepared.slots {
		w, err := in.Prepared.witnesser[i].Witness(ctx, slot.Key, bal.Body)
		if err != nil {
			return Result{}, fmt.Errorf("witness for the %s key of %s: %w", slot.Key.Role, slot.Key.Owner, err)
		}
		if err := txbuild.VerifyWitness(bal.Body, w, slot.Hash); err != nil {
			return Result{}, fmt.Errorf("witness for the %s key of %s: %w", slot.Key.Role, slot.Key.Owner, err)
		}
		witnesses = append(witnesses, w)
	}
	spec := bal.Spec
	return p.Deliver(ctx, in, bal.Body, &spec, witnesses, skipped)
}
