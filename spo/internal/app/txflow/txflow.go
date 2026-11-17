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
	// ErrNoCanonicalizer: a slot of the plan is held by a hardware wallet and
	// no HardwareCanonicalizer is wired. The body must be brought to hardware
	// form before it is fixed, shown or signed (SPO-Xparty-INV-012, SPO-Ctx-EXT-001),
	// so the use case refuses before any effect.
	ErrNoCanonicalizer = errors.New("a key of this transaction is held by a hardware wallet and no hardware canonicalizer is configured: the transaction body cannot be brought to the form the device accepts (it needs the release set's cardano-hw-cli)")
	// ErrMixedHolders: a hardware key and a key-file key sign the same
	// transaction in a workflow that does not allow the mix (SPO-Ptx-PRE-006).
	ErrMixedHolders = errors.New("a hardware wallet key cannot be combined with a key-file key in this transaction: a hardware wallet can only pay for its own stake, node or committee operation (SPO-Ptx-PRE-006)")
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
	// SourceNotes are added to the summary of a transaction whose checks rest on
	// two sources (a cross-check): the sources share a host and the operator
	// declared them independent.
	SourceNotes []string
	Submitter   ports.TxSubmitter
	Queue       ports.TxQueue
	Approval    ApprovalPolicy
	// Canonicalizer brings the body to the form a hardware wallet accepts. It
	// is needed exactly when a slot of the plan is held by hardware; nil with a
	// hardware slot is refused by Prepare (ErrNoCanonicalizer). It is never
	// called for a plan of software keys.
	Canonicalizer ports.HardwareCanonicalizer
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
	// hardware is true when a planned slot is held by a hardware wallet: the
	// body is then canonicalised before it is fixed. unrestricted is the
	// operator's consent to the device's unrestricted mode.
	hardware     bool
	unrestricted bool
}

// Hardware reports whether a planned slot is held by a hardware wallet, so the
// body is canonicalised before anything is shown or signed.
func (p Prepared) Hardware() bool { return p.hardware }

// PrepareOptions are the optional parts of PrepareWith.
type PrepareOptions struct {
	// Pending returns true for a slot signed elsewhere (see PreparePartial).
	Pending func(Slot) bool
	// Unrestricted is the operator's explicit consent to the device's
	// unrestricted signing mode (`--allow-unrestricted-mode`, SPO-21b-SEC-003,
	// SPO-24b-PR-001). It is never implied: a use case sets it only from a
	// request field the caller set after the operator agreed. It puts
	// custody.FeatUnrestricted in the demand of every hardware slot, so a
	// device that cannot do it refuses here, before any prompt; it changes
	// nothing for a software slot.
	Unrestricted bool
	// RefuseMixed refuses a plan in which a hardware key signs together with a
	// key-file key: 01_claimRewards, 03b, 06, 07b, 08b, 22b, 23c and 23e allow
	// only all-hardware or all-key-file (SPO-Ptx-PRE-006). Workflows with
	// their own combination rules (21b and 21d, 24b, 05c, 13b) leave it off.
	RefuseMixed bool
}

// Prepare builds the signing plan from the draft's features, before the
// body is finalised, shown or confirmed (ADR 0008). A slot whose holder has
// no signer in the directory, or a signer that cannot meet the demand (a
// vendor whose device lacks a feature of the body), refuses here and nothing
// has been written; so does a hardware slot when no canonicalizer is wired. The
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
	return p.PrepareWith(draft, slots, witnesses, PrepareOptions{Pending: pending})
}

// PrepareWith is PreparePartial with the options of a hardware plan. A slot
// held by hardware needs a Canonicalizer in the pipeline (ErrNoCanonicalizer
// otherwise); the demand of such a slot is the draft's features, or the slot's
// own, plus FeatUnrestricted when opt.Unrestricted.
//
// spec: SPO-Ptx-INV-006, SPO-Xparty-PRE-003, SPO-Xparty-INV-012, SPO-21b-SEC-003
func (p Pipeline) PrepareWith(draft txbuild.Draft, slots []Slot, witnesses uint, opt PrepareOptions) (Prepared, error) {
	pending := opt.Pending
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
	if opt.RefuseMixed {
		if err := refuseMixed(slots); err != nil {
			return Prepared{}, err
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
	hardware := false
	for i, s := range slots {
		f := feats
		if s.Features != nil {
			f = s.Features
		}
		if s.Key.Holder == custody.HolderHardware {
			hardware = true
			if opt.Unrestricted {
				f = withFeature(f, custody.FeatUnrestricted)
			}
		}
		cs[i] = custody.Slot{Label: s.Label, Key: s.Key, Demand: custody.Demand{Role: s.Key.Role, Operation: custody.OpWitnessTx, Features: f}}
	}
	// A hardware slot that is signed elsewhere (a pool owner's witness made
	// later by `pool witness`) still needs the canonical body: the body is fixed
	// and shown now, and the device will witness exactly it.
	for _, s := range remote {
		hardware = hardware || s.Key.Holder == custody.HolderHardware
	}
	if hardware && p.Canonicalizer == nil {
		return Prepared{}, ErrNoCanonicalizer
	}
	var plan custody.Plan
	if len(cs) > 0 {
		if plan, err = ports.PlanSignatures(p.Signers, cs); err != nil {
			return Prepared{}, err
		}
	}
	out := Prepared{Plan: plan, slots: slots, Pending: remote, hardware: hardware, unrestricted: opt.Unrestricted && hardware}
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

// RefuseMixed returns ErrMixedHolders when the slots mix a hardware key with a
// key-file (vault) key.
//
// spec: SPO-Ptx-PRE-006
func RefuseMixed(slots []Slot) error { return refuseMixed(slots) }

func refuseMixed(slots []Slot) error {
	var hw, soft bool
	for _, s := range slots {
		if s.Key.Holder == custody.HolderHardware {
			hw = true
		} else {
			soft = true
		}
	}
	if hw && soft {
		return ErrMixedHolders
	}
	return nil
}

// CanonicalBodies wraps a body builder so that every body it builds is brought
// to the form a hardware wallet accepts (the Canonicalizer runs after the
// builder, inside the fee loop, so the fee is estimated for the canonical body
// and its id is the one displayed and signed).
func CanonicalBodies(ctx context.Context, c ports.HardwareCanonicalizer, build txbuild.BodyFunc, opt ports.HardwareTxOptions) txbuild.BodyFunc {
	return func(spec txbuild.BodySpec) (txbuild.TxBody, error) {
		b, err := build(spec)
		if err != nil {
			return b, err
		}
		canon, changed, err := c.Canonicalize(ctx, b, opt)
		if err != nil {
			return txbuild.TxBody{}, fmt.Errorf("bring the transaction body to hardware form: %w", err)
		}
		if changed {
			return canon, nil
		}
		return b, nil
	}
}

// withFeature returns a copy of the features with one more.
func withFeature(fs custody.Features, f custody.Feature) custody.Features {
	out := custody.NewFeatures(f)
	for k := range fs {
		out[k] = struct{}{}
	}
	return out
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
	// Stage, when set, is called with the id and the validity bound of the
	// assembled transaction after every check has passed and right before it is
	// queued or submitted. A command that must keep a record for the
	// transaction (a pending update, hazard H9) writes it there, so a crash
	// after the submission cannot lose it. The fields it returns are added to
	// the queue entry; an error stops the delivery before anything leaves.
	Stage func(ctx context.Context, id chain.TxID, validUntil uint64, queued bool) ([]ports.QueuedField, error)
	// SkipSizeCheck leaves the size check out (nobody sets it today:
	// 01_claimRewards skips it upstream, SPO-01claimRewards-INV-005, and
	// the port does not).
	SkipSizeCheck bool
	// HardwareChangeKeys are keys whose hardware signing files are declared to
	// a device witness as `--change-output-key-file`, so the device recognises
	// the change output (SPO-Ptx-INV-009, SPO-01sendLovelaces-EXT-002). They are
	// used only for hardware slots and only when the body has two outputs.
	HardwareChangeKeys []custody.KeyRef
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
	return p.SignWith(ctx, body, nil)
}

// SignWith is Sign for a body with the change keys of a hardware witness
// (Input.HardwareChangeKeys, already reduced to what the body needs).
func (p Prepared) SignWith(ctx context.Context, body txbuild.TxBody, changeKeys []custody.KeyRef) ([]SlotWitness, error) {
	var out []SlotWitness
	for i, slot := range p.slots {
		w, err := p.witness(ctx, i, slot, body, changeKeys)
		if err != nil {
			return nil, fmt.Errorf("witness for the %s key of %s: %w", slot.Key.Role, slot.Key.Owner, err)
		}
		out = append(out, SlotWitness{Slot: slot, Witness: w})
	}
	return out, nil
}

// witness asks one planned slot's signer for its witness. A hardware slot is
// asked through WitnessWith with the operator's unrestricted choice and the
// change keys, when the signer takes them.
func (p Prepared) witness(ctx context.Context, i int, slot Slot, body txbuild.TxBody, changeKeys []custody.KeyRef) (txbuild.Witness, error) {
	if slot.Key.Holder == custody.HolderHardware {
		if hw, ok := p.witnesser[i].(ports.HardwareWitnesser); ok {
			return hw.WitnessWith(ctx, slot.Key, body, ports.HardwareTxOptions{Unrestricted: p.unrestricted, ChangeKeys: changeKeys})
		}
	}
	return p.witnesser[i].Witness(ctx, slot.Key, body)
}

// changeKeys are the hardware change keys of a body: declared only when the
// body has a change output beside the destination (two outputs).
func changeKeys(in Input, spec txbuild.BodySpec) []custody.KeyRef {
	if len(spec.Outputs) < 2 {
		return nil
	}
	return in.HardwareChangeKeys
}

// Build runs stages 6 to 8: fee and balance, the one body, and the size
// estimate. Nothing is confirmed, signed or sent. The pool use cases call
// it, then collect witnesses in their own collection, then Deliver.
//
// spec: SPO-Ptx-EXT-001, SPO-Ptx-EXT-002, SPO-Ptx-INV-005, SPO-Ptx-INV-006, SPO-Ptx-INV-007, SPO-Ptx-PRE-002, SPO-Ptx-PRE-007
func (p Pipeline) Build(in Input) (Built, error) {
	return p.BuildCtx(context.Background(), in)
}

// BuildCtx is Build with the context of the command. When a planned slot is
// held by a hardware wallet the balanced body is brought to hardware form here,
// before it is shown, confirmed, queued or handed to any witness collection:
// the canonical body is the body from then on and its id is the id that is
// displayed and signed (SPO-Xparty-INV-012, SPO-Ctx-EXT-001, SPO-Ptx-EXT-005).
// Every body of the fee loop is canonical, so the fee is estimated for, and
// paid on, the body that is signed.
//
// spec: SPO-Xparty-INV-012, SPO-Ctx-EXT-001, SPO-Ptx-EXT-005
func (p Pipeline) BuildCtx(ctx context.Context, in Input) (Built, error) {
	if err := p.Check(); err != nil {
		return Built{}, err
	}
	build := p.Bodies.BuildBody
	if in.Prepared.hardware {
		if p.Canonicalizer == nil {
			return Built{}, ErrNoCanonicalizer
		}
		build = CanonicalBodies(ctx, p.Canonicalizer, build, ports.HardwareTxOptions{Unrestricted: in.Prepared.unrestricted})
	}
	bal, err := in.Draft.Balance(in.TTL, txbuild.Ledger{
		MinOutput: func(o txbuild.Output) (chain.Lovelace, error) { return p.Min.MinOutput(in.Params, o) },
		Fee: func(b txbuild.TxBody) (chain.Lovelace, error) {
			return p.Fees.EstimateFee(in.Params, b, in.Witnesses)
		},
		Build: build,
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
		if len(sum.Sources) >= 2 {
			sum.Notes = append(append([]string(nil), sum.Notes...), p.SourceNotes...)
		}
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
	if in.Stage != nil {
		ttl := res.TTL
		if ttl == 0 {
			ttl = in.TTL
		}
		extra, err := in.Stage(ctx, signed.ID, ttl, p.Queue != nil)
		if err != nil {
			return Result{}, err
		}
		if p.Queue != nil && len(extra) > 0 {
			in.Queued.Extra = append(append([]ports.QueuedField(nil), in.Queued.Extra...), extra...)
		}
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
		return Result{}, &chain.IDMismatchError{Answered: id, Local: signed.ID}
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
	built, err := p.BuildCtx(ctx, in)
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
		w, err := in.Prepared.witness(ctx, i, slot, bal.Body, changeKeys(in, bal.Spec))
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
