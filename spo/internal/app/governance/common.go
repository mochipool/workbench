// Package governance holds the use cases of the governance family
// (spec/upstream/scripts/21a to 25b): DRep keys, registration, check and
// retirement; committee keys, hot-key authorisation, check and resignation;
// votes (generate, register, query) and governance actions (generate,
// register). Transactions run the shared pipeline of app/txflow; the rules
// are those of domain/governance.
//
// Every use case is one workflow. Where a key is held and whether the
// signed transaction is submitted or queued are decided by the composition:
// a hardware holder is decided up front by the signing plan against the
// device's profile (ADR 0008) and the shared pipeline brings the body to
// hardware form before it is shown (txflow.Pipeline.Canonicalizer); the
// refusals the specs keep (a hardware payer for a governance action, SPO-25b-PRE-002;
// a hardware key mixed with a key-file key, SPO-Ptx-PRE-006) are explicit.
// Where upstream exits 0 after a failed query or a refusal, the use
// case returns an error. A chain answer that is Unknown is never taken as "not
// there" (ADR 0006).
package governance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/domain/txparam"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals of the governance use cases, beyond those of domain/governance and
// app/txflow.
var (
	ErrMissingFile     = errors.New("a file the workflow needs does not exist")
	ErrExists          = errors.New("artefacts of this name already exist")
	ErrNotConfigured   = errors.New("the use case is not configured for this key source")
	ErrOptionNotUsed   = errors.New("option does not apply to this key source")
	ErrDerivationRange = errors.New("account and index numbers must be 0 to 2147483647")
	ErrNoSigningKey    = errors.New("no signing key (.skey) or hardware signing file (.hwsfile)")
	ErrSourceNotKey    = errors.New("the paying address does not use a payment key (a script or Byron address cannot be signed with a key file)")
	ErrNetworkMismatch = errors.New("the address belongs to a different network")
	ErrProtocolTooOld  = errors.New("the protocol version is older than 9: the Conway governance certificates, votes and actions are not available")
	ErrNoChainReader   = errors.New("this workflow needs a chain reader the composition does not provide")
	ErrUnverified      = errors.New("a chain check could not be made")
	ErrBadWord         = errors.New("the word names neither a stored artefact nor a valid id")
	// ErrOfflineUnsupported: the workflow cannot run offline (23c and 23e
	// upstream; 24a and 24c need the governance state).
	ErrOfflineUnsupported = errors.New("this workflow needs the chain and cannot queue a transaction for an offline machine")
	// ErrAnchorNotChecked: an anchor URL was given, nothing can fetch it, and no hash was given.
	ErrAnchorNotChecked = errors.New("the anchor document cannot be fetched here: give its hash")
	// ErrAnchorFetch: the anchor document could not be fetched or is not JSON.
	ErrAnchorFetch = errors.New("the anchor document could not be fetched")
	// ErrAnchorVerifierMissing: the use case verifies the CIP-100 document of an
	// anchor, no verifier is wired, and the operator did not acknowledge the
	// unverified anchor (ADR 0008: a dependency is optional only by explicit policy).
	ErrAnchorVerifierMissing = errors.New("no anchor document verifier is wired: acknowledge that the anchor is not verified, or wire one")
	// ErrSingleSource: a read of the "harmful if false" class rests on one source.
	ErrSingleSource = errors.New("this read rests on a single chain source: give a second independent source, or acknowledge the single source explicitly")
	// ErrSourcesDisagree: two independent sources gave different answers.
	ErrSourcesDisagree = errors.New("the chain sources disagree")
	// ErrGuardrailsUnsupported is domain/governance's: a proposal that needs the
	// guardrails script. It names what is missing; see RegisterAction.
	ErrGuardrailsUnsupported = governance.ErrGuardrailsUnsupported
	// ErrParameterChangeUnsupported: the action-file adapter does not build a
	// parameter-change file yet. An adapter wraps ports.ErrParameterChangeUnsupported.
	ErrParameterChangeUnsupported = ports.ErrParameterChangeUnsupported

	ErrDeclined      = txflow.ErrDeclined
	ErrNoConfirmer   = txflow.ErrNoConfirmer
	ErrNoSigner      = txflow.ErrNoSigner
	ErrMisconfigured = txflow.ErrMisconfigured
)

// ApprovalPolicy and its values are those of txflow.
type ApprovalPolicy = txflow.ApprovalPolicy

// Approval values.
const (
	ApprovalAsk  = txflow.ApprovalAsk
	ApprovalSkip = txflow.ApprovalSkip
)

// SourcePolicy says what a read of the "harmful if false" class does with one
// source (ADR 0006): the deposit a DRep refund rests on, the committee state a
// resignation rests on.
type SourcePolicy int

const (
	// RequireCorroboration is the zero value: a second, independent source that
	// agrees is required.
	RequireCorroboration SourcePolicy = iota
	// SingleSourceAcknowledged goes on with one source; the result and the
	// operator's summary name it.
	SingleSourceAcknowledged
)

// MinConwayMajor is the protocol major version from which the Conway
// governance certificates exist.
const MinConwayMajor = 9

// ---- names and files ---------------------------------------------------------------

func trimDir(s string) string { return strings.TrimPrefix(s, "./") }

// name checks a name as an artefact owner: no directory part (hazard H7).
func name(s string) (string, error) {
	if s == "" || strings.ContainsAny(s, "/\\") {
		return "", fmt.Errorf("%w: %q", ErrBadWord, s)
	}
	return s, nil
}

// drepName: a trailing `.id` then... upstream drops `.id` (21a) or `.drep` (21b).
func drepName(s string) (string, error) {
	s = strings.TrimSuffix(strings.TrimSuffix(trimDir(s), ".id"), ".drep")
	return name(s)
}

func coldName(s string) (string, error) {
	return name(strings.TrimSuffix(strings.TrimSuffix(trimDir(s), ".hash"), ".cc-cold"))
}

func hotName(s string) (string, error) {
	return name(strings.TrimSuffix(strings.TrimSuffix(trimDir(s), ".hash"), ".cc-hot"))
}

func payerName(s string) (string, error) {
	return name(strings.TrimSuffix(trimDir(s), ".addr"))
}

func firstLine(b []byte) string {
	line, _, _ := strings.Cut(string(b), "\n")
	return strings.TrimSpace(line)
}

func get(r ports.Reader, ref ports.Ref) ([]byte, error) {
	b, err := r.Get(ref)
	if errors.Is(err, ports.ErrNotFound) {
		return nil, fmt.Errorf("%w: %s", ErrMissingFile, ref)
	}
	return b, err
}

func refuseExisting(r ports.Reader, refs ...ports.Ref) error {
	for _, ref := range refs {
		ok, err := r.Exists(ref)
		if err != nil {
			return err
		}
		if ok {
			return fmt.Errorf("%w: %s", ErrExists, ref)
		}
	}
	return nil
}

// holderOf says who holds the signing key of an artefact pair: the hardware
// file wins when both exist (SPO-Pfiles-INV-002).
func holderOf(r ports.Reader, skey, hws ports.Ref) (custody.Holder, error) {
	h, err := r.Exists(hws)
	if err != nil {
		return "", err
	}
	if h {
		return custody.HolderHardware, nil
	}
	s, err := r.Exists(skey)
	if err != nil {
		return "", err
	}
	if s {
		return custody.HolderVault, nil
	}
	return "", fmt.Errorf("%w: %s", ErrNoSigningKey, skey)
}

func vkeyHash(env []byte) (txbuild.KeyHash, error) {
	e, err := pool.ParseEnvelope(env)
	if err != nil {
		return txbuild.KeyHash{}, err
	}
	raw, err := e.Key32()
	if err != nil {
		return txbuild.KeyHash{}, err
	}
	return txbuild.HashKey(raw), nil
}

// ---- the transaction tail ------------------------------------------------------------

// Base is what the transaction use cases share; the embedded Pipeline holds
// the signing and ledger ports and exactly one of Submitter and Queue.
type Base struct {
	Store     ports.Store
	Addresses ports.AddressInspector
	Params    ports.ProtocolParametersReader
	Tip       ports.TipReader
	Utxos     ports.UtxoReader
	Pipeline  txflow.Pipeline

	// NetworkID is the network the addresses must belong to.
	NetworkID uint8
	// DefTTL is the number of slots of validity; zero means the default.
	DefTTL uint64
	// Selection chooses the inputs; empty means SelectAll.
	Selection txbuild.SelectionStrategy
	// Files and Encrypter are needed only by a request with Extras that name
	// metadata files or ask for message encryption.
	Files     ports.MetadataFileReader
	Encrypter ports.MessageEncrypter
}

// Result is what a transaction use case did. Nothing in it is secret.
type Result struct {
	txflow.Result
	// Certificate is set by the DRep and committee certificate use cases.
	Certificate stake.Certificate
	Deposit     chain.Lovelace
	Refund      chain.Lovelace
	// Sources names the chain sources the checks and amounts came from.
	Sources []chain.Source
	// SingleSource is true when a read of the harmful class rested on one
	// source, acknowledged by the policy.
	SingleSource bool
	// Unchecked lists the chain checks that were not made, with the reason.
	Unchecked []string
	// Summary is the summary of the transaction as it was prepared, before
	// execution: the attachments, deposit and refund and the sources. The
	// interactive confirmation shows it; a caller that skipped the confirmation
	// (--yes) prints the same one from here (Fee, TTL, Size and TxID are the
	// result's).
	Summary ports.TxSummary
	// Decisions records the explicit operator decisions that shaped the
	// transaction (an acknowledged unverified anchor, a cleared anchor).
	Decisions []string
}

type payer struct {
	name   string
	addr   chain.Address
	hash   txbuild.KeyHash
	holder custody.Holder
}

func (b Base) readPayer(r ports.Reader, pn string) (payer, error) {
	ab, err := get(r, ports.Ref{Name: pn, Kind: ports.AddrFile})
	if err != nil {
		return payer{}, err
	}
	holder, err := holderOf(r, ports.Ref{Name: pn, Kind: ports.AddrSKey}, ports.Ref{Name: pn, Kind: ports.AddrHwsFile})
	if err != nil {
		return payer{}, err
	}
	p := payer{name: pn, addr: chain.Address(firstLine(ab)), holder: holder}
	info, err := b.Addresses.InspectAddress(p.addr)
	if err != nil {
		return payer{}, fmt.Errorf("paying address: %w", err)
	}
	if !info.Kind.IsPayment() || info.PaymentKeyHash == nil {
		return payer{}, fmt.Errorf("%w: %s", ErrSourceNotKey, pn)
	}
	if info.NetworkID != b.NetworkID {
		return payer{}, fmt.Errorf("%w: the paying address %s", ErrNetworkMismatch, pn)
	}
	p.hash = *info.PaymentKeyHash
	return p, nil
}

func (b Base) params(ctx context.Context) (chain.ProtocolParameters, error) {
	if b.Params == nil {
		return chain.ProtocolParameters{}, fmt.Errorf("protocol parameters: %w", ErrNoChainReader)
	}
	p, err := b.Params.ProtocolParameters(ctx)
	if err != nil {
		return chain.ProtocolParameters{}, fmt.Errorf("protocol parameters: %w", err)
	}
	if p.ProtocolMajor < MinConwayMajor {
		return chain.ProtocolParameters{}, ErrProtocolTooOld
	}
	return p, nil
}

// txRun is what a governance transaction use case hands the shared tail.
type txRun struct {
	payer payer
	// signers are the signatures after the payment key's: the DRep key, the
	// committee cold or hot key, the pool's cold key. The count of slots is
	// the fee's witness count (SPO-Ptx-INV-006).
	signers []txflow.Slot
	certs   []stake.Certificate
	votes   []txbuild.VoteAttachment
	props   []txbuild.ProposalAttachment
	message []string
	// extras and pass are the extra parameters of the request; nil for none.
	extras  *txparam.Extras
	pass    *ports.Secret
	params  chain.ProtocolParameters
	summary ports.TxSummary
	queued  ports.QueuedTx
	// ttl overrides the default validity (25b: tip + 25000), zero keeps it.
	ttl uint64
	// refuseMixed refuses a hardware key together with a key-file key
	// (SPO-Ptx-PRE-006: 23c and 23e).
	refuseMixed bool
	// unrestricted is the operator's consent to the device's unrestricted mode
	// (SPO-21b-PR-001, SPO-24b-PR-001), set by the use case from its request.
	unrestricted bool
}

// ErrUnrestrictedNeeded: the transaction needs the device's unrestricted mode
// and the operator did not allow it (SPO-21b-PR-001, SPO-24b-PR-001: declining
// ends the script with exit 2). It is never implied.
var ErrUnrestrictedNeeded = errors.New("the hardware wallet can sign this transaction only in unrestricted mode, which the operator has not allowed")

func (r txRun) prepareOptions() txflow.PrepareOptions {
	return txflow.PrepareOptions{RefuseMixed: r.refuseMixed, Unrestricted: r.unrestricted}
}

// changeKeys are the hardware keys declared to the device so it recognises the
// change output: the payment key and the payer's staking key when it is stored
// as a hardware file (SPO-21b-INV-006, SPO-23c-INV-006).
func (b Base) changeKeys(ctx context.Context, r txRun) []custody.KeyRef {
	if r.payer.holder != custody.HolderHardware {
		return nil
	}
	keys := []custody.KeyRef{{Role: custody.RolePayment, Holder: custody.HolderHardware, Owner: r.payer.name}}
	stem := strings.TrimSuffix(r.payer.name, ".payment")
	if stem == r.payer.name {
		return keys
	}
	_ = b.Store.View(ctx, func(rd ports.Reader) error {
		if ok, err := rd.Exists(ports.Ref{Name: stem, Kind: ports.StakingHwsFile}); err == nil && ok {
			keys = append(keys, custody.KeyRef{Role: custody.RoleStake, Holder: custody.HolderHardware, Owner: stem})
		}
		return nil
	})
	return keys
}

func (b Base) slots(r txRun) []txflow.Slot {
	pay := txflow.Slot{Label: "payment", Key: custody.KeyRef{Role: custody.RolePayment, Holder: r.payer.holder, Owner: r.payer.name}, Hash: r.payer.hash}
	return append([]txflow.Slot{pay}, r.signers...)
}

// early refuses what the signing plan refuses (a hardware holder) before any
// chain read, with a draft that has the features of the attachments.
func (b Base) early(r txRun) error {
	_, err := b.Pipeline.PrepareWith(txbuild.Draft{Certificates: r.certs, Votes: r.votes, Proposals: r.props, Message: r.message}, b.slots(r), uint(1+len(r.signers)), r.prepareOptions())
	return err
}

// execute is the tail of the governance transaction use cases: clock, inputs,
// the draft, the plan, then the shared pipeline.
//
// spec: SPO-Ptx-MODE-001, SPO-Ptx-MODE-002, SPO-Ptx-MODE-003, SPO-Ptx-MODE-004, SPO-Ptx-PRE-001, SPO-Ptx-INV-001, SPO-Ptx-INV-002,
// spec: SPO-Ptx-INV-006, SPO-Ptx-INV-010
func (b Base) execute(ctx context.Context, r txRun) (txflow.Result, ports.TxSummary, error) {
	if err := b.Pipeline.Check(); err != nil {
		return txflow.Result{}, ports.TxSummary{}, err
	}
	// The extra parameters are resolved before any network access.
	//
	// spec: SPO-Pparam-IF-010, SPO-Pparam-IF-016
	meta, err := txflow.ResolveExtras(txflow.ExtrasPorts{Files: b.Files, Encrypter: b.Encrypter}, r.extras, r.message, r.pass)
	if err != nil {
		return txflow.Result{}, ports.TxSummary{}, err
	}
	tip, err := b.Tip.Tip(ctx)
	if err != nil {
		return txflow.Result{}, ports.TxSummary{}, fmt.Errorf("current slot: %w", err)
	}
	def := b.DefTTL
	if r.ttl != 0 {
		def = r.ttl
	}
	ttl, err := txbuild.TTL(tip, def)
	if err != nil {
		return txflow.Result{}, ports.TxSummary{}, err
	}
	utxos, err := b.Utxos.Utxos(ctx, r.payer.addr)
	if err != nil {
		return txflow.Result{}, ports.TxSummary{}, fmt.Errorf("the UTxOs of %s: %w", r.payer.name, err)
	}
	strategy := b.Selection
	if strategy == "" {
		strategy = txbuild.SelectAll
	}
	inputs, err := strategy.Select(utxos)
	if err != nil {
		return txflow.Result{}, ports.TxSummary{}, fmt.Errorf("%s: %w", r.payer.name, err)
	}
	var draft txbuild.Draft
	switch {
	case len(r.certs) > 0:
		draft, err = txbuild.NewCertificateDraft(r.payer.addr, inputs, r.certs, r.message)
	case len(r.votes) > 0:
		draft, err = txbuild.NewVoteDraft(r.payer.addr, inputs, r.votes, r.message)
	default:
		draft, err = txbuild.NewProposalDraft(r.payer.addr, inputs, r.props, r.message)
	}
	if err != nil {
		return txflow.Result{}, ports.TxSummary{}, err
	}
	if r.extras != nil {
		if draft, err = meta.Attach(draft); err != nil {
			return txflow.Result{}, ports.TxSummary{}, err
		}
	}
	witnesses := uint(1 + len(r.signers))
	prep, err := b.Pipeline.PrepareWith(draft, b.slots(r), witnesses, r.prepareOptions())
	if err != nil {
		return txflow.Result{}, ports.TxSummary{}, err
	}
	sum := r.summary
	sum.SourceAddr, sum.Source = r.payer.addr, r.payer.name
	sum.Attachments = draft.AttachmentLines()
	if sum.Deposit, err = draft.Deposits(); err != nil {
		return txflow.Result{}, ports.TxSummary{}, err
	}
	if sum.Refund, err = draft.Refunds(); err != nil {
		return txflow.Result{}, ports.TxSummary{}, err
	}
	res, err := b.Pipeline.Execute(ctx, txflow.Input{Draft: draft, Params: r.params, TTL: ttl, Prepared: prep, Witnesses: witnesses,
		Summary: sum, Queued: r.queued, HardwareChangeKeys: b.changeKeys(ctx, r)})
	return res, sum, err
}

// ---- the anchor ------------------------------------------------------------------------

// AnchorSource resolves the `url:` and `hash:` words of an anchor: it fetches
// the document, requires JSON, and computes the blake2b-256 hash of the
// downloaded bytes, which always wins over a given hash. With no Fetcher (an
// offline composition) the given hash is used and both words are required
// together (SPO-21b-MODE-001).
type AnchorSource struct {
	Fetcher ports.MetadataFetcher
	// IPFSGateway replaces the default gateway for ipfs:// URLs.
	IPFSGateway string
}

// ResolvedAnchor is the outcome.
type ResolvedAnchor struct {
	Anchor governance.Anchor
	// Doc is the fetched document, nil when not fetched.
	Doc     []byte
	Fetched bool
	// GivenHashDiffered: a hash was given and the computed one replaced it.
	GivenHashDiffered bool
}

// Resolve returns the anchor of the words, the zero anchor when there are none.
//
// spec: SPO-21b-MODE-001, SPO-21b-EXT-002, SPO-21b-PRE-004, SPO-21b-PRE-005, SPO-21b-EXT-003, SPO-21b-INV-001, SPO-21b-PRE-006,
// spec: SPO-23e-MODE-002, SPO-23e-PRE-003, SPO-24a-EXT-001, SPO-24a-INV-002, SPO-24a-PRE-002, SPO-25a-EXT-001, SPO-25a-EXT-002, SPO-25a-INV-001, SPO-25a-INV-002, SPO-25a-PRE-007, SPO-25a-PRE-008
func (s AnchorSource) Resolve(ctx context.Context, url, hash string) (ResolvedAnchor, error) {
	if url == "" && hash == "" {
		return ResolvedAnchor{}, nil
	}
	if url == "" {
		return ResolvedAnchor{}, governance.ErrAnchorPair
	}
	u, err := governance.ParseAnchorURL(url)
	if err != nil {
		return ResolvedAnchor{}, err
	}
	var given [32]byte
	haveGiven := hash != ""
	if haveGiven {
		if given, err = governance.ParseHash32(hash); err != nil {
			return ResolvedAnchor{}, err
		}
	}
	if s.Fetcher == nil {
		if !haveGiven {
			return ResolvedAnchor{}, fmt.Errorf("%w: %s", ErrAnchorNotChecked, u)
		}
		return ResolvedAnchor{Anchor: governance.Anchor{URL: u, Hash: given}}, nil
	}
	doc, err := s.Fetcher.Fetch(ctx, governance.FetchURL(u, s.IPFSGateway))
	if err != nil {
		return ResolvedAnchor{}, fmt.Errorf("%w: %s: %v", ErrAnchorFetch, u, err)
	}
	if !json.Valid(doc) {
		// Upstream goes on with a given hash for a body that is not JSON
		// (SPO-25a-INV-002); a port refuses it.
		return ResolvedAnchor{}, fmt.Errorf("%w: %s: the document is not JSON", ErrAnchorFetch, u)
	}
	h := governance.HashDocument(doc)
	return ResolvedAnchor{Anchor: governance.Anchor{URL: u, Hash: h}, Doc: doc, Fetched: true, GivenHashDiffered: haveGiven && given != h}, nil
}

// verifyAnchor applies the optional-by-policy rule for the use cases that
// upstream gates on the CIP-100 verifier: with a verifier it verifies; without
// one it refuses unless the unverified anchor is acknowledged, and then it
// records the decision.
func verifyAnchor(ctx context.Context, v ports.AnchorVerifier, ack bool, kind ports.AnchorDocKind, doc []byte) (verdict *ports.AnchorVerdict, decision string, err error) {
	if v == nil {
		if !ack {
			return nil, "", ErrAnchorVerifierMissing
		}
		return nil, "the anchor document was not verified (no verifier wired, acknowledged)", nil
	}
	vd, err := v.VerifyAnchor(ctx, kind, doc)
	if err != nil {
		return nil, "", fmt.Errorf("verify the anchor document: %w", err)
	}
	return &vd, "", nil
}

// gateAnchor is the first half of the optional-by-policy rule for the use
// cases that write an anchor: an anchor given (a URL) with no verifier wired
// and no acknowledgement is refused, before anything is read or fetched.
func gateAnchor(v ports.AnchorVerifier, ack bool, url string) error {
	if url != "" && v == nil && !ack {
		return ErrAnchorVerifierMissing
	}
	return nil
}

// anchorDecisions is the second half: with the anchor resolved, a verifier
// checks a fetched document, and without one the acknowledged decision is
// recorded. An absent anchor has nothing to verify.
func anchorDecisions(ctx context.Context, v ports.AnchorVerifier, kind ports.AnchorDocKind, a ResolvedAnchor) ([]string, error) {
	if a.Anchor.IsZero() {
		return nil, nil
	}
	if v == nil {
		return []string{"the anchor document was not verified (no verifier wired, acknowledged)"}, nil
	}
	if a.Fetched {
		if _, _, err := verifyAnchor(ctx, v, false, kind, a.Doc); err != nil {
			return nil, err
		}
	}
	return nil, nil
}
