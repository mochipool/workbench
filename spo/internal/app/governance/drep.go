package governance

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/mochipool/workbench/spo/internal/app/hwkeys"
	"github.com/mochipool/workbench/spo/internal/app/keyring"
	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/domain/txparam"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ErrNoDRepDeposit: the protocol parameters carry no dRepDeposit.
var ErrNoDRepDeposit = errors.New("the protocol parameters carry no dRepDeposit")

// ErrAnchorWouldBeCleared: an update without an anchor of a DRep that has
// one on chain.
var ErrAnchorWouldBeCleared = errors.New("the update has no anchor but the DRep has one on chain: the update would replace it with none; give the anchor, or allow clearing it")

// drepReads reads a DRep's state. A read of the harmful class (the deposit a
// retirement refunds) needs the second source to agree or the single source
// to be acknowledged (ADR 0006).
type drepReads struct {
	Primary    ports.DRepStateReader
	CrossCheck ports.DRepStateReader
	Policy     SourcePolicy
	// OnSingle records an acknowledged single source before the use case goes
	// on (ADR 0006). Nil with Policy SingleSourceAcknowledged refuses.
	OnSingle ports.SingleSourceHook
}

type drepAnswer struct {
	State   chain.Reading[chain.DRepState]
	Sources []chain.Source
	Single  bool
}

func sameDRep(a, b chain.Reading[chain.DRepState]) bool {
	if a.IsNone() || b.IsNone() {
		return a.IsNone() && b.IsNone()
	}
	av, _ := a.Get()
	bv, _ := b.Get()
	// A source that does not state the deposit (DepositUnstated) cannot
	// disagree about it: registration is what it corroborates.
	return av.DepositUnstated || bv.DepositUnstated || av.Deposit == bv.Deposit
}

func describeDRep(r chain.Reading[chain.DRepState]) string {
	switch {
	case r.IsUnknown():
		return "unknown (" + r.Why() + ")"
	case r.IsNone():
		return "not registered"
	}
	st, _ := r.Get()
	if st.DepositUnstated {
		return "registered, deposit not stated"
	}
	return fmt.Sprintf("registered, deposit %d lovelace", st.Deposit)
}

func (d drepReads) read(ctx context.Context, id chain.DRepID, harmful bool) (drepAnswer, error) {
	if d.Primary == nil {
		return drepAnswer{}, fmt.Errorf("the DRep state: %w", ErrNoChainReader)
	}
	r, err := d.Primary.DRepState(ctx, id)
	if err != nil {
		return drepAnswer{}, fmt.Errorf("the DRep state from %s: %w", d.Primary.Source(), err)
	}
	out := drepAnswer{State: r, Sources: []chain.Source{d.Primary.Source()}}
	if r.IsUnknown() {
		return out, fmt.Errorf("%w: the DRep state from %s: %s", governance.ErrDRepUnknown, d.Primary.Source(), r.Why())
	}
	if !harmful {
		return out, nil
	}
	corroborated := false
	if d.CrossCheck != nil {
		r2, err := d.CrossCheck.DRepState(ctx, id)
		if err != nil {
			return drepAnswer{}, fmt.Errorf("the DRep state from %s: %w", d.CrossCheck.Source(), err)
		}
		if !r2.IsUnknown() {
			if !sameDRep(r, r2) {
				return drepAnswer{}, fmt.Errorf("%w about the DRep: %s says %s, %s says %s", ErrSourcesDisagree,
					d.Primary.Source(), describeDRep(r), d.CrossCheck.Source(), describeDRep(r2))
			}
			corroborated = true
			out.Sources = append(out.Sources, d.CrossCheck.Source())
		} else if d.Policy != SingleSourceAcknowledged {
			return drepAnswer{}, fmt.Errorf("%w: %s says %s, but %s did not answer: %s", ErrSingleSource,
				d.Primary.Source(), describeDRep(r), d.CrossCheck.Source(), r2.Why())
		}
	}
	if !corroborated {
		if d.Policy != SingleSourceAcknowledged {
			return drepAnswer{}, fmt.Errorf("%w: %s", ErrSingleSource, d.Primary.Source())
		}
		if err := d.OnSingle.Accept(ctx, "the DRep deposit", d.Primary.Source()); err != nil {
			return drepAnswer{}, err
		}
		out.Single = true
	}
	return out, nil
}

// drepInputs is what the store holds for a DRep.
type drepInputs struct {
	name string
	hash stake.KeyHash
	key  custody.KeyRef
}

func readDRep(r ports.NamedReader, nm string) (drepInputs, error) {
	vk, err := get(r, ports.NamedRef{Name: nm, Kind: ports.DRepVKey})
	if err != nil {
		return drepInputs{}, err
	}
	h, err := vkeyHash(vk)
	if err != nil {
		return drepInputs{}, fmt.Errorf("%s.drep.vkey: %w", nm, err)
	}
	key, err := keyring.Held(r, custody.RoleDRep, nm, ErrNoSigningKey)
	if err != nil {
		return drepInputs{}, err
	}
	return drepInputs{name: nm, hash: stake.KeyHash(h), key: key}, nil
}

func (d drepInputs) slot() txflow.Slot {
	return txflow.Slot{Label: "drep", Key: d.key, Hash: txbuild.KeyHash(d.hash)}
}

func (d drepInputs) chainID() chain.DRepID { return chain.DRepID{Hash: d.hash} }

func queuedDRep(typ, verb string, pay payer, nm string) ports.QueuedTx {
	return ports.QueuedTx{Type: typ, FromName: pay.name, FromAddr: pay.addr, ToName: pay.name, ToAddr: pay.addr,
		Description: fmt.Sprintf("signed drep-id %s transaction for '%s', payment via '%s'", verb, nm, pay.name),
		Extra:       []ports.QueuedField{{Key: "drepName", Value: nm}}}
}

// ---- 21b --------------------------------------------------------------------------------

// RegisterDRep registers a DRep on chain, or updates its anchor when it is
// registered (upstream 21b): a payment key and the DRep key sign (two
// witnesses). A registration pays the protocol's dRepDeposit; an update pays
// none. The kind is decided from the chain's answer; an unknown answer is
// refused, because a duplicate registration or an update of nothing would
// follow (SPO-21b-MODE-003).
//
// The certificate `<drep>.drep-reg.cert` is written after the transaction was
// submitted or queued: a run that is refused or declined leaves no file.
type RegisterDRep struct {
	Base
	Certs ports.CertificateBuilder
	// DReps reads the DRep's state (required).
	DReps ports.DRepStateReader
	// Anchors fetches and hashes the anchor document; a zero value has no
	// fetcher and takes the given hash (offline composition).
	Anchors AnchorSource
	// Verifier checks the CIP-119 document. Optional by policy: with an anchor
	// and no verifier the run is refused unless AnchorUnverifiedAcknowledged,
	// and the decision is recorded in the result.
	Verifier                     ports.AnchorVerifier
	AnchorUnverifiedAcknowledged bool
}

// RegisterDRepRequest names the DRep and the paying address as typed and the
// anchor words.
type RegisterDRepRequest struct {
	DRep, Payer string
	URL, Hash   string
	Message     []string
	// Extras are the parsed extra parameters (txparam.Parse with
	// txparam.ForCertificate); Passphrase is the `pass:` of Extras. Optional.
	Extras     *txparam.Extras
	Passphrase *ports.Secret
	// Unrestricted is the operator's consent to the device's unrestricted mode
	// (`--allow-unrestricted-mode`, SPO-21b-PR-001: asked, default Yes, in the
	// hardware-payer and key-file-DRep form; declining exits 2). Never implied:
	// the CLI sets it only after the operator agreed. Without it that form is
	// refused with ErrUnrestrictedNeeded.
	Unrestricted bool
	// AllowAnchorClear lets an update without an anchor replace the anchor a
	// registered DRep has with none (SPO-21b-INV-003; port note).
	AllowAnchorClear bool
}

// Run registers or updates the DRep.
//
// spec: SPO-21b-IF-001, SPO-21b-IF-003, SPO-21b-IN-001, SPO-21b-IN-002, SPO-21b-IN-003, SPO-21b-PRE-002, SPO-21b-PRE-003,
// spec: SPO-21b-EXT-001, SPO-21b-EXT-004, SPO-21b-EXT-005, SPO-21b-EXT-006, SPO-21b-INV-001, SPO-21b-INV-002, SPO-21b-INV-003,
// spec: SPO-21b-INV-004, SPO-21b-INV-005, SPO-21b-INV-006, SPO-21b-INV-007, SPO-21b-INV-009, SPO-21b-INV-010, SPO-21b-INV-011,
// spec: SPO-21b-INV-012, SPO-21b-INV-013, SPO-21b-INV-014, SPO-21b-INV-015, SPO-21b-INV-016, SPO-21b-INV-017, SPO-21b-INV-018,
// spec: SPO-21b-MODE-001, SPO-21b-MODE-002, SPO-21b-MODE-003, SPO-21b-OUT-001, SPO-21b-OUT-002, SPO-21b-PR-002, SPO-Pfiles-OUT-025
func (uc RegisterDRep) Run(ctx context.Context, req RegisterDRepRequest) (Result, error) {
	if req.DRep == "" || req.Payer == "" {
		return Result{}, errors.New("a DRep registration needs a DRep and a paying address")
	}
	if err := txbuild.ValidateMessage(req.Message); err != nil {
		return Result{}, err
	}
	if err := gateAnchor(uc.Verifier, uc.AnchorUnverifiedAcknowledged, req.URL); err != nil {
		return Result{}, err
	}
	dn, err := drepName(req.DRep)
	if err != nil {
		return Result{}, fmt.Errorf("DRep: %w", err)
	}
	pn, err := payerName(req.Payer)
	if err != nil {
		return Result{}, fmt.Errorf("payer: %w", err)
	}
	var dr drepInputs
	var pay payer
	if err := uc.Store.View(ctx, func(r ports.NamedReader) error {
		var err error
		if dr, err = readDRep(r, dn); err != nil {
			return err
		}
		pay, err = uc.readPayer(r, pn)
		return err
	}); err != nil {
		return Result{}, err
	}
	// The early probe asks the plan for the features of a registration; whether
	// this run registers or updates is decided from the chain's answer, and the
	// plan is made again for the real certificate before any device prompt.
	probe := stake.Certificate{Spec: stake.Spec{Kind: stake.CertDRepRegistration, Stake: dr.hash, Deposit: 1}}
	run := txRun{payer: pay, signers: []txflow.Slot{dr.slot()}, certs: []stake.Certificate{probe}, message: req.Message, extras: req.Extras, pass: req.Passphrase, unrestricted: req.Unrestricted}
	if err := drepUnrestricted(uc.Pipeline.Signers, &run, pay, dr); err != nil {
		return Result{}, err
	}
	if err := uc.early(run); err != nil {
		return Result{}, err
	}
	params, err := uc.params(ctx)
	if err != nil {
		return Result{}, err
	}
	if params.DRepDeposit == 0 {
		return Result{}, ErrNoDRepDeposit
	}
	anchor, err := uc.Anchors.Resolve(ctx, req.URL, req.Hash)
	if err != nil {
		return Result{}, err
	}
	decisions, err := anchorDecisions(ctx, uc.Verifier, ports.AnchorCIP119, anchor)
	if err != nil {
		return Result{}, err
	}
	ans, err := drepReads{Primary: uc.DReps}.read(ctx, dr.chainID(), false)
	if err != nil {
		return Result{}, err
	}
	kind, err := governance.DecideDRepKind(ans.State)
	if err != nil {
		return Result{}, err
	}
	spec := stake.Spec{Stake: dr.hash, Anchor: anchor.Anchor}
	if kind == governance.DRepRegistration {
		spec.Kind, spec.Deposit = stake.CertDRepRegistration, params.DRepDeposit
	} else {
		spec.Kind = stake.CertDRepUpdate
		if st, ok := ans.State.Get(); ok && anchor.Anchor.IsZero() && st.AnchorURL != "" {
			if !req.AllowAnchorClear {
				return Result{}, fmt.Errorf("%w: %s", ErrAnchorWouldBeCleared, st.AnchorURL)
			}
			decisions = append(decisions, "the update clears the anchor "+st.AnchorURL+" (allowed)")
		}
	}
	if anchor.GivenHashDiffered {
		decisions = append(decisions, "the given anchor hash differed from the document's and was replaced")
	}
	cert, err := uc.Certs.BuildCertificate(spec)
	if err != nil {
		return Result{}, err
	}
	kindName, typ := "DRep registration", "DRepIDRegistration"
	if kind == governance.DRepUpdate {
		kindName = "DRep update"
	}
	run.certs, run.params = []stake.Certificate{cert}, params
	run.summary = ports.TxSummary{Kind: kindName, Account: dn, Sources: ans.Sources}
	run.queued = queuedDRep(typ, "registration", pay, dn)
	res, sum, err := uc.execute(ctx, run)
	if err != nil {
		return Result{}, err
	}
	if err := uc.Store.Update(ctx, func(w ports.NamedWriter) error {
		return w.Put(ports.NamedRef{Name: dn, Kind: ports.DRepRegCert}, cert.Envelope)
	}); err != nil {
		return Result{}, fmt.Errorf("the transaction was sent, but the certificate file could not be stored: %w", err)
	}
	return Result{Result: res, Summary: sum, Certificate: cert, Deposit: spec.Deposit, Sources: ans.Sources, Decisions: decisions}, nil
}

// ---- 21d --------------------------------------------------------------------------------

// RetireDRep retires a registered DRep and reclaims its deposit (upstream
// 21d). The refund is the deposit in the on-chain DRep state, not the one of
// the protocol parameters, and it is a read of the "harmful if false" class:
// a second independent source must agree, or the single source must be
// acknowledged (ADR 0006). "Not registered" is an error, not exit 0.
type RetireDRep struct {
	Base
	Certs ports.CertificateBuilder
	// DReps is the DRep state source; CrossCheck an optional second one.
	DReps      ports.DRepStateReader
	CrossCheck ports.DRepStateReader
	Sources    SourcePolicy
	// OnSingle records an acknowledged single source before anything is
	// signed or queued; required when Sources is SingleSourceAcknowledged.
	OnSingle ports.SingleSourceHook
}

// RetireDRepRequest names the DRep and the paying address as typed.
type RetireDRepRequest struct {
	DRep, Payer string
	Message     []string
	// Extras are the parsed extra parameters (txparam.Parse with
	// txparam.ForCertificate); Passphrase is the `pass:` of Extras. Optional.
	Extras     *txparam.Extras
	Passphrase *ports.Secret
	// Unrestricted is the operator's consent to the device's unrestricted mode
	// (`--allow-unrestricted-mode`, SPO-21b-PR-001: asked, default Yes, in the
	// hardware-payer and key-file-DRep form; declining exits 2). Never implied:
	// the CLI sets it only after the operator agreed. Without it that form is
	// refused with ErrUnrestrictedNeeded.
	Unrestricted bool
}

// Run retires the DRep.
//
// spec: SPO-21d-IF-001, SPO-21d-IN-001, SPO-21d-IN-002, SPO-21d-PRE-002, SPO-21d-PRE-004, SPO-21d-EXT-001, SPO-21d-EXT-002,
// spec: SPO-21d-INV-001, SPO-21d-INV-002, SPO-21d-INV-003, SPO-21d-INV-004, SPO-21d-INV-005, SPO-21d-INV-006, SPO-21d-INV-007,
// spec: SPO-21d-INV-008, SPO-21d-INV-009, SPO-21d-INV-010, SPO-21d-INV-011, SPO-21d-INV-012, SPO-21d-INV-013, SPO-21d-INV-014,
// spec: SPO-21d-INV-015, SPO-21d-INV-016, SPO-21d-MODE-001, SPO-21d-OUT-001, SPO-21d-OUT-002, SPO-21d-SEC-001, SPO-Pfiles-OUT-025
func (uc RetireDRep) Run(ctx context.Context, req RetireDRepRequest) (Result, error) {
	if req.DRep == "" || req.Payer == "" {
		return Result{}, errors.New("a DRep retirement needs a DRep and a paying address")
	}
	if err := txbuild.ValidateMessage(req.Message); err != nil {
		return Result{}, err
	}
	dn, err := drepName(req.DRep)
	if err != nil {
		return Result{}, fmt.Errorf("DRep: %w", err)
	}
	pn, err := payerName(req.Payer)
	if err != nil {
		return Result{}, fmt.Errorf("payer: %w", err)
	}
	var dr drepInputs
	var pay payer
	if err := uc.Store.View(ctx, func(r ports.NamedReader) error {
		var err error
		if dr, err = readDRep(r, dn); err != nil {
			return err
		}
		pay, err = uc.readPayer(r, pn)
		return err
	}); err != nil {
		return Result{}, err
	}
	probe := stake.Certificate{Spec: stake.Spec{Kind: stake.CertDRepRetirement, Stake: dr.hash, Deposit: 1}}
	run := txRun{payer: pay, signers: []txflow.Slot{dr.slot()}, certs: []stake.Certificate{probe}, message: req.Message, extras: req.Extras, pass: req.Passphrase, unrestricted: req.Unrestricted}
	if err := drepUnrestricted(uc.Pipeline.Signers, &run, pay, dr); err != nil {
		return Result{}, err
	}
	if err := uc.early(run); err != nil {
		return Result{}, err
	}
	params, err := uc.params(ctx)
	if err != nil {
		return Result{}, err
	}
	ans, err := drepReads{Primary: uc.DReps, CrossCheck: uc.CrossCheck, Policy: uc.Sources, OnSingle: uc.OnSingle}.read(ctx, dr.chainID(), true)
	if err != nil {
		return Result{}, err
	}
	refund, err := governance.RefundOf(ans.State)
	if err != nil {
		return Result{}, err
	}
	cert, err := uc.Certs.BuildCertificate(stake.Spec{Kind: stake.CertDRepRetirement, Stake: dr.hash, Deposit: refund})
	if err != nil {
		return Result{}, err
	}
	run.certs, run.params = []stake.Certificate{cert}, params
	run.summary = ports.TxSummary{Kind: "DRep retirement", Account: dn, Sources: ans.Sources, SingleSource: ans.Single}
	run.queued = queuedDRep("DRepIDRetirement", "retirement", pay, dn)
	res, sum, err := uc.execute(ctx, run)
	if err != nil {
		return Result{}, err
	}
	if err := uc.Store.Update(ctx, func(w ports.NamedWriter) error {
		return w.Put(ports.NamedRef{Name: dn, Kind: ports.DRepRetCert}, cert.Envelope)
	}); err != nil {
		return Result{}, fmt.Errorf("the transaction was sent, but the certificate file could not be stored: %w", err)
	}
	return Result{Result: res, Summary: sum, Certificate: cert, Refund: refund, Sources: ans.Sources, SingleSource: ans.Single}, nil
}

// ---- 21c --------------------------------------------------------------------------------

// CheckDRep reports what the chain says about a DRep (upstream 21c): whether
// it is registered, its deposit, anchor, expiry and delegated stake, and, when
// it has an anchor and a fetcher is wired, whether the document at the URL
// hashes to the registered hash and verifies as CIP-100/119.
//
// The answer is a result, not an exit code: registered, registered but expired
// and not registered are three distinct standings (SPO-21c-PRE-004 port note).
// A failed or unknown state is an error.
type CheckDRep struct {
	Store ports.NamedStore
	DReps ports.DRepStateReader
	// Epoch gives the current epoch for the expiry test. Optional: without an
	// epoch source (or when it fails) registration, deposit and anchor are
	// still reported, and the expiry is Unknown with the reason
	// (DRepReport.EpochWhy).
	Epoch ports.EpochReader
	// Anchors fetches the registered anchor document; a zero value (no fetcher)
	// skips the check (offline, SPO-21c-MODE-001).
	Anchors AnchorSource
	// Verifier checks the CIP-100/119 structure and author signatures. It is
	// optional by policy: when the DRep has an anchor, a fetcher is wired and
	// no verifier is, the check is refused unless AnchorUnverifiedAcknowledged.
	Verifier                     ports.AnchorVerifier
	AnchorUnverifiedAcknowledged bool
}

// DRepReport is the result of CheckDRep.
type DRepReport struct {
	Credential governance.Credential
	IDs        governance.DRepIDs
	Standing   governance.DRepStanding
	// Epoch is the current epoch when EpochKnown. Otherwise the expiry is
	// not assessed and EpochWhy says why.
	Epoch      uint64
	EpochKnown bool
	EpochWhy   string
	State      chain.DRepState
	// Source names where the state came from.
	Source chain.Source
	// Anchor is the registered anchor, zero when none. AnchorCheck says what was
	// done with it.
	Anchor      governance.Anchor
	AnchorCheck AnchorCheck
}

// AnchorCheck is the outcome of the display-only anchor check.
type AnchorCheck struct {
	Checked   bool
	Reason    string // why it was not checked, or what failed
	HashMatch bool
	Verdict   *ports.AnchorVerdict
	// Unverified records the decision to go on without a verifier.
	Unverified string
}

// Run resolves the word to a DRep credential and reads its state.
//
// spec: SPO-21c-IF-001, SPO-21c-IF-002, SPO-21c-IN-001, SPO-21c-IN-002, SPO-21c-INV-001, SPO-21c-INV-002, SPO-21c-EXT-001, SPO-21c-EXT-002,
// spec: SPO-21c-PRE-004, SPO-21c-INV-003, SPO-21c-OUT-001, SPO-21c-EXT-003, SPO-21c-EXT-004, SPO-21c-OUT-002, SPO-21c-MODE-001, SPO-21c-SEC-001
func (uc CheckDRep) Run(ctx context.Context, word string) (DRepReport, error) {
	if word == "" {
		return DRepReport{}, errors.New("a DRep check needs a DRep name or id")
	}
	cred, err := uc.resolve(ctx, word)
	if err != nil {
		return DRepReport{}, err
	}
	ids, err := governance.DRepIDsOf(cred)
	if err != nil {
		return DRepReport{}, err
	}
	var epoch uint64
	var epochWhy string
	switch {
	case uc.Epoch == nil:
		epochWhy = "no epoch source in this mode"
	default:
		var err error
		if epoch, err = uc.Epoch.Epoch(ctx); err != nil {
			if ctx.Err() != nil {
				return DRepReport{}, fmt.Errorf("the current epoch: %w", err)
			}
			epochWhy = "the current epoch could not be read: " + err.Error()
		}
	}
	ans, err := drepReads{Primary: uc.DReps}.read(ctx, chain.DRepID{Script: cred.Script, Hash: cred.Hash}, false)
	if err != nil {
		return DRepReport{}, err
	}
	var standing governance.DRepStanding
	if epochWhy == "" {
		standing, _, err = governance.StandingOf(ans.State, epoch)
	} else {
		standing, err = governance.StandingWithoutEpoch(ans.State)
	}
	if err != nil {
		return DRepReport{}, err
	}
	rep := DRepReport{Credential: cred, IDs: ids, Standing: standing, Epoch: epoch, EpochKnown: epochWhy == "", EpochWhy: epochWhy, Source: uc.DReps.Source()}
	st, ok := ans.State.Get()
	if !ok {
		return rep, nil
	}
	rep.State = st
	if st.AnchorURL != "" {
		a, err := governance.ParseAnchorWords(st.AnchorURL, st.AnchorHash)
		if err != nil {
			// The chain's anchor is shown as it is; it is not ours to validate.
			rep.Anchor = governance.Anchor{URL: st.AnchorURL}
		} else {
			rep.Anchor = a
		}
		rep.AnchorCheck, err = uc.checkAnchor(ctx, st)
		if err != nil {
			return DRepReport{}, err
		}
	}
	return rep, nil
}

func (uc CheckDRep) checkAnchor(ctx context.Context, st chain.DRepState) (AnchorCheck, error) {
	if uc.Anchors.Fetcher == nil {
		return AnchorCheck{Reason: "not checked: no fetcher in this mode"}, nil
	}
	if uc.Verifier == nil && !uc.AnchorUnverifiedAcknowledged {
		return AnchorCheck{}, ErrAnchorVerifierMissing
	}
	doc, err := uc.Anchors.Fetcher.Fetch(ctx, governance.FetchURL(st.AnchorURL, uc.Anchors.IPFSGateway))
	if err != nil {
		return AnchorCheck{Checked: true, Reason: "the document could not be fetched: " + err.Error()}, nil
	}
	h := governance.HashDocument(doc)
	out := AnchorCheck{Checked: true, HashMatch: strings.EqualFold(fmt.Sprintf("%x", h), st.AnchorHash)}
	if !out.HashMatch {
		out.Reason = "the document does not hash to the registered anchor hash"
		return out, nil
	}
	// The author signatures are checked only when the content hash matches.
	vd, dec, err := verifyAnchor(ctx, uc.Verifier, uc.AnchorUnverifiedAcknowledged, ports.AnchorCIP119, doc)
	if err != nil {
		return AnchorCheck{}, err
	}
	out.Verdict, out.Unverified = vd, dec
	return out, nil
}

// resolve follows SPO-21c-IN-001: a `<name>.drep.id` file, 56 hex digits, a
// `drep1...` id of 56 or 58 characters, a `drep_script1...` id, a
// `<name>.drep.vkey`. A CIP-129 id keeps its credential type (upstream
// drops it, SPO-21c-IN-002), so a script DRep can be checked.
func (uc CheckDRep) resolve(ctx context.Context, word string) (governance.Credential, error) {
	nm := strings.TrimSuffix(strings.TrimSuffix(trimDir(word), ".id"), ".drep")
	var file governance.Credential
	found := false
	if uc.Store != nil && nm != "" && !strings.ContainsAny(nm, "/\\") {
		err := uc.Store.View(ctx, func(r ports.NamedReader) error {
			if b, err := r.Get(ports.NamedRef{Name: nm, Kind: ports.DRepID}); err == nil {
				w, perr := stake.ParseDRepWord(firstLine(b))
				if perr != nil || !w.IsID {
					return fmt.Errorf("%s.drep.id does not hold a DRep id: %w", nm, perr)
				}
				file, found = governance.Credential{Script: w.DRep.Kind == stake.DRepScript, Hash: w.DRep.Hash}, true
				return nil
			} else if !errors.Is(err, ports.ErrNotFound) {
				return err
			}
			return nil
		})
		if err != nil {
			return governance.Credential{}, err
		}
		if found {
			return file, nil
		}
	}
	w, err := stake.ParseDRepWord(word)
	if err != nil {
		return governance.Credential{}, err
	}
	if w.IsID {
		return governance.Credential{Script: w.DRep.Kind == stake.DRepScript, Hash: w.DRep.Hash}, nil
	}
	if uc.Store != nil && w.Name != "" {
		var out governance.Credential
		err := uc.Store.View(ctx, func(r ports.NamedReader) error {
			vk, err := get(r, ports.NamedRef{Name: w.Name, Kind: ports.DRepVKey})
			if err != nil {
				return fmt.Errorf("%w: %q is not a DRep id or a stored DRep: %v", ErrBadWord, word, err)
			}
			h, err := vkeyHash(vk)
			out = governance.Credential{Hash: h}
			return err
		})
		return out, err
	}
	return governance.Credential{}, fmt.Errorf("%w: %q", ErrBadWord, word)
}

// drepUnrestricted applies SPO-21b-PR-001 and SPO-21b-SEC-003: a hardware payer
// with a key-file DRep key signs a transaction whose certificate the device does
// not own, which only unrestricted mode allows. The mode is the operator's
// explicit consent (the request field), never implied; without it this form is
// refused before any device prompt. In the other forms (both on the device, both
// key files, key-file payer with a hardware DRep) the mode is not used.
//
// spec: SPO-21b-PR-001, SPO-21b-SEC-003, SPO-21b-INV-006, SPO-21d-INV-004
func drepUnrestricted(dir ports.SignerDirectory, run *txRun, pay payer, dr drepInputs) error {
	needs := hwkeys.OnDevice(dir, pay.key) && !hwkeys.OnDevice(dir, dr.key)
	if needs && !run.unrestricted {
		return ErrUnrestrictedNeeded
	}
	run.unrestricted = needs
	return nil
}
