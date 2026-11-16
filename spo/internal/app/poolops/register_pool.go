package poolops

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/domain/txparam"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals of RegisterPool.
var (
	// ErrCollectionOpen: a type or a message was given while a witness
	// collection is open; they are fixed by the stored body (SPO-05c-PRE-003).
	ErrCollectionOpen = errors.New("a witness collection is open: the type and the message are fixed by its stored transaction; discard the collection to change them")
	// ErrCollectionExpired: the stored collection's TTL is below the tip
	// (SPO-05c-INV-008).
	ErrCollectionExpired = errors.New("the witness collection has expired: discard it and register again")
	// ErrPayerDiffers: the paying address differs from the collection's.
	ErrPayerDiffers = errors.New("the paying address differs from the one the witness collection was made for")
	// ErrDelegationOtherPool: an owner's delegation certificate targets
	// another pool (SPO-05c-PRE-006).
	ErrDelegationOtherPool = errors.New("an owner's delegation certificate does not delegate to this pool")
	// ErrNoPoolDeposit: the protocol parameters carry no stakePoolDeposit.
	ErrNoPoolDeposit = errors.New("the protocol parameters carry no stakePoolDeposit")
	// ErrTickerProtected: the ticker-protection service refused the ticker
	// (SPO-05c-EXT-001).
	ErrTickerProtected = errors.New("the ticker is protected by the ticker-protection service")
	// ErrMetadataMismatch: the published metadata does not hash to poolMetaHash
	// (SPO-05c-EXT-002).
	ErrMetadataMismatch = errors.New("the published pool metadata does not match poolMetaHash")
	// ErrCertificateMismatch: the certificate file does not match the
	// descriptor or the keys.
	ErrCertificateMismatch = errors.New("the registration certificate does not match the pool's keys")
	// ErrSourcesDisagree: two independent sources gave different answers.
	ErrSourcesDisagree = errors.New("the chain sources disagree about the pool")
	// ErrSingleSource: the registration state rests on one source and the
	// policy does not acknowledge that (ADR 0006).
	ErrSingleSource = errors.New("the pool registration state rests on a single chain source: give a second independent source, or acknowledge the single source explicitly")
	// ErrUnverified: a chain check could not be made.
	ErrUnverified = errors.New("a chain check could not be made")
)

// RegisterPool registers or updates a pool (upstream 05c_regStakepoolCert):
// one transaction with the registration certificate and the owners'
// delegation certificates, signed by the pool cold key, the payer and every
// owner. The body is built once and stored with one witness slot per signer
// in a pool.Collection; every slot whose signer is local is filled through
// the same verification a remote response takes (Collection.Fill); when the
// collection is complete the transaction is assembled and submitted or
// queued. One workflow: which signer holds a key is the signer's business.
// A holder that no signer in the directory serves refuses up front, unless
// AllowPending is set, which leaves such a slot empty in an OpenIncomplete
// collection (the seam of multi-party signing, SPO-Xparty-INV-013).
type RegisterPool struct {
	Store      ports.Store
	Addresses  ports.AddressInspector
	Params     ports.ProtocolParametersReader
	Tip        ports.TipReader
	Utxos      ports.UtxoReader
	Pipeline   txflow.Pipeline
	PoolCerts  ports.PoolCertificateDecoder
	StakeCerts ports.CertificateDecoder
	TxIDs      ports.TxIDCalculator
	Hasher     ports.PoolMetadataHasher
	Clock      ports.Clock

	// Pools answers "is the pool registered" for the registration type
	// (SPO-05c-MODE-001, MODE-002); CrossCheck is a second independent
	// source. With Pools nil (offline) the descriptor decides
	// (SPO-05c-MODE-003). The read is of the harmful class (ADR 0006).
	Pools      ports.PoolStateReader
	CrossCheck ports.PoolStateReader
	Sources    SourcePolicy
	// OnSingle records an acknowledged single source before the registration
	// is signed, queued or submitted; required when Sources is
	// SingleSourceAcknowledged.
	OnSingle ports.SingleSourceHook
	// Metadata downloads poolMetaUrl for the hash check; nil skips the check
	// (offline: it runs at execute, SPO-05c-MODE-004).
	Metadata ports.MetadataFetcher
	// Files and Encrypter are needed only by a request with Extras that name
	// metadata files or ask for message encryption.
	Files     ports.MetadataFileReader
	Encrypter ports.MessageEncrypter
	// Tickers is the opt-in ticker-protection lookup. It is sent the ticker
	// and nothing else: the registration protection key never leaves the
	// machine (hazard H6, SPO-05c-SEC-002). Nil means no lookup.
	Tickers ports.TickerProtectionChecker
	// Attach stores the metadata files in the offline transfer file after a
	// transaction was queued (SPO-05c-PR-005, PR-006); nil does not.
	Attach ports.TransferAttacher

	NetworkID uint8
	DefTTL    uint64
	Selection txbuild.SelectionStrategy
	// AllowUnverified goes on from the descriptor when the chain could not
	// say whether the pool is registered; the result lists it.
	AllowUnverified bool
	// AllowPending lets a slot with a holder that has no signer here stay
	// empty: the collection is OpenIncomplete and a transfer file is
	// written for it.
	AllowPending bool
	// DiscardOnDecline removes the collection when the final confirmation is
	// declined (SPO-05c-PR-004 answered Yes).
	DiscardOnDecline bool
}

// RegisterRequest names the pool and the paying address as typed. Type is
// the optional `type:` override.
type RegisterRequest struct {
	Pool    string
	Payer   string
	Type    pool.RegistrationType
	Message []string
	// Extras are the parsed extra parameters (txparam.Parse with
	// txparam.ForCertificate); Passphrase is the `pass:` of Extras. Optional.
	Extras     *txparam.Extras
	Passphrase *ports.Secret
}

// RegisterResult is what happened. Nothing in it is secret.
type RegisterResult struct {
	txflow.Result
	Type         pool.RegistrationType
	State        pool.CollectionState
	CollectionID uint64
	// Missing lists the empty slots; TransferFiles the witness transfer
	// files written for them (artefact names, without `.witness`).
	Missing       []string
	TransferFiles []string
	Deposit       chain.Lovelace
	Sources       []chain.Source
	SingleSource  bool
	Unchecked     []string
	// Decisions records where the port departs from upstream.
	Decisions []string
}

type ownerInfo struct {
	desc   pool.DescriptorOwner
	hash   txbuild.KeyHash
	holder custody.Holder
	deleg  stake.Certificate
	hwDesc bool
}

type regInputs struct {
	d       *pool.Descriptor
	name    string
	poolID  chain.PoolID
	cert    pool.Certificate
	cold    custody.Holder
	coldHW  bool
	owners  []ownerInfo
	payer   payer
	coll    *pool.Collection
	vkeys   map[string]ports.Ref // slot name to its verification key artefact
	hasMeta bool
	hasExt  bool
}

// Run registers or continues the registration.
//
// spec: SPO-05c-IF-001, SPO-05c-IF-002, SPO-05c-IF-004, SPO-05c-IN-001, SPO-05c-IN-002, SPO-05c-IN-003,
// spec: SPO-05c-PRE-001, SPO-05c-PRE-002, SPO-05c-PRE-003, SPO-05c-PRE-004, SPO-05c-PRE-005, SPO-05c-PRE-006,
// spec: SPO-05c-INV-001, SPO-05c-INV-002, SPO-05c-INV-003, SPO-05c-INV-004, SPO-05c-INV-005, SPO-05c-INV-006,
// spec: SPO-05c-INV-007, SPO-05c-INV-008, SPO-05c-INV-009
func (uc RegisterPool) Run(ctx context.Context, req RegisterRequest) (RegisterResult, error) {
	if err := uc.Pipeline.Check(); err != nil {
		return RegisterResult{}, err
	}
	if req.Pool == "" || req.Payer == "" {
		return RegisterResult{}, errors.New("a registration needs a pool and a paying address")
	}
	if err := txbuild.ValidateMessage(req.Message); err != nil {
		return RegisterResult{}, err
	}
	// spec: SPO-Pparam-IF-010, SPO-Pparam-IF-016
	meta, err := txflow.ResolveExtras(txflow.ExtrasPorts{Files: uc.Files, Encrypter: uc.Encrypter}, req.Extras, req.Message, req.Passphrase)
	if err != nil {
		return RegisterResult{}, err
	}
	name, err := poolName(req.Pool)
	if err != nil {
		return RegisterResult{}, err
	}
	pn, err := payerName(req.Payer)
	if err != nil {
		return RegisterResult{}, fmt.Errorf("payer: %w", err)
	}
	var in regInputs
	if err := uc.Store.View(ctx, func(r ports.Reader) error {
		var err error
		in, err = uc.read(r, name, pn)
		return err
	}); err != nil {
		return RegisterResult{}, err
	}

	res := RegisterResult{}
	// The signing plan refuses a holder that no signer serves before any
	// chain read, with a draft that has the features of the certificates
	// (ADR 0008); a stored collection is already planned.
	if in.coll == nil {
		if err := uc.early(in, req.Message); err != nil {
			return RegisterResult{}, err
		}
	}
	// The checks against third parties run on every invocation, resumed or
	// not, before the pipeline (SPO-05c-EXT-001, SPO-05c-EXT-002).
	if err := uc.thirdParty(ctx, in, &res); err != nil {
		return RegisterResult{}, err
	}
	params, err := uc.params(ctx)
	if err != nil {
		return RegisterResult{}, err
	}
	tip, err := uc.Tip.Tip(ctx)
	if err != nil {
		return RegisterResult{}, fmt.Errorf("current slot: %w", err)
	}

	if in.coll != nil {
		if req.Type != "" || len(req.Message) > 0 || req.Extras != nil {
			return RegisterResult{}, ErrCollectionOpen
		}
		coll := *in.coll
		if coll.State(tip.Slot) == pool.CollectionExpired {
			return RegisterResult{}, fmt.Errorf("%w: ttl %d, tip %d", ErrCollectionExpired, coll.TTL, tip.Slot)
		}
		if coll.PayName != pn {
			return RegisterResult{}, fmt.Errorf("%w: %s, not %s", ErrPayerDiffers, coll.PayName, pn)
		}
		if err := uc.bind(&coll, in); err != nil {
			return RegisterResult{}, err
		}
		inp := txflow.Input{Params: params, Queued: uc.queued(in, coll.Type), Witnesses: uint(len(coll.Slots))}
		res.Type = coll.Type
		// The report runs on every invocation: a witness transfer file for
		// every empty slot that has none (SPO-05c-OUT-003).
		if len(coll.Missing()) > 0 {
			if res.TransferFiles, err = uc.store(ctx, in, coll, uc.Clock.Now()); err != nil {
				return RegisterResult{}, err
			}
		}
		return uc.finish(ctx, in, inp, coll, nil, res, tip)
	}
	{
		typ, err := uc.decideType(ctx, in, req.Type, &res)
		if err != nil {
			return RegisterResult{}, err
		}
		res.Type = typ
		deposit := chain.Lovelace(0)
		if typ == pool.PoolRegistration {
			if deposit = params.StakePoolDeposit; deposit == 0 {
				return RegisterResult{}, ErrNoPoolDeposit
			}
		}
		res.Deposit = deposit
		certs := []stake.Certificate{in.cert.Attachment(deposit)}
		if !in.hardware() { // SPO-05c-INV-006
			for _, o := range in.owners {
				certs = append(certs, o.deleg)
			}
		}
		ttl, err := txbuild.TTL(tip, uc.DefTTL)
		if err != nil {
			return RegisterResult{}, err
		}
		utxos, err := uc.Utxos.Utxos(ctx, in.payer.addr)
		if err != nil {
			return RegisterResult{}, fmt.Errorf("the UTxOs of %s: %w", in.payer.name, err)
		}
		strategy := uc.Selection
		if strategy == "" {
			strategy = txbuild.SelectAll
		}
		inputs, err := strategy.Select(utxos)
		if err != nil {
			return RegisterResult{}, fmt.Errorf("%s: %w", in.payer.name, err)
		}
		draft, err := txbuild.NewCertificateDraft(in.payer.addr, inputs, certs, req.Message)
		if err != nil {
			return RegisterResult{}, err
		}
		if req.Extras != nil {
			if draft, err = meta.Attach(draft); err != nil {
				return RegisterResult{}, err
			}
		}
		slots, err := uc.slots(draft, in)
		if err != nil {
			return RegisterResult{}, err
		}
		var pending func(txflow.Slot) bool
		if uc.AllowPending {
			pending = func(s txflow.Slot) bool { return s.Key.Holder != custody.HolderVault }
		}
		// SPO-05c-INV-007: the fee is estimated for 2 + owners witnesses.
		witnesses := uint(2 + len(in.owners))
		prep, err := uc.Pipeline.PreparePartial(draft, slots, witnesses, pending)
		if err != nil {
			return RegisterResult{}, err
		}
		inp := txflow.Input{Draft: draft, Params: params, TTL: ttl, Prepared: prep, Witnesses: witnesses, Queued: uc.queued(in, typ),
			Summary: uc.summary(in, typ, "body", nil)}
		inp.Summary.Sources, inp.Summary.SingleSource, inp.Summary.Unchecked = res.Sources, res.SingleSource, res.Unchecked
		inp.Summary.Source, inp.Summary.SourceAddr = in.payer.name, in.payer.addr
		inp.Summary.Attachments = draft.AttachmentLines()
		inp.Summary.Deposit, err = draft.Deposits()
		if err != nil {
			return RegisterResult{}, err
		}
		b, err := uc.Pipeline.BuildCtx(ctx, inp)
		if err != nil {
			return RegisterResult{}, err
		}
		bs := b.Balanced.Spec
		// The first confirmation: nothing is stored when it is declined
		// (SPO-05c-PR-001).
		skipped, err := uc.Pipeline.Confirm(ctx, inp, b)
		if err != nil {
			return RegisterResult{}, err
		}
		res.ApprovalSkipped = skipped

		return uc.open(ctx, in, inp, b, prep, typ, tip, ttl, &bs, res)
	}
}

// early plans the signatures against a draft that has the certificates but
// no inputs yet, so a hardware or remote holder with no signer refuses
// before anything is read.
func (uc RegisterPool) early(in regInputs, message []string) error {
	certs := []stake.Certificate{in.cert.Attachment(1)}
	if !in.hardware() {
		for _, o := range in.owners {
			certs = append(certs, o.deleg)
		}
	}
	draft := txbuild.Draft{Certificates: certs, Message: message}
	slots, err := uc.slots(draft, in)
	if err != nil {
		return err
	}
	var pending func(txflow.Slot) bool
	if uc.AllowPending {
		pending = func(s txflow.Slot) bool { return s.Key.Holder != custody.HolderVault }
	}
	_, err = uc.Pipeline.PreparePartial(draft, slots, uint(len(slots)), pending)
	return err
}

// open creates the collection, fills the local slots, stores it and goes on
// to assembly when it is complete.
//
// spec: SPO-05c-OUT-001, SPO-05c-OUT-002, SPO-05c-OUT-003, SPO-05c-PRE-010, SPO-05c-INV-001
func (uc RegisterPool) open(ctx context.Context, in regInputs, inp txflow.Input, b txflow.Built, prep txflow.Prepared, typ pool.RegistrationType,
	tip chain.Tip, ttl uint64, spec *txbuild.BodySpec, res RegisterResult) (RegisterResult, error) {
	now := uc.Clock.Now()
	coll, err := pool.OpenCollection(pool.Collection{
		ID: uint64(now.Unix()), Type: typ, TTL: ttl, PayName: in.payer.name, PayAmount: res.Deposit + b.Balanced.Spec.Fee,
		PayReturn: changeOf(b.Balanced.Spec), Body: b.Balanced.Body, HardwareWalletIncluded: in.hardware(), Slots: uc.allSlots(in),
	})
	if err != nil {
		return RegisterResult{}, err
	}
	// Every local witness goes through Collection.Fill, the path a remote
	// response takes: the signature must verify over the body hash and the
	// key must hash to the slot's key.
	sws, err := prep.Sign(ctx, b.Balanced.Body)
	if err != nil {
		return RegisterResult{}, err
	}
	for _, sw := range sws {
		if coll, err = coll.Fill(pool.Fill{Slot: sw.Slot.Label, Witness: sw.Witness, ExpectVersion: coll.Version}, tip.Slot); err != nil {
			return RegisterResult{}, err
		}
	}
	// Stored only now: an abort or a refusal while signing leaves the
	// descriptor unchanged (SPO-05c-OUT-001).
	files, err := uc.store(ctx, in, coll, now)
	if err != nil {
		return RegisterResult{}, err
	}
	res.CollectionID, res.TransferFiles = coll.ID, files
	return uc.finish(ctx, in, inp, coll, spec, res, tip)
}

func changeOf(s txbuild.BodySpec) chain.Lovelace {
	if len(s.Outputs) == 0 {
		return 0
	}
	return s.Outputs[0].Lovelace
}

// store writes the collection into the descriptor and a transfer file for
// every empty slot that has none yet, in one transaction.
func (uc RegisterPool) store(ctx context.Context, in regInputs, coll pool.Collection, now time.Time) ([]string, error) {
	var written []string
	err := uc.Store.Update(ctx, func(w ports.Writer) error {
		raw, err := w.Get(ports.Ref{Name: in.name, Kind: ports.PoolDescriptor})
		if err != nil {
			return err
		}
		d, err := pool.ParseDescriptor(raw)
		if err != nil {
			return err
		}
		d.SetCollection(coll)
		if err := w.Put(ports.Ref{Name: in.name, Kind: ports.PoolDescriptor}, d.Render()); err != nil {
			return err
		}
		written = nil
		for _, slot := range coll.Missing() {
			ref := ports.Ref{Name: pool.TransferFileName(in.name, slot, coll.ID), Kind: ports.PoolWitnessFile}
			if ok, err := w.Exists(ref); err != nil {
				return err
			} else if ok {
				continue // never overwritten (SPO-05c-OUT-003)
			}
			vk, err := w.Get(in.vkeys[slot])
			if err != nil {
				return fmt.Errorf("the verification key of slot %s: %w", slot, err)
			}
			tf, err := pool.NewTransferFile(coll, slot, in.name, d.Text(pool.FieldMetaTicker), rfc5322(time.Unix(int64(coll.ID), 0).In(now.Location())), vk)
			if err != nil {
				return err
			}
			if err := w.Put(ref, tf.Render()); err != nil {
				return err
			}
			written = append(written, ref.Name)
		}
		return nil
	})
	return written, err
}

// finish reports an incomplete collection, or assembles and delivers a
// complete one.
//
// spec: SPO-05c-EXT-007, SPO-05c-PRE-011, SPO-05c-PR-003, SPO-05c-PR-004, SPO-05c-OUT-005, SPO-05c-OUT-006
func (uc RegisterPool) finish(ctx context.Context, in regInputs, inp txflow.Input, coll pool.Collection, spec *txbuild.BodySpec,
	res RegisterResult, tip chain.Tip) (RegisterResult, error) {
	res.CollectionID = coll.ID
	res.State = coll.State(tip.Slot)
	res.Missing = coll.Missing()
	if res.State == pool.CollectionOpenIncomplete {
		return res, nil
	}
	if res.State != pool.CollectionOpenComplete {
		return res, fmt.Errorf("%w: it is %s", pool.ErrCollectionNotOpen, res.State)
	}
	ws, err := coll.Witnesses()
	if err != nil {
		return res, err
	}
	// The second confirmation never honours a skip policy (SPO-Ptx-PR-004,
	// SPO-05c-PR-003): the deposit and the pledge are at stake.
	if uc.Pipeline.Confirmer == nil {
		return res, txflow.ErrNoConfirmer
	}
	sum := uc.summary(in, coll.Type, "submit", nil)
	sum.Source, sum.SourceAddr = in.payer.name, in.payer.addr
	sum.TxID, sum.TTL, sum.Route, sum.Deposit = coll.Body.ID, coll.TTL, uc.Pipeline.Route(), res.Deposit
	sum.Sources, sum.SingleSource, sum.Unchecked = res.Sources, res.SingleSource, res.Unchecked
	if spec != nil {
		sum.Inputs, sum.Outputs, sum.Fee, sum.Message = len(spec.Inputs), spec.Outputs, spec.Fee, spec.Message
	}
	yes, err := uc.Pipeline.Confirmer.Confirm(ctx, sum)
	if err != nil {
		return res, fmt.Errorf("confirmation: %w", err)
	}
	if !yes {
		if uc.DiscardOnDecline {
			if derr := uc.discard(ctx, in.name); derr != nil {
				return res, derr
			}
			res.State = pool.CollectionDiscarded
		}
		return res, txflow.ErrDeclined
	}
	out, err := uc.Pipeline.Deliver(ctx, inp, coll.Body, spec, ws, res.ApprovalSkipped)
	if err != nil {
		return res, err
	}
	res.Result = out
	// Record the submission, retire the certificate and the collection in
	// one transaction (SPO-05c-OUT-006: a crash between the two must not
	// leave a reusable certificate).
	stamp := rfc5322(uc.Clock.Now())
	if out.Queued {
		stamp += " (only offline, no proof)"
	}
	if err := uc.Store.Update(ctx, func(w ports.Writer) error {
		raw, err := w.Get(ports.Ref{Name: in.name, Kind: ports.PoolDescriptor})
		if err != nil {
			return err
		}
		d, err := pool.ParseDescriptor(raw)
		if err != nil {
			return err
		}
		d.RecordSubmission(strconv.FormatUint(tip.Epoch, 10), stamp)
		if err := w.Put(ports.Ref{Name: in.name, Kind: ports.PoolDescriptor}, d.Render()); err != nil {
			return err
		}
		// The id of what was submitted, so that a coordinator that asked others to
		// sign can tell this submission from a discard (SPO-Xparty-INV-035).
		if err := w.Put(ports.Ref{Name: in.name, Kind: ports.MultisigSubmitted}, []byte(hex.EncodeToString(out.TxID[:]))); err != nil {
			return err
		}
		return w.Delete(ports.Ref{Name: in.name, Kind: ports.PoolCert})
	}); err != nil {
		return res, fmt.Errorf("the transaction was sent (%s), but the registration record could not be stored: %w", out.TxID, err)
	}
	res.State = pool.CollectionSubmitted
	if out.Queued && uc.Attach != nil {
		if err := uc.attach(ctx, in.name); err != nil {
			return res, fmt.Errorf("the transaction was queued, but a metadata file could not be attached: %w", err)
		}
	}
	res.Decisions = append(res.Decisions,
		"the certificate file is deleted in the transaction that records the submission (SPO-05c-OUT-006, port note)",
		"an empty set of UTxOs or too small a change is an error, where upstream exits 0 (SPO-05c-PRE-007, SPO-05c-PRE-008)")
	return res, nil
}

func (uc RegisterPool) attach(ctx context.Context, name string) error {
	return uc.Store.View(ctx, func(r ports.Reader) error {
		for _, k := range []ports.Kind{ports.PoolMetadata, ports.PoolExtendedMetadata} {
			b, err := r.Get(ports.Ref{Name: name, Kind: k})
			if errors.Is(err, ports.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			file := name + ".metadata.json"
			if k == ports.PoolExtendedMetadata {
				file = name + ".extended-metadata.json"
			}
			if err := uc.Attach.Attach(ctx, file, b); err != nil {
				return err
			}
		}
		return nil
	})
}

func (uc RegisterPool) discard(ctx context.Context, name string) error {
	return uc.Store.Update(ctx, func(w ports.Writer) error {
		raw, err := w.Get(ports.Ref{Name: name, Kind: ports.PoolDescriptor})
		if err != nil {
			return err
		}
		d, err := pool.ParseDescriptor(raw)
		if err != nil {
			return err
		}
		d.ClearCollection()
		return w.Put(ports.Ref{Name: name, Kind: ports.PoolDescriptor}, d.Render())
	})
}

func (uc RegisterPool) params(ctx context.Context) (chain.ProtocolParameters, error) {
	p, err := uc.Params.ProtocolParameters(ctx)
	if err != nil {
		return chain.ProtocolParameters{}, fmt.Errorf("protocol parameters: %w", err)
	}
	if p.ProtocolMajor < 9 {
		return chain.ProtocolParameters{}, ErrProtocolTooOld
	}
	return p, nil
}

func (in regInputs) hardware() bool {
	if in.coldHW {
		return true
	}
	for _, o := range in.owners {
		if o.hwDesc {
			return true
		}
	}
	return false
}

func (uc RegisterPool) summary(in regInputs, typ pool.RegistrationType, stage string, missing []string) ports.TxSummary {
	kind := "pool registration"
	if typ == pool.PoolReRegistration {
		kind = "pool re-registration"
	}
	pledge, _ := pool.ParseLovelace(in.d.Text(pool.FieldPledge))
	return ports.TxSummary{Kind: kind, Stage: stage, Pool: in.poolID.Bech32(), Pledge: pledge, Missing: missing, Account: in.name}
}

func (uc RegisterPool) queued(in regInputs, typ pool.RegistrationType) ports.QueuedTx {
	ticker := in.d.Text(pool.FieldMetaTicker)
	return ports.QueuedTx{Type: string(typ), FromName: in.payer.name, FromAddr: in.payer.addr, ToName: in.payer.name, ToAddr: in.payer.addr,
		Description: fmt.Sprintf("signed pool registration transaction for '%s', payment via '%s'", ticker, in.payer.name),
		Extra: []ports.QueuedField{{Key: "poolMetaTicker", Value: ticker}, {Key: "regProtectionKey", Value: in.d.Text(pool.FieldRegProtection)},
			{Key: "poolMetaUrl", Value: in.d.Text(pool.FieldMetaURL)}, {Key: "poolMetaHash", Value: in.d.Text(pool.FieldMetaHash)}}}
}

// allSlots lists the collection's slots in SPO-05c-INV-005 order: the cold
// key, the payer, then every owner.
func (uc RegisterPool) allSlots(in regInputs) []pool.Slot {
	out := []pool.Slot{
		{Name: in.name + ".node", Role: custody.RolePoolCold, KeyHash: txbuild.KeyHash(in.poolID), Holder: in.cold},
		{Name: in.payer.name, Role: custody.RolePayment, KeyHash: in.payer.hash, Holder: in.payer.holder},
	}
	for _, o := range in.owners {
		s := pool.Slot{Name: o.desc.Name + ".staking", Role: custody.RoleStake, KeyHash: o.hash, Holder: o.holder}
		if o.holder == custody.HolderRemote {
			s.Party = o.desc.Witness
		}
		out = append(out, s)
	}
	return out
}

// slots is the signing plan's input: the same slots, with the per-role
// features of the demand (a device signs the operator and the owner of a pool
// registration in different modes).
func (uc RegisterPool) slots(draft txbuild.Draft, in regInputs) ([]txflow.Slot, error) {
	feats, err := draft.Features()
	if err != nil {
		return nil, err
	}
	without := func(drop custody.Feature) custody.Features {
		f := custody.Features{}
		for k := range feats {
			if k != drop {
				f[k] = struct{}{}
			}
		}
		return f
	}
	var out []txflow.Slot
	for _, s := range uc.allSlots(in) {
		owner := in.name
		switch s.Role {
		case custody.RolePayment:
			owner = in.payer.name
		case custody.RoleStake:
			owner = strings.TrimSuffix(s.Name, ".staking")
		}
		sl := txflow.Slot{Label: s.Name, Key: custody.KeyRef{Role: s.Role, Holder: s.Holder, Owner: owner, Party: s.Party}, Hash: s.KeyHash}
		switch s.Role {
		case custody.RolePoolCold:
			sl.Features = without(custody.FeatPoolRegistrationOwner)
		case custody.RoleStake:
			sl.Features = without(custody.FeatPoolRegistrationOper)
		}
		out = append(out, sl)
	}
	return out, nil
}

// bind gives a collection read from a descriptor the key hash and holder of
// every slot, from the keys in the store; a collection made by the upstream
// script carries neither. A hash that is stored and differs is an error.
func (uc RegisterPool) bind(c *pool.Collection, in regInputs) error {
	want := map[string]pool.Slot{}
	for _, s := range uc.allSlots(in) {
		want[s.Name] = s
	}
	for i, s := range c.Slots {
		w, ok := want[s.Name]
		if !ok {
			return fmt.Errorf("%w: the collection has a slot %q that the pool does not", pool.ErrBadCollection, s.Name)
		}
		if s.KeyHash == (txbuild.KeyHash{}) {
			c.Slots[i].KeyHash, c.Slots[i].Role = w.KeyHash, w.Role
		} else if s.KeyHash != w.KeyHash {
			return fmt.Errorf("%w: slot %q is bound to another key than the pool's", pool.ErrBadCollection, s.Name)
		}
		if c.Slots[i].Holder == "" {
			c.Slots[i].Holder, c.Slots[i].Party = w.Holder, w.Party
		}
	}
	return nil
}

// read gathers what the registration needs from the store.
//
// spec: SPO-05c-IN-001, SPO-05c-IN-003, SPO-05c-PRE-001, SPO-05c-PRE-002, SPO-05c-PRE-005, SPO-05c-PRE-006, SPO-05c-INV-004, SPO-05c-INV-006
func (uc RegisterPool) read(r ports.Reader, name, pn string) (regInputs, error) {
	in := regInputs{name: name, vkeys: map[string]ports.Ref{}}
	var err error
	if in.d, err = readDescriptor(r, name); err != nil {
		return in, err
	}
	if err := in.d.Require(pool.FieldName, pool.FieldOwner, pool.FieldRewards, pool.FieldPledge, pool.FieldCost, pool.FieldMargin,
		pool.FieldRegCertFile, pool.FieldMetaURL, pool.FieldMetaHash, pool.FieldMetaTicker, pool.FieldPoolIDBech); err != nil {
		return in, fmt.Errorf("%w (run the certificate generation again)", err)
	}
	if in.d.Text(pool.FieldRegCertFile) != name+".pool.cert" {
		return in, fmt.Errorf("%w: regCertFile is %q", ErrCertificateMismatch, in.d.Text(pool.FieldRegCertFile))
	}
	nodeRef := ports.Ref{Name: name, Kind: ports.NodeVKey}
	nodeEnv, err := get(r, nodeRef)
	if err != nil {
		return in, err
	}
	if in.poolID, err = poolIDOf(nodeEnv); err != nil {
		return in, fmt.Errorf("%s.node.vkey: %w", name, err)
	}
	if hws, err := r.Exists(ports.Ref{Name: name, Kind: ports.NodeHwsFile}); err != nil {
		return in, err
	} else {
		in.coldHW = hws
	}
	if in.cold, err = holderOf(r, ports.Ref{Name: name, Kind: ports.NodeSKey}, ports.Ref{Name: name, Kind: ports.NodeHwsFile}); err != nil {
		return in, fmt.Errorf("%w: %v", ErrNoColdSigner, err)
	}
	// The collection of an earlier run: it carries its own body (SPO-05c-INV-003).
	if in.coll, err = in.d.Collection(uc.TxIDs.TransactionID); err != nil {
		return in, err
	}
	in.vkeys[name+".node"] = nodeRef

	// The certificate. It is read when the collection is new, and always
	// present: its absence means "not generated or already submitted"
	// (SPO-05c-PRE-002).
	certEnv, err := get(r, ports.Ref{Name: name, Kind: ports.PoolCert})
	if err != nil {
		return in, fmt.Errorf("%w (not generated, or already submitted)", err)
	}
	if in.cert, err = uc.PoolCerts.DecodePoolCertificate(certEnv); err != nil {
		return in, fmt.Errorf("%s.pool.cert: %w", name, err)
	}
	if in.cert.Registration == nil || in.cert.Registration.Operator != in.poolID {
		return in, fmt.Errorf("%w: it is not a registration of %s", ErrCertificateMismatch, in.poolID.Bech32())
	}

	if in.payer, err = readPayer(r, uc.Addresses, uc.NetworkID, pn); err != nil {
		return in, err
	}
	in.vkeys[pn] = ports.Ref{Name: pn, Kind: ports.AddrVKey}

	owners, _, err := in.d.Owners()
	if err != nil {
		return in, err
	}
	seen := map[string]bool{}
	for _, o := range owners {
		if seen[o.Name] {
			return in, fmt.Errorf("%w: %s", ErrDuplicateOwner, o.Name)
		}
		seen[o.Name] = true
		oi := ownerInfo{desc: o}
		vkRef := ports.Ref{Name: o.Name, Kind: ports.StakingVKey}
		vk, err := get(r, vkRef)
		if err != nil {
			return in, err
		}
		if _, oi.hash, err = keyOf(vk); err != nil {
			return in, fmt.Errorf("%s.staking.vkey: %w", o.Name, err)
		}
		if e, err := pool.ParseEnvelope(vk); err == nil && strings.Contains(e.Description, "Hardware") {
			oi.hwDesc = true
		}
		in.vkeys[o.Name+".staking"] = vkRef
		raw, err := get(r, ports.Ref{Name: o.Name, Kind: ports.DelegCert})
		if err != nil {
			return in, err
		}
		if oi.deleg, err = uc.StakeCerts.DecodeCertificate(raw); err != nil {
			return in, fmt.Errorf("%s.deleg.cert: %w", o.Name, err)
		}
		if oi.deleg.Kind != stake.CertPoolDelegation || oi.deleg.Pool != in.poolID {
			return in, fmt.Errorf("%w: %s.deleg.cert", ErrDelegationOtherPool, o.Name)
		}
		if o.IsLocal() {
			if oi.holder, err = holderOf(r, ports.Ref{Name: o.Name, Kind: ports.StakingSKey}, ports.Ref{Name: o.Name, Kind: ports.StakingHwsFile}); err != nil {
				return in, err
			}
		} else {
			oi.holder = custody.HolderRemote
		}
		in.owners = append(in.owners, oi)
	}
	return in, nil
}

// thirdParty runs the opt-in checks against services outside the chain.
//
// spec: SPO-05c-EXT-001, SPO-05c-EXT-002, SPO-05c-MODE-004, SPO-05c-SEC-002, SPO-05c-SEC-005
func (uc RegisterPool) thirdParty(ctx context.Context, in regInputs, res *RegisterResult) error {
	ticker := in.d.Text(pool.FieldMetaTicker)
	if uc.Tickers != nil {
		v, err := uc.Tickers.CheckTicker(ctx, ticker)
		switch {
		case err != nil || v == ports.TickerUnchecked:
			// A service that cannot be reached lets the run go on, as upstream's does.
			res.Unchecked = append(res.Unchecked, "the ticker was not checked: the protection service gave no answer")
		case v == ports.TickerProtected:
			return fmt.Errorf("%w: %s", ErrTickerProtected, ticker)
		}
	} else {
		res.Unchecked = append(res.Unchecked, "the ticker-protection lookup is off (opt-in); the protection key is never sent")
	}
	if uc.Metadata == nil {
		res.Unchecked = append(res.Unchecked, "the published metadata was not compared with poolMetaHash: no fetcher in this mode")
		return nil
	}
	doc, err := uc.Metadata.Fetch(ctx, in.d.Text(pool.FieldMetaURL))
	if err != nil {
		return fmt.Errorf("download %s: %w", in.d.Text(pool.FieldMetaURL), err)
	}
	if len(doc) > pool.MaxMetadataBytes {
		return fmt.Errorf("%w: the download is %d bytes, the limit is %d", ErrMetadataMismatch, len(doc), pool.MaxMetadataBytes)
	}
	h, err := uc.Hasher.MetadataHash(doc)
	if err != nil {
		return fmt.Errorf("the published metadata is not valid pool metadata: %w", err)
	}
	if hexOf(h[:]) != strings.ToLower(in.d.Text(pool.FieldMetaHash)) {
		return fmt.Errorf("%w: published %s, descriptor %s", ErrMetadataMismatch, hexOf(h[:]), in.d.Text(pool.FieldMetaHash))
	}
	return nil
}

// decideType decides registration or re-registration once, from the type
// override, the descriptor and the chain.
//
// spec: SPO-05c-INV-002, SPO-05c-PRE-004, SPO-05c-MODE-001, SPO-05c-MODE-002, SPO-05c-MODE-003
func (uc RegisterPool) decideType(ctx context.Context, in regInputs, forced pool.RegistrationType, res *RegisterResult) (pool.RegistrationType, error) {
	ti := pool.TypeInput{Forced: forced, DeregSubmitted: in.d.Has(pool.FieldDeregSubmit), DescriptorRegistered: in.d.Has(pool.FieldRegSubmitted)}
	if forced != "" || ti.DeregSubmitted {
		return pool.DecideType(ti) // the chain is not consulted
	}
	if uc.Pools == nil {
		res.Unchecked = append(res.Unchecked, "the registration type comes from the descriptor: no chain reader in this mode")
		return pool.DecideType(ti)
	}
	rd, srcs, single, err := uc.readPool(ctx, in.poolID)
	if err != nil {
		if errors.Is(err, errUnknown) && uc.AllowUnverified {
			res.Unchecked = append(res.Unchecked, "the registration type comes from the descriptor: "+err.Error())
			return pool.DecideType(ti)
		}
		return "", err
	}
	ti.Chain = &rd
	res.Sources, res.SingleSource = srcs, single
	return pool.DecideType(ti)
}

var errUnknown = errors.New("the pool state is unknown")

// readPool reads the registration state of the harmful class: Unknown is an
// error and never "not registered"; one source needs the policy's
// acknowledgement, two must agree (ADR 0006).
func (uc RegisterPool) readPool(ctx context.Context, id chain.PoolID) (chain.Reading[chain.PoolState], []chain.Source, bool, error) {
	var zero chain.Reading[chain.PoolState]
	r, err := uc.Pools.PoolState(ctx, id)
	if err != nil {
		return zero, nil, false, fmt.Errorf("the pool state from %s: %w", uc.Pools.Source(), err)
	}
	if r.IsUnknown() {
		return zero, nil, false, fmt.Errorf("%w: %s: %s", errUnknown, uc.Pools.Source(), r.Why())
	}
	srcs := []chain.Source{uc.Pools.Source()}
	corroborated := false
	if uc.CrossCheck != nil {
		r2, err := uc.CrossCheck.PoolState(ctx, id)
		if err != nil {
			return zero, nil, false, fmt.Errorf("the pool state from %s: %w", uc.CrossCheck.Source(), err)
		}
		if !r2.IsUnknown() {
			if diff := chain.DiffPoolReadings(r, r2); diff != "" {
				return zero, nil, false, fmt.Errorf("%w: they differ on the pool's %s: %s says %s, %s says %s", ErrSourcesDisagree, diff,
					uc.Pools.Source(), chain.DescribePoolFor(r, diff), uc.CrossCheck.Source(), chain.DescribePoolFor(r2, diff))
			}
			corroborated = true
			srcs = append(srcs, uc.CrossCheck.Source())
		} else if uc.Sources != SingleSourceAcknowledged {
			return zero, nil, false, fmt.Errorf("%w: %s says %s, but %s did not answer: %s", ErrSingleSource,
				uc.Pools.Source(), describePool(r), uc.CrossCheck.Source(), r2.Why())
		}
	}
	if !corroborated {
		if uc.Sources != SingleSourceAcknowledged {
			return zero, nil, false, fmt.Errorf("%w: %s", ErrSingleSource, uc.Pools.Source())
		}
		if err := uc.OnSingle.Accept(ctx, "the pool registration state", uc.Pools.Source()); err != nil {
			return zero, nil, false, err
		}
		return r, srcs, true, nil
	}
	return r, srcs, false, nil
}

func describePool(r chain.Reading[chain.PoolState]) string { return chain.DescribePool(r) }
