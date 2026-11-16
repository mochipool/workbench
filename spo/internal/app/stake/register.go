package stake

import (
	"context"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	stk "github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/domain/txparam"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// txRun is what a stake transaction use case hands the shared tail.
type txRun struct {
	payer      payer
	stakeOwner string // the wallet whose `.staking` key witnesses
	stakeHold  custody.Holder
	certs      []stk.Certificate
	message    []string
	// extras and pass are the extra parameters of the request (metadata
	// files, message encryption); nil for none.
	extras  *txparam.Extras
	pass    *ports.Secret
	params  chain.ProtocolParameters
	summary ports.TxSummary
	queued  ports.QueuedTx
}

func (b Base) slots(r txRun) []txflow.Slot {
	return []txflow.Slot{
		{Label: "payment", Key: custody.KeyRef{Role: custody.RolePayment, Holder: r.payer.holder, Owner: r.payer.name}, Hash: r.payer.hash},
		{Label: "stake", Key: custody.KeyRef{Role: custody.RoleStake, Holder: r.stakeHold, Owner: r.stakeOwner}, Hash: txbuild.KeyHash(r.certs[0].Stake)},
	}
}

// early refuses what the signing plan refuses before any chain read, with a
// draft that has the features of the certificates: a signer that cannot meet
// the demand (a vendor that lacks a feature, no canonicalizer wired) and, for
// every stake script, a hardware key mixed with a key-file key
// (SPO-Ptx-PRE-006).
func (b Base) early(r txRun) error {
	_, err := b.Pipeline.PrepareWith(txbuild.Draft{Certificates: r.certs, Message: r.message}, b.slots(r), stk.StakeWitnesses,
		txflow.PrepareOptions{RefuseMixed: true})
	return err
}

// changeKeys are the hardware keys declared to the device so it recognises the
// change output: the payment and the stake key of the wallet, when both are on
// the device (SPO-Ptx-INV-009).
func (b Base) changeKeys(r txRun) []custody.KeyRef {
	if r.payer.holder != custody.HolderHardware || r.stakeHold != custody.HolderHardware {
		return nil
	}
	s := b.slots(r)
	return []custody.KeyRef{s[0].Key, s[1].Key}
}

// execute is the tail of the certificate use cases: clock, inputs, the
// draft, the plan, then the shared pipeline.
//
// spec: SPO-Ptx-MODE-001, SPO-Ptx-MODE-002, SPO-Ptx-MODE-003, SPO-Ptx-MODE-004, SPO-Ptx-PRE-001, SPO-Ptx-INV-001, SPO-Ptx-INV-002,
// spec: SPO-Ptx-INV-006, SPO-Ptx-INV-010
func (b Base) execute(ctx context.Context, r txRun) (txflow.Result, error) {
	if err := b.Pipeline.Check(); err != nil {
		return txflow.Result{}, err
	}
	// The extra parameters are resolved before any network access: the
	// metadata files are read, the message is encrypted.
	//
	// spec: SPO-Pparam-IF-010, SPO-Pparam-IF-016
	meta, err := txflow.ResolveExtras(txflow.ExtrasPorts{Files: b.Files, Encrypter: b.Encrypter}, r.extras, r.message, r.pass)
	if err != nil {
		return txflow.Result{}, err
	}
	tip, err := b.Tip.Tip(ctx)
	if err != nil {
		return txflow.Result{}, fmt.Errorf("current slot: %w", err)
	}
	ttl, err := txbuild.TTL(tip, b.DefTTL)
	if err != nil {
		return txflow.Result{}, err
	}
	utxos, err := b.Utxos.Utxos(ctx, r.payer.addr)
	if err != nil {
		return txflow.Result{}, fmt.Errorf("the UTxOs of %s: %w", r.payer.name, err)
	}
	strategy := b.Selection
	if strategy == "" {
		strategy = txbuild.SelectAll
	}
	inputs, err := strategy.Select(utxos)
	if err != nil {
		return txflow.Result{}, fmt.Errorf("%s: %w", r.payer.name, err)
	}
	draft, err := txbuild.NewCertificateDraft(r.payer.addr, inputs, r.certs, r.message)
	if err != nil {
		return txflow.Result{}, err
	}
	if r.extras != nil {
		if draft, err = meta.Attach(draft); err != nil {
			return txflow.Result{}, err
		}
	}
	prep, err := b.Pipeline.PrepareWith(draft, b.slots(r), stk.StakeWitnesses, txflow.PrepareOptions{RefuseMixed: true})
	if err != nil {
		return txflow.Result{}, err
	}
	sum := r.summary
	sum.SourceAddr, sum.Source = r.payer.addr, r.payer.name
	sum.Attachments = draft.AttachmentLines()
	if sum.Deposit, err = draft.Deposits(); err != nil {
		return txflow.Result{}, err
	}
	if sum.Refund, err = draft.Refunds(); err != nil {
		return txflow.Result{}, err
	}
	return b.Pipeline.Execute(ctx, txflow.Input{Draft: draft, Params: r.params, TTL: ttl, Prepared: prep, Witnesses: stk.StakeWitnesses,
		Summary: sum, Queued: r.queued, HardwareChangeKeys: b.changeKeys(r)})
}

func (b Base) params(ctx context.Context) (chain.ProtocolParameters, error) {
	p, err := b.Params.ProtocolParameters(ctx)
	if err != nil {
		return chain.ProtocolParameters{}, fmt.Errorf("protocol parameters: %w", err)
	}
	if p.ProtocolMajor < MinConwayMajor {
		return chain.ProtocolParameters{}, ErrProtocolTooOld
	}
	return p, nil
}

// stakeInputs is what the store holds for a stake account.
type stakeInputs struct {
	name   string
	addr   chain.StakeAddress
	holder custody.Holder
}

// readStake reads `<w>.staking.addr` and the holder of `<w>.staking.skey`.
func readStake(r ports.Reader, w string, needAddr bool) (stakeInputs, error) {
	out := stakeInputs{name: w}
	if needAddr {
		b, err := get(r, ports.Ref{Name: w, Kind: ports.StakingAddr})
		if err != nil {
			return out, err
		}
		out.addr = chain.StakeAddress(firstLine(b))
	}
	h, err := holderOf(r, ports.Ref{Name: w, Kind: ports.StakingSKey}, ports.Ref{Name: w, Kind: ports.StakingHwsFile})
	if err != nil {
		return out, err
	}
	out.holder = h
	return out, nil
}

// softAccount reads the account for a check whose false answer only makes
// the ledger reject the transaction (self-correcting, ADR 0006): is the
// address already registered, is it registered. A missing reader or an
// unknown answer is skipped and reported when AllowUnverified says so, and an
// error otherwise. A failing provider is always an error.
func (b Base) softAccount(ctx context.Context, rd ports.RewardAccountReader, addr chain.StakeAddress, allow bool) (ans accountAnswer, ok bool, note string, err error) {
	if rd == nil {
		if !allow {
			return ans, false, "", ErrNoChainReader
		}
		return ans, false, "the stake address state was not checked: no chain reader in this mode", nil
	}
	ans, err = accountReads{Primary: rd}.read(ctx, addr, false)
	if errors.Is(err, stk.ErrUnknown) && allow {
		return accountAnswer{}, false, "the stake address state was not checked: " + err.Error(), nil
	}
	if err != nil {
		return ans, false, "", err
	}
	return ans, true, "", nil
}

// ---- 03b -----------------------------------------------------------------

// RegisterStakeAddress registers a stake address on chain (upstream 03b): the
// Conway registration certificate with the key deposit of the protocol
// parameters, paid from a payment address. The balance is
// inputs - fee - deposit. Two witnesses: the payment key and the stake key.
//
// The certificate is built in memory and `<name>.staking.cert` is written
// only after the transaction was submitted or queued: a run that is refused
// or declined leaves no file (SPO-03b-OUT-001, port note).
type RegisterStakeAddress struct {
	Base
	Certs ports.CertificateBuilder
	// Rewards answers "is it already registered" (optional, see
	// AllowUnverified).
	Rewards ports.RewardAccountReader
	// AllowUnverified goes on when that check cannot be made (no reader, or
	// the source did not answer): offline, the snapshot holds only addresses
	// that were registered when it was made, so a missing entry is Unknown
	// and upstream skips the check (SPO-03b-MODE-001). The result lists the
	// skipped check.
	AllowUnverified bool
}

// RegisterRequest names the stake account and the paying address as typed.
type RegisterRequest struct {
	Stake   string
	Payer   string
	Message []string
	// Extras are the parsed extra parameters (txparam.Parse with
	// txparam.ForCertificate); Passphrase the `pass:` of Extras. Optional.
	Extras     *txparam.Extras
	Passphrase *ports.Secret
}

// Run registers the stake address.
//
// spec: SPO-03b-IF-001, SPO-03b-IN-001, SPO-03b-IN-002, SPO-03b-PRE-001, SPO-03b-PRE-002, SPO-03b-PRE-003,
// spec: SPO-03b-EXT-001, SPO-03b-EXT-002, SPO-03b-OUT-001, SPO-03b-INV-001, SPO-03b-INV-002, SPO-03b-INV-003,
// spec: SPO-03b-INV-009, SPO-03b-INV-010, SPO-03b-INV-014, SPO-03b-PR-001, SPO-03b-MODE-001, SPO-03b-MODE-002
func (uc RegisterStakeAddress) Run(ctx context.Context, req RegisterRequest) (Result, error) {
	if req.Stake == "" || req.Payer == "" {
		return Result{}, errors.New("a registration needs a stake account and a paying address")
	}
	if err := txbuild.ValidateMessage(req.Message); err != nil {
		return Result{}, err
	}
	w, err := walletName(req.Stake)
	if err != nil {
		return Result{}, fmt.Errorf("stake account: %w", err)
	}
	pn, err := payerName(req.Payer)
	if err != nil {
		return Result{}, fmt.Errorf("payer: %w", err)
	}
	var pay payer
	var st stakeInputs
	if err := uc.Store.View(ctx, func(r ports.Reader) error {
		var err error
		if st, err = readStake(r, w, true); err != nil {
			return err
		}
		pay, err = uc.readPayer(r, pn)
		return err
	}); err != nil {
		return Result{}, err
	}
	key, err := uc.checkStakeAddress(st.addr)
	if err != nil {
		return Result{}, err
	}

	// What the signing plan refuses (a device that lacks a feature of the
	// certificate, a hardware key mixed with a key-file key, no canonicalizer)
	// and the first look at the account come before the parameters and the clock.
	probe := stk.Certificate{Spec: stk.Spec{Kind: stk.CertRegistration, Stake: key, Deposit: 1}}
	if err := uc.early(txRun{payer: pay, stakeOwner: w, stakeHold: st.holder, certs: []stk.Certificate{probe}, message: req.Message}); err != nil {
		return Result{}, err
	}
	var unchecked []string
	var sources []chain.Source
	ans, checked, note, err := uc.softAccount(ctx, uc.Rewards, st.addr, uc.AllowUnverified)
	if err != nil {
		return Result{}, err
	}
	if checked {
		sources = ans.Sources
		if err := ans.Account.CanRegister(); err != nil {
			return Result{}, err
		}
	} else {
		unchecked = append(unchecked, note)
	}

	params, err := uc.params(ctx)
	if err != nil {
		return Result{}, err
	}
	deposit := params.StakeAddressDeposit
	if deposit == 0 {
		return Result{}, ErrNoDeposit
	}
	cert, err := uc.Certs.BuildCertificate(stk.Spec{Kind: stk.CertRegistration, Stake: key, Deposit: deposit})
	if err != nil {
		return Result{}, err
	}
	res, err := uc.execute(ctx, txRun{
		payer: pay, stakeOwner: w, stakeHold: st.holder, certs: []stk.Certificate{cert}, message: req.Message, extras: req.Extras, pass: req.Passphrase, params: params,
		summary: ports.TxSummary{Kind: "stake registration", Account: w, StakeAddr: st.addr, Sources: sources, Unchecked: unchecked},
		queued: ports.QueuedTx{Type: "StakeKeyRegistration", FromName: pay.name, FromAddr: pay.addr, ToName: pay.name, ToAddr: pay.addr,
			Description: fmt.Sprintf("signed staking key registration transaction for '%s.staking', payment via '%s'", w, pay.name),
			Extra:       []ports.QueuedField{{Key: "stakeAddr", Value: w + ".staking"}}},
	})
	if err != nil {
		return Result{}, err
	}
	// The transaction left the machine: now the certificate artefact.
	if err := uc.Store.Update(ctx, func(wr ports.Writer) error {
		return wr.Put(ports.Ref{Name: w, Kind: ports.StakingCert}, cert.Envelope)
	}); err != nil {
		return Result{}, fmt.Errorf("the transaction was sent, but the certificate file could not be stored: %w", err)
	}
	return Result{Result: res, Certificate: cert, Deposit: deposit, Sources: sources, Unchecked: unchecked}, nil
}

// ---- 06 ------------------------------------------------------------------

// RegisterPoolDelegation puts a delegation certificate on chain (upstream
// 06): the stake key of the account delegates to the pool named in the
// certificate, a payment address pays the fee. There is no deposit. The
// certificate is decoded structurally (SPO-06-IN-002), the stake address
// rebuilt from it.
type RegisterPoolDelegation struct {
	Base
	Certs   ports.CertificateDecoder
	Builder ports.AddressBuilder
	// Pools checks that the pool is registered (SPO-06-PRE-002); Rewards
	// that the stake address is (SPO-06-PRE-003). Either may be nil, see
	// AllowUnverified.
	Pools   ports.PoolStateReader
	Rewards ports.RewardAccountReader
	// PoolCross is an optional second, independent source for the pool's
	// registration; Sources decides what happens when it rests on one source:
	// it is a "harmful if false" read (ADR 0006).
	PoolCross ports.PoolStateReader
	Sources   SourcePolicy
	// OnSingle records an acknowledged single source before anything is
	// signed or queued; required when Sources is SingleSourceAcknowledged.
	OnSingle ports.SingleSourceHook
	// AllowUnverified goes on when a check cannot be made, as upstream's
	// offline mode does (SPO-06-MODE-001); the result lists what was skipped.
	AllowUnverified bool
}

// DelegationRegisterRequest names the delegator (the stake account whose
// `<name>.deleg.cert` is read) and the paying address.
type DelegationRegisterRequest struct {
	Delegator string
	Payer     string
	Message   []string
	// Extras are the parsed extra parameters (txparam.Parse with
	// txparam.ForCertificate); Passphrase the `pass:` of Extras. Optional.
	Extras     *txparam.Extras
	Passphrase *ports.Secret
}

// Run registers the delegation.
//
// spec: SPO-06-IF-001, SPO-06-IN-001, SPO-06-IN-002, SPO-06-PRE-001, SPO-06-PRE-002, SPO-06-PRE-003, SPO-06-INV-001,
// spec: SPO-06-INV-002, SPO-06-INV-003, SPO-06-INV-004, SPO-06-INV-009, SPO-06-INV-010, SPO-06-INV-014, SPO-06-MODE-001,
// spec: SPO-06-MODE-003, SPO-06-PR-001
func (uc RegisterPoolDelegation) Run(ctx context.Context, req DelegationRegisterRequest) (Result, error) {
	if req.Delegator == "" || req.Payer == "" {
		return Result{}, errors.New("a delegation needs a stake account and a paying address")
	}
	if err := txbuild.ValidateMessage(req.Message); err != nil {
		return Result{}, err
	}
	w, err := walletName(req.Delegator)
	if err != nil {
		return Result{}, fmt.Errorf("stake account: %w", err)
	}
	pn, err := payerName(req.Payer)
	if err != nil {
		return Result{}, fmt.Errorf("payer: %w", err)
	}
	var pay payer
	var st stakeInputs
	var raw []byte
	if err := uc.Store.View(ctx, func(r ports.Reader) error {
		var err error
		if raw, err = get(r, ports.Ref{Name: w, Kind: ports.DelegCert}); err != nil {
			return err
		}
		if st, err = readStake(r, w, false); err != nil {
			return err
		}
		pay, err = uc.readPayer(r, pn)
		return err
	}); err != nil {
		return Result{}, err
	}
	cert, err := uc.Certs.DecodeCertificate(raw)
	if err != nil {
		return Result{}, fmt.Errorf("%s.deleg.cert: %w", w, err)
	}
	if cert.Kind != stk.CertPoolDelegation {
		return Result{}, fmt.Errorf("%w: %s.deleg.cert is a %s certificate", ErrWrongCertificate, w, cert.Kind)
	}
	if err := uc.early(txRun{payer: pay, stakeOwner: w, stakeHold: st.holder, certs: []stk.Certificate{cert}, message: req.Message}); err != nil {
		return Result{}, err
	}
	st.addr, err = uc.Builder.BuildStakeAddress(uc.NetworkID, txbuild.KeyHash(cert.Stake))
	if err != nil {
		return Result{}, err
	}

	var unchecked []string
	var sources []chain.Source
	single := false
	// The pool (harmful class).
	switch {
	case uc.Pools == nil:
		if !uc.AllowUnverified {
			return Result{}, fmt.Errorf("the pool registration: %w", ErrNoChainReader)
		}
		unchecked = append(unchecked, "the pool registration was not checked: no chain reader in this mode")
	default:
		rd, err := uc.Pools.PoolState(ctx, cert.Pool)
		if err != nil {
			return Result{}, fmt.Errorf("the pool state from %s: %w", uc.Pools.Source(), err)
		}
		switch {
		case rd.IsUnknown():
			if !uc.AllowUnverified {
				return Result{}, fmt.Errorf("%w: the pool state from %s: %s", ErrUnverified, uc.Pools.Source(), rd.Why())
			}
			unchecked = append(unchecked, "the pool registration was not checked: "+rd.Why())
		case rd.IsNone():
			return Result{}, fmt.Errorf("%w: %s", ErrPoolNotRegistered, cert.Pool.Bech32())
		default:
			srcs, one, err := corroboratePool(ctx, uc.Pools, uc.PoolCross, uc.Sources, uc.OnSingle, cert.Pool, rd)
			if err != nil {
				return Result{}, err
			}
			single = one
			sources = append(sources, srcs...)
		}
	}
	// The account (self-correcting).
	ans, checked, note, err := uc.softAccount(ctx, uc.Rewards, st.addr, uc.AllowUnverified)
	if err != nil {
		return Result{}, err
	}
	if checked {
		sources = append(sources, ans.Sources...)
		if err := ans.Account.CanDelegate(); err != nil {
			return Result{}, err
		}
	} else {
		unchecked = append(unchecked, note)
	}

	params, err := uc.params(ctx)
	if err != nil {
		return Result{}, err
	}
	res, err := uc.execute(ctx, txRun{
		payer: pay, stakeOwner: w, stakeHold: st.holder, certs: []stk.Certificate{cert}, message: req.Message, extras: req.Extras, pass: req.Passphrase, params: params,
		summary: ports.TxSummary{Kind: "pool delegation", Account: w, StakeAddr: st.addr, Sources: sources, SingleSource: single, Unchecked: unchecked},
		queued: ports.QueuedTx{Type: "DelegationCertRegistration", FromName: pay.name, FromAddr: pay.addr, ToName: pay.name, ToAddr: pay.addr,
			Description: fmt.Sprintf("signed delegation cert registration transaction for '%s', payment via '%s'", w, pay.name),
			Extra:       []ports.QueuedField{{Key: "delegName", Value: w}}},
	})
	if err != nil {
		return Result{}, err
	}
	return Result{Result: res, Certificate: cert, Sources: sources, SingleSource: single, Unchecked: unchecked}, nil
}

// ---- 22b -----------------------------------------------------------------

// RegisterVoteDelegation puts a vote delegation certificate on chain
// (upstream 22b). A DRep target must be registered; always-abstain and
// always-no-confidence need no check.
type RegisterVoteDelegation struct {
	Base
	Certs   ports.CertificateDecoder
	Builder ports.AddressBuilder
	// DReps checks the DRep (SPO-22b-PRE-002); Rewards the stake address
	// (SPO-22b-PRE-003). Either may be nil, see AllowUnverified.
	DReps   ports.DRepStateReader
	Rewards ports.RewardAccountReader
	// AllowUnverified goes on when a check cannot be made (offline,
	// SPO-22b-MODE-001); the result lists what was skipped.
	AllowUnverified bool
}

// Run registers the vote delegation.
//
// A certificate in a form the decoder does not know is an error, where
// upstream leaves the target undecided and skips the DRep check
// (SPO-22b-IN-002).
//
// spec: SPO-22b-IF-001, SPO-22b-IN-001, SPO-22b-IN-002, SPO-22b-PRE-001, SPO-22b-PRE-002, SPO-22b-PRE-003,
// spec: SPO-22b-INV-001, SPO-22b-INV-002, SPO-22b-INV-004, SPO-22b-INV-005, SPO-22b-INV-006, SPO-22b-MODE-001, SPO-22b-MODE-003, SPO-22b-PR-001
func (uc RegisterVoteDelegation) Run(ctx context.Context, req DelegationRegisterRequest) (Result, error) {
	if req.Delegator == "" || req.Payer == "" {
		return Result{}, errors.New("a vote delegation needs a stake account and a paying address")
	}
	if err := txbuild.ValidateMessage(req.Message); err != nil {
		return Result{}, err
	}
	w, err := walletName(req.Delegator)
	if err != nil {
		return Result{}, fmt.Errorf("stake account: %w", err)
	}
	pn, err := payerName(req.Payer)
	if err != nil {
		return Result{}, fmt.Errorf("payer: %w", err)
	}
	// The era gate comes before any file is read (SPO-22b-PRE-001).
	params, err := uc.params(ctx)
	if err != nil {
		return Result{}, err
	}
	var pay payer
	var st stakeInputs
	var raw []byte
	if err := uc.Store.View(ctx, func(r ports.Reader) error {
		var err error
		if raw, err = get(r, ports.Ref{Name: w, Kind: ports.VoteDelegCert}); err != nil {
			return err
		}
		if st, err = readStake(r, w, false); err != nil {
			return err
		}
		pay, err = uc.readPayer(r, pn)
		return err
	}); err != nil {
		return Result{}, err
	}
	cert, err := uc.Certs.DecodeCertificate(raw)
	if err != nil {
		return Result{}, fmt.Errorf("%s.vote-deleg.cert: %w", w, err)
	}
	if cert.Kind != stk.CertVoteDelegation {
		return Result{}, fmt.Errorf("%w: %s.vote-deleg.cert is a %s certificate", ErrWrongCertificate, w, cert.Kind)
	}
	if err := uc.early(txRun{payer: pay, stakeOwner: w, stakeHold: st.holder, certs: []stk.Certificate{cert}, message: req.Message}); err != nil {
		return Result{}, err
	}
	st.addr, err = uc.Builder.BuildStakeAddress(uc.NetworkID, txbuild.KeyHash(cert.Stake))
	if err != nil {
		return Result{}, err
	}

	var unchecked []string
	var sources []chain.Source
	if id, ok := cert.DRep.ChainID(); ok {
		switch {
		case uc.DReps == nil:
			if !uc.AllowUnverified {
				return Result{}, fmt.Errorf("the DRep registration: %w", ErrNoChainReader)
			}
			unchecked = append(unchecked, "the DRep registration was not checked: no chain reader in this mode")
		default:
			rd, err := uc.DReps.DRepState(ctx, id)
			if err != nil {
				return Result{}, fmt.Errorf("the DRep state from %s: %w", uc.DReps.Source(), err)
			}
			switch {
			case rd.IsUnknown():
				if !uc.AllowUnverified {
					return Result{}, fmt.Errorf("%w: the DRep state from %s: %s", ErrUnverified, uc.DReps.Source(), rd.Why())
				}
				unchecked = append(unchecked, "the DRep registration was not checked: "+rd.Why())
			case rd.IsNone():
				return Result{}, fmt.Errorf("%w: %s", ErrDRepNotRegistered, cert.DRep)
			default:
				sources = append(sources, uc.DReps.Source())
			}
		}
	}
	ans, checked, note, err := uc.softAccount(ctx, uc.Rewards, st.addr, uc.AllowUnverified)
	if err != nil {
		return Result{}, err
	}
	if checked {
		sources = append(sources, ans.Sources...)
		if err := ans.Account.CanDelegate(); err != nil {
			return Result{}, err
		}
	} else {
		unchecked = append(unchecked, note)
	}

	res, err := uc.execute(ctx, txRun{
		payer: pay, stakeOwner: w, stakeHold: st.holder, certs: []stk.Certificate{cert}, message: req.Message, extras: req.Extras, pass: req.Passphrase, params: params,
		summary: ports.TxSummary{Kind: "vote delegation", Account: w, StakeAddr: st.addr, Sources: sources, Unchecked: unchecked},
		queued: ports.QueuedTx{Type: "VoteDelegationCertRegistration", FromName: pay.name, FromAddr: pay.addr, ToName: pay.name, ToAddr: pay.addr,
			Description: fmt.Sprintf("signed vote-delegation cert registration transaction for '%s', payment via '%s'", w, pay.name),
			Extra:       []ports.QueuedField{{Key: "delegName", Value: w}}},
	})
	if err != nil {
		return Result{}, err
	}
	return Result{Result: res, Certificate: cert, Sources: sources, Unchecked: unchecked}, nil
}

// ---- 08b -----------------------------------------------------------------

// DeregisterStakeAddress retires a stake address on chain (upstream 08b): the
// deregistration certificate of 08a, a payment address paying the fee, the
// key deposit refunded to the payer. The account must be registered with no
// rewards and no open governance-action deposit (the refusal 08a makes,
// enforced here too: SPO-08b-INV-001 port note), and the deposit in the
// certificate must be the one the chain holds, or the ledger rejects the
// transaction.
type DeregisterStakeAddress struct {
	Base
	Certs ports.CertificateDecoder
	// Account is where the account state comes from (required);
	// CrossCheck an optional second independent source. The reward balance
	// and the refund rest on this read, which is "harmful if false".
	Account    ports.RewardAccountReader
	CrossCheck ports.RewardAccountReader
	Sources    SourcePolicy
	// OnSingle records an acknowledged single source before anything is
	// signed or queued; required when Sources is SingleSourceAcknowledged.
	OnSingle ports.SingleSourceHook
}

// Run deregisters the stake address.
//
// The refund is the deposit of the certificate, decoded structurally, and it
// must equal the deposit the chain states (SPO-08b-IN-002): a pre-Conway
// certificate without a deposit is refused instead of assumed to be 2000000.
//
// spec: SPO-08b-IF-001, SPO-08b-IN-001, SPO-08b-IN-002, SPO-08b-PRE-001, SPO-08b-PRE-002, SPO-08b-PRE-003,
// spec: SPO-08b-EXT-001, SPO-08b-INV-001, SPO-08b-INV-002, SPO-08b-INV-003, SPO-08b-INV-004, SPO-08b-INV-005, SPO-08b-INV-006,
// spec: SPO-08b-MODE-001, SPO-08b-MODE-003, SPO-08b-PR-001
func (uc DeregisterStakeAddress) Run(ctx context.Context, req RegisterRequest) (Result, error) {
	if req.Stake == "" || req.Payer == "" {
		return Result{}, errors.New("a deregistration needs a stake account and a paying address")
	}
	if err := txbuild.ValidateMessage(req.Message); err != nil {
		return Result{}, err
	}
	w, err := walletName(req.Stake)
	if err != nil {
		return Result{}, fmt.Errorf("stake account: %w", err)
	}
	pn, err := payerName(req.Payer)
	if err != nil {
		return Result{}, fmt.Errorf("payer: %w", err)
	}
	var pay payer
	var st stakeInputs
	var raw []byte
	if err := uc.Store.View(ctx, func(r ports.Reader) error {
		var err error
		if raw, err = get(r, ports.Ref{Name: w, Kind: ports.StakingDeregCert}); err != nil {
			return err
		}
		if st, err = readStake(r, w, true); err != nil {
			return err
		}
		pay, err = uc.readPayer(r, pn)
		return err
	}); err != nil {
		return Result{}, err
	}
	key, err := uc.checkStakeAddress(st.addr)
	if err != nil {
		return Result{}, err
	}
	cert, err := uc.Certs.DecodeCertificate(raw)
	if err != nil {
		return Result{}, fmt.Errorf("%s.staking.dereg-cert: %w", w, err)
	}
	if cert.Kind != stk.CertDeregistration {
		return Result{}, fmt.Errorf("%w: %s.staking.dereg-cert is a %s certificate", ErrWrongCertificate, w, cert.Kind)
	}
	if cert.Stake != key {
		return Result{}, fmt.Errorf("%w: the certificate is for another stake key than %s.staking.addr", ErrWrongCertificate, w)
	}
	if err := uc.early(txRun{payer: pay, stakeOwner: w, stakeHold: st.holder, certs: []stk.Certificate{cert}, message: req.Message}); err != nil {
		return Result{}, err
	}

	ans, err := accountReads{Primary: uc.Account, CrossCheck: uc.CrossCheck, Policy: uc.Sources, OnSingle: uc.OnSingle}.read(ctx, st.addr, true)
	if err != nil {
		return Result{}, err
	}
	deposit, err := refundOf(ans)
	if err != nil {
		return Result{}, err
	}
	if _, err := ans.Account.Apply(cert.Spec); err != nil {
		return Result{}, err
	}
	if deposit != cert.Deposit {
		return Result{}, fmt.Errorf("%w: certificate %d lovelace, chain %d: make the certificate again (08a)", ErrDepositMismatch, cert.Deposit, deposit)
	}

	params, err := uc.params(ctx)
	if err != nil {
		return Result{}, err
	}
	res, err := uc.execute(ctx, txRun{
		payer: pay, stakeOwner: w, stakeHold: st.holder, certs: []stk.Certificate{cert}, message: req.Message, extras: req.Extras, pass: req.Passphrase, params: params,
		summary: ports.TxSummary{Kind: "stake deregistration", Account: w, StakeAddr: st.addr, Sources: ans.Sources, SingleSource: ans.Single, Unchecked: ans.Notes},
		queued: ports.QueuedTx{Type: "StakeKeyDeRegistration", FromName: pay.name, FromAddr: pay.addr, ToName: pay.name, ToAddr: pay.addr,
			Description: fmt.Sprintf("signed staking key deregistration transaction for '%s.staking', payment via '%s'", w, pay.name),
			Extra:       []ports.QueuedField{{Key: "stakeAddr", Value: w + ".staking"}}},
	})
	if err != nil {
		return Result{}, err
	}
	return Result{Result: res, Certificate: cert, Refund: cert.Deposit, Sources: ans.Sources, SingleSource: ans.Single, Unchecked: ans.Notes}, nil
}
