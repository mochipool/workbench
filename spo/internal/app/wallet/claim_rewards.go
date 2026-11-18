package wallet

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/mochipool/workbench/spo/internal/app/keyring"
	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/domain/txparam"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals of ClaimRewards beyond those of SendLovelaces.
var (
	// ErrNoStakeAddress: `<stake>.staking.addr` does not exist (SPO-01claimRewards-IN-001).
	ErrNoStakeAddress = errors.New("the stake account has no address file (.staking.addr)")
	// ErrNoStakeKey: neither `<stake>.staking.skey` nor its hardware file exists.
	ErrNoStakeKey = errors.New("the stake account has no signing key (.staking.skey) or hardware signing file (.staking.hwsfile)")
	// ErrNotStakeAddress: the stored address is not a key-credential stake address of this network.
	ErrNotStakeAddress = errors.New("the stake account's address is not a stake address with a key credential on this network")
	// ErrNoFeePayer: the destination is a literal address and no fee payer was given (SPO-01claimRewards-PRE-001).
	ErrNoFeePayer = errors.New("no fee payer: the destination is not a stored address, so name the address that pays the fee")
	// ErrStakeNotRegistered: the stake address is not registered (SPO-01claimRewards-PRE-004).
	ErrStakeNotRegistered = errors.New("the stake address is not registered on the chain")
	// ErrNoVoteDelegation: protocol 10 and later refuse a withdrawal without a vote delegation (SPO-01claimRewards-PRE-005).
	ErrNoVoteDelegation = errors.New("the stake account has no vote delegation, which protocol version 10 and later require for a withdrawal: delegate to a DRep (22a, 22b)")
	// ErrNoRewards: the reward balance is zero (SPO-01claimRewards-PRE-006).
	ErrNoRewards = errors.New("the stake account has no rewards to claim")
	// ErrNoRewardReader: the composition has no reader for the reward state.
	ErrNoRewardReader = errors.New("claiming rewards needs a reader for the reward state")
	// ErrRewardUnknown: the source did not say what the reward state is.
	ErrRewardUnknown = errors.New("the chain did not say what the reward state of the stake address is")
)

// ClaimRewards withdraws the whole reward balance of a stake account to a
// destination address, paying the fee from a payment address (upstream
// 01_claimRewards). Two witnesses: the payment key and the stake key.
//
// The withdrawal is the balance read at the start of the run and nothing
// else (SPO-01claimRewards-INV-001): a stale balance makes the ledger reject
// the transaction, which is self-correcting (ADR 0006), so one source is
// enough. The body is built once in memory and signed as built: no file from
// an earlier run can be picked up.
type ClaimRewards struct {
	Store     ports.NamedStore
	Signers   ports.SignerDirectory
	Utxos     ports.UtxoReader
	Params    ports.ProtocolParametersReader
	Tip       ports.TipReader
	Addresses ports.AddressInspector
	Min       ports.MinOutputCalculator
	Fees      ports.FeeEstimator
	Bodies    ports.TxBodyBuilder
	Assembler ports.TxAssembler
	Confirmer ports.Confirmer
	// Rewards reads the reward state: the node, Koios or the snapshot.
	Rewards ports.RewardAccountReader

	// Exactly one of Submitter and Queue is set.
	Submitter ports.TxSubmitter
	Queue     ports.TxQueue

	NetworkID uint8
	Approval  ApprovalPolicy
	DefTTL    uint64
	Selection txbuild.SelectionStrategy
	// Files and Encrypter are needed only by a request with Extras that name
	// metadata files or ask for message encryption.
	Files     ports.MetadataFileReader
	Encrypter ports.MessageEncrypter
	// Canonicalizer brings the body to hardware form when a key is held by a
	// hardware wallet; nil refuses a hardware plan (txflow.ErrNoCanonicalizer).
	Canonicalizer ports.HardwareCanonicalizer
	// Handles resolves an ADA Handle destination; nil refuses handles.
	Handles HandleResolver
}

// ClaimRequest is one claim. Stake and Destination are as the operator typed
// them. Payer is the fee payer; empty means the destination when that is a
// stored address (SPO-01claimRewards-IF-005).
type ClaimRequest struct {
	Stake       string
	Destination string
	Payer       string
	Message     []string
	// Extras are the parsed extra parameters (txparam.Parse with
	// txparam.ForCertificate); Passphrase the `pass:` of Extras. Optional.
	Extras     *txparam.Extras
	Passphrase *ports.Secret
}

// ClaimResult is what happened. Nothing in it is secret.
type ClaimResult struct {
	txflow.Result
	Withdrawn   chain.Lovelace
	Destination string
	// Handle is set when the destination was an ADA Handle: the handle and the
	// address it resolved to, both (ADR 0006).
	Handle *HandleDestination
	Payer  string
	Source chain.Source
}

// Run claims the rewards.
//
// A body that cannot be built is an error: upstream goes on to sign and
// submit the body an earlier run left behind (SPO-01claimRewards-PRE-009,
// hazard H2). Here the body is a value built once and never read from disk.
//
// spec: SPO-01claimRewards-IF-001, SPO-01claimRewards-IF-002, SPO-01claimRewards-IF-003, SPO-01claimRewards-IF-005,
// spec: SPO-01claimRewards-PRE-001, SPO-01claimRewards-IN-001, SPO-01claimRewards-PRE-002, SPO-01claimRewards-PRE-003,
// spec: SPO-01claimRewards-IN-002, SPO-01claimRewards-PRE-004, SPO-01claimRewards-PRE-005, SPO-01claimRewards-PRE-006,
// spec: SPO-01claimRewards-INV-001, SPO-01claimRewards-INV-002, SPO-01claimRewards-OUT-001, SPO-01claimRewards-OUT-002,
// spec: SPO-01claimRewards-PRE-007, SPO-01claimRewards-INV-003, SPO-01claimRewards-INV-004, SPO-01claimRewards-PRE-008,
// spec: SPO-01claimRewards-PRE-009, SPO-01claimRewards-INV-005, SPO-01claimRewards-PR-001, SPO-01claimRewards-OUT-003,
// spec: SPO-01claimRewards-MODE-001, SPO-01claimRewards-MODE-002
func (uc ClaimRewards) Run(ctx context.Context, req ClaimRequest) (ClaimResult, error) {
	if (uc.Submitter == nil) == (uc.Queue == nil) {
		return ClaimResult{}, fmt.Errorf("%w: exactly one of Submitter and Queue must be set", ErrMisconfigured)
	}
	if uc.Rewards == nil {
		return ClaimResult{}, ErrNoRewardReader
	}
	if req.Stake == "" || req.Destination == "" {
		return ClaimResult{}, errors.New("a claim needs a stake account and a destination")
	}
	if err := txbuild.ValidateMessage(req.Message); err != nil {
		return ClaimResult{}, err
	}
	// The extra parameters are resolved before any file or network access:
	// the metadata files are read and the message is encrypted.
	meta, err := txflow.ResolveExtras(txflow.ExtrasPorts{Files: uc.Files, Encrypter: uc.Encrypter}, req.Extras, req.Message, req.Passphrase)
	if err != nil {
		return ClaimResult{}, err
	}
	// The stake name always ends in `.staking` upstream, so `w` and
	// `w.staking` are the same account; the artefacts are kept under `w`.
	sn := strings.TrimSuffix(strings.TrimPrefix(req.Stake, "./"), ".staking")
	if sn == "" || strings.ContainsAny(sn, "/\\") {
		return ClaimResult{}, fmt.Errorf("stake account: %w: %q", ErrBadDestination, req.Stake)
	}

	var stakeAddr chain.StakeAddress
	var stakeKey, payKey custody.KeyRef
	var dst, pay resolved
	destWasName := false
	if err := uc.Store.View(ctx, func(r ports.NamedReader) error {
		b, err := r.Get(ports.NamedRef{Name: sn, Kind: ports.StakingAddr})
		if errors.Is(err, ports.ErrNotFound) {
			return fmt.Errorf("%w: %s.staking.addr", ErrNoStakeAddress, sn)
		}
		if err != nil {
			return err
		}
		stakeAddr = chain.StakeAddress(strings.TrimSpace(firstLineOf(b)))
		var held bool
		stakeKey, held, err = keyring.ResolveHeld(r, custody.RoleStake, sn)
		if err != nil {
			return err
		}
		if !held {
			return fmt.Errorf("%w: %s", ErrNoStakeKey, sn)
		}
		// The destination follows the grammar of 01_sendLovelaces.
		dst, err = SendLovelaces{Addresses: uc.Addresses, Handles: uc.Handles}.resolveDestination(r, req.Destination)
		if err != nil {
			return err
		}
		if name, nerr := normalizeName(req.Destination); nerr == nil {
			if _, ok, err := readAddress(r, name); err != nil {
				return err
			} else if ok {
				destWasName = true
			}
		}
		// The fee payer: given, else the destination when it is a stored name.
		switch {
		case req.Payer != "":
			pn, err := normalizeName(req.Payer)
			if err != nil {
				return fmt.Errorf("fee payer: %w", err)
			}
			addr, ok, err := readAddress(r, pn)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("%w: %s.addr", ErrNoSourceAddress, pn)
			}
			pay = resolved{name: pn, addr: addr}
		case destWasName:
			pay = dst
		default:
			return ErrNoFeePayer
		}
		payKey, held, err = keyring.ResolveHeld(r, custody.RolePayment, pay.name)
		if err != nil {
			return err
		}
		if !held {
			return fmt.Errorf("%w: %s", ErrNoSigningKey, pay.name)
		}
		return nil
	}); err != nil {
		return ClaimResult{}, err
	}
	// An ADA Handle destination is resolved and verified here, outside the store
	// view, and shown as the handle and its address (ADR 0006). A handle names no
	// stored payer: the fee payer must be given (SPO-01claimRewards-PRE-001).
	if dst, err = resolveHandle(ctx, uc.Handles, dst); err != nil {
		return ClaimResult{}, err
	}

	// Addresses.
	sInfo, err := uc.Addresses.InspectAddress(chain.Address(stakeAddr))
	if err != nil || sInfo.Kind != ports.AddrReward || sInfo.StakeKeyHash == nil || sInfo.NetworkID != uc.NetworkID {
		return ClaimResult{}, fmt.Errorf("%w: %s", ErrNotStakeAddress, stakeAddr)
	}
	pInfo, err := uc.Addresses.InspectAddress(pay.addr)
	if err != nil {
		return ClaimResult{}, fmt.Errorf("fee payer address: %w", err)
	}
	if !pInfo.Kind.IsPayment() || pInfo.PaymentKeyHash == nil {
		return ClaimResult{}, fmt.Errorf("%w: %s", ErrSourceNotKey, pay.name)
	}
	if pInfo.NetworkID != uc.NetworkID {
		return ClaimResult{}, fmt.Errorf("%w: the fee payer %s", ErrNetworkMismatch, pay.name)
	}
	dInfo, err := uc.Addresses.InspectAddress(dst.addr)
	if err != nil || !dInfo.Kind.IsPayment() {
		return ClaimResult{}, fmt.Errorf("%w: %s", ErrBadDestination, dst.name)
	}
	if dInfo.NetworkID != uc.NetworkID {
		return ClaimResult{}, fmt.Errorf("%w: the destination %s", ErrNetworkMismatch, dst.name)
	}

	stakeHash := stake.KeyHash(*sInfo.StakeKeyHash)
	pipe := txflow.Pipeline{Signers: uc.Signers, Min: uc.Min, Fees: uc.Fees, Bodies: uc.Bodies, Assembler: uc.Assembler,
		Confirmer: uc.Confirmer, Submitter: uc.Submitter, Queue: uc.Queue, Approval: txflow.ApprovalPolicy(uc.Approval),
		Canonicalizer: uc.Canonicalizer}
	slots := []txflow.Slot{
		{Label: "payment", Key: payKey, Hash: *pInfo.PaymentKeyHash},
		{Label: "stake", Key: stakeKey, Hash: txbuild.KeyHash(stakeHash)},
	}
	// A hardware holder the plan cannot serve, and a hardware key mixed with a
	// key-file key (SPO-Ptx-PRE-006), are refused before anything is read from the chain.
	probe := txbuild.Draft{Withdrawals: []txbuild.Withdrawal{{Reward: stakeAddr, Credential: stakeHash, Amount: 1}}, Message: req.Message}
	if _, err := pipe.PrepareWith(probe, slots, stake.StakeWitnesses, txflow.PrepareOptions{RefuseMixed: true}); err != nil {
		return ClaimResult{}, mapPipelineErr(err)
	}

	// Parameters before the reward state (SPO-01claimRewards-INV-010).
	params, err := uc.Params.ProtocolParameters(ctx)
	if err != nil {
		return ClaimResult{}, fmt.Errorf("protocol parameters: %w", err)
	}
	if params.ProtocolMajor < 7 {
		return ClaimResult{}, ErrProtocolTooOld
	}
	tip, err := uc.Tip.Tip(ctx)
	if err != nil {
		return ClaimResult{}, fmt.Errorf("current slot: %w", err)
	}
	ttl, err := txbuild.TTL(tip, uc.DefTTL)
	if err != nil {
		return ClaimResult{}, err
	}

	// The reward state, in the order upstream checks it. An unknown answer
	// and a failing provider are errors, never "not registered" or "no
	// rewards" (hazard H1, SPO-01claimRewards-MODE-001, MODE-002).
	rr, err := uc.Rewards.RewardAccount(ctx, stakeAddr)
	if err != nil {
		return ClaimResult{}, fmt.Errorf("the reward state from %s: %w", uc.Rewards.Source(), err)
	}
	if rr.IsUnknown() {
		return ClaimResult{}, fmt.Errorf("%w: %s: %s", ErrRewardUnknown, uc.Rewards.Source(), rr.Why())
	}
	if rr.IsNone() {
		return ClaimResult{}, fmt.Errorf("%w: %s", ErrStakeNotRegistered, stakeAddr)
	}
	acct, _ := rr.Get()
	if params.ProtocolMajor >= 10 {
		switch {
		case acct.VoteDelegation.IsUnknown():
			return ClaimResult{}, fmt.Errorf("%w: the vote delegation was not stated by %s: %s", ErrRewardUnknown, uc.Rewards.Source(), acct.VoteDelegation.Why())
		default:
			if v, ok := acct.VoteDelegation.Get(); !ok || !stake.HasVoteDelegation(v) {
				return ClaimResult{}, ErrNoVoteDelegation
			}
		}
	}
	if acct.Withdrawable == 0 {
		return ClaimResult{}, ErrNoRewards
	}

	// Inputs of the fee payer.
	utxos, err := uc.Utxos.Utxos(ctx, pay.addr)
	if err != nil {
		return ClaimResult{}, fmt.Errorf("the UTxOs of %s: %w", pay.name, err)
	}
	strategy := uc.Selection
	if strategy == "" {
		strategy = txbuild.SelectAll
	}
	inputs, err := strategy.Select(utxos)
	if err != nil {
		return ClaimResult{}, fmt.Errorf("%s: %w", pay.name, err)
	}
	draft, err := txbuild.NewClaimDraft(pay.addr, dst.addr, inputs,
		txbuild.Withdrawal{Reward: stakeAddr, Credential: stakeHash, Amount: acct.Withdrawable}, req.Message)
	if err != nil {
		return ClaimResult{}, err
	}
	if req.Extras != nil {
		if draft, err = meta.Attach(draft); err != nil {
			return ClaimResult{}, err
		}
	}
	prep, err := pipe.PrepareWith(draft, slots, stake.StakeWitnesses, txflow.PrepareOptions{RefuseMixed: true})
	if err != nil {
		return ClaimResult{}, mapPipelineErr(err)
	}

	res, err := pipe.Execute(ctx, txflow.Input{
		Draft: draft, Params: params, TTL: ttl, Prepared: prep, Witnesses: stake.StakeWitnesses,
		HardwareChangeKeys: hardwareChangeKeys(ctx, uc.Store, pay.name, slots[0].Key),
		Summary: ports.TxSummary{Kind: "rewards withdrawal", Source: pay.name, SourceAddr: pay.addr, Destination: dst.name, DestAddr: dst.addr,
			Amount: fmt.Sprintf("%d", acct.Withdrawable), Account: sn, StakeAddr: stakeAddr, Withdrawal: acct.Withdrawable,
			Attachments: draft.AttachmentLines(), Sources: []chain.Source{uc.Rewards.Source()}},
		Queued: ports.QueuedTx{Type: "Withdrawal", FromName: pay.name, FromAddr: pay.addr, ToName: dst.name, ToAddr: dst.addr,
			Description: fmt.Sprintf("signed rewards withdrawal from '%s.staking' to '%s', payment via '%s'", sn, dst.name, pay.name),
			Extra:       []ports.QueuedField{{Key: "stakeAddr", Value: sn + ".staking"}, {Key: "stakingAddr", Value: string(stakeAddr)}}},
	})
	if err != nil {
		return ClaimResult{}, mapPipelineErr(err)
	}
	return ClaimResult{Result: res, Withdrawn: acct.Withdrawable, Destination: dst.name, Handle: dst.handle, Payer: pay.name, Source: uc.Rewards.Source()}, nil
}

// mapPipelineErr gives the pipeline's refusals the names this package
// already uses, so errors.Is works for callers of either.
func mapPipelineErr(err error) error {
	switch {
	case errors.Is(err, txflow.ErrDeclined):
		return ErrDeclined
	case errors.Is(err, txflow.ErrNoConfirmer):
		return ErrNoConfirmer
	case errors.Is(err, txflow.ErrNoSigner):
		return ErrNoSigner
	}
	return err
}

func firstLineOf(b []byte) string {
	line, _, _ := strings.Cut(string(b), "\n")
	return line
}
