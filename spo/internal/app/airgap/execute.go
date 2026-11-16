package airgap

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/transfer"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals of ExecuteTx. Where upstream ends with exit 0 (a failed query, a
// failed light-mode submit, an unknown type, a declined prompt) these are
// errors (hazard H3); the caller decides what a decline means to its caller.
var (
	// ErrPosition: the position is not an integer from 1 to the queue length
	// (SPO-01workOffline-PRE-010).
	ErrPosition = errors.New("the queue position is out of range")
	// ErrUnknownType: the entry's type has no executor; nothing is submitted
	// and the entry stays (SPO-01workOffline-INV-006, SPO-Ptransfer-INV-001).
	ErrUnknownType = errors.New("unknown transaction type")
	// ErrDeclined: the operator did not approve. Nothing was submitted and
	// the file is unchanged (SPO-01workOffline-PR-001).
	ErrDeclined = errors.New("the transaction was not approved")
	// ErrNoConfirmer: confirmation is required and no confirmer is wired.
	ErrNoConfirmer = errors.New("the transaction needs confirmation and no confirmer is configured; set the approval policy explicitly to skip it")
	// ErrChecksUnavailable: the pool registration checks need ports the
	// composition did not wire, and are not silently skipped.
	ErrChecksUnavailable = errors.New("a pool registration needs the metadata download and hash check, and they are not wired")
	// ErrTickerProtected: the ticker service refused the ticker
	// (SPO-01workOffline-EXT-009).
	ErrTickerProtected = errors.New("the ticker is protected by the ticker-protection service")
	// ErrMetadataMismatch: the published metadata does not hash to the hash
	// the registration used (SPO-01workOffline-EXT-010).
	ErrMetadataMismatch = errors.New("the published pool metadata does not match the registered metadata hash")
	// ErrRecordFailed: the transaction WAS submitted but the bundle could not
	// record it. The error carries the transaction id; the entry is still in
	// the queue and must be cleared by hand, not submitted again.
	ErrRecordFailed = errors.New("the transaction was submitted but the transfer file could not be updated")
)

// UnknownTypeError names the type of an entry that cannot be executed.
type UnknownTypeError struct{ Type string }

func (e *UnknownTypeError) Error() string {
	return fmt.Sprintf("%v %q: nothing was submitted and the entry stays in the queue", ErrUnknownType, e.Type)
}
func (e *UnknownTypeError) Unwrap() error { return ErrUnknownType }

// ExecuteTx submits a queued transaction from the online machine (upstream
// `01_workOffline execute [n]`): it checks that the snapshot the transaction
// was built from still holds, shows the entry, asks for approval, submits,
// and then records the submit in the bundle (the paying address is marked
// used, a history entry is appended, the entry is removed).
//
// It handles one entry per run. The entry is found again by its signed
// transaction when the bundle is updated, not by its position: the position
// shifts, and a second writer may have changed the queue.
type ExecuteTx struct {
	Bundle ports.BundleStore
	// Submitter sends the transaction; nil in offline mode, which refuses
	// (SPO-01workOffline-PRE-001).
	Submitter ports.TxSubmitter
	// Utxos re-reads the paying address (SPO-01workOffline-EXT-007); Rewards
	// re-reads the stake address of a withdrawal (SPO-01workOffline-EXT-008).
	Utxos   ports.UtxoReader
	Rewards ports.RewardAccountReader
	// Sync is optional (SPO-01workOffline-PRE-002).
	Sync ports.SyncChecker
	// Confirmer asks the operator. The approval policy decides whether it is
	// asked.
	Confirmer ports.ExecuteConfirmer
	Approval  ApprovalPolicy
	Clock     ports.Clock
	// OnlineCLI is the local cardano-cli version, compared with the version
	// the offline machine signed with (a warning only,
	// SPO-01workOffline-PRE-011).
	OnlineCLI string
	// TxIDs computes the id shown in the confirmation; optional.
	TxIDs ports.TxIDCalculator
	// Pool registrations: the published metadata is downloaded and hashed
	// (SPO-01workOffline-EXT-010) and the ticker is checked
	// (SPO-01workOffline-EXT-009). The registration protection key is never
	// sent to the ticker service (hazard H6), so the service sees only the
	// ticker.
	Metadata ports.MetadataFetcher
	Hasher   ports.PoolMetadataHasher
	Tickers  ports.TickerProtectionChecker
	// Assets is told of a submitted mint or burn whose entry carried an asset
	// record update; optional. The update also goes into the history of the
	// bundle, whether or not a hook is wired.
	Assets ports.AssetUpdateHook
}

// ExecuteResult says what happened. Nothing in it is secret.
type ExecuteResult struct {
	// Empty is true when the queue was empty: nothing to do, not an error
	// (SPO-01workOffline-PRE-009).
	Empty     bool
	Entry     transfer.QueuedEntry
	TxID      chain.TxID
	Submitted bool
	// Remaining is the number of entries left in the queue.
	Remaining int
	// ApprovalSkipped is true when the confirmation was skipped by policy:
	// the audited replacement of an environment switch that upstream ignores.
	ApprovalSkipped bool
	Warnings        []string
	// Notices are advice after a successful submit (SPO-01workOffline-OUT-017).
	Notices []string
	// Checked and Unchecked say which live checks were made.
	Checked   []string
	Unchecked []string
}

// Run executes the transaction at the 1-based position.
//
// spec: SPO-01workOffline-IF-003, SPO-01workOffline-PRE-001, SPO-01workOffline-PRE-002, SPO-01workOffline-PRE-009,
// spec: SPO-01workOffline-PRE-010, SPO-01workOffline-PRE-011, SPO-01workOffline-PRE-012, SPO-01workOffline-PRE-013,
// spec: SPO-01workOffline-OUT-015, SPO-01workOffline-OUT-016, SPO-01workOffline-OUT-017, SPO-01workOffline-INV-006,
// spec: SPO-01workOffline-INV-007, SPO-01workOffline-INV-008, SPO-01workOffline-EXT-007, SPO-01workOffline-EXT-008,
// spec: SPO-01workOffline-EXT-009, SPO-01workOffline-EXT-010, SPO-01workOffline-EXT-011, SPO-01workOffline-PR-001,
// spec: SPO-01workOffline-SEC-002, SPO-01workOffline-SEC-003, SPO-01workOffline-MODE-003, SPO-Ptransfer-IF-002,
// spec: SPO-Ptransfer-PRE-002, SPO-Ptransfer-PRE-003, SPO-Ptransfer-PRE-004, SPO-Ptransfer-PRE-005, SPO-Ptransfer-PRE-006,
// spec: SPO-Ptransfer-PR-001, SPO-Ptransfer-EXT-001, SPO-Ptransfer-OUT-014, SPO-Ptransfer-INV-001
func (uc ExecuteTx) Run(ctx context.Context, position int) (ExecuteResult, error) {
	if uc.Bundle == nil {
		return ExecuteResult{}, fmt.Errorf("%w: a bundle is needed", ErrMisconfigured)
	}
	if uc.Submitter == nil {
		return ExecuteResult{}, ErrNoChain
	}
	if err := checkSync(ctx, uc.Sync); err != nil {
		return ExecuteResult{}, err
	}
	b, _, err := uc.Bundle.ReadBundle(ctx)
	if err != nil {
		return ExecuteResult{}, err
	}
	queue, err := b.Queue()
	if err != nil {
		return ExecuteResult{}, err
	}
	// An empty queue is not an error, and is answered before the position is
	// looked at (SPO-01workOffline-PRE-009).
	if len(queue) == 0 {
		return ExecuteResult{Empty: true}, nil
	}
	if position < 1 || position > len(queue) {
		return ExecuteResult{}, fmt.Errorf("%w: %d of %d", ErrPosition, position, len(queue))
	}
	entry := queue[position-1]
	res := ExecuteResult{Entry: entry, Remaining: len(queue)}

	// A difference of tool versions only warns (SPO-Ptransfer-PRE-002).
	if info, err := b.Info(); err == nil && uc.OnlineCLI != "" && info.OfflineCLI != "" && info.OfflineCLI != uc.OnlineCLI {
		res.Warnings = append(res.Warnings, fmt.Sprintf("the transaction was signed with cardano-cli %s, this machine has %s", info.OfflineCLI, uc.OnlineCLI))
	}
	res.Unchecked = append(res.Unchecked, "the era of the chain was not compared with the entry's era ("+entry.Era+")")

	// The type must have an executor (SPO-01workOffline-INV-006).
	if !transfer.Executable(entry.Type) {
		return res, &UnknownTypeError{Type: entry.Type}
	}
	txBytes, err := entry.TxBytes()
	if err != nil {
		return res, err
	}

	// Live checks: the paying address still has the UTxOs the transaction
	// was built from. Compared structurally, not as text (SPO-Ptransfer-PRE-004).
	if uc.Utxos == nil {
		return res, ErrNoChain
	}
	stored, err := b.StoredUtxos(entry.FromAddr)
	if err != nil {
		return res, err
	}
	live, err := uc.Utxos.Utxos(ctx, chain.Address(entry.FromAddr))
	if err != nil {
		return res, fmt.Errorf("the UTxOs of the paying address from %s: %w", uc.Utxos.Source(), err)
	}
	if err := transfer.SameUtxoSet(stored, live); err != nil {
		return res, err
	}
	res.Checked = append(res.Checked, "the UTxOs of "+entry.FromName+" are as in the snapshot ("+string(uc.Utxos.Source())+")")

	if entry.Type == transfer.TypeWithdrawal {
		if uc.Rewards == nil {
			return res, ErrNoChain
		}
		sr, err := b.StoredRewardState(entry.StakingAddr)
		if err != nil {
			return res, err
		}
		rd, err := uc.Rewards.RewardAccount(ctx, chain.StakeAddress(entry.StakingAddr))
		if err != nil {
			return res, fmt.Errorf("the reward state from %s: %w", uc.Rewards.Source(), err)
		}
		if err := transfer.SameRewards(sr, rd); err != nil {
			return res, err
		}
		res.Checked = append(res.Checked, "the rewards of "+entry.StakeName+" are as in the snapshot ("+string(uc.Rewards.Source())+")")
	}

	// Pool registrations: refused here, before the confirmation, when the
	// ticker is protected or the published metadata does not match
	// (SPO-01workOffline-PRE-012).
	if transfer.IsPoolRegistration(entry.Type) {
		if err := uc.poolChecks(ctx, entry, &res); err != nil {
			return res, err
		}
	}

	// The confirmation (SPO-01workOffline-PR-001). The summary shows the
	// entry's claims and says they are claims.
	summary := ports.ExecuteSummary{Entry: entry, Warnings: res.Warnings, Checked: res.Checked,
		Unchecked: append(append([]string(nil), res.Unchecked...), "the descriptive fields are the file writer's claim and are not compared with the signed transaction")}
	if uc.Submitter != nil {
		summary.Source = uc.Submitter.Source()
	}
	if uc.TxIDs != nil {
		if id, err := uc.TxIDs.TransactionID(txBytes); err == nil {
			summary.TxID = id.String()
		}
	}
	switch uc.Approval {
	case ApprovalSkip:
		res.ApprovalSkipped = true
	default:
		if uc.Confirmer == nil {
			return res, ErrNoConfirmer
		}
		ok, err := uc.Confirmer.ConfirmExecute(ctx, summary)
		if err != nil {
			return res, fmt.Errorf("confirmation: %w", err)
		}
		if !ok {
			return res, ErrDeclined
		}
	}

	// Submit. A failure leaves the queue as it was (SPO-01workOffline-EXT-011);
	// in light mode upstream exits 0 here (SPO-01workOffline-PRE-013).
	id, err := uc.Submitter.Submit(ctx, txBytes)
	if err != nil {
		return res, fmt.Errorf("submit through %s: %w", uc.Submitter.Source(), err)
	}
	res.TxID, res.Submitted = id, true

	date := now(uc.Clock)
	cbor := entry.CborHex
	if err := uc.Bundle.MutateBundle(ctx, func(nb *transfer.Bundle) error {
		return nb.CompleteSubmit(cbor, id.String(), date)
	}); err != nil {
		return res, fmt.Errorf("%w (transaction %s): %w", ErrRecordFailed, id, err)
	}
	res.Remaining--
	if entry.AssetPending != "" && uc.Assets != nil {
		// A failure here never undoes the submit: the update is in the
		// history of the file, and `spo asset settle` applies it where the
		// record is.
		if herr := uc.Assets.OnSubmittedUpdate(ctx, id, entry.AssetPending); herr != nil {
			res.Notices = append(res.Notices, fmt.Sprintf("the asset record update of transaction %s was not applied here (%v); it is in the history of the transfer file, apply it with spo asset settle where the record is", id, herr))
		} else {
			res.Notices = append(res.Notices, "the asset record update travels back in the transfer file: run spo asset settle on the machine that holds the asset record")
		}
	}
	if entry.Type == transfer.TypePoolRetirement {
		res.Notices = append(res.Notices, "do not de-register the pool's reward address yet: the pool deposit is refunded to it")
	}
	return res, nil
}

func (uc ExecuteTx) poolChecks(ctx context.Context, e transfer.QueuedEntry, res *ExecuteResult) error {
	if uc.Metadata == nil || uc.Hasher == nil {
		return ErrChecksUnavailable
	}
	if uc.Tickers != nil {
		v, err := uc.Tickers.CheckTicker(ctx, e.PoolTicker)
		switch {
		case err != nil || v == ports.TickerUnchecked:
			// An unreachable service lets the registration go on, as upstream
			// does (SPO-01workOffline-EXT-009); the result says it was not checked.
			res.Unchecked = append(res.Unchecked, "the ticker "+e.PoolTicker+" was not checked: the service did not answer")
		case v == ports.TickerProtected:
			return fmt.Errorf("%w: %s", ErrTickerProtected, e.PoolTicker)
		default:
			res.Checked = append(res.Checked, "the ticker "+e.PoolTicker+" is allowed")
		}
	} else {
		res.Unchecked = append(res.Unchecked, "the ticker "+e.PoolTicker+" was not checked: no ticker service is wired")
	}
	doc, err := uc.Metadata.Fetch(ctx, e.PoolMetaURL)
	if err != nil {
		return fmt.Errorf("download %s: %w", e.PoolMetaURL, err)
	}
	if len(doc) > pool.MaxMetadataBytes || !json.Valid(doc) {
		return fmt.Errorf("%w: %s is not a JSON document of at most %d bytes", ErrMetadataMismatch, e.PoolMetaURL, pool.MaxMetadataBytes)
	}
	h, err := uc.Hasher.MetadataHash(doc)
	if err != nil {
		return fmt.Errorf("metadata hash: %w", err)
	}
	if got := hex.EncodeToString(h[:]); !strings.EqualFold(got, e.PoolMetaHash) {
		return fmt.Errorf("%w: the file at %s hashes to %s, the registration used %s", ErrMetadataMismatch, e.PoolMetaURL, got, e.PoolMetaHash)
	}
	res.Checked = append(res.Checked, "the metadata at "+e.PoolMetaURL+" hashes to "+e.PoolMetaHash)
	return nil
}
