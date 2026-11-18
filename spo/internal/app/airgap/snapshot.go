package airgap

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/domain/transfer"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals of the snapshot use cases.
var (
	// ErrNoAddressFile: the name has no stored address.
	ErrNoAddressFile = errors.New("the name has no address file (.addr)")
	// ErrAddressType: the address is neither a payment nor a stake address
	// (SPO-01workOffline-PRE-006).
	ErrAddressType = errors.New("the address type is unknown: it is neither a payment nor a stake address")
	// ErrBadDRepID: the DRep id is not a valid bech32 DRep id
	// (SPO-01workOffline-PRE-007).
	ErrBadDRepID = errors.New("the DRep id is not valid bech32")
)

// contextReaders is what `new` and every `add` refresh: the protocol
// parameters, the era and the versions.
type contextReaders struct {
	Params   ports.ProtocolParametersReader
	Eras     ports.EraReader
	Sync     ports.SyncChecker
	Versions Versions
}

func (c contextReaders) read(ctx context.Context) (transfer.Context, chain.Source, error) {
	if c.Params == nil {
		return transfer.Context{}, "", ErrNoChain
	}
	if err := checkSync(ctx, c.Sync); err != nil {
		return transfer.Context{}, "", err
	}
	pp, err := c.Params.ProtocolParameters(ctx)
	if err != nil {
		// Upstream's check tests the wrong statement and writes a damaged
		// file (SPO-01workOffline-EXT-001 quirk); a failed query is an error.
		return transfer.Context{}, "", fmt.Errorf("the protocol parameters from %s: %w", c.Params.Source(), err)
	}
	if len(pp.Raw) == 0 {
		return transfer.Context{}, "", fmt.Errorf("the protocol parameters from %s carry no document to store", c.Params.Source())
	}
	var era string
	if c.Eras != nil {
		if era, err = c.Eras.Era(ctx); err != nil {
			return transfer.Context{}, "", fmt.Errorf("the era: %w", err)
		}
	} else if e, ok := transfer.EraFromLightDocument(pp.Raw); ok {
		era = e
	}
	if era == "" {
		return transfer.Context{}, "", ErrNoEra
	}
	return transfer.Context{OnlineCLI: c.Versions.CLI, OnlineNode: c.Versions.Node, Parameters: pp.Raw, Era: strings.ToLower(era)}, c.Params.Source(), nil
}

// NewSnapshot creates a fresh bundle with the chain context (upstream
// `01_workOffline new`): the protocol parameters, the era and the tool
// versions, and a history of one entry. Whatever was in the file is
// discarded, including addresses, queued transactions and attached files
// (SPO-Ptransfer-OUT-001); upstream asks no confirmation, so asking before
// that is the caller's business.
//
// The parameters are stored as the reader gives them (the light-mode
// document unchanged, SPO-01workOffline-EXT-002); the merge of governance
// state and era history of a full node (SPO-01workOffline-EXT-001) belongs
// to the node adapter, which does not exist yet.
type NewSnapshot struct {
	Bundle ports.BundleMutator
	// Params is nil in offline mode, which refuses (SPO-01workOffline-PRE-001).
	Params ports.ProtocolParametersReader
	// Eras is optional; without it the era comes from the light-mode document.
	Eras ports.EraReader
	// Sync is optional; a provider that is not synced refuses
	// (SPO-01workOffline-PRE-002).
	Sync     ports.SyncChecker
	Clock    ports.Clock
	Versions Versions
	// WorkMode is "online" or "light"; it appears in the history entry.
	WorkMode string
}

// SnapshotResult says what was written.
type SnapshotResult struct {
	Source chain.Source
	Era    string
	Date   string
}

// Run writes the new bundle.
//
// spec: SPO-01workOffline-OUT-004, SPO-01workOffline-OUT-005, SPO-01workOffline-EXT-002, SPO-01workOffline-PRE-001,
// spec: SPO-01workOffline-PRE-002, SPO-01workOffline-PRE-003, SPO-01workOffline-MODE-001, SPO-Ptransfer-PRE-001,
// spec: SPO-Ptransfer-OUT-001, SPO-Ptransfer-OUT-002, SPO-Ptransfer-OUT-003, SPO-Ptransfer-INV-002
func (uc NewSnapshot) Run(ctx context.Context) (SnapshotResult, error) {
	if uc.Bundle == nil || uc.WorkMode == "" {
		return SnapshotResult{}, fmt.Errorf("%w: a bundle and the work mode are needed", ErrMisconfigured)
	}
	tc, src, err := contextReaders{uc.Params, uc.Eras, uc.Sync, uc.Versions}.read(ctx)
	if err != nil {
		return SnapshotResult{}, err
	}
	date := now(uc.Clock)
	if err := uc.Bundle.MutateBundle(ctx, func(b *transfer.Bundle) error { return b.StartNew(tc, uc.WorkMode, date) }); err != nil {
		return SnapshotResult{}, err
	}
	return SnapshotResult{Source: src, Era: tc.Era, Date: date}, nil
}

// AddAddress adds the state of one stored address to the bundle (upstream
// `01_workOffline add <name>`): the UTxO set of a payment address, or the
// reward state of a registered stake address. The chain context is refreshed
// in the same write, so the whole snapshot carries the newest parameters
// (SPO-Ptransfer-OUT-004). Nothing is written until the entry is complete: a
// refusal leaves the file exactly as it was (SPO-01workOffline-INV-003). A
// bundle that does not exist is created, with no prior `new`
// (SPO-01workOffline-OUT-007).
//
// An asset-registry lookup (SPO-01workOffline-EXT-004) is not made: there is
// no registry port.
type AddAddress struct {
	Bundle ports.BundleMutator
	Store  ports.NamedStore
	// Addresses classifies the address (payment or stake).
	Addresses ports.AddressInspector
	// The chain readers; nil in offline mode, which refuses.
	Params  ports.ProtocolParametersReader
	Utxos   ports.UtxoReader
	Rewards ports.RewardAccountReader
	// Eras, Sync and Versions as in NewSnapshot.
	Eras     ports.EraReader
	Sync     ports.SyncChecker
	Clock    ports.Clock
	Versions Versions
}

// AddResult says what was stored.
type AddResult struct {
	Name    string // the name stored in the entry, as upstream's `addrName`
	Address string
	Kind    string // "payment" or "stake"
	// Total is the total lovelace of a payment address, the reward balance
	// of a stake address.
	Total       uint64
	Outputs     int
	AssetTypes  int
	Source      chain.Source
	ParamSource chain.Source
	Date        string
}

// normalizeName applies SPO-01workOffline-IF-006: a leading `./` and a
// trailing `.addr` are dropped. A directory part cannot name an artefact of
// the store and is refused.
func normalizeName(s string) (string, error) {
	s = strings.TrimSuffix(strings.TrimPrefix(s, "./"), ".addr")
	if s == "" || strings.ContainsAny(s, "/\\") {
		return "", fmt.Errorf("%w: %q", ErrNoAddressFile, s)
	}
	return s, nil
}

// Run adds the address named by name (`<name>` or `<name>.addr`; a stake
// address is `<name>.staking`).
//
// spec: SPO-01workOffline-IF-004, SPO-01workOffline-IF-006, SPO-01workOffline-IN-002, SPO-01workOffline-EXT-003,
// spec: SPO-01workOffline-EXT-005, SPO-01workOffline-OUT-006, SPO-01workOffline-OUT-007, SPO-01workOffline-OUT-008,
// spec: SPO-01workOffline-OUT-009, SPO-01workOffline-OUT-010, SPO-01workOffline-OUT-012, SPO-01workOffline-INV-001,
// spec: SPO-01workOffline-INV-003, SPO-01workOffline-PRE-004, SPO-01workOffline-PRE-005, SPO-01workOffline-PRE-006,
// spec: SPO-01workOffline-MODE-002, SPO-Ptransfer-OUT-004, SPO-Ptransfer-OUT-005, SPO-Ptransfer-OUT-006
func (uc AddAddress) Run(ctx context.Context, name string) (AddResult, error) {
	if uc.Bundle == nil || uc.Store == nil || uc.Addresses == nil {
		return AddResult{}, fmt.Errorf("%w: a bundle, a store and an address inspector are needed", ErrMisconfigured)
	}
	// The gates come before the argument checks (SPO-01workOffline-INV-001).
	tc, psrc, err := contextReaders{uc.Params, uc.Eras, uc.Sync, uc.Versions}.read(ctx)
	if err != nil {
		return AddResult{}, err
	}
	addrName, err := normalizeName(name)
	if err != nil {
		return AddResult{}, err
	}
	// `<x>.staking` names `<x>.staking.addr`: the staking address file of x.
	kind, base := ports.AddrFile, addrName
	if b, ok := strings.CutSuffix(addrName, ".staking"); ok && b != "" {
		kind, base = ports.StakingAddr, b
	}
	var addrText string
	if err := uc.Store.View(ctx, func(r ports.NamedReader) error {
		b, err := r.Get(ports.NamedRef{Name: base, Kind: kind})
		if errors.Is(err, ports.ErrNotFound) || errors.Is(err, ports.ErrInvalidRef) {
			return fmt.Errorf("%w: %s", ErrNoAddressFile, addrName)
		}
		if err != nil {
			return err
		}
		addrText = strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0])
		return nil
	}); err != nil {
		return AddResult{}, err
	}
	info, err := uc.Addresses.InspectAddress(chain.Address(addrText))
	if err != nil {
		return AddResult{}, fmt.Errorf("%w: %v", ErrAddressType, err)
	}
	date := now(uc.Clock)
	res := AddResult{Name: addrName, Address: addrText, ParamSource: psrc, Date: date}

	switch {
	case info.Kind.IsPayment():
		if uc.Utxos == nil {
			return AddResult{}, ErrNoChain
		}
		us, err := uc.Utxos.Utxos(ctx, chain.Address(addrText))
		if err != nil {
			// Upstream prints the error and exits 0 (SPO-01workOffline-PRE-004).
			return AddResult{}, fmt.Errorf("the UTxOs from %s: %w", uc.Utxos.Source(), err)
		}
		entry := transfer.PaymentEntry{Address: addrText, Name: addrName, Outputs: transfer.OutputsFromChain(us)}
		_, res.Total, res.AssetTypes = transfer.UtxoJSON(addrText, entry.Outputs)
		res.Kind, res.Outputs, res.Source = "payment", len(us), uc.Utxos.Source()
		err = uc.Bundle.MutateBundle(ctx, func(b *transfer.Bundle) error {
			if err := b.RefreshContext(tc); err != nil {
				return err
			}
			return b.PutPayment(entry, date)
		})
		return res, err

	case info.Kind == ports.AddrReward:
		if uc.Rewards == nil {
			return AddResult{}, ErrNoChain
		}
		rd, err := uc.Rewards.RewardAccount(ctx, chain.StakeAddress(addrText))
		if err != nil {
			return AddResult{}, fmt.Errorf("the stake address state from %s: %w", uc.Rewards.Source(), err)
		}
		res.Kind, res.Source = "stake", uc.Rewards.Source()
		switch acc, ok := rd.Get(); {
		case ok:
			rj, bal, err := transfer.RewardsJSON(acc)
			if err != nil {
				return AddResult{}, err
			}
			res.Total = bal
			err = uc.Bundle.MutateBundle(ctx, func(b *transfer.Bundle) error {
				if err := b.RefreshContext(tc); err != nil {
					return err
				}
				return b.PutStake(transfer.StakeEntry{Address: addrText, Name: addrName, Rewards: rj, Balance: bal}, date)
			})
			return res, err
		case rd.IsNone():
			return AddResult{}, fmt.Errorf("%w: %s", transfer.ErrNotRegistered, addrText)
		default:
			// "Unknown" is not "not registered" (hazard H1).
			return AddResult{}, fmt.Errorf("the stake address state from %s is not known: %s", uc.Rewards.Source(), rd.Why())
		}
	}
	return AddResult{}, ErrAddressType
}

// AddDRep adds the state of a DRep to the bundle (upstream
// `01_workOffline add <name>.drep`).
type AddDRep struct {
	Bundle ports.BundleMutator
	// DReps reads the registration; nil in offline mode, which refuses.
	DReps ports.DRepStateReader
	// Params, Eras, Sync and Versions as in NewSnapshot.
	Params   ports.ProtocolParametersReader
	Eras     ports.EraReader
	Sync     ports.SyncChecker
	Clock    ports.Clock
	Versions Versions
}

// Run adds the DRep with the id text given (the content of `<name>.id`) and
// the name stored with it, including its `.drep` part. An unregistered DRep
// is stored with a null deposit and `[]` (SPO-Ptransfer-OUT-007). The stored
// state is what the reader states: the credential and the deposit; the
// anchor, expiry and stake that upstream stores are not read
// (SPO-Clight-OUT-015), which the entries of `22b` and `21b` do not need.
//
// spec: SPO-01workOffline-IF-005, SPO-01workOffline-IN-002, SPO-01workOffline-PRE-007, SPO-01workOffline-EXT-006,
// spec: SPO-01workOffline-OUT-011, SPO-Ptransfer-OUT-007
func (uc AddDRep) Run(ctx context.Context, name, id string) (AddResult, error) {
	if uc.Bundle == nil {
		return AddResult{}, fmt.Errorf("%w: a bundle is needed", ErrMisconfigured)
	}
	tc, psrc, err := contextReaders{uc.Params, uc.Eras, uc.Sync, uc.Versions}.read(ctx)
	if err != nil {
		return AddResult{}, err
	}
	if uc.DReps == nil {
		return AddResult{}, ErrNoChain
	}
	id = strings.TrimSpace(id)
	w, err := stake.ParseDRepWord(id)
	if err != nil || !w.IsID {
		return AddResult{}, fmt.Errorf("%w: %q", ErrBadDRepID, id)
	}
	cid, _ := w.DRep.ChainID()
	st, err := uc.DReps.DRepState(ctx, cid)
	if err != nil {
		return AddResult{}, fmt.Errorf("the DRep state from %s: %w", uc.DReps.Source(), err)
	}
	entry, err := transfer.DRepEntryOf(id, name, cid, st)
	if err != nil {
		return AddResult{}, err
	}
	date := now(uc.Clock)
	err = uc.Bundle.MutateBundle(ctx, func(b *transfer.Bundle) error {
		if err := b.RefreshContext(tc); err != nil {
			return err
		}
		return b.PutDRep(entry, date)
	})
	res := AddResult{Name: name, Address: id, Kind: "drep", Source: uc.DReps.Source(), ParamSource: psrc, Date: date}
	if entry.Deposit != nil {
		res.Total = *entry.Deposit
	}
	return res, err
}
