// Package query holds the read-only use cases that answer a question about
// the chain or the air-gap snapshot and change nothing: the balance or reward
// state of an address (upstream 01_queryAddress) and the check of an
// operational certificate against the chain (upstream 04e_checkNodeOpCert).
// A use case returns a structured result and the caller renders it; where
// upstream exits 0 after a failed query, an error is returned (hazard H3).
package query

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/mochipool/workbench/spo/internal/app/handles"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/transfer"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals of QueryAddress.
var (
	// ErrUnresolved: the argument is no stored name, address or Handle
	// (SPO-01queryAddress-PRE-001).
	ErrUnresolved = errors.New("the argument is not the name of a stored address, an address or an ADA Handle: the address can't be resolved")
	// ErrAdaHandleUnsupported: no handle resolver is wired (QueryAddress.Handles).
	ErrAdaHandleUnsupported = errors.New("ADA Handle addresses are not supported yet; give the address or the name of a stored address")
	// ErrAddressType: the address is neither a payment nor a stake address
	// (SPO-01queryAddress-INV-001).
	ErrAddressType = errors.New("the address type is unknown: it is neither a payment nor a stake address")
	// ErrNoFunds: the payment address has no UTxO (SPO-01queryAddress-PRE-004).
	ErrNoFunds = errors.New("no funds on the address")
	// ErrNotRegistered: the stake address is not registered on the chain
	// (SPO-01queryAddress-PRE-007).
	ErrNotRegistered = errors.New("the stake address is not on the chain: register it first")
	// ErrNotInSnapshot: the offline snapshot has no entry for the address;
	// one error for the payment and the stake branch, where upstream exits 1
	// and 0 (SPO-01queryAddress-MODE-001, SPO-01queryAddress-PRE-006).
	ErrNotInSnapshot = errors.New("the address is not in the offline transfer file; include it first on the online machine")
	// ErrNoChainReader: the reader the address kind needs is not wired.
	ErrNoChainReader = errors.New("no reader for this kind of address is available in this mode")
)

var (
	handleRoot = regexp.MustCompile(`^\$[a-z0-9_.-]{1,15}$`)
	handleSub  = regexp.MustCompile(`^\$[a-z0-9_.-]{1,15}@[a-z0-9_.-]{1,15}$`)
)

// QueryAddress reads the state of an address (upstream 01_queryAddress): the
// UTxOs of a payment address with their totals, or the reward state of a
// stake address. The mode is the composition's: the readers are the node, the
// light-mode provider or, offline, the snapshot of the transfer file
// (SPO-01queryAddress-MODE-002). Nothing is written.
type QueryAddress struct {
	// Store resolves a name to its `<name>.addr` or `<name>.staking.addr`;
	// nil means only literal addresses are accepted.
	Store     ports.Store
	Addresses ports.AddressInspector
	Utxos     ports.UtxoReader
	Rewards   ports.RewardAccountReader
	// Pools adds the delegated pool's name and ticker to a stake report
	// (SPO-01queryAddress-EXT-004); optional, a failure shows nothing.
	Pools ports.PoolStateReader
	// Snapshot is set in offline mode: the report then carries the date of
	// the snapshot and its `used` flag, since the data may be stale (the
	// port note of 01_queryAddress).
	Snapshot ports.BundleReader
	// Sync is set in the full online mode: a payment query needs a synced
	// node (SPO-01queryAddress-PRE-002). The light mode has no sync check.
	Sync ports.SyncChecker
	// Handles resolves an ADA Handle argument to the address that holds it,
	// verified against the chain (satisfied by handles.Resolver). Nil keeps the
	// refusal with ErrAdaHandleUnsupported.
	Handles HandleResolver
}

// HandleResolver resolves an ADA Handle (handles.Resolver).
type HandleResolver interface {
	Resolve(ctx context.Context, text string) (handles.Resolved, error)
}

// ErrHandleUnverified: the resolver answered an address it did not verify; a
// wrong address is harmful (ADR 0006), so it is refused.
var ErrHandleUnverified = errors.New("the ADA Handle resolution was not verified against the chain; refusing it")

// ResolvedHandle is shown beside the address of a report for a handle: the
// handle and the address it resolved to are both visible (ADR 0006).
type ResolvedHandle struct {
	Handle     string
	Kind       string
	VerifiedBy string
}

// AssetLine is one asset of an output.
type AssetLine struct {
	Policy   string // hex
	NameHex  string
	NameText string // the name when it is printable text, else empty
	Quantity uint64
}

// UtxoLine is one output.
type UtxoLine struct {
	Ref          string // <txhash>#<index>
	Lovelace     chain.Lovelace
	Assets       []AssetLine
	DatumHash    string
	HasDatumHash bool
}

// AssetTotal is the total of one asset over all outputs
// (SPO-01queryAddress-OUT-001).
type AssetTotal struct {
	Policy, NameHex, NameText string
	Fingerprint               string // CIP-14
	Quantity                  uint64
}

// AddressReport is the read model.
type AddressReport struct {
	// Kind is "payment" or "stake".
	Kind string
	// Name is the stored name, empty for a literal address.
	Name    string
	Address string
	Source  chain.Source
	// Handle is set when the argument was an ADA Handle; Name is then the
	// handle and Address the address it resolved to.
	Handle *ResolvedHandle

	// Payment: the outputs in the order of the reader, the lovelace total and
	// the asset totals ordered by policy and name.
	Utxos         []UtxoLine
	TotalLovelace chain.Lovelace
	Assets        []AssetTotal

	// Stake: registered accounts only; unregistered is an error.
	Deposit        chain.Reading[chain.Lovelace]
	Rewards        chain.Lovelace
	Pool           chain.Reading[chain.PoolID]
	PoolInfo       chain.Reading[chain.PoolState]
	VoteDelegation chain.Reading[string]
	GovDeposits    chain.Reading[[]chain.GovActionDeposit]

	// Offline: the snapshot's date and whether a queued transaction from or
	// to the address was executed since (advisory).
	FromSnapshot bool
	SnapshotDate string
	SnapshotUsed bool
}

// Run resolves the word and reads the address. A word is a stored name when
// `<name>.addr` is stored, else a literal address of the payment or stake
// kind, else an ADA Handle, which is resolved by Handles (refused with
// ErrAdaHandleUnsupported when none is wired).
//
// spec: SPO-01queryAddress-IF-002, SPO-01queryAddress-IN-001, SPO-01queryAddress-IN-002, SPO-01queryAddress-IN-004,
// spec: SPO-01queryAddress-PRE-001, SPO-01queryAddress-INV-001, SPO-01queryAddress-EXT-001, SPO-01queryAddress-EXT-003,
// spec: SPO-01queryAddress-PRE-003, SPO-01queryAddress-PRE-004, SPO-01queryAddress-PRE-005, SPO-01queryAddress-PRE-006,
// spec: SPO-01queryAddress-PRE-007, SPO-01queryAddress-MODE-001, SPO-01queryAddress-MODE-002, SPO-01queryAddress-IN-006,
// spec: SPO-01queryAddress-OUT-001, SPO-01queryAddress-OUT-002, SPO-01queryAddress-OUT-003, SPO-01queryAddress-OUT-004,
// spec: SPO-01queryAddress-EXT-004, SPO-01queryAddress-SEC-001
func (uc QueryAddress) Run(ctx context.Context, word string) (AddressReport, error) {
	word = strings.TrimSpace(word)
	if word == "" || uc.Addresses == nil {
		return AddressReport{}, errors.New("an address query needs a stored name, an address or an ADA Handle")
	}
	name, addr, rh, err := uc.resolve(ctx, word)
	if err != nil {
		return AddressReport{}, err
	}
	info, err := uc.Addresses.InspectAddress(chain.Address(addr))
	if err != nil {
		return AddressReport{}, fmt.Errorf("%w: %v", ErrAddressType, err)
	}
	rep := AddressReport{Name: name, Address: addr, Handle: rh}
	switch {
	case info.Kind.IsPayment():
		err = uc.payment(ctx, &rep)
	case info.Kind == ports.AddrReward:
		err = uc.stake(ctx, &rep)
	default:
		return AddressReport{}, ErrAddressType
	}
	if err != nil {
		return AddressReport{}, err
	}
	if uc.Snapshot != nil {
		uc.annotate(ctx, &rep)
	}
	return rep, nil
}

// resolve follows SPO-01queryAddress-IN-004 and IN-005.
func (uc QueryAddress) resolve(ctx context.Context, word string) (name, addr string, rh *ResolvedHandle, err error) {
	n := strings.TrimSuffix(strings.TrimPrefix(word, "./"), ".addr")
	if uc.Store != nil && n != "" && !strings.ContainsAny(n, "/\\") {
		kind, base := ports.AddrFile, n
		if b, ok := strings.CutSuffix(n, ".staking"); ok && b != "" {
			kind, base = ports.StakingAddr, b
		}
		found := false
		verr := uc.Store.View(ctx, func(r ports.Reader) error {
			b, gerr := r.Get(ports.Ref{Name: base, Kind: kind})
			if errors.Is(gerr, ports.ErrNotFound) || errors.Is(gerr, ports.ErrInvalidRef) {
				return nil
			}
			if gerr != nil {
				return gerr
			}
			// SPO-01queryAddress-IN-001: the whole content, trailing newlines trimmed.
			addr, found = strings.TrimRight(string(b), "\r\n"), true
			return nil
		})
		if verr != nil {
			return "", "", nil, verr
		}
		if found {
			return n, strings.TrimSpace(addr), nil, nil
		}
	}
	if info, ierr := uc.Addresses.InspectAddress(chain.Address(word)); ierr == nil && (info.Kind.IsPayment() || info.Kind == ports.AddrReward) {
		return "", word, nil, nil
	}
	if handleRoot.MatchString(strings.ToLower(word)) || handleSub.MatchString(strings.ToLower(word)) {
		return uc.resolveHandle(ctx, strings.ToLower(word))
	}
	return "", "", nil, fmt.Errorf("%w: %q", ErrUnresolved, word)
}

// resolveHandle resolves an ADA Handle and shows it with the address it
// resolved to. An unverified answer is refused.
//
// spec: SPO-01queryAddress-IN-005, SPO-Caddr-IF-001, SPO-Caddr-IF-002
func (uc QueryAddress) resolveHandle(ctx context.Context, h string) (string, string, *ResolvedHandle, error) {
	if uc.Handles == nil {
		return "", "", nil, ErrAdaHandleUnsupported
	}
	res, err := uc.Handles.Resolve(ctx, h)
	if err != nil {
		return "", "", nil, fmt.Errorf("the ADA Handle %s: %w", h, err)
	}
	if res.Address == "" || res.VerifiedBy == "" {
		return "", "", nil, fmt.Errorf("%w: %s", ErrHandleUnverified, h)
	}
	return h, string(res.Address), &ResolvedHandle{Handle: h, Kind: string(res.Kind), VerifiedBy: res.VerifiedBy}, nil
}

func (uc QueryAddress) payment(ctx context.Context, rep *AddressReport) error {
	if uc.Utxos == nil {
		return fmt.Errorf("%w: payment addresses", ErrNoChainReader)
	}
	rep.Kind, rep.Source = "payment", uc.Utxos.Source()
	if uc.Sync != nil {
		ok, err := uc.Sync.Synced(ctx)
		if err != nil {
			return fmt.Errorf("the sync state from %s: %w", uc.Sync.Source(), err)
		}
		if !ok {
			return fmt.Errorf("%w: %s", ErrNotSynced, uc.Sync.Source())
		}
	}
	us, err := uc.Utxos.Utxos(ctx, chain.Address(rep.Address))
	if err != nil {
		if errors.Is(err, transfer.ErrAddressNotInBundle) {
			return fmt.Errorf("%w: %s", ErrNotInSnapshot, rep.Address)
		}
		return fmt.Errorf("the UTxOs from %s: %w", rep.Source, err)
	}
	if len(us) == 0 {
		return ErrNoFunds
	}
	totals := map[string]uint64{}
	ids := map[string]chain.AssetID{}
	for _, u := range us {
		line := UtxoLine{Ref: fmt.Sprintf("%s#%d", u.TxID, u.Index), Lovelace: u.Lovelace, DatumHash: u.DatumHash, HasDatumHash: u.HasDatumHash}
		rep.TotalLovelace += u.Lovelace
		for _, a := range u.Assets {
			line.Assets = append(line.Assets, AssetLine{Policy: hex.EncodeToString(a.Asset.Policy[:]), NameHex: hex.EncodeToString(a.Asset.Name),
				NameText: readable(a.Asset.Name), Quantity: a.Quantity})
			k := hex.EncodeToString(a.Asset.Policy[:]) + "." + hex.EncodeToString(a.Asset.Name)
			totals[k] += a.Quantity
			ids[k] = a.Asset
		}
		rep.Utxos = append(rep.Utxos, line)
	}
	for k, q := range totals {
		id := ids[k]
		pol := hex.EncodeToString(id.Policy[:])
		rep.Assets = append(rep.Assets, AssetTotal{Policy: pol, NameHex: hex.EncodeToString(id.Name), NameText: readable(id.Name),
			Fingerprint: chain.AssetFingerprint(id), Quantity: q})
	}
	sort.Slice(rep.Assets, func(i, j int) bool {
		a, b := rep.Assets[i], rep.Assets[j]
		return a.Policy < b.Policy || (a.Policy == b.Policy && a.NameHex < b.NameHex)
	})
	return nil
}

func (uc QueryAddress) stake(ctx context.Context, rep *AddressReport) error {
	if uc.Rewards == nil {
		return fmt.Errorf("%w: stake addresses", ErrNoChainReader)
	}
	rep.Kind, rep.Source = "stake", uc.Rewards.Source()
	rd, err := uc.Rewards.RewardAccount(ctx, chain.StakeAddress(rep.Address))
	if err != nil {
		return fmt.Errorf("the stake address state from %s: %w", rep.Source, err)
	}
	switch {
	case rd.IsUnknown():
		// An address with no snapshot entry is Unknown for the file reader;
		// that is "not included", not "not registered".
		if uc.Snapshot != nil {
			return fmt.Errorf("%w: %s", ErrNotInSnapshot, rd.Why())
		}
		return fmt.Errorf("the stake address state from %s is not known: %s", rep.Source, rd.Why())
	case rd.IsNone():
		return ErrNotRegistered
	}
	acc, _ := rd.Get()
	rep.Deposit, rep.Rewards, rep.Pool, rep.VoteDelegation, rep.GovDeposits = acc.Deposit, acc.Withdrawable, acc.DelegatedPool, acc.VoteDelegation, acc.GovActionDeposits
	if pid, ok := acc.DelegatedPool.Get(); ok && uc.Pools != nil && uc.Snapshot == nil {
		if pr, perr := uc.Pools.PoolState(ctx, pid); perr == nil {
			rep.PoolInfo = pr
		}
	}
	return nil
}

func (uc QueryAddress) annotate(ctx context.Context, rep *AddressReport) {
	b, found, err := uc.Snapshot.ReadBundle(ctx)
	if err != nil || !found {
		return
	}
	info, err := b.Info()
	if err != nil {
		return
	}
	for _, a := range info.Addresses {
		if a.Key == rep.Address {
			rep.FromSnapshot, rep.SnapshotDate, rep.SnapshotUsed = true, a.Date, a.Used
		}
	}
}

// readable gives a name when it is printable UTF-8 text (SPO-Cconv-OUT-016).
func readable(name []byte) string {
	if len(name) == 0 || !utf8.Valid(name) {
		return ""
	}
	for _, r := range string(name) {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	return string(name)
}
