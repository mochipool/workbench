package stake

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	stk "github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// CheckStakeAddress reports the on-chain status of a stake address
// (upstream 03c): a read model, no artefact is written. The caller decides
// what an unregistered account means to its own caller (upstream exits 1).
type CheckStakeAddress struct {
	// Store resolves a name to its `<name>.staking.addr`; nil means only
	// literal addresses are accepted.
	Store     ports.NamedStore
	Addresses ports.AddressInspector
	Account   ports.RewardAccountReader
	// Pools adds the pool's name and ticker when the account is delegated
	// (SPO-03c-EXT-002); optional, and its failure is not an error.
	Pools     ports.PoolStateReader
	NetworkID uint8
}

// StakeStatus is the read model of a stake account.
type StakeStatus struct {
	Address    chain.StakeAddress
	Registered bool
	// The remaining fields are meaningful when Registered. Reading values
	// that the source did not state are Unknown, not zero.
	Deposit        chain.Reading[chain.Lovelace]
	Rewards        chain.Lovelace
	Pool           chain.Reading[chain.PoolID]
	PoolInfo       chain.Reading[chain.PoolState]
	VoteDelegation chain.Reading[string]
	GovDeposits    chain.Reading[[]chain.GovActionDeposit]
	Source         chain.Source
}

// Run resolves the word to a stake address and reads the account. A word is
// a name when `<name>.staking.addr` is stored, else the address itself
// (SPO-03c-IF-002). Unknown answers and failing providers are errors and
// never "not registered" (SPO-03c-PRE-002).
//
// spec: SPO-03c-IF-001, SPO-03c-IF-002, SPO-03c-IF-003, SPO-03c-IN-001, SPO-03c-PRE-002, SPO-03c-EXT-001,
// spec: SPO-03c-EXT-002, SPO-03c-OUT-001, SPO-03c-OUT-002, SPO-03c-OUT-003, SPO-03c-MODE-001
func (uc CheckStakeAddress) Run(ctx context.Context, word string) (StakeStatus, error) {
	word = strings.TrimSpace(word)
	if word == "" {
		return StakeStatus{}, errors.New("a status check needs a stake account name or a stake address")
	}
	addr := chain.StakeAddress(word)
	if uc.Store != nil {
		name := strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(word, "./"), ".addr"), ".staking")
		if name != "" && !strings.ContainsAny(name, "/\\") {
			var found bool
			err := uc.Store.View(ctx, func(r ports.NamedReader) error {
				b, err := r.Get(ports.NamedRef{Name: name, Kind: ports.StakingAddr})
				if errors.Is(err, ports.ErrNotFound) {
					return nil
				}
				if err != nil {
					return err
				}
				addr, found = chain.StakeAddress(firstLine(b)), true
				return nil
			})
			if err != nil {
				return StakeStatus{}, err
			}
			_ = found
		}
	}
	if _, err := (Base{Addresses: uc.Addresses, NetworkID: uc.NetworkID}).checkStakeAddress(addr); err != nil {
		return StakeStatus{}, err
	}
	if uc.Account == nil {
		return StakeStatus{}, ErrNoChainReader
	}
	r, err := uc.Account.RewardAccount(ctx, addr)
	if err != nil {
		return StakeStatus{}, fmt.Errorf("the stake address state from %s: %w", uc.Account.Source(), err)
	}
	if r.IsUnknown() {
		return StakeStatus{}, fmt.Errorf("%w: %s: %s", stk.ErrUnknown, uc.Account.Source(), r.Why())
	}
	st := StakeStatus{Address: addr, Source: uc.Account.Source()}
	if r.IsNone() {
		return st, nil
	}
	ra, _ := r.Get()
	st.Registered = true
	st.Deposit, st.Rewards, st.Pool, st.VoteDelegation, st.GovDeposits = ra.Deposit, ra.Withdrawable, ra.DelegatedPool, ra.VoteDelegation, ra.GovActionDeposits
	if pid, ok := ra.DelegatedPool.Get(); ok && uc.Pools != nil {
		if pr, err := uc.Pools.PoolState(ctx, pid); err == nil {
			st.PoolInfo = pr
		}
	}
	return st, nil
}
