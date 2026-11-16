package stake

import (
	"errors"
	"fmt"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// State is where a stake account is in its life.
type State int

// The states, in order of a normal life.
const (
	Unregistered State = iota
	Registered
	Delegated
	Deregistered
)

func (s State) String() string {
	return [...]string{"unregistered", "registered", "delegated", "deregistered"}[s]
}

// Account is a stake account as a use case reasons about it. It is built
// from a chain reading (FromReading) and moved by certificates (Apply); it
// is never stored as truth.
type Account struct {
	State   State
	Deposit chain.Lovelace // the deposit the chain holds for it
	Rewards chain.Lovelace // the reward balance
	Pool    *chain.PoolID  // set when delegated to a pool
	// Vote is the provider's text for the vote delegation; empty when
	// there is none.
	Vote string
	// Gov lists governance-action deposits refunded to the account.
	Gov []chain.GovActionDeposit
}

// Refusals of the transitions.
var (
	ErrAlreadyRegistered = errors.New("the stake address is already registered")
	ErrNotRegistered     = errors.New("the stake address is not registered: register it first")
	ErrHasRewards        = errors.New("the stake address still holds rewards: withdraw them first")
	ErrHasGovDeposits    = errors.New("the stake address is named in open governance actions whose deposits are still to be refunded: wait until they are finished")
	ErrUnknown           = errors.New("the chain did not say what the state of the stake address is")
)

// Known says which optional fields of an Account the source stated. An
// unstated field is not a zero or an empty one.
type Known struct {
	Deposit, Gov, Pool, Vote bool
}

// FromReading reads an account out of a three-valued reading of the reward
// account. None is Unregistered. Unknown is an error and is never turned
// into Unregistered (ADR 0006); neither is a field the provider left
// unknown turned into a default: Known says which fields were stated.
func FromReading(r chain.Reading[chain.RewardAccount]) (Account, Known, error) {
	if r.IsUnknown() {
		return Account{}, Known{}, fmt.Errorf("%w: %s", ErrUnknown, r.Why())
	}
	if r.IsNone() {
		return Account{State: Unregistered}, Known{Deposit: true, Gov: true, Pool: true, Vote: true}, nil
	}
	ra, _ := r.Get()
	a := Account{State: Registered, Rewards: ra.Withdrawable}
	var k Known
	if v, ok := ra.Deposit.Get(); ok {
		a.Deposit, k.Deposit = v, true
	}
	if p, ok := ra.DelegatedPool.Get(); ok {
		a.Pool, k.Pool = &p, true
		a.State = Delegated
	} else if ra.DelegatedPool.IsNone() {
		k.Pool = true
	}
	if v, ok := ra.VoteDelegation.Get(); ok {
		a.Vote, k.Vote = v, true
	} else if ra.VoteDelegation.IsNone() {
		k.Vote = true
	}
	if g, ok := ra.GovActionDeposits.Get(); ok {
		a.Gov, k.Gov = g, true
	} else if ra.GovActionDeposits.IsNone() {
		k.Gov = true
	}
	return a, k, nil
}

// CanRegister: only an unregistered address is registered.
//
// spec: SPO-03b-PRE-002
func (a Account) CanRegister() error {
	if a.State != Unregistered && a.State != Deregistered {
		return ErrAlreadyRegistered
	}
	return nil
}

// CanDelegate: pool and vote delegation need a registered account;
// re-delegation, also to the same target, is allowed.
//
// spec: SPO-06-PRE-003, SPO-06-INV-001, SPO-22b-PRE-003
func (a Account) CanDelegate() error {
	if a.State != Registered && a.State != Delegated {
		return ErrNotRegistered
	}
	return nil
}

// CanDeregister: a registered account with no rewards and no open
// governance-action deposits. Both refusals are reported together.
//
// spec: SPO-08a-PRE-003, SPO-08a-PRE-004, SPO-08a-PRE-005, SPO-08b-PRE-002, SPO-08b-PRE-003
func (a Account) CanDeregister() error {
	if a.State != Registered && a.State != Delegated {
		return ErrNotRegistered
	}
	var errs []error
	if a.Rewards > 0 {
		errs = append(errs, fmt.Errorf("%w (%d lovelace)", ErrHasRewards, a.Rewards))
	}
	if len(a.Gov) > 0 {
		var ids []string
		for _, g := range a.Gov {
			ids = append(ids, g.Action)
		}
		errs = append(errs, fmt.Errorf("%w (%s)", ErrHasGovDeposits, strings.Join(ids, ", ")))
	}
	return errors.Join(errs...)
}

// Apply returns the account after a certificate. It refuses the
// transitions CanRegister, CanDelegate and CanDeregister refuse.
func (a Account) Apply(c Spec) (Account, error) {
	switch c.Kind {
	case CertRegistration:
		if err := a.CanRegister(); err != nil {
			return a, err
		}
		return Account{State: Registered, Deposit: c.Deposit}, nil
	case CertDeregistration:
		if err := a.CanDeregister(); err != nil {
			return a, err
		}
		return Account{State: Deregistered}, nil
	case CertPoolDelegation:
		if err := a.CanDelegate(); err != nil {
			return a, err
		}
		a.State = Delegated
		p := c.Pool
		a.Pool = &p
		return a, nil
	case CertVoteDelegation:
		if err := a.CanDelegate(); err != nil {
			return a, err
		}
		a.Vote = c.DRep.String()
		return a, nil
	}
	return a, ErrBadSpec
}

// HasVoteDelegation reports a vote delegation of any kind: a DRep, a
// script DRep, always-abstain or always-no-confidence. The provider's
// texts "notSet" and "null" mean none.
//
// spec: SPO-01claimRewards-PRE-005
func HasVoteDelegation(text string) bool {
	switch strings.TrimSpace(text) {
	case "", "notSet", "null":
		return false
	}
	return true
}
