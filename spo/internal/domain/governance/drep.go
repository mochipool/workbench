package governance

import (
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// DRepKind is what a DRep transaction does.
type DRepKind string

// The three DRep certificates.
const (
	DRepRegistration DRepKind = "registration"
	DRepUpdate       DRepKind = "update"
	DRepRetirement   DRepKind = "retirement"
)

// Refusals of the DRep life cycle.
var (
	// ErrDRepUnknown: the chain did not say whether the DRep is registered.
	// Unknown is never taken as "not registered" (ADR 0006): a duplicate
	// registration, or an update that registers nothing, would follow.
	ErrDRepUnknown = errors.New("the chain did not state whether the DRep is registered")
	// ErrDRepNotRegistered: a retirement or an update of a DRep that is not registered.
	ErrDRepNotRegistered = errors.New("the DRep is not registered")
	// ErrDRepDeposit: the on-chain DRep state does not state the deposit.
	ErrDRepDeposit = errors.New("the DRep state does not state the deposit the refund rests on")
)

// DRep is a delegated representative: the credential of its key and what
// the chain holds for it. Only key DReps are created by 21a, 21b and 21d;
// a script DRep can be looked up by 21c.
//
//	not registered -> Registered(deposit, anchor) -> Updated(anchor) -> Retired(refund)
type DRep struct {
	Cred       Credential
	Registered bool
	Deposit    chain.Lovelace
	Anchor     Anchor
}

// Register is the registration of a DRep that is not registered.
func (d DRep) Register(deposit chain.Lovelace, a Anchor) (DRep, error) {
	if d.Registered {
		return DRep{}, errors.New("the DRep is already registered")
	}
	return DRep{Cred: d.Cred, Registered: true, Deposit: deposit, Anchor: a}, nil
}

// Update replaces the anchor of a registered DRep. The deposit stays.
func (d DRep) Update(a Anchor) (DRep, error) {
	if !d.Registered {
		return DRep{}, ErrDRepNotRegistered
	}
	d.Anchor = a
	return d, nil
}

// Retire ends the registration and returns the refund: the deposit the
// chain holds, not the one of the current protocol parameters.
//
// spec: SPO-21d-INV-001
func (d DRep) Retire() (refund chain.Lovelace, _ DRep, _ error) {
	if !d.Registered {
		return 0, DRep{}, ErrDRepNotRegistered
	}
	return d.Deposit, DRep{Cred: d.Cred}, nil
}

// DecideDRepKind says whether a registration or an update is due, from the
// chain's answer: not registered is a registration, any state, including an
// expired DRep, an update (nothing else is compared). An unknown answer is
// refused.
//
// spec: SPO-21b-INV-002, SPO-21b-EXT-004
func DecideDRepKind(state chain.Reading[chain.DRepState]) (DRepKind, error) {
	switch {
	case state.IsUnknown():
		return "", fmt.Errorf("%w: %s", ErrDRepUnknown, state.Why())
	case state.IsNone():
		return DRepRegistration, nil
	}
	return DRepUpdate, nil
}

// RefundOf is the deposit a retirement certificate carries, from the DRep's
// on-chain state: none registered is ErrDRepNotRegistered (nothing to
// retire), an unknown state is refused, and a registered DRep whose deposit
// the provider did not state is refused rather than defaulted to 0.
//
// spec: SPO-21d-PRE-004, SPO-21d-INV-001
func RefundOf(state chain.Reading[chain.DRepState]) (chain.Lovelace, error) {
	switch {
	case state.IsUnknown():
		return 0, fmt.Errorf("%w: %s", ErrDRepUnknown, state.Why())
	case state.IsNone():
		return 0, ErrDRepNotRegistered
	}
	st, _ := state.Get()
	if st.Deposit == 0 { // a registered DRep always paid a non-zero deposit: zero is "not stated"
		return 0, ErrDRepDeposit
	}
	return st.Deposit, nil
}

// DRepStanding is how 21c reports a registered DRep.
type DRepStanding string

// Standings of a DRep.
const (
	DRepNotRegistered DRepStanding = "not registered"
	DRepActive        DRepStanding = "registered"
	DRepInactive      DRepStanding = "registered, expired (inactive)"
	// DRepRegisteredUnassessed: registered, and whether it is expired is not
	// known because no epoch could be read; the report says why.
	DRepRegisteredUnassessed DRepStanding = "registered (expiry not assessed)"
)

// StandingWithoutEpoch classifies a DRep state when the current epoch is
// unknown: registered or not registered are answers of the state alone, the
// expiry part is not assessed (Unknown with a reason, never assumed active). An
// unknown state is refused.
//
// spec: SPO-21c-PRE-004, SPO-21c-INV-003
func StandingWithoutEpoch(state chain.Reading[chain.DRepState]) (DRepStanding, error) {
	switch {
	case state.IsUnknown():
		return "", fmt.Errorf("%w: %s", ErrDRepUnknown, state.Why())
	case state.IsNone():
		return DRepNotRegistered, nil
	}
	return DRepRegisteredUnassessed, nil
}

// StandingOf classifies a DRep state against the current epoch. A registered
// DRep whose expiry is below the current epoch is inactive; an unstated expiry
// leaves the standing as registered with Known false.
//
// spec: SPO-21c-PRE-004, SPO-21c-INV-003
func StandingOf(state chain.Reading[chain.DRepState], epoch uint64) (st DRepStanding, expiryKnown bool, err error) {
	switch {
	case state.IsUnknown():
		return "", false, fmt.Errorf("%w: %s", ErrDRepUnknown, state.Why())
	case state.IsNone():
		return DRepNotRegistered, true, nil
	}
	v, _ := state.Get()
	exp, ok := v.Expiry.Get()
	if !ok {
		return DRepActive, false, nil
	}
	if exp < epoch {
		return DRepInactive, true, nil
	}
	return DRepActive, true, nil
}
