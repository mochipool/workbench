package governance

import (
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// HotAuth is the state of a committee member's hot key.
type HotAuth string

// The authorisation tags of the committee state.
const (
	HotNotAuthorized HotAuth = "MemberNotAuthorized"
	HotAuthorized    HotAuth = "MemberAuthorized"
	HotResigned      HotAuth = "MemberResigned"
)

// CommitteeMember is a member of the constitutional committee as the chain
// reports it: the cold credential, the authorised hot credential and the
// state of the authorisation.
//
//	Authorised(hot) -> Resigned
//
// A resigned cold key can never be authorised again.
type CommitteeMember struct {
	Cold Credential
	Auth HotAuth
	// Hot is the authorised hot credential, set when Auth is HotAuthorized.
	Hot Credential
	// Status is the provider's text (`Active`, `Expired`, `Unrecognized`).
	Status string
	Expiry chain.Reading[uint64]
	// NextChange is the pending change of the next epoch, as the provider says it.
	NextChange string
}

// Refusals of the committee life cycle.
var (
	// ErrCommitteeUnknown: the chain did not say what the committee state is.
	ErrCommitteeUnknown = errors.New("the chain did not state the committee state of the key")
	// ErrCommitteeResigned: a resigned cold key cannot be authorised again.
	ErrCommitteeResigned = errors.New("the cold key has resigned: a resigned cold key cannot be authorised again")
	// ErrSameHotKey: the hot key is already the authorised one.
	ErrSameHotKey = errors.New("this hot key is already authorised for the cold key")
	// ErrNotOnChain: the key is no committee member: there is nothing to resign.
	ErrNotOnChain = errors.New("the cold key is not on chain as a committee member: there is nothing to retire")
)

// CheckAuthorize decides whether a hot-key authorisation may go on. An
// absent member is allowed (the authorisation may precede the member's
// enactment, SPO-23c-INV-002); a resigned one and the same hot key are
// refused. An unknown answer is refused: Unknown is never "not on chain".
//
// spec: SPO-23c-PRE-002, SPO-23c-PRE-003, SPO-23c-INV-002, SPO-23c-INV-003
func CheckAuthorize(state chain.Reading[CommitteeMember], hot Credential) (onChain bool, err error) {
	switch {
	case state.IsUnknown():
		return false, fmt.Errorf("%w: %s", ErrCommitteeUnknown, state.Why())
	case state.IsNone():
		return false, nil
	}
	m, _ := state.Get()
	switch {
	case m.Auth == HotResigned:
		return true, ErrCommitteeResigned
	case m.Auth == HotAuthorized && m.Hot == hot:
		return true, ErrSameHotKey
	}
	return true, nil
}

// CheckResign decides whether a cold-key resignation may go on: the member
// must be on chain. Any state, including an already resigned key, goes on
// (upstream submits a second resignation, SPO-23e-INV-001, SPO-23e-PRE-002).
//
// spec: SPO-23e-PRE-002, SPO-23e-INV-001
func CheckResign(state chain.Reading[CommitteeMember]) error {
	switch {
	case state.IsUnknown():
		return fmt.Errorf("%w: %s", ErrCommitteeUnknown, state.Why())
	case state.IsNone():
		return ErrNotOnChain
	}
	return nil
}

// Authorise and Resign are the transitions of a member.
func (m CommitteeMember) Authorise(hot Credential) (CommitteeMember, error) {
	if m.Auth == HotResigned {
		return CommitteeMember{}, ErrCommitteeResigned
	}
	m.Auth, m.Hot = HotAuthorized, hot
	return m, nil
}

// Resign ends the authorisation.
func (m CommitteeMember) Resign() CommitteeMember {
	m.Auth, m.Hot = HotResigned, Credential{}
	return m
}
