package party

import (
	"errors"
	"fmt"
	"slices"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
)

// Scope is what a signing request between us and an enrolled party may be
// about (SPO-Xparty-INV-010). For a coordinator enrolled at a signer it says
// what the coordinator may ask of this machine; for a signer enrolled at a
// coordinator it says what the coordinator is willing to ask of it, and is
// checked before a request is sent. The zero Scope allows nothing, so a record
// without a scope is read as the most restrictive one.
type Scope struct {
	// KeyRoles are the key roles that may be requested. Default: none.
	KeyRoles []custody.Role
	// Pools are the pools (bech32 pool ids) a body may concern.
	Pools []string
	// Unscoped allows a body that concerns no pool (a payment, a
	// withdrawal, a vote that names no pool). Default: false.
	Unscoped bool
}

// Empty reports that the scope allows nothing a coordinator or signer could
// use: no key role, or neither a pool nor Unscoped.
func (s Scope) Empty() bool { return len(s.KeyRoles) == 0 || (len(s.Pools) == 0 && !s.Unscoped) }

// normalised returns a sorted, duplicate-free copy, or refuses a key role or
// pool that is not one.
func (s Scope) normalised() (Scope, error) {
	out := Scope{Unscoped: s.Unscoped, KeyRoles: slices.Clone(s.KeyRoles), Pools: slices.Clone(s.Pools)}
	slices.Sort(out.KeyRoles)
	for i, r := range out.KeyRoles {
		if !knownRole(r) || (i > 0 && out.KeyRoles[i-1] == r) {
			return Scope{}, fmt.Errorf("%w: key role %q", ErrInvalidEnrollment, r)
		}
	}
	slices.Sort(out.Pools)
	for i, p := range out.Pools {
		if !poolRE.MatchString(p) || (i > 0 && out.Pools[i-1] == p) {
			return Scope{}, fmt.Errorf("%w: pool %q", ErrInvalidEnrollment, p)
		}
	}
	return out, nil
}

// ErrOutOfScope: a request asks for more than the sender's scope allows.
var ErrOutOfScope = errors.New("party: the request is outside the sender's scope")

// CheckScope is the scope rule of SPO-Xparty-INV-010. The requested key role
// must be one of s.KeyRoles; every pool in pools (the pools the body concerns,
// decoded by the receiver, in the receiver's bech32 form) must be one of
// s.Pools; a body that concerns no pool needs s.Unscoped.
func CheckScope(s Scope, role custody.Role, pools []string) error {
	if !slices.Contains(s.KeyRoles, role) {
		return fmt.Errorf("%w: key role %s", ErrOutOfScope, role)
	}
	if len(pools) == 0 && !s.Unscoped {
		return fmt.Errorf("%w: the body concerns no pool", ErrOutOfScope)
	}
	for _, p := range pools {
		if !slices.Contains(s.Pools, p) {
			return fmt.Errorf("%w: pool %s", ErrOutOfScope, p)
		}
	}
	return nil
}
