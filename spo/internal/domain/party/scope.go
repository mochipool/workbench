package party

import (
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
)

// Scope is what a signing request from one enrolled coordinator may be about
// (SPO-Xparty-INV-010). It belongs to the coordinator role of a party and is
// what that coordinator may ask of THIS machine: it is checked by the signer
// when the request arrives and again when it is approved. It is not used for
// what this machine asks of a signer: those requests are limited by the slot
// assignment and by the signer's own checks. The zero Scope allows nothing,
// so a record without a scope is read as the most restrictive one.
type Scope struct {
	// KeyRoles are the key roles that may be requested. Default: none.
	KeyRoles []custody.Role
	// Pools are the pools (bech32 pool ids) a body may name: every part of
	// the body that names a pool must name one of these.
	Pools []string
	// Unscoped allows the parts of a body that name no pool (withdrawals,
	// stake registration and deregistration, vote delegation, DRep and
	// committee certificates, votes that are not a pool's) and every payment
	// request, which can spend this machine's funds. Default: false.
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

// ScopeParts is a body split for the scope rule of SPO-Xparty-INV-010: the
// pools that the parts naming a pool name, in bech32, and a description of
// each part that names no pool.
type ScopeParts struct {
	Pools    []string
	Unscoped []string
}

// ScopePartsOf splits the body of a request for key role role. A certificate
// that names a pool (a registration, a retirement, a delegation, a combined
// delegation) and a vote of a stake pool name a pool. Every other certificate,
// every withdrawal, every other vote, and the request of a payment key
// (whose witness can spend any UTxO of the key) name none. A body with no part
// that names a pool counts as one that names none.
func ScopePartsOf(role custody.Role, v TxView) ScopeParts {
	var sp ScopeParts
	add := func(id [28]byte) {
		if p := chain.PoolID(id).Bech32(); !slices.Contains(sp.Pools, p) {
			sp.Pools = append(sp.Pools, p)
		}
	}
	for _, c := range v.Certificates {
		switch {
		case c.PoolReg != nil || c.HasPool:
			if c.PoolReg != nil {
				add(c.PoolReg.Operator)
			}
			if c.HasPool {
				add(c.Pool)
			}
			// A combined certificate has parts that name no pool: its
			// registration (a deposit paid) and its vote delegation (a DRep).
			// Each is checked on its own (SPO-Xparty-INV-010).
			if c.Kind == CertStakeRegDelegation || c.Kind == CertStakeVoteRegDeleg || c.Tag == 11 || c.Tag == 13 {
				sp.Unscoped = append(sp.Unscoped, "the registration part of a "+c.Kind+" certificate")
			}
			if c.DRep != "" || c.Kind == CertStakeVoteDelegation || c.Kind == CertStakeVoteRegDeleg || c.Tag == 10 || c.Tag == 13 {
				sp.Unscoped = append(sp.Unscoped, "the vote delegation part of a "+c.Kind+" certificate")
			}
		default:
			sp.Unscoped = append(sp.Unscoped, "a "+c.Kind+" certificate")
		}
	}
	for _, w := range v.Withdrawals {
		sp.Unscoped = append(sp.Unscoped, "a withdrawal from "+w.Account)
	}
	for _, vote := range v.Votes {
		if h, ok := strings.CutPrefix(vote.Voter, "pool:"); ok {
			if b, err := hex.DecodeString(h); err == nil && len(b) == 28 {
				add([28]byte(b))
				continue
			}
		}
		sp.Unscoped = append(sp.Unscoped, "a vote by "+vote.Voter)
	}
	if role == custody.RolePayment {
		sp.Unscoped = append(sp.Unscoped, "a payment key request, which can spend this machine's funds")
	}
	if len(sp.Pools) == 0 && len(sp.Unscoped) == 0 {
		sp.Unscoped = append(sp.Unscoped, "a body that names no pool")
	}
	return sp
}

// CheckScope is the scope rule of SPO-Xparty-INV-010, per part of the body
// and not per body: the requested key role must be one of s.KeyRoles; every
// pool that a part of the body names must be one of s.Pools; and every part
// that names no pool needs s.Unscoped. A body that mixes an in-scope pool
// certificate with a withdrawal needs both the pool and Unscoped.
func CheckScope(s Scope, role custody.Role, v TxView) error {
	if !slices.Contains(s.KeyRoles, role) {
		return fmt.Errorf("%w: key role %s", ErrOutOfScope, role)
	}
	sp := ScopePartsOf(role, v)
	for _, p := range sp.Pools {
		if !slices.Contains(s.Pools, p) {
			return fmt.Errorf("%w: pool %s", ErrOutOfScope, p)
		}
	}
	if len(sp.Unscoped) > 0 && !s.Unscoped {
		return fmt.Errorf("%w: the body has a part that names no pool (%s) and the scope is not unscoped", ErrOutOfScope, sp.Unscoped[0])
	}
	return nil
}
