package custody

import (
	"errors"
	"fmt"
	"sort"

	"github.com/mochipool/workbench/spo/internal/domain/identity"
)

// Sensitivity ranks a role for the cold-key rule of ADR 0010 decision 3.
// The ranking is a project choice, not taken from a specification: only the
// distinction of the cold roles (pool cold, committee cold) is load-bearing.
func (r Role) Sensitivity() int {
	switch r {
	case RolePoolCold, RoleCommitteeCold:
		return 3
	case RolePayment, RoleStake, RoleDRep, RolePolicy:
		return 2
	case RoleKES, RoleVRF, RoleCommitteeHot, RoleCalidus, RoleCatalystVote:
		return 1
	}
	return 0
}

// IsCold reports whether the role is a cold role: pool cold or committee cold.
func (r Role) IsCold() bool { return r == RolePoolCold || r == RoleCommitteeCold }

func (r Role) valid() bool {
	for _, x := range Roles() {
		if x == r {
			return true
		}
	}
	return false
}

// ErrRoleHistory is the refusal of an invalid role history.
var ErrRoleHistory = errors.New("custody: invalid role history")

// RoleHistory is every role one key identity has been used or imported in.
// The set only grows: there is no way to remove a role. It is the value of
// the workspace record of kind role-history (a later change stores it, keyed
// by the key identity as its own anchor and number 0). A key's identity does
// not contain its role; the role is a property of a use.
type RoleHistory struct {
	id    identity.Ref
	roles map[Role]struct{}
}

func isKeyKind(k identity.Kind) bool {
	switch k {
	case identity.KindKeyHash, identity.KindVRFKeyHash, identity.KindKESKeyHash,
		identity.KindBLSKeyHash, identity.KindCatalystKeyHash, identity.KindCalidusKeyHash:
		return true
	}
	return false
}

// NewRoleHistory starts the history of a key identity with its first role.
func NewRoleHistory(id identity.Ref, first Role) (RoleHistory, error) {
	if !isKeyKind(id.Kind()) || id.IsZero() {
		return RoleHistory{}, fmt.Errorf("%w: %s is not a key identity", ErrRoleHistory, id)
	}
	return RoleHistory{id: id, roles: map[Role]struct{}{}}.With(first)
}

// Identity returns the key identity the history belongs to.
func (h RoleHistory) Identity() identity.Ref { return h.id }

// With returns the history with one more role. The receiver is unchanged.
func (h RoleHistory) With(r Role) (RoleHistory, error) {
	if !r.valid() {
		return RoleHistory{}, fmt.Errorf("%w: unknown role %q", ErrRoleHistory, r)
	}
	out := RoleHistory{id: h.id, roles: map[Role]struct{}{r: {}}}
	for x := range h.roles {
		out.roles[x] = struct{}{}
	}
	return out, nil
}

// Merge returns the union of two histories of the same identity (two clients
// of a workspace that recorded different roles).
func (h RoleHistory) Merge(o RoleHistory) (RoleHistory, error) {
	if h.id != o.id {
		return RoleHistory{}, fmt.Errorf("%w: histories of two identities", ErrRoleHistory)
	}
	out := RoleHistory{id: h.id, roles: map[Role]struct{}{}}
	for x := range h.roles {
		out.roles[x] = struct{}{}
	}
	for x := range o.roles {
		out.roles[x] = struct{}{}
	}
	return out, nil
}

// Roles lists the recorded roles in the order of Roles().
func (h RoleHistory) Roles() []Role {
	var out []Role
	for _, r := range Roles() {
		if _, ok := h.roles[r]; ok {
			out = append(out, r)
		}
	}
	return out
}

// Has reports whether the role was ever recorded.
func (h RoleHistory) Has(r Role) bool { _, ok := h.roles[r]; return ok }

// MostSensitive returns the most sensitive recorded role (ties: the first in
// the order of Roles()), and false for an empty history.
func (h RoleHistory) MostSensitive() (Role, bool) {
	var best Role
	found := false
	for _, r := range h.Roles() {
		if !found || r.Sensitivity() > best.Sensitivity() {
			best, found = r, true
		}
	}
	return best, found
}

// HasColdRole reports whether a cold role was ever recorded: the key must
// never be answered for over a network transport, whatever role a demand names.
func (h RoleHistory) HasColdRole() bool {
	for r := range h.roles {
		if r.IsCold() {
			return true
		}
	}
	return false
}

// Canonical is the canonical CBOR encoding [identity, [role...]] with the
// identity in its binary form and the roles sorted by name.
func (h RoleHistory) Canonical() ([]byte, error) {
	ib, err := h.id.MarshalBinary()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(h.roles))
	for r := range h.roles {
		names = append(names, string(r))
	}
	sort.Strings(names)
	rs := make([]any, len(names))
	for i, n := range names {
		rs[i] = n
	}
	return identity.EncodeCanonical([]any{ib, rs})
}

// ParseRoleHistory reads the encoding of Canonical, refusing non-canonical
// bytes, a duplicate or unknown role and an empty set.
func ParseRoleHistory(b []byte) (RoleHistory, error) {
	v, err := identity.DecodeCanonical(b)
	if err != nil {
		return RoleHistory{}, err
	}
	top, ok := v.([]any)
	if !ok || len(top) != 2 {
		return RoleHistory{}, fmt.Errorf("%w: shape", ErrRoleHistory)
	}
	ib, ok1 := top[0].([]byte)
	rs, ok2 := top[1].([]any)
	if !ok1 || !ok2 || len(rs) == 0 {
		return RoleHistory{}, fmt.Errorf("%w: shape", ErrRoleHistory)
	}
	id, err := identity.UnmarshalRef(ib)
	if err != nil {
		return RoleHistory{}, err
	}
	if !isKeyKind(id.Kind()) {
		return RoleHistory{}, fmt.Errorf("%w: %s is not a key identity", ErrRoleHistory, id)
	}
	h := RoleHistory{id: id, roles: map[Role]struct{}{}}
	var prev string
	for i, e := range rs {
		s, ok := e.(string)
		if !ok || !Role(s).valid() || (i > 0 && s <= prev) {
			return RoleHistory{}, fmt.Errorf("%w: role %v", ErrRoleHistory, e)
		}
		prev = s
		h.roles[Role(s)] = struct{}{}
	}
	return h, nil
}

// ErrRoleHistoryShrunk means a role history that replaces a stored one lacks
// a role the stored one has, or belongs to another identity: the set only
// grows.
var ErrRoleHistoryShrunk = errors.New("custody: a role history only grows")

// Extends checks that h is a legitimate successor of the stored history prev:
// the same identity and every stored role still present. The store calls it
// on every write of a role-history record.
func (h RoleHistory) Extends(prev RoleHistory) error {
	if h.id != prev.id {
		return fmt.Errorf("%w: another identity (%s, stored %s)", ErrRoleHistoryShrunk, h.id, prev.id)
	}
	for r := range prev.roles {
		if _, ok := h.roles[r]; !ok {
			return fmt.Errorf("%w: role %s is gone", ErrRoleHistoryShrunk, r)
		}
	}
	return nil
}
