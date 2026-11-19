// Package parties holds the use cases that manage who the other parties are:
// create the local identity, export it, enroll another party, revoke one,
// list them (spec/extensions/Xparty.md, "Party identity" and "Enrollment").
//
// Every change to the registry is one Store.Update, together with the audit
// event that records it.
//
// Not done: `party rotate` (SPO-Xparty-IF-008). A rotation
// needs a statement signed by the old key and a second confirmation on the
// peer; it is a separate change and waived in spo/spec-coverage.toml.
package parties

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaypeer"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var (
	localKeys = ports.NamedRef{Name: "local", Kind: ports.PartyKeys}
	localDoc  = ports.NamedRef{Name: "local", Kind: ports.PartyIdentity}
)

// Refusals.
var (
	// ErrIdentityExists: the workspace already has an identity; replacing it
	// would orphan every peer that enrolled it.
	ErrIdentityExists = errors.New("this workspace already has a party identity")
	// ErrNoIdentity: there is no local identity to export.
	ErrNoIdentity = errors.New("this workspace has no party identity yet")
	// ErrOwnIdentity: a party cannot enroll itself.
	ErrOwnIdentity = errors.New("that identity document is this workspace's own")
	// ErrBadPool: a pool is not a pool id.
	ErrBadPool = errors.New("a pool is given as its pool id: pool1... or 56 hexadecimal characters")
)

// InitIdentity creates the local identity: an Ed25519 and an X25519 key pair
// in guarded memory, stored as a Secret record, and the signed public
// document (SPO-Xparty-INV-001, INV-003). It refuses when one exists.
type InitIdentity struct {
	Store ports.NamedStore
	Kit   ports.IdentityKit
	Clock ports.Clock
}

// InitRequest names the identity. The label is shown to peers and not
// trusted by them.
type InitRequest struct {
	Label string
	// Node is the tailcat node public key to publish, nil for none.
	Node *party.NodeKey
}

// InitResult carries the public document and the fingerprint to read out to
// the other party.
type InitResult struct {
	Fingerprint party.Fingerprint
	Document    []byte
}

// Run creates the identity.
//
// spec: SPO-Xparty-INV-001, SPO-Xparty-INV-002, SPO-Xparty-INV-003
func (uc InitIdentity) Run(ctx context.Context, req InitRequest) (InitResult, error) {
	g, err := uc.Kit.Generate(req.Label, req.Node, uc.Clock.Now())
	if err != nil {
		return InitResult{}, err
	}
	defer g.Keys.Destroy()
	err = uc.Store.Update(ctx, func(w ports.NamedWriter) error {
		for _, ref := range []ports.NamedRef{localKeys, localDoc} {
			if ok, err := w.Exists(ref); err != nil {
				return err
			} else if ok {
				return ErrIdentityExists
			}
		}
		if err := w.PutSecret(localKeys, g.Keys); err != nil {
			return err
		}
		return w.Put(localDoc, g.Document)
	})
	if err != nil {
		return InitResult{}, err
	}
	return InitResult{Fingerprint: g.Identity.Fingerprint(), Document: g.Document}, nil
}

// ExportIdentity returns the local public identity document
// (SPO-Xparty-IF-001): it holds no secret and no tailcat address.
type ExportIdentity struct {
	Store ports.NamedStore
	Kit   ports.IdentityKit
}

// Run reads the stored document and checks it is well formed and signed
// before handing it out.
//
// spec: SPO-Xparty-IF-001
func (uc ExportIdentity) Run(ctx context.Context) (InitResult, error) {
	var raw []byte
	err := uc.Store.View(ctx, func(r ports.NamedReader) error {
		var err error
		raw, err = r.Get(localDoc)
		return err
	})
	if errors.Is(err, ports.ErrNotFound) {
		return InitResult{}, ErrNoIdentity
	}
	if err != nil {
		return InitResult{}, err
	}
	doc, err := uc.Kit.ParseDocument(raw)
	if err != nil {
		return InitResult{}, err
	}
	if err := doc.Verify(); err != nil {
		return InitResult{}, err
	}
	return InitResult{Fingerprint: doc.Identity.Fingerprint(), Document: raw}, nil
}

// Enroll records another party (SPO-Xparty-IF-002). The operator reads the
// fingerprint from the document, hears the other party read theirs out over
// another channel, and types the first four groups (PR-001): Inspect gives
// what to show (the last four groups, not the first four), Run takes what was
// typed and compares it with the document.
type Enroll struct {
	Store    ports.NamedStore
	Kit      ports.IdentityKit
	Registry ports.PartyRegistry
	Clock    ports.Clock
	// Relay checks a binding given with the document (SPO-Xparty-PRE-008); its
	// zero value refuses every binding and leaves enrollment without one as it
	// was.
	Relay RelayCheck
}

// Inspection is what the operator is shown before typing the groups. It
// holds the label, the roles being requested and only the last four groups of
// the fingerprint: the first four are typed from what the other party reads
// out, so they must not be on the screen to be copied (SPO-Xparty-PR-001).
type Inspection struct {
	Label     string // chosen by its owner, not trusted
	Roles     []party.Role
	LastGroup string // the last four groups of the fingerprint
	HasNode   bool
}

// Inspect parses a document and verifies its signature (SPO-Xparty-PRE-001),
// so that nothing is shown for a document that does not verify.
//
// spec: SPO-Xparty-PRE-001, SPO-Xparty-PR-001
func (uc Enroll) Inspect(raw []byte, roles []party.Role) (Inspection, error) {
	doc, err := uc.Kit.ParseDocument(raw)
	if err != nil {
		return Inspection{}, err
	}
	if err := doc.Verify(); err != nil {
		return Inspection{}, err
	}
	return Inspection{Label: doc.Identity.Label, Roles: roles, LastGroup: doc.Identity.Fingerprint().Tail(), HasNode: doc.Identity.Node != nil}, nil
}

// EnrollRequest is the operator's enrollment.
type EnrollRequest struct {
	Document []byte
	Name     string // local name
	Roles    []party.Role
	// KeyRoles, Pools and Unscoped are the party's scope
	// (SPO-Xparty-INV-010), required for a coordinator or a signer. There is
	// no default: KeyRoles are which of the key roles a request between us
	// may name (for a coordinator, which of this machine's keys it may ask
	// for); Pools are pool ids, "pool1..." or 56 hexadecimal characters, that
	// a body may concern; Unscoped allows a body that concerns no pool.
	KeyRoles []custody.Role
	Pools    []string
	Unscoped bool
	// Confirmation is the first four groups of the fingerprint as the
	// operator typed them. There is no default (SPO-Xparty-PR-001).
	Confirmation string
	// Binding is the party's binding, given with the document; nil enrolls it
	// with no relay identity.
	Binding *BindingEvidence
}

// canonicalPool turns a pool id into its bech32 form, the form a body's pool
// is compared in.
func canonicalPool(p string) (string, error) {
	if id, err := chain.ParsePoolBech32(p); err == nil {
		return id.Bech32(), nil
	}
	if len(p) == 56 {
		if raw, err := hex.DecodeString(strings.ToLower(p)); err == nil {
			var id chain.PoolID
			copy(id[:], raw)
			return id.Bech32(), nil
		}
	}
	return "", fmt.Errorf("%w: %q", ErrBadPool, p)
}

// Run enrolls the party and records the audit event in one transaction.
//
// spec: SPO-Xparty-PRE-001, SPO-Xparty-PR-001, SPO-Xparty-OUT-001, SPO-Xparty-INV-004, SPO-Xparty-IF-002
func (uc Enroll) Run(ctx context.Context, req EnrollRequest) (party.Party, error) {
	doc, err := uc.Kit.ParseDocument(req.Document)
	if err != nil {
		return party.Party{}, err
	}
	pools := make([]string, 0, len(req.Pools))
	for _, p := range req.Pools {
		c, err := canonicalPool(p)
		if err != nil {
			return party.Party{}, err
		}
		pools = append(pools, c)
	}
	now := uc.Clock.Now()
	var pre relaypeer.Evidence
	if req.Binding != nil {
		// the binding and the role history first, outside the transaction (the
		// history is read from the key index); the registry is checked inside
		if pre, err = uc.Relay.verifyNoStore(ctx, req.Binding, doc.Identity.Fingerprint(), now); err != nil {
			return party.Party{}, err
		}
	}
	var out party.Party
	err = uc.Store.Update(ctx, func(w ports.NamedWriter) error {
		// A party does not enroll itself.
		if own, err := w.Get(localDoc); err == nil {
			if d, err := uc.Kit.ParseDocument(own); err == nil && d.Identity.Fingerprint() == doc.Identity.Fingerprint() {
				return ErrOwnIdentity
			}
		} else if !errors.Is(err, ports.ErrNotFound) {
			return err
		}
		existing, err := uc.Registry.List(w)
		if err != nil {
			return err
		}
		e := party.Enrollment{Document: doc, Name: req.Name, Roles: req.Roles,
			Scope:        party.Scope{KeyRoles: req.KeyRoles, Pools: pools, Unscoped: req.Unscoped},
			Confirmation: req.Confirmation}
		if req.Binding != nil {
			e.Relay = &pre.Relay
		}
		p, err := party.Enroll(e, existing, now)
		if err != nil {
			return err
		}
		if p.Relay != nil {
			if _, err := relaypeer.CheckClaim(p.Relay.WalletKey, p.Fingerprint, append(existing, p)); err != nil {
				return err
			}
		}
		if err := uc.Registry.Put(w, p); err != nil {
			return err
		}
		out = p
		detail := fmt.Sprintf("%s roles=%v key roles=%v pools=%v unscoped=%v", p.Name, p.Roles, p.Scope.KeyRoles, p.Scope.Pools, p.Scope.Unscoped)
		if p.Relay != nil {
			detail += fmt.Sprintf(" wallet key=%x until=%d", p.Relay.WalletKey[:], p.Relay.Until)
		}
		return AppendEvent(w, Event{At: now, Kind: "party-enrolled", Peer: p.Fingerprint.String(), Detail: detail})
	})
	return out, err
}

// Revoke sets a party to revoked (SPO-Xparty-IF-003, INV-005): its envelopes
// are refused from the moment the record commits, including ones created
// before. Open collections keep the witnesses already verified; the hooks
// unassign the unfilled slots that were assigned to the party, in the same
// transaction.
type Revoke struct {
	Store    ports.NamedStore
	Registry ports.PartyRegistry
	Clock    ports.Clock
	// Hooks run inside the transaction with the revoked party, so that
	// whatever refers to it by name (witness collections, queued
	// envelopes) changes with it. multisig.Coordinator.OnRevoke is one.
	Hooks []func(w ports.NamedWriter, revoked party.Party) error
}

// Run revokes the party named locally.
//
// spec: SPO-Xparty-IF-003, SPO-Xparty-INV-005, SPO-Xparty-OUT-004
func (uc Revoke) Run(ctx context.Context, name string) (party.Party, error) {
	var out party.Party
	err := uc.Store.Update(ctx, func(w ports.NamedWriter) error {
		p, err := uc.Registry.Revoke(w, name)
		if err != nil {
			return err
		}
		for _, h := range uc.Hooks {
			if err := h(w, p); err != nil {
				return err
			}
		}
		out = p
		return AppendEvent(w, Event{At: uc.Clock.Now(), Kind: "party-revoked", Peer: p.Fingerprint.String(), Detail: p.Name})
	})
	return out, err
}

// List shows the enrolled parties, by local name.
type List struct {
	Store    ports.NamedStore
	Registry ports.PartyRegistry
}

// Run reads the registry.
func (uc List) Run(ctx context.Context) ([]party.Party, error) {
	var out []party.Party
	err := uc.Store.View(ctx, func(r ports.NamedReader) error {
		var err error
		out, err = uc.Registry.List(r)
		return err
	})
	slices.SortFunc(out, func(a, b party.Party) int { return strings.Compare(a.Name, b.Name) })
	return out, err
}
