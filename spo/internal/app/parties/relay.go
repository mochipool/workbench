package parties

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relaypeer"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// BindingEvidence is the binding another party gave with its identity document
// (ADR 0014 decision 2, the companion file): the COSE_Sign1 and the COSE_Key, as
// given.
type BindingEvidence struct {
	Statement, Key []byte
}

// RelayCheck is what the evidence check needs from the workspace
// (SPO-Xparty-PRE-008). The zero value refuses every binding: there is no
// history source, so the cold-key rule cannot be checked.
type RelayCheck struct {
	// History is the role history of a key identity in this store
	// (ports.RoleHistoryOf over the key index).
	History func(ctx context.Context, id identity.Ref) (custody.RoleHistory, bool, error)
	// Policy is the relay policy the binding is held to; the zero value is
	// relaybind.DefaultPolicy.
	Policy relaybind.Policy
	// Network is the workspace's network id (1 mainnet, 0 the test networks), the
	// network an address in the binding must be on; relaypeer.NetworkAny checks
	// none.
	Network int
	// PoolIDs is this workspace's own pool ids (a pool kept here only by its id
	// or its cold verification key has no role history of the cold key): a wallet
	// key that is one is refused. The pools named in a party's scope are checked
	// against the registry in the transaction. Required.
	PoolIDs func(ctx context.Context) (map[[28]byte]bool, error)
}

// ErrNoHistory: the evidence check has no role-history source, so the cold-key
// rule cannot be checked and no binding is taken.
var ErrNoHistory = errors.New("no role history source: a binding cannot be checked against the cold-key rule")

// ErrNoPoolSource: the evidence check has no source of this workspace's pool
// ids, so no binding is taken.
var ErrNoPoolSource = errors.New("no source of this workspace's pool ids: a binding cannot be checked against them")

// BindingView is the evidence shown to the operator next to the typed groups
// (SPO-Xparty-PR-007): the wallet key (never the address bytes), the address form
// the wallet signed for, the window, and the enrolled parties that share the key.
type BindingView struct {
	WalletKey   party.WalletKey
	Part        relaybind.AddressPart
	From, Until int64
	Shared      []string
}

// WalletKeyHex is the wallet key as the operator reads it.
func (v BindingView) WalletKeyHex() string { return hex.EncodeToString(v.WalletKey[:]) }

// FromTime and UntilTime are the window in UTC.
func (v BindingView) FromTime() time.Time  { return time.Unix(v.From, 0).UTC() }
func (v BindingView) UntilTime() time.Time { return time.Unix(v.Until, 0).UTC() }

// verifyNoStore runs the checks of PRE-008 that need no transaction: the binding
// itself on the clock, for the fingerprint fp computed from the identity's keys,
// and the role history of K.
func (c RelayCheck) verifyNoStore(ctx context.Context, ev *BindingEvidence, fp party.Fingerprint, now time.Time) (relaypeer.Evidence, error) {
	if c.History == nil {
		return relaypeer.Evidence{}, ErrNoHistory
	}
	if c.PoolIDs == nil {
		return relaypeer.Evidence{}, ErrNoPoolSource
	}
	pol := c.Policy
	if pol == (relaybind.Policy{}) {
		pol = relaybind.DefaultPolicy()
	}
	got, err := relaypeer.Verify(ev.Statement, ev.Key, fp, now.Unix(), pol, c.Network)
	if err != nil {
		return relaypeer.Evidence{}, err
	}
	k := got.Relay.WalletKey
	own, err := c.PoolIDs(ctx)
	if err != nil {
		return relaypeer.Evidence{}, fmt.Errorf("%w: %w", ErrNoPoolSource, err)
	}
	if own[[28]byte(k)] {
		return relaypeer.Evidence{}, fmt.Errorf("%w: it is the id of a pool of this workspace", relaypeer.ErrColdKey)
	}
	id, err := identity.NewRef(identity.KindKeyHash, k[:])
	if err != nil {
		return relaypeer.Evidence{}, err
	}
	h, known, herr := c.History(ctx, id)
	if err := relaypeer.CheckKeyHistory(k, h, known, herr); err != nil {
		return relaypeer.Evidence{}, err
	}
	return got, nil
}

// check is the whole evidence check against the registry as it is (existing).
func (c RelayCheck) check(ctx context.Context, ev *BindingEvidence, fp party.Fingerprint, existing []party.Party, now time.Time) (relaypeer.Evidence, []string, error) {
	got, err := c.verifyNoStore(ctx, ev, fp, now)
	if err != nil {
		return relaypeer.Evidence{}, nil, err
	}
	shared, err := relaypeer.CheckClaim(got.Relay.WalletKey, fp, existing)
	if err != nil {
		return relaypeer.Evidence{}, nil, err
	}
	return got, shared, nil
}

func viewOf(e relaypeer.Evidence, shared []string) BindingView {
	return BindingView{WalletKey: e.Relay.WalletKey, Part: e.Part, From: e.Relay.From, Until: e.Relay.Until, Shared: shared}
}

// InspectBinding checks the binding given with a document, as Run will, and
// returns what to show next to the typed groups. Nothing is stored.
//
// spec: SPO-Xparty-PRE-008, SPO-Xparty-PR-007
func (uc Enroll) InspectBinding(ctx context.Context, raw []byte, ev *BindingEvidence) (BindingView, error) {
	doc, err := uc.Kit.ParseDocument(raw)
	if err != nil {
		return BindingView{}, err
	}
	if err := doc.Verify(); err != nil {
		return BindingView{}, err
	}
	if ev == nil {
		return BindingView{}, errors.New("no binding to inspect")
	}
	var existing []party.Party
	if err := uc.Store.View(ctx, func(r ports.NamedReader) error {
		var err error
		existing, err = uc.Registry.List(r)
		return err
	}); err != nil {
		return BindingView{}, err
	}
	got, shared, err := uc.Relay.check(ctx, ev, doc.Identity.Fingerprint(), existing, uc.Clock.Now())
	if err != nil {
		return BindingView{}, err
	}
	return viewOf(got, shared), nil
}

// CheckRotationBinding checks the binding given with a rotation acceptance for
// the NEW identity of the pending announcement of name and returns the relay
// identity to pass in party.RotationAcceptance.Relay, and what to show
// (SPO-Xparty-INV-042). The registry is read as it is now; the acceptance
// re-checks the rest in its own transaction.
func (c RelayCheck) CheckRotationBinding(ctx context.Context, store ports.NamedStore, reg ports.PartyReader, newFP party.Fingerprint, ev *BindingEvidence, now time.Time) (*party.RelayIdentity, BindingView, error) {
	var existing []party.Party
	if err := store.View(ctx, func(r ports.NamedReader) error {
		var err error
		existing, err = reg.List(r)
		return err
	}); err != nil {
		return nil, BindingView{}, err
	}
	got, shared, err := c.check(ctx, ev, newFP, existing, now)
	if err != nil {
		return nil, BindingView{}, err
	}
	return &got.Relay, viewOf(got, shared), nil
}

// SetPeerRelay replaces or clears the relay identity of an enrolled party
// (`party relay peer NAME --binding FILE | --clear`). Run compares the
// confirmation it is given with the party's fingerprint. To record a binding
// the command passes the first four groups the operator typed, as enrollment
// does: the binding never replaces them (SPO-Xparty-PR-007). To clear, the
// command asks a yes or no question and passes the groups itself: clearing
// grants nothing and only stops delivery over a relay, so no typed groups are
// asked for it.
type SetPeerRelay struct {
	Store    ports.NamedStore
	Registry ports.PartyReader
	// SetRelay is partystore.Registry.SetRelay.
	SetRelay func(w ports.NamedWriter, name string, r *party.RelayIdentity) (party.Party, error)
	Clock    ports.Clock
	Relay    RelayCheck
}

// Run checks the confirmation against the party's fingerprint, then the
// binding (nil clears), and stores it with an audit event in one transaction.
//
// spec: SPO-Xparty-PR-007, SPO-Xparty-PRE-008
func (uc SetPeerRelay) Run(ctx context.Context, name, confirmation string, ev *BindingEvidence) (party.Party, error) {
	var cur party.Party
	if err := uc.Store.View(ctx, func(r ports.NamedReader) error {
		var err error
		cur, err = uc.Registry.ByName(r, name)
		return err
	}); err != nil {
		return party.Party{}, err
	}
	if !party.ConfirmPrefix(cur.Fingerprint, confirmation) {
		return party.Party{}, party.ErrConfirmation
	}
	now := uc.Clock.Now()
	var pre relaypeer.Evidence
	if ev != nil {
		var err error
		if pre, err = uc.Relay.verifyNoStore(ctx, ev, cur.Fingerprint, now); err != nil {
			return party.Party{}, err
		}
	}
	var out party.Party
	err := uc.Store.Update(ctx, func(w ports.NamedWriter) error {
		p, err := uc.Registry.ByName(w, name)
		if err != nil {
			return err
		}
		if p.Fingerprint != cur.Fingerprint {
			return party.ErrConfirmation // the record changed under the operator
		}
		var next *party.RelayIdentity
		kind, detail := "party-relay-cleared", p.Name
		if ev != nil {
			existing, err := uc.Registry.List(w)
			if err != nil {
				return err
			}
			if _, err := relaypeer.CheckClaim(pre.Relay.WalletKey, p.Fingerprint, existing); err != nil {
				return err
			}
			same, err := relaypeer.CheckUpdate(p.Relay, pre.Relay)
			if err != nil {
				return err
			}
			if same {
				out = p
				return nil
			}
			next = &pre.Relay
			kind, detail = "party-relay-set", fmt.Sprintf("%s wallet key=%x until=%d", p.Name, pre.Relay.WalletKey[:], pre.Relay.Until)
		}
		if out, err = uc.SetRelay(w, name, next); err != nil {
			return err
		}
		return AppendEvent(w, Event{At: now, Kind: kind, Peer: p.Fingerprint.String(), Detail: detail})
	})
	return out, err
}
