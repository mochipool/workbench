// Package relayroutes builds, from the party registry, where a put to each
// enrolled party goes at a relay and whose mail this device expects (ADR 0014
// decision 2 and 5, work package 8; spec Xmailbox IF-020 and OUT-096). The
// mailbox client's resolver reads the table without I/O; the caller refreshes it
// when the registry changes and hands the expected senders to the client's
// SetSenders when Refresh says they changed.
//
// A route is built from a party record alone: the key hash of a signing slot is
// never one, and a wallet key with a cold or unknown-role history in this store,
// that is a pool id named in a scope, or that is one of this workspace's own
// pool ids, is never looked up or put to.
package relayroutes

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaypeer"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ErrNoHistory: the table has no role-history source, so the cold-key rule
// cannot be checked and nothing routes.
var ErrNoHistory = errors.New("relayroutes: no role history source: nothing routes")

// ErrNoPoolSource: the table has no source of this workspace's own pool ids, so
// nothing routes.
var ErrNoPoolSource = errors.New("relayroutes: no source of this workspace's pool ids: nothing routes")

// Route is where a put to one party goes.
type Route struct {
	WalletKey party.WalletKey
	Device    party.Fingerprint
}

// Table is the routes and the expected senders, as of the last Refresh.
type Table struct {
	Store    ports.NamedStore
	Registry ports.PartyReader
	// History is the role history of a key identity in this store
	// (ports.RoleHistoryOf over the key index). Required.
	History func(ctx context.Context, id identity.Ref) (custody.RoleHistory, bool, error)
	// PoolIDs is this workspace's own pool ids (and any others it knows): a
	// wallet key that is one is no route. Required.
	PoolIDs func(ctx context.Context) (map[[28]byte]bool, error)

	mu         sync.RWMutex
	routes     map[party.Fingerprint]Route
	senders    []party.WalletKey
	unverified []string
	built      bool
	// started counts the refreshes begun; installed is the number of the one
	// whose table is installed. A refresh that read the registry before the
	// installed one installs nothing.
	started, installed uint64
	afterBuild         func() // a test's hook between the build and the install
}

// Refresh reads the registry once and rebuilds the table. changed reports that
// the expected-sender set differs from the one before (always true the first
// time). On an error the table is emptied: nothing routes until a Refresh
// succeeds, so an outbox item stays queued (ports.ErrNoRoute). Of two refreshes
// that run at once, the one that began later wins: an older read never
// replaces a newer table.
//
// spec: SPO-Xmailbox-IF-020, SPO-Xmailbox-OUT-096
func (t *Table) Refresh(ctx context.Context) (changed bool, err error) {
	t.mu.Lock()
	t.started++
	seq := t.started
	t.mu.Unlock()
	routes, senders, unverified, err := t.build(ctx)
	if t.afterBuild != nil {
		t.afterBuild()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if seq < t.installed {
		return false, nil // a later refresh installed a newer table
	}
	t.installed = seq
	if err != nil {
		t.routes, t.senders, t.unverified, t.built = nil, nil, nil, false
		return false, err
	}
	changed = !t.built || !slices.Equal(t.senders, senders)
	t.routes, t.senders, t.unverified, t.built = routes, senders, unverified, true
	return changed, nil
}

func (t *Table) build(ctx context.Context) (map[party.Fingerprint]Route, []party.WalletKey, []string, error) {
	if t.History == nil {
		return nil, nil, nil, ErrNoHistory
	}
	if t.PoolIDs == nil {
		return nil, nil, nil, ErrNoPoolSource
	}
	own, err := t.PoolIDs(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	var ps []party.Party
	if err := t.Store.View(ctx, func(r ports.NamedReader) error {
		var err error
		ps, err = t.Registry.List(r)
		return err
	}); err != nil {
		return nil, nil, nil, err
	}
	slices.SortFunc(ps, func(a, b party.Party) int { return strings.Compare(a.Name, b.Name) })
	routes := map[party.Fingerprint]Route{}
	var senders []party.WalletKey
	var unverified []string
	ok := map[party.WalletKey]bool{} // the verdict of the history check per key
	for _, p := range ps {
		if p.Active() && p.Relay != nil && p.Relay.Unverified != "" {
			unverified = append(unverified, p.Name)
		}
		k, dev, routed := routeOf(p, ps)
		if !routed || own[[28]byte(k)] {
			continue
		}
		verdict, seen := ok[k]
		if !seen {
			var err error
			if verdict, err = t.acceptable(ctx, k); err != nil {
				return nil, nil, nil, err
			}
			ok[k] = verdict
		}
		if !verdict {
			continue
		}
		routes[p.Fingerprint] = Route{WalletKey: k, Device: dev}
		if !slices.Contains(senders, k) {
			senders = append(senders, k)
		}
	}
	return routes, senders, unverified, nil
}

// routeOf is relaypeer.Route, with a wallet key that is a pool id named in any
// scope taken out.
func routeOf(p party.Party, all []party.Party) (party.WalletKey, party.Fingerprint, bool) {
	k, dev, ok := relaypeer.Route(p)
	if !ok || relaypeer.IsPoolID(k, all) {
		return party.WalletKey{}, party.Fingerprint{}, false
	}
	return k, dev, true
}

// acceptable applies the cold-key rule of a peer's wallet key. A history that
// cannot be read fails the whole refresh: no route is better than a route that
// was not checked.
func (t *Table) acceptable(ctx context.Context, k party.WalletKey) (bool, error) {
	id, err := identity.NewRef(identity.KindKeyHash, k[:])
	if err != nil {
		return false, nil
	}
	h, known, herr := t.History(ctx, id)
	if herr != nil {
		return false, herr
	}
	return relaypeer.CheckKeyHistory(k, h, known, nil) == nil, nil
}

// Resolve is the route of the party with fingerprint fp, as of the last
// Refresh. It does no I/O and takes no lock the client holds.
//
// spec: SPO-Xmailbox-IF-020
func (t *Table) Resolve(fp party.Fingerprint) (Route, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	r, ok := t.routes[fp]
	return r, ok
}

// Senders is the expected-sender list as of the last Refresh: the wallet keys of
// the parties that route, in the order of their names, once each.
//
// spec: SPO-Xmailbox-OUT-096
func (t *Table) Senders() []party.WalletKey {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return slices.Clone(t.senders)
}

// Unverified is the names of the active parties whose relay identity no longer
// verifies (no route), as of the last Refresh, for the command to report with
// the repair: spo party relay peer NAME --binding FILE, or --clear.
//
// spec: SPO-Xparty-OUT-007
func (t *Table) Unverified() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return slices.Clone(t.unverified)
}
