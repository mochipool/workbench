package relayroutes_test

import (
	"context"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/app/relayroutes"
	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// A wallet key that is one of this workspace's own pool ids (a pool known only
// by its id, its cold key never in this store) is no route; without a source
// of the own pool ids nothing routes.
//
// spec: SPO-Xmailbox-IF-020
func TestOwnPoolIDIsNoRoute(t *testing.T) {
	bob, carol := mkParty(1, "bob", 1), mkParty(2, "carol", 2)
	reg := &memRegistry{ps: []party.Party{bob, carol}}
	tb := newTable(t, reg, &hist{})
	tb.PoolIDs = func(context.Context) (map[[28]byte]bool, error) {
		return map[[28]byte]bool{[28]byte(carol.Relay.WalletKey): true}, nil
	}
	if _, err := tb.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := tb.Resolve(carol.Fingerprint); ok {
		t.Fatal("a wallet key that is this workspace's pool id routes")
	}
	if _, ok := tb.Resolve(bob.Fingerprint); !ok {
		t.Fatal("bob does not route")
	}
	if s := tb.Senders(); len(s) != 1 || s[0] != bob.Relay.WalletKey {
		t.Fatalf("senders %x", s)
	}
	tb.PoolIDs = nil
	if _, err := tb.Refresh(ctx); !errors.Is(err, relayroutes.ErrNoPoolSource) {
		t.Fatalf("no pool-id source: %v", err)
	}
	if _, ok := tb.Resolve(bob.Fingerprint); ok {
		t.Fatal("a route without a pool-id source")
	}
}

// A party whose relay identity no longer verifies has no route, and the table
// names it so the command can tell the operator.
//
// spec: SPO-Xmailbox-IF-020, SPO-Xparty-OUT-007
func TestUnverifiedRelayIdentityIsReported(t *testing.T) {
	bob, carol := mkParty(1, "bob", 1), mkParty(2, "carol", 2)
	carol.Relay.Unverified = "the signature does not verify"
	tb := newTable(t, &memRegistry{ps: []party.Party{bob, carol}}, &hist{})
	if _, err := tb.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := tb.Resolve(carol.Fingerprint); ok {
		t.Fatal("an unverifiable relay identity routes")
	}
	if u := tb.Unverified(); len(u) != 1 || u[0] != "carol" {
		t.Fatalf("unverified %v", u)
	}
}
