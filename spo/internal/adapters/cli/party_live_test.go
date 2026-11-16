package cli

import (
	"io"
	"sync"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// liveServer records the node keys a server is told to admit.
type liveServer struct {
	TailcatServer
	mu      sync.Mutex
	allowed map[party.NodeKey]bool
}

func (s *liveServer) Allow(k party.NodeKey)  { s.mu.Lock(); s.allowed[k] = true; s.mu.Unlock() }
func (s *liveServer) Revoke(k party.NodeKey) { s.mu.Lock(); delete(s.allowed, k); s.mu.Unlock() }

// After a rotation of a party with a node key, the revoked old record and the
// active new one share the key. What the running server does (revoke the old
// record, allow the new one, in that order) leaves the key admitted; revoking
// the new one then removes it.
//
// spec: SPO-Xparty-IF-005, SPO-Xparty-INV-032
func TestLiveAllowListFollowsTheActiveRecordOfASharedNodeKey(t *testing.T) {
	n := party.NodeKey{3, 3}
	mk := func(state party.State, seed byte) party.Party {
		id := party.Identity{Ed25519: party.Ed25519Public{seed}, X25519: party.X25519Public{seed, 1}, Node: &n}
		return party.Party{Identity: id, Fingerprint: id.Fingerprint(), State: state, Roles: []party.Role{party.RoleSigner}}
	}
	retired, next := mk(party.StateRevoked, 1), mk(party.StateActive, 2)
	srv := &liveServer{allowed: map[party.NodeKey]bool{n: true}}
	defer registerLive(srv)()
	revokeLive(retired)
	allowLive(next)
	if !srv.allowed[n] {
		t.Fatal("the node key of the rotated party is not admitted after the rotation")
	}
	// allowLive of a revoked record never admits its key
	delete(srv.allowed, n)
	allowLive(retired)
	if srv.allowed[n] {
		t.Fatal("a revoked record's node key was admitted")
	}
}

// recServer records Allow and Revoke calls in order.
type recServer struct {
	TailcatServer
	calls []string
}

func (s *recServer) Allow(k party.NodeKey)  { s.calls = append(s.calls, "allow") }
func (s *recServer) Revoke(k party.NodeKey) { s.calls = append(s.calls, "revoke") }

// A node key whose holder changed between two syncs (X revoked, Y enrolled with
// the same key) is revoked and allowed again, so X's open connection closes; an
// unchanged key does nothing.
//
// spec: SPO-Xparty-IF-005, SPO-Xparty-INV-005
func TestSyncFollowsAKeyThatChangedHands(t *testing.T) {
	n := party.NodeKey{4}
	x, y := party.Fingerprint{1}, party.Fingerprint{2}
	srv := &recServer{}
	known := map[party.NodeKey]party.Fingerprint{n: x}
	followRegistry(srv, known, map[party.NodeKey]party.Fingerprint{n: x}, io.Discard)
	if len(srv.calls) != 0 {
		t.Fatalf("an unchanged key: %v", srv.calls)
	}
	followRegistry(srv, known, map[party.NodeKey]party.Fingerprint{n: y}, io.Discard)
	if len(srv.calls) != 2 || srv.calls[0] != "revoke" || srv.calls[1] != "allow" || known[n] != y {
		t.Fatalf("a key that changed hands: %v", srv.calls)
	}
}
