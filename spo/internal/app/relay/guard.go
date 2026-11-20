package relay

import (
	"context"
	"sync"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// A Guard is the eviction guard of the binding registry: a device's binding
// may be dropped to make room, or for idleness, only when its queue is empty and
// no session of it is open ("queue empty and not connected", ADR 0014 decision
// 5). The registry does not know the mailbox store or the sessions, so the
// session layer supplies the fact: the composition root makes one Guard, hands
// Guard.Evictable to the registry's configuration and the same Guard to the
// Server, which marks a device connected from the moment it logs in until its
// last session ends.
//
// Evictable is cheap (one map read and a listing of at most one entry), takes no
// lock of the registry and never calls a writer of it: the registry calls it
// with its writers serialised, so a call back into Register, Revoke,
// SetExpectedSenders or Sweep would wait for itself. It reads only the mailbox
// store. Any error from the store is "not evictable" (fail closed).
//
// spec: SPO-Xmailbox-IF-014, SPO-Xmailbox-PRE-051 (obligation 16 of "What a
// session must still do in version 2")
type Guard struct {
	rd relayport.MailboxReader

	mu   sync.Mutex
	conn map[party.Fingerprint]int
}

// guardTimeout bounds the one store read of Evictable.
const guardTimeout = 2 * time.Second

// NewGuard makes a Guard that reads queues through rd.
func NewGuard(rd relayport.MailboxReader) *Guard {
	return &Guard{rd: rd, conn: map[party.Fingerprint]int{}}
}

// watch makes the guard read through the server's authority wrapper
// (authority.go): once the authority is lost the read fails and the guard says
// "not evictable" without reaching the store (SPO-Xmailbox-SEC-088). relay.New
// calls it.
func (g *Guard) watch(rd relayport.MailboxReader) {
	g.mu.Lock()
	g.rd = rd
	g.mu.Unlock()
}

// Evictable reports whether the binding of device may be dropped: no session of
// it is open and its queue is empty.
func (g *Guard) Evictable(device party.Fingerprint) bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	connected := g.conn[device] > 0
	rd := g.rd
	g.mu.Unlock()
	if connected || rd == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), guardTimeout)
	defer cancel()
	entries, _, err := rd.List(ctx, device, nil, 1)
	return err == nil && len(entries) == 0
}

// Connected is the number of open sessions of device.
func (g *Guard) Connected(device party.Fingerprint) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.conn[device]
}

func (g *Guard) enter(device party.Fingerprint) {
	g.mu.Lock()
	g.conn[device]++
	g.mu.Unlock()
}

func (g *Guard) leave(device party.Fingerprint) {
	g.mu.Lock()
	if g.conn[device]--; g.conn[device] <= 0 {
		delete(g.conn, device)
	}
	g.mu.Unlock()
}
