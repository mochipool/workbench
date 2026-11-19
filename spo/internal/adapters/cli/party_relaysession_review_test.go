package cli

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/relayloop"
	"github.com/mochipool/workbench/spo/internal/app/relayself"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

// The fixes of the review of work package 9 on the command line.

// busyTerm is a foreground terminal of a TUI whose relay session is logging
// in, logging out or stuck: busy, not logged in.
type busyTerm struct{ *ptTerm }

func (busyTerm) RelaySessionLive() bool { return false }
func (busyTerm) RelaySessionBusy() bool { return true }

// lendTerm is a foreground terminal of a TUI whose session is logged in and
// lends its revoke sending.
type lendTerm struct {
	*ptTerm
	mu    sync.Mutex
	books []any
}

func (*lendTerm) RelaySessionLive() bool { return true }
func (*lendTerm) RelaySessionBusy() bool { return true }
func (l *lendTerm) RelaySessionRevokes() relayloop.Revokes {
	return func(_ context.Context, book any) (map[string]error, error) {
		l.mu.Lock()
		l.books = append(l.books, book)
		l.mu.Unlock()
		return map[string]error{"relay-a": nil}, nil
	}
}

// While the TUI's session is busy (logging out, stuck), every command that
// would dial the relays refuses before it dials: serve, connect, forget and
// send-revokes.
//
// spec: SPO-Xmailbox-OUT-120, SPO-Xmailbox-OUT-117
func TestEveryRelayCommandRefusesWhileTheSessionIsBusy(t *testing.T) {
	s := newRelayScene(t)
	c := s.coord
	s.addRelayB(t)
	s.fake.down = map[string]bool{"relay-b": true}
	c.run(c.term(), "party", "relay", "forget", "--yes", "--as", "coordinator") //nolint:errcheck // leaves a revoke owed to relay-b
	s.fake.mu.Lock()
	s.fake.calls, s.fake.sends = nil, nil
	s.fake.mu.Unlock()
	for _, args := range [][]string{
		{"party", "serve", "--transport", "mailbox"},
		{"party", "relay", "forget", "--yes", "--as", "coordinator"},
		{"party", "relay", "send-revokes"},
	} {
		_, err := c.run(busyTerm{c.term()}, args...)
		if err == nil || !strings.Contains(err.Error(), "logging in, logging out or stuck") {
			t.Fatalf("%v: %v", args, err)
		}
	}
	b := s.bob
	b.edit = func(env *Env, k *PartyKit) { k.Relay = s.fake.ops(k.Relay) }
	if _, err := b.run(busyTerm{b.term()}, "party", "connect", "--transport", "mailbox"); err == nil || !strings.Contains(err.Error(), "logging in, logging out or stuck") {
		t.Fatalf("connect: %v", err)
	}
	if len(s.fake.callList()) != 0 || len(s.fake.sends) != 0 {
		t.Fatalf("a refused command dialled: %v, %d revoke-only sends", s.fake.callList(), len(s.fake.sends))
	}
}

// forget --lost while the TUI's session is busy is refused before its revoke is
// stored: nothing is signed or kept that could not be sent.
//
// spec: SPO-Xmailbox-OUT-120
func TestForgetLostRefusesWhileTheSessionIsBusyAndStoresNothing(t *testing.T) {
	s := newRelayScene(t)
	c := s.coord
	_, err := c.run(busyTerm{c.term()}, "party", "relay", "forget", "--lost", strings.Repeat("ab", 20), "--key", "coordpay")
	if err == nil || !strings.Contains(err.Error(), "logging in, logging out or stuck") {
		t.Fatalf("forget --lost while busy: %v", err)
	}
	st, err := relayself.Service{Store: s.C.Store, Device: s.C.Identity.Fingerprint}.Load(context.Background())
	if err != nil || len(st.Revokes) != 0 {
		t.Fatalf("a revoke was stored: %+v %v", st.Revokes, err)
	}
}

// While the TUI's session is logged in, sending revokes goes over the session's
// connections (the book the command loaded, with what it stored); no
// revoke-only connection of its own is dialled.
//
// spec: SPO-Xmailbox-OUT-120, SPO-Xmailbox-OUT-111
func TestRevokesGoThroughTheLoggedInSessionsConnections(t *testing.T) {
	s := newRelayScene(t)
	c := s.coord
	s.addRelayB(t)
	s.fake.down = map[string]bool{"relay-b": true}
	c.run(c.term(), "party", "relay", "forget", "--yes", "--as", "coordinator") //nolint:errcheck // a revoke owed to relay-b
	before := len(s.fake.sends)
	lt := &lendTerm{ptTerm: c.term()}
	c.run(lt, "party", "relay", "send-revokes") //nolint:errcheck // the session's relays answer for relay-a only
	if len(lt.books) != 1 || len(s.fake.sends) != before {
		t.Fatalf("lent %d, revoke-only sends %d (before %d)", len(lt.books), len(s.fake.sends), before)
	}
	if _, ok := lt.books[0].(*relayself.Book); !ok {
		t.Fatalf("the session was lent %T, not the workspace's book", lt.books[0])
	}
}

// memLock is the relay-login lock as a process table: one holder per path.
type memLock struct {
	mu   sync.Mutex
	held map[string]bool
}

func (m *memLock) lock(path string) (func() error, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.held[path] {
		return nil, ErrRelayLockHeld
	}
	m.held[path] = true
	return func() error { m.mu.Lock(); delete(m.held, path); m.mu.Unlock(); return nil }, nil
}

func (m *memLock) any() bool { m.mu.Lock(); defer m.mu.Unlock(); return len(m.held) > 0 }

// The relay-login lock: held for the life of a login and released at its
// clean logout; kept held when the teardown is stuck; a second holder (another
// process) is refused with the remedy, before anything is dialled; a
// revoke-only send holds it too.
//
// spec: SPO-Xmailbox-PRE-067
func TestTheRelayLoginLock(t *testing.T) {
	s := newRelayScene(t)
	c := s.coord
	ml := &memLock{held: map[string]bool{}}
	c.relayLock = ml.lock
	heldDuring := false
	if err := c.runUntil(c.term(), func() bool {
		heldDuring = ml.any()
		return s.saw("receive")
	}, "party", "relay", "login", "--as", "coordinator"); err != nil {
		t.Fatal(err)
	}
	if !heldDuring || ml.any() {
		t.Fatalf("held during the login %v, after the logout %v", heldDuring, ml.any())
	}
	// another process holds it: refused before connecting, with the remedy
	rel, _ := ml.lock(c.dir + "/" + WorkspaceFile + relayLockSuffix)
	s.fake.mu.Lock()
	s.fake.calls = nil
	s.fake.mu.Unlock()
	for _, args := range [][]string{{"party", "serve", "--transport", "mailbox"}, {"party", "relay", "login", "--as", "coordinator"}} {
		_, err := c.run(c.term(), args...)
		if !errors.Is(err, ErrRelayLockHeld) || !strings.Contains(err.Error(), "end it first") {
			t.Fatalf("%v with the lock held elsewhere: %v", args, err)
		}
	}
	if s.saw("connect") {
		t.Fatal("a refused login connected")
	}
	rel()
	// a stuck teardown keeps it held until the process ends
	s.fake.logoutErr = errors.New("engine stuck")
	err := c.runUntil(c.term(), func() bool { return s.saw("receive") }, "party", "relay", "login", "--as", "coordinator")
	if err == nil || !ml.any() {
		t.Fatalf("a stuck logout: %v, held %v", err, ml.any())
	}
	stuckLocks.mu.Lock()
	kept := len(stuckLocks.held)
	stuckLocks.mu.Unlock()
	if kept == 0 {
		t.Fatal("the stuck lock is not kept reachable")
	}
}

// A revoke stored by another command while a login runs is sent by that login
// within its next store sync, on revoke-only connections of its own tunnels,
// not only at the next login; the command says so truthfully.
//
// spec: SPO-Xmailbox-OUT-121
func TestARevokeStoredDuringALoginIsSentByIt(t *testing.T) {
	serveSyncEvery = 20 * time.Millisecond
	t.Cleanup(func() { serveSyncEvery = 2 * time.Second })
	s := newRelayScene(t)
	c := s.coord
	g := newPfixOf(t, s.C)
	g.edit = c.edit
	acted, out := false, ""
	other := relayport.Revoke{}
	err := c.runUntil(c.term(), func() bool {
		if !s.saw("receive") {
			return false
		}
		if !acted {
			acted = true
			out = g.must(g.term(), "party", "relay", "revoke", "--device", strings.Repeat("ab", 20), "--key", "coordpay")
			return false
		}
		s.fake.mu.Lock()
		defer s.fake.mu.Unlock()
		for _, rv := range s.fake.revokes {
			if rv.Kind == relayport.RevokeByWalletKey {
				other = rv
				return true
			}
		}
		return false
	}, "party", "relay", "login", "--as", "coordinator")
	if err != nil {
		t.Fatal(err)
	}
	if other.Kind != relayport.RevokeByWalletKey {
		t.Fatal("the login did not send the revoke stored while it ran")
	}
	if !strings.Contains(out, "A relay login or serve running for this workspace sends it within seconds") {
		t.Fatalf("the revoke command said: %s", out)
	}
}

// A login with no binding whose owed revoke's own tunnel did not stop is stuck,
// not logged out: under the TUI's host the last report is stuck.
//
// spec: SPO-Xmailbox-OUT-117, SPO-Xmailbox-OUT-111
func TestAFailedLoginWhoseRevokeTunnelSticksIsStuck(t *testing.T) {
	s := newRelayScene(t)
	c := s.coord
	s.addRelayB(t)
	s.fake.down = map[string]bool{"relay-b": true}
	c.run(c.term(), "party", "relay", "forget", "--yes", "--as", "coordinator") //nolint:errcheck // no binding; a revoke owed to relay-b
	s.fake.stuckErr = errors.Join(ErrTunnelDidNotStop, errors.New("relay relay-b"))
	h := &fakeHost{}
	_, err := c.run(hostTerm{c.term(), h}, "party", "relay", "login", "--as", "coordinator")
	_, reports := h.snapshot()
	if !errors.Is(err, ErrTunnelDidNotStop) || len(reports) == 0 || reports[len(reports)-1].Phase != relayloop.PhaseStuck {
		t.Fatalf("%v, reports %+v", err, reports)
	}
}

// eventHost is a host that records its posts and reports in order.
type eventHost struct {
	mu     sync.Mutex
	events []string
}

func (h *eventHost) Post(ctx context.Context, job func(context.Context) error) error {
	h.mu.Lock()
	h.events = append(h.events, "post")
	h.mu.Unlock()
	return relayloop.Inline.Post(ctx, job)
}

func (h *eventHost) Report(s relayloop.State) {
	h.mu.Lock()
	h.events = append(h.events, "report:"+string(s.Phase))
	h.mu.Unlock()
}

// The real login command's close under a TUI host: the book is saved through
// the host after the logging-out report, the clients log out, the identity the
// clients signed with is destroyed and signs nothing, the guarded buffers are
// back to their count before the login, and no goroutine of the session is
// left.
//
// spec: SPO-Xmailbox-SEC-083, SPO-Xmailbox-OUT-116, SPO-Xmailbox-INV-040
func TestTheRealLoginCloseUnderAHostLeavesNothing(t *testing.T) {
	fakenet.CheckLeaks(t)
	s := newRelayScene(t)
	c := s.coord
	h := &eventHost{}
	before := secret.Budget().Live
	if err := c.runUntil(hostTerm{c.term(), h}, func() bool { return s.saw("receive") }, "party", "relay", "login", "--as", "coordinator"); err != nil {
		t.Fatal(err)
	}
	if got := secret.Budget().Live; got != before {
		t.Fatalf("%d guarded buffers live after the logout, %d before the login", got, before)
	}
	s.fake.mu.Lock()
	local := s.fake.cfg.Local
	s.fake.mu.Unlock()
	if _, err := local.(relayport.AuthSigner).SignMailboxAuth(s.pin, s.pin, [32]byte{}, 1, [32]byte{}, [32]byte{}); err == nil {
		t.Fatal("the identity of the session still signs a login after the logout")
	}
	h.mu.Lock()
	ev := strings.Join(h.events, " ")
	h.mu.Unlock()
	i := strings.LastIndex(ev, "report:logging-out")
	if i < 0 || !strings.Contains(ev[i:], "post") || !strings.HasSuffix(ev, "report:logged-out") {
		t.Fatalf("the close's steps: %s", ev)
	}
	if calls := s.fake.callList(); calls[len(calls)-1] != "logout" {
		t.Fatalf("calls %v", calls)
	}
}

// A command that needs the workspace alone, refused while this TUI's own
// session holds it, is told to log out of the relays.
//
// spec: SPO-Xmailbox-OUT-120
func TestALockedWorkspaceUnderTheOwnSessionSaysLogOut(t *testing.T) {
	a := &app{term: busyTerm{}}
	if err := a.explainOwnSession(ErrLocked); err == nil || !strings.Contains(err.Error(), "log out of the relays first") {
		t.Fatalf("%v", err)
	}
	if err := (&app{term: liveTerm{}}).explainOwnSession(errors.New("other")); err.Error() != "other" {
		t.Fatalf("another error: %v", err)
	}
	if err := (&app{}).explainOwnSession(ErrLocked); !errors.Is(err, ErrLocked) || strings.Contains(err.Error(), "log out of the relays") {
		t.Fatalf("no session: %v", err)
	}
}

// The requests waiting for review of a signer's login are counted from the
// store, as their ids, at every sync.
//
// spec: SPO-Xmailbox-OUT-115
func TestASignersLoginCountsTheRequestsWaitingForReview(t *testing.T) {
	serveSyncEvery = 20 * time.Millisecond
	t.Cleanup(func() { serveSyncEvery = 2 * time.Second })
	s := newRelayScene(t)
	b := s.bob
	s.B.AddKey(custody.RolePayment, "bobpay")
	b.edit = func(env *Env, k *PartyKit) { k.Relay = s.fake.ops(k.Relay) }
	b.must(b.term(), "party", "relay", "bind", "--key", "bobpay")
	b.must(b.term(), "party", "relay", "add", "relay-a", "--node-key", "42"+"07"+strings.Repeat("00", 30), "--address-file", writeAddr(t, s.pin))
	h := &fakeHost{}
	if err := b.runUntil(hostTerm{b.term(), h}, func() bool {
		_, reports := h.snapshot()
		return len(reports) > 0 && reports[len(reports)-1].ReviewsKnown
	}, "party", "relay", "login", "--as", "signer"); err != nil {
		t.Fatal(err)
	}
}
