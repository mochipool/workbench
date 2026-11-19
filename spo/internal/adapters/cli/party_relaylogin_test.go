package cli

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/relayloop"
	"github.com/mochipool/workbench/spo/internal/platform/uihint"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// The relay login (ADR 0014 work package 9): spo party relay login on the
// command line, and the same command under the host of the TUI's session.

func (s *relayScene) saw(call string) bool {
	for _, x := range s.fake.callList() {
		if x == call {
			return true
		}
	}
	return false
}

// login exchanges over the relays until it is stopped and then logs out; a
// stuck tunnel fails it with "tunnel did not stop" and never says logged out.
//
// spec: SPO-Xmailbox-IF-028, SPO-Xmailbox-OUT-116, SPO-Xmailbox-OUT-117
func TestLoginExchangesUntilStoppedAndLogsOut(t *testing.T) {
	s := newRelayScene(t)
	c := s.coord
	if err := c.runUntil(c.term(), func() bool { return s.saw("receive") }, "party", "relay", "login", "--as", "coordinator"); err != nil {
		t.Fatalf("login: %v\n%s", err, c.err.String())
	}
	calls := s.fake.callList()
	if calls[0] != "connect" || calls[len(calls)-1] != "logout" {
		t.Fatalf("calls %v", calls)
	}
	if out := c.out.String(); !strings.Contains(out, "Exchanging over 1 relay(s): relay-a") || !strings.Contains(out, "Logged out of the relays.") {
		t.Fatalf("out:\n%s", out)
	}
	s.fake.logoutErr = errors.New("engine stuck")
	s.fake.mu.Lock()
	s.fake.calls = nil
	s.fake.mu.Unlock()
	err := c.runUntil(c.term(), func() bool { return s.saw("receive") }, "party", "relay", "login", "--as", "coordinator")
	if err == nil || !strings.Contains(err.Error(), "tunnel did not stop") || strings.Contains(c.out.String(), "Logged out of the relays") {
		t.Fatalf("a stuck tunnel: %v\nout:\n%s", err, c.out.String())
	}
}

// At login the binding's end is shown, and within 14 days of it the reminder to
// renew it.
//
// spec: SPO-Xmailbox-OUT-115
func TestLoginRemindsWithinFourteenDaysOfTheBindingsEnd(t *testing.T) {
	s := newRelayScene(t)
	c := s.coord
	if err := c.runUntil(c.term(), func() bool { return s.saw("receive") }, "party", "relay", "login", "--as", "coordinator"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(c.out.String(), "renew it with spo party relay bind") {
		t.Fatalf("a binding of 90 days reminded at once:\n%s", c.out.String())
	}
	s.clock.Advance(77 * 24 * time.Hour) // 13 days left of the 90
	s.fake.mu.Lock()
	s.fake.calls = nil
	s.fake.mu.Unlock()
	if err := c.runUntil(c.term(), func() bool { return s.saw("receive") }, "party", "relay", "login", "--as", "coordinator"); err != nil {
		t.Fatal(err)
	}
	if out := c.out.String(); !strings.Contains(out, "(in 12 day(s)): renew it with spo party relay bind") && !strings.Contains(out, "(in 13 day(s)): renew it with spo party relay bind") {
		t.Fatalf("no reminder 13 days before the end:\n%s", out)
	}
}

// login ends itself at relay_login_max, measured on the exchange's clock, with
// the full logout.
//
// spec: SPO-Xmailbox-OUT-118, SPO-Xmailbox-IF-028
func TestLoginEndsItselfAtTheLimit(t *testing.T) {
	s := newRelayScene(t)
	c := s.coord
	c.cfg = WorkspaceConfig{Network: "preview", Mode: c.mode, Party: &PartyConfig{RelayLoginMax: 90 * time.Minute}}
	base := time.Now()
	var calls atomic.Int64
	relayNow = func() time.Time {
		if calls.Add(1) > 20 {
			return base.Add(90 * time.Minute)
		}
		return base
	}
	t.Cleanup(func() { relayNow = time.Now })
	out, err := c.run(c.term(), "party", "relay", "login", "--as", "coordinator")
	if err != nil {
		t.Fatalf("login: %v\n%s", err, c.err.String())
	}
	if !strings.Contains(out, "The login limit of 1h30m0s (relay_login_max) was reached.") || !strings.Contains(out, "Logged out of the relays.") {
		t.Fatalf("out:\n%s", out)
	}
	if calls := s.fake.callList(); calls[len(calls)-1] != "logout" {
		t.Fatalf("calls %v", calls)
	}
	if c.cfg.Party = nil; (&partyRun{o: WireOptions{Config: c.cfg}}).loginMax() != 12*time.Hour {
		t.Fatal("the default login limit is not 12 hours")
	}
}

// login ends itself when the binding in use has ended by the device's clock.
//
// spec: SPO-Xmailbox-OUT-118
func TestLoginEndsWhenTheBindingEnds(t *testing.T) {
	s := newRelayScene(t)
	c := s.coord
	advanced := false
	err := c.runUntil(c.term(), func() bool {
		if !advanced && s.saw("receive") {
			advanced = true
			s.clock.Advance(91 * 24 * time.Hour)
		}
		return false // the command ends by itself
	}, "party", "relay", "login", "--as", "coordinator")
	if err != nil {
		t.Fatal(err)
	}
	if out := c.out.String(); !strings.Contains(out, "The binding of this device ended") || !strings.Contains(out, "Logged out of the relays.") {
		t.Fatalf("out:\n%s", out)
	}
}

// goneStore is a store whose handle stops working when gone is set.
type goneStore struct {
	SealedStore
	gone *atomic.Bool
}

var errHandleGone = errors.New("the handle lost its lock")

func (g goneStore) View(ctx context.Context, fn func(ports.Reader) error) error {
	if g.gone.Load() {
		return errHandleGone
	}
	return g.SealedStore.View(ctx, fn)
}

func (g goneStore) Update(ctx context.Context, fn func(ports.Writer) error) error {
	if g.gone.Load() {
		return errHandleGone
	}
	return g.SealedStore.Update(ctx, fn)
}

// login ends itself when a store step says that the handle can no longer be
// used; another command's errors do not count.
//
// spec: SPO-Xmailbox-OUT-118
func TestLoginEndsWhenTheStoreHandleIsGone(t *testing.T) {
	serveSyncEvery = 20 * time.Millisecond
	t.Cleanup(func() { serveSyncEvery = 2 * time.Second })
	s := newRelayScene(t)
	c := s.coord
	var gone atomic.Bool
	c.wrapSealed = func(st SealedStore) SealedStore { return goneStore{st, &gone} }
	c.storeGone = func(err error) bool { return errors.Is(err, errHandleGone) }
	err := c.runUntil(c.term(), func() bool {
		if s.saw("receive") {
			gone.Store(true)
		}
		return false
	}, "party", "relay", "login", "--as", "coordinator")
	if err != nil {
		t.Fatal(err)
	}
	if out := c.out.String(); !strings.Contains(out, "The workspace can no longer be used by this session") || !strings.Contains(out, "Logged out of the relays.") {
		t.Fatalf("out:\n%s", out)
	}
}

// fakeHost runs the store steps of a hosted login on a goroutine of its own
// and records the reports.
type fakeHost struct {
	mu      sync.Mutex
	posts   int
	reports []relayloop.State
}

func (h *fakeHost) Post(ctx context.Context, job func(context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	h.mu.Lock()
	h.posts++
	h.mu.Unlock()
	done := make(chan error, 1)
	go func() { done <- job(ctx) }()
	return <-done
}

func (h *fakeHost) Report(s relayloop.State) {
	h.mu.Lock()
	h.reports = append(h.reports, s)
	h.mu.Unlock()
}

func (h *fakeHost) snapshot() (int, []relayloop.State) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.posts, append([]relayloop.State(nil), h.reports...)
}

// hostTerm is the terminal of the TUI's session run: it offers the host.
type hostTerm struct {
	*ptTerm
	host relayloop.Host
}

func (h hostTerm) SessionHost() relayloop.Host { return h.host }

// liveTerm is a foreground terminal of a TUI whose relay session is logged in.
type liveTerm struct{ *ptTerm }

func (liveTerm) RelaySessionLive() bool { return true }

// Under the TUI's host the login runs its store steps through the host and
// reports connecting, logged in, logging out and logged out, with each relay
// connected and the binding's end; a stuck tunnel reports stuck.
//
// spec: SPO-Xmailbox-IF-029, SPO-Xmailbox-OUT-114, SPO-Xmailbox-OUT-115, SPO-Xmailbox-OUT-117
func TestLoginUnderTheTUIsHost(t *testing.T) {
	s := newRelayScene(t)
	c := s.coord
	h := &fakeHost{}
	noted := false
	if err := c.runUntil(hostTerm{c.term(), h}, func() bool {
		p, reports := h.snapshot()
		if !s.saw("receive") || p <= 1 {
			return false
		}
		if !noted {
			// the relay answers its first exchange: until then it is waiting
			noted = true
			s.fake.mu.Lock()
			note := s.fake.cfg.Note
			s.fake.mu.Unlock()
			note(RelayNote{Relay: "relay-a", Outcome: "acked"})
		}
		last := reports[len(reports)-1]
		return len(last.Relays) == 1 && last.Relays[0].Class == relayloop.RelayConnected
	}, "party", "relay", "login", "--as", "coordinator"); err != nil {
		t.Fatal(err)
	}
	posts, reports := h.snapshot()
	var phases, classes []string
	sawRelay := false
	for _, r := range reports {
		if len(phases) == 0 || phases[len(phases)-1] != string(r.Phase) {
			phases = append(phases, string(r.Phase))
		}
		if len(r.Relays) == 1 && r.Relays[0].Name == "relay-a" && r.BindingUntil > s.clock.Now().Unix() {
			sawRelay = true
			if c := string(r.Relays[0].Class); len(classes) == 0 || classes[len(classes)-1] != c {
				classes = append(classes, c)
			}
		}
	}
	if strings.Join(phases, " ") != "connecting logged-in logging-out logged-out" || !sawRelay || posts < 2 {
		t.Fatalf("phases %v, relay shown %v, %d posts", phases, sawRelay, posts)
	}
	// SPO-Xmailbox-OUT-115: waiting until the first exchange, connected after it
	if strings.Join(classes, " ") != "waiting connected" {
		t.Fatalf("the relay's classes: %v", classes)
	}
	s.fake.logoutErr = errors.New("engine stuck")
	h = &fakeHost{}
	err := c.runUntil(hostTerm{c.term(), h}, func() bool { return s.saw("receive") }, "party", "relay", "login", "--as", "coordinator")
	_, reports = h.snapshot()
	if err == nil || reports[len(reports)-1].Phase != relayloop.PhaseStuck || !strings.Contains(reports[len(reports)-1].Err, "tunnel did not stop") {
		t.Fatalf("stuck: %v, last report %+v", err, reports[len(reports)-1])
	}
}

// While the TUI's session is logged in, the commands that would log this
// device in a second time refuse, before they connect.
//
// spec: SPO-Xmailbox-OUT-120
func TestTheExchangeCommandsRefuseWhileTheTUISessionIsLive(t *testing.T) {
	s := newRelayScene(t)
	c := s.coord
	for _, args := range [][]string{{"party", "serve", "--transport", "mailbox"}, {"party", "relay", "forget", "--yes", "--as", "coordinator"}} {
		_, err := c.run(liveTerm{c.term()}, args...)
		if err == nil || !strings.Contains(err.Error(), "relay session of the TUI is logged in") {
			t.Fatalf("%v: %v", args, err)
		}
	}
	// connect --transport mailbox, the signer's exchange
	b := s.bob
	b.edit = func(env *Env, k *PartyKit) { k.Relay = s.fake.ops(k.Relay) }
	if _, err := b.run(liveTerm{b.term()}, "party", "connect", "--transport", "mailbox"); err == nil || !strings.Contains(err.Error(), "relay session of the TUI is logged in") {
		t.Fatalf("connect: %v", err)
	}
	if s.saw("connect") {
		t.Fatal("a refused command connected")
	}
}

// The TUI finds the relay commands by their annotation: one login, forget, and
// the commands that only queue mail.
//
// spec: SPO-Xmailbox-IF-029, SPO-Xmailbox-OUT-120
func TestTheRelayCommandsCarryTheirSessionAnnotation(t *testing.T) {
	root := hintRoot(t)
	want := map[string]string{
		"party relay login": uihint.RelayLogin, "party relay forget": uihint.RelayForget,
		"party request queue": uihint.RelayOutbox, "party approve": uihint.RelayOutbox, "party refuse": uihint.RelayOutbox,
		"party outbox status": uihint.RelayOutbox, "party outbox retry": uihint.RelayOutbox,
	}
	for path, kind := range want {
		c := find(root, path)
		if c == nil || c.Annotations[uihint.RelaySession] != kind {
			t.Errorf("%s: %v", path, c)
		}
	}
	logins := 0
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if c.Annotations[uihint.RelaySession] == uihint.RelayLogin {
			logins++
		}
		for _, s := range c.Commands() {
			walk(s)
		}
	}
	walk(root)
	if logins != 1 {
		t.Fatalf("%d commands are marked as the login", logins)
	}
}

// The composite's notes become the classes the session shows.
//
// spec: SPO-Xmailbox-OUT-115
func TestRelayNotesBecomeRelayClasses(t *testing.T) {
	for _, tc := range []struct {
		n    RelayNote
		want relayloop.RelayClass
		ok   bool
	}{
		{RelayNote{Outcome: "identity_refused", Identity: ports.ErrIdentityRefused, Backoff: time.Second}, relayloop.RelayIdentity, true},
		{RelayNote{Outcome: "failed", Pinned: true, Backoff: time.Second}, relayloop.RelayPinned, true},
		{RelayNote{Outcome: "failed", Backoff: 4 * time.Second}, relayloop.RelayBackingOff, true},
		{RelayNote{Outcome: "stored"}, relayloop.RelayConnected, true},
		{RelayNote{Outcome: "acked"}, relayloop.RelayConnected, true},
		{RelayNote{Outcome: "duplicate"}, relayloop.RelayConnected, true},
		{RelayNote{Outcome: "no_route"}, "", false},
		{RelayNote{Outcome: "abandoned"}, "", false},
	} {
		if got, ok := relayClass(tc.n); got != tc.want || ok != tc.ok {
			t.Errorf("%+v: %q %v", tc.n, got, ok)
		}
	}
}
