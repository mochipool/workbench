package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/app/relayloop"
	"github.com/mochipool/workbench/spo/internal/app/relayroutes"
	"github.com/mochipool/workbench/spo/internal/app/relayself"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/platform/uihint"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// Several relays (ADR 0014 work package 10, SPO-Xmailbox-IF-025, OUT-108,
// OUT-109): the relay list of this device, the exchange of serve and connect
// over every listed relay at once, and the order of "forget this device" over
// them. This package builds no tunnel and no mailbox client: the composition
// root gives RelayOps.Connect, CheckAddress and SendRevokes.

var (
	// ErrRelayLockHeld is Deps.RelayLock's refusal: another process holds the
	// relay-login lock of this workspace (SPO-Xmailbox-PRE-067).
	ErrRelayLockHeld = errors.New("another spo process holds the relay login of this workspace")
	// ErrTunnelDidNotStop marks the error of a close or of a revoke-only send
	// whose tunnel did not stop (relayloop.ErrTunnelDidNotStop): the composition
	// root wraps it, the command says "tunnel did not stop" and a TUI is stuck.
	ErrTunnelDidNotStop = relayloop.ErrTunnelDidNotStop
	// errSessionBusy: the TUI's relay session is logging in, logging out or
	// stuck, and a command that would dial the relays refuses.
	errSessionBusy = errors.New("the relay session of the TUI is logging in, logging out or stuck (tunnel did not stop): " +
		"wait until it has logged in or ended (Relay session shows where it stands), or quit spo and start it again")
)

// RelayEndpoint is one listed relay with its address opened. The callee copies
// what it needs; the caller destroys the buffer.
type RelayEndpoint struct {
	Name    string
	Key     party.NodeKey // pinned
	Port    uint16
	Address *secret.Buffer
}

// RelayNote is one relay's outcome, for the operator: its name, what happened
// and, for a refused identity, the refusal (the remedy is told once per binding).
type RelayNote struct {
	Relay    string
	Kind     string
	Outcome  string
	Identity error
	// Pinned: the relay's key is not the pinned one (the tunnel or the client
	// said so). Backoff: the pause of a relay whose receive failed.
	Pinned  bool
	Backoff time.Duration
}

// relayClass is the class of a relay that a note shows, and whether the note
// changes it (SPO-Xmailbox-OUT-115).
func relayClass(n RelayNote) (relayloop.RelayClass, bool) {
	switch {
	case n.Identity != nil:
		return relayloop.RelayIdentity, true
	case n.Pinned:
		return relayloop.RelayPinned, true
	case n.Backoff > 0:
		return relayloop.RelayBackingOff, true
	case n.Outcome == "stored" || n.Outcome == "acked" || n.Outcome == "duplicate":
		// an exchange with the relay succeeded: until the first one it is
		// shown waiting (SPO-Xmailbox-OUT-115)
		return relayloop.RelayConnected, true
	}
	return "", false
}

// sessionClient is the composite as a session's steps may use it: it has no
// Send. The one way an envelope leaves a session is the outbox's flush over the
// transport taken once at the opening, so the cold-key rule of the outbox
// covers everything a session sends (SPO-Xmailbox-SEC-082; an architecture
// test holds this file to it).
type sessionClient interface {
	Receive(ctx context.Context) (ports.Received, error)
	AckContext(ctx context.Context) error
	SetBinding(statement, key []byte) error
	SetSenders([]party.WalletKey)
	SendRevokes(ctx context.Context) map[string]error
	Logout(within time.Duration) error
}

// RelayConnectConfig is what RelayOps.Connect needs.
type RelayConnectConfig struct {
	Relays     []RelayEndpoint
	NodeKey    *secret.Buffer // this device's tailcat node private key
	DERPMapURL string
	// Local signs the logins (it implements relayport.AuthSigner).
	Local          ports.LocalIdentity
	Statement, Key []byte // the binding presented
	Senders        []party.WalletKey
	Resolve        func(to party.Fingerprint) (wallet party.WalletKey, device party.Fingerprint, ok bool)
	Book           relayport.RevokeBook
	Clock          ports.Clock
	Note           func(RelayNote)
}

// RelayClient is this device over every listed relay (mailbox.Multi).
type RelayClient interface {
	ports.EnvelopeSender
	ports.EnvelopeContextAcker
	Transport() ports.Transport
	SetBinding(statement, key []byte) error
	SetSenders([]party.WalletKey)
	// SendRevokes sends the book's revokes to every relay on revoke-only
	// connections and returns each relay's own error, by name (nil: the
	// exchange ran; what each relay recorded is told to the book with its
	// name, relayport.RelayRevokeBook).
	SendRevokes(ctx context.Context) map[string]error
	// Logout closes the clients and then every tunnel dialer within the bound;
	// an error means a tunnel did not stop.
	Logout(within time.Duration) error
}

// RelaySendConfig is what RelayOps.SendRevokes needs: revoke-only connections
// to every listed relay, with no binding and no signer.
type RelaySendConfig struct {
	Relays     []RelayEndpoint
	NodeKey    *secret.Buffer
	DERPMapURL string
	Clock      ports.Clock
	Book       relayport.RevokeBook
}

// relayLogout bounds the teardown of the clients and tunnels at the end of an
// exchange.
var relayLogout = 10 * time.Second

// relayRearmEvery is how often an exchange over the relays makes the
// unanswered requests go out again.
var relayRearmEvery = 10 * time.Minute

// tellRemedyOnce tells the remedy of a refused identity once per binding
// statement per process (SPO-Xmailbox-OUT-108), and reports whether it told it
// now. The exchange loop tells it through its relayloop.Teller.
func tellRemedyOnce(w io.Writer, statement []byte, err error) bool {
	return relayloop.TellRemedyOnce(func(f string, a ...any) { fmt.Fprintf(w, f, a...) }, statement, err, relayRemedy)
}

// openRelays opens the listed relays' addresses and this device's node key. done
// destroys them.
func (r *partyRun) openRelays(ctx context.Context) ([]RelayEndpoint, *secret.Buffer, func(), error) {
	list, err := relayself.Relays(ctx, r.s.Store)
	if err != nil {
		return nil, nil, func() {}, err
	}
	var eps []RelayEndpoint
	done := func() {
		for _, e := range eps {
			e.Address.Destroy()
		}
	}
	for _, rl := range list {
		buf, err := r.openSecret(ctx, relayself.AddressRef(rl.Name))
		if err != nil {
			done()
			return nil, nil, func() {}, fmt.Errorf("the address of the relay %s: %w", rl.Name, err)
		}
		eps = append(eps, RelayEndpoint{Name: rl.Name, Key: rl.Key, Port: rl.Port, Address: buf})
	}
	if len(eps) == 0 {
		return nil, nil, func() {}, nil
	}
	nk, err := r.openSecret(ctx, ports.NamedRef{Name: "local", Kind: ports.TailcatNodeKey})
	if errors.Is(err, ports.ErrNotFound) {
		done()
		return nil, nil, func() {}, errors.New("this identity has no tailcat node key, which the relays' tunnels admit: make the identity with spo party init --tailcat, and give the relay operators its node key")
	}
	if err != nil {
		done()
		return nil, nil, func() {}, err
	}
	return eps, nk, func() { done(); nk.Destroy() }, nil
}

// relaySender is relayself's Send: the pending revokes to every listed relay on
// revoke-only connections. Nil when the build sends none. In the TUI, while
// its relay session is logged in, the revokes go over the session's own
// connections (no second dial with the same node key); while the session is
// logging in, logging out or stuck the send is refused; a revoke-only tunnel
// that does not stop makes the TUI stuck (SPO-Xmailbox-OUT-120, OUT-117). The
// relay-login lock is held while it dials (SPO-Xmailbox-PRE-067).
func (r *partyRun) relaySender() func(ctx context.Context, book relayport.RevokeBook) (map[string]error, error) {
	ops := r.kit().Relay
	if ops.SendRevokes == nil {
		return nil
	}
	return func(ctx context.Context, book relayport.RevokeBook) (map[string]error, error) {
		if send := r.a.sessionRevokes(); send != nil {
			return send(ctx, book)
		}
		if r.a.relaySessionBusy() {
			return nil, errSessionBusy
		}
		release, err := r.holdRelays()
		if err != nil {
			return nil, err
		}
		eps, nk, done, err := r.openRelays(ctx)
		if err != nil {
			release(false)
			return nil, err
		}
		defer done()
		if len(eps) == 0 {
			release(false)
			return nil, relayself.ErrNoSender
		}
		_, derp := r.tailcatSettings()
		errs, err := ops.SendRevokes(ctx, RelaySendConfig{Relays: eps, NodeKey: nk, DERPMapURL: derp, Clock: r.env.Clock, Book: book})
		stuck := errors.Is(err, ErrTunnelDidNotStop)
		release(stuck)
		if stuck {
			r.a.tunnelStuck(err)
		}
		return errs, err
	}
}

// holdRelays takes the workspace's relay-login lock for this command, or
// counts one more use when it holds it already (a login that sends the owed
// revokes first). The release keeps the lock held when stuck: a tunnel that did
// not stop may still be online, and the kernel drops the lock when the process
// ends (SPO-Xmailbox-PRE-067).
func (r *partyRun) holdRelays() (func(stuck bool), error) {
	if r.relayHeld > 0 || r.a.d.RelayLock == nil {
		r.relayHeld++
		return func(bool) { r.relayHeld-- }, nil
	}
	path := r.a.workspaceFile() + relayLockSuffix
	rel, err := r.a.d.RelayLock(path)
	if errors.Is(err, ErrRelayLockHeld) {
		return nil, fmt.Errorf("%w: end it first (Ctrl-C in that process, or Log out of relays in its TUI), then run this again. "+
			"The lock (%s) is the kernel's and ends with that process", err, path)
	}
	if err != nil {
		return nil, err
	}
	r.relayHeld++
	return func(stuck bool) {
		r.relayHeld--
		if stuck {
			keepHeld(rel)
			return
		}
		rel() //nolint:errcheck // closing the descriptor drops the lock
	}, nil
}

// relayLockSuffix names the relay-login lock file beside the workspace file.
const relayLockSuffix = ".relay.lock"

// stuckLocks keeps the release of every lock left held by a stuck teardown
// reachable, so that no finalizer closes its descriptor (which would drop the
// lock) before the process ends.
var stuckLocks struct {
	mu   sync.Mutex
	held []func() error
}

func keepHeld(rel func() error) {
	stuckLocks.mu.Lock()
	stuckLocks.held = append(stuckLocks.held, rel)
	stuckLocks.mu.Unlock()
}

// liveBook is the book an exchange gives its clients: it can be replaced by a
// fresh load (after forget stored a new revoke) without a new connection.
type liveBook struct {
	mu sync.Mutex
	b  *relayself.Book
}

var _ relayport.RelayRevokeBook = (*liveBook)(nil)

func (l *liveBook) set(b *relayself.Book) { l.mu.Lock(); l.b = b; l.mu.Unlock() }
func (l *liveBook) get() *relayself.Book  { l.mu.Lock(); defer l.mu.Unlock(); return l.b }
func (l *liveBook) Pending() []relayport.Revoke {
	return l.get().Pending()
}
func (l *liveBook) Result(rv relayport.Revoke, o relayport.RevokeOutcome) { l.get().Result(rv, o) }
func (l *liveBook) ResultAt(relay string, rv relayport.Revoke, o relayport.RevokeOutcome) {
	l.get().ResultAt(relay, rv, o)
}

// relaySession is one exchange over every listed relay.
type relaySession struct {
	r      *partyRun
	svc    relayself.Service
	client sessionClient // no Send: see sessionClient
	// transport is the composite as the outbox's flush sends over it, taken
	// once at the opening: the only path by which an envelope leaves.
	transport ports.Transport
	local     ports.LocalIdentity
	routes    *relayroutes.Table
	book      *liveBook
	tell      *relayloop.Teller // the error output and the binding in use, shared with the client's callback
	status    *relayloop.Status // what the session shows (nil: nothing)
	from      int64
	until     atomic.Int64 // the end of the binding in use
	names     []string
	reviews   func(ctx context.Context) ([]string, error) // the requests waiting for review (nil: not this role)
	savedAt   int                                         // the book's changes at the last save
	due       atomic.Bool                                 // a revoke stored since the book was loaded is to be sent now
	closed    atomic.Bool                                 // the close has begun: nothing more is lent
}

// swapBook makes b the book the clients use and the one saved (savedAt -1:
// saved at the next sync).
func (s *relaySession) swapBook(b *relayself.Book, saved int) {
	s.book.set(b)
	s.savedAt = saved
}

// relayRemind is how long before the end of the binding a login reminds the
// operator to renew it (ADR 0014 decision 3, "Lifetime").
const relayRemind = 14 * 24 * time.Hour

// sessionHost is the host of the relay session when this command runs as the
// TUI's background session: its terminal offers one (SPO-Xmailbox-IF-029).
func (a *app) sessionHost() relayloop.Host {
	if h, ok := a.term.(interface{ SessionHost() relayloop.Host }); ok {
		return h.SessionHost()
	}
	return nil
}

// relaySessionLive reports that the TUI this command runs in has a relay
// session logged in (SPO-Xmailbox-OUT-120).
func (a *app) relaySessionLive() bool {
	l, ok := a.term.(interface{ RelaySessionLive() bool })
	return ok && l.RelaySessionLive()
}

// relaySessionBusy reports that the TUI this command runs in has a relay
// session in any phase but logged out: logging in, logged in, logging out or
// stuck. Every command that would dial the relays refuses then, unless it goes
// through the logged-in session (SPO-Xmailbox-OUT-120).
func (a *app) relaySessionBusy() bool {
	b, ok := a.term.(interface{ RelaySessionBusy() bool })
	return ok && b.RelaySessionBusy()
}

// inTUI reports that this command runs in the TUI.
func (a *app) inTUI() bool {
	_, ok := a.term.(interface{ RelaySessionBusy() bool })
	return ok
}

// sessionRevokes is the revoke sending the TUI's logged-in session lends, or
// nil.
func (a *app) sessionRevokes() func(ctx context.Context, book relayport.RevokeBook) (map[string]error, error) {
	l, ok := a.term.(interface{ RelaySessionRevokes() relayloop.Revokes })
	if !ok {
		return nil
	}
	send := l.RelaySessionRevokes()
	if send == nil {
		return nil
	}
	return func(ctx context.Context, book relayport.RevokeBook) (map[string]error, error) { return send(ctx, book) }
}

// tunnelStuck tells the TUI this command runs in that a tunnel it dialled did
// not stop (SPO-Xmailbox-OUT-117).
func (a *app) tunnelStuck(err error) {
	if s, ok := a.term.(interface{ RelayTunnelStuck(string) }); ok {
		s.RelayTunnelStuck(err.Error())
	}
}

// explainOwnSession: a command that needs the workspace alone (a rekey, a
// restore) is refused with ErrLocked while this TUI's own relay session holds
// the workspace open; it is told to log out of the relays, not to wait for
// "another spo process".
func (a *app) explainOwnSession(err error) error {
	if err == nil || !errors.Is(err, ErrLocked) || !a.relaySessionBusy() {
		return err
	}
	return Explain(err, "the relay session of this TUI holds the workspace open: log out of the relays first (Log out of relays), then run the command again")
}

// refuseBusy is the refusal of a command that would log this device in, or
// dial the relays, while the TUI's session is logged in or busy.
func (a *app) refuseBusy() error {
	switch {
	case a.relaySessionLive():
		// one login of this device at a time (SPO-Xmailbox-OUT-120)
		return errors.New("the relay session of the TUI is logged in and already exchanges over the relays: log out of the relays first, or let the session do it")
	case a.relaySessionBusy():
		return errSessionBusy
	}
	return nil
}

// openRelaySession connects this device to every listed relay with its stored
// binding, its routes and expected senders and its revoke book. status, when
// set, is given each relay's class and the binding's end.
func (r *partyRun) openRelaySession(ctx context.Context, status *relayloop.Status) (*relaySession, error) {
	ops := r.kit().Relay
	if ops.Connect == nil {
		return nil, errors.New("this build has no relay transport")
	}
	svc, err := r.self(ctx)
	if err != nil {
		return nil, err
	}
	st, err := svc.Load(ctx)
	if err != nil {
		return nil, err
	}
	if st.Binding == nil {
		// a revoke still owed to a relay needs no binding: it goes first
		// (SPO-Xmailbox-OUT-111), then the refusal; a revoke-only tunnel that
		// did not stop goes with the refusal, so the session is stuck, not
		// logged out (SPO-Xmailbox-OUT-117)
		refusal := errors.New("this device has no relay binding: bind it first with spo party relay bind")
		if stuck := r.sendOwedRevokes(ctx, svc); stuck != nil {
			return nil, errors.Join(refusal, stuck)
		}
		return nil, refusal
	}
	eps, nk, done, err := r.openRelays(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	if len(eps) == 0 {
		return nil, errors.New("no relay is listed: add one with spo party relay add NAME --node-key HEX --address-file FILE")
	}
	routes := &relayroutes.Table{Store: r.s.Store, Registry: r.kit().Registry, History: r.history(), PoolIDs: r.knownPoolIDs}
	if _, err := routes.Refresh(ctx); err != nil {
		return nil, err
	}
	for _, n := range routes.Unverified() {
		fmt.Fprintf(r.a.d.Err, "the relay identity of %s no longer verifies: it is not routed (spo party relay peer %s --binding FILE)\n", safeText(n), safeText(n))
	}
	b, err := svc.Book(ctx)
	if err != nil {
		return nil, err
	}
	local, err := r.kit().Kit.Local(ctx)
	if err != nil {
		return nil, partyIdentityErr(err)
	}
	s := &relaySession{r: r, svc: svc, local: local, routes: routes, book: &liveBook{b: b}, from: st.Binding.From,
		tell: relayloop.New(r.a.d.Err, st.Binding.Statement, relayRemedy), status: status}
	s.until.Store(st.Binding.Until)
	for _, e := range eps {
		s.names = append(s.names, e.Name)
	}
	r.remind(st.Binding.Until, status)
	_, derp := r.tailcatSettings()
	tell := s.tell
	c, err := ops.Connect(RelayConnectConfig{
		Relays: eps, NodeKey: nk, DERPMapURL: derp, Local: local,
		Statement: st.Binding.Statement, Key: st.Binding.Key, Senders: routes.Senders(),
		Resolve: func(to party.Fingerprint) (party.WalletKey, party.Fingerprint, bool) {
			rt, ok := routes.Resolve(to)
			return rt.WalletKey, rt.Device, ok
		},
		Book: s.book, Clock: r.env.Clock,
		// called on the composite's member goroutines: only the teller and the
		// status are used, both under their own locks
		Note: func(n RelayNote) {
			if n.Identity != nil && tell.Remedy(n.Identity) {
				text := tell.LastRemedy()
				status.Update(func(st *relayloop.State) { st.Remedy = text })
			}
			if class, ok := relayClass(n); ok {
				status.Relay(n.Relay, class, n.Backoff)
			}
		},
	})
	if err != nil {
		local.Destroy()
		return nil, err
	}
	s.client, s.transport = c, c.Transport()
	for _, n := range s.names {
		// Connect dials nothing: a relay is waiting until its first exchange
		// (SPO-Xmailbox-OUT-115)
		status.Relay(n, relayloop.RelayWaiting, 0)
	}
	s.noteOwed(ctx)
	return s, nil
}

// remind says when the binding ends and, within 14 days of its end, to renew it
// (SPO-Xmailbox-OUT-115).
func (r *partyRun) remind(until int64, status *relayloop.Status) {
	left := time.Unix(until, 0).Sub(r.env.Clock.Now())
	text := ""
	if left <= relayRemind {
		text = fmt.Sprintf("the binding of this device ends on %s (in %d day(s)): renew it with spo party relay bind",
			time.Unix(until, 0).UTC().Format(time.DateTime+" MST"), max(int64(left/(24*time.Hour)), 0))
		fmt.Fprintf(r.a.d.Out, "relay: %s.\n", text)
	}
	status.Update(func(st *relayloop.State) { st.BindingUntil, st.Reminder = until, text })
}

// noteOwed gives the status the number of revokes a listed relay still owes.
func (s *relaySession) noteOwed(ctx context.Context) {
	if s.status == nil {
		return
	}
	if st, err := s.svc.Status(ctx); err == nil {
		s.status.Update(func(x *relayloop.State) { x.Owed = len(st.Owed) })
	}
}

// sync follows the store: the routes and the expected senders (SetSenders when
// they changed), a binding renewed by another command (SetBinding), and the
// revoke book (saved when the clients learnt something). It returns the error
// of reading the store, so that a handle that can no longer be used ends a
// login (SPO-Xmailbox-OUT-118).
func (s *relaySession) sync(ctx context.Context) error {
	changed, rerr := s.routes.Refresh(ctx)
	if rerr == nil && changed {
		s.client.SetSenders(s.routes.Senders())
	}
	st, err := s.svc.Load(ctx)
	if err == nil && st.Binding != nil && st.Binding.From > s.from {
		if err := s.client.SetBinding(st.Binding.Statement, st.Binding.Key); err == nil {
			s.tell.SetStatement(st.Binding.Statement)
			s.from = st.Binding.From
			s.until.Store(st.Binding.Until)
			s.status.Update(func(x *relayloop.State) { x.BindingUntil = st.Binding.Until })
			fmt.Fprintln(s.r.a.d.Out, "relay: the new binding is used from the next connection")
		}
	}
	s.saveBook(ctx)
	s.followBook(ctx)
	s.noteOwed(ctx)
	if s.reviews != nil {
		if ids, err := s.reviews(ctx); err == nil {
			s.status.Update(func(x *relayloop.State) { x.Reviews, x.ReviewsKnown = ids, true })
		}
	}
	return errors.Join(rerr, err)
}

// followBook loads the revoke book again when the stored revokes changed since
// it was loaded (another command stored a revoke, or dropped one): the clients
// use the new book at once, and a revoke that is new is sent now, on the loop's
// goroutine (sendDue), not at the next connection. The book was saved just
// before, so nothing it learnt is lost (SPO-Xmailbox-OUT-111).
func (s *relaySession) followBook(ctx context.Context) {
	fresh, err := s.svc.Book(ctx)
	if err != nil {
		return
	}
	had := map[string]bool{}
	for _, rv := range s.book.get().Pending() {
		had[relayself.ShortID(rv)] = true
	}
	added, changed := false, len(fresh.Pending()) != len(had)
	for _, rv := range fresh.Pending() {
		if !had[relayself.ShortID(rv)] {
			added, changed = true, true
		}
	}
	if !changed {
		return
	}
	s.swapBook(fresh, fresh.Changes())
	if added {
		s.due.Store(true)
	}
}

// sendDue sends the book's revokes on revoke-only connections when the sync
// found a new one (Exchange.Between): what it learns is saved at the next sync.
func (s *relaySession) sendDue(ctx context.Context) {
	if !s.due.Swap(false) {
		return
	}
	for name, err := range s.client.SendRevokes(ctx) {
		if err != nil && ctx.Err() == nil {
			s.tell.Failure("sending the revokes to "+name, err)
		}
	}
}

// saveBook saves the revoke book when it learnt something since the last save.
func (s *relaySession) saveBook(ctx context.Context) {
	b := s.book.get()
	n := b.Changes()
	if n == s.savedAt {
		return
	}
	if err := b.Save(context.WithoutCancel(ctx)); err != nil {
		s.tell.Printf("relay: saving the revoke book: %v\n", err)
		return
	}
	s.savedAt = n
}

// relayBookSave bounds the save of the revoke book at logout, which waits for
// the host's executor (SPO-Xmailbox-OUT-116).
var relayBookSave = 2 * time.Second

// close logs out: the revoke book is saved through the host (bounded), then the
// clients and every tunnel are closed, and the local identity is destroyed. A
// tunnel that did not stop is an error that says so (SPO-Xmailbox-OUT-116,
// OUT-117).
func (s *relaySession) close(ctx context.Context, host relayloop.Host) error {
	if host == nil {
		host = relayloop.Inline
	}
	s.closed.Store(true)
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), relayBookSave)
	if err := host.Post(sctx, func(jctx context.Context) error { s.saveBook(jctx); return nil }); err != nil {
		s.tell.Printf("relay: the revoke book was not saved at logout (%v); its revokes stay owed and are sent again\n", err)
	}
	cancel()
	err := s.client.Logout(relayLogout)
	s.local.Destroy()
	if err != nil {
		s.tell.Printf("tunnel did not stop: %v. The device may still be registered at the relay; exit this process.\n", err)
		return fmt.Errorf("%w: %w", ErrTunnelDidNotStop, err)
	}
	return nil
}

// errRevokeOwed: a revoke is not recorded at every listed relay yet.
var errRevokeOwed = errors.New("a revoke is not recorded at every listed relay yet")

// reportOwed says, per listed relay, whether it recorded the revoke with the
// short id (every pending revoke when id is empty), naming the cause of each
// that did not (the relay's own error from relayErrs, else its answer), and how
// the revoke will be completed. It returns errRevokeOwed when a relay still owes
// one (SPO-Xmailbox-OUT-111).
func (r *partyRun) reportOwed(ctx context.Context, svc relayself.Service, id string, relayErrs map[string]error) error {
	st, err := svc.Status(ctx)
	if err != nil {
		return err
	}
	w := r.a.d.Out
	owed := map[string]int{}
	until := int64(0)
	found := id == ""
	for _, v := range st.Revokes {
		if id != "" && v.ID != id {
			continue
		}
		found = true
		for _, n := range v.OwedTo {
			owed[n]++
			until = max(until, v.Until)
		}
	}
	if !found {
		return fmt.Errorf("the revoke %s is no longer pending: see spo party relay status", id)
	}
	var missing []string
	for _, n := range st.Relays {
		if owed[n] == 0 {
			fmt.Fprintf(w, "  relay %s: recorded\n", n)
			continue
		}
		missing = append(missing, n)
		why := "it did not record it (it answered refused, or the revoke waits for a later connection)"
		if e := relayErrs[n]; e != nil {
			why = "not reached: " + safeText(e.Error())
		}
		if id == "" {
			fmt.Fprintf(w, "  relay %s: %d revoke(s) NOT recorded: %s\n", n, owed[n], why)
		} else {
			fmt.Fprintf(w, "  relay %s: NOT recorded: %s\n", n, why)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	fmt.Fprintf(w, "The revoke stays pending for %s until %s. A binding stays valid at a relay that has not recorded the revoke.\n"+
		"Complete it with: spo party relay send-revokes (it needs no binding and signs nothing; run it until every relay recorded it).\n"+
		"spo party serve and spo party connect --transport mailbox also send it first.\n",
		strings.Join(missing, ", "), time.Unix(until, 0).UTC().Format(time.DateTime+" MST"))
	return fmt.Errorf("%w: %s", errRevokeOwed, strings.Join(missing, ", "))
}

// sendOwedRevokes sends the pending revokes on revoke-only connections when a
// listed relay still owes one, and reports it: what serve and connect do before
// they refuse a device with no binding (SPO-Xmailbox-OUT-111). It returns the
// error of a revoke-only tunnel that did not stop, nil otherwise.
func (r *partyRun) sendOwedRevokes(ctx context.Context, svc relayself.Service) error {
	if svc.Send == nil {
		return nil
	}
	st, err := svc.Status(ctx)
	if err != nil || len(st.Owed) == 0 {
		return nil
	}
	fmt.Fprintln(r.a.d.Out, "Sending the revokes still owed to the relays (no binding is needed for that):")
	rep, err := svc.SendPending(ctx)
	if err != nil && !errors.Is(err, relayself.ErrNoSender) {
		fmt.Fprintf(r.a.d.Err, "sending the revokes: %v\n", err)
	}
	if err := r.reportOwed(ctx, svc, "", rep.Relays); err != nil && !errors.Is(err, errRevokeOwed) {
		fmt.Fprintf(r.a.d.Err, "%v\n", err)
	}
	if errors.Is(err, ErrTunnelDidNotStop) {
		return err
	}
	return nil
}

// relayExchange is serve and connect over the relays (SPO-Xmailbox-OUT-108):
// flush the outbox, receive and handle, acknowledge, follow the store, until the
// command is stopped.
//
// The loop is relayloop.Exchange, run by relayloop.Serve (SPO-Xmailbox-IF-027).
// The store steps go through the host: at once on the command line, on the
// TUI's executor for its background session. A login (o.login) also ends at
// its limit, at the end of the binding in use and when the store handle can no
// longer be used (SPO-Xmailbox-OUT-118).
func (r *partyRun) relayExchange(ctx context.Context, handle multisig.Handler, after func(multisig.Handled), o exchangeOpts) (err error) {
	a := r.a
	host := o.host
	if host == nil {
		if err := a.refuseBusy(); err != nil {
			return err
		}
		host = relayloop.Inline
	}
	// one login of this device at a time, across processes too
	// (SPO-Xmailbox-PRE-067); kept when the teardown is stuck
	release, err := r.holdRelays()
	if err != nil {
		return err
	}
	defer func() { release(errors.Is(err, ErrTunnelDidNotStop)) }()
	status := relayloop.NewStatus(host)
	end, err := relayloop.Serve(ctx, status, func() (*relayloop.Exchange, func() error, error) {
		s, err := r.openRelaySession(ctx, status)
		if err != nil {
			return nil, nil, err
		}
		s.reviews = o.reviews
		lender, _ := host.(relayloop.Lender)
		closeFn := func() error {
			if lender != nil {
				lender.Lend(nil)
			}
			return s.close(ctx, host)
		}
		ob := r.node().Outbox()
		if err := ob.Rearm(ctx); err != nil {
			return nil, closeFn, err
		}
		fmt.Fprintf(a.d.Out, "Exchanging over %d relay(s): %s. Stop with Ctrl-C (that logs out).\n", len(s.names), strings.Join(s.names, ", "))
		e := sessionExchange(s, host, status, ob.Flush, ob.Rearm, handle, after)
		if o.login {
			e.Limit = o.limit
			e.Expired = func() bool { return r.env.Clock.Now().Unix() > s.until.Load() }
			e.Gone = a.d.StoreGone
		}
		if lender != nil {
			// foreground commands of the TUI send revokes over this session's
			// connections while it is logged in (SPO-Xmailbox-OUT-120)
			lender.Lend(s.lendRevokes)
		}
		return e, closeFn, nil
	})
	if err != nil {
		if errors.Is(err, ErrTunnelDidNotStop) {
			a.tunnelStuck(err)
		}
		return err
	}
	switch end {
	case relayloop.EndLimit:
		fmt.Fprintf(a.d.Out, "The login limit of %v (relay_login_max) was reached.\n", o.limit)
	case relayloop.EndExpired:
		fmt.Fprintln(a.d.Out, "The binding of this device ended: renew it with spo party relay bind, then log in again.")
	case relayloop.EndStoreGone:
		fmt.Fprintln(a.d.Out, "The workspace can no longer be used by this session (it was locked or changed elsewhere): open it again and log in again.")
	}
	fmt.Fprintln(a.d.Out, "Logged out of the relays.")
	return nil
}

// sessionExchange is the loop of one session over its relays. Its steps are
// given the session's narrow client (no Send) and the transport only through
// flush, the outbox's own Flush: no step can put an envelope that the outbox's
// cold-key rule has not seen (SPO-Xmailbox-SEC-082).
func sessionExchange(s *relaySession, host relayloop.Host, status *relayloop.Status,
	flush func(ctx context.Context, tr ports.Transport) (int, error), rearm func(ctx context.Context) error,
	handle multisig.Handler, after func(multisig.Handled)) *relayloop.Exchange {
	var last multisig.Handled
	tr := s.transport
	return &relayloop.Exchange{
		Client: s.client, Host: host, Tell: s.tell, Status: status,
		Flush: func(ctx context.Context) (int, error) { return flush(ctx, tr) },
		Handle: func(ctx context.Context, rcv ports.Received) (relayloop.Handled, error) {
			h, err := handle(ctx, rcv)
			last = h
			return relayloop.Handled{Refused: h.Refused, HasSender: h.HasSender}, err
		},
		After: func(relayloop.Handled) {
			if after != nil {
				after(last)
			}
			line := handledLine(last)
			status.Update(func(st *relayloop.State) { st.Last = line })
		},
		Sync:    s.sync,
		Between: s.sendDue,
		Rearm:   rearm,
		Window:  connectReceiveWindow, SyncEvery: serveSyncEvery, RearmEvery: relayRearmEvery,
		Now: relayNow, Wall: relayWall, Sleep: sleepCtx, WatchEvery: relayWatchEvery,
	}
}

// lendRevokes is the session's revoke sending as it is lent to the TUI's
// foreground commands: the book the command loaded (with the revoke it stored)
// becomes the book of the session's clients, and its revokes go on revoke-only
// connections of the session's own tunnels. The command saves the book; the
// session saves it again at its next sync.
func (s *relaySession) lendRevokes(ctx context.Context, book any) (map[string]error, error) {
	if s.closed.Load() {
		return nil, errSessionBusy
	}
	b, ok := book.(*relayself.Book)
	if !ok {
		return nil, errors.New("the relay session sends only the workspace's own revoke book")
	}
	s.swapBook(b, -1)
	return s.client.SendRevokes(ctx), nil
}

// exchangeOpts is what a relay login adds to an exchange: the host of the TUI's
// session (nil: the command line), the end of a login, and the count of the
// requests waiting for review.
type exchangeOpts struct {
	host    relayloop.Host
	limit   time.Duration
	login   bool
	reviews func(ctx context.Context) ([]string, error)
}

// relayWall is the wall clock of the login limit, without its monotonic
// reading (a test's seam); relayWatchEvery is how often the limit and the
// binding's end are looked at.
var (
	relayWall       = func() time.Time { return time.Now().Round(0) }
	relayWatchEvery = time.Second
)

// relayNow is the clock of the exchange's intervals and of the login limit (a
// test's seam): time.Now, whose differences are monotonic.
var relayNow = time.Now

// handledLine is printHandled's line of one envelope, for the session's state.
func handledLine(h multisig.Handled) string {
	var b strings.Builder
	printHandled(&b, h)
	return strings.TrimSpace(b.String())
}

// loginMax is the limit of a relay login: relay_login_max, or 12 hours.
func (r *partyRun) loginMax() time.Duration {
	if p := r.o.Config.Party; p != nil && p.RelayLoginMax > 0 {
		return p.RelayLoginMax
	}
	return defaultRelayLoginMax
}

// defaultRelayLoginMax is the default of relay_login_max (ADR 0014 decision 9).
const defaultRelayLoginMax = 12 * time.Hour

// partyRelayLoginCommand is spo party relay login (SPO-Xmailbox-IF-028): the
// exchange of this device's role over every listed relay until it is stopped.
// The TUI runs it as its background relay session (SPO-Xmailbox-IF-029).
func (a *app) partyRelayLoginCommand() *cobra.Command {
	var as string
	cmd := &cobra.Command{
		Use:   "login [--as coordinator|signer]",
		Short: "Log in to the listed relays and receive until stopped (stopping logs out)",
		Long: `Log this device in to every listed relay with its binding and exchange: send
what waits in the outbox, fetch what waits at the relays and hand it to this
machine's coordinator or signer (--as when it is both), acknowledge it. Nothing
is approved here: a signing request waits for spo party review and approve.

On the command line logging out is the end of this command: Ctrl-C (SIGINT) or
SIGTERM closes the connections and the tunnels and destroys the identity in
memory. There is no logout command. In spo tui the login runs in the background
and "Log out of relays" ends it without closing the TUI.

The login ends itself after relay_login_max ([party] in spo.toml, default 12h),
when the binding ends, and when the workspace can no longer be used. A device
with no binding is told to bind first; revokes still owed to a relay are sent
before that.`,
		Annotations: map[string]string{uihint.RelaySession: uihint.RelayLogin},
		Args:        cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.party(cmd, nil, []Need{CapClock}, func(ctx context.Context, r *partyRun) error {
				handle, reviews, err := r.roleHandler(ctx, as)
				if err != nil {
					return err
				}
				return r.relayExchange(ctx, handle, func(h multisig.Handled) {
					if h.Effect != "duplicate" {
						printHandled(a.d.Out, h)
					}
				}, exchangeOpts{host: a.sessionHost(), limit: r.loginMax(), login: true, reviews: reviews})
			})
		},
	}
	cmd.Flags().StringVar(&as, "as", "", "which role handles what arrives, when this machine is both: coordinator or signer")
	return cmd
}

// connectRelays is connect --transport mailbox: the signer over every listed
// relay. Receiving never signs; --interactive reviews and asks, as over tailcat.
func (r *partyRun) connectRelays(ctx context.Context, f *signerFlags, interactive bool) error {
	a := r.a
	sg, why, err := r.signer(ctx, f.snapshot, r.dirs(f.inbox, f.outbox))
	if err != nil {
		return err
	}
	fmt.Fprintf(a.d.Out, "This machine's own chain view: %s.\n", why)
	if !sg.Resolver.IsSet() {
		fmt.Fprintln(a.d.Err, "WARNING: this signer has no chain view of its own, so EVERY request that arrives over a relay will be refused automatically and in silence (SPO-Xparty-PRE-007). Give it a view (light mode uses its own provider; or --own-snapshot PATH), or exchange requests by file.")
	}
	handle := func(ctx context.Context, rcv ports.Received) (multisig.Handled, error) {
		h, err := sg.Handle(ctx, rcv)
		return h, mapSignerErr(err)
	}
	return r.relayExchange(ctx, handle, func(h multisig.Handled) {
		if h.Effect == "duplicate" {
			return
		}
		printHandled(a.d.Out, h)
		if interactive && !h.Refused && h.Effect == "stored" {
			if err := a.reviewAndApprove(ctx, r, sg, h.Request, fmt.Sprintf("%x", h.Request[:4]), f.full); err != nil {
				fmt.Fprintf(a.d.Err, "not approved: %v\n", err)
			}
		}
	}, exchangeOpts{})
}

// relayForget is "forget this device" over the relays, in the order of ADR 0014
// decision 8 (SPO-Xmailbox-OUT-109): log in, fetch and hand the queue to this
// device's role, store the device revoke keeping the binding, send it to every
// relay, log out, and only then delete the binding. It returns the revoke and
// each relay's own error of the send; whether each relay recorded it is in the
// store (reportOwed says it).
//
// The binding is deleted even when a relay did not record the revoke: the
// revoke is device-signed and is sent on revoke-only connections that need no
// binding (spo party relay send-revokes, and serve and connect before they
// refuse), so keeping the binding would buy nothing but a device that can still
// log in, which the operator asked to end.
func (r *partyRun) relayForget(ctx context.Context, handle multisig.Handler) (got relayport.Revoke, errs map[string]error, err error) {
	a := r.a
	if err := a.refuseBusy(); err != nil {
		return relayport.Revoke{}, nil, err
	}
	release, err := r.holdRelays()
	if err != nil {
		return relayport.Revoke{}, nil, err
	}
	defer func() {
		stuck := errors.Is(err, ErrTunnelDidNotStop)
		release(stuck)
		if stuck {
			a.tunnelStuck(err)
		}
	}()
	s, err := r.openRelaySession(ctx, nil)
	if err != nil {
		return relayport.Revoke{}, nil, err
	}
	handle = forgetHandleWrap(handle)
	// (1) the queue: everything waiting is handled first, because a relay deletes
	// the queue of a revoked device. An envelope whose handling fails is tried
	// once: when it comes again it is acknowledged without being handled and
	// counted, so the drain does not spin on it (the relay deletes it with the
	// revoke anyway).
	n, start := 0, time.Now()
	failed := map[[32]byte]bool{}
	skipped := 0
	for n+len(failed)+skipped < forgetDrainMax && time.Since(start) < forgetDrainFor && ctx.Err() == nil {
		rctx, cancel := context.WithTimeout(ctx, forgetDrainIdle)
		rcv, err := s.client.Receive(rctx)
		cancel()
		if err != nil {
			if !errors.Is(err, context.DeadlineExceeded) {
				s.tell.Remedy(err)
				s.tell.Printf("fetching the queue: %v (going on with the revoke)\n", err)
			}
			break
		}
		id := sha256.Sum256(rcv.Envelope)
		if failed[id] {
			if err := s.client.AckContext(ctx); err != nil {
				s.tell.Printf("acknowledging: %v\n", err)
			}
			skipped++
			continue
		}
		h, herr := handle(ctx, rcv)
		if herr != nil {
			failed[id] = true
			s.tell.Printf("handling an envelope: %v (it is not tried again)\n", herr)
			continue
		}
		if err := s.client.AckContext(ctx); err != nil {
			s.tell.Printf("acknowledging: %v\n", err)
		}
		printHandled(a.d.Out, h)
		n++
	}
	fmt.Fprintf(a.d.Out, "Handled %d envelope(s) from the relays' queue.\n", n)
	if len(failed) > 0 {
		fmt.Fprintf(a.d.Out, "%d envelope(s) could not be handled; each was tried once (%d acknowledged afterwards without handling). The relays delete the queue with the revoke.\n",
			len(failed), skipped)
	}
	// (2) the revoke, stored with the binding kept
	got, err = s.svc.ForgetRevoke(ctx)
	if err != nil {
		return relayport.Revoke{}, nil, errors.Join(err, s.close(ctx, nil))
	}
	// (3) sent to every relay on revoke-only connections of the same tunnels;
	// the book learns which relay recorded it
	if b, err := s.svc.Book(ctx); err == nil {
		s.book.set(b)
		s.savedAt = 0
	}
	errs = s.client.SendRevokes(ctx)
	// (4) log out (the book is saved first)
	if err := s.close(ctx, nil); err != nil {
		return got, errs, err
	}
	// (5) only then the binding
	if err := s.svc.DropBinding(ctx); err != nil {
		return got, errs, err
	}
	return got, errs, nil
}

// Bounds of the queue fetched before a forget.
var (
	forgetDrainMax  = 1000
	forgetDrainFor  = 5 * time.Minute
	forgetDrainIdle = 2 * time.Second
	// forgetHandleWrap wraps the handler of the drain (a test's seam).
	forgetHandleWrap = func(h multisig.Handler) multisig.Handler { return h }
)

// forgetHandler is the handler of this device's role for the queue of forget.
func (r *partyRun) forgetHandler(ctx context.Context, as string) (multisig.Handler, error) {
	h, _, err := r.roleHandler(ctx, as)
	return h, err
}

// roleHandler is the handler of this device's role and, for a signer, the
// short ids of the requests waiting for its review, read from the store (the
// TUI shows them; never text a peer chose).
func (r *partyRun) roleHandler(ctx context.Context, as string) (multisig.Handler, func(context.Context) ([]string, error), error) {
	role, err := r.inboxRole(ctx, as)
	if err != nil {
		return nil, nil, err
	}
	if role == "signer" {
		sg, _, err := r.signer(ctx, "", r.dirs("", ""))
		if err != nil {
			return nil, nil, err
		}
		reviews := func(ctx context.Context) ([]string, error) {
			pending, err := sg.Pending(ctx)
			if err != nil {
				return nil, err
			}
			ids := make([]string, 0, len(pending))
			for _, p := range pending {
				ids = append(ids, hex.EncodeToString(p.ID[:]))
			}
			return ids, nil
		}
		return func(ctx context.Context, rcv ports.Received) (multisig.Handled, error) {
			out, err := sg.Handle(ctx, rcv)
			return out, mapSignerErr(err)
		}, reviews, nil
	}
	co, err := r.coordinator()
	if err != nil {
		return nil, nil, err
	}
	return co.Handle, nil, nil
}

// ---- the relay list ----

func (a *app) partyRelayAddCommand() *cobra.Command {
	var (
		nodeKey, addrFile string
		port              uint16
	)
	cmd := &cobra.Command{
		Use:   "add NAME --node-key HEX --address-file FILE [--port N]",
		Short: "List a relay this device sends to and fetches from",
		Long: `Add a relay to this device's list. Its operator gives you two things: the relay's
node key (64 hex digits, from spo-relay init-key or serve; compare it with the
operator by another channel) and its address, which holds the relay's
pre-shared key and is a secret. Put the address in a file only you can read and
name it with --address-file; it is sealed in the workspace, and you can delete
the file afterwards. The address is checked to lead to the node key before
anything is stored. Give the operator this device's tailcat node key (spo party
show): the relay's tunnel admits only the node keys its operator lists.

Up to 8 relays. A device sends to all of them and fetches from all of them; any
one storing an envelope is enough.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := decodeHexArg("--node-key", nodeKey, 32)
			if err != nil || len(raw) != 32 {
				return errors.New("--node-key: the relay's node key is 64 hex digits")
			}
			pin := party.NodeKey(raw)
			return a.party(cmd, nil, []Need{CapClock}, func(ctx context.Context, r *partyRun) error {
				ops := r.kit().Relay
				if ops.CheckAddress == nil {
					return errors.New("this build has no relay transport")
				}
				addr, err := readAddressFile(addrFile)
				if err != nil {
					return err
				}
				defer addr.Destroy()
				nk, err := r.openSecret(ctx, ports.NamedRef{Name: "local", Kind: ports.TailcatNodeKey})
				if errors.Is(err, ports.ErrNotFound) {
					return errors.New("this identity has no tailcat node key: make the identity with spo party init --tailcat")
				}
				if err != nil {
					return err
				}
				defer nk.Destroy()
				if port == 0 {
					port = relayself.DefaultRelayPort
				}
				if err := ops.CheckAddress(RelayEndpoint{Name: args[0], Key: pin, Port: port, Address: addr}, nk); err != nil {
					return fmt.Errorf("the address does not lead to that node key, or is not a relay address: %w. Nothing was stored", err)
				}
				if err := relayself.AddRelay(ctx, r.s.Store, relayself.Relay{Name: args[0], Key: pin, Port: port}, addr); err != nil {
					return err
				}
				fmt.Fprintf(a.d.Out, "Listed the relay %s (node key %s, port %d).\n", args[0], hex.EncodeToString(pin[:]), port)
				fmt.Fprintf(a.d.Out, "The address is sealed in the workspace; delete %s if you no longer need it.\n", addrFile)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&nodeKey, "node-key", "", "the relay's node key, 64 hex digits (pinned)")
	cmd.Flags().StringVar(&addrFile, "address-file", "", "a file that holds the relay's address (a secret)")
	cmd.Flags().Uint16Var(&port, "port", 0, "the relay's port inside the tunnel (default 7346)")
	return cmd
}

// readAddressFile reads a relay address, which holds the relay's pre-shared key
// (SPO-Xmailbox-SEC-081). The file is opened as the signing key files of an
// import are (readKeyFile): without following a symbolic link and without
// waiting, so a FIFO is refused at once by the regular-file check on the
// descriptor. Like the relay's own key file (SPO-Xmailbox-SEC-077) it must have
// no group or other permission bit: a key file of an import is only warned
// about, but this file was written for this command, so a loose mode is refused
// with the chmod that fixes it. A file over relayself.MaxAddressBytes (and two
// bytes of line end) is refused before it is read. The bytes go straight into
// guarded memory and are never copied to the Go heap; the address is one line,
// trailing white space removed.
func readAddressFile(path string) (*secret.Buffer, error) {
	if path == "" {
		return nil, errors.New("--address-file FILE is required")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("the address file %s cannot be opened: %v (a symbolic link is refused: name the file itself)", path, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	const most = relayself.MaxAddressBytes + 2
	switch {
	case !st.Mode().IsRegular():
		return nil, fmt.Errorf("the address file %s is not a regular file", path)
	case st.Size() > most:
		return nil, fmt.Errorf("the address file %s is larger than an address may be (%d bytes)", path, relayself.MaxAddressBytes)
	case st.Mode().Perm()&0o077 != 0:
		return nil, fmt.Errorf("the address file %s holds the relay's pre-shared key and others may read or write it (mode %04o): chmod 600 %s, and get the address from the operator again if others could read it",
			path, st.Mode().Perm(), path)
	}
	raw, err := secret.TryRead(io.LimitReader(f, most+1))
	if err != nil {
		return nil, err
	}
	defer raw.Destroy()
	end := 0
	err = raw.Use(func(b []byte) error {
		if len(b) > most {
			return fmt.Errorf("the address file %s is larger than an address may be (%d bytes)", path, relayself.MaxAddressBytes)
		}
		end = len(b)
		for end > 0 && strings.IndexByte(" \t\r\n", b[end-1]) >= 0 {
			end--
		}
		for _, c := range b[:end] {
			if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
				end = 0
				break
			}
		}
		if end == 0 {
			return fmt.Errorf("the address file %s does not hold one address on one line", path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return secret.Fill(end, func(dst []byte) error {
		return raw.Use(func(b []byte) error { copy(dst, b[:end]); return nil })
	})
}

func (a *app) partyRelayListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Show the relays this device uses",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.party(cmd, nil, nil, func(ctx context.Context, r *partyRun) error {
				rs, err := relayself.Relays(ctx, r.s.Store)
				if err != nil {
					return err
				}
				if len(rs) == 0 {
					fmt.Fprintln(a.d.Out, "No relay is listed (spo party relay add NAME --node-key HEX --address-file FILE).")
					return nil
				}
				for _, rl := range rs {
					fmt.Fprintf(a.d.Out, "%-16s node key %s  port %d\n", rl.Name, hex.EncodeToString(rl.Key[:]), rl.Port)
				}
				return nil
			})
		},
	}
}

func (a *app) partyRelayRemoveCommand() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "remove NAME [--yes]",
		Short: "Stop using a relay: drop it and its sealed address",
		Long: `Remove a relay from this device's list, with its sealed address. Mail waiting
for this device at that relay is no longer fetched; pending revokes are no
longer sent to it. It asks first.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.party(cmd, nil, nil, func(ctx context.Context, r *partyRun) error {
				ok, err := a.confirm(ctx, fmt.Sprintf("Stop using the relay %s?", args[0]), yes)
				if err != nil {
					return err
				}
				if !ok {
					return errors.New("nothing changed")
				}
				if err := relayself.RemoveRelay(ctx, r.s.Store, args[0]); err != nil {
					return err
				}
				fmt.Fprintf(a.d.Out, "Removed the relay %s.\n", args[0])
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "do not ask")
	return cmd
}
