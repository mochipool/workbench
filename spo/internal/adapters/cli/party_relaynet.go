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
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/app/relayloop"
	"github.com/mochipool/workbench/spo/internal/app/relayroutes"
	"github.com/mochipool/workbench/spo/internal/app/relayself"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// Several relays (ADR 0014 work package 10, SPO-Xmailbox-IF-025, OUT-108,
// OUT-109): the relay list of this device, the exchange of serve and connect
// over every listed relay at once, and the order of "forget this device" over
// them. This package builds no tunnel and no mailbox client: the composition
// root gives RelayOps.Connect, CheckAddress and SendRevokes.

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
// revoke-only connections. Nil when the build sends none.
func (r *partyRun) relaySender() func(ctx context.Context, book relayport.RevokeBook) (map[string]error, error) {
	ops := r.kit().Relay
	if ops.SendRevokes == nil {
		return nil
	}
	return func(ctx context.Context, book relayport.RevokeBook) (map[string]error, error) {
		eps, nk, done, err := r.openRelays(ctx)
		if err != nil {
			return nil, err
		}
		defer done()
		if len(eps) == 0 {
			return nil, relayself.ErrNoSender
		}
		_, derp := r.tailcatSettings()
		return ops.SendRevokes(ctx, RelaySendConfig{Relays: eps, NodeKey: nk, DERPMapURL: derp, Clock: r.env.Clock, Book: book})
	}
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
	r       *partyRun
	svc     relayself.Service
	client  RelayClient
	local   ports.LocalIdentity
	routes  *relayroutes.Table
	book    *liveBook
	tell    *relayloop.Teller // the error output and the binding in use, shared with the client's callback
	from    int64
	names   []string
	savedAt int // the book's changes at the last save
}

// openRelaySession connects this device to every listed relay with its stored
// binding, its routes and expected senders and its revoke book.
func (r *partyRun) openRelaySession(ctx context.Context) (*relaySession, error) {
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
		// (SPO-Xmailbox-OUT-111), then the refusal
		r.sendOwedRevokes(ctx, svc)
		return nil, errors.New("this device has no relay binding: bind it first with spo party relay bind")
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
		tell: relayloop.New(r.a.d.Err, st.Binding.Statement, relayRemedy)}
	for _, e := range eps {
		s.names = append(s.names, e.Name)
	}
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
		// called on the composite's member goroutines: only the teller is used
		Note: func(n RelayNote) {
			if n.Identity != nil {
				tell.Remedy(n.Identity)
			}
		},
	})
	if err != nil {
		local.Destroy()
		return nil, err
	}
	s.client = c
	return s, nil
}

// sync follows the store: the routes and the expected senders (SetSenders when
// they changed), a binding renewed by another command (SetBinding), and the
// revoke book (saved when the clients learnt something).
func (s *relaySession) sync(ctx context.Context) {
	if changed, err := s.routes.Refresh(ctx); err == nil && changed {
		s.client.SetSenders(s.routes.Senders())
	}
	if st, err := s.svc.Load(ctx); err == nil && st.Binding != nil && st.Binding.From > s.from {
		if err := s.client.SetBinding(st.Binding.Statement, st.Binding.Key); err == nil {
			s.tell.SetStatement(st.Binding.Statement)
			s.from = st.Binding.From
			fmt.Fprintln(s.r.a.d.Out, "relay: the new binding is used from the next connection")
		}
	}
	s.saveBook(ctx)
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

// close logs out: the clients, then every tunnel; the local identity is
// destroyed. A tunnel that did not stop is an error that says so.
func (s *relaySession) close(ctx context.Context) error {
	s.saveBook(ctx)
	err := s.client.Logout(relayLogout)
	s.local.Destroy()
	if err != nil {
		s.tell.Printf("tunnel did not stop: %v. The device may still be registered at the relay; exit this process.\n", err)
		return fmt.Errorf("tunnel did not stop: %w", err)
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
// they refuse a device with no binding (SPO-Xmailbox-OUT-111).
func (r *partyRun) sendOwedRevokes(ctx context.Context, svc relayself.Service) {
	if svc.Send == nil {
		return
	}
	st, err := svc.Status(ctx)
	if err != nil || len(st.Owed) == 0 {
		return
	}
	fmt.Fprintln(r.a.d.Out, "Sending the revokes still owed to the relays (no binding is needed for that):")
	rep, err := svc.SendPending(ctx)
	if err != nil && !errors.Is(err, relayself.ErrNoSender) {
		fmt.Fprintf(r.a.d.Err, "sending the revokes: %v\n", err)
	}
	if err := r.reportOwed(ctx, svc, "", rep.Relays); err != nil && !errors.Is(err, errRevokeOwed) {
		fmt.Fprintf(r.a.d.Err, "%v\n", err)
	}
}

// relayExchange is serve and connect over the relays (SPO-Xmailbox-OUT-108):
// flush the outbox, receive and handle, acknowledge, follow the store, until the
// command is stopped.
func (r *partyRun) relayExchange(ctx context.Context, handle multisig.Handler, after func(multisig.Handled)) error {
	s, err := r.openRelaySession(ctx)
	if err != nil {
		return err
	}
	a := r.a
	ob := r.node().Outbox()
	if err := ob.Rearm(ctx); err != nil {
		s.close(ctx)
		return err
	}
	fmt.Fprintf(a.d.Out, "Exchanging over %d relay(s): %s. Stop with Ctrl-C (that logs out).\n", len(s.names), strings.Join(s.names, ", "))
	synced, rearmed := time.Now(), time.Now()
	var junk relayloop.Pacer
	for ctx.Err() == nil {
		switch _, err := ob.Flush(ctx, s.client.Transport()); {
		case err == nil:
			s.tell.Clear("sending")
		case ctx.Err() != nil:
		case errors.Is(err, ports.ErrIdentityRefused):
			s.tell.Remedy(err)
		default:
			s.tell.Failure("sending", err)
		}
		rctx, cancel := context.WithTimeout(ctx, connectReceiveWindow)
		rcv, err := s.client.Receive(rctx)
		cancel()
		switch {
		case err == nil:
			s.tell.Clear("receiving")
			h, herr := handle(ctx, rcv)
			if herr != nil {
				s.tell.Printf("handling an envelope: %v\n", herr)
				break
			}
			if err := s.client.AckContext(ctx); err != nil && ctx.Err() == nil {
				s.tell.Printf("acknowledging: %v\n", err)
			}
			if after != nil {
				after(h)
			}
			if h.Refused && !h.HasSender {
				// junk anyone on the path can make: its work is paced (SPO-Xmailbox-OUT-112)
				sleepCtx(ctx, junk.Junk())
			}
		case ctx.Err() != nil, errors.Is(err, context.DeadlineExceeded):
		case errors.Is(err, ports.ErrIdentityRefused):
			s.tell.Remedy(err)
			sleepCtx(ctx, connectReceiveWindow)
		default:
			// a failure that persists is told once, and again when it changes
			s.tell.Failure("receiving", err)
			sleepCtx(ctx, connectReceiveWindow)
		}
		if time.Since(synced) > serveSyncEvery {
			synced = time.Now()
			s.sync(ctx)
		}
		if time.Since(rearmed) > relayRearmEvery {
			// no Hello arrives over a relay: the unanswered requests are put again
			// on a timer, so a lost response is recovered while this runs
			// (SPO-Xparty-INV-017, SPO-Xmailbox-OUT-110)
			rearmed = time.Now()
			if err := ob.Rearm(ctx); err != nil && ctx.Err() == nil {
				s.tell.Failure("re-arming the outbox", err)
			}
		}
	}
	if err := s.close(ctx); err != nil {
		return err
	}
	fmt.Fprintln(a.d.Out, "Logged out of the relays.")
	return nil
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
	})
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
func (r *partyRun) relayForget(ctx context.Context, handle multisig.Handler) (relayport.Revoke, map[string]error, error) {
	a := r.a
	s, err := r.openRelaySession(ctx)
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
	got, err := s.svc.ForgetRevoke(ctx)
	if err != nil {
		s.close(ctx)
		return relayport.Revoke{}, nil, err
	}
	// (3) sent to every relay on revoke-only connections of the same tunnels;
	// the book learns which relay recorded it
	if b, err := s.svc.Book(ctx); err == nil {
		s.book.set(b)
		s.savedAt = 0
	}
	errs := s.client.SendRevokes(ctx)
	// (4) log out (the book is saved first)
	if err := s.close(ctx); err != nil {
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
	role, err := r.inboxRole(ctx, as)
	if err != nil {
		return nil, err
	}
	if role == "signer" {
		sg, _, err := r.signer(ctx, "", r.dirs("", ""))
		if err != nil {
			return nil, err
		}
		return func(ctx context.Context, rcv ports.Received) (multisig.Handled, error) {
			out, err := sg.Handle(ctx, rcv)
			return out, mapSignerErr(err)
		}, nil
	}
	co, err := r.coordinator()
	if err != nil {
		return nil, err
	}
	return co.Handle, nil
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
