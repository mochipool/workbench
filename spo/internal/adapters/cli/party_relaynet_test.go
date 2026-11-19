package cli

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/app/relayself"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

// fakeRelays is the relay transport of the command tree: a client that records
// what it is asked, and the address check of a fake address "relay-address-<key>".
type fakeRelays struct {
	mu         sync.Mutex
	cfg        RelayConnectConfig
	connects   int
	calls      []string
	inbox      chan ports.Received
	sendErr    error
	recvErr    error
	logoutErr  error
	revokesErr error
	sticky     bool               // an envelope not acknowledged is served again
	unacked    *ports.Received    // the last envelope served and not acknowledged
	down       map[string]bool    // relays not reached by a revoke send
	refuse     map[string]bool    // relays that answer every revoke refused
	revokes    []relayport.Revoke // what SendRevokes found in the book
	bindings   [][]byte
	senders    [][]party.WalletKey
	sends      []RelaySendConfig
}

func (f *fakeRelays) note(s string) { f.mu.Lock(); f.calls = append(f.calls, s); f.mu.Unlock() }

func (f *fakeRelays) callList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeRelays) Send(ctx context.Context, to party.Fingerprint, env []byte) error {
	f.note("send")
	return f.sendErr
}
func (f *fakeRelays) Receive(ctx context.Context) (ports.Received, error) {
	f.note("receive")
	if f.recvErr != nil {
		return ports.Received{}, f.recvErr
	}
	f.mu.Lock()
	if f.sticky && f.unacked != nil { // a relay serves what was not acknowledged again
		r := *f.unacked
		f.mu.Unlock()
		return r, nil
	}
	f.mu.Unlock()
	select {
	case r := <-f.inbox:
		f.mu.Lock()
		f.unacked = &r
		f.mu.Unlock()
		return r, nil
	case <-ctx.Done():
		return ports.Received{}, ctx.Err()
	}
}
func (f *fakeRelays) Ack() error { return f.AckContext(context.Background()) }
func (f *fakeRelays) AckContext(context.Context) error {
	f.note("ack")
	f.mu.Lock()
	f.unacked = nil
	f.mu.Unlock()
	return nil
}
func (f *fakeRelays) Transport() ports.Transport { return ports.NetworkTransport(f) }
func (f *fakeRelays) SetSenders(ks []party.WalletKey) {
	f.mu.Lock()
	f.senders = append(f.senders, ks)
	f.mu.Unlock()
}
func (f *fakeRelays) SetBinding(st, key []byte) error {
	f.mu.Lock()
	f.bindings = append(f.bindings, st)
	f.mu.Unlock()
	return nil
}
func (f *fakeRelays) SendRevokes(context.Context) map[string]error {
	f.note("revokes")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokes = f.cfg.Book.Pending()
	return f.answer(f.cfg.Relays, f.cfg.Book)
}

// answer is what each relay does with the book's revokes: a relay in down is
// not reached (its own error), one in refuse answers refused, the others record
// every revoke; revokesErr makes every relay unreachable. f.mu is held.
func (f *fakeRelays) answer(relays []RelayEndpoint, book relayport.RevokeBook) map[string]error {
	errs := map[string]error{}
	rb, _ := book.(relayport.RelayRevokeBook)
	for _, e := range relays {
		switch {
		case f.revokesErr != nil:
			errs[e.Name] = f.revokesErr
			continue
		case f.down[e.Name]:
			errs[e.Name] = errors.New("relay " + e.Name + " unreachable")
			continue
		}
		errs[e.Name] = nil
		for _, rv := range book.Pending() {
			o := relayport.RevokeRecorded
			if f.refuse[e.Name] {
				o = relayport.RevokeRefused
			}
			if rb != nil {
				rb.ResultAt(e.Name, rv, o)
			} else {
				book.Result(rv, o)
			}
		}
	}
	return errs
}
func (f *fakeRelays) Logout(time.Duration) error { f.note("logout"); return f.logoutErr }

// ops are the relay operations over the fake, on top of the vault's signing.
func (f *fakeRelays) ops(base RelayOps) RelayOps {
	base.Connect = func(c RelayConnectConfig) (RelayClient, error) {
		f.mu.Lock()
		f.cfg = c
		f.connects++
		f.mu.Unlock()
		f.note("connect")
		return f, nil
	}
	base.CheckAddress = func(e RelayEndpoint, nk *secret.Buffer) error {
		var addr string
		e.Address.Use(func(b []byte) error { addr = string(b); return nil })
		if addr != "relay-address-"+hex.EncodeToString(e.Key[:]) {
			return errors.New("the address leads to another node key")
		}
		return nil
	}
	base.SendRevokes = func(ctx context.Context, c RelaySendConfig) (map[string]error, error) {
		f.note("revoke-only")
		f.mu.Lock()
		defer f.mu.Unlock()
		f.sends = append(f.sends, c)
		return f.answer(c.Relays, c.Book), nil
	}
	return base
}

func writeAddr(t *testing.T, key party.NodeKey) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "addr")
	if err := os.WriteFile(p, []byte("relay-address-"+hex.EncodeToString(key[:])+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// relayScene is the network scene with the coordinator bound to a payment key of
// its vault, one relay listed, and the fake relay transport.
type relayScene struct {
	*netScene
	fake *fakeRelays
	pin  party.NodeKey
}

func newRelayScene(t *testing.T) *relayScene {
	t.Helper()
	n := newNetScene(t, ModeLight)
	s := &relayScene{netScene: n, fake: &fakeRelays{inbox: make(chan ports.Received, 4)}, pin: party.NodeKey{0x42, 7}}
	n.C.AddKey(custody.RolePayment, "coordpay")
	n.coord.edit = func(env *Env, k *PartyKit) { k.Relay = s.fake.ops(k.Relay) }
	n.coord.must(n.coord.term(), "party", "relay", "bind", "--key", "coordpay")
	n.coord.must(n.coord.term(), "party", "relay", "add", "relay-a", "--node-key", hex.EncodeToString(s.pin[:]), "--address-file", writeAddr(t, s.pin))
	return s
}

// The relay list through the commands: add checks the address against the
// pinned key before storing, list shows the pins, remove asks and drops.
//
// spec: SPO-Xmailbox-IF-025
func TestRelayListThroughTheCommands(t *testing.T) {
	s := newRelayScene(t)
	c := s.coord
	out := c.must(c.term(), "party", "relay", "list")
	if !strings.Contains(out, "relay-a") || !strings.Contains(out, hex.EncodeToString(s.pin[:])) || !strings.Contains(out, "7346") {
		t.Fatalf("list: %s", out)
	}
	other := party.NodeKey{9}
	if _, err := c.run(c.term(), "party", "relay", "add", "relay-b", "--node-key", hex.EncodeToString(other[:]), "--address-file", writeAddr(t, s.pin)); err == nil ||
		!strings.Contains(err.Error(), "does not lead") {
		t.Fatalf("an address of another key: %v", err)
	}
	if _, err := c.run(c.term(), "party", "relay", "add", "relay-b", "--node-key", "abc", "--address-file", writeAddr(t, other)); err == nil {
		t.Fatal("a short node key was taken")
	}
	if _, err := c.run(c.term(), "party", "relay", "add", "relay-a", "--node-key", hex.EncodeToString(other[:]), "--address-file", writeAddr(t, other)); !errors.Is(err, relayself.ErrRelayExists) {
		t.Fatalf("a name twice: %v", err)
	}
	if rs, _ := relayself.Relays(context.Background(), s.C.Store); len(rs) != 1 {
		t.Fatalf("a refused add stored something: %+v", rs)
	}
	c.must(c.term(), "party", "relay", "remove", "relay-a", "--yes")
	if out := c.must(c.term(), "party", "relay", "list"); !strings.Contains(out, "No relay is listed") {
		t.Fatalf("after remove: %s", out)
	}
}

// serve --transport mailbox connects with the stored binding, the routes and the
// book, exchanges until it is stopped and then logs out; a stuck tunnel fails
// the command with "tunnel did not stop".
//
// spec: SPO-Xmailbox-OUT-108, SPO-Xmailbox-IF-025
func TestServeOverTheRelaysLogsOutAtTheEnd(t *testing.T) {
	s := newRelayScene(t)
	c := s.coord
	err := c.runUntil(c.term(), func() bool {
		for _, x := range s.fake.callList() {
			if x == "receive" {
				return true
			}
		}
		return false
	}, "party", "serve", "--transport", "mailbox")
	if err != nil {
		t.Fatalf("serve: %v\n%s", err, c.err.String())
	}
	st, err := relayself.Service{Store: s.C.Store, Device: s.C.Identity.Fingerprint}.Load(context.Background())
	if err != nil || st.Binding == nil {
		t.Fatal(err)
	}
	cfg := s.fake.cfg
	if !bytes.Equal(cfg.Statement, st.Binding.Statement) || cfg.Book == nil || cfg.Local == nil || len(cfg.Relays) != 1 || cfg.Relays[0].Key != s.pin {
		t.Fatalf("connect config %+v", cfg)
	}
	calls := s.fake.callList()
	if calls[0] != "connect" || calls[len(calls)-1] != "logout" {
		t.Fatalf("calls %v", calls)
	}
	if !strings.Contains(c.out.String(), "Logged out of the relays") {
		t.Fatalf("out: %s", c.out.String())
	}
	s.fake.logoutErr = errors.New("engine stuck")
	err = c.runUntil(c.term(), func() bool { return len(s.fake.callList()) > len(calls)+2 }, "party", "serve", "--transport", "mailbox")
	if err == nil || !strings.Contains(err.Error(), "tunnel did not stop") || !strings.Contains(c.err.String(), "tunnel did not stop") {
		t.Fatalf("a stuck tunnel: %v\n%s", err, c.err.String())
	}
	if _, err := c.run(c.term(), "party", "serve", "--transport", "mailbox", "--invite", "bob"); err == nil {
		t.Fatal("--invite with the mailbox transport")
	}
	if _, err := c.run(c.term(), "party", "serve", "--transport", "carrier-pigeon"); err == nil {
		t.Fatal("an unknown transport")
	}
}

// A refused identity is told with its remedy once per binding statement in a
// process, however often the relays answer it.
//
// spec: SPO-Xmailbox-OUT-108, SPO-Xmailbox-OUT-099
func TestARefusedIdentityIsToldOncePerBinding(t *testing.T) {
	var w bytes.Buffer
	err := errors.Join(ports.ErrIdentityRefused, errors.New("binding"))
	st := []byte("a binding statement " + t.Name())
	for range 5 {
		tellRemedyOnce(&w, st, err)
	}
	if n := strings.Count(w.String(), "spo party relay bind"); n != 1 {
		t.Fatalf("told %d times: %s", n, w.String())
	}
	if tellRemedyOnce(&w, st, errors.New("unreachable")) {
		t.Fatal("an error that is not a refused identity was told as one")
	}
	if !tellRemedyOnce(&w, []byte("a new binding "+t.Name()), err) {
		t.Fatal("a new binding refused again was not told")
	}

	s := newRelayScene(t)
	c := s.coord
	s.fake.recvErr = err
	s.fake.sendErr = err
	if err := c.runUntil(c.term(), func() bool { return len(s.fake.callList()) > 12 }, "party", "serve", "--transport", "mailbox"); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(c.err.String(), "spo party relay bind"); n != 1 {
		t.Fatalf("the serve loop told the remedy %d times:\n%s", n, c.err.String())
	}
}

// Forget over the relays: the queue is fetched and handled first, the revoke is
// stored with the binding kept and sent to the relays, the clients log out, and
// only then the binding is deleted. A stuck tunnel keeps the binding.
//
// spec: SPO-Xmailbox-OUT-109, SPO-Xmailbox-SEC-073
func TestForgetOverTheRelaysRunsTheOrderOfTheADR(t *testing.T) {
	s := newRelayScene(t)
	c := s.coord
	s.fake.logoutErr = errors.New("engine stuck")
	if _, err := c.run(c.term(), "party", "relay", "forget", "--yes", "--as", "coordinator"); err == nil || !strings.Contains(err.Error(), "tunnel did not stop") {
		t.Fatalf("forget with a stuck tunnel: %v", err)
	}
	load := func() relayself.State {
		st, err := relayself.Service{Store: s.C.Store, Device: s.C.Identity.Fingerprint}.Load(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	if st := load(); st.Binding == nil || len(st.Revokes) != 1 {
		t.Fatalf("a stuck logout deleted the binding or lost the revoke: %+v", st)
	}
	s.fake.logoutErr = nil
	s.fake.mu.Lock()
	s.fake.calls = nil
	s.fake.mu.Unlock()
	s.clock.Advance(10 * time.Second) // the second revoke is a new one
	out := c.must(c.term(), "party", "relay", "forget", "--yes", "--as", "coordinator")
	calls := strings.Join(s.fake.callList(), " ")
	if !strings.HasPrefix(calls, "connect receive") || !strings.Contains(calls, "receive revokes logout") {
		t.Fatalf("the order of forget: %s", calls)
	}
	if len(s.fake.revokes) == 0 || s.fake.revokes[len(s.fake.revokes)-1].Kind != relayport.RevokeByDeviceKey {
		t.Fatalf("the revoke was not in the book when it was sent: %+v", s.fake.revokes)
	}
	st := load()
	if st.Binding != nil {
		t.Fatal("forget kept the binding")
	}
	// what was sent is the revoke this forget made (the book was loaded again
	// after it was stored), not the one of the session's start
	newest := int64(0)
	for _, rv := range st.Revokes {
		newest = max(newest, rv.NotBefore)
	}
	if got := s.fake.revokes[len(s.fake.revokes)-1].NotBefore; got != newest || newest != s.clock.Now().Unix() {
		t.Fatalf("the revoke sent has not-before %d; the one stored now %d (clock %d)", got, newest, s.clock.Now().Unix())
	}
	if !strings.Contains(out, "logged out and deleted its binding") {
		t.Fatalf("out: %s", out)
	}
	// with no binding left, forget stores a revoke and sends it on revoke-only connections
	c.must(c.term(), "party", "relay", "forget", "--yes")
	if len(s.fake.sends) == 0 || len(s.fake.sends[0].Relays) != 1 {
		t.Fatalf("no revoke-only send: %+v", s.fake.sends)
	}
}

// connect --transport mailbox takes no coordinator; tailcat needs one.
//
// spec: SPO-Xmailbox-IF-025
func TestConnectTransportArguments(t *testing.T) {
	s := newRelayScene(t)
	b := s.bob
	if _, err := b.run(b.term(), "party", "connect", "coord", "--transport", "mailbox"); err == nil || !strings.Contains(err.Error(), "takes no COORDINATOR") {
		t.Fatal("a coordinator with the mailbox transport")
	}
	if _, err := b.run(b.term(), "party", "connect"); err == nil {
		t.Fatal("tailcat with no coordinator")
	}
	if _, err := b.run(b.term(), "party", "connect", "--transport", "mailbox"); err == nil || !strings.Contains(err.Error(), "relay") {
		t.Fatalf("a device with no binding and no relay: %v", err)
	}
}

// Forget over the relays when no relay recorded the revoke: the command does
// not say the device was revoked at the relays.
//
// spec: SPO-Xmailbox-OUT-109, SPO-Xmailbox-OUT-111
func TestForgetDoesNotClaimARevokeNoRelayRecorded(t *testing.T) {
	s := newRelayScene(t)
	c := s.coord
	s.fake.revokesErr = errors.New("mailbox: no relay took the revokes")
	out, err := c.run(c.term(), "party", "relay", "forget", "--yes", "--as", "coordinator")
	if strings.Contains(out, "Revoked this device at") {
		t.Fatalf("forget claimed the revoke with every relay down: %v\n%s", err, out)
	}
	if err == nil || !strings.Contains(c.err.String()+err.Error(), "relay-a") {
		t.Fatalf("the relay that did not record it is not named: %v\n%s", err, c.err.String())
	}
	if !strings.Contains(out, "relay relay-a: NOT recorded: not reached") || !strings.Contains(out, "spo party relay send-revokes") {
		t.Fatalf("forget does not say how the revoke is completed:\n%s", out)
	}
}

// serve over the relays follows the store while it runs: another command
// records a peer's relay identity (the routes are read again and the new
// expected-sender set goes to the relays with SetSenders), and another command
// binds this device again (the newer binding is given to the relays with
// SetBinding and is the one a refusal is told for).
//
// spec: SPO-Xmailbox-OUT-108
func TestServeFollowsTheStoreWhileItRuns(t *testing.T) {
	serveSyncEvery = 20 * time.Millisecond
	t.Cleanup(func() { serveSyncEvery = 2 * time.Second })
	s := newRelayScene(t)
	c := s.coord
	g := newPfixOf(t, s.C)
	wal := relayporttest.NewWallet(6)
	bobFP := s.B.Identity.Fingerprint
	now := s.clock.Now().Unix()
	st := wal.BindingStatement(bobFP, now-60, now+3600, false)
	bfile := filepath.Join(t.TempDir(), "bob.binding")
	if err := os.WriteFile(bfile, []byte(fmt.Sprintf(`{"v":1,"statement":"%x","cose_key":"%x"}`, st.Sign1, st.COSEKey)), 0o600); err != nil {
		t.Fatal(err)
	}
	acted := false
	err := c.runUntil(c.term(), func() bool {
		s.fake.mu.Lock()
		connected, senders, bindings := s.fake.connects > 0, len(s.fake.senders), len(s.fake.bindings)
		s.fake.mu.Unlock()
		if !connected {
			return false
		}
		if !acted {
			acted = true
			g.must(g.term(first4(bobFP)), "party", "relay", "peer", "bob", "--binding", bfile)
			s.clock.Advance(time.Hour)
			g.must(g.term(), "party", "relay", "bind", "--key", "coordpay")
			return false
		}
		return senders > 0 && bindings > 0
	}, "party", "serve", "--transport", "mailbox")
	if err != nil {
		t.Fatal(err)
	}
	s.fake.mu.Lock()
	defer s.fake.mu.Unlock()
	last := s.fake.senders[len(s.fake.senders)-1]
	if len(last) != 1 || last[0] != party.WalletKey(wal.Key) {
		t.Fatalf("SetSenders got %x, want bob's wallet key", last)
	}
	stored, err := relayself.Service{Store: s.C.Store, Device: s.C.Identity.Fingerprint}.Load(context.Background())
	if err != nil || stored.Binding == nil {
		t.Fatal(err)
	}
	if b := s.fake.bindings[len(s.fake.bindings)-1]; !bytes.Equal(b, stored.Binding.Statement) || bytes.Equal(b, s.fake.cfg.Statement) {
		t.Fatal("SetBinding did not get the newer stored binding")
	}
	if !strings.Contains(c.out.String(), "the new binding is used from the next connection") {
		t.Fatalf("out:\n%s", c.out.String())
	}
}

// The drain of forget does not spin on an envelope whose handling fails: it is
// tried once, acknowledged without handling when the relay serves it again, and
// counted; the envelopes after it are handled and forget goes on.
//
// spec: SPO-Xmailbox-OUT-109
func TestForgetDrainTriesAFailingEnvelopeOnce(t *testing.T) {
	s := newRelayScene(t)
	c := s.coord
	s.fake.sticky = true
	var calls sync.Map
	forgetHandleWrap = func(h multisig.Handler) multisig.Handler {
		return func(ctx context.Context, rcv ports.Received) (multisig.Handled, error) {
			n, _ := calls.LoadOrStore(string(rcv.Envelope), new(int))
			*n.(*int)++
			if string(rcv.Envelope) == "fails" {
				return multisig.Handled{}, errors.New("the store is busy")
			}
			return multisig.Handled{Effect: "stored"}, nil
		}
	}
	forgetDrainFor = 5 * time.Second // a drain that spins ends here, and fails the counts below
	t.Cleanup(func() {
		forgetHandleWrap = func(h multisig.Handler) multisig.Handler { return h }
		forgetDrainFor = 5 * time.Minute
	})
	s.fake.inbox <- ports.NetworkReceived([]byte("fails"))
	s.fake.inbox <- ports.NetworkReceived([]byte("fine"))
	began := time.Now()
	out := c.must(c.term(), "party", "relay", "forget", "--yes", "--as", "coordinator")
	if d := time.Since(began); d > 20*time.Second {
		t.Fatalf("forget took %v: the drain spun", d)
	}
	if n, _ := calls.Load("fails"); n == nil || *n.(*int) != 1 {
		got := 0
		if n != nil {
			got = *n.(*int)
		}
		t.Fatalf("the failing envelope was handled %d times, want once", got)
	}
	if n, _ := calls.Load("fine"); n == nil || *n.(*int) != 1 {
		t.Fatal("the envelope after the failing one was not handled")
	}
	if !strings.Contains(out, "1 envelope(s) could not be handled; each was tried once (1 acknowledged afterwards without handling)") ||
		!strings.Contains(out, "Handled 1 envelope(s)") {
		t.Fatalf("out:\n%s", out)
	}
}

// addRelayB lists a second relay, relay-b.
func (s *relayScene) addRelayB(t *testing.T) {
	t.Helper()
	pin := party.NodeKey{0x43, 8}
	s.coord.must(s.coord.term(), "party", "relay", "add", "relay-b", "--node-key", hex.EncodeToString(pin[:]), "--address-file", writeAddr(t, pin))
}

// Forget over two relays with one down: it names the relay that did not record
// the revoke and says how it is completed, deletes the binding all the same,
// and status shows what that relay owes. serve with no binding sends the owed
// revoke first, before it refuses; send-revokes completes it, and only then
// says every relay recorded it. A relay that answers refused is named too.
//
// spec: SPO-Xmailbox-OUT-109, SPO-Xmailbox-OUT-111
func TestForgetWithARelayDownIsCompletedWithoutABinding(t *testing.T) {
	s := newRelayScene(t)
	c := s.coord
	s.addRelayB(t)
	s.fake.down = map[string]bool{"relay-b": true}
	out, err := c.run(c.term(), "party", "relay", "forget", "--yes", "--as", "coordinator")
	if err == nil || !strings.Contains(err.Error(), "relay-b") || strings.Contains(err.Error(), "relay-a") {
		t.Fatalf("forget with relay-b down: %v\n%s", err, out)
	}
	if !strings.Contains(out, "relay relay-a: recorded") || !strings.Contains(out, "relay relay-b: NOT recorded: not reached") ||
		strings.Contains(out, "Revoked this device at every listed relay") {
		t.Fatalf("the per-relay report:\n%s", out)
	}
	st, err := relayself.Service{Store: s.C.Store, Device: s.C.Identity.Fingerprint}.Load(context.Background())
	if err != nil || st.Binding != nil {
		t.Fatalf("the binding after forget: %v", err)
	}
	status := c.must(c.term(), "party", "relay", "status")
	if !strings.Contains(status, "recorded at relay-a; NOT yet recorded at relay-b") {
		t.Fatalf("status:\n%s", status)
	}
	// serve with no binding: the owed revoke goes first, then the refusal; still down
	before := len(s.fake.sends)
	if _, err := c.run(c.term(), "party", "serve", "--transport", "mailbox"); err == nil || !strings.Contains(err.Error(), "no relay binding") {
		t.Fatalf("serve with no binding: %v", err)
	}
	if len(s.fake.sends) != before+1 {
		t.Fatalf("serve did not send the owed revoke first: %d sends", len(s.fake.sends)-before)
	}
	// relay-b answers refused: still owed, named
	s.fake.down, s.fake.refuse = nil, map[string]bool{"relay-b": true}
	out, err = c.run(c.term(), "party", "relay", "send-revokes")
	if err == nil || !strings.Contains(out, "relay relay-b: 1 revoke(s) NOT recorded: it did not record it") {
		t.Fatalf("send-revokes to a relay that refuses: %v\n%s", err, out)
	}
	// relay-b records it: complete
	s.fake.refuse = nil
	out = c.must(c.term(), "party", "relay", "send-revokes")
	if !strings.Contains(out, "relay relay-b: recorded") || !strings.Contains(out, "Every listed relay recorded every pending revoke") {
		t.Fatalf("send-revokes with relay-b back:\n%s", out)
	}
	if status := c.must(c.term(), "party", "relay", "status"); strings.Contains(status, "NOT yet recorded at relay") {
		t.Fatalf("status after completion:\n%s", status)
	}
	// serve with no binding and nothing owed sends nothing
	before = len(s.fake.sends)
	c.run(c.term(), "party", "serve", "--transport", "mailbox") //nolint:errcheck // refused: no binding
	if len(s.fake.sends) != before {
		t.Fatal("serve sent revokes that no relay owes")
	}
}

// Forget with every relay recording the revoke says so; forget without a binding
// sends on revoke-only connections and reports per relay as well.
//
// spec: SPO-Xmailbox-OUT-109, SPO-Xmailbox-OUT-111
func TestForgetSaysRevokedOnlyWhenEveryRelayRecordedIt(t *testing.T) {
	s := newRelayScene(t)
	c := s.coord
	s.addRelayB(t)
	out := c.must(c.term(), "party", "relay", "forget", "--yes", "--as", "coordinator")
	if !strings.Contains(out, "relay relay-a: recorded") || !strings.Contains(out, "relay relay-b: recorded") || !strings.Contains(out, "Revoked this device at every listed relay") {
		t.Fatalf("forget with every relay up:\n%s", out)
	}
	s.clock.Advance(10 * time.Second)
	s.fake.down = map[string]bool{"relay-a": true, "relay-b": true}
	out, err := c.run(c.term(), "party", "relay", "forget", "--yes")
	if err == nil || strings.Contains(out, "Revoked this device at every listed relay") || !strings.Contains(out, "relay relay-a: NOT recorded") {
		t.Fatalf("forget without a binding, every relay down: %v\n%s", err, out)
	}
}
