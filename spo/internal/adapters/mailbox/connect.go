package mailbox

import (
	"context"
	"errors"
	"fmt"
	"sync"

	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// Endpoint is one relay of a device's list as the client needs it: the device's
// name for it, the relay's pinned node key and the dialer of its tunnel.
type Endpoint struct {
	Name     string
	RelayKey party.NodeKey
	Dialer   ClosableDialer
}

// DeviceConfig is what Connect needs: the relays and, once for all of them, this
// device's identity, binding, expected senders, routes and pending revokes.
type DeviceConfig struct {
	Relays []Endpoint
	// NodeKey is this device's node public key (the same on every tunnel).
	NodeKey party.NodeKey
	Self    party.Fingerprint
	Device  wire.DeviceKeys
	Binding Binding
	Senders []wire.WalletKey
	Resolve Resolver
	// Revokes is the device's book; Connect gives every client the same book
	// behind a lock (LockedBook).
	Revokes RevokeBook
	Signer  relayport.AuthSigner
	Clock   relayport.Clock
	Limits  Limits
	// Events receives each client's events with the relay's name.
	Events func(relay string, e Event)
	// Multi is the composite's configuration; its Members are set by Connect.
	Multi MultiConfig
}

// Connect makes one client per relay over its dialer and the composite over
// them (SPO-Xmailbox-IF-024, OUT-107): one binding, one expected-sender list and
// one book for every relay, because a revoke and a binding name no relay. It
// dials nothing. The dialers stay the caller's until Connect returns the
// composite, whose Logout closes them.
func Connect(cfg DeviceConfig) (*Multi, error) {
	if len(cfg.Relays) == 0 {
		return nil, errors.New("mailbox: no relay is configured")
	}
	book := LockedBook(cfg.Revokes)
	var members []Member
	fail := func(err error) (*Multi, error) {
		for _, m := range members {
			m.Client.Close()
		}
		return nil, err
	}
	for _, r := range cfg.Relays {
		if r.Dialer == nil {
			return fail(fmt.Errorf("mailbox: the relay %q has no dialer", r.Name))
		}
		var ev EventSink
		if cfg.Events != nil {
			name := r.Name
			ev = func(e Event) { cfg.Events(name, e) }
		}
		c, err := New(Config{Dialer: r.Dialer, RelayKey: r.RelayKey, NodeKey: cfg.NodeKey, Self: cfg.Self, Device: cfg.Device,
			Binding: cfg.Binding, Senders: cfg.Senders, Resolve: cfg.Resolve, Revokes: ForRelay(book, r.Name), Signer: cfg.Signer,
			Clock: cfg.Clock, Limits: cfg.Limits, Events: ev})
		if err != nil {
			return fail(fmt.Errorf("mailbox: relay %s: %w", r.Name, err))
		}
		members = append(members, Member{Name: r.Name, Client: c, Dialer: r.Dialer})
	}
	mc := cfg.Multi
	mc.Members = members
	m, err := NewMulti(mc)
	if err != nil {
		return fail(err)
	}
	return m, nil
}

// SendRevokesTo sends the book's pending revokes to every relay at once on
// revoke-only connections, with no binding and no signer (a RevokeSender per
// relay; OUT-107): the way a device with no binding revokes a lost one, or
// forgets itself after its clients were closed. It returns each relay's report,
// with the relay's own error in its Err, and fails only when every relay failed.
// Each relay's sender reports to the book with the relay's name (ForRelay). The
// dialers stay the caller's.
func SendRevokesTo(ctx context.Context, relays []Endpoint, clock relayport.Clock, book RevokeBook, lim Limits) (map[string]RevokeReport, error) {
	if len(relays) == 0 {
		return nil, errors.New("mailbox: no relay is configured")
	}
	shared := LockedBook(book)
	reps := make([]RevokeReport, len(relays))
	errs := make([]error, len(relays))
	var wg sync.WaitGroup
	for i, r := range relays {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := NewRevokeSender(RevokeConfig{Dialer: r.Dialer, RelayKey: r.RelayKey, Clock: clock, Revokes: ForRelay(shared, r.Name), Limits: lim})
			if err != nil {
				errs[i] = err
				return
			}
			defer s.Close()
			reps[i], errs[i] = s.SendRevokes(ctx)
			if errs[i] != nil {
				errs[i] = fmt.Errorf("relay %s: %w", r.Name, errs[i])
			}
		}()
	}
	wg.Wait()
	out := map[string]RevokeReport{}
	ok := false
	for i, r := range relays {
		reps[i].Err = errs[i]
		out[r.Name] = reps[i]
		if errs[i] == nil {
			ok = true
		}
	}
	if ok {
		return out, nil
	}
	return out, fmt.Errorf("mailbox: no relay took the revokes: %w", errors.Join(errs...))
}
