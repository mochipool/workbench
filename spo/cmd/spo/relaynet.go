package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	"github.com/mochipool/workbench/spo/internal/adapters/tailcat/stream"
	mbw "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// The relay transport of the command tree (ADR 0014 work package 10): a tailcat
// stream dialer per listed relay, a mailbox.Client per relay over it, and
// mailbox.Multi over them. The logic is in adapters/mailbox (Connect,
// SendRevokesTo); this only builds the dialers.

// relayDialers makes one dialer per relay. The buffers are read here and stay
// the caller's. On an error the dialers made so far are closed.
func relayDialers(relays []cli.RelayEndpoint, nodeKey *secret.Buffer, derp string) ([]mailbox.Endpoint, error) {
	var out []mailbox.Endpoint
	for _, r := range relays {
		d, err := stream.NewDialer(stream.DialerConfig{Address: r.Address.Use, NodeKey: nodeKey.Use, ExpectServerKey: r.Key, Port: r.Port, DERPMapURL: derp})
		if err != nil {
			for _, e := range out {
				e.Dialer.CloseWithin(5 * time.Second) //nolint:errcheck // a failed start
			}
			return nil, fmt.Errorf("relay %s: %w", r.Name, err)
		}
		out = append(out, mailbox.Endpoint{Name: r.Name, RelayKey: r.Key, Dialer: d})
	}
	return out, nil
}

// relayClient is mailbox.Multi as the command tree's RelayClient.
type relayClient struct{ *mailbox.Multi }

func (c relayClient) SetBinding(statement, key []byte) error {
	return c.Multi.SetBinding(mailbox.Binding{Statement: statement, Key: key})
}

func (c relayClient) SetSenders(ks []party.WalletKey) { c.Multi.SetSenders(walletKeys(ks)) }

func (c relayClient) SendRevokes(ctx context.Context) map[string]error {
	reps, _ := c.Multi.SendRevokes(ctx) // each relay's own error is in its report
	return relayErrs(reps)
}

// relayErrs is each relay's own error of a revoke-only exchange, by name.
func relayErrs(reps map[string]mailbox.RevokeReport) map[string]error {
	out := make(map[string]error, len(reps))
	for name, r := range reps {
		out[name] = r.Err
	}
	return out
}

func walletKeys(ks []party.WalletKey) []mbw.WalletKey {
	out := make([]mbw.WalletKey, 0, len(ks))
	for _, k := range ks {
		out = append(out, mbw.WalletKey(k))
	}
	return out
}

// relayConnect is cli.RelayOps.Connect: the tunnel dialers, then connectOver.
func relayConnect(c cli.RelayConnectConfig) (cli.RelayClient, error) {
	if _, ok := c.Local.(relayport.AuthSigner); !ok {
		return nil, errors.New("the local identity cannot sign a relay login")
	}
	eps, err := relayDialers(c.Relays, c.NodeKey, c.DERPMapURL)
	if err != nil {
		return nil, err
	}
	var nodePub party.NodeKey
	if d, ok := eps[0].Dialer.(*stream.Dialer); ok {
		nodePub = d.NodeKey()
	}
	return connectOver(eps, nodePub, c, mailbox.Limits{}, mailbox.MultiConfig{})
}

// connectOver is the composite over dialers already made: one client per relay
// with this device's identity, binding, routes and book (mailbox.Connect), the
// composite's events turned into the command's notes. On a failure the dialers
// are closed.
func connectOver(eps []mailbox.Endpoint, nodePub party.NodeKey, c cli.RelayConnectConfig, lim mailbox.Limits, mc mailbox.MultiConfig) (cli.RelayClient, error) {
	signer, ok := c.Local.(relayport.AuthSigner)
	if !ok {
		return nil, errors.New("the local identity cannot sign a relay login")
	}
	id := c.Local.Identity()
	note := c.Note
	mc.Events = func(e mailbox.MultiEvent) {
		if note != nil {
			note(noteOf(e))
		}
	}
	m, err := mailbox.Connect(mailbox.DeviceConfig{
		Relays: eps, NodeKey: nodePub, Self: id.Fingerprint(), Device: mbw.DeviceKeys{Ed25519: id.Ed25519, X25519: id.X25519},
		Binding: mailbox.Binding{Statement: c.Statement, Key: c.Key}, Senders: walletKeys(c.Senders),
		Resolve: func(to party.Fingerprint) (mailbox.Route, bool) {
			k, d, ok := c.Resolve(to)
			return mailbox.Route{WalletKey: mbw.WalletKey(k), Device: d}, ok
		},
		Revokes: c.Book, Signer: signer, Clock: c.Clock, Limits: lim, Multi: mc,
	})
	if err != nil {
		for _, e := range eps {
			e.Dialer.CloseWithin(5 * time.Second) //nolint:errcheck // a failed start
		}
		return nil, err
	}
	return relayClient{m}, nil
}

// noteOf is the command's note of one event of the composite: the relay, the
// class and, for a refused identity, the refusal.
func noteOf(e mailbox.MultiEvent) cli.RelayNote {
	n := cli.RelayNote{Relay: e.Relay, Kind: string(e.Kind), Outcome: string(e.Outcome)}
	if e.Outcome == mailbox.OutcomeIdentity || (e.Err != nil && (errors.Is(e.Err, mailbox.ErrBindingRefused) || errors.Is(e.Err, mailbox.ErrNotAllowed))) {
		n.Identity = e.Err
	}
	return n
}

func relayCheckAddress(e cli.RelayEndpoint, nodeKey *secret.Buffer) error {
	d, err := stream.NewDialer(stream.DialerConfig{Address: e.Address.Use, NodeKey: nodeKey.Use, ExpectServerKey: e.Key, Port: e.Port})
	if err != nil {
		return err
	}
	return d.CloseWithin(5 * time.Second)
}

func relaySendRevokes(ctx context.Context, c cli.RelaySendConfig) (map[string]error, error) {
	eps, err := relayDialers(c.Relays, c.NodeKey, c.DERPMapURL)
	if err != nil {
		return nil, err
	}
	return sendRevokesOver(ctx, eps, c)
}

// sendRevokesOver is the revoke-only exchange over dialers already made: each
// relay's own error by name, and the error of a tunnel that did not stop.
func sendRevokesOver(ctx context.Context, eps []mailbox.Endpoint, c cli.RelaySendConfig) (map[string]error, error) {
	reps, _ := mailbox.SendRevokesTo(ctx, eps, c.Clock, c.Book, mailbox.Limits{})
	var stuck error
	for _, e := range eps {
		if err := e.Dialer.CloseWithin(10 * time.Second); err != nil {
			stuck = errors.Join(stuck, fmt.Errorf("tunnel did not stop (relay %s): %w", e.Name, err))
		}
	}
	return relayErrs(reps), stuck
}
