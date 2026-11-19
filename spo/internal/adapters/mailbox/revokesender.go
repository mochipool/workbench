package mailbox

import (
	"context"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// RevokeConfig is what a RevokeSender needs. It has no binding, no auth signer,
// no expected senders and no resolver: a revoke-only sender has nothing to log
// in with.
//
// spec: SPO-Xmailbox-IF-019
type RevokeConfig struct {
	// Dialer opens a stream to the relay; the key it reports must be RelayKey.
	Dialer relayport.StreamDialer
	// RelayKey is the relay's node key, pinned at enrolment. Required.
	RelayKey party.NodeKey
	// Clock gives the time of the dial limit and of the revokes' own check.
	// Required.
	Clock relayport.Clock
	// Revokes is the book of pending revokes. Required.
	Revokes RevokeBook
	// Policy is the lifetime and skew policy the revokes are checked against; the
	// zero value is relaybind.DefaultPolicy.
	Policy relaybind.Policy
	// Limits are the sender's own bounds, as the client's; zero fields take the
	// table.
	Limits Limits
	// Events receives the operator events; nil drops them.
	Events EventSink
}

// RevokeSender sends pending revokes for a device that has no binding at the
// relay, or none it may present: a new device that revokes a lost one with a
// wallet-signed revoke (`spo party relay forget --lost`, ADR 0014 decision 8). It
// is the client's revoke-only exchange and nothing else: the same dial, the same
// checks of the dialer's key, of the Challenge's relay key and of the version
// (version 2 only), the same bounded reads, dial limit, backoff and interruption
// by Close, and the same order of the revokes. It holds no binding and no signer,
// and it has no way to send an Auth: its connections end after the last answer.
type RevokeSender struct {
	c *Client
}

// errRevokeOnly is the answer of the signer a RevokeSender's client holds. That
// client never asks it (its connections end before the Auth); if it did, the
// login would fail before anything was sent.
var errRevokeOnly = errors.New("mailbox: a revoke-only sender signs nothing")

type revokeOnlySigner struct{}

func (revokeOnlySigner) SignMailboxAuth(party.NodeKey, party.NodeKey, [32]byte, int64, [32]byte, [32]byte) ([64]byte, error) {
	return [64]byte{}, errRevokeOnly
}

// NewRevokeSender checks the configuration and makes a revoke-only sender. It
// does not dial.
//
// spec: SPO-Xmailbox-IF-019
func NewRevokeSender(cfg RevokeConfig) (*RevokeSender, error) {
	switch {
	case cfg.Dialer == nil, cfg.Clock == nil, cfg.Revokes == nil:
		return nil, errors.New("mailbox: a dialer, a clock and a revoke book are required")
	case cfg.RelayKey == (party.NodeKey{}):
		return nil, errors.New("mailbox: the relay's pinned node key is required")
	}
	lim, err := cfg.Limits.resolved()
	if err != nil {
		return nil, err
	}
	c := &Client{
		cfg: Config{Dialer: cfg.Dialer, RelayKey: cfg.RelayKey, Clock: cfg.Clock, Revokes: cfg.Revokes, Policy: cfg.Policy,
			Limits: cfg.Limits, Events: cfg.Events, Signer: revokeOnlySigner{}},
		lim: lim, sem: make(chan struct{}, 1), closedCh: make(chan struct{}),
		revokeOnly: true,
		cr:         &creds{}, // nothing to present
	}
	if err := c.policy().Validate(); err != nil {
		return nil, fmt.Errorf("mailbox: the revoke policy: %w", err)
	}
	return &RevokeSender{c: c}, nil
}

// SendRevokes is Client.SendRevokes: the pending revokes on a connection of their
// own, before any login and without one, and the report of what happened to each.
//
// spec: SPO-Xmailbox-IF-019, SPO-Xmailbox-OUT-090
func (s *RevokeSender) SendRevokes(ctx context.Context) (RevokeReport, error) {
	return s.c.SendRevokes(ctx)
}

// Close ends an exchange in progress and every later call is ports.ErrClosed. It
// closes nothing it was given: the dialer stays the caller's.
func (s *RevokeSender) Close() error { return s.c.Close() }
