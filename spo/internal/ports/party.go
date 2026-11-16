package ports

import (
	"context"
	"errors"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// TransportKind says how an envelope arrived. The cold-key rule
// (SPO-Xparty-PRE-004, PRE-006) depends on it, so a receiver must report it
// truthfully and a caller must not guess.
type TransportKind uint8

const (
	// ViaFile: the envelope was read from a file.
	ViaFile TransportKind = iota + 1
	// ViaNetwork: the envelope came over a network transport (tailcat).
	ViaNetwork
)

func (k TransportKind) String() string {
	switch k {
	case ViaFile:
		return "file"
	case ViaNetwork:
		return "network"
	}
	return "unknown"
}

// Transport errors.
var (
	// ErrEnvelopeSize: the envelope is empty or larger than
	// party.MaxEnvelopeBytes (SPO-Xparty-INV-008).
	ErrEnvelopeSize = errors.New("envelope is empty or larger than the limit")
	// ErrNoRoute: the sender knows no way to reach that party now.
	ErrNoRoute = errors.New("no route to that party")
	// ErrClosed: the transport was closed.
	ErrClosed = errors.New("transport closed")
)

// EnvelopeSender sends one sealed envelope to a party. It sees ciphertext
// only and holds no application state (SPO-Xparty-SEC-003). A nil error means
// the transport took the envelope, not that the party accepted it.
type EnvelopeSender interface {
	Send(ctx context.Context, to party.Fingerprint, envelope []byte) error
}

// EnvelopeReceiver delivers sealed envelopes. Receive blocks until one is
// available or ctx ends, and returns ctx's error then. Delivery order is not
// specified. The bytes are unchecked: the caller opens them with
// adapters/envelope, whatever the transport said (SPO-Xparty-SEC-002).
type EnvelopeReceiver interface {
	Receive(ctx context.Context) (envelope []byte, via TransportKind, err error)
}

// PartyReader reads the party registry inside a Store View or Update.
// Lookups return ErrNotFound for an unknown party.
type PartyReader interface {
	ByFingerprint(r Reader, fp party.Fingerprint) (party.Party, error)
	ByName(r Reader, name string) (party.Party, error)
	List(r Reader) ([]party.Party, error)
}

// PartyWriter changes the registry inside a Store Update.
type PartyWriter interface {
	// Put stores a new party. It refuses a name or fingerprint in use.
	Put(w Writer, p party.Party) error
	// Revoke sets a party to revoked (SPO-Xparty-IF-003).
	Revoke(w Writer, name string) (party.Party, error)
}

// PartyRegistry is the registry backed by ports.Store records.
type PartyRegistry interface {
	PartyReader
	PartyWriter
}

// ErrReplay: the message id was already accepted (SPO-Xparty-INV-007).
var ErrReplay = errors.New("message id already accepted")

// ErrReplayFull: the replay log is full; the message is refused rather than
// accepted unrecorded.
var ErrReplayFull = errors.New("replay log is full")

// ReplayLog is the replay log of SPO-Xparty-INV-007. Record takes the Writer
// of the store transaction that applies the message's effect, so the id and
// the effect commit together or not at all: there is no window in which the
// effect happened and a replay is accepted, or the id is recorded and the
// effect lost. Entries are kept until their expiry has passed.
type ReplayLog interface {
	// Seen reports whether id is recorded and not yet expired at now.
	Seen(r Reader, id party.MessageID, now time.Time) (bool, error)
	// Record stores id until expires; ErrReplay if it is already there.
	Record(w Writer, id party.MessageID, expires, now time.Time) error
}
