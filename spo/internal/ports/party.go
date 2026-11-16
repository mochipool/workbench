package ports

import (
	"context"
	"errors"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// TransportKind says how an envelope arrived or leaves. The cold-key rule
// (SPO-Xparty-PRE-004, PRE-006) depends on it. The zero value is unknown, and
// unknown is treated as a network in every cold-key check: a kind that was not
// stated is never taken for the file transport.
type TransportKind uint8

const (
	// ViaUnknown: the kind was not stated. It is a network for the cold-key
	// rule, and is refused where a kind must be stated.
	ViaUnknown TransportKind = iota
	// ViaFile: the envelope was read from or written to a file.
	ViaFile
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

// IsFile reports that the kind is the file transport. Everything else, the
// unknown kind included, is a network for the cold-key rule.
func (k TransportKind) IsFile() bool { return k == ViaFile }

// Known reports that the kind was stated.
func (k TransportKind) Known() bool { return k == ViaFile || k == ViaNetwork }

// Transport is a sender together with what kind of transport it is. Only the
// transport adapters make one (filebag.Bag.Transport, tailcat.Server.Transport,
// tailcat.Client.Transport), through the two constructors below: there is no
// constructor that takes a kind, so a call site cannot pick one at run time,
// and a test (ports/transport_callers_test.go) fails when code outside the
// adapters and tests calls them. The zero Transport has no sender and an
// unknown kind.
type Transport struct {
	send EnvelopeSender
	kind TransportKind
}

// FileTransport is a sender that writes files (SPO-Xparty-INV-024).
func FileTransport(s EnvelopeSender) Transport { return Transport{send: s, kind: ViaFile} }

// NetworkTransport is a sender over a network (SPO-Xparty-INV-024).
func NetworkTransport(s EnvelopeSender) Transport { return Transport{send: s, kind: ViaNetwork} }

// Received is one envelope as a transport delivered it, with how it arrived.
// The kind is not a field a caller can set: only FileReceived and
// NetworkReceived, which the adapters call, make one, and Signer.Handle and
// Coordinator.Handle take a Received, so wiring cannot relabel what came over
// a network as a file (SPO-Xparty-INV-024). The bytes are unchecked.
type Received struct {
	Envelope []byte
	via      TransportKind
}

// FileReceived is an envelope read from a file.
func FileReceived(envelope []byte) Received { return Received{Envelope: envelope, via: ViaFile} }

// NetworkReceived is an envelope that came over a network.
func NetworkReceived(envelope []byte) Received { return Received{Envelope: envelope, via: ViaNetwork} }

// Via is how the envelope arrived; ViaUnknown for the zero Received, which is
// a network for the cold-key rule.
func (r Received) Via() TransportKind { return r.via }

// Sender is the envelope sender; nil for the zero Transport.
func (t Transport) Sender() EnvelopeSender { return t.send }

// Kind is the transport's kind.
func (t Transport) Kind() TransportKind { return t.kind }

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
	Receive(ctx context.Context) (Received, error)
}

// EnvelopeAcker is an EnvelopeReceiver that keeps what it delivered until the
// caller has handled it: the file bag marks a file read only after Ack, so a
// crash between delivery and handling delivers it again (the replay log makes
// that harmless). Ack marks the envelope returned by the last Receive.
type EnvelopeAcker interface {
	EnvelopeReceiver
	Ack() error
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

// ErrReplayFull: the sender already has as many live replay entries as it may
// (party.MaxReplayPerSender), or the log is full; the message is refused
// rather than accepted unrecorded. Only that sender is refused.
var ErrReplayFull = errors.New("replay log is full for that sender")

// ReplayLog is the replay log of SPO-Xparty-INV-007. Record takes the Writer
// of the store transaction that applies the message's effect, so the id and
// the effect commit together or not at all: there is no window in which the
// effect happened and a replay is accepted, or the id is recorded and the
// effect lost. Entries are kept until their expiry has passed.
type ReplayLog interface {
	// Seen reports whether id is recorded and not yet expired at now.
	Seen(r Reader, id party.MessageID, now time.Time) (bool, error)
	// Record stores id, sent by sender, until expires; ErrReplay if it is
	// already there, ErrReplayFull when the sender is over its quota.
	Record(w Writer, sender party.Fingerprint, id party.MessageID, expires, now time.Time) error
}

// ---- sealing and opening (SPO-Xparty-OUT-002, PRE-002) ----------------------

// OpenedEnvelope is an envelope that decrypted and passed the first six
// steps of SPO-Xparty-PRE-002. Its body is reachable only through Admit,
// which runs the replay check and the authorisation, so a body cannot be read
// from an envelope that was not admitted.
type OpenedEnvelope interface {
	Sender() party.Party
	Type() party.Type
	ID() party.MessageID
	Created() time.Time
	Expires() time.Time
	// Admit runs step 7 (the message id is not in the replay log: seen) and
	// step 8 (the body decodes and the sender's roles and pools permit it:
	// authorise) and returns the body. It does not record the id: the caller
	// does, in the store transaction of the message's effect (INV-007).
	Admit(seen func(party.MessageID) (bool, error), authorise func(sender party.Party, t party.Type, body party.Body) error) (party.Body, error)
}

// EnvelopeSealer builds envelopes from the local identity. The private
// signing key stays behind it.
type EnvelopeSealer interface {
	// Identity is the local public identity.
	Identity() party.Identity
	// Seal signs and encrypts body from the local identity to the recipient,
	// valid from now to expires, and returns the envelope and its message id.
	Seal(to party.Identity, body party.Body, now, expires time.Time) (envelope []byte, id party.MessageID, err error)
}

// EnvelopeOpener opens envelopes addressed to the local identity.
type EnvelopeOpener interface {
	// Open runs SPO-Xparty-PRE-002 steps 1 to 6 against the lookup of
	// enrolled parties and returns the first refusal.
	Open(envelope []byte, lookup func(party.Fingerprint) (party.Party, bool), now time.Time) (OpenedEnvelope, error)
	// Audit says what a refusal returned by Open or Admit records: the
	// reason and, when the signature verified, the sender
	// (SPO-Xparty-INV-006). known false means the refusal came before the
	// signature step: nothing in it is authenticated.
	Audit(err error) (reason string, sender party.Fingerprint, known bool)
	// IsRefusal tells a refusal of an envelope from a failure of the
	// machinery (a store that could not be read): only a refusal is
	// recorded as an audit event and answered with nothing (INV-006).
	IsRefusal(err error) bool
}

// LocalIdentity is the party's own identity with its private keys in guarded
// memory. Destroy wipes them.
type LocalIdentity interface {
	EnvelopeSealer
	EnvelopeOpener
	Destroy()
}

// GeneratedIdentity is a new identity: the private keys for PutSecret under
// Ref{"local", PartyKeys}, the signed public document for PartyIdentity.
type GeneratedIdentity struct {
	Keys     *Secret
	Document []byte
	Identity party.Identity
}

// IdentityKit generates, parses and loads party identities.
type IdentityKit interface {
	Generate(label string, node *party.NodeKey, now time.Time) (GeneratedIdentity, error)
	// ParseDocument decodes a public identity document strictly. It does not
	// verify the signature: party.Enroll does (SPO-Xparty-PRE-001).
	ParseDocument(b []byte) (party.Document, error)
	// Local loads the workspace's own identity from the store and vault. The
	// caller destroys it.
	Local(ctx context.Context) (LocalIdentity, error)
}

// Multi-party records. All are one JSON blob each, so a change commits
// atomically with the replay entry of the message that caused it.
const (
	// MultisigCoordinator is the coordinator's view of the collections it
	// asked others to sign: per collection and slot, the request last sent.
	MultisigCoordinator Kind = "multisig.coordinator"
	// MultisigSigner is the signer's inbox: every admitted request, its
	// decision and the response it gave (SPO-Xparty-INV-017).
	MultisigSigner Kind = "multisig.signer"
	// MultisigOutbox holds the sealed envelopes not yet handed to a
	// transport (SPO-Xparty-SEC-003).
	MultisigOutbox Kind = "multisig.outbox"
	// MultisigEvents is the log of audit events of OUT-004 and INV-006.
	MultisigEvents Kind = "multisig.events"
	// MultisigCollection holds a witness collection of a transaction that is
	// not a pool registration (the pool's own is in its descriptor).
	MultisigCollection Kind = "multisig.collection"
)

func init() {
	for _, k := range []Kind{MultisigCoordinator, MultisigSigner, MultisigOutbox, MultisigEvents, MultisigCollection} {
		kinds[k] = kindInfo{}
	}
}

// ApprovalGate asks the operator to authenticate again before a key signs
// (SPO-Xparty-INV-016): the wiring prompts for the store passphrase for the
// pool cold, payment and owner stake roles. Signer.Approve calls it with the
// key about to sign and the hash of the body that was reviewed, and signs only
// when it returns nil. There is no default: a Signer with no gate refuses
// to approve.
type ApprovalGate interface {
	Reauthenticate(ctx context.Context, key custody.KeyRef, bodyHash [32]byte) error
}
