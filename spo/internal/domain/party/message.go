package party

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
)

// Type names a message (the table in spec/extensions/Xparty.md).
type Type string

const (
	TypeSigningRequest   Type = "SigningRequest"
	TypeSigningResponse  Type = "SigningResponse"
	TypeSigningRefusal   Type = "SigningRefusal"
	TypeCollectionClosed Type = "CollectionClosed"
	TypeInvite           Type = "Invite"
	TypeHello            Type = "Hello"
	TypeBundle           Type = "Bundle"
)

// Types lists every message type.
func Types() []Type {
	return []Type{TypeSigningRequest, TypeSigningResponse, TypeSigningRefusal,
		TypeCollectionClosed, TypeInvite, TypeHello, TypeBundle}
}

// Valid reports whether t is a known type.
func (t Type) Valid() bool {
	for _, k := range Types() {
		if t == k {
			return true
		}
	}
	return false
}

// MessageID is 16 random bytes (SPO-Xparty-OUT-003).
type MessageID [16]byte

// CollectionID names a witness collection; SlotID a slot within it. The spec
// does not fix their shape: a collection id is 16 bytes, a slot id a small
// number.
type (
	CollectionID [16]byte
	SlotID       uint16
)

// Limits. MaxEnvelopeBytes is SPO-Xparty-INV-008; the others bound what a
// well-formed peer sends so that a malicious one cannot make us hold more.
const (
	MaxEnvelopeBytes = 1 << 20
	MaxPurposeBytes  = 1024
	MaxOperationLen  = 64
	MaxWitnessBytes  = 1024
	MaxAddressBytes  = 2048
	// MaxAuxDataBytes bounds the auxiliary data a request carries: it is part
	// of the transaction, which maxTxSize bounds anyway.
	MaxAuxDataBytes = 16384
	// MaxPendingPerSender is how many undecided requests one coordinator may
	// have at a signer; MaxReplayPerSender is how many live replay entries
	// one sender may hold (SPO-Xparty-INV-022).
	MaxPendingPerSender = 64
	MaxReplayPerSender  = 512
	// DefaultMaxTxSize is the upper bound on a transaction body taken when no
	// protocol parameters are wired (SPO-Xparty-INV-008).
	DefaultMaxTxSize = 16384
	MaxBundleTxs     = 1024
	MaxAttachments   = 256
	MaxAttachName    = 128
)

// ErrInvalidBody is returned for a body that breaks a field rule.
var ErrInvalidBody = errors.New("party: invalid message body")

func bad(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidBody, fmt.Sprintf(format, a...))
}

// Body is a message body. Validate checks field sizes and shapes only; what a
// body means for the receiver's state is the receiver's decision.
type Body interface {
	Type() Type
	Validate() error
}

// SigningRequest: coordinator to signer.
// [collection id, slot id, key role, key hash, operation, transaction body
// CBOR, body hash, ttl slot, network magic, purpose text, auxiliary data].
type SigningRequest struct {
	Collection   CollectionID
	Slot         SlotID
	KeyRole      custody.Role
	KeyHash      [28]byte // BLAKE2b-224 of the verification key
	Operation    string
	TxBody       []byte
	BodyHash     [32]byte // BLAKE2b-256 of TxBody
	TTLSlot      uint64
	NetworkMagic uint32
	// Purpose is for display only; nothing is derived from it (SPO-Xparty-INV-011).
	Purpose string
	// AuxData is the auxiliary data of the transaction, as carried in it: a
	// body that has an auxiliary-data hash must come with it, so that the
	// signer can show the metadata (SPO-Xparty-PR-002). Empty when the body
	// has none.
	AuxData []byte
}

func (SigningRequest) Type() Type { return TypeSigningRequest }

func knownRole(r custody.Role) bool {
	for _, k := range custody.Roles() {
		if r == k {
			return true
		}
	}
	return false
}

// Validate checks the field rules. The transaction size against the
// protocol's maxTxSize is CheckTxSize.
func (m SigningRequest) Validate() error {
	switch {
	case !knownRole(m.KeyRole):
		return bad("key role %q", m.KeyRole)
	case m.Operation == "" || len(m.Operation) > MaxOperationLen || !cleanText(m.Operation):
		return bad("operation")
	case len(m.TxBody) == 0 || len(m.TxBody) > MaxEnvelopeBytes:
		return bad("transaction body size %d", len(m.TxBody))
	case len(m.Purpose) > MaxPurposeBytes || !cleanText(m.Purpose):
		return bad("purpose text")
	case m.TTLSlot == 0:
		return bad("ttl slot")
	case len(m.AuxData) > MaxAuxDataBytes:
		return bad("auxiliary data size %d", len(m.AuxData))
	}
	return nil
}

// CheckTxSize is the transaction half of SPO-Xparty-INV-008: the body and the
// auxiliary data together are the transaction's size.
func (m SigningRequest) CheckTxSize(maxTxSize int) error {
	return CheckTxSize(len(m.TxBody), len(m.AuxData), maxTxSize)
}

// CheckTxSize refuses a body and auxiliary data whose sizes together exceed
// maxTxSize (SPO-Xparty-INV-008). The coordinator runs it before sealing, the
// signer on receipt.
func CheckTxSize(bodyLen, auxLen, maxTxSize int) error {
	if bodyLen < 0 || auxLen < 0 || bodyLen > maxTxSize || auxLen > maxTxSize-bodyLen {
		return bad("transaction body (%d bytes) and auxiliary data (%d bytes) together exceed maxTxSize %d", bodyLen, auxLen, maxTxSize)
	}
	return nil
}

// SigningResponse: signer to coordinator.
// [collection id, slot id, request message id, witness CBOR].
type SigningResponse struct {
	Collection CollectionID
	Slot       SlotID
	Request    MessageID
	Witness    []byte
}

func (SigningResponse) Type() Type { return TypeSigningResponse }

func (m SigningResponse) Validate() error {
	if len(m.Witness) == 0 || len(m.Witness) > MaxWitnessBytes {
		return bad("witness size %d", len(m.Witness))
	}
	return nil
}

// RefusalReason is the reason code of a SigningRefusal. The codes follow the
// refusal list of SPO-Xparty-PRE-006, in its order, and add the operator's
// own decision (SPO-Xparty-PR-002).
type RefusalReason uint8

const (
	RefuseNoKey RefusalReason = iota + 1
	RefuseWrongNetwork
	RefuseBodyHash
	RefuseBodyDecode
	RefuseExpired
	RefuseColdKeyOverNetwork
	RefuseCannotSign
	RefuseDeclined
	// Added after the first codes; the numbers never change.
	RefuseOutOfScope
	RefuseCannotResolveInputs
	RefuseNotASignerInput
	RefuseUndisplayable
	// RefuseScriptInput: the body spends a script address, withdraws from a
	// script reward account or carries a certificate or vote with a script
	// credential (SPO-Xparty-PR-004). Silent, like the other reasons that
	// depend on the signer's own chain view.
	RefuseScriptInput
)

// Valid reports whether r is a defined code.
func (r RefusalReason) Valid() bool { return r >= RefuseNoKey && r <= RefuseScriptInput }

// Disclosed reports whether a signer tells the coordinator it refused for
// this reason (SPO-Xparty-INV-006). A reason that depends on the signer's
// private state (which keys it holds, what it owns, whom it trusts for what)
// is never sent: the refusal would let an enrolled coordinator probe that
// state. The signer records it locally and stays silent. The operator's own
// decision is a message.
func (r RefusalReason) Disclosed() bool {
	switch r {
	case RefuseWrongNetwork, RefuseBodyHash, RefuseBodyDecode, RefuseExpired,
		RefuseColdKeyOverNetwork, RefuseDeclined, RefuseUndisplayable:
		return true
	}
	return false
}

// SigningRefusal: signer to coordinator.
// [collection id, slot id, request message id, reason code].
type SigningRefusal struct {
	Collection CollectionID
	Slot       SlotID
	Request    MessageID
	Reason     RefusalReason
}

func (SigningRefusal) Type() Type { return TypeSigningRefusal }

func (m SigningRefusal) Validate() error {
	if !m.Reason.Valid() {
		return bad("refusal reason %d", m.Reason)
	}
	return nil
}

// Outcome of a collection.
type Outcome string

const (
	OutcomeSubmitted Outcome = "submitted"
	OutcomeDiscarded Outcome = "discarded"
	OutcomeExpired   Outcome = "expired"
)

// CollectionClosed: coordinator to signer.
// [collection id, outcome: submitted with tx id, discarded, or expired].
// On the wire the outcome is a text string and the transaction id a byte
// string, empty unless submitted.
type CollectionClosed struct {
	Collection CollectionID
	Outcome    Outcome
	TxID       []byte // 32 bytes when submitted, empty otherwise
}

func (CollectionClosed) Type() Type { return TypeCollectionClosed }

func (m CollectionClosed) Validate() error {
	switch m.Outcome {
	case OutcomeSubmitted:
		if len(m.TxID) != 32 {
			return bad("submitted needs a 32-byte transaction id")
		}
	case OutcomeDiscarded, OutcomeExpired:
		if len(m.TxID) != 0 {
			return bad("%s carries no transaction id", m.Outcome)
		}
	default:
		return bad("outcome %q", m.Outcome)
	}
	return nil
}

// Invite: coordinator to signer. [tailcat address, coordinator tailcat node
// key]. The address is a Secret (SPO-Xparty-SEC-001): it is redacted in
// every format verb.
type Invite struct {
	Address string
	Node    NodeKey
}

func (Invite) Type() Type { return TypeInvite }

func (m Invite) Validate() error {
	if m.Address == "" || len(m.Address) > MaxAddressBytes || !cleanText(m.Address) {
		return bad("tailcat address")
	}
	if zero32(m.Node) {
		return bad("node key")
	}
	return nil
}

func (m Invite) String() string   { return "Invite{[redacted]}" }
func (m Invite) GoString() string { return m.String() }

// Hello: signer to coordinator, empty body (SPO-Xparty-INV-021). It opens a
// connection when the signer has nothing else to send, so that it can receive
// the requests waiting for it. It has no effect beyond authenticating the
// connection.
type Hello struct{}

func (Hello) Type() Type      { return TypeHello }
func (Hello) Validate() error { return nil }

var attachRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// Attachment is a named blob in a Bundle. The name is a plain label, never a
// path (SPO-Ptransfer-SEC-001).
type Attachment struct {
	Name string
	Data []byte
}

// Bundle: machine to machine, the air-gap bundle. [chain snapshot, queued
// transactions, attachments]; the spec leaves the inner shape open, this is
// the smallest one: a snapshot blob, a list of transaction blobs, a list of
// named attachments.
type Bundle struct {
	Snapshot     []byte
	Transactions [][]byte
	Attachments  []Attachment
}

func (Bundle) Type() Type { return TypeBundle }

func (m Bundle) Validate() error {
	if len(m.Transactions) > MaxBundleTxs || len(m.Attachments) > MaxAttachments {
		return bad("too many items")
	}
	total := len(m.Snapshot)
	for _, t := range m.Transactions {
		total += len(t)
	}
	seen := map[string]bool{}
	for _, a := range m.Attachments {
		if !attachRE.MatchString(a.Name) || strings.Contains(a.Name, "..") || seen[a.Name] {
			return bad("attachment name %q", a.Name)
		}
		seen[a.Name] = true
		total += len(a.Data)
	}
	if total > MaxEnvelopeBytes {
		return bad("bundle is larger than an envelope")
	}
	return nil
}

// Timing (SPO-Xparty-PRE-002, INV-009).
const (
	// ClockSkew is how far in the future a created time may be.
	ClockSkew = 10 * time.Minute
	// MaxRequestLifetime caps SigningRequest.expires after created (INV-009).
	MaxRequestLifetime = 7 * 24 * time.Hour
	// MaxHelloLifetime caps Hello.expires after created (SPO-Xparty-INV-021).
	MaxHelloLifetime = 5 * time.Minute
	// MaxLifetime caps any message's lifetime. The spec does not set it; the
	// replay log holds an id until expiry, so an unbounded expiry would let
	// a peer grow it without limit.
	MaxLifetime = 30 * 24 * time.Hour
)

// Timing refusals.
var (
	ErrExpired    = errors.New("party: message expired")
	ErrFromFuture = errors.New("party: message created in the future")
	ErrWindow     = errors.New("party: message validity window is malformed")
)

// CheckWindow is the time step of SPO-Xparty-PRE-002: expires has not
// passed, and created is at most ClockSkew ahead. It also refuses a window
// that ends before it starts or is longer than MaxLifetime.
func CheckWindow(created, expires, now time.Time) error {
	if now.After(expires) {
		return ErrExpired
	}
	if created.After(now.Add(ClockSkew)) {
		return ErrFromFuture
	}
	if expires.Before(created) || expires.Sub(created) > MaxLifetime {
		return ErrWindow
	}
	return nil
}

// ErrRequestExpiry is SPO-Xparty-INV-009.
var ErrRequestExpiry = errors.New("party: signing request expires later than allowed")

// CheckRequestExpiry is SPO-Xparty-INV-009: expires is no later than the
// wall-clock time of the body's TTL slot, and no later than 7 days after
// created. Converting the slot to a time needs the chain's genesis, so the
// caller passes the result.
func CheckRequestExpiry(created, expires, ttlTime time.Time) error {
	if expires.After(ttlTime) || expires.After(created.Add(MaxRequestLifetime)) {
		return ErrRequestExpiry
	}
	return nil
}

// ErrHelloExpiry is SPO-Xparty-INV-021.
var ErrHelloExpiry = errors.New("party: hello expires later than 5 minutes after it was created")

// CheckHelloExpiry is the lifetime rule of SPO-Xparty-INV-021.
func CheckHelloExpiry(created, expires time.Time) error {
	if expires.After(created.Add(MaxHelloLifetime)) {
		return ErrHelloExpiry
	}
	return nil
}

// String names the reason for display and for the audit log.
func (r RefusalReason) String() string {
	switch r {
	case RefuseNoKey:
		return "no key with that hash and role"
	case RefuseWrongNetwork:
		return "wrong network"
	case RefuseBodyHash:
		return "body hash does not match the body"
	case RefuseBodyDecode:
		return "body does not decode"
	case RefuseExpired:
		return "ttl slot has passed"
	case RefuseColdKeyOverNetwork:
		return "pool cold key requested over a network transport"
	case RefuseCannotSign:
		return "signer cannot meet the demand of the body"
	case RefuseDeclined:
		return "declined by the operator"
	case RefuseOutOfScope:
		return "outside the coordinator's scope"
	case RefuseCannotResolveInputs:
		return "cannot resolve the inputs of the request"
	case RefuseNotASignerInput:
		return "no input of the body is this signer's"
	case RefuseUndisplayable:
		return "the body has a part that cannot be displayed in full"
	case RefuseScriptInput:
		return "the body spends or acts for a script, whose witness set the signer cannot see"
	}
	return "unknown reason"
}

// Describe is String with the key role the request asked for named, for the
// reasons whose meaning depends on it: whether the inputs must resolve
// depends on the role (a payment key always, any other key over a network,
// SPO-Xparty-PRE-007), so the text says which request it refused.
func (r RefusalReason) Describe(role custody.Role) string {
	if r == RefuseCannotResolveInputs {
		return "cannot resolve the inputs of a " + string(role) + " key request"
	}
	return r.String()
}

// FileName is the file transport's name for an envelope (SPO-Xparty-IF-004):
// <type>-<collection id prefix>-<slot>.spo, the prefix being the first 4
// bytes in hex.
func FileName(t Type, c CollectionID, s SlotID) string {
	return fmt.Sprintf("%s-%x-%d.spo", t, c[:4], s)
}
