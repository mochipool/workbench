package mailbox

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// Errors. Every refusal wraps one of these.
var (
	ErrFrameSize    = errors.New("mailbox: frame length out of bounds")
	ErrNotCanonical = errors.New("mailbox: the CBOR is not canonical")
	ErrShape        = errors.New("mailbox: the CBOR exceeds a structural bound")
	ErrMalformed    = errors.New("mailbox: malformed message")
	ErrRange        = errors.New("mailbox: value out of range")
	ErrUnknownType  = errors.New("mailbox: unknown message type")
	ErrVersion      = errors.New("mailbox: unsupported protocol version")
	ErrHash         = errors.New("mailbox: envelope hash mismatch")
	ErrSize         = errors.New("mailbox: envelope size mismatch")
	ErrTooLarge     = errors.New("mailbox: envelope too large")
	ErrAuth         = errors.New("mailbox: authentication failed")
	ErrQuota        = errors.New("mailbox: invalid quota configuration")
	ErrDirection    = errors.New("mailbox: the peer may not send this message type")

	// ErrAuth is the root of every failed authentication. The four below are
	// the specific reasons; each is reported together with ErrAuth, so
	// errors.Is(err, ErrAuth) holds for all of them. A bad signature is
	// ErrAuth alone.
	ErrAuthNoNodeKey    = errors.New("the listed identity has no node key")
	ErrAuthFingerprint  = errors.New("the claimed fingerprint is not that of the listed identity")
	ErrAuthTunnelKey    = errors.New("the claimed node key is not the tunnel peer's")
	ErrAuthIdentityNode = errors.New("the claimed node key is not the listed identity's")
)

func bad(sentinel error, format string, a ...any) error {
	return fmt.Errorf("%w: %s", sentinel, fmt.Sprintf(format, a...))
}

// Hash is the mailbox id: Blake2b-256 of the envelope bytes (ADR 0013
// decision 2). It is an identifier, not a signature.
type Hash [HashSize]byte

// String is the lower-case hex form used in names.
func (h Hash) String() string { return hex.EncodeToString(h[:]) }

// MsgType is the first element of every header array.
type MsgType uint64

// Message types.
const (
	MsgChallenge MsgType = 0
	MsgAuth      MsgType = 1
	MsgAuthOK    MsgType = 2
	MsgPut       MsgType = 3
	MsgPutResult MsgType = 4
	MsgFetch     MsgType = 5
	MsgItems     MsgType = 6
	MsgAck       MsgType = 7
	MsgAckResult MsgType = 8
	MsgError     MsgType = 9
)

// Status is the result code of a put.
type Status uint64

// Put statuses (ADR 0013 decision 6).
const (
	StatusStored      Status = 0
	StatusDuplicate   Status = 1
	StatusRefused     Status = 2
	StatusFull        Status = 3
	StatusTooLarge    Status = 4
	StatusBadHash     Status = 5
	StatusBusy        Status = 6
	StatusUnavailable Status = 7
)

// Valid reports whether s is a defined status.
func (s Status) Valid() bool { return s <= StatusUnavailable }

// Code is the error code of an Error message.
type Code uint64

// Error codes. No text travels with them.
const (
	CodeVersion      Code = 0
	CodeAuth         Code = 1
	CodeProtocol     Code = 2
	CodeLimit        Code = 3
	CodeRevoked      Code = 4
	CodeShuttingDown Code = 5
)

// Valid reports whether c is a defined code.
func (c Code) Valid() bool { return c <= CodeShuttingDown }

// Message is one header frame. The method set is closed: only the types of
// this package implement it.
type Message interface {
	Type() MsgType
	fields() ([]any, error)
}

// Challenge: relay to client, `[min, max, nonce, relay node key, relay time]`.
type Challenge struct {
	Min, Max  uint
	Nonce     [NonceSize]byte
	RelayKey  party.NodeKey
	RelayTime int64 // unix seconds; unauthenticated
}

// Auth: client to relay, `[version, fingerprint, signature]`.
type Auth struct {
	Version     uint
	Fingerprint party.Fingerprint
	Signature   [SignatureSize]byte
}

// AuthOK: relay to client, the limits that apply.
type AuthOK struct {
	Version          uint
	MaxEnvelope      uint64
	MaxEntries       uint64
	MaxBytes         uint64
	RetentionSeconds uint64
}

// Put: client to relay. The header is followed by one raw frame of Size bytes.
type Put struct {
	RequestID uint32
	To        party.Fingerprint
	Mid       Hash
	Size      uint32
}

// PutResult: relay to client.
type PutResult struct {
	RequestID uint32
	Status    Status
}

// Fetch: client to relay. A nil After means "from the start".
type Fetch struct {
	RequestID   uint32
	After       *Hash
	MaxItems    uint
	WaitSeconds uint
}

// Item names one entry of an Items reply.
type Item struct {
	Mid  Hash
	Size uint32
}

// NewPut builds a Put for an envelope whose hash and size the caller already
// has. It refuses a size outside 1 to MaxEnvelopeBytes. It cannot check that
// mid is the hash of the envelope that will follow the header: that is the
// sender's obligation, and NewPutOf makes it by construction.
func NewPut(requestID uint32, to party.Fingerprint, mid Hash, size uint32) (Put, error) {
	if err := checkSize(uint64(size)); err != nil {
		return Put{}, err
	}
	return Put{RequestID: requestID, To: to, Mid: mid, Size: size}, nil
}

// NewPutOf builds the Put for an envelope: Mid and Size are computed from the
// bytes, so the header cannot disagree with them. The sender must still send
// exactly these bytes in the raw frame that follows.
func NewPutOf(requestID uint32, to party.Fingerprint, envelope []byte) (Put, error) {
	if len(envelope) == 0 || len(envelope) > MaxEnvelopeBytes {
		return Put{}, bad(ErrRange, "envelope size %d is not 1 to %d", len(envelope), MaxEnvelopeBytes)
	}
	return Put{RequestID: requestID, To: to, Mid: HashOf(envelope), Size: uint32(len(envelope))}, nil
}

// Items: relay to client. The header is followed by one raw frame per entry.
type Items struct {
	RequestID uint32
	Entries   []Item
	More      bool
}

// Ack: client to relay, at most MaxAckHashes distinct hashes.
type Ack struct {
	RequestID uint32
	Mids      []Hash
}

// AckResult: relay to client.
type AckResult struct {
	RequestID uint32
	Deleted   uint
}

// Error: relay to client; the relay then closes.
type Error struct{ Code Code }

func (Challenge) Type() MsgType { return MsgChallenge }
func (Auth) Type() MsgType      { return MsgAuth }
func (AuthOK) Type() MsgType    { return MsgAuthOK }
func (Put) Type() MsgType       { return MsgPut }
func (PutResult) Type() MsgType { return MsgPutResult }
func (Fetch) Type() MsgType     { return MsgFetch }
func (Items) Type() MsgType     { return MsgItems }
func (Ack) Type() MsgType       { return MsgAck }
func (AckResult) Type() MsgType { return MsgAckResult }
func (Error) Type() MsgType     { return MsgError }

// AuthParams are the typed, fixed-length inputs of the signed auth array.
// There is no field for arbitrary bytes.
type AuthParams struct {
	Version       uint
	RelayKey      party.NodeKey // the key the client pinned, never read from the challenge
	ClientNodeKey party.NodeKey // the client's own node key
	Nonce         [NonceSize]byte
	RelayTime     int64
	Fingerprint   party.Fingerprint
}

// Quota holds the bounds of ADR 0013 decision 2 for one relay. Zero values
// are invalid; use DefaultQuota, tighten, and call Validated: only a
// ValidQuota admits a put.
type Quota struct {
	MailboxEntries uint64
	MailboxBytes   uint64
	PairEntries    uint64
	PairBytes      uint64
	SenderBytes    uint64
	GlobalBytes    uint64
}

// Usage is what the store reports before a put is admitted: the figures
// before the put.
type Usage struct {
	MailboxEntries uint64
	MailboxBytes   uint64
	PairEntries    uint64
	PairBytes      uint64
	SenderBytes    uint64
	GlobalBytes    uint64
}
