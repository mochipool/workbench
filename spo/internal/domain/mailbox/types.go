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

	// ErrAuth is the root of every failed authentication. The two below, and
	// ErrAuthWeakKey, are the specific reasons; each is reported together with
	// ErrAuth, so errors.Is(err, ErrAuth) holds for all of them. A bad signature is
	// ErrAuth alone.
	ErrAuthFingerprint = errors.New("the claimed fingerprint is not that of the presented keys")
	ErrAuthTunnelKey   = errors.New("the claimed node key is not the tunnel peer's")
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

// Put statuses (ADR 0013 decision 6; StatusUnbound is ADR 0014's).
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
func (s Status) Valid() bool { return s.ValidIn(Version2) }

// Code is the error code of an Error message.
type Code uint64

// Error codes. No text travels with them. CodeNotAllowed and CodeBinding are
// ADR 0014's (types_v2.go).
const (
	CodeVersion      Code = 0
	CodeAuth         Code = 1
	CodeProtocol     Code = 2
	CodeLimit        Code = 3
	CodeRevoked      Code = 4
	CodeShuttingDown Code = 5
)

// Valid reports whether c is a defined code.
func (c Code) Valid() bool { return c.ValidIn(Version2) }

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
func (PutResult) Type() MsgType { return MsgPutResult }
func (Fetch) Type() MsgType     { return MsgFetch }
func (Items) Type() MsgType     { return MsgItems }
func (Ack) Type() MsgType       { return MsgAck }
func (AckResult) Type() MsgType { return MsgAckResult }
func (Error) Type() MsgType     { return MsgError }

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
