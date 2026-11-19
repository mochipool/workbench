package mailbox

import (
	"errors"
	"fmt"

	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
)

// Errors. A failure of the connection wraps one of the first five, so a caller
// tells what kind of failure it is with errors.Is.
var (
	// ErrUnreachable: the relay could not be reached or did not answer in time,
	// or the stream broke. Nothing is wrong with the relay's answers; trying
	// again later may help.
	ErrUnreachable = errors.New("mailbox: the relay cannot be reached")
	// ErrProtocol: the relay broke the protocol (a frame out of order, malformed,
	// from the wrong side, above a bound, or an envelope that does not hash to
	// its announced id). The client closed the connection and delivered nothing
	// from the reply.
	ErrProtocol = errors.New("mailbox: the relay broke the protocol")
	// ErrRelayKey: the peer is not the relay whose node key the client pinned.
	// The client signed nothing.
	ErrRelayKey = errors.New("mailbox: the peer is not the pinned relay")
	// ErrSigner: the auth signer failed.
	ErrSigner = errors.New("mailbox: the auth signer failed")
	// ErrRelayError: the relay ended the connection with an Error frame (the
	// code is in the event). The codes "limit" and "shutting down" also satisfy
	// ErrUnreachable: the relay is not available now.
	ErrRelayError = errors.New("mailbox: the relay sent an error code")
)

// errRotate is not a failure: a reply cannot be read on this connection without
// passing the client's read bound, so the connection is replaced and the request
// asked again. It never leaves the package.
var errRotate = errors.New("mailbox: replace the connection")

// connErr is a failure of one connection: a fixed reason class, the sentinels
// it satisfies and the underlying cause.
type connErr struct {
	reason  Reason
	bases   []error
	cause   error
	code    wire.Code
	hasCode bool
}

func (e *connErr) Error() string {
	s := fmt.Sprintf("%v (%s)", e.bases[0], e.reason)
	if e.cause != nil {
		s += ": " + e.cause.Error()
	}
	return s
}

func (e *connErr) Unwrap() []error {
	out := append([]error(nil), e.bases...)
	if e.cause != nil {
		out = append(out, e.cause)
	}
	return out
}

func newErr(reason Reason, cause error, bases ...error) *connErr {
	return &connErr{reason: reason, bases: bases, cause: cause}
}

func reasonOf(err error) Reason {
	var ce *connErr
	if errors.As(err, &ce) {
		return ce.reason
	}
	return ReasonPeer
}

func codeOf(err error) (wire.Code, bool) {
	var ce *connErr
	if errors.As(err, &ce) {
		return ce.code, ce.hasCode
	}
	return 0, false
}

// relayError is the failure for an Error frame.
func relayError(code wire.Code) error {
	e := newErr(ReasonRelayError, nil, ErrRelayError)
	if code == wire.CodeLimit || code == wire.CodeShuttingDown {
		e.bases = append(e.bases, ErrUnreachable)
	}
	e.code, e.hasCode = code, true
	return e
}

// reasonText is what the operator reads for a reason class: fixed text.
func reasonText(r Reason) string {
	switch r {
	case ReasonDial:
		return "the relay cannot be reached"
	case ReasonRelayKey:
		return "the peer is not the pinned relay"
	case ReasonVersion:
		return "no protocol version in common with the relay"
	case ReasonProtocol, ReasonLimit:
		return "the relay broke the protocol"
	case ReasonHash:
		return "an envelope did not match its id"
	case ReasonTimeout:
		return "the relay did not answer in time"
	case ReasonPeer:
		return "the connection to the relay broke"
	case ReasonRelayError:
		return "the relay ended the connection with an error"
	case ReasonSigner:
		return "the authentication could not be signed"
	case ReasonBackoff:
		return "waiting before the next attempt to reach the relay"
	case ReasonDialLimit:
		return "too many connections to the relay in the last minute; waiting"
	case ReasonFull:
		return "the mailbox is full"
	case ReasonBusy:
		return "the relay is busy"
	case ReasonStorage:
		return "the relay's storage failed"
	}
	return "the relay is not available"
}
