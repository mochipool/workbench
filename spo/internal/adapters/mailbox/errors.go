package mailbox

import (
	"errors"
	"fmt"

	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/ports"
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
	// ErrBindingRefused: the relay refused the binding the client presented (the
	// Error code `binding`: invalid, expired or revoked), or the binding the client
	// holds has expired by its own clock, so it did not dial. A new binding must be
	// signed and given to SetBinding. The client backs off and does not retry in a
	// loop. It is an ErrRelayError when the relay said it.
	ErrBindingRefused = errors.New("mailbox: the binding is refused: a new one must be signed")
	// ErrNotAllowed: the relay answered the login with the Error code
	// `not_allowed`: the operator's allow-list does not hold this wallet key. Only
	// the operator can change that. Backed off like ErrBindingRefused; also an
	// ErrRelayError.
	ErrNotAllowed = errors.New("mailbox: the relay's operator does not allow this wallet key")
	// ErrBindingInvalid: a binding given to New or SetBinding did not pass the
	// client's own check (it does not parse or verify, it is for another device,
	// it has expired or is not valid yet, or it is older than the one held). Nothing
	// was changed.
	ErrBindingInvalid = errors.New("mailbox: the binding is not valid for this device now")
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
	switch code {
	case wire.CodeLimit, wire.CodeShuttingDown:
		e.bases = append(e.bases, ErrUnreachable)
	case wire.CodeBinding:
		// the binding is invalid, expired or revoked: a new one must be signed
		e.reason = ReasonBinding
		e.bases = append(e.bases, ErrBindingRefused, ports.ErrIdentityRefused)
	case wire.CodeNotAllowed:
		// the operator's allow-list does not hold this wallet key
		e.reason = ReasonNotAllowed
		e.bases = append(e.bases, ErrNotAllowed, ports.ErrIdentityRefused)
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
	case ReasonUnbound:
		return "the recipient has no binding at this relay yet"
	case ReasonNoWalletKey:
		return "the recipient has no wallet key; it is reachable by file or direct connection only"
	case ReasonBinding:
		return "the relay refuses the binding; a new one must be signed"
	case ReasonBindingExpired:
		return "the binding has expired or is not valid yet; a new one must be signed"
	case ReasonNotAllowed:
		return "the relay's operator does not allow this wallet key"
	}
	return "the relay is not available"
}
