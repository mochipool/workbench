package chain

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// TipFreshnessWindow is how old the tip of a web provider may be, against the
// local clock, before its answers stop counting (SPO-Xconfirm-INV-001). The
// expiry slack of a wait is derived from it (SPO-Xconfirm-PRE-002).
const TipFreshnessWindow = 10 * time.Minute

// MaxConfirmations bounds a confirmation count taken from a provider's JSON.
// A chain has at most a few tens of millions of blocks; a larger number is
// nonsense, and the reading is unknown rather than a printed depth
// (SPO-Xconfirm-IF-002).
const MaxConfirmations = 100_000_000

// ErrSubmitOutcomeUnknown is matched (errors.Is) by every adapter's "the
// transaction was sent and no answer came back" error. The transaction may be
// in a block or a mempool, so the caller checks its status before it builds
// another one from the same inputs.
var ErrSubmitOutcomeUnknown = errors.New("the outcome of the submission is unknown")

// NewOutcomeUnknown makes an adapter's own submit-outcome-unknown error: it
// prints msg and matches ErrSubmitOutcomeUnknown (and itself).
func NewOutcomeUnknown(msg string) error { return &outcomeUnknown{msg: msg} }

type outcomeUnknown struct{ msg string }

func (e *outcomeUnknown) Error() string { return e.msg }

func (e *outcomeUnknown) Is(target error) bool { return target == ErrSubmitOutcomeUnknown }

// IDMismatchError is the answer of a provider that accepted a transaction and
// named a different id for it than the one computed from the bytes sent. The
// transaction left, so this is an unknown outcome and not a refusal: it
// matches ErrSubmitOutcomeUnknown, and a caller keeps whatever it staged for
// the transaction (SPO-Xconfirm-PR-008).
type IDMismatchError struct{ Answered, Local TxID }

func (e *IDMismatchError) Error() string {
	return fmt.Sprintf("the provider answered transaction id %s for %s: the transaction may have been accepted under its own id. Check where it is with: spo tx status %s", e.Answered, e.Local, e.Local)
}

// Is makes a mismatch an unknown submit outcome.
func (e *IDMismatchError) Is(target error) bool { return target == ErrSubmitOutcomeUnknown }

// SubmitStatusRefuses says whether an HTTP status from a web provider's submit
// endpoint is a definite refusal: the node or the provider looked at the
// transaction and said no, so it did not leave. The rule: a 4xx is definite
// (400 carries the node's rejection; 401, 403, 404, 413 and the like are
// stopped before the transaction is looked at), except 408, 425 and 429, which
// say the request was not finished or deferred and do not say the transaction
// was not taken. Every other status, a 5xx (a gateway can answer 502 after it
// forwarded the transaction), a 3xx, or a 2xx the adapter did not expect, is
// an unknown outcome (SPO-Xconfirm-PR-008).
func SubmitStatusRefuses(status int) bool {
	if status < 400 || status > 499 {
		return false
	}
	switch status {
	case 408, 425, 429:
		return false
	}
	return true
}

// TxState is where a provider says a transaction is.
type TxState int

const (
	// TxInBlock: the transaction is in a block of the provider's chain.
	TxInBlock TxState = iota + 1
	// TxInMempool: the provider holds the transaction in its mempool and it is
	// in no block yet. Only a provider that can say so honestly reports it.
	TxInMempool
)

// TxStatus is a provider's statement about a transaction it has seen. "Not
// seen" is the None reading, never a TxStatus, and is stated only from a
// positive answer of a fresh, synced provider (SPO-Xconfirm-INV-001).
type TxStatus struct {
	State TxState
	// BlockHeight and Slot are those of the block that holds the transaction,
	// when the provider states them.
	BlockHeight     uint64
	HaveBlockHeight bool
	Slot            uint64
	HaveSlot        bool
	// Confirmations counts blocks from the one that holds the transaction to
	// the provider's tip (SPO-Xconfirm-INV-003). A provider that cannot count
	// them leaves HaveConfirmations false.
	Confirmations     uint64
	HaveConfirmations bool
}

// Depth is the number of confirmations of a transaction in a block, and
// whether it is stated. A provider that says "in a block" and not how deep
// counts as depth 1: the block exists at its tip, and nothing more is claimed
// (SPO-Xconfirm-INV-003).
func (s TxStatus) Depth() (depth uint64, stated bool) {
	if s.State != TxInBlock {
		return 0, false
	}
	if s.HaveConfirmations {
		return s.Confirmations, true
	}
	return 1, false
}

// Text is a short plain description of the statement. Numbers only: nothing a
// provider chose as text is in it.
func (s TxStatus) Text() string {
	switch s.State {
	case TxInMempool:
		return "in the mempool, in no block yet"
	case TxInBlock:
		var parts []string
		if s.HaveBlockHeight {
			parts = append(parts, fmt.Sprintf("block %d", s.BlockHeight))
		}
		if s.HaveSlot {
			parts = append(parts, fmt.Sprintf("slot %d", s.Slot))
		}
		out := "in a block"
		if len(parts) > 0 {
			out += " (" + strings.Join(parts, ", ") + ")"
		}
		if s.HaveConfirmations {
			out += fmt.Sprintf(", %d confirmation(s)", s.Confirmations)
		} else {
			out += ", depth not stated"
		}
		return out
	}
	return "unrecognised state"
}

// ProviderAnswer is one provider's reading of one transaction.
type ProviderAnswer struct {
	Source  Source
	Reading Reading[TxStatus]
}

// Verdict is what the answers of every configured provider say together.
type Verdict int

const (
	// VerdictUnknown: no provider gave a usable answer, or some did not and
	// none of the others saw the transaction. Nothing is said about the chain.
	VerdictUnknown Verdict = iota
	// VerdictNotSeen: every provider answered and none has seen it.
	VerdictNotSeen
	// VerdictPending: seen, but in a mempool only or in a block that is not
	// yet as deep as asked.
	VerdictPending
	// VerdictConfirmed: every provider says it is in a block, at the depth
	// asked.
	VerdictConfirmed
	// VerdictDisagree: one provider has it in a block or a mempool and another
	// says it has not seen it.
	VerdictDisagree
	// VerdictPartial: at least one provider has seen it and the others gave no
	// usable answer. Never reported as confirmed.
	VerdictPartial
)

// Assess combines the answers of every configured provider (SPO-Xconfirm-INV-002).
// "Confirmed" needs every provider to say in a block, each at depth want or
// more; a provider that does not state a depth satisfies want of 1 or less.
// With no answers the verdict is Unknown.
func Assess(answers []ProviderAnswer, want uint64) Verdict {
	var seen, none, unknown, shallow, mempool int
	for _, a := range answers {
		switch st, ok := a.Reading.Get(); {
		case ok:
			seen++
			if st.State == TxInMempool {
				mempool++
				continue
			}
			d, stated := st.Depth()
			if d < want || (!stated && want > 1) {
				shallow++
			}
		case a.Reading.IsNone():
			none++
		default:
			unknown++
		}
	}
	switch {
	case len(answers) == 0 || (seen == 0 && none == 0):
		return VerdictUnknown
	case seen == 0:
		if unknown > 0 {
			return VerdictUnknown // a silent provider keeps "not seen" from being said
		}
		return VerdictNotSeen
	case none > 0:
		return VerdictDisagree
	case unknown > 0:
		return VerdictPartial
	case mempool > 0 || shallow > 0:
		return VerdictPending
	}
	return VerdictConfirmed
}

// String names the verdict in plain words.
func (v Verdict) String() string {
	switch v {
	case VerdictNotSeen:
		return "not seen"
	case VerdictPending:
		return "seen, not yet confirmed"
	case VerdictConfirmed:
		return "confirmed"
	case VerdictDisagree:
		return "the providers disagree"
	case VerdictPartial:
		return "seen by one provider, the others gave no answer"
	}
	return "unknown"
}
