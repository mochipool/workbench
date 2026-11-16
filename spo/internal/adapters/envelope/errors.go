package envelope

import (
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// Refusal reasons, in the order of SPO-Xparty-PRE-002. They are for the audit
// log (SPO-Xparty-INV-006). Test with errors.Is.
var (
	ErrTooLarge      = errors.New("envelope: larger than 1 MiB or empty") // INV-008, checked before decryption
	ErrDecrypt       = errors.New("envelope: does not decrypt")
	ErrVersion       = errors.New("envelope: unknown version")
	ErrSenderUnknown = errors.New("envelope: sender is not an enrolled party")
	ErrSenderRevoked = errors.New("envelope: sender is revoked")
	ErrSignature     = errors.New("envelope: signature does not verify")
	ErrNotRecipient  = errors.New("envelope: addressed to another party")
	// ErrExpired, ErrFromFuture and ErrWindow are party's.
	ErrExpired    = party.ErrExpired
	ErrFromFuture = party.ErrFromFuture
	ErrWindow     = party.ErrWindow
	ErrReplayed   = errors.New("envelope: message id already accepted")
	// authorisation is party.ErrNotAuthorised; a body that does not decode
	// or validate is ErrMalformed or party.ErrInvalidBody.
)

// Refusal wraps the reason an envelope was refused with the sender, when it
// is known. Sender is set only once the signature has verified under the
// enrolled party's key; before that, including when the signature fails or
// the party is revoked, the fingerprint is the claim of whoever sent the
// bytes, and an attacker-chosen fingerprint is never recorded as the sender.
type Refusal struct {
	Err       error
	Sender    party.Fingerprint
	HasSender bool
}

func (r *Refusal) Error() string {
	if r.HasSender {
		return fmt.Sprintf("envelope refused (sender %s): %v", r.Sender, r.Err)
	}
	return fmt.Sprintf("envelope refused: %v", r.Err)
}

func (r *Refusal) Unwrap() error { return r.Err }

func refuse(err error) error { return &Refusal{Err: err} }

func refuseFrom(err error, s party.Fingerprint) error {
	return &Refusal{Err: err, Sender: s, HasSender: true}
}

// Audit returns what the audit log records for a refusal: the reason text
// and the sender when known.
func Audit(err error) (reason string, sender party.Fingerprint, known bool) {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Err.Error(), r.Sender, r.HasSender
	}
	return err.Error(), party.Fingerprint{}, false
}

// Outward is the one response a sender gets for any refusal
// (SPO-Xparty-INV-006): nothing. It returns no bytes for every error, so
// nothing about the reason reaches the peer and nothing is written before a
// signature has verified. Callers use it for every refusal and never build a
// reply from the error. A refusal still costs different time per step (a
// decryption failure is cheaper than a signature check); that is not hidden.
func Outward(err error) []byte { return nil }
