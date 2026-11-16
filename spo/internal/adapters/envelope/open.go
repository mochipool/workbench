package envelope

import (
	"bytes"
	"io"
	"time"

	"filippo.io/age"
	"github.com/fxamacker/cbor/v2"

	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// LookupFunc finds an enrolled party by fingerprint. It returns ok false for
// an unknown one. It may return a revoked party; Open refuses it.
type LookupFunc func(party.Fingerprint) (p party.Party, ok bool)

// Opened is an envelope that passed the first six steps of SPO-Xparty-PRE-002:
// it decrypted, its version is known, its sender is an active enrolled party,
// the signature verified under that party's key, it is addressed to us, and
// its window is valid. Only Open makes one, and the body is reachable only
// through Admit, so no body is visible for an envelope whose signature did
// not verify.
type Opened struct {
	sender    party.Party
	typ       party.Type
	id        party.MessageID
	recipient party.Fingerprint
	created   time.Time
	expires   time.Time
	body      []byte // verified, not yet decoded
}

func (o *Opened) Sender() party.Party          { return o.sender }
func (o *Opened) Type() party.Type             { return o.typ }
func (o *Opened) ID() party.MessageID          { return o.id }
func (o *Opened) Created() time.Time           { return o.created }
func (o *Opened) Expires() time.Time           { return o.expires }
func (o *Opened) Recipient() party.Fingerprint { return o.recipient }

// Open runs PRE-002 steps one to six in the spec's order and returns the first
// refusal as a *Refusal:
//
//  0. size at most party.MaxEnvelopeBytes (INV-008), before anything is
//     allocated for decryption: ErrTooLarge;
//  1. it decrypts under our X25519 key: ErrDecrypt;
//  2. the payload version is known: ErrVersion (a malformed plaintext is
//     ErrMalformed);
//  3. the sender fingerprint is an active enrolled party: ErrSenderUnknown,
//     ErrSenderRevoked;
//  4. the signature verifies under that party's Ed25519 key: ErrSignature;
//  5. the recipient fingerprint is ours: ErrNotRecipient;
//  6. expires has not passed and created is at most 10 minutes ahead
//     (ErrExpired, ErrFromFuture, ErrWindow).
//
// Steps 7 (replay) and 8 (authorisation) need the caller's store and
// registry: they are Admit, which the caller must call before acting on the
// message. The sender is recorded in a refusal only once the signature has
// verified (from step 5 on); before that, a failed signature and a revoked
// sender included, the fingerprint in the payload is an attacker's claim.
//
// Open reads no clock and no store; now and lookup are inputs.
func Open(recipient *Private, envelope []byte, lookup LookupFunc, now time.Time) (*Opened, error) {
	if len(envelope) == 0 || len(envelope) > party.MaxEnvelopeBytes {
		return nil, refuse(ErrTooLarge)
	}
	plain, err := decrypt(recipient, envelope)
	if err != nil {
		return nil, refuse(ErrDecrypt)
	}
	var outer plaintextWire
	if err := unmarshal(plain, &outer); err != nil {
		return nil, refuse(err)
	}
	// The version is read before the payload is interpreted: another
	// version may lay its fields out differently.
	var head []cbor.RawMessage
	if err := dec.Unmarshal(outer.Payload, &head); err != nil || len(head) == 0 {
		return nil, refuse(ErrMalformed)
	}
	var version uint
	if err := dec.Unmarshal(head[0], &version); err != nil {
		return nil, refuse(ErrMalformed)
	}
	if version != Version {
		return nil, refuse(ErrVersion)
	}
	var w payloadWire
	if err := unmarshal(outer.Payload, &w); err != nil {
		return nil, refuse(err)
	}
	var sfp, rfp party.Fingerprint
	o := &Opened{typ: party.Type(w.Type), created: time.Unix(w.Created, 0).UTC(), expires: time.Unix(w.Expires, 0).UTC(), body: w.Body}
	if err := firstErr(fixed(sfp[:], w.Sender), fixed(rfp[:], w.Recipient), fixed(o.id[:], w.ID)); err != nil {
		return nil, refuse(err)
	}
	p, ok := lookup(sfp)
	if !ok || p.Fingerprint != sfp {
		return nil, refuse(ErrSenderUnknown)
	}
	if !p.Active() {
		return nil, refuse(ErrSenderRevoked) // the signature is not checked yet: nothing is authenticated
	}
	if len(outer.Signature) != ed25519SigLen || !verifySig(p.Identity.Ed25519, outer.Payload, outer.Signature) {
		return nil, refuse(ErrSignature) // the fingerprint is a claim of whoever sent the bytes
	}
	if !equalFP(rfp, recipient.Fingerprint()) {
		return nil, refuseFrom(ErrNotRecipient, sfp)
	}
	if err := party.CheckWindow(o.created, o.expires, now); err != nil {
		return nil, refuseFrom(err, sfp)
	}
	o.sender, o.recipient = p, rfp
	return o, nil
}

const ed25519SigLen = 64

// decrypt opens the age ciphertext. The plaintext is bounded: age's output is
// no larger than its input, and the read stops one byte past the envelope
// limit regardless.
func decrypt(recipient *Private, envelope []byte) ([]byte, error) {
	id, err := recipient.ageIdentity()
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(envelope), id)
	if err != nil {
		return nil, err
	}
	plain, err := io.ReadAll(io.LimitReader(r, party.MaxEnvelopeBytes+1))
	if err != nil || len(plain) > party.MaxEnvelopeBytes {
		return nil, ErrDecrypt
	}
	return plain, nil
}

// Admit runs the rest of SPO-Xparty-PRE-002 and returns the body:
//
//  7. the message id is not in the replay log: ErrReplayed (seen reports it);
//  8. the body decodes and validates (ErrMalformed, party.ErrInvalidBody),
//     then the sender's roles and pools permit the message type
//     (authorise, normally party.Authorise with a Concern built from the
//     receiver's own state: party.ErrNotAuthorised).
//
// The body is decoded between 7 and 8 only because authorisation needs the
// pool it concerns. An error from seen is the store failing, not a refusal,
// and is returned as is. Admit does not record the id: the caller does that
// with ports.ReplayLog.Record in the transaction of the message's effect
// (SPO-Xparty-INV-007), which returns ErrReplay if another transaction got
// there first.
func (o *Opened) Admit(seen func(party.MessageID) (bool, error), authorise func(sender party.Party, t party.Type, body party.Body) error) (party.Body, error) {
	dup, err := seen(o.id)
	if err != nil {
		return nil, err
	}
	if dup {
		return nil, refuseFrom(ErrReplayed, o.sender.Fingerprint)
	}
	body, err := decodeBody(o.typ, o.body)
	if err != nil {
		return nil, refuseFrom(err, o.sender.Fingerprint)
	}
	if err := authorise(o.sender, o.typ, body); err != nil {
		return nil, refuseFrom(err, o.sender.Fingerprint)
	}
	return body, nil
}
