package envelope

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"io"
	"time"

	"filippo.io/age"
	"github.com/fxamacker/cbor/v2"

	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// EnvelopeDomain prefixes the bytes the envelope signature covers
// (SPO-Xparty-OUT-002).
const EnvelopeDomain = "spo/envelope/v1"

// plaintextWire is what age encrypts: [payload, signature]. The payload is a
// byte string holding canonical CBOR, so the signature covers exactly the
// bytes the receiver parses.
type plaintextWire struct {
	_         struct{} `cbor:",toarray"`
	Payload   []byte
	Signature []byte
}

// payloadWire is SPO-Xparty-OUT-003:
// [version, type, sender fp, recipient fp, message id, created, expires, body].
type payloadWire struct {
	_         struct{} `cbor:",toarray"`
	Version   uint
	Type      string
	Sender    []byte
	Recipient []byte
	ID        []byte
	Created   int64
	Expires   int64
	Body      cbor.RawMessage
}

func signedBytes(payload []byte) []byte {
	return append([]byte(EnvelopeDomain), payload...)
}

// Seal builds the envelope for body, from sender to recipient: it encodes the
// payload with a fresh message id read from rand, signs it with the sender's
// Ed25519 key, and encrypts payload and signature to the recipient's X25519
// key with age. The message type is the body's. created is now. It returns
// the envelope and the message id (the coordinator keeps it as the last
// request id of a slot).
//
// The id is the only use of rand. age draws its own randomness (the
// ephemeral key and file key) from crypto/rand, so the ciphertext differs
// each time; the plaintext and the signature are deterministic given the id.
//
// Seal refuses an invalid body, a window CheckWindow refuses, and a result
// larger than party.MaxEnvelopeBytes. SigningRequest's INV-009 expiry rule
// needs the TTL slot's wall-clock time and is the caller's
// (party.CheckRequestExpiry).
func Seal(sender *Private, recipient party.Identity, body party.Body, now, expires time.Time, rand io.Reader) ([]byte, party.MessageID, error) {
	var id party.MessageID
	if err := recipient.Validate(); err != nil {
		return nil, id, err
	}
	if err := party.CheckWindow(now, expires, now); err != nil {
		return nil, id, err
	}
	if _, err := io.ReadFull(rand, id[:]); err != nil {
		return nil, id, err
	}
	_, _, plain, err := buildPlaintext(sender, recipient.Fingerprint(), body, id, now, expires)
	if err != nil {
		return nil, id, err
	}
	rcpt, err := ageRecipient(recipient.X25519)
	if err != nil {
		return nil, id, err
	}
	var out bytes.Buffer
	w, err := age.Encrypt(&out, rcpt)
	if err != nil {
		return nil, id, err
	}
	if _, err := w.Write(plain); err != nil {
		return nil, id, err
	}
	if err := w.Close(); err != nil {
		return nil, id, err
	}
	if out.Len() > party.MaxEnvelopeBytes {
		return nil, id, fmt.Errorf("%w: %d bytes", ErrTooLarge, out.Len())
	}
	return out.Bytes(), id, nil
}

// verifySig is Ed25519 verification under the sender's enrolled key.
func verifySig(pub party.Ed25519Public, payload, sig []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(pub[:]), signedBytes(payload), sig)
}

// buildPlaintext encodes and signs the payload. It returns the payload bytes,
// the signature and the plaintext [payload, signature] that age encrypts.
func buildPlaintext(sender *Private, rfp party.Fingerprint, body party.Body, id party.MessageID, now, expires time.Time) (payload []byte, sig [64]byte, plain []byte, err error) {
	bodyCBOR, err := encodeBody(body)
	if err != nil {
		return
	}
	sfp := sender.Fingerprint()
	payload, err = marshal(payloadWire{Version: Version, Type: string(body.Type()), Sender: sfp[:], Recipient: rfp[:],
		ID: id[:], Created: now.Unix(), Expires: expires.Unix(), Body: bodyCBOR})
	if err != nil {
		return
	}
	if sig, err = sender.sign(signedBytes(payload)); err != nil {
		return
	}
	plain, err = marshal(plaintextWire{Payload: payload, Signature: sig[:]})
	return
}
