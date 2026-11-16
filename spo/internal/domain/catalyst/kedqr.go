// Package catalyst holds the pure encoding of the Project Catalyst voting-key
// QR code: the PIN-encrypted payload the Catalyst mobile app scans to import a
// voting key (upstream 09a `qrcode`, SPO-09a-EXT-005).
//
// Source of the format, read on 2026-11-16 and implemented from it:
//
//   - https://github.com/cardano-foundation/catalyst-toolbox at commit
//     b9910d772186dddd3593dd8b315ed38e6d7f4d15 (formerly input-output-hk):
//     catalyst-toolbox/src/kedqr/payload.rs (the payload is the lower-case hex
//     of the encrypted key), catalyst-toolbox/src/bin/cli/kedqr/mod.rs (QrPin:
//     exactly four digits, each digit used as the byte 0..9, not as ASCII),
//     catalyst-toolbox/src/kedqr/img.rs (QR error correction level H),
//     catalyst-toolbox/doc/private-key-and-qr-code.md (the layout).
//   - https://github.com/input-output-hk/chain-wallet-libs at commit
//     b46e4740823719c83af688e6e7c031a792978c03: symmetric-cipher/src/lib.rs
//     (PBKDF2-HMAC-SHA512, 12983 iterations, 32-byte key, ChaCha20-Poly1305 with
//     empty associated data; the data is a multiple of 64 bytes).
//
// Layout of the encrypted bytes: version 0x01, salt (16), nonce (12),
// ciphertext (64 bytes for one extended Ed25519 secret key), tag (16): 109
// bytes, written as 218 lower-case hex characters.
//
// UNVERIFIED against the mobile app: neither the toolbox's tests nor its
// documentation publish a known-answer vector (its tests use random salts), so
// the tests of this package check the primitives and the layout against
// independently computed values and the round trip, not against an image the
// app accepted.
package catalyst

import (
	"crypto/pbkdf2"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
)

// Constants of the symmetric-cipher crate.
const (
	protocolVersion = 1
	saltSize        = 16
	nonceSize       = 12
	tagSize         = 16
	kdfIterations   = 12983
	keySize         = 32
	// SecretKeyBytes is the extended Ed25519 secret key the payload carries
	// (kL then kR, without the public key and the chain code).
	SecretKeyBytes = 64
	// PINLength is the number of digits of the PIN (QrPin: PIN_LENGTH).
	PINLength = 4
)

// Errors.
var (
	ErrBadPIN       = errors.New("the PIN must be exactly four digits")
	ErrBadKey       = errors.New("the voting key must be a 64-byte extended Ed25519 secret key")
	ErrBadPayload   = errors.New("the payload is not a Catalyst key QR payload")
	ErrWrongPIN     = errors.New("wrong PIN, or the payload was altered")
	ErrUnknownProto = errors.New("unknown payload protocol version")
)

// PIN is the four digits as the password of the cipher: the digit values 0..9,
// one byte each (spec: SPO-09a-PRE-009; the toolbox's QrPin).
type PIN [PINLength]byte

// ParsePIN reads four ASCII digits. Anything else is ErrBadPIN. The upstream
// script accepts "digits only, 0 to 9999", and the tool then needs exactly four.
func ParsePIN(digits []byte) (PIN, error) {
	var p PIN
	if len(digits) != PINLength {
		return p, ErrBadPIN
	}
	for i, c := range digits {
		if c < '0' || c > '9' {
			return PIN{}, ErrBadPIN
		}
		p[i] = c - '0'
	}
	return p, nil
}

// Wipe overwrites the PIN.
func (p *PIN) Wipe() {
	for i := range p {
		p[i] = 0
	}
}

func deriveKey(pin PIN, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha512.New, string(pin[:]), salt, kdfIterations, keySize)
}

// Encode encrypts the extended secret key with the PIN and returns the QR
// payload: the lower-case hex of version, salt, nonce, ciphertext and tag.
// random supplies the salt and the nonce (crypto/rand in production).
func Encode(secretKey []byte, pin PIN, random io.Reader) ([]byte, error) {
	if len(secretKey) != SecretKeyBytes {
		return nil, ErrBadKey
	}
	buf := make([]byte, 1+saltSize+nonceSize)
	buf[0] = protocolVersion
	if _, err := io.ReadFull(random, buf[1:]); err != nil {
		return nil, fmt.Errorf("random salt and nonce: %w", err)
	}
	key, err := deriveKey(pin, buf[1:1+saltSize])
	if err != nil {
		return nil, err
	}
	defer wipe(key)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	// Seal appends ciphertext and then the 16-byte tag, the order of the layout.
	sealed := aead.Seal(buf, buf[1+saltSize:1+saltSize+nonceSize], secretKey, nil)
	out := make([]byte, hex.EncodedLen(len(sealed)))
	hex.Encode(out, sealed)
	return out, nil
}

// Decode reverses Encode. It exists for the round-trip test and for a check
// of a payload against its PIN; the command does not expose it.
func Decode(payload []byte, pin PIN) ([]byte, error) {
	raw := make([]byte, hex.DecodedLen(len(payload)))
	n, err := hex.Decode(raw, payload)
	if err != nil {
		return nil, ErrBadPayload
	}
	raw = raw[:n]
	if len(raw) <= 1+saltSize+nonceSize+tagSize || (len(raw)-1-saltSize-nonceSize-tagSize)%64 != 0 {
		return nil, ErrBadPayload
	}
	if raw[0] != protocolVersion {
		return nil, ErrUnknownProto
	}
	salt := raw[1 : 1+saltSize]
	nonce := raw[1+saltSize : 1+saltSize+nonceSize]
	key, err := deriveKey(pin, salt)
	if err != nil {
		return nil, err
	}
	defer wipe(key)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, raw[1+saltSize+nonceSize:], nil)
	if err != nil {
		return nil, ErrWrongPIN
	}
	return plain, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
