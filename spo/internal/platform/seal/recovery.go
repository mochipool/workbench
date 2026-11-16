package seal

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"errors"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// Recovery key text format (version 1), to be printed and typed back:
//
//	raw   = 32-byte key || checksum
//	check = first 3 bytes of SHA-256("spo-workbench/recovery-key/v1" || key)
//	text  = base32 (RFC 4648, upper case, no padding) of raw, 56 characters,
//	        written in 14 groups of 4 separated by '-'
//
// Example shape: ABCD-EFGH-... (14 groups). Decoding ignores '-', spaces and
// tabs and accepts lower case. The 24-bit checksum catches a mistyped or
// transposed character with probability 1-2^-24; it is not a secret and gives
// no extra security. Non-canonical encodings (set trailing bits) are refused.
const (
	recoveryChecksumLabel = "spo-workbench/recovery-key/v1"
	recoveryChecksumLen   = 3
	recoveryRawLen        = KeySize + recoveryChecksumLen
	recoveryChars         = 56 // 35 bytes * 8 / 5, exactly
	recoveryGroup         = 4
)

// Errors for recovery key text.
var (
	ErrRecoveryFormat   = errors.New("seal: recovery key has the wrong length or characters")
	ErrRecoveryChecksum = errors.New("seal: recovery key checksum does not match; check for a typing mistake")
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func recoveryChecksum(key []byte) []byte {
	h := sha256.New()
	h.Write([]byte(recoveryChecksumLabel))
	h.Write(key)
	return h.Sum(nil)[:recoveryChecksumLen]
}

// EncodeRecoveryKey returns the printable text of a raw 32-byte recovery key,
// in guarded memory.
func EncodeRecoveryKey(key *secret.Buffer) (*secret.Buffer, error) {
	if key.Len() != KeySize {
		return nil, ErrRecoveryFormat
	}
	raw := make([]byte, 0, recoveryRawLen)
	text := make([]byte, recoveryChars)
	defer func() { wipe(raw); wipe(text) }()
	if err := key.Use(func(k []byte) error {
		raw = append(raw, k...)
		raw = append(raw, recoveryChecksum(k)...)
		return nil
	}); err != nil {
		return nil, err
	}
	b32.Encode(text, raw)
	grouped := make([]byte, 0, recoveryChars+recoveryChars/recoveryGroup)
	defer func() { wipe(grouped) }()
	for i := 0; i < len(text); i += recoveryGroup {
		if i > 0 {
			grouped = append(grouped, '-')
		}
		grouped = append(grouped, text[i:i+recoveryGroup]...)
	}
	return secret.Take(append([]byte(nil), grouped...)), nil
}

// DecodeRecoveryKey parses the text produced by EncodeRecoveryKey and returns
// the raw 32-byte key in guarded memory.
func DecodeRecoveryKey(text *secret.Buffer) (*secret.Buffer, error) {
	clean := make([]byte, 0, recoveryChars)
	raw := make([]byte, recoveryRawLen)
	again := make([]byte, recoveryChars)
	defer func() { wipe(clean); wipe(raw); wipe(again) }()
	err := text.Use(func(t []byte) error {
		for _, c := range t {
			switch {
			case c == '-' || c == ' ' || c == '\t' || c == '\n' || c == '\r':
			case c >= 'a' && c <= 'z':
				clean = append(clean, c-'a'+'A')
			default:
				clean = append(clean, c)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(clean) != recoveryChars {
		return nil, ErrRecoveryFormat
	}
	if n, err := b32.Decode(raw, clean); err != nil || n != recoveryRawLen {
		return nil, ErrRecoveryFormat
	}
	b32.Encode(again, raw)
	if subtle.ConstantTimeCompare(again, clean) != 1 {
		return nil, ErrRecoveryFormat // non-canonical trailing bits
	}
	if subtle.ConstantTimeCompare(raw[KeySize:], recoveryChecksum(raw[:KeySize])) != 1 {
		return nil, ErrRecoveryChecksum
	}
	return secret.Take(append([]byte(nil), raw[:KeySize]...)), nil
}
