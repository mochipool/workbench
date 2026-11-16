package native

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// CIP-83 `basic` message encryption, byte-compatible with
//
//	openssl enc -e -aes-256-cbc -pbkdf2 -iter 10000 -a -k <passphrase>
//
// The output is `Salted__` + an 8-byte salt + the ciphertext; the key and the
// IV are the 48 bytes of PBKDF2-HMAC-SHA256 over the passphrase and the salt
// (10 000 iterations, 32 bytes of key then 16 of IV); the plaintext is PKCS#7
// padded; the base64 is wrapped at 64 characters, and each line becomes one
// message line (SPO-Pparam-EXT-001). There is no library for it: the code is
// the standard library's AES, CBC and PBKDF2, and its parity with `openssl`
// is a test in spo/test/parity.

const (
	cip83Iterations = 10000
	cip83Magic      = "Salted__"
	// DefaultMessagePassphrase is upstream's default passphrase
	// (SPO-Pparam-IF-012).
	DefaultMessagePassphrase = "cardano"
)

// ErrDecrypt: a message that cannot be decrypted with the passphrase.
var ErrDecrypt = errors.New("the message cannot be decrypted")

// CIP83 implements ports.MessageEncrypter. Rand is the salt source; nil means
// crypto/rand.
type CIP83 struct{ Rand io.Reader }

// jqCompact renders lines as `jq -crM` prints a JSON array of strings: no
// spaces, non-ASCII characters as they are, `"` `\` and the control
// characters escaped, and DEL as \u007f (jq escapes it; encoding/json does
// not). It is not encoding/json, which also escapes `<`, `>`, `&`, U+2028 and
// U+2029.
func jqCompact(lines []string) []byte {
	var b bytes.Buffer
	b.WriteByte('[')
	for i, l := range lines {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('"')
		for _, r := range l {
			switch {
			case r == '"':
				b.WriteString(`\"`)
			case r == '\\':
				b.WriteString(`\\`)
			case r == '\n':
				b.WriteString(`\n`)
			case r == '\t':
				b.WriteString(`\t`)
			case r == '\r':
				b.WriteString(`\r`)
			case r == '\b':
				b.WriteString(`\b`)
			case r == '\f':
				b.WriteString(`\f`)
			case r < 0x20 || r == 0x7f:
				fmt.Fprintf(&b, `\u%04x`, r)
			default:
				b.WriteRune(r)
			}
		}
		b.WriteByte('"')
	}
	b.WriteByte(']')
	return b.Bytes()
}

func cip83KeyIV(pass, salt []byte) (key, iv []byte, err error) {
	dk, err := pbkdf2.Key(sha256.New, string(pass), salt, cip83Iterations, 48)
	if err != nil {
		return nil, nil, err
	}
	return dk[:32], dk[32:], nil
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// encryptBytes is `openssl enc -aes-256-cbc -pbkdf2 -iter 10000 -a` over data
// with the given salt: the base64 text with a newline after every 64
// characters and at the end.
func encryptBytes(data, pass, salt []byte) (string, error) {
	key, iv, err := cip83KeyIV(pass, salt)
	if err != nil {
		return "", err
	}
	defer wipeBytes(key)
	blk, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	pad := aes.BlockSize - len(data)%aes.BlockSize
	plain := append(append([]byte(nil), data...), bytes.Repeat([]byte{byte(pad)}, pad)...)
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(out, plain)
	wipeBytes(plain)
	raw := append(append([]byte(cip83Magic), salt...), out...)
	enc := base64.StdEncoding.EncodeToString(raw)
	var sb strings.Builder
	for len(enc) > 64 {
		sb.WriteString(enc[:64])
		sb.WriteByte('\n')
		enc = enc[64:]
	}
	sb.WriteString(enc)
	sb.WriteByte('\n')
	return sb.String(), nil
}

// EncryptMessages implements ports.MessageEncrypter. The plaintext is the
// compact JSON of the lines followed by a newline, which is what upstream's
// here-string feeds to openssl.
//
// spec: SPO-Pparam-EXT-001, SPO-Pparam-IF-012, SPO-Pparam-SEC-001
func (c CIP83) EncryptMessages(lines []string, passphrase *ports.Secret) ([]string, error) {
	r := c.Rand
	if r == nil {
		r = rand.Reader
	}
	salt := make([]byte, 8)
	if _, err := io.ReadFull(r, salt); err != nil {
		return nil, fmt.Errorf("salt: %w", err)
	}
	plain := append(jqCompact(lines), '\n')
	var text string
	run := func(pass []byte) error {
		var err error
		text, err = encryptBytes(plain, pass, salt)
		return err
	}
	var err error
	if passphrase == nil {
		err = run([]byte(DefaultMessagePassphrase))
	} else {
		err = passphrase.Use(func(p []byte) error { return run(p) })
	}
	wipeBytes(plain)
	if err != nil {
		return nil, err
	}
	return strings.Fields(text), nil
}

// DecryptMessages reverses EncryptMessages (and `openssl enc -d`): it joins
// the base64 lines, decrypts and returns the message lines. The reader of an
// encrypted message does the same.
func DecryptMessages(lines []string, passphrase *ports.Secret) ([]string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.Join(lines, ""))
	if err != nil {
		return nil, fmt.Errorf("%w: not base64", ErrDecrypt)
	}
	if len(raw) < 16+16 || len(raw)%16 != 0 || string(raw[:8]) != cip83Magic {
		return nil, fmt.Errorf("%w: not an openssl salted message", ErrDecrypt)
	}
	var plain []byte
	run := func(pass []byte) error {
		key, iv, err := cip83KeyIV(pass, raw[8:16])
		if err != nil {
			return err
		}
		defer wipeBytes(key)
		blk, err := aes.NewCipher(key)
		if err != nil {
			return err
		}
		out := make([]byte, len(raw)-16)
		cipher.NewCBCDecrypter(blk, iv).CryptBlocks(out, raw[16:])
		n := int(out[len(out)-1])
		if n < 1 || n > aes.BlockSize || n > len(out) {
			return fmt.Errorf("%w: wrong passphrase or damaged data", ErrDecrypt)
		}
		for _, p := range out[len(out)-n:] {
			if int(p) != n {
				return fmt.Errorf("%w: wrong passphrase or damaged data", ErrDecrypt)
			}
		}
		plain = out[:len(out)-n]
		return nil
	}
	if passphrase == nil {
		err = run([]byte(DefaultMessagePassphrase))
	} else {
		err = passphrase.Use(func(p []byte) error { return run(p) })
	}
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(plain) {
		return nil, fmt.Errorf("%w: wrong passphrase", ErrDecrypt)
	}
	return parseJSONStringArray(plain)
}

// parseJSONStringArray reads a JSON array of strings (the decrypted
// plaintext, with its trailing newline).
func parseJSONStringArray(b []byte) ([]string, error) {
	var out []string
	if err := jsonUnmarshal(bytes.TrimSpace(b), &out); err != nil {
		return nil, fmt.Errorf("%w: the plaintext is not a JSON array of strings", ErrDecrypt)
	}
	return out, nil
}

var _ ports.MessageEncrypter = CIP83{}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
