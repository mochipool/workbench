// Package nodeage is the age side of the node-delivery exception (ADR 0011
// decision 2): `node export` seals the three hot files to the block producer's
// recipient key with it, and the start-up helper opens them with the producer's
// identity. It accepts X25519 recipients and identities only: a passphrase, a
// plugin or a post-quantum recipient is refused, so a delivery is never
// openable by anything but the one key the operator named.
package nodeage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Sealer implements ports.HotSealer.
type Sealer struct{}

var _ ports.HotSealer = Sealer{}

// ErrRecipient is the refusal of a recipient that is not an age X25519 public key.
var ErrRecipient = errors.New("the recipient is not an age X25519 public key (age1...)")

// ParseRecipientFile reads the recipient text of a file: one X25519 public key,
// with blank lines and comment lines allowed. A file with a secret key, with
// several recipients or with none is refused.
func ParseRecipientFile(data []byte) (string, error) {
	var found string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
			continue
		case strings.HasPrefix(strings.ToUpper(line), "AGE-SECRET-KEY-"):
			return "", fmt.Errorf("%w: the file holds a secret key; give the PUBLIC key of the block producer", ErrRecipient)
		case found != "":
			return "", fmt.Errorf("%w: the file names more than one recipient; a delivery has exactly one", ErrRecipient)
		}
		found = line
	}
	if found == "" {
		return "", fmt.Errorf("%w: the file names no recipient", ErrRecipient)
	}
	return found, nil
}

// ParseRecipientFile implements ports.HotSealer.
func (Sealer) ParseRecipientFile(data []byte) (string, error) { return ParseRecipientFile(data) }

// CheckRecipient implements ports.HotSealer.
func (Sealer) CheckRecipient(recipient string) (string, error) {
	if _, err := age.ParseX25519Recipient(recipient); err != nil {
		return "", ErrRecipient
	}
	sum := sha256.Sum256([]byte(recipient))
	return hex.EncodeToString(sum[:8]), nil
}

// Seal implements ports.HotSealer.
func (Sealer) Seal(_ context.Context, recipient string, plaintext *secret.Buffer) ([]byte, error) {
	r, err := age.ParseX25519Recipient(recipient)
	if err != nil {
		return nil, ErrRecipient
	}
	var out bytes.Buffer
	err = plaintext.Use(func(b []byte) error {
		w, err := age.Encrypt(&out, r)
		if err != nil {
			return err
		}
		if _, err := w.Write(b); err != nil {
			return err
		}
		return w.Close()
	})
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// ErrIdentity is the refusal of an identity that is not an age X25519 secret key.
var ErrIdentity = errors.New("the identity is not a single age X25519 secret key (AGE-SECRET-KEY-1...)")

// ParseIdentity reads an identity from the guarded text of a credential: one
// AGE-SECRET-KEY line, with blank and comment lines allowed.
func ParseIdentity(text *secret.Buffer) (*Identity, error) {
	var id *age.X25519Identity
	err := text.Use(func(b []byte) error {
		for _, line := range bytes.Split(b, []byte("\n")) {
			line = bytes.TrimSpace(line)
			if len(line) == 0 || line[0] == '#' {
				continue
			}
			if id != nil {
				return ErrIdentity
			}
			i, err := age.ParseX25519Identity(string(line))
			if err != nil {
				return ErrIdentity
			}
			id = i
		}
		if id == nil {
			return ErrIdentity
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &Identity{x: id}, nil
}

// Identity is the secret key of a recipient.
type Identity struct{ x *age.X25519Identity }

// ErrOpen is the refusal of a ciphertext that the identity does not open: it was
// sealed to another recipient, or it was changed.
var ErrOpen = errors.New("the ciphertext does not open with this identity (sealed to another recipient, or tampered)")

// ErrTooLarge: the plaintext is larger than the limit.
var ErrTooLarge = errors.New("the decrypted file is larger than any hot file")

// Open decrypts ciphertext with the identity into guarded memory. The plaintext
// may not exceed max bytes.
func (id *Identity) Open(ciphertext []byte, max int) (*secret.Buffer, error) {
	r, err := age.Decrypt(bytes.NewReader(ciphertext), id.x)
	if err != nil {
		return nil, ErrOpen
	}
	buf := make([]byte, max+1)
	n := 0
	for n < len(buf) {
		m, err := r.Read(buf[n:])
		n += m
		if err == io.EOF {
			break
		}
		if err != nil {
			clear(buf)
			return nil, ErrOpen
		}
	}
	if n > max {
		clear(buf)
		return nil, ErrTooLarge
	}
	b := secret.Take(buf[:n])
	clear(buf)
	return b, nil
}
