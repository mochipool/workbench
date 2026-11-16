// Package secret holds key material in locked, guarded memory.
//
// Secret bytes never become a Go string and are never copied into ordinary
// heap memory by this package. Callers get access through Buffer.Use, which
// lends the bytes for the duration of a function.
package secret

import (
	"errors"
	"io"

	"github.com/awnumar/memguard"
)

// Buffer is a secret value in guarded memory. The zero value is unusable;
// build one with New, Take or Read.
type Buffer struct {
	b *memguard.LockedBuffer
}

// ErrDestroyed is returned when a destroyed buffer is used.
var ErrDestroyed = errors.New("secret: buffer destroyed")

// New returns a buffer of n random bytes.
func New(n int) *Buffer {
	return &Buffer{b: memguard.NewBufferRandom(n)}
}

// Take moves src into guarded memory and wipes src.
func Take(src []byte) *Buffer {
	return &Buffer{b: memguard.NewBufferFromBytes(src)}
}

// Read fills a new buffer from r until EOF. It reads in guarded memory.
func Read(r io.Reader) (*Buffer, error) {
	b, err := memguard.NewBufferFromEntireReader(r)
	if err != nil && b.Size() == 0 {
		return nil, err
	}
	return &Buffer{b: b}, err
}

// Use lends the secret bytes to fn. The slice is valid only until fn returns
// and must not be retained or copied into ordinary memory.
func (s *Buffer) Use(fn func(b []byte) error) error {
	if s == nil || s.b == nil || !s.b.IsAlive() {
		return ErrDestroyed
	}
	return fn(s.b.Bytes())
}

// Len returns the size in bytes, or 0 when destroyed.
func (s *Buffer) Len() int {
	if s == nil || s.b == nil {
		return 0
	}
	return s.b.Size()
}

// WriteTo writes the secret to w. It exists so a secret can be sent down a
// pipe to a child process without an intermediate copy.
func (s *Buffer) WriteTo(w io.Writer) (int64, error) {
	var n int
	err := s.Use(func(b []byte) error {
		var werr error
		n, werr = w.Write(b)
		return werr
	})
	return int64(n), err
}

// Destroy wipes and releases the memory. It is safe to call twice.
func (s *Buffer) Destroy() {
	if s != nil && s.b != nil {
		s.b.Destroy()
	}
}

// String never reveals the content, so a Buffer is safe in a format verb.
func (s *Buffer) String() string { return "[secret]" }

// GoString never reveals the content.
func (s *Buffer) GoString() string { return "[secret]" }

// MarshalText refuses, so a Buffer cannot be serialised by accident.
func (s *Buffer) MarshalText() ([]byte, error) {
	return nil, errors.New("secret: refusing to serialise")
}

// Purge wipes every live buffer. Call it before the process exits.
func Purge() { memguard.Purge() }
