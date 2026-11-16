// Package poll is the pure side of SPO polls (CIP-94, label 94): the
// canonical CBOR of a question, its hash and the answer metadata.
package poll

import (
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/blake2b"
)

// Label is the metadata label of CIP-94 polls.
const Label = 94

// Question is a poll question: its lines and the lines of every option.
type Question struct {
	Lines   []string
	Options [][]string
}

// ErrEmpty: a question with no lines or no options (SPO-13a-PRE-004).
var ErrEmpty = errors.New("the poll has no question text or no options")

// Check refuses a question that has no question lines or no options, and an
// option with no lines.
func (q Question) Check() error {
	if len(q.Lines) == 0 || len(q.Options) == 0 {
		return ErrEmpty
	}
	for i, o := range q.Options {
		if len(o) == 0 {
			return fmt.Errorf("%w: option %d has no text", ErrEmpty, i)
		}
	}
	return nil
}

// Text is the lines of the question joined, for display.
func (q Question) Text() string { return join(q.Lines) }

// OptionText is the lines of option i joined, for display.
func (q Question) OptionText(i int) string { return join(q.Options[i]) }

func join(ls []string) string {
	s := ""
	for _, l := range ls {
		s += l
	}
	return s
}

// head writes a definite-length CBOR header of a major type and an argument.
func head(b []byte, major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return append(b, m|byte(n))
	case n < 1<<8:
		return append(b, m|24, byte(n))
	case n < 1<<16:
		return append(b, m|25, byte(n>>8), byte(n))
	case n < 1<<32:
		return append(b, m|26, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	return append(b, m|27, byte(n>>56), byte(n>>48), byte(n>>40), byte(n>>32), byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// EncodeQuestion is the definite-length CBOR of {94: {0: [lines], 1: [[option
// lines], ...]}} (SPO-13a-INV-001): the map keys in the order 0, 1, the text
// strings as the UTF-8 bytes of the lines. Upstream interprets backslash
// escapes in the lines before encoding them (SPO-Cconv-OUT-007), so a line
// with `\n` in it encodes differently from the chain's bytes; the port encodes
// the text as it is (decision: fix).
func EncodeQuestion(q Question) []byte {
	b := head(nil, 5, 1)
	b = head(b, 0, Label)
	b = head(b, 5, 2)
	b = head(b, 0, 0)
	b = head(b, 4, uint64(len(q.Lines)))
	for _, l := range q.Lines {
		b = head(b, 3, uint64(len(l)))
		b = append(b, l...)
	}
	b = head(b, 0, 1)
	b = head(b, 4, uint64(len(q.Options)))
	for _, o := range q.Options {
		b = head(b, 4, uint64(len(o)))
		for _, l := range o {
			b = head(b, 3, uint64(len(l)))
			b = append(b, l...)
		}
	}
	return b
}

// Hash is the question hash: BLAKE2b-256 of the question CBOR
// (SPO-13a-INV-002).
func Hash(q Question) [32]byte { return blake2b.Sum256(EncodeQuestion(q)) }

// EncodeAnswer is the definite-length CBOR of {94: {2: <32-byte question
// hash>, 3: <index>}} (SPO-13a-OUT-001).
func EncodeAnswer(hash [32]byte, index uint64) []byte {
	b := head(nil, 5, 1)
	b = head(b, 0, Label)
	b = head(b, 5, 2)
	b = head(b, 0, 2)
	b = head(b, 2, 32)
	b = append(b, hash[:]...)
	b = head(b, 0, 3)
	return head(b, 0, index)
}

// FileName is the answer file `spopoll_<hash hex>.cbor` (SPO-13a-OUT-002).
func FileName(hash [32]byte) string { return "spopoll_" + hex.EncodeToString(hash[:]) + ".cbor" }
