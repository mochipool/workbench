package objlease

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// The lease object's encoding (SPO-Xobjstore-IF-101). It is a fixed sequence of
// eight lines, each "name value\n", in this order and no other:
//
//	spo-lease 1
//	node <64 lower-case hex: the relay's node public key>
//	holder <32 lower-case hex: the random id of the holding process>
//	generation <decimal, at least 1: raised at each take>
//	counter <decimal, at least 1: raised at every write, renewals included>
//	duration-ms <decimal: the holder's lease duration in milliseconds>
//	margin-ms <decimal: the holder's margin in milliseconds>
//	state held|released
//
// The first line is the version. Decimals have no sign and no leading zero. A
// line that is missing, repeated, out of order, unknown or followed by anything
// is refused, as is a body longer than MaxRecordBytes, which is checked before
// anything is read for it.
const (
	// MaxRecordBytes bounds the lease object. The largest well-formed record is
	// 12+70+40+32+29+19+17+15 = 234 bytes.
	MaxRecordBytes = 256
	// RecordVersion is the version this package writes and reads.
	RecordVersion = 1
	// MinDuration and MaxDuration bound a record's duration, and so how long a
	// waiter honours a record's duration that exceeds its own: at most ten
	// times the default of 30 s. A record above it is unreadable.
	MinDuration = time.Second
	MaxDuration = 5 * time.Minute
)

// The two states of a record.
const (
	StateHeld     = "held"
	StateReleased = "released"
)

// ErrUnreadable matches a lease object that is not a record this package can
// read: too large, malformed, or of another version. Acquire refuses to start
// on one (SPO-Xobjstore-PRE-102): it cannot tell who holds it or for how long.
var ErrUnreadable = errors.New("the lease object is not a lease record this relay can read")

// Record is the decoded lease object.
type Record struct {
	Node       string // 64 lower-case hex
	Holder     string // 32 lower-case hex
	Generation uint64
	Counter    uint64
	Duration   time.Duration // whole milliseconds, MinDuration..MaxDuration
	Margin     time.Duration // whole milliseconds, from a third of Duration to below it
	State      string        // StateHeld or StateReleased
}

var fieldNames = [...]string{"spo-lease", "node", "holder", "generation", "counter", "duration-ms", "margin-ms", "state"}

// Encode returns the record's bytes. It refuses a record Decode would refuse,
// so a holder never writes what a waiter cannot read.
func Encode(r Record) ([]byte, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	vals := [...]string{
		strconv.Itoa(RecordVersion), r.Node, r.Holder,
		strconv.FormatUint(r.Generation, 10), strconv.FormatUint(r.Counter, 10),
		strconv.FormatInt(r.Duration.Milliseconds(), 10), strconv.FormatInt(r.Margin.Milliseconds(), 10),
		r.State,
	}
	for i, n := range fieldNames {
		b.WriteString(n)
		b.WriteByte(' ')
		b.WriteString(vals[i])
		b.WriteByte('\n')
	}
	return b.Bytes(), nil
}

// Decode reads a record strictly. Every refusal matches ErrUnreadable.
func Decode(b []byte) (Record, error) {
	if len(b) > MaxRecordBytes {
		return Record{}, fmt.Errorf("%w: %d bytes, more than %d", ErrUnreadable, len(b), MaxRecordBytes)
	}
	var vals [len(fieldNames)]string
	rest := b
	for i, n := range fieldNames {
		nl := bytes.IndexByte(rest, '\n')
		if nl < 0 {
			return Record{}, fmt.Errorf("%w: line %d (%s) is missing or does not end in a newline", ErrUnreadable, i+1, n)
		}
		line := rest[:nl]
		rest = rest[nl+1:]
		name, val, ok := bytes.Cut(line, []byte{' '})
		if !ok || string(name) != n {
			return Record{}, fmt.Errorf("%w: line %d is not %q", ErrUnreadable, i+1, n)
		}
		// each value is then compared exactly (the version, the state), checked
		// as lower-case hex (node, holder) or as a decimal: nothing else passes
		vals[i] = string(val)
	}
	if len(rest) != 0 {
		return Record{}, fmt.Errorf("%w: bytes after the last line", ErrUnreadable)
	}
	if vals[0] != strconv.Itoa(RecordVersion) {
		return Record{}, fmt.Errorf("%w: version %q, this relay reads version %d", ErrUnreadable, vals[0], RecordVersion)
	}
	var r Record
	var err error
	r.Node, r.Holder, r.State = vals[1], vals[2], vals[7]
	if r.Generation, err = decimal(vals[3]); err != nil {
		return Record{}, fmt.Errorf("%w: generation: %v", ErrUnreadable, err)
	}
	if r.Counter, err = decimal(vals[4]); err != nil {
		return Record{}, fmt.Errorf("%w: counter: %v", ErrUnreadable, err)
	}
	d, err := decimal(vals[5])
	if err != nil || d > uint64(MaxDuration.Milliseconds()) {
		return Record{}, fmt.Errorf("%w: duration-ms %q", ErrUnreadable, vals[5])
	}
	m, err := decimal(vals[6])
	if err != nil || m > uint64(MaxDuration.Milliseconds()) {
		return Record{}, fmt.Errorf("%w: margin-ms %q", ErrUnreadable, vals[6])
	}
	r.Duration, r.Margin = time.Duration(d)*time.Millisecond, time.Duration(m)*time.Millisecond
	if err := r.check(); err != nil {
		return Record{}, err
	}
	return r, nil
}

func (r Record) check() error {
	switch {
	case !lowerHex(r.Node, 64):
		return fmt.Errorf("%w: the node key is not 64 lower-case hex", ErrUnreadable)
	case !lowerHex(r.Holder, 32):
		return fmt.Errorf("%w: the holder id is not 32 lower-case hex", ErrUnreadable)
	case r.Generation == 0 || r.Counter == 0:
		return fmt.Errorf("%w: the generation and the counter start at 1", ErrUnreadable)
	case r.Duration < MinDuration || r.Duration > MaxDuration || r.Duration%time.Millisecond != 0:
		return fmt.Errorf("%w: the duration %v is not whole milliseconds from %v to %v", ErrUnreadable, r.Duration, MinDuration, MaxDuration)
	case r.Margin < 0 || r.Margin >= r.Duration || r.Margin%time.Millisecond != 0 || 3*r.Margin < r.Duration:
		// a margin under a third of the duration would let a waiter take the
		// lease while its holder still holds it at a clock-rate ratio under 2
		// (SPO-Xobjstore-INV-102): the record is not one this relay can read
		return fmt.Errorf("%w: the margin %v is not whole milliseconds, at least a third of the duration %v and below it", ErrUnreadable, r.Margin, r.Duration)
	case r.State != StateHeld && r.State != StateReleased:
		return fmt.Errorf("%w: the state %q is neither %q nor %q", ErrUnreadable, r.State, StateHeld, StateReleased)
	}
	return nil
}

// decimal parses an unsigned decimal without a sign or a leading zero.
func decimal(s string) (uint64, error) {
	if s == "" || len(s) > 20 || (len(s) > 1 && s[0] == '0') {
		return 0, errors.New("not a decimal without a leading zero")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, errors.New("not a decimal")
		}
	}
	return strconv.ParseUint(s, 10, 64)
}

func lowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !(s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'f') {
			return false
		}
	}
	return true
}
