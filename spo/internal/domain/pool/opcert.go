package pool

import (
	"errors"
	"fmt"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// Envelope types and descriptions cardano-cli writes.
const (
	TypeOpCert       = "NodeOperationalCertificate"
	TypeIssueCounter = "NodeOperationalCertificateIssueCounter"
)

// ErrSlotLength means the genesis slot length is not a whole number of
// seconds. Upstream computes in shell integers and fails on such a value;
// every current network has one-second slots.
var ErrSlotLength = errors.New("the genesis slot length is not a whole number of seconds")

func slotSeconds(g chain.Genesis) (uint64, error) {
	if g.SlotLength <= 0 || g.SlotLength%time.Second != 0 {
		return 0, fmt.Errorf("%w: %s", ErrSlotLength, g.SlotLength)
	}
	return uint64(g.SlotLength / time.Second), nil
}

// KesPeriod is floor(slot / (slotsPerKESPeriod * slotLength)).
//
// The multiplication by slotLength is upstream's: it is the identity for a
// one-second slot and wrong for any other length, which this function
// reproduces for parity (SPO-04d-INV-001). A slot is unsigned, so the
// "negative becomes 0" clause of the spec cannot arise here.
//
// spec: SPO-04d-INV-001
func KesPeriod(g chain.Genesis, slot uint64) (uint64, error) {
	secs, err := slotSeconds(g)
	if err != nil {
		return 0, err
	}
	if g.SlotsPerKESPeriod == 0 {
		return 0, errors.New("the genesis slotsPerKESPeriod is zero")
	}
	return slot / (g.SlotsPerKESPeriod * secs), nil
}

// KesExpiry is the content of <pool>.kes-expire.json (SPO-Pfiles-OUT-015).
type KesExpiry struct {
	LatestKESFileIndex int
	CurrentKESPeriod   uint64
	ExpireKESPeriod    uint64
	ExpireKESDate      time.Time
}

// ExpireDateLayout is the text of upstream's `date --date=@<secs>` in the C
// locale. Upstream's text follows the operator's
// locale and time zone; this port fixes the layout.
const ExpireDateLayout = "Mon Jan _2 15:04:05 MST 2006"

// NewKesExpiry computes the expiry for key number n issued at period.
//
// Decision (SPO-04d-INV-002): expireKESdate reproduces upstream's "from
// now" computation, now + slotLength * maxKESEvolutions * slotsPerKESPeriod
// seconds, although that overestimates by the time elapsed in the current
// period. The spec's port note proposes computing it from the period start;
// that is a deliberate later change, not a parity-preserving one.
//
// spec: SPO-04d-INV-002
func NewKesExpiry(g chain.Genesis, n int, period uint64, now time.Time) (KesExpiry, error) {
	secs, err := slotSeconds(g)
	if err != nil {
		return KesExpiry{}, err
	}
	span := time.Duration(secs*g.MaxKESEvolutions*g.SlotsPerKESPeriod) * time.Second
	return KesExpiry{
		LatestKESFileIndex: n,
		CurrentKESPeriod:   period,
		ExpireKESPeriod:    period + g.MaxKESEvolutions,
		ExpireKESDate:      now.Add(span),
	}, nil
}

// JSON renders the file exactly as upstream writes it: four string members,
// tab-indented, trailing newline.
//
// spec: SPO-04d-OUT-004
func (e KesExpiry) JSON() []byte {
	return []byte(fmt.Sprintf("{\n\t\"latestKESfileindex\": \"%03d\",\n\t\"currentKESperiod\": \"%d\",\n\t\"expireKESperiod\": \"%d\",\n\t\"expireKESdate\": \"%s\"\n}\n",
		e.LatestKESFileIndex, e.CurrentKESPeriod, e.ExpireKESPeriod, e.ExpireKESDate.Local().Format(ExpireDateLayout)))
}

// IssueCounter is the cold issue counter: the number the next operational
// certificate of the pool will carry, and the cold verification key it
// belongs to.
type IssueCounter struct {
	Next     uint64
	ColdVKey [32]byte
}

// ErrBadIssueCounter means a counter file is not a valid issue counter.
var ErrBadIssueCounter = errors.New("malformed operational certificate issue counter")

// Envelope renders the counter as cardano-cli writes it: cborHex is the CBOR
// array [next, bytes(cold vkey)] and the description says what the file is.
//
// spec: SPO-Pfiles-OUT-011, SPO-04d-OUT-002
func (c IssueCounter) Envelope() []byte {
	b := []byte{0x82}
	b = appendHead(b, 0, c.Next)
	b = appendHead(b, 2, 32)
	b = append(b, c.ColdVKey[:]...)
	return MarshalEnvelope(Envelope{
		Type:        TypeIssueCounter,
		Description: fmt.Sprintf("Next certificate issue number: %d", c.Next),
		CborHex:     hexOf(b),
	})
}

// ParseIssueCounter reads a counter file.
func ParseIssueCounter(file []byte) (IssueCounter, error) {
	e, err := ParseEnvelope(file)
	if err != nil || e.Type != TypeIssueCounter {
		return IssueCounter{}, ErrBadIssueCounter
	}
	raw, err := unhex(e.CborHex)
	if err != nil || len(raw) == 0 || raw[0] != 0x82 {
		return IssueCounter{}, ErrBadIssueCounter
	}
	major, next, rest, err := readHead(raw[1:])
	if err != nil || major != 0 {
		return IssueCounter{}, ErrBadIssueCounter
	}
	major, n, rest, err := readHead(rest)
	if err != nil || major != 2 || n != 32 || len(rest) != 32 {
		return IssueCounter{}, ErrBadIssueCounter
	}
	c := IssueCounter{Next: next}
	copy(c.ColdVKey[:], rest)
	return c, nil
}
