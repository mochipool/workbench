package parties

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// Event is one line of the multi-party audit log: an enrollment, a
// revocation, an envelope refused, a request sent, a response accepted or
// refused, a collection closed (SPO-Xparty-OUT-001, OUT-004, INV-006).
//
// The log is a record of the store, so the sealed store's own audit chain
// covers its every change. It is for the operator and for tests: nothing
// decides from it.
type Event struct {
	At   time.Time `json:"at"`
	Kind string    `json:"kind"`
	// Peer is the fingerprint text of the other party, when it is known: for
	// a refusal before the signature verified it is not (INV-006).
	Peer       string `json:"peer,omitempty"`
	Collection string `json:"collection,omitempty"`
	Slot       int    `json:"slot,omitempty"`
	BodyHash   string `json:"bodyHash,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Detail     string `json:"detail,omitempty"`
	// Count and LastSeen are set on a coalesced refusal (AppendRefusal): how
	// many times the same sender was refused for the same reason, and when
	// last. Zero for an ordinary event.
	Count    int       `json:"count,omitempty"`
	LastSeen time.Time `json:"lastSeen,omitempty"`
}

// The record holds two logs (SPO-Xparty-INV-023). Security events are what
// the operator may need to reconstruct: enrollment, revocation, requests sent
// and received, reviews, approvals, refusals and responses from an
// authenticated sender, the collection's life. They are evicted only by other
// security events, oldest first. An unauthenticated refusal, one that failed
// before the signature step, is noise anyone who can reach us can make: it goes
// to a small ring and a counter and can never push a security event out.
const (
	MaxSecurityEvents = 8192
	MaxNoiseEvents    = 128
)

var eventsRef = ports.NamedRef{Name: "log", Kind: ports.MultisigEvents}

type eventLog struct {
	Security   []Event `json:"security"`
	Noise      []Event `json:"noise"`
	NoiseTotal uint64  `json:"noiseTotal"`
}

func readLog(r ports.NamedReader) (eventLog, error) {
	var l eventLog
	b, err := r.Get(eventsRef)
	if errors.Is(err, ports.ErrNotFound) {
		return l, nil
	}
	if err != nil {
		return l, err
	}
	if len(b) > 0 && b[0] == '[' { // the older form: one list, all security
		if err := json.Unmarshal(b, &l.Security); err != nil {
			return l, fmt.Errorf("the multi-party event log is corrupt: %w", err)
		}
		return l, nil
	}
	if err := json.Unmarshal(b, &l); err != nil {
		return l, fmt.Errorf("the multi-party event log is corrupt: %w", err)
	}
	return l, nil
}

// Events reads the security log, oldest first.
func Events(r ports.NamedReader) ([]Event, error) {
	l, err := readLog(r)
	return l.Security, err
}

// Noise reads the ring of unauthenticated refusals, oldest first, and how many
// there have been in all.
func Noise(r ports.NamedReader) (ring []Event, total uint64, err error) {
	l, err := readLog(r)
	return l.Noise, l.NoiseTotal, err
}

func writeLog(w ports.NamedWriter, l eventLog) error {
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	return w.Put(eventsRef, b)
}

// AppendEvent adds a security event inside the caller's transaction, so the
// event commits with the change it records.
func AppendEvent(w ports.NamedWriter, e Event) error {
	l, err := readLog(w)
	if err != nil {
		return err
	}
	e.At = e.At.UTC().Truncate(time.Second)
	l.Security = append(l.Security, e)
	if len(l.Security) > MaxSecurityEvents {
		l.Security = l.Security[len(l.Security)-MaxSecurityEvents:]
	}
	return writeLog(w, l)
}

// MaxRefusalEntriesPerSender bounds the security-log entries one authenticated
// sender can cause with refused envelopes (SPO-Xparty-INV-023): repeats of the
// same refusal are one entry with a counter and the time last seen, and a
// sender that is refused for more distinct reasons than this has the rest
// counted in one further entry.
const MaxRefusalEntriesPerSender = 16

// OtherRefusals is the reason of the entry that counts a sender's refusals
// beyond MaxRefusalEntriesPerSender.
const OtherRefusals = "further refusals for other reasons"

// AppendRefusal adds a refusal of an authenticated sender to the security log
// inside the caller's transaction, coalescing it: the same kind, sender and
// reason as an earlier entry raises that entry's Count and LastSeen instead of
// adding one. A hostile but enrolled party that sends refused envelopes in a
// loop cannot push the operator's own history out of the log.
func AppendRefusal(w ports.NamedWriter, e Event) error {
	l, err := readLog(w)
	if err != nil {
		return err
	}
	e.At = e.At.UTC().Truncate(time.Second)
	distinct, other := 0, -1
	for i := range l.Security {
		x := &l.Security[i]
		if x.Kind != e.Kind || x.Peer != e.Peer {
			continue
		}
		if x.Reason == OtherRefusals {
			other = i
		}
		if x.Reason == e.Reason && x.Reason != OtherRefusals {
			if x.Count == 0 {
				x.Count = 1
			}
			x.Count++
			x.LastSeen = e.At
			return writeLog(w, l)
		}
		distinct++
	}
	if distinct >= MaxRefusalEntriesPerSender {
		if other >= 0 {
			l.Security[other].Count++
			l.Security[other].LastSeen = e.At
			return writeLog(w, l)
		}
		e.Reason, e.Detail = OtherRefusals, ""
	}
	e.Count, e.LastSeen = 1, e.At
	l.Security = append(l.Security, e)
	if len(l.Security) > MaxSecurityEvents {
		l.Security = l.Security[len(l.Security)-MaxSecurityEvents:]
	}
	return writeLog(w, l)
}

// AppendNoise records an unauthenticated refusal: in the ring, oldest first
// out, and in the counter. It never touches the security events.
func AppendNoise(w ports.NamedWriter, e Event) error {
	l, err := readLog(w)
	if err != nil {
		return err
	}
	e.At = e.At.UTC().Truncate(time.Second)
	l.Noise = append(l.Noise, e)
	if len(l.Noise) > MaxNoiseEvents {
		l.Noise = l.Noise[len(l.Noise)-MaxNoiseEvents:]
	}
	l.NoiseTotal++
	return writeLog(w, l)
}
