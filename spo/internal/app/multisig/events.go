package multisig

import (
	"time"

	"github.com/mochipool/workbench/spo/internal/app/parties"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func eventOf(at time.Time, kind, collection string, slot int, body [32]byte) parties.Event {
	e := parties.Event{At: at, Kind: kind, Collection: collection, Slot: slot}
	if body != ([32]byte{}) {
		e.BodyHash = hexHash(body)
	}
	return e
}

func appendEvent(w ports.Writer, e parties.Event) error { return parties.AppendEvent(w, e) }

// Events reads the audit log (SPO-Xparty-OUT-004, INV-006), oldest first.
func Events(r ports.Reader) ([]parties.Event, error) { return parties.Events(r) }

// appendRefusal records a refusal of an authenticated sender, coalesced per
// sender and reason (SPO-Xparty-INV-023).
func appendRefusal(w ports.Writer, e parties.Event) error { return parties.AppendRefusal(w, e) }

func appendNoise(w ports.Writer, e parties.Event) error { return parties.AppendNoise(w, e) }

// Noise reads the ring of unauthenticated refusals and how many there have
// been (SPO-Xparty-INV-023).
func Noise(r ports.Reader) ([]parties.Event, uint64, error) { return parties.Noise(r) }
