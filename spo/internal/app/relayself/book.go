package relayself

import (
	"context"
	"sync"

	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// Book is the pending revokes as the mailbox client's relayport.RevokeBook
// (SPO-Xmailbox-OUT-098). It is loaded from the store and answers from memory, so
// its calls never block; Save writes back what it learnt: a revoke with a final
// outcome is dropped, others stay pending, and the relays that recorded each
// one are added to its record (SPO-Xmailbox-OUT-111). One Book may be shared by
// several clients (it has its own lock); the clients of several relays report
// with the relay's name (relayport.RelayRevokeBook).
type Book struct {
	s        Service
	mu       sync.Mutex
	pending  []relayport.Revoke
	final    map[string]bool
	report   map[relayport.RevokeOutcome]int
	recorded map[string][]string // revoke id -> the relays that recorded it now
	changes  int
}

var _ relayport.RelayRevokeBook = (*Book)(nil)

// Book loads the pending revokes that have not ended.
//
// spec: SPO-Xmailbox-OUT-098
func (s Service) Book(ctx context.Context) (*Book, error) {
	st, err := s.Load(ctx)
	if err != nil {
		return nil, err
	}
	now := s.Clock.Now().Unix()
	b := &Book{s: s, final: map[string]bool{}, report: map[relayport.RevokeOutcome]int{}, recorded: map[string][]string{}}
	for _, r := range st.Revokes {
		if r.Until >= now {
			b.pending = append(b.pending, r)
		}
	}
	return b, nil
}

// Pending is the revokes still owed, oldest first. A revoke recorded by every
// relay stays pending until it ends: a relay may lose its state.
func (b *Book) Pending() []relayport.Revoke {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]relayport.Revoke, 0, len(b.pending))
	for _, r := range b.pending {
		if !b.final[revokeID(r)] {
			out = append(out, r)
		}
	}
	return out
}

// Result notes the outcome of one revoke at a relay that is not named.
func (b *Book) Result(r relayport.Revoke, o relayport.RevokeOutcome) {
	b.ResultAt("", r, o)
}

// ResultAt notes the outcome of one revoke at the named relay: recorded there,
// the relay no longer owes it (SPO-Xmailbox-OUT-111).
//
// spec: SPO-Xmailbox-IF-026, SPO-Xmailbox-OUT-111
func (b *Book) ResultAt(relay string, r relayport.Revoke, o relayport.RevokeOutcome) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.report[o]++
	b.changes++
	id := revokeID(r)
	if o.Final() {
		b.final[id] = true
	}
	if o == relayport.RevokeRecorded && relayNameRE.MatchString(relay) {
		b.recorded[id] = mergeRelays(b.recorded[id], []string{relay})
	}
}

// Changes is how many outcomes were noted: a caller saves when it grew.
func (b *Book) Changes() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.changes
}

// Report is the outcomes noted so far.
func (b *Book) Report() SendReport {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := SendReport{Outcomes: map[relayport.RevokeOutcome]int{}}
	for o, n := range b.report {
		out.Outcomes[o] = n
	}
	return out
}

// Save drops from the store the revokes with a final outcome, and the ones that
// have ended, and adds the relays that recorded a revoke to its record. A
// revoke added to the store since the Book was loaded is kept.
func (b *Book) Save(ctx context.Context) error {
	b.mu.Lock()
	final := make(map[string]bool, len(b.final))
	for k, v := range b.final {
		final[k] = v
	}
	recorded := make(map[string][]string, len(b.recorded))
	for k, v := range b.recorded {
		recorded[k] = append([]string(nil), v...)
	}
	b.mu.Unlock()
	now := b.s.Clock.Now().Unix()
	return b.s.update(ctx, func(st *State) error {
		kept := st.Revokes[:0]
		at := map[string][]string{}
		for _, r := range st.Revokes {
			if final[revokeID(r)] || r.Until < now {
				continue
			}
			kept = append(kept, r)
			id := revokeID(r)
			if names := mergeRelays(st.RecordedAt[id], recorded[id]); len(names) > 0 {
				at[id] = names
			}
		}
		st.Revokes, st.RecordedAt = kept, at
		return nil
	})
}
