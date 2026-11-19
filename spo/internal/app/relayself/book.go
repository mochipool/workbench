package relayself

import (
	"context"
	"sync"

	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// Book is the pending revokes as the mailbox client's relayport.RevokeBook
// (SPO-Xmailbox-OUT-098). It is loaded from the store and answers from memory, so
// its calls never block; Save writes back what it learnt: a revoke with a final
// outcome is dropped, others stay pending. One Book may be shared by several
// clients (it has its own lock).
type Book struct {
	s       Service
	mu      sync.Mutex
	pending []relayport.Revoke
	final   map[string]bool
	report  map[relayport.RevokeOutcome]int
}

var _ relayport.RevokeBook = (*Book)(nil)

// Book loads the pending revokes that have not ended.
//
// spec: SPO-Xmailbox-OUT-098
func (s Service) Book(ctx context.Context) (*Book, error) {
	st, err := s.Load(ctx)
	if err != nil {
		return nil, err
	}
	now := s.Clock.Now().Unix()
	b := &Book{s: s, final: map[string]bool{}, report: map[relayport.RevokeOutcome]int{}}
	for _, r := range st.Revokes {
		if r.Until >= now {
			b.pending = append(b.pending, r)
		}
	}
	return b, nil
}

// Pending is the revokes still owed, oldest first.
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

// Result notes the outcome of one revoke.
func (b *Book) Result(r relayport.Revoke, o relayport.RevokeOutcome) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.report[o]++
	if o.Final() {
		b.final[revokeID(r)] = true
	}
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
// have ended. A revoke added to the store since the Book was loaded is kept.
func (b *Book) Save(ctx context.Context) error {
	b.mu.Lock()
	final := make(map[string]bool, len(b.final))
	for k, v := range b.final {
		final[k] = v
	}
	b.mu.Unlock()
	now := b.s.Clock.Now().Unix()
	return b.s.update(ctx, func(st *State) error {
		kept := st.Revokes[:0]
		for _, r := range st.Revokes {
			if !final[revokeID(r)] && r.Until >= now {
				kept = append(kept, r)
			}
		}
		st.Revokes = kept
		return nil
	})
}
