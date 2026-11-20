package relay

import "github.com/mochipool/workbench/spo/internal/domain/party"

// StrangerUsage is the entries and bytes the stranger book holds for a recipient,
// reservations of puts in flight included.
func (s *Server) StrangerUsage(rcpt party.Fingerprint) (entries, bytes uint64) {
	return s.strangerUsage(rcpt)
}

// Unauth is the number of live connections that have not logged in.
func (s *Server) Unauth() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unauth
}

// Test-only views of the server's bounded tables and of its long-polls, so that
// a test can synchronise on a state and check that a table is bounded. They are
// compiled into the test binary only.

// Waiters is the number of long-polls that are parked on the notifier.
func (s *Server) Waiters() int { return s.notes.count() }

// Tables is the number of keys in each rate table: connections per node key in
// the last minute, puts per party, rejects per node key.
func (s *Server) Tables() (recent, puts, rejects int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.recent), len(s.puts), len(s.rejects)
}

// RejectTableSize is the fixed size of the table of rejected node keys.
const RejectTableSize = rejectTableSize

// MaxRejectWriters is the bound on concurrent reject writers.
const MaxRejectWriters = maxRejectWriters

// Note is what a store call of the server does with its error: a test makes
// the window between a store call that reported a lost authority and the end
// of the session that made it (LoseAuthority has not run yet).
func (s *Server) Note(err error) { s.note(err) }

// StoreFieldsWatched reports whether every store capability the server holds
// is the authority wrapper (authority.go), the purge of the revoke path
// included, and whether the eviction guard reads through it too.
func StoreFieldsWatched(s *Server) bool {
	for _, f := range []any{s.w, s.rd, s.ack, s.retract, s.purge, s.usage, s.reg} {
		if _, ok := f.(*watched); !ok {
			return false
		}
	}
	s.guard.mu.Lock()
	defer s.guard.mu.Unlock()
	_, ok := s.guard.rd.(*watched)
	return ok
}
