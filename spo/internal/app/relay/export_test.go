package relay

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
