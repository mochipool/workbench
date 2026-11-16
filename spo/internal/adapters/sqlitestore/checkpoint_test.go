package sqlitestore

import (
	"os"
	"testing"

	"github.com/mochipool/workbench/spo/internal/ports"
)

var _ ports.WALCheckpointer = (*Store)(nil)

// CheckpointWAL empties the write-ahead log after commits, keeps every record,
// and leaves the store usable.
//
// spec: SPO-Xparty-IF-008
func TestCheckpointWALTruncatesTheLog(t *testing.T) {
	s, path := newStore(t)
	for i := 0; i < 5; i++ {
		put(t, s, counter, "value that is replaced again and again")
	}
	if st, err := os.Stat(path + "-wal"); err != nil || st.Size() == 0 {
		t.Skipf("no write-ahead log to fold: %v", err)
	}
	if err := s.CheckpointWAL(ctx); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(path + "-wal"); err == nil && st.Size() != 0 {
		t.Fatalf("the log still holds %d bytes", st.Size())
	}
	if b, err := get(s, counter); err != nil || string(b) != "value that is replaced again and again" {
		t.Fatalf("the record after the checkpoint: %q, %v", b, err)
	}
	put(t, s, counter, "later")
}
