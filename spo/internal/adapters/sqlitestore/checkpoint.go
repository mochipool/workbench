package sqlitestore

import (
	"context"
	"fmt"
)

// CheckpointWAL folds the write-ahead log into the database file and truncates
// it (PRAGMA wal_checkpoint(TRUNCATE)), so that the versions of records that
// committed transactions replaced do not stay in the log. It waits for the
// handle's gate like any operation, and reports a checkpoint that could not
// finish (another connection holds the log) as an error. It implements
// ports.WALCheckpointer. Earlier backups of the workspace are not touched.
func (s *Store) CheckpointWAL(ctx context.Context) error {
	if err := s.writable(); err != nil {
		return err
	}
	release, err := s.enter(ctx)
	if err != nil {
		return err
	}
	defer release()
	var busy, logFrames, done int
	if err := s.db.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &done); err != nil {
		return fmt.Errorf("sqlitestore: checkpoint: %w", err)
	}
	if busy != 0 {
		return fmt.Errorf("sqlitestore: the write-ahead log could not be truncated (another connection holds it)")
	}
	return nil
}
