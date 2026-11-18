package sqlitestore

import (
	"context"
	"database/sql"
	"path/filepath"

	"github.com/mochipool/workbench/spo/internal/platform/seal"
)

// BackupFacts is what a backup or workspace file says about itself without any
// key: the workspace id, the end of its audit chain and the hash of its slot
// table (policy and every slot row). A checkpoint statement is made over, and
// checked against, exactly these (ADR 0012 stage 2).
type BackupFacts struct {
	WorkspaceID []byte
	Head        Head
	SlotTable   []byte
}

// InspectBackupFacts reads the facts of the file at path, read-only and without
// a key.
func InspectBackupFacts(path string) (BackupFacts, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return BackupFacts{}, err
	}
	var f BackupFacts
	err = withReadOnly(abs, func(db *sql.DB) error {
		ctx := context.Background()
		m, err := loadMeta(ctx, db)
		if err != nil {
			return err
		}
		f.WorkspaceID = m.ws
		if f.Head, err = chainHead(ctx, db); err != nil {
			return err
		}
		f.SlotTable, err = slotSetHash(ctx, db)
		return err
	})
	return f, err
}

// DailyCredentialIDs lists the FIDO2 credential ids of the slots that unlock the
// workspace day to day: every factor of every slot that is not a recovery
// composite. The checkpoint key may not be one of them (ADR 0012 decision 13).
// The credential id is all the store can compare: it cannot tell two
// credentials on one physical token apart, so the command refuses the device the
// session unlocked with as well, and the how-to says to use another token.
func (s *Store) DailyCredentialIDs(ctx context.Context) ([][]byte, error) {
	release, err := s.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	t, err := s.currentTable(ctx)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for _, ts := range t.slots {
		if !ts.isFactor() || tslotHasRecovery(ts) {
			continue
		}
		for _, f := range ts.fs.Spec.Factors {
			if f.Kind == seal.FactorFIDO2 {
				out = append(out, append([]byte(nil), f.CredentialID...))
			}
		}
	}
	return out, nil
}
