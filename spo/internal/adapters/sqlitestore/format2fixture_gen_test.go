//go:build format2fixture

package sqlitestore

// This generator builds testdata/legacy-v2/*.db: stores of format 2 (identity
// keyed records, key slots of the two original kinds, schema version 1). It runs
// the format 1 -> 2 conversion (migrateTo2, unchanged by ADR 0011) over the
// committed format 1 fixtures and stops there. It was run after the format 3
// code was written, not before it: the format 2 writer (Init) had already been
// replaced, so these files come from the conversion code and not from a
// freshly made format 2 workspace. They hold no real secret; the passphrase is
// "legacy fixture passphrase".
//
//	go test -tags format2fixture -run TestGenerateFormat2Fixtures ./internal/adapters/sqlitestore/

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateFormat2Fixtures(t *testing.T) {
	out := filepath.Join("testdata", "legacy-v2")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"store.db"} {
		p := legacyCopy(t, name)
		s, err := OpenLegacy(p, legacyPW())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.migrateTo2(ctx, MigrateOptions{}); err != nil {
			t.Fatal(err)
		}
		s.Close()
		// fold the WAL into the file and drop the sidecars
		db := rawDB(t, p)
		db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
		db.Close()
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
