package sqlitestore

import (
	"context"
	"errors"
	"fmt"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"os"
	"strconv"

	"github.com/mochipool/workbench/spo/internal/domain/unlock"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
)

// MIGRATION FROM FORMAT 2 TO FORMAT 3 (ADR 0011).
//
// Migrate3 converts a store of format 2 in one transaction: the key slot table
// is rebuilt with the new kinds and columns, the meta row gets the policy
// `standard`, and one audit row records the migration and the new slot-set hash
// (which covers the policy). No record is re-sealed: the record encoding stays
// format 2 (seal.RecordFormat), and the genesis nonce is the existing random
// workspace id, so every slot and record keeps valid associated data. The
// existing passphrase and recovery slots are carried over as they are (legacy
// slots: their associated data is the one they were made with, because
// rewrapping them needs their credentials, which a migration does not have). They
// open the workspace exactly as before. They bind neither the policy nor a
// recovery public key; the first rekey replaces them with slots that do. A
// backup of the sealed file is made first. The workspace is `standard` after the
// migration, which is the weakest policy: nothing about a format 2 workspace
// becomes harder to open or easier to attack.

// OpenFormat2 opens a store of format 2 with a passphrase, for Migrate3. Any
// other open of such a file is refused with ErrFormat2, before a key is derived.
func OpenFormat2(path string, passphrase *secret.Buffer) (*Store, error) {
	return open(path, credential{kind: seal.SlotPassphrase, buf: passphrase}, false, OpenOptions{legacy2: true})
}

// OpenFormat2WithRecovery is OpenFormat2 with the recovery key as printed.
func OpenFormat2WithRecovery(path string, recovery *secret.Buffer) (*Store, error) {
	raw, err := seal.DecodeRecoveryKey(recovery)
	if err != nil {
		return nil, err
	}
	defer raw.Destroy()
	return open(path, credential{kind: seal.SlotRecovery, buf: raw}, false, OpenOptions{legacy2: true})
}

// Migrate3Report says what Migrate3 did.
type Migrate3Report struct {
	Backup string
	Slots  int // slots carried over
	// ColdRecords is the number of signing keys sealed in the cold form.
	ColdRecords int
	// ColdNoWrap is how many of them carry no recovery wrap: the slots of a format
	// 2 workspace bind no recovery public key, so every one of them, until a rekey
	// (spo store passphrase change, spo store recovery-key new) adds the wraps.
	ColdNoWrap int
}

// migrate3Hook, when set, is called inside the transaction after the data is
// converted and before the audit row; a test makes it fail to show that a failed
// migration leaves the original file untouched.
var migrate3Hook func() error

// Migrate3 converts the format 2 store this handle holds. A failure anywhere
// leaves the original file as it was. The handle is a format 3 handle afterwards.
func (s *Store) Migrate3(ctx context.Context, backupPath string) (*Migrate3Report, error) {
	if !s.legacy2 {
		return nil, ErrNotLegacy
	}
	if err := s.writableMigrating(); err != nil {
		return nil, err
	}
	backup := backupPath
	if backup == "" {
		backup = s.path + ".pre-migrate-v2"
		for n := 2; ; n++ {
			if _, err := os.Lstat(backup); errors.Is(err, os.ErrNotExist) {
				break
			}
			backup = s.path + ".pre-migrate-v2." + strconv.Itoa(n)
		}
	}
	if _, err := s.BackupWithHead(ctx, backup); err != nil {
		return nil, fmt.Errorf("the backup before the migration could not be made, so nothing was changed: %w", err)
	}
	release, err := s.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if err := s.checkEpochNow(ctx); err != nil {
		return nil, err
	}
	// The sub-key passphrase of the cold keys the migration seals is asked for
	// before the exclusive lock and the write transaction: a rolled-back dry run
	// counts the cold keys, the factor is gathered with nothing held, and the real
	// run only consumes it.
	var prep *coldPrep
	need, err := s.migrate3Probe(ctx)
	if err != nil {
		return nil, err
	}
	if need > 0 {
		if prep, err = s.gatherColdCreate(ctx, need); err != nil {
			return nil, err
		}
		defer prep.destroy()
	}
	if err := upgradeLock(s.lock); err != nil {
		if errors.Is(err, ErrLockLost) {
			s.loseLock()
		}
		return nil, err
	}
	s.writing.Add(1)
	defer func() {
		s.writing.Add(-1)
		if derr := downgradeFile(s.lock); derr != nil {
			s.loseLock()
			s.notice("the file lock could not be taken back to shared after the migration: " + derr.Error())
		}
	}()
	rep := &Migrate3Report{Backup: backup}
	committed, err := s.withWriteTxMode(ctx, true, func(q dbq) (*Head, error) {
		return s.migrate3Body(ctx, q, rep, prep, nil)
	}, func(nc context.Context, q dbq) (bool, error) {
		var got int
		if err := q.QueryRowContext(nc, `SELECT format_version FROM meta WHERE id = 1`).Scan(&got); err != nil {
			return false, err
		}
		return uint64(got) == seal.StoreFormat, nil
	})
	if !committed {
		return nil, err
	}
	if rep.ColdRecords > 0 {
		// the hot versions of the keys that are cold now must not stay in the write-ahead
		// log (as after an Update that gives a key a cold role)
		var busy, logFrames, done int
		if cerr := s.db.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &done); cerr != nil || busy != 0 {
			s.notice("the write-ahead log could not be truncated after the migration: the hot versions of the cold keys may stay in the -wal file until it is checkpointed")
		}
	}
	s.legacy, s.legacy2 = false, false
	s.policy = unlock.Standard
	s.schemaV = len(migrations)
	s.known = nil
	return rep, nil
}

var errProbeDone = errors.New("sqlitestore: dry run done")

// migrate3Probe runs the migration in a transaction that is always rolled back
// and says how many cold-role records it would create.
func (s *Store) migrate3Probe(ctx context.Context) (int, error) {
	need := 0
	_, err := s.withWriteTxMode(ctx, true, func(q dbq) (*Head, error) {
		if _, err := s.migrate3Body(ctx, q, &Migrate3Report{}, nil, &need); err != nil {
			return nil, err
		}
		return nil, errProbeDone
	}, nil)
	if err != nil && !errors.Is(err, errProbeDone) {
		return 0, err
	}
	return need, nil
}

// migrate3Body does the database work of Migrate3 inside the transaction. With
// probe (a non-nil need) cold records are sealed under throwaway sub-keys and
// counted; otherwise prep carries the factor gathered before the transaction.
func (s *Store) migrate3Body(ctx context.Context, q dbq, rep *Migrate3Report, prep *coldPrep, probeNeed *int) (*Head, error) {
	// Verify first, under the format 2 rules: a migration must not launder tampering.
	_, _, known, err := s.verify(ctx, q, true)
	if err != nil {
		return nil, fmt.Errorf("sqlitestore: migration refused, nothing was changed: %w", err)
	}
	s.known = known
	before, err := loadTable(ctx, q, s.ws, seal.RecordFormat)
	if err != nil {
		return nil, err
	}
	rep.Slots = len(before.slots)
	if _, err := q.ExecContext(ctx, migrations[1]); err != nil {
		return nil, fmt.Errorf("sqlitestore: migration 2: %w", err)
	}
	if _, err := q.ExecContext(ctx, `UPDATE schema_version SET version = 2`); err != nil {
		return nil, err
	}
	if _, err := q.ExecContext(ctx, `UPDATE meta SET format_version = ?, policy = ?`, int64(seal.StoreFormat), string(unlock.Standard)); err != nil {
		return nil, err
	}
	t, err := checkTable(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("sqlitestore: the migrated slot table breaks its policy, nothing was changed: %w", err)
	}
	if len(t.slots) != rep.Slots {
		return nil, errWriteChanged("the set of key slot rows")
	}
	set, err := slotSetHash(ctx, q)
	if err != nil {
		return nil, err
	}
	// A key whose identity has a cold role in its role history is sealed in the
	// cold form from now on (decision 6): this is the one step of the migration
	// that re-seals records. Under standard it needs a new sub-key passphrase, which
	// the migration asks for through the handle's cold source; with none, a
	// workspace that holds such keys is refused and the keys are named by kind.
	cold, err := s.sealColdRecords(ctx, q, prep, probeNeed)
	if err != nil {
		return nil, err
	}
	rep.ColdRecords = cold
	if _, bound, _ := t.commonRecHash(); !bound {
		rep.ColdNoWrap = cold
	}
	prev, err := chainHead(ctx, q)
	if err != nil {
		return nil, err
	}
	if migrate3Hook != nil {
		if err := migrate3Hook(); err != nil {
			return nil, err
		}
	}
	events := [][]any{{"migrate", seal.RecordFormat, seal.StoreFormat, string(unlock.Standard)}}
	return appendAudit(ctx, q, s.ws, s.keys, auditSlots, s.now().Unix(), prev, events, nil, set)
}

// sealColdRecords re-seals, inside the migration's transaction, every signing key
// whose key identity has a cold role (it is classified from the format 2 records
// as they are). It returns how many.
func (s *Store) sealColdRecordsH(ctx context.Context, q dbq, prep *coldPrep, probeNeed *int) (int, *Head, error) {
	t := &txn{s: s, ctx: ctx, q: q, writable: true, ops: map[ports.Ref]*op{}, preset: map[ports.Ref]*nextSub{}, prep: prep, probe: probeNeed != nil}
	defer t.discard()
	var found []ports.Ref
	recorded := 0
	for _, kind := range ports.AllKinds() {
		if !labels.IsKeySecret(kind) {
			continue
		}
		refs, err := t.Records(kind)
		if err != nil {
			return 0, nil, err
		}
		for _, ref := range refs {
			cls, err := labels.ClassifyKeyRecord(t, ref)
			if errors.Is(err, labels.ErrNoRoleHistory) && cls.Identity != (identity.Ref{}) {
				// A format 2 store may hold a signing key whose identity has no role
				// history (Calidus and Catalyst voting keys were written without
				// one). The history is recorded from the verification key stored
				// beside it, in this transaction, for the role of the key's kind.
				role, ok := labels.RoleOfKind(ref.Kind)
				if !ok {
					return 0, nil, &RefError{ref, err}
				}
				recorded++
				if err = labels.RecordRole(t, cls.Identity, role); err != nil {
					return 0, nil, &RefError{ref, err}
				}
				cls, err = labels.ClassifyKeyRecord(t, ref)
			}
			if err != nil {
				return 0, nil, &RefError{ref, err}
			}
			if cls.Cold {
				found = append(found, ref)
			}
		}
	}
	if len(found) == 0 {
		if recorded > 0 {
			h, err := t.apply() // only the missing role histories
			return 0, h, err
		}
		return 0, nil, nil
	}
	if src := s.coldSource(); src == nil || (src.Passphrase == nil) {
		var kinds []string
		for _, r := range found {
			kinds = append(kinds, string(r.Kind))
		}
		return 0, nil, fmt.Errorf("%w: the workspace holds %d signing key(s) of a cold role (%v) and the migration seals them under a sub-key passphrase; give one", ErrColdFactorRequired, len(found), kinds)
	}
	for _, ref := range found {
		row, err := t.fetch(ref)
		if err != nil {
			return 0, nil, err
		}
		buf, err := s.keys.OpenSecret(t.meta(ref, row), row.sealed)
		if err != nil {
			return 0, nil, corrupt(ref, err)
		}
		t.stage(ref, &op{secret: buf})
	}
	head, err := t.apply()
	if err != nil {
		return 0, nil, err
	}
	if probeNeed != nil {
		*probeNeed = t.coldNeed
	}
	return len(found), head, nil
}

func (s *Store) sealColdRecords(ctx context.Context, q dbq, prep *coldPrep, probeNeed *int) (int, error) {
	n, _, err := s.sealColdRecordsH(ctx, q, prep, probeNeed)
	return n, err
}
