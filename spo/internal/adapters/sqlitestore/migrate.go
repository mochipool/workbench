package sqlitestore

import (
	"bytes"
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
)

// MIGRATION FROM FORMAT 1 (ADR 0010 decision 4).
//
// A store of format 1 keys its records by the operator's names. Migrate converts
// the file to format 2 in one transaction: records keep their random ids; each is
// opened under its old associated data and sealed again under the same master key
// with a fresh payload nonce, its data key re-wrapped, its owner blob rewritten
// from the anchor identity and the number, and its lookup tag recomputed. The
// master key and the data keys do not change, so this is not a rekey. The label,
// owner, manifest and role-history records are added, every pool descriptor's
// owner and reward references are rewritten from names to key hashes, and the
// witness-collection slots get the fingerprint of their party. One audit row
// records the migration. The audit chain, the key slots and the key epoch are
// untouched.
//
// Before anything is written the plan is made and its identity layer is checked
// the way every open checks it; a plan that refuses lists every problem and
// writes nothing, not even a backup. A backup of the file is made next to it
// before the transaction.

// OpenLegacy opens a store of format 1 with a passphrase, for Migrate. Any other
// open of such a file is refused with ErrLegacyFormat.
func OpenLegacy(path string, passphrase *secret.Buffer) (*Store, error) {
	return open(path, credential{kind: seal.SlotPassphrase, buf: passphrase}, false, OpenOptions{legacy: true})
}

// OpenLegacyWithRecovery is OpenLegacy with the recovery key.
func OpenLegacyWithRecovery(path string, recovery *secret.Buffer) (*Store, error) {
	raw, err := seal.DecodeRecoveryKey(recovery)
	if err != nil {
		return nil, err
	}
	defer raw.Destroy()
	return open(path, credential{kind: seal.SlotRecovery, buf: raw}, false, OpenOptions{legacy: true})
}

// MigrateOptions are the operator's choices.
type MigrateOptions struct {
	// Quarantine names the pools that proceed although their descriptor does not
	// resolve to keys or their records collide: they are left unusable.
	Quarantine []string
	// BackupPath is where the copy of the old file goes; empty is
	// "<file>.pre-migrate-v1" (a number is added when that exists).
	BackupPath string
}

// MigrateReport says what a migration did.
type MigrateReport struct {
	Backup      string
	Backup3     string // the backup made before the conversion to format 3
	Records     int    // records converted
	Merged      int    // records merged into another with identical bytes
	Added       int    // label, owner, manifest and role-history records written
	Owners      int    // owners that got an anchor
	Rewritten   []string
	Quarantined []string
	Unassigned  []string
	// ColdNoWrap is the number of cold-role records the migration sealed with no
	// recovery wrap (the migrated slots bind no recovery key).
	ColdNoWrap int
}

type legacyRec struct {
	id      []byte
	tag     []byte
	kind    string
	version uint64
	name    string
	num     int
	sealed  seal.SealedRecord
	upd     int64
	data    []byte
	secret  *secret.Buffer
}

func parseLegacyOwner(o string) (name string, num int, err error) {
	i := strings.LastIndexByte(o, '#')
	if i < 0 {
		return "", 0, fmt.Errorf("%w: malformed owner", ErrCorrupt)
	}
	if num, err = strconv.Atoi(o[i+1:]); err != nil {
		return "", 0, fmt.Errorf("%w: malformed owner", ErrCorrupt)
	}
	return o[:i], num, nil
}

// readLegacy opens every record of a format 1 store.
func (s *Store) readLegacy(ctx context.Context, q dbq) ([]*legacyRec, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, lookup_tag, kind, version, nonce, wrapped_key, owner_sealed, ciphertext, updated_at FROM records ORDER BY id`)
	if err != nil {
		return nil, err
	}
	var out []*legacyRec
	for rows.Next() {
		r := &legacyRec{}
		var v int64
		if err := rows.Scan(&r.id, &r.tag, &r.kind, &v, &r.sealed.Nonce, &r.sealed.WrappedKey, &r.sealed.Owner, &r.sealed.Ciphertext, &r.upd); err != nil {
			rows.Close()
			return nil, err
		}
		r.version = uint64(v)
		out = append(out, r)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	fail := func(err error) ([]*legacyRec, error) {
		for _, r := range out {
			r.secret.Destroy()
		}
		return nil, err
	}
	for _, r := range out {
		owner, err := s.keys.OpenOwner(s.ws, r.id, r.kind, r.sealed)
		if err != nil {
			return fail(fmt.Errorf("%w: a record's owner blob does not open (%v)", ErrCorrupt, err))
		}
		if r.name, r.num, err = parseLegacyOwner(owner); err != nil {
			return fail(err)
		}
		want, err := s.keys.Index.Tag("record-ref", []byte(r.name), []byte(r.kind), []byte(strconv.Itoa(r.num)))
		if err != nil {
			return fail(err)
		}
		if !bytes.Equal(want, r.tag) {
			return fail(&RefError{ports.Ref{Kind: ports.Kind(r.kind)}, fmt.Errorf("%w: lookup tag does not match the owner", ErrCorrupt)})
		}
		meta := r.legacyMeta(s.ws, owner)
		if ports.Kind(r.kind).Secret() {
			r.secret, err = s.keys.OpenSecret(meta, r.sealed)
		} else {
			r.data, err = s.keys.OpenRecord(meta, r.sealed)
		}
		if err != nil {
			return fail(corrupt(ports.Ref{Kind: ports.Kind(r.kind)}, err))
		}
	}
	return out, nil
}

func (r *legacyRec) class() string {
	if ports.Kind(r.kind).Secret() {
		return seal.ClassSecret
	}
	return seal.ClassSensitive
}

func (r *legacyRec) legacyMeta(ws []byte, owner string) seal.RecordMeta {
	return seal.RecordMeta{WorkspaceID: ws, RecordID: r.id, Kind: r.kind, Owner: owner, Class: r.class(), Version: r.version, Format: seal.LegacyRecordFormat}
}

func (r *legacyRec) sameBytes(o *legacyRec) bool {
	switch {
	case r.secret != nil && o.secret != nil:
		same := false
		_ = r.secret.Use(func(a []byte) error {
			return o.secret.Use(func(b []byte) error {
				same = len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
				return nil
			})
		})
		return same
	case r.secret == nil && o.secret == nil:
		return bytes.Equal(r.data, o.data)
	}
	return false
}

// partyResolver reads the party registry of the store being migrated: its record
// holds each party's name and fingerprint.
func partyResolver(recs []*legacyRec) func(string) (party.Fingerprint, bool) {
	by := map[string]party.Fingerprint{}
	for _, r := range recs {
		if r.kind != string(ports.PartyRecords) || r.data == nil {
			continue
		}
		var js []struct {
			Name        string `json:"name"`
			Fingerprint string `json:"fingerprint"`
		}
		if json.Unmarshal(r.data, &js) != nil {
			continue
		}
		for _, p := range js {
			b, err := hex.DecodeString(p.Fingerprint)
			var fp party.Fingerprint
			if err == nil && len(b) == len(fp) {
				copy(fp[:], b)
				by[p.Name] = fp
			}
		}
	}
	return func(n string) (party.Fingerprint, bool) { fp, ok := by[n]; return fp, ok }
}

func planOf(recs []*legacyRec, o MigrateOptions) (*labels.MigrationPlan, error) {
	lr := make([]labels.LegacyRecord, len(recs))
	for i, r := range recs {
		lr[i] = labels.LegacyRecord{Name: r.name, Kind: ports.Kind(r.kind), Num: r.num, Data: r.data}
	}
	q := map[string]bool{}
	for _, p := range o.Quarantine {
		q[p] = true
	}
	return labels.PlanMigration(lr, labels.MigrationOptions{
		Quarantine: q,
		Party:      partyResolver(recs),
		Same:       func(a, b int) bool { return recs[a].sameBytes(recs[b]) },
	})
}

// memReader is the planned store, for the integrity check made before anything
// is written: the identity-layer records and the non-secret payloads under their
// new references.
type memReader map[ports.Ref][]byte

func (m memReader) Get(r ports.Ref) ([]byte, error) {
	b, ok := m[r]
	if !ok {
		return nil, ports.ErrNotFound
	}
	return b, nil
}
func (m memReader) Exists(r ports.Ref) (bool, error) { _, ok := m[r]; return ok, nil }
func (m memReader) Records(k ports.Kind) ([]ports.Ref, error) {
	var out []ports.Ref
	for r := range m {
		if r.Kind == k {
			out = append(out, r)
		}
	}
	return out, nil
}

func (p memReader) fill(recs []*legacyRec, plan *labels.MigrationPlan) {
	for _, r := range plan.Records {
		p[r.Ref] = r.Data
	}
	for i, r := range recs {
		if plan.Drop[i] || r.data == nil {
			continue
		}
		if nb, ok := plan.Rewrite[i]; ok {
			p[plan.Target[i]] = nb
		} else {
			p[plan.Target[i]] = r.data
		}
	}
}

func destroyAll(recs []*legacyRec) {
	for _, r := range recs {
		r.secret.Destroy()
	}
}

// migrateHook, when set, is called after each record is converted; a test makes
// it fail to show that a failed migration leaves the original file untouched.
var migrateHook func(converted int) error

// migrateTo2 converts a store of format 1 (opened with OpenLegacy) to format 2. A
// plan that refuses returns *labels.Refusal and changes nothing; a failure
// anywhere in the transaction leaves the original file as it was. The handle is a
// format 2 handle afterwards.
func (s *Store) migrateTo2(ctx context.Context, o MigrateOptions) (*MigrateReport, error) {
	if !s.legacy || s.legacy2 {
		return nil, ErrNotLegacy
	}
	if err := s.writableMigrating(); err != nil {
		return nil, err
	}
	// 1. Plan, read-only: a refusal costs nothing.
	_, err := s.planMigration(ctx, o)
	if err != nil {
		return nil, err
	}
	// 2. The backup, next to the file: sealed bytes, the same permissions.
	backup := o.BackupPath
	if backup == "" {
		backup = s.path + ".pre-migrate-v1"
		for n := 2; ; n++ {
			if _, err := os.Lstat(backup); errors.Is(err, os.ErrNotExist) {
				break
			}
			backup = s.path + ".pre-migrate-v1." + strconv.Itoa(n)
		}
	}
	if _, err := s.BackupWithHead(ctx, backup); err != nil {
		return nil, fmt.Errorf("the backup before the migration could not be made, so nothing was changed: %w", err)
	}
	// 3. The transaction.
	release, err := s.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if err := s.checkEpochNow(ctx); err != nil {
		return nil, err
	}
	if err := upgradeLock(s.lock); err != nil {
		if errors.Is(err, ErrLockLost) {
			s.loseLock()
		}
		return nil, err
	}
	defer func() {
		if derr := downgradeFile(s.lock); derr != nil {
			s.loseLock()
			s.notice("the file lock could not be taken back to shared after the migration: " + derr.Error())
		}
	}()
	var rep *MigrateReport
	committed, err := s.withWriteTxMode(ctx, true, func(q dbq) (*Head, error) {
		var head *Head
		var err error
		rep, head, err = s.migrateBody(ctx, q, o)
		return head, err
	}, func(nc context.Context, q dbq) (bool, error) {
		var got int
		if err := q.QueryRowContext(nc, `SELECT format_version FROM meta WHERE id = 1`).Scan(&got); err != nil {
			return false, err
		}
		return uint64(got) == seal.RecordFormat, nil
	})
	if !committed {
		return nil, err
	}
	rep.Backup = backup
	s.legacy2 = true // a format 2 handle now: only Migrate3 goes on from here
	s.known = nil    // rebuilt at the next use
	return rep, nil
}

// Migrate converts a store of format 1 (opened with OpenLegacy) to format 3: the
// identity-keyed format 2 first, then, in a second transaction with a backup of
// its own, the slot table and policy of format 3 (Migrate3). A failure in the
// second leaves the file in format 2, converted; running the migration again
// finishes it. The handle is a format 3 handle afterwards.
func (s *Store) Migrate(ctx context.Context, o MigrateOptions) (*MigrateReport, error) {
	rep, err := s.migrateTo2(ctx, o)
	if err != nil {
		return nil, err
	}
	rep3, err := s.Migrate3(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("the conversion to format 2 is done (backup %s) but the conversion to format 3 failed; run the migration again: %w", rep.Backup, err)
	}
	rep.Backup3 = rep3.Backup
	rep.ColdNoWrap = rep3.ColdNoWrap
	return rep, nil
}

func (s *Store) planMigration(ctx context.Context, o MigrateOptions) (*labels.MigrationPlan, error) {
	release, err := s.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if err := s.checkEpochNow(ctx); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	recs, err := s.readLegacy(ctx, tx)
	if err != nil {
		return nil, err
	}
	defer destroyAll(recs)
	plan, err := planOf(recs, o)
	if err != nil {
		return nil, err
	}
	if len(plan.Problems) > 0 {
		return nil, &labels.Refusal{Problems: plan.Problems}
	}
	if err := checkPlan(recs, plan); err != nil {
		return nil, err
	}
	return plan, nil
}

// checkPlan runs the integrity check of every open over the planned store.
func checkPlan(recs []*legacyRec, plan *labels.MigrationPlan) error {
	m := memReader{}
	m.fill(recs, plan)
	if err := labels.Check(m); err != nil {
		return fmt.Errorf("the migration would produce an inconsistent workspace, so nothing was changed: %w", err)
	}
	return nil
}

// migrateBody does the database work of Migrate inside the transaction.
func (s *Store) migrateBody(ctx context.Context, q dbq, o MigrateOptions) (*MigrateReport, *Head, error) {
	// Verify first: a migration must not launder a rolled-back record.
	if _, _, _, err := s.verify(ctx, q, true); err != nil {
		return nil, nil, fmt.Errorf("sqlitestore: migration refused, nothing was changed: %w", err)
	}
	recs, err := s.readLegacy(ctx, q)
	if err != nil {
		return nil, nil, err
	}
	defer destroyAll(recs)
	plan, err := planOf(recs, o)
	if err != nil {
		return nil, nil, err
	}
	if len(plan.Problems) > 0 {
		return nil, nil, &labels.Refusal{Problems: plan.Problems}
	}
	if err := checkPlan(recs, plan); err != nil {
		return nil, nil, err
	}
	now := s.now().Unix()
	var entries []touched
	var wrote []*stored
	var deleted [][]byte
	rep := &MigrateReport{Owners: plan.Owners, Rewritten: plan.Rewritten, Quarantined: plan.Quarantined, Unassigned: plan.Unassigned}
	for i, r := range recs {
		if plan.Drop[i] {
			res, err := q.ExecContext(ctx, `DELETE FROM records WHERE id = ? AND version = ?`, r.id, int64(r.version))
			if err != nil {
				return nil, nil, mapErr(err)
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return nil, nil, ports.ErrConflict
			}
			entries = append(entries, touched{ID: r.id, Version: r.version, Hash: []byte{}})
			deleted = append(deleted, r.id)
			rep.Merged++
			continue
		}
		ref := plan.Target[i]
		owner := r.name + "#" + strconv.Itoa(r.num)
		old := r.legacyMeta(s.ws, owner)
		// Every record is a new version: the audit chain wants each change of a
		// record to be the next one.
		version := r.version + 1
		var sealed seal.SealedRecord
		if nb, ok := plan.Rewrite[i]; ok {
			// the content changes too (a descriptor): sealed afresh under the new keys
			sealed, err = s.keys.SealRecord(metaOf(s.ws, r.id, ref, r.class(), version), nb)
		} else {
			sealed, err = s.keys.Reseal(old, metaOf(s.ws, r.id, ref, r.class(), version), r.sealed)
		}
		if err != nil {
			return nil, nil, &RefError{ports.Ref{Kind: ref.Kind}, err}
		}
		tag, err := tagFor(s.keys, ref.Anchor, r.kind, ref.Num)
		if err != nil {
			return nil, nil, err
		}
		res, err := q.ExecContext(ctx, `UPDATE records SET lookup_tag=?, version=?, nonce=?, wrapped_key=?, owner_sealed=?, ciphertext=?, updated_at=? WHERE id=? AND version=?`,
			tag, int64(version), sealed.Nonce, sealed.WrappedKey, sealed.Owner, sealed.Ciphertext, now, r.id, int64(r.version))
		if err != nil {
			return nil, nil, mapErr(err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return nil, nil, ports.ErrConflict
		}
		h, err := recordHash(r.kind, tag, sealed)
		if err != nil {
			return nil, nil, err
		}
		entries = append(entries, touched{ID: r.id, Version: version, Hash: h})
		wrote = append(wrote, &stored{id: r.id, tag: tag, kind: r.kind, version: int64(version), sealed: sealed, updatedAt: now})
		rep.Records++
		if migrateHook != nil {
			if err := migrateHook(rep.Records); err != nil {
				return nil, nil, err
			}
		}
	}
	for _, pr := range plan.Records {
		id, err := seal.NewID()
		if err != nil {
			return nil, nil, err
		}
		meta := metaOf(s.ws, id, pr.Ref, seal.ClassSensitive, 1)
		sealed, err := s.keys.SealRecord(meta, pr.Data)
		if err != nil {
			return nil, nil, &RefError{ports.Ref{Kind: pr.Ref.Kind}, err}
		}
		tag, err := tagFor(s.keys, pr.Ref.Anchor, string(pr.Ref.Kind), pr.Ref.Num)
		if err != nil {
			return nil, nil, err
		}
		if _, err := q.ExecContext(ctx, `INSERT INTO records (id, lookup_tag, kind, version, nonce, wrapped_key, owner_sealed, ciphertext, updated_at) VALUES (?,?,?,?,?,?,?,?,?)`,
			id, tag, string(pr.Ref.Kind), int64(1), sealed.Nonce, sealed.WrappedKey, sealed.Owner, sealed.Ciphertext, now); err != nil {
			return nil, nil, mapErr(err)
		}
		h, err := recordHash(string(pr.Ref.Kind), tag, sealed)
		if err != nil {
			return nil, nil, err
		}
		entries = append(entries, touched{ID: id, Version: 1, Hash: h})
		wrote = append(wrote, &stored{id: id, tag: tag, kind: string(pr.Ref.Kind), version: 1, sealed: sealed, updatedAt: now})
		rep.Added++
	}
	if _, err := q.ExecContext(ctx, `UPDATE meta SET format_version = ?`, int64(seal.RecordFormat)); err != nil {
		return nil, nil, err
	}
	prev, err := chainHead(ctx, q)
	if err != nil {
		return nil, nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return bytes.Compare(entries[i].ID, entries[j].ID) < 0 })
	events := [][]any{{"migrate", uint64(seal.LegacyRecordFormat), uint64(seal.RecordFormat), uint64(rep.Records), uint64(rep.Added), uint64(rep.Merged)}}
	head, err := appendAudit(ctx, q, s.ws, s.keys, auditUpdate, now, prev, events, entries, nil)
	if err != nil {
		return nil, nil, err
	}
	if err := verifyWrites(ctx, q, wrote, deleted); err != nil {
		return nil, nil, err
	}
	return rep, head, nil
}
