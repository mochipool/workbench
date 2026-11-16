// Package sqlitestore implements ports.Store and ports.Vault over one SQLite
// file in which every payload is sealed (ADR 0003, ADR 0004).
//
// The database is not encrypted. Table and column names, record ids, kinds,
// classes, versions, write times, key-slot parameters and the schema version
// are readable by anyone with the file. Everything else, including the artefact
// names, is sealed with internal/platform/seal before it is written.
//
// Journal mode is WAL: it gives snapshot reads, and a stale snapshot is what
// reports a lost race (SQLITE_BUSY_SNAPSHOT, mapped to ports.ErrConflict).
// Backups use VACUUM INTO, which is safe under WAL; never copy the file
// byte for byte while it is open. A workspace that was not closed cleanly
// has -wal and -shm files beside it; they are sealed like the main file and
// are created with the same mode.
package sqlitestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"

	_ "modernc.org/sqlite" // driver name "sqlite"
)

// Errors.
var (
	// ErrWrongCredential: no slot of the requested kind opens with the given
	// passphrase or recovery key (or the file's slots were modified).
	ErrWrongCredential = errors.New("sqlitestore: wrong passphrase or recovery key")
	// ErrCorrupt: a record failed to authenticate.
	ErrCorrupt = errors.New("sqlitestore: a record failed authentication; the file is damaged or was tampered with")
	// ErrNotWorkspace: the file has no workspace schema.
	ErrNotWorkspace = errors.New("sqlitestore: not a workspace file")
	// ErrExists: the destination already holds a workspace.
	ErrExists = errors.New("sqlitestore: destination already exists")
	// ErrLastSlot: removing the slot would leave no way to unlock.
	ErrLastSlot = errors.New("sqlitestore: refusing to remove the last key slot")
)

// kdfForNewSlots is what new passphrase slots use. Tests may lower it to the
// accepted minimum (seal.MinKDF) but never below: seal refuses weaker values.
var kdfForNewSlots = seal.DefaultKDF()

const busyTimeoutMS = 5000

// Store is an unlocked workspace. It is safe for concurrent use; operations
// on one Store serialise on its single database connection.
type Store struct {
	db     *sql.DB
	path   string
	ws     []byte
	master *secret.Buffer // kept for slot management; guarded memory
	keys   *seal.Keys
	slotID []byte // slot that unlocked this store
	ro     bool
	now    func() time.Time
}

var (
	_ ports.Store = (*Store)(nil)
	_ ports.Vault = (*Store)(nil)
)

// Close wipes the keys and closes the database.
func (s *Store) Close() error {
	s.keys.Destroy()
	s.master.Destroy()
	return s.db.Close()
}

// checkFile refuses anything but a regular file that only its owner can access.
func checkFile(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("sqlitestore: %s is not a regular file", path)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("sqlitestore: %s has mode %04o; refusing a file other users can access (chmod 600)", path, st.Mode().Perm())
	}
	return nil
}

func dsn(path string, readOnly bool) string {
	q := url.Values{}
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", busyTimeoutMS))
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "secure_delete(1)")
	if readOnly {
		q.Set("mode", "ro")
		q.Add("_pragma", "query_only(1)")
	} else {
		q.Add("_pragma", "journal_mode(WAL)")
		q.Add("_pragma", "synchronous(FULL)")
		q.Set("mode", "rw")
	}
	u := url.URL{Scheme: "file", Path: path, RawQuery: q.Encode()}
	return u.String()
}

func openDB(path string, readOnly bool) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dsn(path, readOnly))
	if err != nil {
		return nil, err
	}
	// One connection: the pragmas are per connection, and one writer at a time
	// is the model anyway.
	db.SetMaxOpenConns(1)
	db.SetConnMaxLifetime(0)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// schemaVersion returns the applied version, or 0 when there is none.
func schemaVersion(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (int, error) {
	var n int
	err := q.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name='schema_version'`).Scan(&n)
	if err != nil || n == 0 {
		return 0, err
	}
	var v int
	if err := q.QueryRowContext(ctx, `SELECT version FROM schema_version`).Scan(&v); err != nil {
		return 0, err
	}
	return v, nil
}

// migrate applies pending migrations in one transaction.
func migrate(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	v, err := schemaVersion(ctx, tx)
	if err != nil {
		return err
	}
	if v > len(migrations) {
		return fmt.Errorf("sqlitestore: file has schema version %d, this binary knows %d; upgrade the binary", v, len(migrations))
	}
	if v == 0 {
		if _, err := tx.ExecContext(ctx, `CREATE TABLE schema_version (version INTEGER NOT NULL) STRICT`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_version (version) VALUES (0)`); err != nil {
			return err
		}
	}
	for i := v; i < len(migrations); i++ {
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			return fmt.Errorf("sqlitestore: migration %d: %w", i+1, err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE schema_version SET version = ?`, i+1); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type metaRow struct {
	ws     []byte
	format int
}

func loadMeta(ctx context.Context, db *sql.DB) (metaRow, error) {
	var m metaRow
	err := db.QueryRowContext(ctx, `SELECT workspace_id, format_version FROM meta WHERE id = 1`).Scan(&m.ws, &m.format)
	if err != nil {
		return m, fmt.Errorf("%w: %v", ErrNotWorkspace, err)
	}
	if m.format != seal.FormatVersion {
		return m, fmt.Errorf("sqlitestore: format version %d is not supported (this binary: %d)", m.format, seal.FormatVersion)
	}
	if len(m.ws) != seal.IDSize {
		return m, fmt.Errorf("%w: bad workspace id", ErrNotWorkspace)
	}
	return m, nil
}

func loadSlots(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) ([]seal.Slot, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, kind, kdf_memory_kib, kdf_passes, kdf_lanes, salt, nonce, wrapped_key FROM keyslots ORDER BY rowid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []seal.Slot
	for rows.Next() {
		var s seal.Slot
		var mem, passes, lanes sql.NullInt64
		if err := rows.Scan(&s.ID, &s.Kind, &mem, &passes, &lanes, &s.Salt, &s.Nonce, &s.Wrapped); err != nil {
			return nil, err
		}
		// Out-of-range values wrap around to numbers seal then refuses.
		s.KDF = seal.KDFParams{MemoryKiB: uint32(mem.Int64), Passes: uint32(passes.Int64), Lanes: uint8(lanes.Int64)}
		if mem.Int64 < 0 || mem.Int64 > 1<<32-1 || passes.Int64 < 0 || passes.Int64 > 1<<32-1 || lanes.Int64 < 0 || lanes.Int64 > 255 {
			s.KDF = seal.KDFParams{} // zero: refused as weak
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func insertSlot(ctx context.Context, tx *sql.Tx, s seal.Slot) error {
	var mem, passes, lanes any
	var salt any
	if s.Kind == seal.SlotPassphrase {
		mem, passes, lanes, salt = int64(s.KDF.MemoryKiB), int64(s.KDF.Passes), int64(s.KDF.Lanes), s.Salt
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO keyslots (id, kind, kdf_memory_kib, kdf_passes, kdf_lanes, salt, nonce, wrapped_key) VALUES (?,?,?,?,?,?,?,?)`,
		s.ID, s.Kind, mem, passes, lanes, salt, s.Nonce, s.Wrapped)
	return err
}

// Init creates a new workspace file at path (which must not exist) with one
// passphrase slot and one recovery slot. It returns the recovery key as text
// to show to the operator once (format: seal.EncodeRecoveryKey); the caller
// destroys it. Init does not leave the file open.
func Init(path string, passphrase *secret.Buffer) (recoveryKey *secret.Buffer, err error) {
	ctx := context.Background()
	if passphrase.Len() == 0 {
		return nil, errors.New("sqlitestore: empty passphrase")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(abs, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("%w: %s", ErrExists, abs)
		}
		return nil, err
	}
	f.Close()
	defer func() {
		if err != nil {
			removeDB(abs)
		}
	}()
	db, err := openDB(abs, false)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	if err := migrate(ctx, db); err != nil {
		return nil, err
	}
	ws, err := seal.NewID()
	if err != nil {
		return nil, err
	}
	master, err := seal.NewMasterKey()
	if err != nil {
		return nil, err
	}
	defer master.Destroy()
	pid, err := seal.NewID()
	if err != nil {
		return nil, err
	}
	rid, err := seal.NewID()
	if err != nil {
		return nil, err
	}
	pslot, err := seal.NewPassphraseSlot(ws, pid, master, passphrase, kdfForNewSlots)
	if err != nil {
		return nil, err
	}
	rslot, rawRecovery, err := seal.NewRecoverySlot(ws, rid, master)
	if err != nil {
		return nil, err
	}
	defer rawRecovery.Destroy()
	text, err := seal.EncodeRecoveryKey(rawRecovery)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			text.Destroy()
		}
	}()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO meta (id, workspace_id, format_version, created_at) VALUES (1,?,?,?)`,
		ws, seal.FormatVersion, time.Now().Unix()); err != nil {
		return nil, err
	}
	if err := insertSlot(ctx, tx, pslot); err != nil {
		return nil, err
	}
	if err := insertSlot(ctx, tx, rslot); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return text, nil
}

func removeDB(path string) {
	os.Remove(path)
	os.Remove(path + "-wal")
	os.Remove(path + "-shm")
	os.Remove(path + "-journal")
}

type credential struct {
	kind string
	buf  *secret.Buffer // passphrase text, or the raw 32-byte recovery key
}

// Open unlocks the workspace at path with a passphrase.
func Open(path string, passphrase *secret.Buffer) (*Store, error) {
	return open(path, credential{seal.SlotPassphrase, passphrase}, false)
}

// OpenWithRecovery unlocks the workspace with the recovery key as printed
// (see seal.EncodeRecoveryKey for the text format).
func OpenWithRecovery(path string, recovery *secret.Buffer) (*Store, error) {
	raw, err := seal.DecodeRecoveryKey(recovery)
	if err != nil {
		return nil, err
	}
	defer raw.Destroy()
	return open(path, credential{seal.SlotRecovery, raw}, false)
}

func open(path string, cred credential, readOnly bool) (*Store, error) {
	ctx := context.Background()
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := checkFile(abs); err != nil {
		return nil, err
	}
	db, err := openDB(abs, readOnly)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Store, error) { db.Close(); return nil, err }
	v, err := schemaVersion(ctx, db)
	if err != nil {
		return fail(fmt.Errorf("%w: %v", ErrNotWorkspace, err))
	}
	switch {
	case v == 0:
		return fail(ErrNotWorkspace)
	case v < len(migrations) && readOnly:
		return fail(fmt.Errorf("sqlitestore: file needs migration from schema %d to %d; open it read-write first", v, len(migrations)))
	case v < len(migrations):
		if err := migrate(ctx, db); err != nil {
			return fail(err)
		}
	case v > len(migrations):
		return fail(fmt.Errorf("sqlitestore: file has schema version %d, this binary knows %d; upgrade the binary", v, len(migrations)))
	}
	m, err := loadMeta(ctx, db)
	if err != nil {
		return fail(err)
	}
	slots, err := loadSlots(ctx, db)
	if err != nil {
		return fail(err)
	}
	var master *secret.Buffer
	var used []byte
	tried := 0
	for _, sl := range slots {
		if sl.Kind != cred.kind {
			continue
		}
		tried++
		mk, err := sl.Unwrap(m.ws, cred.buf)
		if errors.Is(err, seal.ErrAuth) {
			continue
		}
		if err != nil {
			return fail(err)
		}
		master, used = mk, sl.ID
		break
	}
	if master == nil {
		if tried == 0 {
			return fail(fmt.Errorf("%w: the workspace has no %s slot", ErrWrongCredential, cred.kind))
		}
		return fail(ErrWrongCredential)
	}
	keys, err := seal.DeriveKeys(master)
	if err != nil {
		master.Destroy()
		return fail(err)
	}
	return &Store{db: db, path: abs, ws: m.ws, master: master, keys: keys, slotID: used, ro: readOnly, now: time.Now}, nil
}

// SlotInfo describes a key slot. Kind and id are structural data.
type SlotInfo struct {
	ID   []byte
	Kind string
	KDF  seal.KDFParams // passphrase slots
}

// Slots lists the key slots.
func (s *Store) Slots(ctx context.Context) ([]SlotInfo, error) {
	sl, err := loadSlots(ctx, s.db)
	if err != nil {
		return nil, err
	}
	var out []SlotInfo
	for _, x := range sl {
		out = append(out, SlotInfo{ID: x.ID, Kind: x.Kind, KDF: x.KDF})
	}
	return out, nil
}

func (s *Store) writable() error {
	if s.ro {
		return errors.New("sqlitestore: store opened read-only")
	}
	return nil
}

// AddPassphraseSlot adds another passphrase that unlocks the workspace and
// returns the new slot id.
func (s *Store) AddPassphraseSlot(ctx context.Context, passphrase *secret.Buffer) ([]byte, error) {
	if err := s.writable(); err != nil {
		return nil, err
	}
	id, err := seal.NewID()
	if err != nil {
		return nil, err
	}
	slot, err := seal.NewPassphraseSlot(s.ws, id, s.master, passphrase, kdfForNewSlots)
	if err != nil {
		return nil, err
	}
	return id, s.slotTx(ctx, func(tx *sql.Tx) error { return insertSlot(ctx, tx, slot) })
}

// AddRecoverySlot adds a new recovery key and returns it as printable text.
func (s *Store) AddRecoverySlot(ctx context.Context) (text *secret.Buffer, slotID []byte, err error) {
	if err := s.writable(); err != nil {
		return nil, nil, err
	}
	id, err := seal.NewID()
	if err != nil {
		return nil, nil, err
	}
	slot, raw, err := seal.NewRecoverySlot(s.ws, id, s.master)
	if err != nil {
		return nil, nil, err
	}
	defer raw.Destroy()
	text, err = seal.EncodeRecoveryKey(raw)
	if err != nil {
		return nil, nil, err
	}
	if err := s.slotTx(ctx, func(tx *sql.Tx) error { return insertSlot(ctx, tx, slot) }); err != nil {
		text.Destroy()
		return nil, nil, err
	}
	return text, id, nil
}

// RemoveSlot deletes a key slot. The last remaining slot is never removed.
func (s *Store) RemoveSlot(ctx context.Context, id []byte) error {
	if err := s.writable(); err != nil {
		return err
	}
	return s.slotTx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM keyslots`).Scan(&n); err != nil {
			return err
		}
		if n <= 1 {
			return ErrLastSlot
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM keyslots WHERE id = ?`, id)
		if err != nil {
			return err
		}
		if c, _ := res.RowsAffected(); c != 1 {
			return ports.ErrNotFound
		}
		return nil
	})
}

// ChangePassphrase replaces the passphrase slot slotID with one for
// newPassphrase (fresh salt, current default parameters) and returns the new
// slot's id. The old passphrase stops working. Records are not re-encrypted.
func (s *Store) ChangePassphrase(ctx context.Context, slotID []byte, newPassphrase *secret.Buffer) ([]byte, error) {
	if err := s.writable(); err != nil {
		return nil, err
	}
	id, err := seal.NewID()
	if err != nil {
		return nil, err
	}
	slot, err := seal.NewPassphraseSlot(s.ws, id, s.master, newPassphrase, kdfForNewSlots)
	if err != nil {
		return nil, err
	}
	err = s.slotTx(ctx, func(tx *sql.Tx) error {
		var kind string
		if err := tx.QueryRowContext(ctx, `SELECT kind FROM keyslots WHERE id = ?`, slotID).Scan(&kind); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ports.ErrNotFound
			}
			return err
		}
		if kind != seal.SlotPassphrase {
			return fmt.Errorf("sqlitestore: slot is a %s slot, not a passphrase slot", kind)
		}
		if err := insertSlot(ctx, tx, slot); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM keyslots WHERE id = ?`, slotID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return id, nil
}

func (s *Store) slotTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	return mapErr(tx.Commit())
}
