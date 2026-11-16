// Package sqlitestore implements ports.Store and ports.Vault over one SQLite
// file in which every payload is sealed (ADR 0003, ADR 0004).
//
// The database is not encrypted. Table and column names, record ids, kinds,
// versions, write times, key-slot parameters and the schema version are
// readable by anyone with the file (schema.go lists every column). Everything
// else, including the artefact names, is sealed with internal/platform/seal
// before it is written. Record classes are not stored: they follow from the
// kind.
//
// FILES. <path> is the database; <path>-wal and <path>-shm exist while it is
// open (WAL mode, secure_delete on); <path>.head records the end of the audit
// chain to notice a rollback and <path>.head.lock serialises its writers
// (head.go). All are created with mode 0600. Open refuses a database that is
// not a regular file, is not owned by the current user, or that group or
// others can access.
//
// KEYS AND THE KEY EPOCH. A random master key is wrapped once per key slot
// (passphrase or recovery); HKDF splits it into a record-wrapping key, an
// index key and an audit key (internal/platform/seal). meta holds a key epoch
// (16 random bytes, new at Init and at every Rekey) and epoch_mac, the MAC of
// the workspace id and epoch under the audit key. A master key belongs to the
// current epoch exactly when its audit key reproduces epoch_mac. Unlocking
// accepts only such a key; a slot that unwraps to another one is a slot row
// from before a rekey, and is skipped (ErrKeyEpoch when nothing else opens).
// Every handle remembers the epoch it unlocked, and View, Update, Open, slot
// operations, Verify and Rekey compare it with meta.key_epoch inside their
// transaction before anything else: a handle that outlived another process's
// rekey (or a modification of the meta row) gets ErrStaleHandle and does
// nothing.
//
// CONCURRENCY. One handle has one database connection, and operations on it
// run one at a time, on the handle's gate. The gate is waited for until the
// caller's context ends, with no other timeout. A call into the same handle
// from inside a View or Update callback therefore waits for itself until its
// context ends and then returns an error wrapping ErrReentrant and the
// context's error; with context.Background it would wait forever. Inside an
// Update, read a secret with the Writer's OpenSecret (tx.go). Close waits for
// the gate without limit and is safe to call twice; do not call it from
// inside a callback. Several handles, in one process or several, may open the
// same file: Update starts with BEGIN IMMEDIATE, so a second writer waits up
// to the busy timeout and then fails with ports.ErrConflict. A handle holds a
// shared flock on the file for its lifetime (an open that finds the file idle
// holds it exclusively while it runs its read-only checks, so that they can
// read it as immutable, and then goes back to shared). A restore and a rekey take it exclusively and
// fail with ErrLocked while any other handle has the file open. (flock is
// advisory: a process that does not use it can still write; the key epoch
// check is what stops its stale handles, and the record map what stops it from
// getting a record rolled back under a handle.) A handle whose lock upgrade
// or downgrade failed (Rekey) is marked broken and returns ErrLockLost from
// every operation but Close.
//
// OPEN ORDER. A failed open writes nothing: not the store file, nor -wal and
// -shm, nor the head file or its lock. Open
//
//  1. checks the file (regular, owned by the user, mode 0600) and takes the
//     file lock;
//  2. on a READ-ONLY connection: reads the declared schema version, checks the
//     schema against the allow-list (SCHEMA ALLOW-LIST, schemacheck.go) before
//     anything the file says is trusted, loads the meta row and key slots,
//     unlocks, checks the key epoch, compares the head file (without changing
//     it) and runs the full verification (verify.go: WHAT VERIFY COVERS AND
//     DOES NOT COVER, which includes the schema again). A wrong credential, a
//     forged audit row, a rolled-back record, a planted trigger: the open fails
//     here and nothing has been written;
//  3. only then reopens READ-WRITE, re-checks the schema and the epoch,
//     migrates if the file's schema is older (and then checks the schema of
//     the new version and verifies again), writes or advances the head file,
//     and retries a rekey's pending cleanup.
//
// AcceptRollback changes only what step 2 does with a head file that is ahead
// of or foreign to the chain; SkipVerify skips only the full verification in
// step 2 (the schema check and the unlock stay), and the handle then does it at
// its first use (below). Neither writes before the checks that remain passed.
// (A read-only connection to a database in WAL mode may create empty -wal and
// -shm files; when the open fails and nobody else has the file, they are removed
// again.) Passphrases are used as the bytes typed, with no Unicode
// normalisation. Unlocking depends on the slots and the key epoch only; damage
// to audit rows or records never makes a credential "wrong".
//
// SCHEMA ALLOW-LIST. Every connection is opened with trusted_schema OFF,
// cell_size_check ON and the driver's defensive mode (dsn). The database
// schema is compared with the exact schema the migrations create for the
// file's version (schemacheck.go): a trigger, view, extra table or index, or a
// changed column is an ErrVerify wrapping ErrSchema. The comparison runs at
// every open, after a migration, at the start of every write transaction and of
// every verification (so before every Update, slot change and Rekey).
//
// WRITE VERIFICATION. Before COMMIT, every statement-level write is read back
// and compared byte for byte with what the store wrote: Update reads back the
// record rows and the audit row, slot changes the new slot row and the audit
// row, Rekey every record row (and that there are no others), both key slot
// rows (and that there are no others), the meta row and the audit row. A
// difference aborts the transaction with ErrVerify. This catches anything that
// rewrites rows behind the store's back even where the schema check did not
// apply.
//
// THE HANDLE'S RECORD MAP. Each handle keeps what the audit chain says every
// record is, and every record it reads is compared with it, so a record rolled
// back to an older authentic version while the handle is open is refused
// instead of being written back as a new version (tx.go: THE HANDLE'S RECORD
// MAP).
//
// Backups use VACUUM INTO, which is safe under WAL; never copy the file byte
// for byte while it is open.
package sqlitestore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"

	_ "modernc.org/sqlite" // driver name "sqlite"
)

// kdfForNewSlots is what new passphrase slots use. Tests may lower it to the
// accepted minimum (seal.MinKDF) but never below: seal refuses weaker values.
var kdfForNewSlots = seal.DefaultKDF()

// busyTimeoutMS is how long a writer waits for the write lock. Tests lower it.
var busyTimeoutMS = 5000

// maxUnlockWork caps the key-derivation work one unlock attempts, in MiB times
// passes summed over the slots tried: about eleven default slots, or one slot
// at the ceiling. Slots past the cap are skipped with a notice. (A variable
// only so a test can lower it.)
var maxUnlockWork uint64 = 16384

// Store is an unlocked workspace. It is safe for concurrent use; operations
// on one Store serialise on its gate and its single database connection.
type Store struct {
	db     *sql.DB
	path   string
	ws     []byte
	epoch  []byte         // the key epoch this handle unlocked; read and replaced under the gate
	master *secret.Buffer // kept for slot management; guarded memory
	keys   *seal.Keys
	slotID []byte // slot that unlocked this store
	ro     bool
	now    func() time.Time
	lock   *os.File
	gate   chan struct{} // capacity 1: held for the length of an operation

	// Both are read and replaced under the gate.
	schemaV int         // schema version the database was last checked against
	known   *chainKnown // what the audit chain says every record is; nil until built (verify.go)

	mu       sync.Mutex // guards head, notices, closed, lockLost
	head     Head
	notices  []string
	closed   bool
	lockLost bool // a lock upgrade or downgrade failed; see ErrLockLost
}

var (
	_ ports.Store = (*Store)(nil)
	_ ports.Vault = (*Store)(nil)
)

// enter takes the handle's gate. It waits until the gate is free or ctx
// ends. A caller that is itself inside a View or Update callback of this
// handle waits for itself, so it gets the error only when ctx ends. A handle
// that lost its file lock gets ErrLockLost here, so every operation but Close
// refuses.
func (s *Store) enter(ctx context.Context) (release func(), err error) {
	select {
	case s.gate <- struct{}{}:
		s.mu.Lock()
		lost := s.lockLost
		s.mu.Unlock()
		if lost {
			<-s.gate
			return nil, ErrLockLost
		}
		return func() { <-s.gate }, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %w (a call made from inside a View or Update callback of the same store would cause this)", ErrReentrant, ctx.Err())
	}
}

// Close wipes the keys and closes the database. It waits for every running
// operation of the handle, with no time limit, and is safe to call twice. If
// a rekey's cleanup is still pending (see Cleanup) it is retried first; a
// failure becomes a notice, so check Notices after Close.
func (s *Store) Close() error {
	s.gate <- struct{}{}
	defer func() { <-s.gate }()
	s.mu.Lock()
	done := s.closed
	s.closed = true
	s.mu.Unlock()
	if done {
		return nil
	}
	s.mu.Lock()
	lost := s.lockLost
	s.mu.Unlock()
	if !s.ro && !lost {
		s.retryCleanup(context.Background())
	}
	s.keys.Destroy()
	s.master.Destroy()
	err := s.db.Close()
	if s.lock != nil {
		s.lock.Close()
	}
	return err
}

// checkFile refuses anything but a regular file, owned by the current user,
// that only its owner can access.
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
	return checkOwner(path, st)
}

// dsn builds the connection string. immutable promises SQLite that nobody
// changes the file while it is open (and that no WAL has to be replayed): it
// then neither locks the file nor creates -wal and -shm files, so inspecting
// a closed workspace leaves nothing behind.
//
// Every connection, whatever its mode, is opened with trusted_schema OFF
// (SQL functions and virtual tables that a view, trigger or CHECK in the file
// names run only if SQLite deems them innocuous), cell_size_check ON (a
// corrupt cell size is an error, not an out-of-bounds read) and the driver's
// defensive mode (_defensive=1: SQLITE_DBCONFIG_DEFENSIVE, so a statement
// cannot switch on writable_schema or write to shadow tables). The driver
// applies _defensive before the _pragma list, so all of it holds from the
// first statement. This build of SQLite is not compiled with
// SQLITE_TRUSTED_SCHEMA=0, which is why the pragma is set here. None of
// these stops a trigger made of plain UPDATE statements; the schema
// allow-list (schemacheck.go) does.
func dsn(path string, readOnly, immutable bool) string {
	q := url.Values{}
	q.Set("_defensive", "1")
	q.Add("_pragma", "trusted_schema(0)")
	q.Add("_pragma", "cell_size_check(1)")
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", busyTimeoutMS))
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "secure_delete(1)")
	if readOnly {
		q.Set("mode", "ro")
		q.Add("_pragma", "query_only(1)")
		if immutable {
			q.Set("immutable", "1")
		}
	} else {
		q.Add("_pragma", "journal_mode(WAL)")
		q.Add("_pragma", "synchronous(FULL)")
		q.Set("mode", "rw")
	}
	u := url.URL{Scheme: "file", Path: path, RawQuery: q.Encode()}
	return u.String()
}

func openDB(path string, readOnly, immutable bool) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dsn(path, readOnly, immutable))
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
	if err := applyMigrations(ctx, tx, v, len(migrations)); err != nil {
		return err
	}
	return tx.Commit()
}

// applyMigrations brings a database at schema version from (0: empty) to
// version to. migrate and expectedSchema (schemacheck.go) both use it, so the
// schema the check expects is the schema the migrations create.
func applyMigrations(ctx context.Context, tx *sql.Tx, from, to int) error {
	if from == 0 {
		if _, err := tx.ExecContext(ctx, `CREATE TABLE schema_version (version INTEGER NOT NULL) STRICT`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_version (version) VALUES (0)`); err != nil {
			return err
		}
	}
	for i := from; i < to; i++ {
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			return fmt.Errorf("sqlitestore: migration %d: %w", i+1, err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE schema_version SET version = ?`, i+1); err != nil {
			return err
		}
	}
	return nil
}

type metaRow struct {
	ws       []byte
	format   int
	epoch    []byte
	epochMAC []byte
}

// loadMeta reads the meta row. The schema has been checked by now, so a row
// that is missing or malformed was modified: an integrity error, not "not a
// workspace".
func loadMeta(ctx context.Context, q dbq) (metaRow, error) {
	var m metaRow
	bad := func(why string) error {
		return &VerifyError{Problems: []string{"the meta row " + why + " (it was modified)"}}
	}
	err := q.QueryRowContext(ctx, `SELECT workspace_id, format_version, key_epoch, epoch_mac FROM meta WHERE id = 1`).Scan(&m.ws, &m.format, &m.epoch, &m.epochMAC)
	if err != nil {
		return m, bad("is missing or unreadable")
	}
	if m.format != seal.FormatVersion {
		return m, fmt.Errorf("sqlitestore: format version %d is not supported (this binary: %d; or the meta row was modified)", m.format, seal.FormatVersion)
	}
	if len(m.ws) != seal.IDSize {
		return m, bad("has a bad workspace id")
	}
	if len(m.epoch) != seal.EpochSize || len(m.epochMAC) != seal.MACSize {
		return m, bad("has a bad key epoch")
	}
	return m, nil
}

// loadSlots reads the key slots in a stable order (by id).
func loadSlots(ctx context.Context, q dbq) ([]seal.Slot, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, kind, kdf_memory_kib, kdf_passes, kdf_lanes, salt, key_commit, nonce, wrapped_key FROM keyslots ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []seal.Slot
	for rows.Next() {
		var s seal.Slot
		var mem, passes, lanes sql.NullInt64
		if err := rows.Scan(&s.ID, &s.Kind, &mem, &passes, &lanes, &s.Salt, &s.Commit, &s.Nonce, &s.Wrapped); err != nil {
			return nil, err
		}
		s.KDF = seal.KDFParams{MemoryKiB: uint32(mem.Int64), Passes: uint32(passes.Int64), Lanes: uint8(lanes.Int64)}
		if mem.Int64 < 0 || mem.Int64 > 1<<32-1 || passes.Int64 < 0 || passes.Int64 > 1<<32-1 || lanes.Int64 < 0 || lanes.Int64 > 255 {
			s.KDF = seal.KDFParams{} // out of range values wrap: zero is refused as weak
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func insertSlot(ctx context.Context, q dbq, s seal.Slot) error {
	var mem, passes, lanes any
	var salt any
	if s.Kind == seal.SlotPassphrase {
		mem, passes, lanes, salt = int64(s.KDF.MemoryKiB), int64(s.KDF.Passes), int64(s.KDF.Lanes), s.Salt
	}
	_, err := q.ExecContext(ctx, `INSERT INTO keyslots (id, kind, kdf_memory_kib, kdf_passes, kdf_lanes, salt, key_commit, nonce, wrapped_key) VALUES (?,?,?,?,?,?,?,?,?)`,
		s.ID, s.Kind, mem, passes, lanes, salt, s.Commit, s.Nonce, s.Wrapped)
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
	db, err := openDB(abs, false, false)
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
	keys, err := seal.DeriveKeys(master)
	if err != nil {
		return nil, err
	}
	defer keys.Destroy()
	epoch, err := seal.NewEpoch()
	if err != nil {
		return nil, err
	}
	epochMAC, err := keys.Audit.EpochMAC(ws, epoch)
	if err != nil {
		return nil, err
	}
	pslot, rslot, text, err := newSlots(ws, master, passphrase)
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
	now := time.Now().Unix()
	if _, err := tx.ExecContext(ctx, `INSERT INTO meta (id, workspace_id, format_version, created_at, key_epoch, epoch_mac) VALUES (1,?,?,?,?,?)`,
		ws, seal.FormatVersion, now, epoch, epochMAC); err != nil {
		return nil, err
	}
	if err := insertSlot(ctx, tx, pslot); err != nil {
		return nil, err
	}
	if err := insertSlot(ctx, tx, rslot); err != nil {
		return nil, err
	}
	// The first audit row records the slot set the workspace starts with.
	set, err := slotSetHash(ctx, tx)
	if err != nil {
		return nil, err
	}
	head, err := appendAudit(ctx, tx, ws, keys, auditSlots, now, Head{MAC: zeroMAC}, [][]any{{"init"}}, nil, set)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	if err := writeHeadFile(abs, ws, *head); err != nil {
		return nil, err
	}
	return text, nil
}

// newSlots wraps master in one passphrase slot and one new recovery slot, and
// returns the recovery key as printable text.
func newSlots(ws []byte, master, passphrase *secret.Buffer) (pslot, rslot seal.Slot, text *secret.Buffer, err error) {
	pid, err := seal.NewID()
	if err != nil {
		return
	}
	rid, err := seal.NewID()
	if err != nil {
		return
	}
	if pslot, err = seal.NewPassphraseSlot(ws, pid, master, passphrase, kdfForNewSlots); err != nil {
		return
	}
	rslot, raw, err := seal.NewRecoverySlot(ws, rid, master)
	if err != nil {
		return
	}
	defer raw.Destroy()
	text, err = seal.EncodeRecoveryKey(raw)
	return
}

// hasWAL reports whether a non-empty -wal file sits beside path.
func hasWAL(path string) bool {
	st, err := os.Stat(path + "-wal")
	return err == nil && st.Size() > 0
}

func removeDB(path string) {
	os.Remove(path)
	os.Remove(path + "-wal")
	os.Remove(path + "-shm")
	os.Remove(path + "-journal")
	os.Remove(headPath(path))
	os.Remove(headPath(path) + ".lock")
}

type credential struct {
	kind string
	buf  *secret.Buffer // passphrase text, or the raw 32-byte recovery key
}

// OpenOptions are the choices of OpenWithOptions.
type OpenOptions struct {
	// AcceptRollback opens a workspace whose file is older than its head file
	// (or whose head file belongs to another workspace) and records the
	// file's own head as the new one. Use it after deliberately restoring an
	// older backup, never to silence the error.
	AcceptRollback bool
	// SkipVerify opens the workspace without the full verification that Open
	// otherwise runs after unlocking (and fails the open with). The
	// verification reads every audit row and every record row and runs
	// SQLite's integrity check; for the few thousand records a workspace holds
	// it takes well under a second. Skip it only to open a workspace that
	// fails verification in order to inspect or repair it; a record rolled
	// back inside the file is then not noticed until Verify is called.
	// AcceptRollback is independent: it only governs the head-file check.
	SkipVerify bool
}

// Open unlocks the workspace at path with a passphrase.
func Open(path string, passphrase *secret.Buffer) (*Store, error) {
	return open(path, credential{seal.SlotPassphrase, passphrase}, false, OpenOptions{})
}

// OpenWithOptions is Open with options. Check Store.Notices after it.
func OpenWithOptions(path string, passphrase *secret.Buffer, o OpenOptions) (*Store, error) {
	return open(path, credential{seal.SlotPassphrase, passphrase}, false, o)
}

// OpenWithRecovery unlocks the workspace with the recovery key as printed
// (see seal.EncodeRecoveryKey for the text format).
func OpenWithRecovery(path string, recovery *secret.Buffer) (*Store, error) {
	return OpenWithRecoveryOptions(path, recovery, OpenOptions{})
}

// OpenWithRecoveryOptions is OpenWithRecovery with options.
func OpenWithRecoveryOptions(path string, recovery *secret.Buffer, o OpenOptions) (*Store, error) {
	raw, err := seal.DecodeRecoveryKey(recovery)
	if err != nil {
		return nil, err
	}
	defer raw.Destroy()
	return open(path, credential{seal.SlotRecovery, raw}, false, o)
}

// open follows the order in the package comment (OPEN ORDER): file checks and
// lock; then, on a read-only connection, schema, unlock, epoch, the head-file
// comparison and the full verification, none of which writes anything; and
// only when all of that passed, a read-write connection for the migration, the
// head file and the cleanup retry.
func open(path string, cred credential, readOnly bool, o OpenOptions) (st *Store, err error) {
	ctx := context.Background()
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := checkFile(abs); err != nil {
		return nil, err
	}
	// The checks before the first write read the file on a read-only
	// connection. One that can have the file to itself (nobody holds it open,
	// no WAL to replay) reads it as immutable, which leaves no -wal or -shm
	// behind; otherwise it shares, and a read-only connection to a database in
	// WAL mode may create empty -wal and -shm files, which the failure path
	// below removes again when it can prove nobody else uses them. A
	// read-write open takes the exclusive lock only for this stretch and goes
	// back to shared before it writes; two opens at the same instant may
	// therefore see ErrLocked from each other, which is what the lock is for.
	var lock *os.File
	immutable := false
	_, errW := os.Lstat(abs + "-wal")
	_, errS := os.Lstat(abs + "-shm")
	hadSideFiles := errW == nil || errS == nil
	if !hasWAL(abs) {
		if lock, err = lockFile(abs, true); err == nil {
			immutable = true
		}
	}
	if lock == nil {
		if lock, err = lockFile(abs, false); err != nil {
			return nil, err
		}
	}
	db, err := openDB(abs, true, immutable)
	if err != nil {
		lock.Close()
		return nil, err
	}
	var master *secret.Buffer
	var keys *seal.Keys
	defer func() {
		if err != nil {
			db.Close()
			if !hadSideFiles && !immutable && upgradeLock(lock) == nil {
				// Nobody else has the file: take back what our read-only
				// connection created, so a failed open leaves no trace.
				os.Remove(abs + "-wal")
				os.Remove(abs + "-shm")
			}
			lock.Close()
			master.Destroy()
			keys.Destroy()
		}
	}()
	v, err := declaredVersion(ctx, db)
	if err != nil {
		return nil, err
	}
	switch {
	case v < len(migrations) && readOnly:
		return nil, fmt.Errorf("sqlitestore: file needs migration from schema %d to %d; open it read-write first", v, len(migrations))
	case v > len(migrations):
		return nil, fmt.Errorf("sqlitestore: file has schema version %d, this binary knows %d; upgrade the binary (or the schema_version table was modified)", v, len(migrations))
	}
	// Nothing the file says is trusted before its schema is the expected one.
	if err = checkSchema(ctx, db, v); err != nil {
		return nil, err
	}
	m, err := loadMeta(ctx, db)
	if err != nil {
		return nil, err
	}
	slots, err := loadSlots(ctx, db)
	if err != nil {
		return nil, err
	}
	master, used, notices, err := unlock(m.ws, slots, cred, func(mk *secret.Buffer) (bool, error) {
		return epochMatches(m, mk)
	})
	if err != nil {
		return nil, err
	}
	if keys, err = seal.DeriveKeys(master); err != nil {
		return nil, err
	}
	head, notices, rewrite, err := checkHead(ctx, db, abs, m.ws, readOnly, o, notices)
	if err != nil {
		return nil, err
	}
	st = &Store{db: db, path: abs, ws: m.ws, epoch: m.epoch, master: master, keys: keys, slotID: used, ro: readOnly, now: time.Now,
		lock: lock, gate: make(chan struct{}, 1), head: head, notices: notices, schemaV: v}
	// The full verification, still on the read-only connection. (With
	// SkipVerify the handle builds the same knowledge at its first use.)
	if !o.SkipVerify {
		res, err := st.verifyLocked(ctx, false)
		if err != nil {
			return nil, err
		}
		st.notices = append(st.notices, res.Notices...)
	}
	if readOnly {
		return st, nil
	}
	// The credential is good and the file verified: now it may be written.
	db.Close()
	if immutable {
		if err = downgradeLock(lock); err != nil {
			return nil, fmt.Errorf("%w: the shared lock could not be taken after the checks: %v", ErrLocked, err)
		}
		immutable = false // the handle holds the file shared from here on
	}
	rw, err := openDB(abs, false, false)
	if err != nil {
		return nil, err
	}
	db, st.db = rw, rw
	if err = checkSchema(ctx, db, v); err != nil { // the file may have changed between the two connections
		return nil, err
	}
	if err = st.checkEpochNow(ctx); err != nil {
		return nil, err
	}
	if v < len(migrations) {
		if err = migrate(ctx, db); err != nil {
			return nil, err
		}
		st.schemaV = len(migrations)
		if err = checkSchema(ctx, db, st.schemaV); err != nil {
			return nil, err
		}
		if !o.SkipVerify {
			if _, err = st.verifyLocked(ctx, false); err != nil {
				return nil, err
			}
		}
	}
	if rewrite {
		write := advanceHeadFile
		if o.AcceptRollback {
			write = writeHeadFile // the operator said the file's own state is the truth
		}
		if err = write(abs, m.ws, head); err != nil {
			return nil, err
		}
	}
	st.retryCleanup(ctx)
	return st, nil
}

// epochMatches reports whether master belongs to the key epoch recorded in m:
// its audit key reproduces epoch_mac.
func epochMatches(m metaRow, master *secret.Buffer) (bool, error) {
	keys, err := seal.DeriveKeys(master)
	if err != nil {
		return false, err
	}
	defer keys.Destroy()
	return keys.Audit.CheckEpoch(m.ws, m.epoch, m.epochMAC)
}

// unlock tries the slots of cred's kind in the order given (by id). A slot
// whose parameters are outside the accepted range or that is malformed is
// skipped with a notice instead of failing the unlock, and the total
// key-derivation work is capped, so a planted slot cannot lock the operator
// out or make the binary compute without limit.
//
// A slot that unwraps is then checked with accept: the master key must belong
// to the workspace's current key epoch. One that does not is a slot row from
// before a rekey (put back from an old copy); it is skipped with a notice.
// When no slot is accepted, the error is ErrKeyEpoch if some slot did unwrap
// (the credential was right, for an earlier epoch) and ErrWrongCredential if
// none did. Nothing about the audit chain or the records takes part: damage
// there is reported by Verify, never as a wrong credential.
//
// What an attacker who can write the file can still do: put an old slot row
// back together with the old meta row (key_epoch and epoch_mac). The old
// credential then unlocks the old master key, which is accepted as current.
// That key opens nothing sealed after the rekey (the records' data keys are
// wrapped under the new record-wrapping key), and the verification Open runs
// afterwards fails, because the audit rows after the rollover are MAC'd under
// the new audit key and the slot set no longer matches the recorded one. With
// SkipVerify the handle opens, finds no record, and Verify fails.
func unlock(ws []byte, slots []seal.Slot, cred credential, accept func(*secret.Buffer) (bool, error)) (master *secret.Buffer, used []byte, notices []string, err error) {
	work := uint64(0)
	unwrapped := false
	for _, sl := range slots {
		if sl.Kind != cred.kind {
			continue
		}
		skip := func(why string) {
			notices = append(notices, fmt.Sprintf("skipped %s slot %s: %s", sl.Kind, hex.EncodeToString(sl.ID[:min(4, len(sl.ID))]), why))
		}
		if sl.Kind == seal.SlotPassphrase {
			if err := sl.KDF.Validate(); err != nil {
				skip("key-derivation parameters outside the accepted range")
				continue
			}
			w := uint64(sl.KDF.MemoryKiB/1024) * uint64(sl.KDF.Passes)
			if work+w > maxUnlockWork {
				skip("the unlock has already done the most key-derivation work it allows")
				continue
			}
			work += w
		}
		mk, err := sl.Unwrap(ws, cred.buf)
		switch {
		case errors.Is(err, seal.ErrAuth):
			continue
		case errors.Is(err, seal.ErrWeakKDF), errors.Is(err, seal.ErrFormat):
			skip("malformed")
			continue
		case err != nil:
			return nil, nil, notices, err
		}
		unwrapped = true
		ok, err := accept(mk)
		if err != nil || !ok {
			mk.Destroy()
			if err != nil {
				return nil, nil, notices, err
			}
			skip("it opens a master key of an earlier key epoch (a rekey replaced it)")
			continue
		}
		return mk, sl.ID, notices, nil
	}
	err = ErrWrongCredential
	if unwrapped {
		err = ErrKeyEpoch
	}
	if len(notices) > 0 {
		return nil, nil, notices, fmt.Errorf("%w (%s)", err, strings.Join(notices, "; "))
	}
	return nil, nil, notices, err
}

// checkHead compares the file with its head file. It returns the file's own
// head, whether the head file must be (re)written, and the notices so far.
func checkHead(ctx context.Context, db dbq, path string, ws []byte, readOnly bool, o OpenOptions, notices []string) (Head, []string, bool, error) {
	own, err := chainHead(ctx, db)
	if err != nil {
		return Head{}, notices, false, err
	}
	hws, hh, found, herr := readHeadFile(path)
	switch {
	case !found:
		if !readOnly {
			notices = append(notices, "the head file was missing and has been recreated; a rollback of this workspace before now cannot be detected")
		}
		return own, notices, true, nil
	case herr != nil || !bytes.Equal(hws, ws):
		if !o.AcceptRollback {
			return Head{}, notices, false, ErrHeadMismatch
		}
		return own, notices, true, nil
	}
	ok, err := chainContains(ctx, db, hh)
	if err != nil {
		return Head{}, notices, false, err
	}
	if !ok && !o.AcceptRollback {
		return Head{}, notices, false, fmt.Errorf("%w (head file: sequence %d, file ends at sequence %d)", ErrRolledBack, hh.Seq, own.Seq)
	}
	// Equal, or the file is ahead (a crash between commit and head write), or
	// the rollback was accepted: the file's own head is the truth now.
	return own, notices, !hh.equal(own), nil
}

// SlotInfo describes a key slot. Kind and id are structural data.
type SlotInfo struct {
	ID   []byte
	Kind string
	KDF  seal.KDFParams // passphrase slots
}

// Slots lists the key slots, ordered by id.
func (s *Store) Slots(ctx context.Context) ([]SlotInfo, error) {
	release, err := s.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := s.checkEpoch(ctx, tx); err != nil {
		return nil, err
	}
	sl, err := loadSlots(ctx, tx)
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
