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
// OTHER TOOLS. The schema check (SCHEMA ALLOW-LIST) accepts exactly the objects
// the migrations create. Running ANALYZE or PRAGMA optimize on the file (or any
// tool that does) creates sqlite_stat1, which the check does not know: the
// store is then refused with ErrSchema, and nothing is repaired automatically
// (drop the table with the sqlite3 shell only if you know it is the cause).
// That is a safe refusal, not a defect to work around. VACUUM and backup or
// restore of the file keep the schema as it is and pass.
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
// CONCURRENCY. One handle has one long-lived connection for reads, and
// operations on it run one at a time, on the handle's gate. The gate is waited
// for until the caller's context ends, with no other timeout. A call into the
// same handle from inside a View or Update callback therefore waits for itself
// until its context ends and then returns an error wrapping ErrReentrant and
// the context's error; with context.Background it would wait forever. A
// context that has ended before the call starts gets the context's error, not
// ErrReentrant. Inside an Update, read a secret with the Writer's OpenSecret
// (tx.go). Close waits for the gate without limit and is safe to call twice; do
// not call it from inside a callback. Several handles, in one process or
// several, may open the same file: Update starts with BEGIN IMMEDIATE, so a
// second writer waits up to the busy timeout and then fails with
// ports.ErrConflict. A handle holds a shared flock on the file for its
// lifetime. An open takes the file exclusively only while it reads it (below)
// and waits up to five seconds for another open's exclusive stretch to end
// before it gives up with ErrLocked. A restore and a rekey take the lock
// exclusively and fail with ErrLocked at once while any other handle has the
// file open. (flock is advisory: a process that does not use it can still
// write; the key epoch check is what stops its stale handles, and the record
// map what stops it from getting a record rolled back or deleted under a
// handle.) A handle whose lock upgrade or downgrade failed (Rekey) is marked
// broken and returns ErrLockLost from every operation but Close.
//
// A write is one transaction on a CONNECTION OF ITS OWN: every Update, slot
// change, rekey and cleanup opens a new connection to the file, runs the
// epoch and schema checks on it right after BEGIN IMMEDIATE and the statements
// on it, and closes it. The schema that is checked and the schema the
// statements run against are then read from the same snapshot, under the write
// lock. (A long-lived connection keeps the schema it parsed: another process
// could plant a trigger, let the handle load it, and remove it from
// sqlite_master again without changing the schema cookie; the text check would
// then pass while the trigger still fired.) The new connection parses the
// schema when it connects, which is before the write lock is held, so the
// transaction also runs PRAGMA writable_schema=RESET first, which makes SQLite
// parse the schema again from the file. Cost, measured with 3000 records:
// opening such a connection, BEGIN IMMEDIATE, the reset, the epoch and schema
// checks and closing it take about 0.15 ms, inside a whole Update of about
// 1 ms; an Open costs hundreds of milliseconds (key derivation and
// verification). Reads (View, Open, Verify) use the long-lived connection: they
// run SELECTs on the base tables, which no trigger fires on.
//
// ENDING A WRITE. A write is cancelled only before COMMIT starts: the context
// is checked right before it and the transaction rolled back. COMMIT itself,
// and the head-file write after it, run without the caller's cancellation (a
// driver that watches the context can report a context error for a COMMIT that
// SQLite completed, which would report a committed rekey as failed and destroy
// its new recovery key, or invite a retry that applies a change twice). If
// COMMIT returns any error, the store reads the file back to find out whether
// it committed (the chain holds the row the transaction appended; for a rekey,
// meta.key_epoch is the new epoch) and reports that: success when it did, the
// error when it did not, ErrOutcomeUnknown when even that read fails. The
// read-back runs on a new connection (the failed one is closed first). A head
// file that cannot be advanced after a commit is a notice; the next open accepts
// a file that is ahead of its head file. A rekey whose outcome is unknown returns
// its new recovery key with ErrOutcomeUnknown (valid only if the rekey took
// effect).
//
// OPEN ORDER. A failed open leaves the database, its -wal and the head file
// byte for byte as they were, and creates no head file or head lock. A
// read-only open (VerifyFile included) and a failed open may leave -wal and -shm
// files that SQLite created; the store never removes, truncates or otherwise
// touches either on any path (another process may have committed into that WAL;
// only SQLite decides when it is checkpointed and removed).
// Open
//
//  1. checks the file (regular, owned by the user, mode 0600);
//  2. reads the meta row and the key slots (schema first), holding the file
//     lock for that read only, and releases the lock;
//  3. unlocks (the Argon2 work), holding no lock;
//  4. takes the lock again and, on a READ-ONLY connection, reads the declared
//     schema version, checks the schema against the allow-list (SCHEMA
//     ALLOW-LIST, schemacheck.go) before anything the file says is trusted,
//     reloads the meta row and requires the unlocked master key to belong to
//     its key epoch (else ErrStaleHandle: the file changed meanwhile), compares
//     the head file (without changing it) and runs the full verification
//     (verify.go: WHAT VERIFY COVERS AND DOES NOT COVER, which includes the
//     schema again). A wrong credential, a forged audit row, a rolled-back
//     record, a planted trigger: the open fails here and nothing has been
//     written;
//  5. goes back to a shared lock and reopens the file, read-write (or, for a
//     read-only handle, read-only without the immutable promise). The reopened
//     file must be the file the lock is held on (the descriptor's identity) and
//     its chain must end at the head just verified, else ErrVerify. (When
//     other handles share the file a well-behaved writer may have appended
//     since; then the verified head must still be in the chain, and the
//     handle's record map checks the new rows at its first use.) The schema
//     and the epoch are checked again;
//  6. migrates if the file's schema is older (and then checks the schema of the
//     new version and verifies again), writes or advances the head file, and
//     retries a rekey's pending cleanup.
//
// Steps 2 and 4 take the lock exclusively when nobody holds the file and, with
// that lock held, no -wal is waiting to be replayed, and read the file as
// immutable (it cannot change between the checks and the reopening); otherwise
// they share, and wait up to five seconds for an exclusive holder. A read-only
// handle (VerifyFile) holds the shared lock like any other after step 4.
//
// AcceptRollback changes only what step 4 does with a head file that is ahead
// of or foreign to the chain; SkipVerify skips only the full verification in
// step 4 (the schema check and the unlock stay), and the handle then does it at
// its first use (below). Neither writes before the checks that remain passed.
// Passphrases are used as the bytes typed, with no Unicode normalisation.
// Unlocking depends on the slots and the key epoch only; damage to audit rows
// or records never makes a credential "wrong".
//
// SCHEMA ALLOW-LIST. Every connection is opened with trusted_schema OFF,
// cell_size_check ON and the driver's defensive mode (dsn). The database
// schema is compared with the exact schema the migrations create for the
// file's version (schemacheck.go): a trigger, view, extra table or index, or a
// changed column is an ErrVerify wrapping ErrSchema. The comparison runs at
// every open, after a migration, at the start of every write transaction and of
// every verification (so before every Update, slot change and Rekey), on the
// connection the write then uses (see CONCURRENCY).
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
// record is and which lookup tag it has, and every record it reads is compared
// with it, so a record rolled back to an older authentic version while the
// handle is open is refused instead of being written back as a new version, and
// a record deleted behind the handle's back is an ErrVerify, not "not found"
// (tx.go: THE HANDLE'S RECORD MAP).
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
	"sync/atomic"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/unlock"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"

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
	// viaRecovery: the handle was unlocked with the recovery credential, which is
	// a presentation of it; recProof is the last PresentRecovery on this handle.
	viaRecovery bool
	recProof    *RecoveryProof
	// writing counts the write transactions and exclusive file locks this handle
	// holds right now (writeHeld); the cold factor is never asked while it is
	// not zero.
	writing atomic.Int32
	ro      bool
	legacy  bool          // a format 1 store opened for the migration: nothing else works on it
	legacy2 bool          // a format 2 store opened for Migrate3: nothing else works on it
	policy  unlock.Policy // the policy of the table this handle unlocked
	// cold is the source of the cold sub-key factor (SetColdSource); recSecret is
	// the recovery key of a handle unlocked with it. Both are guarded by mu.
	cold      *ColdSource
	recSecret *recoveryKey
	now       func() time.Time
	lock      *os.File
	gate      chan struct{} // capacity 1: held for the length of an operation

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
// refuses. A context that has ended before the call gets its own error.
func (s *Store) enter(ctx context.Context) (release func(), err error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("sqlitestore: %w", err)
	}
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
	s.recSecret.destroy()
	if s.recProof != nil {
		s.recProof.key.destroy()
	}
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
// changes the file while it is open (and that no WAL has to be replayed); the
// open's stages promise it only while they hold the file lock exclusively.
//
// Every connection, whatever its mode, is opened with trusted_schema OFF
// (SQL functions and virtual tables that a view, trigger or CHECK in the file
// names run only if SQLite deems them innocuous), cell_size_check ON (a
// corrupt cell size is an error, not an out-of-bounds read) and the driver's
// defensive mode (_defensive=1: SQLITE_DBCONFIG_DEFENSIVE, so a statement
// cannot switch on writable_schema or write to shadow tables). The driver
// sorts the _pragma values by name before it runs them, so their order here
// means nothing; only _defensive is applied before the first statement. The
// pragmas then run one after another during connecting, and some of them
// (journal_mode) already make SQLite parse the schema, which is why a write
// transaction resets it (CONCURRENCY). This build of SQLite is not compiled with
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
	if f := uint64(m.format); f != seal.LegacyRecordFormat && f != seal.RecordFormat && f != seal.StoreFormat {
		return m, fmt.Errorf("sqlitestore: format version %d is not supported (this binary: %d; or the meta row was modified)", m.format, seal.StoreFormat)
	}
	if len(m.ws) != seal.IDSize {
		return m, bad("has a bad workspace id")
	}
	if len(m.epoch) != seal.EpochSize || len(m.epochMAC) != seal.MACSize {
		return m, bad("has a bad key epoch")
	}
	return m, nil
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
	if _, err := tx.ExecContext(ctx, `INSERT INTO meta (id, workspace_id, format_version, created_at, key_epoch, epoch_mac, policy) VALUES (1,?,?,?,?,?,?)`,
		ws, seal.StoreFormat, now, epoch, epochMAC, string(unlock.Standard)); err != nil {
		return nil, err
	}
	for _, sl := range []tslot{pslot, rslot} {
		if err := insertTSlot(ctx, tx, sl); err != nil {
			return nil, err
		}
	}
	if err := writeRecoveryPub(ctx, tx, pslot.recPub); err != nil {
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

// newSlots wraps master in one passphrase slot and one new recovery slot, both
// of store format 3 under the standard policy and both binding the hash of the
// recovery public key derived from the new recovery key, and returns the
// recovery key as printable text.
func newSlots(ws []byte, master, passphrase *secret.Buffer) (pslot, rslot tslot, text *secret.Buffer, err error) {
	rk, err := seal.NewMasterKey() // 32 random bytes in guarded memory
	if err != nil {
		return
	}
	defer rk.Destroy()
	return newSlotsWith(ws, master, passphrase, rk)
}

// newSlotsWith is newSlots for a given recovery key: a passphrase change that
// keeps the recovery key (and so the bound recovery public key hash).
func newSlotsWith(ws []byte, master, passphrase, rk *secret.Buffer) (pslot, rslot tslot, text *secret.Buffer, err error) {
	pid, err := seal.NewID()
	if err != nil {
		return
	}
	rid, err := seal.NewID()
	if err != nil {
		return
	}
	priv, err := seal.RecoveryKeyPair(rk)
	if err != nil {
		return
	}
	pub := priv.PublicKey().Bytes()
	hash := seal.RecoveryPubKeyHash(pub)
	b := seal.SlotBinding{Policy: string(unlock.Standard), RecoveryPubKeyHash: hash}
	ps, err := seal.NewBoundPassphraseSlot(ws, pid, master, passphrase, kdfForNewSlots, b)
	if err != nil {
		return
	}
	rs, err := seal.NewBoundRecoverySlot(ws, rid, master, rk, b)
	if err != nil {
		return
	}
	text, err = seal.EncodeRecoveryKey(rk)
	if err != nil {
		return
	}
	return tslot{id: pid, kind: seal.SlotPassphrase, ps: ps, bound: true, recPub: pub}, tslot{id: rid, kind: seal.SlotRecovery, ps: rs, bound: true, recPub: pub}, text, nil
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
	kind    string
	buf     *secret.Buffer // passphrase text, or the raw 32-byte recovery key
	factors *FactorInputs  // kind credFactors: what the fido2-hmac and composite slots need
}

// credFactors is the credential kind of OpenWithFactors.
const credFactors = "factors"

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

	// legacy opens a store of format 1 for the migration (Migrate), which is the
	// only code that reads one; every other open refuses it with ErrLegacyFormat.
	legacy bool
	// legacy2 opens a store of format 2 for Migrate3, the only code that reads
	// one; every other open refuses it with ErrFormat2, before any key is derived.
	legacy2 bool
}

// Open unlocks the workspace at path with a passphrase.
func Open(path string, passphrase *secret.Buffer) (*Store, error) {
	return open(path, credential{kind: seal.SlotPassphrase, buf: passphrase}, false, OpenOptions{})
}

// OpenWithOptions is Open with options. Check Store.Notices after it.
func OpenWithOptions(path string, passphrase *secret.Buffer, o OpenOptions) (*Store, error) {
	return open(path, credential{kind: seal.SlotPassphrase, buf: passphrase}, false, o)
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
	return open(path, credential{kind: seal.SlotRecovery, buf: raw}, false, o)
}

// lockWaitMax is how long an open waits for the file lock held by another
// open. (A variable so a test can lower it.)
var lockWaitMax = 5 * time.Second

// lockShared takes a shared lock, retrying while an exclusive holder (another
// open reading the file, which takes well under a second) has it, for at most
// lockWaitMax or until ctx ends.
func lockShared(ctx context.Context, path string) (*os.File, error) {
	deadline := time.Now().Add(lockWaitMax)
	for {
		f, err := lockFile(path, false)
		if !errors.Is(err, ErrLocked) || time.Now().After(deadline) {
			return f, err
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: %w", ErrLocked, ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// A stage is one read-only look at the file: the file lock and a read-only
// connection. When nobody holds the file and, with the exclusive lock held, no
// -wal waits to be replayed, the lock stays exclusive and the connection is
// immutable, so the file cannot change between the checks and the reopening;
// otherwise the lock is shared (waited for). The store never removes -wal or
// -shm itself.
type stage struct {
	lock      *os.File
	db        *sql.DB
	exclusive bool
}

func openStage(ctx context.Context, abs string) (*stage, error) {
	g := &stage{}
	if l, err := lockFile(abs, true); err == nil {
		if hasWAL(abs) {
			if err := downgradeLock(l); err != nil {
				l.Close()
				return nil, fmt.Errorf("%w: the shared lock could not be taken: %v", ErrLocked, err)
			}
			g.lock = l
		} else {
			g.lock, g.exclusive = l, true
		}
	}
	if g.lock == nil {
		l, err := lockShared(ctx, abs)
		if err != nil {
			return nil, err
		}
		g.lock = l
	}
	db, err := openDB(abs, true, g.exclusive)
	if err != nil {
		g.lock.Close()
		return nil, err
	}
	g.db = db
	return g, nil
}

// close ends the stage.
func (g *stage) close() {
	g.db.Close()
	g.lock.Close()
}

// checkDeclared reads the file's schema version, refuses one this binary cannot
// use and checks the schema against the allow-list, before anything else the
// file says is trusted.
func checkDeclared(ctx context.Context, db dbq, readOnly bool) (int, error) {
	v, err := declaredVersion(ctx, db)
	if err != nil {
		return 0, err
	}
	switch {
	case v < len(migrations) && readOnly:
		return 0, fmt.Errorf("sqlitestore: file needs migration from schema %d to %d; open it read-write first", v, len(migrations))
	case v > len(migrations):
		return 0, fmt.Errorf("sqlitestore: file has schema version %d, this binary knows %d; upgrade the binary (or the schema_version table was modified)", v, len(migrations))
	}
	if err := checkSchema(ctx, db, v); err != nil {
		return 0, err
	}
	return v, nil
}

// test hooks: beforeUnlock is called before the key derivation, beforeReopen
// between the verification and the reopening of the file.
var beforeUnlock, beforeReopen func()

// confirmReopen checks that the connection just opened reads the file this
// handle verified: the same file as the locked descriptor, and a chain that
// ends at the head verified (when the lock was exclusive; under a shared lock a
// well-behaved writer may have appended, and the verified head must still be in
// the chain).
func confirmReopen(ctx context.Context, abs string, lock *os.File, db dbq, want Head, exclusive bool) error {
	bad := func(why string) error {
		return &VerifyError{Problems: []string{"the workspace file changed between its verification and its reopening: " + why}}
	}
	f, err := os.Open(abs)
	if err != nil {
		return err
	}
	defer f.Close()
	a, err := f.Stat()
	b, err2 := lock.Stat()
	if err != nil || err2 != nil || !os.SameFile(a, b) {
		return bad("the path no longer names the file that was verified")
	}
	got, err := chainHead(ctx, db)
	if err != nil {
		return err
	}
	if got.equal(want) {
		return nil
	}
	if !exclusive {
		if ok, err := chainContains(ctx, db, want); err != nil {
			return err
		} else if ok {
			return nil
		}
	}
	return bad("the audit chain does not end where the verification saw it end")
}

// open follows the order in the package comment (OPEN ORDER): the meta row and
// the key slots are read and the lock released; the key derivation runs with no
// lock held; then, on a read-only connection and under the lock again, schema,
// epoch, the head-file comparison and the full verification, none of which
// writes anything; and only when all of that passed, a connection that may
// write (unless the handle is read-only) for the migration, the head file and
// the cleanup retry.
func open(path string, cred credential, readOnly bool, o OpenOptions) (*Store, error) {
	st, err := openFile(path, cred, readOnly, o)
	if err != nil {
		return nil, err
	}
	if !o.SkipVerify && !o.legacy && !o.legacy2 {
		// The identity layer, on every open (ADR 0010 decision 4): manifest
		// members against the identities recomputed from the stored keys,
		// owner anchors, membership uniqueness, labels.
		if cerr := st.View(context.Background(), func(r ports.Reader) error { return labels.Check(r) }); cerr != nil {
			st.Close()
			return nil, cerr
		}
	}
	return st, nil
}

func openFile(path string, cred credential, readOnly bool, o OpenOptions) (st *Store, err error) {
	ctx := context.Background()
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := checkFile(abs); err != nil {
		return nil, err
	}
	// Steps 2 and 3: what the key derivation needs, then the key derivation.
	m1, tbl, err := readUnlockInputs(ctx, abs, readOnly)
	if err != nil {
		return nil, err
	}
	// Before any key is derived: a format this open does not read, and a slot
	// table that breaks its own policy.
	switch f := uint64(m1.format); {
	case f == seal.LegacyRecordFormat && !o.legacy:
		return nil, ErrLegacyFormat
	case f == seal.RecordFormat && !o.legacy2:
		return nil, ErrFormat2
	case f == seal.LegacyRecordFormat && o.legacy, f == seal.RecordFormat && o.legacy2:
	case o.legacy || o.legacy2:
		return nil, ErrNotLegacy
	}
	if tbl.format >= seal.StoreFormat {
		if err := tbl.check(); err != nil {
			return nil, fmt.Errorf("%w: the slot table of this workspace was edited or is damaged, so nothing was unlocked (run `spo store verify` to see what differs; an old copy of the file may be the way back): %w", ErrVerify, err)
		}
	}
	var master *secret.Buffer
	var keys *seal.Keys
	defer func() {
		if err != nil {
			master.Destroy()
			keys.Destroy()
		}
	}()
	if beforeUnlock != nil {
		beforeUnlock()
	}
	master, used, notices, err := unlockTable(ctx, tbl, cred, func(mk *secret.Buffer) (bool, error) {
		return epochMatches(m1, mk)
	})
	if err != nil {
		return nil, err
	}
	if keys, err = seal.DeriveKeys(master); err != nil {
		return nil, err
	}

	// Step 4: the checks, under the lock, on a read-only connection.
	g, err := openStage(ctx, abs)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			g.close()
		}
	}()
	db := g.db
	v, err := checkDeclared(ctx, db, readOnly)
	if err != nil {
		return nil, err
	}
	m, err := loadMeta(ctx, db)
	if err != nil {
		return nil, err
	}
	if ok, err := epochMatches(m, master); err != nil {
		return nil, err
	} else if !ok {
		return nil, fmt.Errorf("%w: the file changed while the credential was being checked; open it again", ErrStaleHandle)
	}
	head, notices, rewrite, adopted, err := checkHead(ctx, db, abs, m.ws, readOnly, o, notices)
	if err != nil {
		return nil, err
	}
	st = &Store{legacy: o.legacy || o.legacy2, legacy2: o.legacy2, policy: tbl.policy, db: db, path: abs, ws: m.ws, epoch: m.epoch, master: master, keys: keys, slotID: used, viaRecovery: cred.kind == seal.SlotRecovery, ro: readOnly, now: time.Now,
		lock: g.lock, gate: make(chan struct{}, 1), head: head, notices: notices, schemaV: v}
	if cred.kind == seal.SlotRecovery && cred.buf != nil {
		if cp, cerr := copySecret(cred.buf); cerr == nil {
			st.recSecret = &recoveryKey{secret: cp}
		}
	}
	// The full verification, still on the read-only connection. (With
	// SkipVerify the handle builds the same knowledge at its first use.)
	if !o.SkipVerify {
		res, err := st.verifyLocked(ctx, false)
		if err != nil {
			return nil, err
		}
		st.notices = append(st.notices, res.Notices...)
	}

	// Step 5: the credential is good and the file verified. From here the
	// handle holds the file shared and uses a connection that does not promise
	// SQLite the file is immutable.
	exclusive := g.exclusive
	db.Close()
	if exclusive {
		if err = downgradeLock(g.lock); err != nil {
			return nil, fmt.Errorf("%w: the shared lock could not be taken after the checks: %v", ErrLocked, err)
		}
		g.exclusive = false
	}
	if beforeReopen != nil {
		beforeReopen()
	}
	db, err = openDB(abs, readOnly, false)
	if err != nil {
		return nil, err
	}
	g.db, st.db = db, db
	if err = confirmReopen(ctx, abs, g.lock, db, head, exclusive); err != nil {
		return nil, err
	}
	if err = checkSchema(ctx, db, v); err != nil { // the file may have changed between the two connections
		return nil, err
	}
	if err = st.checkEpochNow(ctx); err != nil {
		return nil, err
	}
	if readOnly {
		return st, nil
	}
	// Step 6. A file of format 1 or 2 is migrated by Migrate and Migrate3 only.
	if v < len(migrations) && !o.legacy && !o.legacy2 {
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
		if o.AcceptRollback || adopted {
			write = writeHeadFile // the operator said the file's own state is the truth
		}
		if err = write(abs, m.ws, head); err != nil {
			return nil, err
		}
	}
	if _, serr := os.Lstat(sidecarPath(abs)); serr == nil {
		os.Remove(sidecarPath(abs)) // announced by a restore, now settled by a verified open
	}
	st.retryCleanup(ctx)
	return st, nil
}

// readUnlockInputs is step 2 of the open: under the file lock, the schema
// check, the meta row and the slot table. The lock is released before it
// returns.
func readUnlockInputs(ctx context.Context, abs string, readOnly bool) (m metaRow, t *table, err error) {
	g, err := openStage(ctx, abs)
	if err != nil {
		return m, nil, err
	}
	defer g.close()
	if _, err = checkDeclared(ctx, g.db, readOnly); err != nil {
		return m, nil, err
	}
	if m, err = loadMeta(ctx, g.db); err != nil {
		return m, nil, err
	}
	t, err = loadTable(ctx, g.db, m.ws, uint64(m.format))
	return m, t, err
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
func unlockTable(ctx context.Context, t *table, cred credential, accept func(*secret.Buffer) (bool, error)) (master *secret.Buffer, used []byte, notices []string, err error) {
	if cred.kind == credFactors {
		return unlockFactors(ctx, t, cred.factors, accept)
	}
	ws := t.ws
	work := uint64(0)
	unwrapped := false
	for _, ts := range t.slots {
		sl := ts.ps
		if ts.isFactor() || sl.Kind != cred.kind {
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
// head, whether the head file must be (re)written, whether that write adopts a
// restore's announcement (see adoptSidecar), and the notices so far.
func checkHead(ctx context.Context, db dbq, path string, ws []byte, readOnly bool, o OpenOptions, notices []string) (Head, []string, bool, bool, error) {
	own, err := chainHead(ctx, db)
	if err != nil {
		return Head{}, notices, false, false, err
	}
	hws, hh, found, herr := readHeadFile(path)
	switch {
	case !found:
		if !readOnly {
			notices = append(notices, "the head file was missing and has been recreated; a rollback of this workspace before now cannot be detected")
		}
		return own, notices, true, false, nil
	case herr != nil || !bytes.Equal(hws, ws):
		if !o.AcceptRollback {
			if n, ok := adoptSidecar(path, ws, own); ok {
				return own, append(notices, n), true, true, nil
			} else if n != "" {
				return Head{}, notices, false, false, fmt.Errorf("%w (%s)", ErrHeadMismatch, n)
			}
			return Head{}, notices, false, false, ErrHeadMismatch
		}
		return own, notices, true, false, nil
	}
	ok, err := chainContains(ctx, db, hh)
	if err != nil {
		return Head{}, notices, false, false, err
	}
	if !ok && !o.AcceptRollback {
		if n, adopt := adoptSidecar(path, ws, own); adopt {
			return own, append(notices, n), true, true, nil
		} else if n != "" {
			return Head{}, notices, false, false, fmt.Errorf("%w (head file: sequence %d, file ends at sequence %d; %s)", ErrRolledBack, hh.Seq, own.Seq, n)
		}
		return Head{}, notices, false, false, fmt.Errorf("%w (head file: sequence %d, file ends at sequence %d)", ErrRolledBack, hh.Seq, own.Seq)
	}
	// Equal, or the file is ahead (a crash between commit and head write), or
	// the rollback was accepted: the file's own head is the truth now.
	return own, notices, !hh.equal(own), false, nil
}

// adoptSidecar decides whether <path>.head.next, which a restore wrote before it
// swapped the file in, settles a head file that disagrees with the file. It is
// trusted only when it parses, names this workspace and names exactly the head
// the file itself verifies to (own, read from the file's audit chain). The
// message says what was done or why the sidecar was ignored; empty when there is
// no sidecar.
//
// What an attacker who can write the workspace directory gains from this: the
// ability to make an open accept the file's own state as the recorded head. They
// already have that: the head file is a plain file with no key, and replacing
// it does the same. The sidecar never names a head other than the file's own,
// so it cannot make the open accept anything that the chain of the file does
// not already show; a sidecar that does not match is ignored and reported.
func adoptSidecar(path string, ws []byte, own Head) (msg string, adopt bool) {
	sp := sidecarPath(path)
	sws, sh, found, err := readHeadAt(sp)
	if !found {
		return "", false
	}
	switch {
	case err != nil:
		return "the file " + filepath.Base(sp) + " cannot be read as a head record and was ignored", false
	case !bytes.Equal(sws, ws):
		return "the file " + filepath.Base(sp) + " names another workspace and was ignored", false
	case !sh.equal(own):
		return "the file " + filepath.Base(sp) + " does not name this file's own head and was ignored", false
	}
	return "an interrupted restore left " + filepath.Base(sp) + "; it names this file's own head, so it was adopted as the head file", true
}

// FactorInfo describes one factor of a slot: its kind (unlock's names), its id,
// and for a FIDO2 factor the credential id.
type FactorInfo struct {
	Kind         string
	ID           []byte
	CredentialID []byte
	// Touch is the stored result of the enrolment touch probe (0 when the factor
	// is not a FIDO2 credential or the probe did not run).
	Touch uint8
}

// SlotInfo describes a key slot. Kind and id are structural data.
type SlotInfo struct {
	ID      []byte
	Kind    string
	KDF     seal.KDFParams // passphrase slots
	Factors []FactorInfo
	// Legacy: a passphrase or recovery slot carried over from format 2; it binds
	// neither the policy nor a recovery public key hash.
	Legacy bool
	// RecoveryPubKeyHash is the hash the slot binds (empty for a legacy slot and
	// under strict).
	RecoveryPubKeyHash []byte
}

// Slots lists the key slots, ordered by id.
func (s *Store) Slots(ctx context.Context) ([]SlotInfo, error) {
	_, out, err := s.slotsAndPolicy(ctx)
	return out, err
}

// Policy returns the workspace policy of the table this handle unlocked, read
// from the file again.
func (s *Store) Policy(ctx context.Context) (unlock.Policy, error) {
	p, _, err := s.slotsAndPolicy(ctx)
	return p, err
}

func (s *Store) slotsAndPolicy(ctx context.Context) (unlock.Policy, []SlotInfo, error) {
	release, err := s.enter(ctx)
	if err != nil {
		return "", nil, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", nil, err
	}
	defer tx.Rollback()
	if err := s.checkEpoch(ctx, tx); err != nil {
		return "", nil, err
	}
	m, err := loadMeta(ctx, tx)
	if err != nil {
		return "", nil, err
	}
	t, err := loadTable(ctx, tx, m.ws, uint64(m.format))
	if err != nil {
		return "", nil, err
	}
	out := t.infos()
	return t.policy, out, nil
}

// writable refuses a write on a read-only handle and on a handle opened for the
// migration: a store of format 1 is changed only by Migrate.
func (s *Store) writable() error {
	if s.legacy {
		return ErrLegacyFormat
	}
	return s.writableMigrating()
}

// writableMigrating is writable for Migrate, the one writer of a legacy handle.
func (s *Store) writableMigrating() error {
	if s.ro {
		return errors.New("sqlitestore: store opened read-only")
	}
	return nil
}

// writeHeld reports whether this handle holds a write transaction or the exclusive
// file lock.
func (s *Store) writeHeld() bool { return s.writing.Load() > 0 }
