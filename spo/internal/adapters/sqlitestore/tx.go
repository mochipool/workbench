package sqlitestore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"

	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"

	sqlite "modernc.org/sqlite"
)

// payloadV1 is the first byte of every sealed payload. It keeps the sealed
// plaintext non-empty (an empty artefact is allowed) and versions the payload
// framing independently of the seal format.
const payloadV1 = 0x01

const (
	tagNamespace = "record-ref"
	eventKind    = "audit.event"
	// SQLITE_BUSY_SNAPSHOT: this transaction's read snapshot is stale, so
	// someone else committed since it began.
	sqliteBusySnapshot = 517
)

func classOf(k ports.Kind) string {
	if k.Secret() {
		return seal.ClassSecret
	}
	return seal.ClassSensitive
}

// ownerOf is the owner field of the associated data: the owner name and the
// sequence number. Names cannot contain '#', so the pair is unambiguous. The
// number is bound so that two numbered records of one owner cannot swap their
// lookup tags undetected.
func ownerOf(r ports.Ref) string { return r.Name + "#" + strconv.Itoa(r.Num) }

// mapErr turns a lost snapshot or a unique-tag collision into ErrConflict.
func mapErr(err error) error {
	var se *sqlite.Error
	if errors.As(err, &se) {
		if se.Code() == sqliteBusySnapshot {
			return fmt.Errorf("%w: %v", ports.ErrConflict, err)
		}
		// SQLITE_CONSTRAINT_UNIQUE / PRIMARYKEY: another writer inserted the same ref.
		if se.Code() == 2067 || se.Code() == 1555 {
			return fmt.Errorf("%w: %v", ports.ErrConflict, err)
		}
	}
	return err
}

func (s *Store) tag(r ports.Ref) ([]byte, error) {
	return s.keys.Index.Tag(tagNamespace, []byte(r.Name), []byte(r.Kind), []byte(strconv.Itoa(r.Num)))
}

type dbq interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

type recRow struct {
	id      []byte
	kind    string
	class   string
	version uint64
	sealed  seal.SealedRecord
}

// op is one staged change inside an Update.
type op struct {
	del    bool
	data   []byte         // non-secret content
	secret *secret.Buffer // secret content (a private guarded copy)
}

type txn struct {
	s        *Store
	ctx      context.Context
	q        dbq
	writable bool
	ops      map[ports.Ref]*op
	order    []ports.Ref
}

// fetch reads the record row for ref, or ports.ErrNotFound.
func (t *txn) fetch(ref ports.Ref) (*recRow, error) {
	tag, err := t.s.tag(ref)
	if err != nil {
		return nil, err
	}
	var r recRow
	var v int64
	err = t.q.QueryRowContext(t.ctx, `SELECT id, kind, class, version, nonce, wrapped_key, ciphertext FROM records WHERE lookup_tag = ?`, tag).
		Scan(&r.id, &r.kind, &r.class, &v, &r.sealed.Nonce, &r.sealed.WrappedKey, &r.sealed.Ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ports.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if v < 1 {
		return nil, fmt.Errorf("%w: bad version", ErrCorrupt)
	}
	r.version = uint64(v)
	return &r, nil
}

// openRow authenticates and decrypts a row. The associated data uses the
// row's own kind, class and version, so any edit to those columns fails here;
// kind and class are also checked against what the reference implies.
func (t *txn) openRow(ref ports.Ref, r *recRow) (*secret.Buffer, error) {
	if r.kind != string(ref.Kind) || r.class != classOf(ref.Kind) {
		return nil, fmt.Errorf("%w: %s has kind/class %q/%q", ErrCorrupt, ref, r.kind, r.class)
	}
	pt, err := t.s.keys.OpenRecord(seal.RecordMeta{
		WorkspaceID: t.s.ws, RecordID: r.id, Kind: r.kind, Owner: ownerOf(ref), Class: r.class, Version: r.version,
	}, r.sealed)
	if err != nil {
		if errors.Is(err, seal.ErrAuth) || errors.Is(err, seal.ErrFormat) {
			return nil, fmt.Errorf("%w: %s", ErrCorrupt, ref)
		}
		return nil, err
	}
	// Strip the payload framing byte into a fresh guarded buffer.
	defer pt.Destroy()
	var out *secret.Buffer
	err = pt.Use(func(b []byte) error {
		if b[0] != payloadV1 {
			return fmt.Errorf("%w: %s has payload framing %#x", ErrCorrupt, ref, b[0])
		}
		if len(b) == 1 {
			return nil // empty artefact
		}
		out = secret.Take(append([]byte(nil), b[1:]...))
		return nil
	})
	return out, err
}

func (t *txn) Get(ref ports.Ref) ([]byte, error) {
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	if ref.Kind.Secret() {
		return nil, ports.ErrSecretKind
	}
	if o := t.ops[ref]; o != nil {
		if o.del {
			return nil, ports.ErrNotFound
		}
		return append([]byte{}, o.data...), nil
	}
	r, err := t.fetch(ref)
	if err != nil {
		return nil, err
	}
	b, err := t.openRow(ref, r)
	if err != nil {
		return nil, err
	}
	if b == nil {
		return []byte{}, nil
	}
	defer b.Destroy()
	var out []byte
	err = b.Use(func(x []byte) error { out = append([]byte{}, x...); return nil })
	return out, err
}

func (t *txn) Exists(ref ports.Ref) (bool, error) {
	if err := ref.Validate(); err != nil {
		return false, err
	}
	if o := t.ops[ref]; o != nil {
		return !o.del, nil
	}
	_, err := t.fetch(ref)
	if errors.Is(err, ports.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

func (t *txn) stage(ref ports.Ref, o *op) {
	if old, ok := t.ops[ref]; ok {
		old.secret.Destroy()
	} else {
		t.order = append(t.order, ref)
	}
	t.ops[ref] = o
}

func (t *txn) Put(ref ports.Ref, data []byte) error {
	if err := ref.Validate(); err != nil {
		return err
	}
	if ref.Kind.Secret() {
		return ports.ErrSecretKind
	}
	t.stage(ref, &op{data: append([]byte{}, data...)})
	return nil
}

func (t *txn) PutSecret(ref ports.Ref, sec *secret.Buffer) error {
	if err := ref.Validate(); err != nil {
		return err
	}
	if !ref.Kind.Secret() {
		return fmt.Errorf("%w: %s is not a secret kind", ports.ErrInvalidRef, ref.Kind)
	}
	var cp *secret.Buffer
	if err := sec.Use(func(b []byte) error {
		cp = secret.Take(append([]byte(nil), b...))
		return nil
	}); err != nil {
		return fmt.Errorf("sqlitestore: empty or destroyed secret for %s: %w", ref, err)
	}
	t.stage(ref, &op{secret: cp})
	return nil
}

func (t *txn) Delete(ref ports.Ref) error {
	if err := ref.Validate(); err != nil {
		return err
	}
	t.stage(ref, &op{del: true})
	return nil
}

func (t *txn) discard() {
	for _, o := range t.ops {
		o.secret.Destroy()
	}
}

// touched is one audit entry: a record written (Hash = SHA-256 of the sealed
// record bytes) or deleted (Hash empty).
type touched struct {
	_       struct{} `cbor:",toarray"`
	ID      []byte
	Version uint64
	Hash    []byte
}

func sealedHash(r seal.SealedRecord) []byte {
	h := sha256.Sum256(r.Bytes())
	return h[:]
}

// apply writes every staged change and the audit row. It runs in the same SQL
// transaction as the reads of the Update, so a stale snapshot fails at the
// first write (reported as ErrConflict) and nothing is changed.
func (t *txn) apply() error {
	var entries []touched
	var events [][]string // [op, ref]
	now := t.s.now().Unix()
	for _, ref := range t.order {
		o := t.ops[ref]
		tag, err := t.s.tag(ref)
		if err != nil {
			return err
		}
		var oldID []byte
		var oldVer int64
		err = t.q.QueryRowContext(t.ctx, `SELECT id, version FROM records WHERE lookup_tag = ?`, tag).Scan(&oldID, &oldVer)
		exists := err == nil
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if o.del {
			if !exists {
				continue
			}
			res, err := t.q.ExecContext(t.ctx, `DELETE FROM records WHERE id = ? AND version = ?`, oldID, oldVer)
			if err != nil {
				return mapErr(err)
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return ports.ErrConflict
			}
			entries = append(entries, touched{ID: oldID, Version: uint64(oldVer), Hash: []byte{}})
			events = append(events, []string{"delete", ref.String()})
			continue
		}
		id, version := oldID, uint64(oldVer)+1
		if !exists {
			if id, err = seal.NewID(); err != nil {
				return err
			}
			version = 1
		}
		meta := seal.RecordMeta{WorkspaceID: t.s.ws, RecordID: id, Kind: string(ref.Kind), Owner: ownerOf(ref), Class: classOf(ref.Kind), Version: version}
		sealed, err := t.seal(meta, o)
		if err != nil {
			return err
		}
		if exists {
			res, err := t.q.ExecContext(t.ctx, `UPDATE records SET version=?, nonce=?, wrapped_key=?, ciphertext=?, updated_at=? WHERE id=? AND version=?`,
				int64(version), sealed.Nonce, sealed.WrappedKey, sealed.Ciphertext, now, id, oldVer)
			if err != nil {
				return mapErr(err)
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return ports.ErrConflict
			}
		} else if _, err := t.q.ExecContext(t.ctx, `INSERT INTO records (id, lookup_tag, kind, class, version, nonce, wrapped_key, ciphertext, updated_at) VALUES (?,?,?,?,?,?,?,?,?)`,
			id, tag, meta.Kind, meta.Class, int64(version), sealed.Nonce, sealed.WrappedKey, sealed.Ciphertext, now); err != nil {
			return mapErr(err)
		}
		entries = append(entries, touched{ID: id, Version: version, Hash: sealedHash(sealed)})
		events = append(events, []string{"put", ref.String()})
	}
	if len(entries) == 0 {
		return nil
	}
	return t.appendAudit(now, events, entries)
}

func (t *txn) seal(meta seal.RecordMeta, o *op) (seal.SealedRecord, error) {
	// The framed plaintext is built in an ordinary heap slice because seal
	// takes lent []byte; it is wiped right after sealing. For a secret kind
	// this puts the secret in ordinary memory for the duration of the call.
	var pt []byte
	defer func() { clear(pt) }()
	if o.secret != nil {
		if err := o.secret.Use(func(b []byte) error {
			pt = append(append(make([]byte, 0, len(b)+1), payloadV1), b...)
			return nil
		}); err != nil {
			return seal.SealedRecord{}, err
		}
	} else {
		pt = append(append(make([]byte, 0, len(o.data)+1), payloadV1), o.data...)
	}
	return t.s.keys.SealRecord(meta, pt)
}

// auditID is the "record id" of an audit event payload: 8 zero bytes then the
// sequence number, big endian. Events are sealed like records so the same
// code path (and the same bindings) protect them.
func auditID(seq uint64) []byte {
	id := make([]byte, seal.IDSize)
	binary.BigEndian.PutUint64(id[8:], seq)
	return id
}

func (s *Store) eventMeta(seq uint64) seal.RecordMeta {
	return seal.RecordMeta{WorkspaceID: s.ws, RecordID: auditID(seq), Kind: eventKind, Owner: "", Class: seal.ClassSensitive, Version: seq}
}

var zeroMAC = make([]byte, seal.MACSize)

// auditRowBytes is the canonical CBOR the chain MAC covers:
// [format version, workspace id, seq, at, sealed event, touched list (CBOR bytes)].
func auditRowBytes(ws []byte, seq uint64, at int64, event, touchedRaw []byte) ([]byte, error) {
	return seal.EncodeCanonical([]any{seal.FormatVersion, ws, seq, at, event, touchedRaw})
}

func (t *txn) appendAudit(now int64, events [][]string, entries []touched) error {
	var prevSeq uint64
	prev := zeroMAC
	var last []byte
	var seq64 int64
	err := t.q.QueryRowContext(t.ctx, `SELECT seq, mac FROM audit ORDER BY seq DESC LIMIT 1`).Scan(&seq64, &last)
	switch {
	case err == nil:
		prevSeq, prev = uint64(seq64), last
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}
	seq := prevSeq + 1
	evBytes, err := seal.EncodeCanonical(events)
	if err != nil {
		return err
	}
	sealedEv, err := t.s.keys.SealRecord(t.s.eventMeta(seq), append([]byte{payloadV1}, evBytes...))
	if err != nil {
		return err
	}
	touchedRaw, err := seal.EncodeCanonical(entries)
	if err != nil {
		return err
	}
	event := sealedEv.Bytes()
	row, err := auditRowBytes(t.s.ws, seq, now, event, touchedRaw)
	if err != nil {
		return err
	}
	mac, err := t.s.keys.Audit.MAC(prev, row)
	if err != nil {
		return err
	}
	_, err = t.q.ExecContext(t.ctx, `INSERT INTO audit (seq, at, event, touched, mac, prev_mac) VALUES (?,?,?,?,?,?)`,
		int64(seq), now, event, touchedRaw, mac, prev)
	return mapErr(err)
}

// View implements ports.Store: reads at one consistent snapshot.
func (s *Store) View(ctx context.Context, fn func(ports.Reader) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	t := &txn{s: s, ctx: ctx, q: tx, ops: map[ports.Ref]*op{}}
	return fn(t)
}

// Update implements ports.Store. Reads see one snapshot plus this update's own
// writes. All writes, and one audit row for them, are applied in a single SQL
// transaction after fn returns nil; if fn fails, or another writer committed
// since the snapshot, nothing is written.
func (s *Store) Update(ctx context.Context, fn func(ports.Writer) error) error {
	if err := s.writable(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Pin the read snapshot now: a later commit by another handle makes our
	// first write fail with a stale snapshot instead of silently overwriting.
	var one int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM meta`).Scan(&one); err != nil {
		return err
	}
	t := &txn{s: s, ctx: ctx, q: tx, writable: true, ops: map[ports.Ref]*op{}}
	defer t.discard()
	if err := fn(t); err != nil {
		return err
	}
	if err := t.apply(); err != nil {
		return mapErr(err)
	}
	return mapErr(tx.Commit())
}

// Open implements ports.Vault: it returns the secret in guarded memory.
func (s *Store) Open(ctx context.Context, ref ports.Ref) (*secret.Buffer, error) {
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	if !ref.Kind.Secret() {
		return nil, fmt.Errorf("%w: %s is not a secret kind", ports.ErrInvalidRef, ref.Kind)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	t := &txn{s: s, ctx: ctx, q: tx, ops: map[ports.Ref]*op{}}
	r, err := t.fetch(ref)
	if err != nil {
		return nil, err
	}
	b, err := t.openRow(ref, r)
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, fmt.Errorf("%w: %s holds an empty secret", ErrCorrupt, ref)
	}
	return b, nil
}
