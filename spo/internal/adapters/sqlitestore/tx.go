package sqlitestore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/fxamacker/cbor/v2"

	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"

	sqlite "modernc.org/sqlite"
)

const (
	tagNamespace = "record-ref"
	eventKind    = "audit.event"
	sqliteBusy   = 5 // primary result code; BUSY_SNAPSHOT (517) and BUSY_RECOVERY (261) carry it in the low byte
)

// Audit row kinds.
const (
	auditUpdate   = "update"
	auditSlots    = "slots"
	auditRollover = "rollover"
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

// parseOwner is the inverse of ownerOf.
func parseOwner(o string) (name string, num int, err error) {
	i := strings.LastIndexByte(o, '#')
	if i < 0 {
		return "", 0, fmt.Errorf("%w: malformed owner", ErrCorrupt)
	}
	if num, err = strconv.Atoi(o[i+1:]); err != nil {
		return "", 0, fmt.Errorf("%w: malformed owner", ErrCorrupt)
	}
	return o[:i], num, nil
}

// mapErr turns a lost lock or a unique-tag collision into ErrConflict: any
// SQLITE_BUSY (5, and its extended forms such as BUSY_SNAPSHOT 517) or a
// uniqueness violation (2067, 1555) means another writer got there first.
func mapErr(err error) error {
	var se *sqlite.Error
	if errors.As(err, &se) {
		if se.Code()&0xff == sqliteBusy || se.Code() == 2067 || se.Code() == 1555 {
			return fmt.Errorf("%w: %v", ports.ErrConflict, err)
		}
	}
	return err
}

// busyOrLocked reports a plain SQLITE_BUSY (5) or SQLITE_LOCKED (6) error.
func busyOrLocked(err error) bool {
	var se *sqlite.Error
	if errors.As(err, &se) {
		c := se.Code() & 0xff
		return c == sqliteBusy || c == 6
	}
	return false
}

func tagFor(keys *seal.Keys, name string, kind string, num int) ([]byte, error) {
	return keys.Index.Tag(tagNamespace, []byte(name), []byte(kind), []byte(strconv.Itoa(num)))
}

func (s *Store) tag(r ports.Ref) ([]byte, error) {
	return tagFor(s.keys, r.Name, string(r.Kind), r.Num)
}

type dbq interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

type recRow struct {
	id      []byte
	kind    string
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
	r, err := t.fetchTag(tag)
	if errors.Is(err, errBadVersion) {
		return nil, &RefError{ref, fmt.Errorf("%w: bad version", ErrCorrupt)}
	}
	return r, err
}

var errBadVersion = errors.New("bad version")

// fetchTag reads the record row with lookup tag tag, or ports.ErrNotFound.
// Every row it returns has been compared with the handle's record map: its
// version and hash must be what the audit chain recorded for its id, and its
// tag the one the map holds for that id, or the result is an ErrVerify (a
// record changed or rolled back behind this handle's back). So is a missing row
// for a tag the map lists.
func (t *txn) fetchTag(tag []byte) (*recRow, error) {
	var r recRow
	var v int64
	err := t.q.QueryRowContext(t.ctx, `SELECT id, kind, version, nonce, wrapped_key, owner_sealed, ciphertext FROM records WHERE lookup_tag = ?`, tag).
		Scan(&r.id, &r.kind, &v, &r.sealed.Nonce, &r.sealed.WrappedKey, &r.sealed.Owner, &r.sealed.Ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		if _, live := t.s.known.tags[string(tag)]; live {
			return nil, errRecordChanged() // the chain lists a record with this tag, and it is gone
		}
		return nil, ports.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if v < 1 {
		return nil, errBadVersion
	}
	r.version = uint64(v)
	h, err := recordHash(r.kind, tag, r.sealed)
	if err != nil {
		return nil, err
	}
	if st, ok := t.s.known.recs[string(r.id)]; !ok || st.deleted || st.version != r.version || !bytes.Equal(st.hash, h) || t.s.known.tags[string(tag)] != string(r.id) {
		return nil, errRecordChanged()
	}
	return &r, nil
}

// errRecordChanged is what a row that disagrees with the record map returns.
// It names nothing.
func errRecordChanged() error {
	return &VerifyError{Problems: []string{"a record does not match what the audit chain recorded for it: it was changed or rolled back while the workspace was open"}}
}

func (t *txn) meta(ref ports.Ref, r *recRow) seal.RecordMeta {
	return seal.RecordMeta{WorkspaceID: t.s.ws, RecordID: r.id, Kind: r.kind, Owner: ownerOf(ref), Class: classOf(ref.Kind), Version: r.version}
}

// corrupt maps a seal failure to ErrCorrupt for ref. Anything else (a memory
// limit, a destroyed key) is returned as it is.
func corrupt(ref ports.Ref, err error) error {
	if errors.Is(err, seal.ErrAuth) || errors.Is(err, seal.ErrFormat) {
		return &RefError{ref, ErrCorrupt}
	}
	return err
}

// openData opens a sensitive row. The associated data uses the row's own kind
// and version, so any edit to those columns fails here; the kind is also
// checked against what the reference implies.
func (t *txn) openData(ref ports.Ref, r *recRow) ([]byte, error) {
	if r.kind != string(ref.Kind) {
		return nil, &RefError{ref, fmt.Errorf("%w: stored kind %q", ErrCorrupt, r.kind)}
	}
	pt, err := t.s.keys.OpenRecord(t.meta(ref, r), r.sealed)
	return pt, corrupt(ref, err)
}

// OpenSecret returns a secret artefact in guarded memory from inside a View or
// Update, seeing this update's own writes. The caller destroys it. It is not
// part of ports.Writer: reach it with a type assertion. (Calling Store.Open
// from inside a callback waits for itself until its context ends.)
func (t *txn) OpenSecret(ref ports.Ref) (*secret.Buffer, error) {
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	if !ref.Kind.Secret() {
		return nil, fmt.Errorf("%w: %s is not a secret kind", ports.ErrInvalidRef, ref.Kind)
	}
	if o := t.ops[ref]; o != nil {
		if o.del {
			return nil, ports.ErrNotFound
		}
		return copySecret(o.secret)
	}
	r, err := t.fetch(ref)
	if err != nil {
		return nil, err
	}
	if r.kind != string(ref.Kind) {
		return nil, &RefError{ref, fmt.Errorf("%w: stored kind %q", ErrCorrupt, r.kind)}
	}
	b, err := t.s.keys.OpenSecret(t.meta(ref, r), r.sealed)
	return b, corrupt(ref, err)
}

// copySecret copies a guarded buffer into another guarded buffer; the bytes
// never reach ordinary memory.
func copySecret(src *secret.Buffer) (*secret.Buffer, error) {
	return secret.Fill(src.Len(), func(dst []byte) error {
		return src.Use(func(b []byte) error { copy(dst, b); return nil })
	})
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
	return t.openData(ref, r)
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

// PutSecret stages a secret. The caller's buffer may be destroyed as soon as
// PutSecret returns, so it is copied, guarded memory to guarded memory.
func (t *txn) PutSecret(ref ports.Ref, sec *secret.Buffer) error {
	if err := ref.Validate(); err != nil {
		return err
	}
	if !ref.Kind.Secret() {
		return fmt.Errorf("%w: %s is not a secret kind", ports.ErrInvalidRef, ref.Kind)
	}
	if sec.Len() == 0 {
		return &RefError{ref, errors.New("sqlitestore: empty or destroyed secret")}
	}
	cp, err := copySecret(sec)
	if err != nil {
		return &RefError{ref, err}
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

// touched is one audit entry: a record written (Hash = recordHash) or deleted
// (Hash empty). The list is the canonical CBOR of an array of these arrays:
// [record id, version, hash].
type touched struct {
	_       struct{} `cbor:",toarray"`
	ID      []byte
	Version uint64
	Hash    []byte
}

// recordHash is SHA-256 of the canonical CBOR of
// [kind, lookup tag, nonce, wrapped key, owner blob, ciphertext]. Including
// the kind and the tag means that editing either column, or swapping the tags
// of two records, changes a hash the audit chain covers.
func recordHash(kind string, tag []byte, r seal.SealedRecord) ([]byte, error) {
	b, err := seal.EncodeCanonical([]any{kind, tag, r.Nonce, r.WrappedKey, r.Owner, r.Ciphertext})
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(b)
	return h[:], nil
}

// stored is one row of the records table as the store wrote it.
type stored struct {
	id, tag   []byte
	kind      string
	version   int64
	sealed    seal.SealedRecord
	updatedAt int64
}

func (a *stored) equal(b *stored) bool {
	return bytes.Equal(a.id, b.id) && bytes.Equal(a.tag, b.tag) && a.kind == b.kind && a.version == b.version &&
		bytes.Equal(a.sealed.Nonce, b.sealed.Nonce) && bytes.Equal(a.sealed.WrappedKey, b.sealed.WrappedKey) &&
		bytes.Equal(a.sealed.Owner, b.sealed.Owner) && bytes.Equal(a.sealed.Ciphertext, b.sealed.Ciphertext) && a.updatedAt == b.updatedAt
}

// readStored reads the row with the given id, or returns nil when there is none.
func readStored(ctx context.Context, q dbq, id []byte) (*stored, error) {
	var r stored
	err := q.QueryRowContext(ctx, `SELECT id, lookup_tag, kind, version, nonce, wrapped_key, owner_sealed, ciphertext, updated_at FROM records WHERE id = ?`, id).
		Scan(&r.id, &r.tag, &r.kind, &r.version, &r.sealed.Nonce, &r.sealed.WrappedKey, &r.sealed.Owner, &r.sealed.Ciphertext, &r.updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &r, err
}

// errWriteChanged is the error of write verification: something between the
// store's statement and the end of the transaction changed what it wrote (a
// trigger, or a modified schema the allow-list should have caught). The
// transaction is rolled back.
func errWriteChanged(what string) error {
	return &VerifyError{Problems: []string{what + " does not read back as written; the transaction was rolled back (a trigger or another writer changed it)"}}
}

// verifyWrites re-reads every record row written, and every id deleted, and
// compares them byte for byte with what the store wrote. It runs before
// COMMIT.
func verifyWrites(ctx context.Context, q dbq, wrote []*stored, deleted [][]byte) error {
	for _, w := range wrote {
		got, err := readStored(ctx, q, w.id)
		if err != nil {
			return err
		}
		if got == nil || !got.equal(w) {
			return errWriteChanged("a record row")
		}
	}
	for _, id := range deleted {
		got, err := readStored(ctx, q, id)
		if err != nil {
			return err
		}
		if got != nil {
			return errWriteChanged("a record deletion")
		}
	}
	return nil
}

// apply writes every staged change and the audit row. It runs in the same SQL
// transaction as the reads of the Update, so nothing is changed unless all of
// it is. Before it returns (so before COMMIT) it reads back every row it
// wrote, the records and the audit row, and fails if any differs from what was
// written. It returns the new chain head, or nil when nothing was written.
func (t *txn) apply() (*Head, error) {
	var entries []touched
	var events [][]any
	var wrote []*stored
	var deleted [][]byte
	now := t.s.now().Unix()
	for _, ref := range t.order {
		o := t.ops[ref]
		tag, err := t.s.tag(ref)
		if err != nil {
			return nil, err
		}
		old, err := t.fetchTag(tag) // compared with the record map
		exists := err == nil
		if err != nil && !errors.Is(err, ports.ErrNotFound) {
			if errors.Is(err, errBadVersion) {
				err = &RefError{ref, fmt.Errorf("%w: bad version", ErrCorrupt)}
			}
			return nil, err
		}
		if o.del {
			if !exists {
				continue
			}
			res, err := t.q.ExecContext(t.ctx, `DELETE FROM records WHERE id = ? AND version = ?`, old.id, int64(old.version))
			if err != nil {
				return nil, mapErr(err)
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return nil, ports.ErrConflict
			}
			entries = append(entries, touched{ID: old.id, Version: old.version, Hash: []byte{}})
			deleted = append(deleted, old.id)
			events = append(events, []any{"delete", ref.String()})
			continue
		}
		var id []byte
		var version uint64 = 1
		if exists {
			id, version = old.id, old.version+1
		} else if id, err = seal.NewID(); err != nil {
			return nil, err
		}
		meta := seal.RecordMeta{WorkspaceID: t.s.ws, RecordID: id, Kind: string(ref.Kind), Owner: ownerOf(ref), Class: classOf(ref.Kind), Version: version}
		var sealed seal.SealedRecord
		if o.secret != nil {
			sealed, err = t.s.keys.SealSecret(meta, o.secret)
		} else {
			sealed, err = t.s.keys.SealRecord(meta, o.data)
		}
		if err != nil {
			return nil, &RefError{ref, err}
		}
		if exists {
			res, err := t.q.ExecContext(t.ctx, `UPDATE records SET version=?, nonce=?, wrapped_key=?, owner_sealed=?, ciphertext=?, updated_at=? WHERE id=? AND version=?`,
				int64(version), sealed.Nonce, sealed.WrappedKey, sealed.Owner, sealed.Ciphertext, now, id, int64(old.version))
			if err != nil {
				return nil, mapErr(err)
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return nil, ports.ErrConflict
			}
		} else if _, err := t.q.ExecContext(t.ctx, `INSERT INTO records (id, lookup_tag, kind, version, nonce, wrapped_key, owner_sealed, ciphertext, updated_at) VALUES (?,?,?,?,?,?,?,?,?)`,
			id, tag, meta.Kind, int64(version), sealed.Nonce, sealed.WrappedKey, sealed.Owner, sealed.Ciphertext, now); err != nil {
			return nil, mapErr(err)
		}
		wrote = append(wrote, &stored{id: id, tag: tag, kind: meta.Kind, version: int64(version), sealed: sealed, updatedAt: now})
		h, err := recordHash(meta.Kind, tag, sealed)
		if err != nil {
			return nil, err
		}
		entries = append(entries, touched{ID: id, Version: version, Hash: h})
		events = append(events, []any{"put", ref.String()})
	}
	if len(entries) == 0 {
		return nil, nil
	}
	prev, err := chainHead(t.ctx, t.q)
	if err != nil {
		return nil, err
	}
	head, err := appendAudit(t.ctx, t.q, t.s.ws, t.s.keys, auditUpdate, now, prev, events, entries, nil)
	if err != nil {
		return nil, err
	}
	if err := verifyWrites(t.ctx, t.q, wrote, deleted); err != nil {
		return nil, err
	}
	return head, nil
}

// auditID is the "record id" of an audit event payload: 8 zero bytes then the
// sequence number, big endian. Events are sealed like records so the same
// code path (and the same bindings) protect them.
func auditID(seq uint64) []byte {
	id := make([]byte, seal.IDSize)
	binary.BigEndian.PutUint64(id[8:], seq)
	return id
}

// eventMeta is the associated data input of the event of audit row seq: kind
// "audit.event", no owner, class sensitive, record id auditID(seq), version
// seq.
func eventMeta(ws []byte, seq uint64) seal.RecordMeta {
	return seal.RecordMeta{WorkspaceID: ws, RecordID: auditID(seq), Kind: eventKind, Owner: "", Class: seal.ClassSensitive, Version: seq}
}

var zeroMAC = make([]byte, seal.MACSize)

// auditRowBytes is the canonical CBOR the chain MAC covers:
// [format version, workspace id, seq, kind, at, sealed event, touched list (CBOR bytes), slotset].
func auditRowBytes(ws []byte, seq uint64, kind string, at int64, event, touchedRaw, slotset []byte) ([]byte, error) {
	return seal.EncodeCanonical([]any{seal.FormatVersion, ws, seq, kind, at, event, touchedRaw, slotset})
}

// eventBucket is the unit the plaintext of an audit event is padded to, so
// the stored length reveals the number of events only to the nearest 256
// bytes.
const eventBucket = 256

// padEvent frames an event payload: its length (4 bytes, big endian), the
// payload, zero padding up to a multiple of eventBucket.
func padEvent(b []byte) []byte {
	n := (4 + len(b) + eventBucket - 1) / eventBucket * eventBucket
	out := make([]byte, n)
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}

// unpadEvent is the inverse of padEvent. It refuses any other length, an
// impossible length field and non-zero padding.
func unpadEvent(b []byte) ([]byte, error) {
	if len(b) < 4 || len(b)%eventBucket != 0 {
		return nil, errors.New("event padding")
	}
	n := int(binary.BigEndian.Uint32(b))
	if n > len(b)-4 || len(padEvent(b[4:4+n])) != len(b) {
		return nil, errors.New("event padding")
	}
	for _, x := range b[4+n:] {
		if x != 0 {
			return nil, errors.New("event padding")
		}
	}
	return b[4 : 4+n], nil
}

// openEvent opens the sealed event of audit row seq into its list of events.
func openEvent(keys *seal.Keys, ws []byte, seq uint64, event []byte) ([][]any, error) {
	sealed, err := seal.ParseSealed(event)
	if err != nil {
		return nil, err
	}
	padded, err := keys.OpenRecord(eventMeta(ws, seq), sealed)
	if err != nil {
		return nil, err
	}
	pt, err := unpadEvent(padded)
	if err != nil {
		return nil, err
	}
	var events [][]any
	if err := cbor.Unmarshal(pt, &events); err != nil {
		return nil, err
	}
	return events, nil
}

// appendAudit adds the row after prev under keys and reads it back (it must be
// the newest row and equal what was written, else errWriteChanged). The event
// is the sealed, padded canonical CBOR of events, which carry event names and
// references only, nothing secret. slotset is the slot-set hash for 'slots'
// and 'rollover' rows and nil for 'update' rows.
func appendAudit(ctx context.Context, q dbq, ws []byte, keys *seal.Keys, kind string, now int64, prev Head, events [][]any, entries []touched, slotset []byte) (*Head, error) {
	seq := prev.Seq + 1
	evBytes, err := seal.EncodeCanonical(events)
	if err != nil {
		return nil, err
	}
	sealedEv, err := keys.SealRecord(eventMeta(ws, seq), padEvent(evBytes))
	if err != nil {
		return nil, err
	}
	if entries == nil {
		entries = []touched{}
	}
	if slotset == nil {
		slotset = []byte{}
	}
	touchedRaw, err := seal.EncodeCanonical(entries)
	if err != nil {
		return nil, err
	}
	event := sealedEv.Bytes()
	row, err := auditRowBytes(ws, seq, kind, now, event, touchedRaw, slotset)
	if err != nil {
		return nil, err
	}
	mac, err := keys.Audit.MAC(prev.MAC, row)
	if err != nil {
		return nil, err
	}
	if _, err := q.ExecContext(ctx, `INSERT INTO audit (seq, at, kind, event, touched, slotset, mac, prev_mac) VALUES (?,?,?,?,?,?,?,?)`,
		int64(seq), now, kind, event, touchedRaw, slotset, mac, prev.MAC); err != nil {
		return nil, mapErr(err)
	}
	// Read the newest row back: it must be the one just written, byte for byte.
	var got auditRow
	if err := q.QueryRowContext(ctx, `SELECT seq, at, kind, event, touched, slotset, mac, prev_mac FROM audit ORDER BY seq DESC LIMIT 1`).
		Scan(&got.seq, &got.at, &got.kind, &got.event, &got.touchedRaw, &got.slotset, &got.mac, &got.prev); err != nil {
		return nil, err
	}
	if got.seq != int64(seq) || got.at != now || got.kind != kind || !bytes.Equal(got.event, event) || !bytes.Equal(got.touchedRaw, touchedRaw) ||
		!bytes.Equal(got.slotset, slotset) || !bytes.Equal(got.mac, mac) || !bytes.Equal(got.prev, prev.MAC) {
		return nil, errWriteChanged("the audit row")
	}
	return &Head{Seq: seq, MAC: mac}, nil
}

// checkEpochNow is checkEpoch in a transaction of its own.
func (s *Store) checkEpochNow(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	return s.checkEpoch(ctx, tx)
}

// checkSchemaNow is the epoch and schema checks in a transaction of their own.
func (s *Store) checkSchemaNow(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.checkEpoch(ctx, tx); err != nil {
		return err
	}
	return checkSchema(ctx, tx, s.schemaV)
}

// checkEpoch returns ErrStaleHandle when the workspace's key epoch is not the
// one this handle unlocked. Every operation calls it first, inside its
// transaction, before it reads or writes anything else: a handle that
// survived another process's rekey (one that did not honour the file lock)
// holds revoked keys and must not write with them.
func (s *Store) checkEpoch(ctx context.Context, q dbq) error {
	var epoch []byte
	if err := q.QueryRowContext(ctx, `SELECT key_epoch FROM meta WHERE id = 1`).Scan(&epoch); err != nil {
		return err
	}
	if !bytes.Equal(epoch, s.epoch) {
		return ErrStaleHandle
	}
	return nil
}

// THE HANDLE'S RECORD MAP
//
// Open's verification and the audit chain catch a record rolled back to an
// older, authentic version when the workspace is opened. They would not catch
// one rolled back WHILE a handle is open (by a process that ignores the file
// lock): the handle's next read-modify-write would read the old version, write
// a new one on top of it, and the chain would record the result as genuine.
// So each handle keeps a map, record id to the (version, hash) the audit chain
// recorded last, together with the chain row it has verified up to
// (chainKnown). It is built by a full verification (at Open, by Verify, and
// lazily at first use when the handle was opened with SkipVerify; if that
// verification fails the operation returns its error) and is extended at the
// start of every transaction by catchUp:
//
//   - the chain row the handle last knew must still be in the file with the
//     same MAC;
//   - every row after it is checked as Verify checks rows (sequence, prev_mac,
//     MAC under the audit key, slot-set length, entry order), because another
//     well-behaved handle may have written them; its entries update the map.
//     A rollover row here would mean a rekey by another process, which the
//     key-epoch check has already refused;
//   - the number of record rows must equal the number of live entries in the
//     map (so a row deleted or injected behind the handle's back is noticed
//     without reading every record).
//
// Every record row a View, Update or Open then reads (fetchTag) is compared
// with the map: its version and recordHash must be the recorded ones, else the
// call returns an ErrVerify that names nothing. The map also holds the lookup
// tag of every live record (verification reads the tags; the audit entries do
// not carry them, so for a record the chain says was written since, extend reads
// the row by its id and requires its hash to be the recorded one): a lookup
// that finds no row for a tag the map lists, or a row under another id, is the
// same ErrVerify, not "not found". Without it a record deleted behind the
// handle's back, with one junk row inserted so the row count still balances,
// would read as absent and a Put would create it again. The handle's own commits are
// not applied to the map directly: the next transaction's catchUp reads them
// back from the chain like anybody else's (one MAC check per row), which makes
// them the same code path. A Rekey drops the map (the chain starts a new
// segment under new keys) and the next use rebuilds it with a full
// verification.
//
// COST. Per transaction: one lookup of the known row, one query for newer
// rows, one count of the records table, plus one MAC and one CBOR decode per
// new audit row. A full verification is a read of every audit and record row
// plus SQLite's integrity check, and happens once per handle (twice after a
// Rekey). Nothing here is tuned: a few thousand records take well under a
// second.
//
// WHAT IT DOES NOT COVER. A row that is replaced by a different authentic
// version of itself and put back before the handle next reads it is
// indistinguishable from no change. A record that is swapped for another id
// that the chain also lists is caught when it is read, not at the count. An
// attacker who rewrites the chain itself needs the audit key.

// catchUp brings the record map up to date as described above. It runs inside
// the transaction, after the key-epoch check, with the gate held.
func (s *Store) catchUp(ctx context.Context, q dbq) error {
	if s.known == nil {
		_, _, k, err := s.verify(ctx, q, false)
		if err != nil {
			return err
		}
		s.known = k
		return nil // verify read this transaction's snapshot: the map is current
	}
	if err := s.extend(ctx, q); err != nil {
		s.known = nil // half-updated: rebuilt by a full verification next time
		return err
	}
	return nil
}

func (s *Store) extend(ctx context.Context, q dbq) error {
	k := s.known
	changed := func(why string) error {
		return &VerifyError{Problems: []string{"the audit chain " + why + " while the workspace was open"}}
	}
	if ok, err := chainContains(ctx, q, k.head); err != nil {
		return err
	} else if !ok {
		return changed("no longer contains the row this handle last verified (the file was rolled back or rewritten)")
	}
	rows, err := q.QueryContext(ctx, `SELECT seq, at, kind, event, touched, slotset, mac, prev_mac FROM audit WHERE seq > ? ORDER BY seq`, int64(k.head.Seq))
	if err != nil {
		return err
	}
	var fresh []auditRow
	for rows.Next() {
		var r auditRow
		if err := rows.Scan(&r.seq, &r.at, &r.kind, &r.event, &r.touchedRaw, &r.slotset, &r.mac, &r.prev); err != nil {
			rows.Close()
			return err
		}
		fresh = append(fresh, r)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}
	prev := k.head
	touchedIDs := map[string]bool{}
	for _, r := range fresh {
		if uint64(r.seq) != prev.Seq+1 || !bytes.Equal(r.prev, prev.MAC) {
			return changed("has a row out of sequence")
		}
		if r.kind == auditRollover {
			return changed("has a rollover row that no rekey of this handle wrote")
		}
		if (r.kind == auditUpdate) != (len(r.slotset) == 0) || r.kind == auditSlots && len(r.slotset) != sha256.Size {
			return changed("has a row with a slot-set hash of the wrong length")
		}
		rowBytes, err := auditRowBytes(s.ws, uint64(r.seq), r.kind, r.at, r.event, r.touchedRaw, r.slotset)
		if err != nil {
			return err
		}
		if ok, err := s.keys.Audit.Check(r.prev, rowBytes, r.mac); err != nil {
			return err
		} else if !ok {
			return changed("has a row whose MAC does not verify")
		}
		var entries []touched
		if err := cbor.Unmarshal(r.touchedRaw, &entries); err != nil {
			return changed("has an unreadable touched list")
		}
		for _, e := range entries {
			if why := noteEntry(k.recs, e); why != "" {
				return changed("has an inconsistent record history (" + why + ")")
			}
			touchedIDs[string(e.ID)] = true
		}
		prev = Head{Seq: uint64(r.seq), MAC: r.mac}
	}
	k.head = prev
	for id := range touchedIDs {
		if err := k.bindTag(ctx, q, id); err != nil {
			return err
		}
	}
	live := 0
	for _, st := range k.recs {
		if !st.deleted {
			live++
		}
	}
	var n int
	if err := q.QueryRowContext(ctx, `SELECT count(*) FROM records`).Scan(&n); err != nil {
		return err
	}
	if n != live {
		return changed("lists " + strconv.Itoa(live) + " records but the file holds another number of rows")
	}
	return nil
}

// ErrOutcomeUnknown: a COMMIT returned an error and the store could not read
// the file back to find out whether it took effect. Open the workspace again and
// look before repeating the operation. Rekey, ChangePassphraseRekey and
// AddRecoverySlot return it together with the new recovery key text, which is
// valid only if the change took effect.
var ErrOutcomeUnknown = errors.New("sqlitestore: a commit returned an error and whether it took effect could not be determined; check the workspace before repeating the operation")

// afterWriteConnect is a test hook: called with a write connection after it has
// been opened, before its transaction begins.
var afterWriteConnect func(*sql.Conn)

// execCommit runs COMMIT. (A variable so a test can make it report an error for
// a commit that happened.)
var execCommit = func(ctx context.Context, conn *sql.Conn) error {
	_, err := conn.ExecContext(ctx, "COMMIT")
	return err
}

// writeConn opens a connection of its own for one write transaction (see
// CONCURRENCY). It refuses a path that no longer names the file this handle
// has locked. The caller closes it with the returned function.
func (s *Store) writeConn(ctx context.Context) (*sql.Conn, func(), error) {
	if err := s.samePath(); err != nil {
		return nil, nil, err
	}
	db, err := openDB(s.path, false, false)
	if err != nil {
		return nil, nil, err
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		db.Close()
		return nil, nil, err
	}
	if afterWriteConnect != nil {
		afterWriteConnect(conn)
	}
	if err := s.samePath(); err != nil { // the connection opened what the path named a moment ago
		conn.Close()
		db.Close()
		return nil, nil, err
	}
	return conn, func() { conn.Close(); db.Close() }, nil
}

// samePath refuses a path that names another file than the one this handle has
// open and locked (the file was replaced behind the handle's back).
func (s *Store) samePath() error {
	a, err := os.Stat(s.path)
	b, err2 := s.lock.Stat()
	if err != nil || err2 != nil || !os.SameFile(a, b) {
		return &VerifyError{Problems: []string{"the path no longer names the workspace file this handle opened (it was replaced); nothing was done"}}
	}
	return nil
}

// checkWriteSnapshot is the first thing a write transaction does, right after
// BEGIN IMMEDIATE, on the connection that goes on to write: it makes SQLite
// parse the schema again from the file (PRAGMA writable_schema=RESET; the
// connection parsed it while connecting, before it held the write lock), then
// checks the key epoch and compares the schema text with the allow-list. Under
// the write lock nothing can change between these and the statements that
// follow, so the schema checked is the schema executed.
func (s *Store) checkWriteSnapshot(ctx context.Context, q dbq) error {
	if _, err := q.ExecContext(ctx, `PRAGMA writable_schema=RESET`); err != nil {
		return err
	}
	if err := s.checkEpoch(ctx, q); err != nil {
		return err
	}
	return checkSchema(ctx, q, s.schemaV)
}

// withWriteTx runs body inside BEGIN IMMEDIATE ... COMMIT on a connection of its
// own, so a concurrent writer waits for the busy timeout and then fails with
// ports.ErrConflict, instead of failing later on a lock upgrade. When body
// returns a new chain head it is recorded in the head file after the commit.
// committed reports whether the transaction committed (a failure to advance the
// head file after it is a notice, not an error). The caller holds the gate.
//
// The caller's context ends the transaction only before COMMIT starts (ENDING A
// WRITE, in the package comment). If COMMIT reports an error, confirm (or, when
// it is nil, whether the chain holds the row body returned the head of) says
// whether the transaction took effect.
func (s *Store) withWriteTx(ctx context.Context, body func(q dbq) (*Head, error), confirm func(context.Context, dbq) (bool, error)) (committed bool, err error) {
	return s.withWriteTxMode(ctx, false, body, confirm)
}

// withWriteTxMode is withWriteTx. With strict set (a Rekey, whose new recovery
// key exists nowhere else), any COMMIT error other than a plain busy or locked
// one (SQLite primary codes 5 and 6) is ErrOutcomeUnknown whatever a read-back
// shows: a COMMIT that failed on fsync may have left its frame in the WAL,
// where a crash can make it take effect.
func (s *Store) withWriteTxMode(ctx context.Context, strict bool, body func(q dbq) (*Head, error), confirm func(context.Context, dbq) (bool, error)) (committed bool, err error) {
	conn, closeConn, err := s.writeConn(ctx)
	if err != nil {
		return false, err
	}
	defer closeConn()
	nc := context.WithoutCancel(ctx)
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return false, mapErr(err)
	}
	defer func() {
		if !committed {
			conn.ExecContext(nc, "ROLLBACK")
		}
	}()
	if err := s.checkWriteSnapshot(ctx, conn); err != nil {
		return false, err
	}
	head, err := body(conn)
	if err != nil {
		return false, mapErr(err)
	}
	// The point of no return: until here the context cancels the transaction.
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if cerr := execCommit(nc, conn); cerr != nil {
		// Nothing about this connection can be trusted (a COMMIT that failed may
		// have left its transaction open, which would show our own writes): close
		// it and read the file back on a new one.
		closeConn()
		if strict && !busyOrLocked(cerr) {
			return false, fmt.Errorf("%w (commit: %v)", ErrOutcomeUnknown, cerr)
		}
		took, derr := s.readBack(nc, head, confirm)
		if derr != nil {
			return false, fmt.Errorf("%w (commit: %v; reading the file back: %v)", ErrOutcomeUnknown, cerr, derr)
		}
		if !took {
			return false, mapErr(cerr)
		}
		s.notice("a commit reported an error (" + cerr.Error() + ") but the file shows it took effect; it was treated as committed")
	}
	committed = true
	if head != nil {
		s.setHead(*head)
		if err := advanceHeadFile(s.path, s.ws, *head); err != nil {
			// The next open accepts a file that is ahead of its head file and advances it.
			s.notice("the change is committed but the head file could not be written: " + err.Error())
		}
	}
	return true, nil
}

// readBack says whether a transaction whose COMMIT reported an error took
// effect, on a connection of its own.
func (s *Store) readBack(ctx context.Context, head *Head, confirm func(context.Context, dbq) (bool, error)) (bool, error) {
	db, err := openDB(s.path, true, false)
	if err != nil {
		return false, err
	}
	defer db.Close()
	switch {
	case confirm != nil:
		return confirm(ctx, db)
	case head != nil:
		return chainContains(ctx, db, *head)
	}
	return false, nil
}

// View implements ports.Store: reads at one consistent snapshot.
func (s *Store) View(ctx context.Context, fn func(ports.Reader) error) error {
	release, err := s.enter(ctx)
	if err != nil {
		return err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.checkEpoch(ctx, tx); err != nil {
		return err
	}
	if err := s.catchUp(ctx, tx); err != nil {
		return err
	}
	t := &txn{s: s, ctx: ctx, q: tx, ops: map[ports.Ref]*op{}}
	return fn(t)
}

// Update implements ports.Store. It begins with BEGIN IMMEDIATE, so reads see
// the latest committed state plus this update's own writes, and no other
// writer can commit meanwhile. All writes, and one audit row for them, are
// applied in a single SQL transaction after fn returns nil; if fn fails
// nothing is written. A second writer on the same file waits up to the busy
// timeout, then fails with ports.ErrConflict.
func (s *Store) Update(ctx context.Context, fn func(ports.Writer) error) error {
	if err := s.writable(); err != nil {
		return err
	}
	release, err := s.enter(ctx)
	if err != nil {
		return err
	}
	defer release()
	_, err = s.withWriteTx(ctx, func(q dbq) (*Head, error) {
		if err := s.catchUp(ctx, q); err != nil {
			return nil, err
		}
		t := &txn{s: s, ctx: ctx, q: q, writable: true, ops: map[ports.Ref]*op{}}
		defer t.discard()
		if err := fn(t); err != nil {
			return nil, err
		}
		return t.apply()
	}, nil)
	return err
}

// Open implements ports.Vault: it returns the secret in guarded memory.
func (s *Store) Open(ctx context.Context, ref ports.Ref) (*secret.Buffer, error) {
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
	if err := s.catchUp(ctx, tx); err != nil {
		return nil, err
	}
	t := &txn{s: s, ctx: ctx, q: tx, ops: map[ports.Ref]*op{}}
	return t.OpenSecret(ref)
}

// portsKindSecret reports whether a stored kind name is a secret kind.
func portsKindSecret(kind string) bool { return ports.Kind(kind).Secret() }
