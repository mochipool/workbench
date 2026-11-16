package sqlitestore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// KEY SLOTS AND REKEYING
//
// Adding a slot needs no rekey: the master key is wrapped once more, nothing
// else changes. Removing or replacing a slot is different. A slot row is a
// wrapped copy of the master key; whoever kept a copy of the file, or finds
// the deleted row in a backup or in free pages, can put it back and unlock
// everything with the old credential, including records written later,
// because the master key never changed. Removing a slot therefore revokes
// nothing unless the master key is replaced as well. That is what Rekey does,
// and removal and passphrase change are Rekey.
//
// Rekey needs every slot it keeps to be rewritten under the new master key,
// which needs that slot's credential. The store holds none (it holds the
// master key, not the passphrase), so a rekey keeps exactly the credentials
// the caller supplies, and the result always has one passphrase slot (for the
// supplied passphrase) and one new recovery slot (its key is returned, to be
// shown once). Any other slot is dropped; add further slots again afterwards
// with AddPassphraseSlot or AddRecoverySlot.
//
// WHAT A REKEY DOES AND DOES NOT REVOKE. A rekey draws a new master key and
// so new record-wrapping, index and audit keys, and re-wraps every record's
// data key under the new record-wrapping key. It does NOT rotate the data
// keys, and it does not re-encrypt payloads: the payload ciphertexts are
// byte for byte what they were. It therefore revokes access to the file as it
// is after the rekey: an old passphrase or recovery key, even with its old
// slot row put back, unlocks a master key that opens nothing sealed after the
// rekey (the key epoch no longer matches, and the new wrapped data keys are
// under keys it cannot derive). It does not revoke anything that existed
// before: anyone who holds an OLD COPY of the file (a backup, a stolen copy,
// free pages not yet overwritten) together with an OLD credential keeps
// everything the workspace held at the time of that copy, because the old
// master key opens the old wrapped data keys, and these open the unchanged
// payloads. To make old copies useless, the secrets themselves must change
// (new KES keys, new payment keys). After a committed rekey the old wrapped
// keys are removed from this file and its WAL by VACUUM and a WAL truncate
// (secure_delete is on); on a copy-on-write filesystem or an SSD, earlier
// blocks may survive outside the program's reach.
//
// A rekey needs every other handle of the workspace closed (it takes the file
// lock exclusively and returns ErrLocked otherwise), and it refuses to run on
// a workspace that does not verify (Verify, under the old keys, runs first
// inside the same transaction): a rekey must not launder tampering into the
// new audit segment.

// Credential is a secret that unlocks a slot, for Rekey.
type Credential struct {
	Kind   string         // seal.SlotPassphrase
	Secret *secret.Buffer // the passphrase text
}

// PassphraseCredential is the credential of a passphrase slot.
func PassphraseCredential(p *secret.Buffer) Credential {
	return Credential{Kind: seal.SlotPassphrase, Secret: p}
}

// checkSlots enforces M5: at least one passphrase slot and one recovery slot.
func checkSlots(ctx context.Context, q dbq) error {
	for _, kind := range []string{seal.SlotPassphrase, seal.SlotRecovery} {
		var n int
		if err := q.QueryRowContext(ctx, `SELECT count(*) FROM keyslots WHERE kind = ?`, kind).Scan(&n); err != nil {
			return err
		}
		if n < 1 {
			return ErrLastSlot
		}
	}
	return nil
}

// addSlot inserts slot and an audit row naming the event, in one transaction.
// The row records the new slot-set hash.
func (s *Store) addSlot(ctx context.Context, slot seal.Slot) error {
	_, err := s.withWriteTx(ctx, func(q dbq) (*Head, error) {
		if err := insertSlot(ctx, q, slot); err != nil {
			return nil, err
		}
		if err := checkSlots(ctx, q); err != nil {
			return nil, err
		}
		set, err := slotSetHash(ctx, q)
		if err != nil {
			return nil, err
		}
		prev, err := chainHead(ctx, q)
		if err != nil {
			return nil, err
		}
		head, err := appendAudit(ctx, q, s.ws, s.keys, auditSlots, s.now().Unix(), prev, [][]any{{"slot-added", slot.Kind}}, nil, set)
		if err != nil {
			return nil, err
		}
		if err := verifySlotRows(ctx, q, []seal.Slot{slot}); err != nil {
			return nil, err
		}
		return head, nil
	})
	return err
}

// verifySlotRows re-reads the key slot rows of want and compares them with what
// was written, field by field (before COMMIT).
func verifySlotRows(ctx context.Context, q dbq, want []seal.Slot) error {
	have, err := loadSlots(ctx, q)
	if err != nil {
		return err
	}
	for _, w := range want {
		found := false
		for _, h := range have {
			if bytes.Equal(h.ID, w.ID) {
				found = slotEqual(h, w)
			}
		}
		if !found {
			return errWriteChanged("a key slot row")
		}
	}
	return nil
}

// slotEqual compares the columns insertSlot stores. The KDF parameters and the
// salt exist for passphrase slots only.
func slotEqual(a, b seal.Slot) bool {
	if a.Kind != b.Kind || !bytes.Equal(a.Commit, b.Commit) || !bytes.Equal(a.Nonce, b.Nonce) || !bytes.Equal(a.Wrapped, b.Wrapped) {
		return false
	}
	return a.Kind != seal.SlotPassphrase || a.KDF == b.KDF && bytes.Equal(a.Salt, b.Salt)
}

// slotSetHash is SHA-256 of the canonical CBOR of every keyslots row, sorted
// by id, each row an array of all nine columns in table order (NULL as CBOR
// null). A 'slots' or 'rollover' audit row records it, so that Verify notices
// a slot row that was edited, added or removed behind the store's back.
func slotSetHash(ctx context.Context, q dbq) ([]byte, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, kind, kdf_memory_kib, kdf_passes, kdf_lanes, salt, key_commit, nonce, wrapped_key FROM keyslots ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var all [][]any
	for rows.Next() {
		row := make([]any, 9)
		ptr := make([]any, 9)
		for i := range row {
			ptr[i] = &row[i]
		}
		if err := rows.Scan(ptr...); err != nil {
			return nil, err
		}
		all = append(all, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return hashSlotRows(all)
}

// hashSlotRows is the hash slotSetHash takes over the rows it read.
func hashSlotRows(all [][]any) ([]byte, error) {
	b, err := seal.EncodeCanonical(all)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(b)
	return h[:], nil
}

// AddPassphraseSlot adds another passphrase that unlocks the workspace and
// returns the new slot id. It does not change the master key, so it needs no
// rekey (but removing the slot later does).
func (s *Store) AddPassphraseSlot(ctx context.Context, passphrase *secret.Buffer) ([]byte, error) {
	if err := s.writable(); err != nil {
		return nil, err
	}
	release, err := s.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	id, err := seal.NewID()
	if err != nil {
		return nil, err
	}
	slot, err := seal.NewPassphraseSlot(s.ws, id, s.master, passphrase, kdfForNewSlots)
	if err != nil {
		return nil, err
	}
	return id, s.addSlot(ctx, slot)
}

// AddRecoverySlot adds a new recovery key and returns it as printable text.
// It does not change the master key, so it needs no rekey. The older recovery
// keys keep working until a Rekey.
func (s *Store) AddRecoverySlot(ctx context.Context) (text *secret.Buffer, slotID []byte, err error) {
	if err := s.writable(); err != nil {
		return nil, nil, err
	}
	release, err := s.enter(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer release()
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
	if err := s.addSlot(ctx, slot); err != nil {
		text.Destroy()
		return nil, nil, err
	}
	return text, id, nil
}

// RemoveSlot always fails with ErrUseRekey: deleting a slot row revokes
// nothing while the master key stays the same (see the note above). Use
// Rekey, supplying the passphrase to keep.
func (s *Store) RemoveSlot(ctx context.Context, id []byte) error { return ErrUseRekey }

// ChangePassphrase always fails with ErrUseRekey: replacing a passphrase slot
// revokes the old passphrase only if the master key changes, and a rekey also
// makes a new recovery key, which this signature cannot return. Use
// ChangePassphraseRekey.
func (s *Store) ChangePassphrase(ctx context.Context, slotID []byte, newPassphrase *secret.Buffer) ([]byte, error) {
	return nil, ErrUseRekey
}

// ChangePassphraseRekey changes the passphrase by a Rekey with the new
// passphrase as the only credential. It returns the new recovery key as text.
func (s *Store) ChangePassphraseRekey(ctx context.Context, newPassphrase *secret.Buffer) (*secret.Buffer, error) {
	return s.Rekey(ctx, []Credential{PassphraseCredential(newPassphrase)})
}

// Rekey replaces the master key. It
//
//   - checks, inside the transaction and under the OLD keys, that the
//     workspace verifies (audit chain, record hashes, slot set, key epoch,
//     head file, database integrity) and refuses with that error when it does
//     not;
//   - generates a new master key and from it new record-wrapping, index and
//     audit keys, and a new key epoch;
//   - re-wraps every record's data key under the new record-wrapping key
//     (payload ciphertexts stay as they are) and recomputes every lookup tag
//     under the new index key;
//   - replaces ALL key slots with one passphrase slot for the single
//     passphrase credential in keep and one new recovery slot;
//   - starts a new audit segment: a "rollover" row, sealed and MAC'd under
//     the new keys, that records the old chain's final (sequence, MAC), a
//     SHA-256 over every old audit row (history) and the new slot-set hash,
//     and lists every record. Verify checks the chain from that row on, and
//     recomputes the history hash over the rows before it; the old rows' own
//     MACs cannot be checked any more (the old audit key cannot be derived
//     from the new master);
//
// all in one SQL transaction. It needs every other handle of the workspace
// closed: it upgrades its file lock to exclusive without waiting and returns
// ErrLocked while any other handle, in this process or another, holds the
// file.
//
// Before COMMIT it reads back every key slot row, every record row, the audit
// row and the meta row and compares them byte for byte with what it wrote; a
// difference (a trigger, or another writer) aborts the transaction with
// ErrVerify and nothing changes.
//
// Once the transaction has COMMITTED, Rekey advances the head file and returns
// the new recovery key as printable text, to show once, with a nil error,
// whatever happens next: the previous recovery keys no longer work and the new
// one exists nowhere else. It does NOT run the cleanup that removes the old
// wrapped keys from the file (VACUUM) and the WAL (a truncating checkpoint):
// those take time, and the key must reach the operator first. The commit sets
// meta.cleanup_pending, and the caller calls Cleanup as soon as the key has
// been shown and saved. Until then, and if the process dies before that, the old
// wrapped keys are still in free pages and in the WAL; every Open and Close
// retries the cleanup while the flag is set. A failure to advance the head
// file after the commit is a notice.
func (s *Store) Rekey(ctx context.Context, keep []Credential) (newRecovery *secret.Buffer, err error) {
	if err := s.writable(); err != nil {
		return nil, err
	}
	if len(keep) != 1 || keep[0].Kind != seal.SlotPassphrase || keep[0].Secret.Len() == 0 {
		return nil, ErrRekeyCredentials
	}
	// The key derivation (Argon2id) needs nothing of the handle: do it before
	// taking the gate.
	master, err := seal.NewMasterKey()
	if err != nil {
		return nil, err
	}
	keys, err := seal.DeriveKeys(master)
	if err != nil {
		master.Destroy()
		return nil, err
	}
	swapped := false
	defer func() {
		if !swapped {
			keys.Destroy()
			master.Destroy()
		}
	}()
	epoch, err := seal.NewEpoch()
	if err != nil {
		return nil, err
	}
	epochMAC, err := keys.Audit.EpochMAC(s.ws, epoch)
	if err != nil {
		return nil, err
	}
	pslot, rslot, text, err := newSlots(s.ws, master, keep[0].Secret)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			text.Destroy()
		}
	}()

	release, err := s.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if err := s.checkEpochNow(ctx); err != nil { // before touching the lock: a stale handle's lock may be gone
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
			s.notice("the file lock could not be taken back to shared after the rekey, so this handle refuses every further operation: " + derr.Error())
		}
	}()

	committed, err := s.withWriteTx(ctx, func(q dbq) (*Head, error) {
		return s.rekeyBody(ctx, q, keys, epoch, epochMAC, pslot, rslot)
	})
	if !committed {
		return nil, err
	}
	// From here on the rekey is done and the old keys match nothing in the
	// file. Nothing below may fail the call.
	s.keys.Destroy()
	s.master.Destroy()
	s.master, s.keys, s.slotID, s.epoch, swapped = master, keys, pslot.ID, epoch, true
	s.known = nil // the chain has a new segment under new keys: rebuilt at the next use
	if err != nil {
		s.notice("the rekey is committed but the head file could not be written: " + err.Error())
	}
	return text, nil
}

// downgradeFile is downgradeLock; a test replaces it.
var downgradeFile = downgradeLock

// loseLock marks the handle as having lost its file lock (ErrLockLost).
func (s *Store) loseLock() {
	s.mu.Lock()
	s.lockLost = true
	s.mu.Unlock()
}

// Cleanup finishes a rekey: it removes the old wrapped keys from the file's
// free pages (VACUUM) and from the WAL (a truncating checkpoint) and clears
// meta.cleanup_pending. Rekey leaves it to the caller so that the new
// recovery key is in the operator's hands first. It does nothing, and returns
// nil, when no cleanup is pending. On failure it returns the error and the
// flag stays set; Open and Close retry it (their failures are notices).
func (s *Store) Cleanup(ctx context.Context) error {
	if err := s.writable(); err != nil {
		return err
	}
	release, err := s.enter(ctx)
	if err != nil {
		return err
	}
	defer release()
	var pending int
	if err := s.db.QueryRowContext(ctx, `SELECT cleanup_pending FROM meta WHERE id = 1`).Scan(&pending); err != nil {
		return err
	}
	if pending == 0 {
		return nil
	}
	return s.cleanup(ctx)
}

// cleanup removes the old wrapped keys that a rekey left in free pages and in
// the WAL, and then clears meta.cleanup_pending. VACUUM rewrites the database
// (freed pages are zeroed by secure_delete); the checkpoint folds the WAL into
// it and truncates the WAL file, which fails (busy) while another connection
// holds a read snapshot. The flag is cleared only when both succeeded.
func (s *Store) cleanup(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `VACUUM`); err != nil {
		return fmt.Errorf("vacuum: %w", err)
	}
	var busy, logFrames, ckpt int
	if err := s.db.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &ckpt); err != nil {
		return fmt.Errorf("WAL checkpoint: %w", err)
	}
	if busy != 0 {
		return errors.New("WAL checkpoint: another connection holds the database busy")
	}
	_, err := s.db.ExecContext(ctx, `UPDATE meta SET cleanup_pending = 0`)
	return err
}

// retryCleanup runs cleanup when a rekey's cleanup is still pending, and
// reports a failure as a notice.
func (s *Store) retryCleanup(ctx context.Context) {
	var pending int
	if err := s.db.QueryRowContext(ctx, `SELECT cleanup_pending FROM meta WHERE id = 1`).Scan(&pending); err != nil || pending == 0 {
		return
	}
	if err := s.cleanup(ctx); err != nil {
		s.notice("cleaning the old keys out of the file after a rekey is still pending: " + err.Error())
	}
}

type oldRow struct {
	id        []byte
	kind      string
	version   uint64
	sealed    seal.SealedRecord
	updatedAt int64
}

// historyHash is SHA-256 of the canonical CBOR of every audit row, in order,
// as [seq, at, kind, event, touched, slotset, mac, prev_mac]. A rollover row
// seals it, so the rows before the rollover (whose MACs the new keys cannot
// check) cannot change afterwards without Verify noticing. Each rollover
// covers every row before it, including earlier rollover rows and the hashes
// they sealed, so checking the newest rollover covers all earlier segments.
func historyHash(chain []auditRow) ([]byte, error) {
	rows := make([][]any, 0, len(chain))
	for _, r := range chain {
		rows = append(rows, []any{r.seq, r.at, r.kind, r.event, r.touchedRaw, r.slotset, r.mac, r.prev})
	}
	b, err := seal.EncodeCanonical(rows)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(b)
	return h[:], nil
}

// rekeyBody does the database work of Rekey inside the transaction.
func (s *Store) rekeyBody(ctx context.Context, q dbq, keys *seal.Keys, epoch, epochMAC []byte, pslot, rslot seal.Slot) (*Head, error) {
	// Verify first, under the old keys, so that a rekey cannot launder a
	// rolled-back record or a modified chain into the new segment.
	_, chain, _, err := s.verify(ctx, q, true)
	if err != nil {
		return nil, fmt.Errorf("sqlitestore: rekey refused, nothing was changed: %w", err)
	}
	history, err := historyHash(chain)
	if err != nil {
		return nil, err
	}
	rows, err := q.QueryContext(ctx, `SELECT id, kind, version, nonce, wrapped_key, owner_sealed, ciphertext, updated_at FROM records ORDER BY id`)
	if err != nil {
		return nil, err
	}
	var all []oldRow
	for rows.Next() {
		var r oldRow
		var v int64
		if err := rows.Scan(&r.id, &r.kind, &v, &r.sealed.Nonce, &r.sealed.WrappedKey, &r.sealed.Owner, &r.sealed.Ciphertext, &r.updatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		r.version = uint64(v)
		all = append(all, r)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var entries []touched
	var wrote []*stored
	for _, r := range all {
		owner, err := s.keys.OpenOwner(s.ws, r.id, r.kind, r.sealed)
		if err != nil {
			return nil, fmt.Errorf("%w: a record's owner blob does not open (%v); nothing was changed", ErrCorrupt, err)
		}
		name, num, err := parseOwner(owner)
		if err != nil {
			return nil, err
		}
		tag, err := tagFor(keys, name, r.kind, num)
		if err != nil {
			return nil, err
		}
		class := seal.ClassSensitive
		if portsKindSecret(r.kind) {
			class = seal.ClassSecret
		}
		meta := seal.RecordMeta{WorkspaceID: s.ws, RecordID: r.id, Kind: r.kind, Owner: owner, Class: class, Version: r.version}
		re, err := s.keys.Rewrap(keys, meta, r.sealed)
		if err != nil {
			return nil, fmt.Errorf("%w: a record does not rewrap (%v); nothing was changed", ErrCorrupt, err)
		}
		res, err := q.ExecContext(ctx, `UPDATE records SET lookup_tag=?, wrapped_key=?, owner_sealed=? WHERE id=? AND version=?`,
			tag, re.WrappedKey, re.Owner, r.id, int64(r.version))
		if err != nil {
			return nil, err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return nil, errors.New("sqlitestore: a record changed during the rekey")
		}
		h, err := recordHash(r.kind, tag, re)
		if err != nil {
			return nil, err
		}
		entries = append(entries, touched{ID: r.id, Version: r.version, Hash: h})
		wrote = append(wrote, &stored{id: r.id, tag: tag, kind: r.kind, version: int64(r.version), sealed: re, updatedAt: r.updatedAt})
	}
	if _, err := q.ExecContext(ctx, `DELETE FROM keyslots`); err != nil {
		return nil, err
	}
	for _, sl := range []seal.Slot{pslot, rslot} {
		if err := insertSlot(ctx, q, sl); err != nil {
			return nil, err
		}
	}
	if err := checkSlots(ctx, q); err != nil {
		return nil, err
	}
	if _, err := q.ExecContext(ctx, `UPDATE meta SET key_epoch = ?, epoch_mac = ?, cleanup_pending = 1`, epoch, epochMAC); err != nil {
		return nil, err
	}
	set, err := slotSetHash(ctx, q)
	if err != nil {
		return nil, err
	}
	prev, err := chainHead(ctx, q)
	if err != nil {
		return nil, err
	}
	events := [][]any{{"rollover", prev.Seq, prev.MAC, history}}
	head, err := appendAudit(ctx, q, s.ws, keys, auditRollover, s.now().Unix(), prev, events, entries, set)
	if err != nil {
		return nil, err
	}
	// Read everything back before COMMIT: a trigger, or any change behind the
	// store's back, must abort the rekey, not turn it into a loss.
	if err := verifyRekeyWrites(ctx, q, wrote, []seal.Slot{pslot, rslot}, s.ws, epoch, epochMAC); err != nil {
		return nil, err
	}
	return head, nil
}

// verifyRekeyWrites compares the rows a rekey wrote with what is in the
// transaction now: every record row (and that there are no others), exactly the
// two new key slot rows, and the meta row.
func verifyRekeyWrites(ctx context.Context, q dbq, wrote []*stored, slots []seal.Slot, ws, epoch, epochMAC []byte) error {
	if err := verifyWrites(ctx, q, wrote, nil); err != nil {
		return err
	}
	var n int
	if err := q.QueryRowContext(ctx, `SELECT count(*) FROM records`).Scan(&n); err != nil {
		return err
	}
	if n != len(wrote) {
		return errWriteChanged("the set of record rows")
	}
	have, err := loadSlots(ctx, q)
	if err != nil {
		return err
	}
	if len(have) != len(slots) {
		return errWriteChanged("the set of key slot rows")
	}
	if err := verifySlotRows(ctx, q, slots); err != nil {
		return err
	}
	var (
		gotWS, gotEpoch, gotMAC []byte
		format, pending, rows   int
	)
	if err := q.QueryRowContext(ctx, `SELECT count(*) FROM meta`).Scan(&rows); err != nil {
		return err
	}
	if err := q.QueryRowContext(ctx, `SELECT workspace_id, format_version, key_epoch, epoch_mac, cleanup_pending FROM meta WHERE id = 1`).
		Scan(&gotWS, &format, &gotEpoch, &gotMAC, &pending); err != nil {
		return err
	}
	if rows != 1 || !bytes.Equal(gotWS, ws) || format != seal.FormatVersion || !bytes.Equal(gotEpoch, epoch) || !bytes.Equal(gotMAC, epochMAC) || pending != 1 {
		return errWriteChanged("the meta row")
	}
	return nil
}
