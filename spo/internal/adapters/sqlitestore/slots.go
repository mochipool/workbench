package sqlitestore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/unlock"
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

// checkTable loads the slot table with its policy inside the transaction and
// runs domain/unlock on it: the one function slot add, rekey and the opener use.
func checkTable(ctx context.Context, q dbq) (*table, error) {
	m, err := loadMeta(ctx, q)
	if err != nil {
		return nil, err
	}
	t, err := loadTable(ctx, q, m.ws, uint64(m.format))
	if err != nil {
		return nil, err
	}
	return t, t.check()
}

// addSlot inserts slot and an audit row naming the event, in one transaction.
// The row records the new slot-set hash. The table is checked against its policy
// after the insertion and before the commit.
func (s *Store) addSlot(ctx context.Context, slot tslot, event string) error {
	_, err := s.withWriteTx(ctx, func(q dbq) (*Head, error) {
		if err := insertTSlot(ctx, q, slot); err != nil {
			return nil, err
		}
		if _, err := checkTable(ctx, q); err != nil {
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
		head, err := appendAudit(ctx, q, s.ws, s.keys, auditSlots, s.now().Unix(), prev, [][]any{{event, slot.kind}}, nil, set)
		if err != nil {
			return nil, err
		}
		if err := verifySlotRows(ctx, q, []tslot{slot}); err != nil {
			return nil, err
		}
		return head, nil
	}, nil)
	return err
}

// verifySlotRows re-reads the key slot rows of want and compares them with what
// was written, field by field (before COMMIT).
func verifySlotRows(ctx context.Context, q dbq, want []tslot) error {
	m, err := loadMeta(ctx, q)
	if err != nil {
		return err
	}
	t, err := loadTable(ctx, q, m.ws, uint64(m.format))
	if err != nil {
		return err
	}
	for _, w := range want {
		found := false
		for _, h := range t.slots {
			if bytes.Equal(h.id, w.id) {
				found = tslotEqual(h, w)
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
	if v3, err := hasColumn(ctx, q, "keyslots", "factors"); err != nil {
		return nil, err
	} else if v3 {
		return tableSetHash(ctx, q)
	}
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

// currentTable reads the slot table inside a read transaction on the handle.
func (s *Store) currentTable(ctx context.Context) (*table, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := s.checkEpoch(ctx, tx); err != nil {
		return nil, err
	}
	m, err := loadMeta(ctx, tx)
	if err != nil {
		return nil, err
	}
	return loadTable(ctx, tx, m.ws, uint64(m.format))
}

// binding is the binding a new slot of the table gets: the policy and the
// recovery public key hash the table's bound slots share. bound is false for a
// table of legacy slots only (a migrated workspace before its first rekey),
// whose new slots are legacy too because no recovery public key exists to bind.
func (t *table) binding() (b seal.SlotBinding, bound bool, err error) {
	h, any, ok := t.commonRecHash()
	if !ok {
		return b, false, fmt.Errorf("%w: the slots bind different recovery public key hashes", ErrPolicyViolated)
	}
	return seal.SlotBinding{Policy: string(t.policy), RecoveryPubKeyHash: h}, any, nil
}

// AddPassphraseSlot adds another passphrase that unlocks the workspace and
// returns the new slot id. It does not change the master key, so it needs no
// rekey (but removing the slot later does). The policy must allow it: under
// hardware and strict a passphrase slot is refused.
func (s *Store) AddPassphraseSlot(ctx context.Context, passphrase *secret.Buffer) ([]byte, error) {
	if err := s.writable(); err != nil {
		return nil, err
	}
	release, err := s.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	t, err := s.currentTable(ctx)
	if err != nil {
		return nil, err
	}
	if s.viaRecoverySlot(t) {
		return nil, ErrSlotViaRecovery
	}
	b, bound, err := t.binding()
	if err != nil {
		return nil, err
	}
	id, err := seal.NewID()
	if err != nil {
		return nil, err
	}
	var slot seal.Slot
	if bound {
		slot, err = seal.NewBoundPassphraseSlot(s.ws, id, s.master, passphrase, kdfForNewSlots, b)
	} else {
		slot, err = seal.NewPassphraseSlot(s.ws, id, s.master, passphrase, kdfForNewSlots)
	}
	if err != nil {
		return nil, err
	}
	return id, s.addSlot(ctx, tslot{id: id, kind: seal.SlotPassphrase, ps: slot, bound: bound}, "slot-added")
}

// AddRecoverySlot adds a new recovery key and returns it as printable text. It
// does not change the master key, so it needs no rekey. Only a workspace whose
// slots are all legacy (migrated from format 2, no recovery public key bound
// yet) can add one: in format 3 a recovery key is bound in every slot, so a
// second key is a rekey (ErrUseRekey). On ErrOutcomeUnknown it returns the key
// and the error: the key is valid only if the slot was stored.
func (s *Store) AddRecoverySlot(ctx context.Context) (text *secret.Buffer, slotID []byte, err error) {
	if err := s.writable(); err != nil {
		return nil, nil, err
	}
	release, err := s.enter(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer release()
	t, err := s.currentTable(ctx)
	if err != nil {
		return nil, nil, err
	}
	if s.viaRecoverySlot(t) {
		return nil, nil, ErrSlotViaRecovery
	}
	if _, bound, err := t.binding(); err != nil || bound {
		if err == nil {
			err = fmt.Errorf("%w: the recovery key is bound in every slot of this workspace; a rekey makes a new one", ErrUseRekey)
		}
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
	if err := s.addSlot(ctx, tslot{id: id, kind: seal.SlotRecovery, ps: slot}, "slot-added"); err != nil {
		if errors.Is(err, ErrOutcomeUnknown) {
			return text, id, err // valid only if the slot was stored
		}
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
// On ErrOutcomeUnknown it returns the key AND the error (see Rekey).
func (s *Store) ChangePassphraseRekey(ctx context.Context, newPassphrase *secret.Buffer) (*secret.Buffer, error) {
	return s.Rekey(ctx, []Credential{PassphraseCredential(newPassphrase)})
}

// ChangePassphraseRekeyCold is ChangePassphraseRekey that also re-establishes the
// cold-role records under cold (RekeyCold).
func (s *Store) ChangePassphraseRekeyCold(ctx context.Context, newPassphrase *secret.Buffer, cold *ColdSource) (*secret.Buffer, error) {
	return s.RekeyCold(ctx, []Credential{PassphraseCredential(newPassphrase)}, cold)
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
//
// If COMMIT reports an error and the store cannot read the file back to learn
// whether the rekey took effect, Rekey returns the new recovery key text AND an
// error wrapping ErrOutcomeUnknown: the key is valid only if the rekey took
// effect, and the caller must show it and say so. (Whether it did is told by
// opening with the new passphrase.) The same holds for any COMMIT error other
// than a plain busy or locked one, whatever the read-back shows: a commit that
// failed on fsync may still take effect after a crash. Only when COMMIT was
// never issued is the key destroyed.
func (s *Store) Rekey(ctx context.Context, keep []Credential) (newRecovery *secret.Buffer, err error) {
	return s.RekeyCold(ctx, keep, nil)
}

// RekeyCold is Rekey for a handle opened through the recovery credential
// (`store recover`) that also re-establishes the cold-role records: each one that
// has a recovery wrap is opened through it (checked against its key identity) and
// sealed again under the new cold factor given by cold, whose material is gathered
// before the write transaction; every record the old factor opens is sealed again
// under it too. A record that cannot be re-established because its old factor
// cannot be presented REFUSES the recovery, with the record named (ErrColdWouldStrand),
// unless cold.LeaveUnreachable names it. With cold nil the records are only
// re-wrapped to the new recovery key.
func (s *Store) RekeyCold(ctx context.Context, keep []Credential, cold *ColdSource) (newRecovery *secret.Buffer, err error) {
	defer s.consumeRecovery()
	if err := s.writable(); err != nil {
		return nil, err
	}
	if len(keep) != 1 || keep[0].Kind != seal.SlotPassphrase || keep[0].Secret.Len() == 0 {
		return nil, ErrRekeyCredentials
	}
	return s.rekeyCore(ctx, rekeyReq{cold: cold, guard: s.rekeyGuard, build: func(master *secret.Buffer) ([]tslot, unlock.Policy, *secret.Buffer, error) {
		p, r, text, err := newSlots(s.ws, master, keep[0].Secret)
		return []tslot{p, r}, "", text, err
	}})
}

// rekeyGuard refuses a rekey of a hardware or strict workspace with a message that
// names the way: a rekey makes a passphrase slot and a recovery slot, which
// neither policy allows, so the table is re-created by a rotation. (ADR 0011,
// Amends, ADR 0003 "Rekey" step 3, says a rekey "re-creates the slots that the
// workspace policy allows"; this implementation does not do that under hardware
// or strict, and says so.)
func (s *Store) rekeyGuard(t *table) error {
	if t.policy == unlock.Standard {
		return s.requireRecovery(t)
	}
	return fmt.Errorf("%w: a rekey makes a passphrase slot and a recovery slot, which the %s policy does not allow; to replace the workspace key, change a factor or remove a slot, run: spo workspace rotate --policy %s", ErrPolicyViolated, t.policy, t.policy)
}

// requireRecovery refuses a change of the recovery path unless the current
// recovery credential was presented on this handle for this table (a
// PresentRecovery proof, or an unlock with the recovery credential).
func (s *Store) requireRecovery(t *table) error {
	hash, _, ok := t.commonRecHash()
	if !ok {
		return ErrRecoveryNotPresented
	}
	if s.viaRecovery {
		return nil
	}
	p := s.recProof
	if p == nil || p.s != s || !bytes.Equal(p.epoch, s.epoch) || !bytes.Equal(p.hash, hash) {
		return ErrRecoveryNotPresented
	}
	return nil
}

// RekeyKeepRecovery changes the passphrase by a rekey that re-creates the
// recovery slot from the PRESENTED recovery key (rk, 32 raw bytes) and keeps the
// bound recovery public key hash: no new recovery key is made. The current
// recovery credential must have been presented on this handle (PresentRecovery).
func (s *Store) RekeyKeepRecovery(ctx context.Context, newPassphrase, rk *secret.Buffer) error {
	defer s.consumeRecovery()
	if err := s.writable(); err != nil {
		return err
	}
	if newPassphrase.Len() == 0 {
		return ErrRekeyCredentials
	}
	keepHash, herr := seal.RecoveryPublicKeyHash(rk)
	if herr != nil {
		return herr
	}
	guard := func(t *table) error {
		// the key to be kept must be the one that was presented: the hash bound in
		// the slots, so a different key cannot replace the recovery path
		if err := s.rekeyGuard(t); err != nil {
			return err
		}
		if bound, _, ok := t.commonRecHash(); ok && bound != nil && !bytes.Equal(bound, keepHash) {
			return ErrWrongRecovery
		}
		return nil
	}
	_, err := s.rekeyCore(ctx, rekeyReq{guard: guard, build: func(master *secret.Buffer) ([]tslot, unlock.Policy, *secret.Buffer, error) {
		p, r, text, err := newSlotsWith(s.ws, master, newPassphrase, rk)
		text.Destroy()
		return []tslot{p, r}, "", nil, err
	}})
	return err
}

// rekeyReq is what rekeyCore needs: how to build the new slots once the new
// master key exists, and whether to re-encrypt every payload under a fresh data
// key (a rotation) or only re-wrap the data keys (a rekey).
type rekeyReq struct {
	// build returns the new slots (slots[0] is the one this handle will report as
	// its own), the policy of the new table ("" keeps the current one) and the
	// recovery key as text (nil when the table has none).
	build     func(master *secret.Buffer) ([]tslot, unlock.Policy, *secret.Buffer, error)
	reencrypt bool
	// guard, when set, is run on the slot table inside the transaction, after the
	// verification and before anything is written; an error aborts the rekey.
	guard func(t *table) error
	// events are extra audit events appended with the rotation's rows (a slot
	// removal names itself).
	events [][]any
	// lazyEvents, when set, is called inside the transaction after the guard has
	// run, with the slots the rotation wrote, and its events are appended after
	// events (a rotation names each old slot it removed).
	lazyEvents func(written []tslot) [][]any
	// cold presents the sub-key factor of the NEW table for the cold-role records
	// a rotation re-seals; proof is the recovery presentation of the rotation.
	cold  *ColdSource
	proof *RecoveryProof
}

func (s *Store) rekeyCore(ctx context.Context, req rekeyReq) (newRecovery *secret.Buffer, err error) {
	defer s.consumeRecovery()
	if err := s.writable(); err != nil {
		return nil, err
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
	slots, policy, text, err := req.build(master)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil && !errors.Is(err, ErrOutcomeUnknown) {
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
	// A rekey that makes the table bind a recovery key adds a recovery wrap to every
	// cold record that has none. That needs the cold factor, presented here: before
	// the file lock is upgraded and before any write transaction.
	pre, err := s.gatherColdRekey(ctx, req, slots, policy)
	if err != nil {
		return nil, err
	}
	defer pre.destroy()
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
			s.notice("the file lock could not be taken back to shared after the rekey, so this handle refuses every further operation: " + derr.Error())
		}
	}()

	// If COMMIT reports an error, the rekey took effect exactly when the file's
	// key epoch is the new one (R4-2). The new recovery key is shown or lost
	// by this answer, so it comes from the file, not from the error.
	committed, err := s.withWriteTxMode(ctx, true, func(q dbq) (*Head, error) {
		return s.rekeyBody(ctx, q, keys, epoch, epochMAC, slots, policy, req.reencrypt, req.guard, func() [][]any {
			ev := append([][]any(nil), req.events...)
			if req.lazyEvents != nil {
				ev = append(ev, req.lazyEvents(slots)...)
			}
			return ev
		}, req.cold, req.proof, pre)
	}, func(nc context.Context, q dbq) (bool, error) {
		var got []byte
		if err := q.QueryRowContext(nc, `SELECT key_epoch FROM meta WHERE id = 1`).Scan(&got); err != nil {
			return false, err
		}
		return bytes.Equal(got, epoch), nil
	})
	if !committed {
		if errors.Is(err, ErrOutcomeUnknown) {
			return text, err // the rekey may be on disk: the key is valid only if it is
		}
		return nil, err
	}
	// From here on the rekey is done and the old keys match nothing in the
	// file. Nothing below may fail the call.
	s.keys.Destroy()
	s.master.Destroy()
	s.master, s.keys, s.slotID, s.epoch, swapped = master, keys, slots[0].id, epoch, true
	// The recovery credential was presented for the table that just ended: the
	// next rekey or rotation needs a new presentation.
	s.viaRecovery = false
	s.setProof(nil)
	if policy != "" {
		s.policy = policy
	}
	s.known = nil // the chain has a new segment under new keys: rebuilt at the next use
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
//
// It runs on a connection of its own. Immediately before VACUUM (which copies
// the whole schema into the new file) that connection checks the key epoch and
// the schema as a write transaction does, and the flag is cleared by a
// checked write transaction that reads the meta row back.
func (s *Store) cleanup(ctx context.Context) error {
	conn, closeConn, err := s.writeConn(ctx)
	if err != nil {
		return err
	}
	defer closeConn()
	nc := context.WithoutCancel(ctx)
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return mapErr(err)
	}
	err = s.checkWriteSnapshot(ctx, conn)
	conn.ExecContext(nc, "ROLLBACK") // VACUUM cannot run inside a transaction
	if err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `VACUUM`); err != nil {
		return fmt.Errorf("vacuum: %w", err)
	}
	var busy, logFrames, ckpt int
	if err := conn.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &ckpt); err != nil {
		return fmt.Errorf("WAL checkpoint: %w", err)
	}
	if busy != 0 {
		return errors.New("WAL checkpoint: another connection holds the database busy")
	}
	_, err = s.withWriteTx(ctx, func(q dbq) (*Head, error) {
		if _, err := q.ExecContext(ctx, `UPDATE meta SET cleanup_pending = 0`); err != nil {
			return nil, err
		}
		var rows, pending int
		var ws, epoch, mac []byte
		if err := q.QueryRowContext(ctx, `SELECT count(*) FROM meta`).Scan(&rows); err != nil {
			return nil, err
		}
		if err := q.QueryRowContext(ctx, `SELECT workspace_id, key_epoch, epoch_mac, cleanup_pending FROM meta WHERE id = 1`).Scan(&ws, &epoch, &mac, &pending); err != nil {
			return nil, err
		}
		ok, err := s.keys.Audit.CheckEpoch(ws, epoch, mac)
		if err != nil {
			return nil, err
		}
		if rows != 1 || pending != 0 || !ok || !bytes.Equal(ws, s.ws) || !bytes.Equal(epoch, s.epoch) {
			return nil, errWriteChanged("the meta row")
		}
		return nil, nil
	}, nil)
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
func (s *Store) rekeyBody(ctx context.Context, q dbq, keys *seal.Keys, epoch, epochMAC []byte, slots []tslot, policy unlock.Policy, reencrypt bool, guard func(*table) error, extra func() [][]any, coldSrc *ColdSource, proof *RecoveryProof, pre *coldPre) (*Head, error) {
	// Verify first, under the old keys, so that a rekey cannot launder a
	// rolled-back record or a modified chain into the new segment.
	_, chain, known, err := s.verify(ctx, q, true)
	if err != nil {
		return nil, fmt.Errorf("sqlitestore: rekey refused, nothing was changed: %w", err)
	}
	s.known = known
	if guard != nil {
		m, err := loadMeta(ctx, q)
		if err != nil {
			return nil, err
		}
		t, err := loadTable(ctx, q, m.ws, uint64(m.format))
		if err != nil {
			return nil, err
		}
		if err := guard(t); err != nil {
			return nil, err
		}
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
	cold, err := s.prepareColdRekey(ctx, q, slots, policy, reencrypt, coldSrc, proof, all, pre)
	if err != nil {
		return nil, err
	}
	defer cold.destroy()
	newPub, err := commonPub(slots)
	if err != nil {
		return nil, err
	}
	var entries []touched
	var wrote []*stored
	for _, r := range all {
		ref, err := s.refOf(r.id, r.kind, r.sealed)
		if err != nil {
			return nil, fmt.Errorf("%w: a record's owner blob does not open (%v); nothing was changed", ErrCorrupt, err)
		}
		tag, err := tagFor(keys, ref.Anchor, r.kind, ref.Num)
		if err != nil {
			return nil, err
		}
		class := seal.ClassSensitive
		if portsKindSecret(r.kind) {
			class = seal.ClassSecret
		}
		isCold := seal.IsColdSealed(r.sealed)
		if isCold {
			class = seal.ClassSecretCold
		}
		meta := metaOf(s.ws, r.id, ref, class, r.version)
		var re seal.SealedRecord
		if isCold {
			if reencrypt && rotateHook != nil {
				if herr := rotateHook(len(wrote)); herr != nil {
					return nil, herr
				}
			}
			re, err = cold.row(ctx, keys, meta, r)
		} else if reencrypt {
			if rotateHook != nil {
				if herr := rotateHook(len(wrote)); herr != nil {
					return nil, herr
				}
			}
			re, err = s.reencrypt(keys, meta, r.sealed)
		} else {
			re, err = s.keys.Rewrap(keys, meta, r.sealed)
		}
		if err != nil {
			if isFactorError(err) || errors.Is(err, ErrRecoveredIdentity) {
				// a factor that was wrong or absent is not damage; a recovered key that
				// is not the one of its record is tampering, and is reported as such
				return nil, err
			}
			return nil, fmt.Errorf("%w: a record does not rewrap (%w); nothing was changed", ErrCorrupt, err)
		}
		res, err := q.ExecContext(ctx, `UPDATE records SET lookup_tag=?, nonce=?, wrapped_key=?, owner_sealed=?, ciphertext=? WHERE id=? AND version=?`,
			tag, re.Nonce, re.WrappedKey, re.Owner, re.Ciphertext, r.id, int64(r.version))
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
	if policy != "" {
		if err := writePolicy(ctx, q, policy); err != nil {
			return nil, err
		}
	}
	for _, sl := range slots {
		if err := insertTSlot(ctx, q, sl); err != nil {
			return nil, err
		}
	}
	if err := writeRecoveryPub(ctx, q, newPub); err != nil {
		return nil, err
	}
	// A rekey creates a passphrase slot and a recovery slot, which only the
	// standard policy allows: under hardware or strict the table breaks its
	// policy and the rekey is refused (rekey is bound by the policy function).
	if _, err := checkTable(ctx, q); err != nil {
		return nil, fmt.Errorf("sqlitestore: rekey refused, nothing was changed: %w", err)
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
	if reencrypt {
		// A rotation says so in a row of its own (the rollover event has a fixed
		// shape): the table and the policy it wrote are in the slot-set hash.
		pol := policy
		if pol == "" {
			pol = s.policy
		}
		if head, err = appendAudit(ctx, q, s.ws, keys, auditSlots, s.now().Unix(), *head, append([][]any{{"rotate", string(pol)}}, extra()...), nil, set); err != nil {
			return nil, err
		}
	}
	if pre != nil && len(pre.left) > 0 {
		// the records the operator left under their old cold factor are named in the
		// audit trail in the transaction that left them (ids only), so `store verify`
		// can list them until a later rotation re-establishes them
		ev := make([][]any, 0, len(pre.left))
		for _, id := range pre.left {
			ev = append(ev, []any{"cold-left", id})
		}
		if head, err = appendAudit(ctx, q, s.ws, keys, auditSlots, s.now().Unix(), *head, ev, nil, set); err != nil {
			return nil, err
		}
	}
	// Read everything back before COMMIT: a trigger, or any change behind the
	// store's back, must abort the rekey, not turn it into a loss.
	if err := verifyRekeyWrites(ctx, q, wrote, slots, s.ws, epoch, epochMAC); err != nil {
		return nil, err
	}
	return head, nil
}

// verifyRekeyWrites compares the rows a rekey wrote with what is in the
// transaction now: every record row (and that there are no others), exactly the
// two new key slot rows, and the meta row.
func verifyRekeyWrites(ctx context.Context, q dbq, wrote []*stored, slots []tslot, ws, epoch, epochMAC []byte) error {
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
	m, err := loadMeta(ctx, q)
	if err != nil {
		return err
	}
	have, err := loadTable(ctx, q, m.ws, uint64(m.format))
	if err != nil {
		return err
	}
	if len(have.slots) != len(slots) {
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
	if rows != 1 || !bytes.Equal(gotWS, ws) || !formatOK(uint64(format)) || !bytes.Equal(gotEpoch, epoch) || !bytes.Equal(gotMAC, epochMAC) || pending != 1 {
		return errWriteChanged("the meta row")
	}
	return nil
}

// formatOK says whether a meta row's format version is one this binary reads:
// the current one, or format 1 while a migration is running.
func formatOK(f uint64) bool {
	return f == seal.StoreFormat || f == seal.RecordFormat || f == seal.LegacyRecordFormat
}

// reencrypt is the payload step of a rotation: the record is opened under the
// old keys and sealed again under the new ones with a fresh data key, a fresh
// payload nonce and fresh wrapping nonces, so no byte of the old ciphertext or
// of the old wrapped data key survives (a rekey keeps both).
func (s *Store) reencrypt(to *seal.Keys, m seal.RecordMeta, r seal.SealedRecord) (seal.SealedRecord, error) {
	if m.Class == seal.ClassSecret {
		pt, err := s.keys.OpenSecret(m, r)
		if err != nil {
			return seal.SealedRecord{}, err
		}
		defer pt.Destroy()
		return to.SealSecret(m, pt)
	}
	pt, err := s.keys.OpenRecord(m, r)
	if err != nil {
		return seal.SealedRecord{}, err
	}
	return to.SealRecord(m, pt)
}

// rotateHook, when set, is called before each record of a rotation is
// re-encrypted; a test makes it fail to show that a rotation that stops half
// way leaves the file logically unchanged (one transaction).
var rotateHook func(done int) error
