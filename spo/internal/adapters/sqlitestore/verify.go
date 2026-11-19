package sqlitestore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/fxamacker/cbor/v2"

	"github.com/mochipool/workbench/spo/internal/domain/unlock"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
)

// ErrVerify is wrapped by every verification failure (a schema failure
// included: ErrSchema).
var ErrVerify = errors.New("sqlitestore: verification failed")

// VerifyError lists everything Verify found wrong.
type VerifyError struct{ Problems []string }

func (e *VerifyError) Error() string {
	return fmt.Sprintf("%v: %d problem(s): %s", ErrVerify, len(e.Problems), strings.Join(e.Problems, "; "))
}

func (e *VerifyError) Is(target error) bool { return target == ErrVerify }

// VerifyResult is what a verification learned besides pass or fail.
type VerifyResult struct {
	// Head is the end of the audit chain. Record it where an attacker cannot
	// write, to detect a rollback that replaces the file and its head file.
	Head Head
	// Notices are things that are not failures but the operator should know,
	// such as history that predates a rekey and cannot be verified.
	Notices []string
	// CheckpointKey says a checkpoint key record is present; CheckpointKeyHash is
	// its key hash (nil when it does not parse).
	CheckpointKey     bool
	CheckpointKeyHash []byte
}

type chainState struct {
	version uint64
	hash    []byte
	deleted bool
}

// chainKnown is what a handle knows about its workspace from the audit chain:
// the chain row it has verified up to, and for every record id the version and
// hash the chain recorded last (see THE HANDLE'S RECORD MAP).
type chainKnown struct {
	head  Head
	recs  map[string]chainState
	tags  map[string]string // lookup tag -> record id, for every live record
	tagOf map[string]string // record id -> lookup tag
}

// setTag records that the live record id has lookup tag tag.
func (k *chainKnown) setTag(id, tag []byte) {
	if old, ok := k.tagOf[string(id)]; ok && k.tags[old] == string(id) {
		delete(k.tags, old)
	}
	k.tagOf[string(id)] = string(tag)
	k.tags[string(tag)] = string(id)
}

// bindTag brings the tag maps in line with the chain's last word on id: a
// deleted record loses its tag; a live one gets the tag of its row, which must
// be the recorded version of it (the audit entries carry the hash, not the tag).
func (k *chainKnown) bindTag(ctx context.Context, q dbq, id string) error {
	st := k.recs[id]
	if st.deleted {
		if old, ok := k.tagOf[id]; ok {
			if k.tags[old] == id { // a record created in the same batch may have the tag now
				delete(k.tags, old)
			}
			delete(k.tagOf, id)
		}
		return nil
	}
	changed := &VerifyError{Problems: []string{"a record the audit chain lists does not match its row while the workspace was open"}}
	row, err := readStored(ctx, q, []byte(id))
	if err != nil {
		return err
	}
	if row == nil || row.version < 1 || uint64(row.version) != st.version {
		return changed
	}
	if h, err := recordHash(row.kind, row.tag, row.sealed); err != nil {
		return err
	} else if !bytes.Equal(h, st.hash) {
		return changed
	}
	k.setTag([]byte(id), row.tag)
	return nil
}

// noteEntry applies one touched entry to state and returns what is wrong with
// it, or "". Within one segment of the chain a record's versions only go up by
// one at a time (a put), or the record is deleted at the version it had; an
// id is never used again after its deletion (new records get new random ids).
// The first entry for an id in a segment may have any version: a rollover row
// lists every record at its current version.
func noteEntry(state map[string]chainState, e touched) string {
	prev, seen := state[string(e.ID)]
	st := chainState{version: e.Version, hash: e.Hash, deleted: len(e.Hash) == 0}
	problem := ""
	switch {
	case !seen:
	case prev.deleted:
		problem = "a record is touched again after the chain recorded its deletion"
	case st.deleted && e.Version != prev.version:
		problem = "a deletion names another version than the record had"
	case !st.deleted && e.Version != prev.version+1:
		problem = "a record's version goes backwards, repeats or skips"
	}
	state[string(e.ID)] = st
	return problem
}

// WHAT VERIFY COVERS AND DOES NOT COVER
//
// Covered, at one snapshot, with no secret decrypted except the sealed events
// of rollover rows:
//
//   - the schema is exactly the allow-list of the file's schema version
//     (schemacheck.go): no trigger, view, extra table or index, no changed
//     column, and the schema_version table holds that version;
//   - SQLite's own PRAGMA integrity_check returns exactly "ok" (pages, b-trees
//     and indexes, including the lookup-tag index, are consistent);
//   - audit sequence numbers are 1, 2, 3, ... with no gap, and each row's
//     prev_mac is the previous row's mac;
//   - from the newest rollover row (a rekey) on, or from the first row when
//     there is none, each row's mac is the MAC of its whole content under the
//     audit key (including the slot-set hash);
//   - for the segment before the newest rollover, the SHA-256 over the rows
//     present equals the history hash the rollover sealed; one changed,
//     removed or added old row (or one old row's MAC) is an error. Each
//     rollover covers everything before it, earlier rollovers included, so
//     checking the newest one covers every earlier segment;
//   - every record's current (version, recordHash of kind, lookup tag and the
//     sealed parts) equals the last entry the chain recorded for it; no record
//     exists that the chain never recorded or recorded as deleted, and none
//     the chain recorded as live is missing; within the chain a record's
//     version only ever goes up by one, or ends in a deletion at the version
//     it had, and an id is not used again after its deletion;
//   - the keyslots table, hashed over all columns, equals the newest slot-set
//     hash the chain recorded (written at Init, at every slot addition and at
//     every rekey);
//   - meta.epoch_mac is the MAC of the workspace id and key_epoch under the
//     current audit key;
//   - the head file, when there is one, names a row the chain still has.
//
// NOT covered: the plaintext of records. Verify compares the stored bytes of
// every record with the authenticated audit chain; it does not decrypt
// payloads or owner names, so a record whose chain entry is genuine but whose
// bytes cannot be opened under the current keys is found only when it is read
// or by VerifyPayloads, which decrypts every record and checks its lookup tag.
// Also not covered: meta columns
// other than the workspace id, key epoch and its MAC (created_at,
// format_version, cleanup_pending); the schema_version table; unused database
// pages. Rows of the first segment of a rekeyed workspace cannot have their
// MACs checked, only their hash; whoever holds the master key of the time
// before the rekey could have forged them, but not after. Replacing the whole
// file and its head file by an older, internally consistent pair is not
// detectable from the file alone (head.go). An attacker who can write the
// file AND holds an old copy can put back an old slot row together with the
// old meta row: the credential of that time then unlocks the OLD master key,
// which opens nothing sealed after the rekey, and Verify (which Open runs)
// fails because the audit rows after the rollover are MAC'd under the new
// audit key. That attacker gains nothing they did not already hold.

// Verify checks the workspace as described under WHAT VERIFY COVERS AND DOES
// NOT COVER. It returns a *VerifyError (errors.Is ErrVerify) listing every
// problem found. Open runs it after unlocking.
//
// A passing Verify refreshes the handle's record map (THE HANDLE'S RECORD
// MAP); a failing one leaves it as it was.
func (s *Store) Verify(ctx context.Context) error {
	_, err := s.VerifyDetailed(ctx)
	return err
}

// VerifyDetailed is Verify that also returns the chain head and notices, even
// when verification fails.
func (s *Store) VerifyDetailed(ctx context.Context) (res VerifyResult, err error) {
	release, err := s.enter(ctx)
	if err != nil {
		return res, err
	}
	defer release()
	return s.verifyLocked(ctx, true)
}

// VerifyPayloads is Verify and then, at the same snapshot, a decryption of
// every record: each record's owner blob opens, its lookup tag is the tag of
// the name it carries, and its payload opens under the current keys (secrets
// into guarded buffers that are destroyed at once, other payloads into memory
// that is cleared at once). It proves the records can be read, which Verify
// does not. It costs one authenticated decryption per record, so it is slower
// than Verify; nothing is returned to the caller but the error. A record that
// does not open is reported by its kind only (a *RefError wrapping ErrCorrupt).
func (s *Store) VerifyPayloads(ctx context.Context) error {
	_, err := s.VerifyPayloadsReport(ctx)
	return err
}

// VerifyPayloadsReport is VerifyPayloads and says what it could not check. A
// cold-role record is opened only as far as the master key goes: its outer layer
// authenticates the class, the header, the recovery wrap and the associated data,
// and its role history agrees with its sealed class, but whether the payload
// decrypts, and whether the key in it derives the record's identity, cannot be
// known without the sub-key factor. VerifyColdPayloads is the variant that
// presents the factor.
func (s *Store) VerifyPayloadsReport(ctx context.Context) (ColdCheck, error) {
	var cold ColdCheck
	release, err := s.enter(ctx)
	if err != nil {
		return cold, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return cold, err
	}
	defer tx.Rollback()
	if err := s.checkEpoch(ctx, tx); err != nil {
		return cold, err
	}
	_, _, known, err := s.verify(ctx, tx, true)
	if err != nil {
		return cold, err
	}
	s.known = known
	return cold, s.openAll(ctx, tx, &cold)
}

// openAll decrypts every record as VerifyPayloads describes.
func (s *Store) openAll(ctx context.Context, q dbq, cold *ColdCheck) error {
	rows, err := q.QueryContext(ctx, `SELECT id, lookup_tag, kind, version, nonce, wrapped_key, owner_sealed, ciphertext FROM records ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var keyRefs []keyRow
	for rows.Next() {
		var id, tag []byte
		var kind string
		var v int64
		var r seal.SealedRecord
		if err := rows.Scan(&id, &tag, &kind, &v, &r.Nonce, &r.WrappedKey, &r.Owner, &r.Ciphertext); err != nil {
			return err
		}
		ref, err := s.refOf(id, kind, r)
		kref := ports.Ref{Kind: ports.Kind(kind)} // errors carry the kind only: the anchor is Sensitive
		if err != nil {
			return corrupt(kref, err)
		}
		if want, err := tagFor(s.keys, ref.Anchor, kind, ref.Num); err != nil {
			return err
		} else if !bytes.Equal(want, tag) {
			return &RefError{kref, fmt.Errorf("%w: lookup tag does not match the owner", ErrCorrupt)}
		}
		meta := metaOf(s.ws, id, ref, classOf(ref.Kind), uint64(v))
		if ref.Kind.Secret() && seal.IsColdSealed(r) {
			// A cold-role record: the master key opens the outer layer, which
			// authenticates the class, the header, the recovery wrap and the
			// associated data; the payload needs the sub-key factor and is not
			// opened here (VerifyColdPayloads does, with the factor).
			if _, err := s.keys.OpenColdOuter(meta.ColdMeta(), r); err != nil {
				return corrupt(kref, err)
			}
			cold.Records++
			cold.OuterOnly++
			keyRefs = append(keyRefs, keyRow{ref, true})
			continue
		}
		if labels.IsKeySecret(ref.Kind) {
			keyRefs = append(keyRefs, keyRow{ref, false})
		}
		if ref.Kind.Secret() {
			b, err := s.keys.OpenSecret(meta, r)
			if err != nil {
				return corrupt(kref, err)
			}
			b.Destroy()
		} else {
			pt, err := s.keys.OpenRecord(meta, r)
			if err != nil {
				return corrupt(kref, err)
			}
			clear(pt)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	// The sealed class of every signing key agrees with its role history.
	t := &txn{s: s, ctx: ctx, q: q, ops: map[ports.Ref]*op{}}
	for _, k := range keyRefs {
		cls, err := labels.ClassifyKeyRecord(t, k.ref)
		if err != nil {
			return &RefError{ports.Ref{Kind: k.ref.Kind}, err}
		}
		if cls.Cold != k.cold {
			return &RefError{ports.Ref{Kind: k.ref.Kind}, ErrColdClassMismatch}
		}
	}
	return nil
}

type keyRow struct {
	ref  ports.Ref
	cold bool
}

// verifyLocked runs verify in its own read transaction. The caller holds the
// gate. A pass replaces the handle's record map.
func (s *Store) verifyLocked(ctx context.Context, withHeadFile bool) (VerifyResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return VerifyResult{}, err
	}
	defer tx.Rollback()
	if err := s.checkEpoch(ctx, tx); err != nil {
		return VerifyResult{}, err
	}
	res, _, known, err := s.verify(ctx, tx, withHeadFile)
	if err == nil {
		s.known = known
	}
	return res, err
}

// verify does the work of Verify on q, inside a transaction, and returns the
// audit chain it read. withHeadFile says whether to compare with the head
// file (Open has done that already, in its own way).
func (s *Store) verify(ctx context.Context, q dbq, withHeadFile bool) (res VerifyResult, chain []auditRow, known *chainKnown, err error) {
	var problems []string
	bad := func(f string, a ...any) { problems = append(problems, fmt.Sprintf(f, a...)) }
	fail := func() (VerifyResult, []auditRow, *chainKnown, error) {
		return res, chain, nil, &VerifyError{Problems: problems}
	}

	if err := checkSchema(ctx, q, s.schemaV); err != nil {
		return res, nil, nil, err
	}
	if msg, err := integrityCheck(ctx, q); err != nil {
		bad("database integrity check could not run: %v", err)
		return fail()
	} else if msg != "" {
		bad("database integrity check failed: %s", msg)
		return fail() // the tables cannot be trusted to be read
	}

	rows, err := q.QueryContext(ctx, `SELECT seq, at, kind, event, touched, slotset, mac, prev_mac FROM audit ORDER BY seq`)
	if err != nil {
		return res, nil, nil, err
	}
	for rows.Next() {
		var r auditRow
		if err := rows.Scan(&r.seq, &r.at, &r.kind, &r.event, &r.touchedRaw, &r.slotset, &r.mac, &r.prev); err != nil {
			rows.Close()
			return res, nil, nil, err
		}
		chain = append(chain, r)
	}
	if err := rows.Close(); err != nil {
		return res, nil, nil, err
	}
	if err := rows.Err(); err != nil {
		return res, nil, nil, err
	}

	// The key epoch.
	m, err := loadMeta(ctx, q)
	if err != nil {
		return res, nil, nil, err
	}
	if ok, err := s.keys.Audit.CheckEpoch(s.ws, m.epoch, m.epochMAC); err != nil {
		return res, nil, nil, err
	} else if !ok {
		bad("the key epoch does not match the keys: meta was modified, or it was put back from before a rekey")
	}

	// Structure: no key needed.
	expect, prevMAC := int64(1), zeroMAC
	firstChecked := 0 // index of the first row whose MAC can be checked: the newest rollover
	for i, r := range chain {
		if r.seq != expect {
			bad("audit sequence jumps from %d to %d (row missing, added or reordered)", expect-1, r.seq)
			expect = r.seq
		}
		expect++
		if !bytes.Equal(r.prev, prevMAC) {
			bad("audit row %d: prev_mac does not match the previous row", r.seq)
		}
		prevMAC = r.mac
		if r.kind == auditRollover {
			firstChecked = i
		}
	}
	if firstChecked > 0 {
		s.checkRollover(chain, firstChecked, bad)
		res.Notices = append(res.Notices, fmt.Sprintf("the MACs of the rows before sequence %d were made under a previous key and are not checked; their content is checked against the hash the rollover row sealed", chain[firstChecked].seq))
	}

	// Content: MACs and the per-record state, from the newest rollover on.
	state := map[string]chainState{}
	var recordedSlotSet []byte
	for _, r := range chain[firstChecked:] {
		rowBytes, err := auditRowBytes(s.ws, uint64(r.seq), r.kind, r.at, r.event, r.touchedRaw, r.slotset)
		if err != nil {
			return res, nil, nil, err
		}
		ok, err := s.keys.Audit.Check(r.prev, rowBytes, r.mac)
		if err != nil {
			return res, nil, nil, err
		}
		if !ok {
			bad("audit row %d: MAC mismatch (row modified)", r.seq)
			continue
		}
		switch {
		case r.kind == auditUpdate && len(r.slotset) != 0, r.kind != auditUpdate && len(r.slotset) != sha256.Size:
			bad("audit row %d: its slot-set hash has the wrong length for a %s row", r.seq, r.kind)
		case r.kind != auditUpdate:
			recordedSlotSet = r.slotset
		}
		var entries []touched
		if err := cbor.Unmarshal(r.touchedRaw, &entries); err != nil {
			bad("audit row %d: unreadable touched list", r.seq)
			continue
		}
		for _, e := range entries {
			if why := noteEntry(state, e); why != "" {
				bad("audit row %d: %s", r.seq, why)
			}
		}
	}

	// The key slots.
	live, err := slotSetHash(ctx, q)
	if err != nil {
		return res, nil, nil, err
	}
	if recordedSlotSet == nil {
		bad("the audit chain records no slot set")
	} else if !bytes.Equal(live, recordedSlotSet) {
		bad("the key slots do not match the last slot set the audit chain recorded (a slot row was modified, added or removed)")
	}

	rrows, err := q.QueryContext(ctx, `SELECT id, lookup_tag, kind, version, nonce, wrapped_key, owner_sealed, ciphertext FROM records ORDER BY id`)
	if err != nil {
		return res, nil, nil, err
	}
	defer rrows.Close()
	seen := map[string]bool{}
	tags, tagOf := map[string]string{}, map[string]string{}
	for rrows.Next() {
		var id, tag []byte
		var kind string
		var v int64
		var r seal.SealedRecord
		if err := rrows.Scan(&id, &tag, &kind, &v, &r.Nonce, &r.WrappedKey, &r.Owner, &r.Ciphertext); err != nil {
			return res, nil, nil, err
		}
		seen[string(id)] = true
		tags[string(tag)], tagOf[string(id)] = string(id), string(tag)
		name := hex.EncodeToString(id)
		st, ok := state[string(id)]
		h, err := recordHash(kind, tag, r)
		if err != nil {
			return res, nil, nil, err
		}
		switch {
		case !ok:
			bad("record %s is not in the audit chain (injected?)", name)
		case st.deleted:
			bad("record %s is present but the audit chain recorded its deletion (restored?)", name)
		case st.version != uint64(v) || !bytes.Equal(st.hash, h):
			bad("record %s does not match the audit chain (rolled back or modified; chain has version %d, file has %d)", name, st.version, v)
		}
	}
	if err := rrows.Err(); err != nil {
		return res, nil, nil, err
	}
	for id, st := range state {
		if !st.deleted && !seen[id] {
			bad("record %s is recorded in the audit chain but missing from the file", hex.EncodeToString([]byte(id)))
		}
	}

	// The head file.
	res.Head = Head{MAC: zeroMAC}
	if n := len(chain); n > 0 {
		res.Head = Head{Seq: uint64(chain[n-1].seq), MAC: chain[n-1].mac}
	}
	if withHeadFile {
		hws, hh, found, herr := readHeadFile(s.path)
		disagrees := found && (herr != nil || !bytes.Equal(hws, s.ws) || hh.Seq > res.Head.Seq || (hh.Seq > 0 && !chainHas(chain, hh)))
		sidecarMsg, sidecarOK := "", false
		if disagrees {
			sidecarMsg, sidecarOK = adoptSidecar(s.path, s.ws, res.Head)
		}
		switch {
		case !found:
			// Also for a read-only handle, which does not create it.
			res.Notices = append(res.Notices, "there is no head file: a rollback of the workspace file cannot be detected")
		case disagrees && sidecarOK:
			// A restore died between the swap and the head file. Verify is read-only
			// and adopts nothing; an open completes the restore.
			res.Notices = append(res.Notices, sidecarMsg+"; opening the workspace completes the restore (verify itself adopts nothing and changes no file)")
		case herr != nil || !bytes.Equal(hws, s.ws):
			bad("the head file is unreadable or belongs to another workspace")
		case hh.Seq > res.Head.Seq:
			bad("the workspace is older than its head file: the head file records sequence %d, the audit chain ends at %d (rolled back?)", hh.Seq, res.Head.Seq)
		case hh.Seq > 0 && !chainHas(chain, hh):
			bad("the audit chain does not contain the sequence %d recorded in the head file (rolled back or rewritten)", hh.Seq)
		}
	}
	if len(problems) > 0 {
		return fail()
	}
	return res, chain, &chainKnown{head: res.Head, recs: state, tags: tags, tagOf: tagOf}, nil
}

// integrityCheck runs PRAGMA integrity_check. It returns "" when SQLite
// answers exactly "ok", and otherwise the first line it reported.
func integrityCheck(ctx context.Context, q dbq) (string, error) {
	rows, err := q.QueryContext(ctx, `PRAGMA integrity_check`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var l string
		if err := rows.Scan(&l); err != nil {
			return "", err
		}
		lines = append(lines, l)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if len(lines) == 1 && lines[0] == "ok" {
		return "", nil
	}
	if len(lines) == 0 {
		return "no answer", nil
	}
	return lines[0], nil
}

// auditRow is one row of the audit table.
type auditRow struct {
	seq, at                               int64
	kind                                  string
	event, touchedRaw, slotset, mac, prev []byte
}

func chainHas(chain []auditRow, h Head) bool {
	for _, r := range chain {
		if uint64(r.seq) == h.Seq {
			return bytes.Equal(r.mac, h.MAC)
		}
	}
	return false
}

// checkRollover opens the sealed event of the newest rollover row, chain[i],
// and checks that it names the row before it and that the history hash it
// sealed is the hash of the rows before it.
func (s *Store) checkRollover(chain []auditRow, i int, bad func(string, ...any)) {
	r := chain[i]
	rowBytes, err := auditRowBytes(s.ws, uint64(r.seq), r.kind, r.at, r.event, r.touchedRaw, r.slotset)
	if err != nil {
		bad("audit row %d: %v", r.seq, err)
		return
	}
	if ok, err := s.keys.Audit.Check(r.prev, rowBytes, r.mac); err != nil || !ok {
		return // reported as a MAC mismatch by the caller; its event cannot be trusted
	}
	events, err := openEvent(s.keys, s.ws, uint64(r.seq), r.event)
	if err != nil {
		bad("audit row %d: the rollover event does not open", r.seq)
		return
	}
	if len(events) != 1 || len(events[0]) != 4 {
		bad("audit row %d: malformed rollover event", r.seq)
		return
	}
	oldSeq, _ := events[0][1].(uint64)
	oldMAC, _ := events[0][2].([]byte)
	history, _ := events[0][3].([]byte)
	if int64(oldSeq) != r.seq-1 || !bytes.Equal(oldMAC, r.prev) {
		bad("audit row %d: the rollover event does not name the previous row", r.seq)
	}
	want, err := historyHash(chain[:i])
	if err != nil {
		bad("audit row %d: %v", r.seq, err)
		return
	}
	if !bytes.Equal(want, history) {
		bad("the audit rows before the rollover at sequence %d do not match the history hash it sealed (an old row was modified, removed or added)", r.seq)
	}
}

// VerifyFile opens the workspace read-only with the passphrase and runs
// Verify. It writes nothing to the file.
func VerifyFile(path string, passphrase *secret.Buffer) error {
	_, err := VerifyFileDetailed(path, passphrase)
	return err
}

// VerifyFileDetailed is VerifyFile that also returns the chain head and notices.
func VerifyFileDetailed(path string, passphrase *secret.Buffer) (VerifyResult, error) {
	return verifyFile(path, credential{kind: seal.SlotPassphrase, buf: passphrase}, false)
}

// VerifyFilePayloads is VerifyFileDetailed followed by VerifyPayloads: it also
// decrypts every record. Read-only, like VerifyFile.
func VerifyFilePayloads(path string, passphrase *secret.Buffer) (VerifyResult, error) {
	return verifyFile(path, credential{kind: seal.SlotPassphrase, buf: passphrase}, true)
}

// VerifyFileFactors is VerifyFileDetailed (payloads false) or VerifyFilePayloads
// (true) for a workspace that unlocks through FIDO2 factors: the file's own slot
// table decides which slot opens, and the authenticator is asked again (PIN and
// touch). A backup of a hardware workspace has the same slots, so this is how
// `store backup` verifies its copy under that policy. Read-only.
func VerifyFileFactors(path string, in FactorInputs, payloads bool) (VerifyResult, error) {
	if !in.canPresent() {
		return VerifyResult{}, errors.New("sqlitestore: no factor source")
	}
	return verifyFile(path, credential{kind: credFactors, factors: &in}, payloads)
}

// VerifyFileWithRecovery is VerifyFile with the printed recovery key.
func VerifyFileWithRecovery(path string, recovery *secret.Buffer) error {
	raw, err := seal.DecodeRecoveryKey(recovery)
	if err != nil {
		return err
	}
	defer raw.Destroy()
	_, err = verifyFile(path, credential{kind: seal.SlotRecovery, buf: raw}, false)
	return err
}

func verifyFile(path string, cred credential, payloads bool) (VerifyResult, error) {
	return verifyFileThen(path, cred, payloads, nil)
}

// verifyFileThen is verifyFile that, when the verification passed, calls then
// with the open store (read-only) before closing it, so that a caller can take
// what it needs of the verified file without presenting the credential again.
func verifyFileThen(path string, cred credential, payloads bool, then func(*Store) error) (VerifyResult, error) {
	// SkipVerify: VerifyDetailed below runs the verification and reports every
	// problem, which Open's all-or-nothing check would hide.
	s, err := open(path, cred, true, OpenOptions{AcceptRollback: true, SkipVerify: true})
	if err != nil {
		return VerifyResult{}, err
	}
	defer s.Close()
	res, err := s.VerifyDetailed(context.Background())
	res.Notices = append(s.Notices(), res.Notices...)
	if err == nil && payloads {
		var cold ColdCheck
		cold, err = s.VerifyPayloadsReport(context.Background())
		if err == nil && cold.OuterOnly > 0 {
			res.Notices = append(res.Notices, fmt.Sprintf("%d cold-role record(s): the outer layer was opened with the workspace key and authenticated (class, header, recovery wrap, associated data), but the payloads were not decrypted, because that needs the cold sub-key factor, and so it is not known that the keys in them can be read or belong to their identities; run `spo store verify --deep --with-cold-factor` to open them with the factor", cold.OuterOnly))
		}
	}
	if err == nil && !s.legacy {
		// What the workspace key alone says about the cold records: no recovery wrap,
		// a healed fallback, and records out of step with the policy, which fail the
		// verification (no factor needed).
		st, cerr := coldStatusFn(s, context.Background())
		if cerr != nil {
			err = fmt.Errorf("%w: reading the cold-role records: %w", ErrVerify, cerr)
		} else {
			if st.WithoutWrap > 0 && s.policy != unlock.Strict {
				res.Notices = append(res.Notices, ColdNoWrapNotice(st.WithoutWrap))
			}
			for _, f := range st.Fallbacks {
				res.Notices = append(res.Notices, fmt.Sprintf("cold record %s was healed from its previous wrap %d time(s): the authenticator gave a faulty answer once", f.Record, f.Count))
			}
			if len(st.Problems) > 0 {
				ve := &VerifyError{}
				for _, p := range st.Problems {
					ve.Problems = append(ve.Problems, fmt.Sprintf("cold record %s: %s", p.Record, p.Why))
				}
				err = ve
			}
		}
	}
	if err == nil && !s.legacy {
		// the checkpoint key record (ADR 0012 stage 2): present, and with --deep
		// parsed strictly
		raw, kerr := readCheckpointKey(context.Background(), s)
		switch {
		case kerr != nil:
			err = fmt.Errorf("%w: reading the checkpoint key record: %w", ErrVerify, kerr)
		case raw != nil:
			res.CheckpointKey = true
			res.CheckpointKeyHash = checkpointKeyHash(raw)
			if payloads {
				if perr := checkpointKeyProblem(raw); perr != nil {
					ve := &VerifyError{Problems: []string{perr.Error()}}
					err = ve
				}
			} else {
				res.Notices = append(res.Notices, "a checkpoint key record is present (it is not decrypted by this check; --deep parses it)")
			}
		}
	}
	if err == nil && !s.legacy {
		// the identity layer, as every open checks it (ADR 0010 decision 4)
		if cerr := s.View(context.Background(), func(r ports.Reader) error { return labels.Check(r) }); cerr != nil {
			err = fmt.Errorf("%w: the identity layer: %w", ErrVerify, cerr)
		}
	}
	if err == nil && then != nil {
		err = then(s)
	}
	return res, err
}
