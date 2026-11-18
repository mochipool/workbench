package sqlitestore

// Regression tests for the security review of the store: one section per
// finding (H1, M1..M5, L1..L5, slot commitment, audit of slot operations,
// error text). Several tests build their workspace with Init instead of
// copying the shared template, so the creation path is exercised.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// scratch makes a workspace with Init and opens it with its passphrase. The
// handle holds NO recovery proof and no recovery secret: it is a handle that the
// master key alone could have made. A test that rekeys presents the recovery key
// itself (presentStd, or rekeyTo, which does it from heldRecovery).
func scratch(t *testing.T) (s *Store, path string, recoveryText string) {
	t.Helper()
	s, path, recoveryText = scratchUnpresented(t)
	heldRecovery.Store(s, recoveryText)
	return s, path, recoveryText
}

// scratchPresented is scratch with the recovery key presented on the handle, for
// a test that rekeys or rotates it once (a rekey consumes the presentation).
func scratchPresented(t *testing.T) (s *Store, path string, recoveryText string) {
	t.Helper()
	s, path, recoveryText = scratch(t)
	presentStd(t, s, recoveryText)
	return s, path, recoveryText
}

// scratchUnpresented is scratch without the presentation: a handle that only
// the passphrase opened.
func scratchUnpresented(t *testing.T) (s *Store, path string, recoveryText string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "ws.db")
	p1, p2 := pw(), pw()
	defer p1.Destroy()
	defer p2.Destroy()
	rk, err := Init(path, p1)
	if err != nil {
		t.Fatal(err)
	}
	rk.Use(func(b []byte) error { recoveryText = string(b); return nil })
	rk.Destroy()
	s, err = Open(path, p2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path, recoveryText
}

func passphrase(p string) *secret.Buffer { return secret.Take([]byte(p)) }

func rawDB(t *testing.T, p string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+p)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return db
}

func readAll(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return b
}

func liveBuffers() int { return secret.Budget().Live }

// ---- Init from scratch ----

func TestInitFromScratch(t *testing.T) {
	s, path, rec := scratch(t)
	infos, err := s.Slots(ctx)
	if err != nil || len(infos) != 2 {
		t.Fatalf("%v %v", infos, err)
	}
	kinds := map[string]int{}
	for _, i := range infos {
		kinds[i.Kind]++
	}
	if kinds[seal.SlotPassphrase] != 1 || kinds[seal.SlotRecovery] != 1 {
		t.Errorf("slots %v, want one of each kind", kinds)
	}
	// The head file exists from the start, mode 0600, and names the one audit
	// row Init wrote (the slot set the workspace starts with).
	st, err := os.Stat(path + ".head")
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("head file: %v %v", st, err)
	}
	if seq, _ := s.Head(); seq != 1 {
		t.Errorf("fresh head = %d, want 1", seq)
	}
	if n := s.Notices(); len(n) != 0 {
		t.Errorf("a fresh workspace has notices: %v", n)
	}
	put(t, s, counter, "1")
	putSecret(t, s, skey0, "sk")
	if err := s.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	s.Close()
	r, err := OpenWithRecovery(path, secret.Take([]byte(rec)))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if b, _ := get(r, counter); string(b) != "1" {
		t.Errorf("%q", b)
	}
}

// ---- H1: rekey ----

// heldRecovery remembers, per handle, the recovery key an operator would hold
// (the one printed at creation or by the last rekey), so a test helper can
// present it before the next rekey.
var heldRecovery sync.Map

func rekeyTo(t *testing.T, s *Store, p string) string {
	t.Helper()
	if cur, ok := heldRecovery.Load(s); ok {
		presentStd(t, s, cur.(string))
	}
	rk, err := s.ChangePassphraseRekey(ctx, passphrase(p))
	if err != nil {
		t.Fatal(err)
	}
	var text string
	rk.Use(func(b []byte) error { text = string(b); return nil })
	rk.Destroy()
	heldRecovery.Store(s, text)
	// What the CLI does once the key has been shown.
	if err := s.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	return text
}

func TestRekeyRevokesOldSlotsEvenIfPutBack(t *testing.T) {
	s, path, oldRecovery := scratch(t)
	put(t, s, counter, "before")
	putSecret(t, s, skey0, "the-key")
	oldID, err := s.AddPassphraseSlot(ctx, passphrase("old-pass"))
	if err != nil {
		t.Fatal(err)
	}
	var slotRow [11]any
	if err := s.db.QueryRow(`SELECT id,kind,kdf_memory_kib,kdf_passes,kdf_lanes,salt,key_commit,nonce,wrapped_key,bound,rec_hash FROM keyslots WHERE id=?`, oldID).
		Scan(&slotRow[0], &slotRow[1], &slotRow[2], &slotRow[3], &slotRow[4], &slotRow[5], &slotRow[6], &slotRow[7], &slotRow[8], &slotRow[9], &slotRow[10]); err != nil {
		t.Fatal(err)
	}
	oldWrapped := slotRow[8].([]byte)
	var oldMeta [2]any // key epoch and its MAC, to put back below
	s.db.QueryRow(`SELECT key_epoch, epoch_mac FROM meta`).Scan(&oldMeta[0], &oldMeta[1])
	oldMaster, err := copySecret(s.master)
	if err != nil {
		t.Fatal(err)
	}
	defer oldMaster.Destroy()
	oldKeys, err := seal.DeriveKeys(oldMaster)
	if err != nil {
		t.Fatal(err)
	}
	defer oldKeys.Destroy()
	var tagBefore []byte
	s.db.QueryRow(`SELECT lookup_tag FROM records WHERE kind='kes.counter'`).Scan(&tagBefore)

	newRecovery := rekeyTo(t, s, "new-pass")
	var newMeta [2]any
	s.db.QueryRow(`SELECT key_epoch, epoch_mac FROM meta`).Scan(&newMeta[0], &newMeta[1])

	// The records survive, under new keys, found through new lookup tags.
	if b, err := get(s, counter); err != nil || string(b) != "before" {
		t.Fatalf("record after rekey: %q %v", b, err)
	}
	k, err := s.Open(ctx, skey0)
	if err != nil {
		t.Fatal(err)
	}
	k.Destroy()
	var tagAfter []byte
	s.db.QueryRow(`SELECT lookup_tag FROM records WHERE kind='kes.counter'`).Scan(&tagAfter)
	if bytes.Equal(tagBefore, tagAfter) {
		t.Error("lookup tag did not change under the new index key")
	}
	put(t, s, counter, "after") // later records are written under the new keys
	if err := s.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	// Finding 12, the cryptographic property, independent of any gate: the OLD
	// master key cannot open a record sealed after the rekey, neither its
	// payload nor its owner blob.
	{
		var id, nonce, wrapped, owner, ct []byte
		var v int64
		if err := s.db.QueryRow(`SELECT id, version, nonce, wrapped_key, owner_sealed, ciphertext FROM records WHERE kind='kes.counter'`).
			Scan(&id, &v, &nonce, &wrapped, &owner, &ct); err != nil {
			t.Fatal(err)
		}
		sr := seal.SealedRecord{Nonce: nonce, WrappedKey: wrapped, Owner: owner, Ciphertext: ct}
		m := metaOf(s.ws, id, counter, seal.ClassSensitive, uint64(v))
		if _, err := oldKeys.OpenRecord(m, sr); !errors.Is(err, seal.ErrAuth) {
			t.Errorf("the old master key opened a record sealed after the rekey: %v", err)
		}
		if _, err := oldKeys.OpenOwner(s.ws, id, "kes.counter", sr); !errors.Is(err, seal.ErrAuth) {
			t.Errorf("the old master key opened an owner blob sealed after the rekey: %v", err)
		}
		if _, err := s.keys.OpenRecord(m, sr); err != nil { // control: the new keys do
			t.Errorf("control: %v", err)
		}
	}
	// The old wrapped key is gone from the live files, including the WAL.
	if bytes.Contains(readAll(t, path), oldWrapped) {
		t.Error("the removed slot's wrapped key is still in the database file")
	}
	if wal := readAll(t, path+"-wal"); bytes.Contains(wal, oldWrapped) {
		t.Errorf("the removed slot's wrapped key is still in the -wal file (%d bytes)", len(wal))
	}
	s.Close()

	// Nothing of the old credentials works.
	for name, open := range map[string]func() error{
		"old passphrase":        func() error { _, err := Open(path, passphrase("old-pass")); return err },
		"original passphrase":   func() error { _, err := Open(path, pw()); return err },
		"original recovery key": func() error { _, err := OpenWithRecovery(path, secret.Take([]byte(oldRecovery))); return err },
	} {
		if err := open(); !errors.Is(err, ErrWrongCredential) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Put the removed slot row back, as from a backup or a -wal remnant: it
	// unwraps to the OLD master key, which no longer protects anything, and
	// the store refuses it.
	db := rawDB(t, path)
	if _, err := db.Exec(`INSERT INTO keyslots (id,kind,kdf_memory_kib,kdf_passes,kdf_lanes,salt,key_commit,nonce,wrapped_key,bound,rec_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?)`, slotRow[:]...); err != nil {
		t.Fatal(err)
	}
	db.Close()
	_, err = Open(path, passphrase("old-pass"))
	// Format 3: the old slot binds another recovery public key hash than the
	// current slots, so the policy check refuses the table before any key is
	// derived (this test expected ErrKeyEpoch in format 2).
	if !errors.Is(err, ErrPolicyViolated) || errors.Is(err, ErrWrongCredential) {
		t.Errorf("re-inserted old slot: %v", err)
	}
	// With the slot AND the old meta row put back, the old credential unlocks
	// the old master key (nothing in the file can tell it from the current one
	// by the credential alone) -- and that key opens nothing sealed after the
	// rekey, and verification fails.
	db = rawDB(t, path)
	if _, err := db.Exec(`UPDATE meta SET key_epoch = ?, epoch_mac = ?`, oldMeta[0], oldMeta[1]); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, err = Open(path, passphrase("old-pass")); !errors.Is(err, ErrVerify) {
		t.Errorf("old slot with old meta: %v, want a verification error", err)
	}
	// The policy check is not part of the verification SkipVerify skips: the old
	// slot's table is refused even then (format 2 opened and failed at first use).
	if _, err := OpenWithOptions(path, passphrase("old-pass"), OpenOptions{SkipVerify: true}); !errors.Is(err, ErrPolicyViolated) {
		t.Fatalf("old slot with old meta, verification skipped: %v", err)
	}
	// Back to the new state for the rest of the test.
	db = rawDB(t, path)
	db.Exec(`DELETE FROM keyslots WHERE id = ?`, slotRow[0])
	db.Exec(`UPDATE meta SET key_epoch = ?, epoch_mac = ?`, newMeta[0], newMeta[1])
	db.Close()
	// The new credentials work, and the new recovery key too.
	n, err := Open(path, passphrase("new-pass"))
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := get(n, counter); string(b) != "after" {
		t.Errorf("%q", b)
	}
	n.Close()
	r, err := OpenWithRecovery(path, secret.Take([]byte(newRecovery)))
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
}

func TestRekeyResultHasOnePassphraseAndOneRecoverySlot(t *testing.T) {
	s, _, _ := scratch(t)
	if _, err := s.AddPassphraseSlot(ctx, passphrase("second")); err != nil {
		t.Fatal(err)
	}
	// (Format 3 binds one recovery key in every slot, so a second recovery slot is
	// refused; this test used one to get four slots, now it gets three.)
	if _, _, err := s.AddRecoverySlot(ctx); !errors.Is(err, ErrUseRekey) {
		t.Fatalf("a second recovery slot: %v", err)
	}
	if infos, _ := s.Slots(ctx); len(infos) != 3 {
		t.Fatalf("%d slots", len(infos))
	}
	rekeyTo(t, s, "only")
	infos, _ := s.Slots(ctx)
	kinds := map[string]int{}
	for _, i := range infos {
		kinds[i.Kind]++
	}
	if len(infos) != 2 || kinds[seal.SlotPassphrase] != 1 || kinds[seal.SlotRecovery] != 1 {
		t.Errorf("after rekey: %v", kinds)
	}
	// The slot that is open is the new passphrase slot.
	found := false
	for _, i := range infos {
		found = found || bytes.Equal(i.ID, s.slotID)
	}
	if !found {
		t.Error("the handle's slot id is not a current slot")
	}
}

func TestRekeyNeedsExactlyOnePassphrase(t *testing.T) {
	s, path, _ := scratch(t)
	put(t, s, counter, "x")
	before := readAll(t, path)
	for name, keep := range map[string][]Credential{
		"none":     nil,
		"empty":    {PassphraseCredential(secret.Take(nil))},
		"two":      {PassphraseCredential(passphrase("a")), PassphraseCredential(passphrase("b"))},
		"recovery": {{Kind: seal.SlotRecovery, Secret: secret.New(32)}},
		"mixed":    {PassphraseCredential(passphrase("a")), {Kind: seal.SlotRecovery, Secret: secret.New(32)}},
	} {
		if _, err := s.Rekey(ctx, keep); !errors.Is(err, ErrRekeyCredentials) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := s.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	_ = before
}

func TestRekeyIsAtomic(t *testing.T) {
	s, path, _ := scratch(t)
	put(t, s, counter, "x")
	put(t, s, rf("p", ports.KesVKey), "v")
	np := passphrase("new")
	defer np.Destroy()
	live := liveBuffers()
	if _, err := s.db.Exec(`CREATE TRIGGER boom BEFORE UPDATE ON records WHEN NEW.kind = 'kes.vkey' BEGIN SELECT RAISE(ABORT, 'boom'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ChangePassphraseRekey(ctx, np); err == nil {
		t.Fatal("rekey succeeded despite a failing write")
	}
	if got := liveBuffers(); got != live {
		t.Errorf("a failed rekey leaked %d guarded buffers", got-live)
	}
	s.db.Exec(`DROP TRIGGER boom`)
	if err := s.Verify(ctx); err != nil {
		t.Fatalf("a failed rekey changed the chain: %v", err)
	}
	s.Close()
	if r, err := Open(path, pw()); err != nil {
		t.Fatalf("old passphrase after a failed rekey: %v", err)
	} else {
		if b, _ := get(r, counter); string(b) != "x" {
			t.Error("records changed")
		}
		r.Close()
	}
}

func TestRekeySegmentOfTheAuditChain(t *testing.T) {
	s, _, _ := scratch(t)
	for _, v := range []string{"1", "2"} {
		put(t, s, counter, v)
	}
	oldSeq, oldMAC := s.Head()
	rekeyTo(t, s, "new")
	put(t, s, counter, "3")
	res, err := s.VerifyDetailed(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Notices) == 0 || !strings.Contains(res.Notices[0], "the MACs of the rows before sequence 4 were made under a previous key") {
		t.Errorf("notices %v", res.Notices)
	}
	var kind string
	var prev []byte
	s.db.QueryRow(`SELECT kind, prev_mac FROM audit WHERE seq = ?`, oldSeq+1).Scan(&kind, &prev)
	if kind != "rollover" || !bytes.Equal(prev, oldMAC) {
		t.Errorf("row %d: kind %q, prev_mac links to the old head: %v", oldSeq+1, kind, bytes.Equal(prev, oldMAC))
	}
	// A rollover row that does not name the previous row is caught.
	exec(t, s, `UPDATE audit SET prev_mac = zeroblob(32) WHERE seq = 4`)
	if err := s.Verify(ctx); !errors.Is(err, ErrVerify) {
		t.Errorf("modified rollover: %v", err)
	}
	exec(t, s, `UPDATE audit SET prev_mac = ? WHERE seq = 4`, oldMAC)
	if err := s.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	// The unverified part is not wholly unguarded: its order is checked.
	exec(t, s, `DELETE FROM audit WHERE seq = 1`)
	if err := s.Verify(ctx); !errors.Is(err, ErrVerify) {
		t.Errorf("row removed from the old segment: %v", err)
	}
}

func TestRekeyTwiceAndWithSecretsAndNumberedRecords(t *testing.T) {
	s, path, _ := scratch(t)
	var refs []ports.Ref
	for i := 0; i < 4; i++ {
		r := rf("pool-a", ports.KesSKey, i)
		putSecret(t, s, r, strings.Repeat("k", 10+i)) // writes the verification key and role history too
		refs = append(refs, r)
	}
	rekeyTo(t, s, "second")
	rekeyTo(t, s, "third")
	for i, r := range refs {
		k, err := s.Open(ctx, r)
		if err != nil {
			t.Fatalf("%s: %v", r.Kind, err)
		}
		if k.Len() != 10+i {
			t.Errorf("secret %d has %d bytes", i, k.Len())
		}
		k.Destroy()
		if _, err := get(s, rf("pool-a", ports.KesVKey, i)); err != nil {
			t.Errorf("vkey %d: %v", i, err)
		}
	}
	if err := s.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	s.Close()
	r, err := Open(path, passphrase("third"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.Verify(ctx); err != nil {
		t.Fatal(err)
	}
}

// ---- M5: always a passphrase slot and a recovery slot ----

func TestSlotInvariantIsEnforcedInsideTheTransaction(t *testing.T) {
	s, _, _ := scratch(t)
	if err := s.RemoveSlot(ctx, nil); !errors.Is(err, ErrUseRekey) {
		t.Errorf("RemoveSlot: %v", err)
	}
	// Even if the file was edited so that a kind is missing, no slot
	// operation commits a state without one of each kind.
	exec(t, s, `DELETE FROM keyslots WHERE kind = 'recovery'`)
	if _, err := s.AddPassphraseSlot(ctx, passphrase("another")); !errors.Is(err, ErrLastSlot) {
		t.Errorf("AddPassphraseSlot on a workspace without a recovery slot: %v", err)
	}
	if infos, _ := s.Slots(ctx); len(infos) != 1 {
		t.Errorf("the refused operation changed the slots: %d", len(infos))
	}
	// A recovery key is bound in every slot of a format 3 workspace, so the
	// missing recovery slot is not added back: a rekey makes a new one.
	if _, _, err := s.AddRecoverySlot(ctx); !errors.Is(err, ErrUseRekey) {
		t.Errorf("AddRecoverySlot: %v", err)
	}
}

// ---- M1: rollback ----

func TestTailTruncationAndRevertIsCaughtByTheHeadFile(t *testing.T) {
	s, p, _ := scratch(t)
	put(t, s, counter, "1")
	bk := filepath.Join(t.TempDir(), "old.db")
	if err := s.Backup(ctx, bk); err != nil {
		t.Fatal(err)
	}
	put(t, s, counter, "2")
	headBefore := readAll(t, p+".head")
	s.Close()
	// The attack: drop the newest audit row and put the old record back.
	raw, old := rawDB(t, p), rawDB(t, bk)
	var v, at int64
	var n, wk, ow, ct []byte
	if err := old.QueryRow(`SELECT version,nonce,wrapped_key,owner_sealed,ciphertext,updated_at FROM records`).Scan(&v, &n, &wk, &ow, &ct, &at); err != nil {
		t.Fatal(err)
	}
	raw.Exec(`DELETE FROM audit WHERE seq = (SELECT max(seq) FROM audit)`)
	raw.Exec(`UPDATE records SET version=?,nonce=?,wrapped_key=?,owner_sealed=?,ciphertext=?,updated_at=?`, v, n, wk, ow, ct, at)
	raw.Close()
	// The file now verifies by itself, which is the review's reproduction;
	// opening it is refused because the head file remembers sequence 2.
	_, err := Open(p, pw())
	if !errors.Is(err, ErrRolledBack) {
		t.Fatalf("Open: %v, want ErrRolledBack", err)
	}
	if !bytes.Equal(readAll(t, p+".head"), headBefore) {
		t.Error("a refused open rewrote the head file")
	}
	// A deliberate restore is possible, and the head file then follows.
	s2, err := OpenWithOptions(p, pw(), OpenOptions{AcceptRollback: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if seq, _ := s2.Head(); seq != 2 {
		t.Errorf("head after accepting the rollback: %d", seq)
	}
	if err := s2.Verify(ctx); err != nil {
		t.Errorf("accepted store: %v", err)
	}
	if b := readAll(t, p+".head"); bytes.Equal(b, headBefore) {
		t.Error("the head file was not updated by the accepted rollback")
	}
}

func TestWipedStoreWithHeadFileIsReported(t *testing.T) {
	s, p, _ := scratch(t)
	put(t, s, counter, "1")
	put(t, s, counter, "2")
	// (c): an initialised but empty store whose head file says seq > 0.
	exec(t, s, `DELETE FROM audit`)
	exec(t, s, `DELETE FROM records`)
	err := s.Verify(ctx)
	var ve *VerifyError
	if !errors.As(err, &ve) || !strings.Contains(err.Error(), "older than its head file") {
		t.Fatalf("Verify of a wiped store: %v", err)
	}
	s.Close()
	if _, err := Open(p, pw()); !errors.Is(err, ErrRolledBack) {
		t.Errorf("Open of a wiped store: %v", err)
	}
}

func TestHeadFile(t *testing.T) {
	s, p, _ := scratch(t)
	put(t, s, counter, "1")
	seq, mac := s.Head()
	if seq != 2 {
		t.Fatalf("seq %d", seq)
	}
	want := "spo-workbench-head 1\nworkspace " + hex.EncodeToString(s.ws) + "\nseq 2\nmac " + hex.EncodeToString(mac) + "\n"
	if got := string(readAll(t, p+".head")); got != want {
		t.Errorf("head file:\n%s\nwant:\n%s", got, want)
	}
	if st, _ := os.Stat(p + ".head"); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %o", st.Mode().Perm())
	}
	// No temporary files are left behind.
	ents, _ := os.ReadDir(filepath.Dir(p))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".head-") {
			t.Errorf("stray %s", e.Name())
		}
	}
	s.Close()

	// Missing: recreated, with a notice.
	os.Remove(p + ".head")
	s2, err := Open(p, pw())
	if err != nil {
		t.Fatal(err)
	}
	if n := s2.Notices(); len(n) != 1 || !strings.Contains(n[0], "head file was missing") {
		t.Errorf("notices %v", n)
	}
	if got := string(readAll(t, p+".head")); got != want {
		t.Errorf("recreated head file differs: %q", got)
	}
	s2.Close()

	// The store is ahead of the head file (a crash between commit and head
	// write): accepted, and the head file catches up.
	old := readAll(t, p+".head")
	s3, _ := Open(p, pw())
	put(t, s3, counter, "2")
	s3.Close()
	os.WriteFile(p+".head", old, 0o600)
	s4, err := Open(p, pw())
	if err != nil {
		t.Fatalf("store ahead of its head file: %v", err)
	}
	if seq, _ := s4.Head(); seq != 3 {
		t.Errorf("head %d", seq)
	}
	if bytes.Equal(readAll(t, p+".head"), old) {
		t.Error("head file did not catch up")
	}
	s4.Close()

	// Garbage or another workspace's head file: refused, never trusted.
	os.WriteFile(p+".head", []byte("garbage"), 0o600)
	if _, err := Open(p, pw()); !errors.Is(err, ErrHeadMismatch) {
		t.Errorf("garbage head file: %v", err)
	}
	other, op, _ := scratch(t)
	other.Close()
	os.WriteFile(p+".head", readAll(t, op+".head"), 0o600)
	if _, err := Open(p, pw()); !errors.Is(err, ErrHeadMismatch) {
		t.Errorf("another workspace's head file: %v", err)
	}
	s5, err := OpenWithOptions(p, pw(), OpenOptions{AcceptRollback: true})
	if err != nil {
		t.Fatal(err)
	}
	s5.Close()
}

// M1(a): the lookup tag and the kind are in the hash the audit covers.
func TestVerifyCoversTagAndKind(t *testing.T) {
	s, _, _ := scratch(t)
	a, b := rf("p", ports.KesVKey, 0), rf("p", ports.KesVKey, 1)
	put(t, s, a, "va")
	put(t, s, b, "vb")
	ta, _ := s.tag(a)
	tb, _ := s.tag(b)
	exec(t, s, `UPDATE records SET lookup_tag = x'00' WHERE lookup_tag = ?`, ta)
	exec(t, s, `UPDATE records SET lookup_tag = ? WHERE lookup_tag = ?`, ta, tb)
	exec(t, s, `UPDATE records SET lookup_tag = ? WHERE lookup_tag = x'00'`, tb)
	if err := s.Verify(ctx); !errors.Is(err, ErrVerify) {
		t.Errorf("swapped lookup tags: %v", err)
	}
}

// ---- M2: secrets ----

func TestSecretCiphertextLengthHidesThePayloadSize(t *testing.T) {
	s, _, _ := scratch(t)
	size := func(ref ports.Ref) int {
		var n int
		s.db.QueryRow(`SELECT length(ciphertext) FROM records WHERE kind = ? AND version >= 1 AND lookup_tag = ?`, string(ref.Kind), mustTag(t, s, ref)).Scan(&n)
		return n
	}
	r12, r24 := rf("w", ports.AddrSKey), rf("w2", ports.AddrSKey)
	putSecret(t, s, r12, strings.Repeat("abandon ", 12))
	putSecret(t, s, r24, strings.Repeat("abandon ", 24))
	if a, b := size(r12), size(r24); a != b || a != 256+16 {
		t.Errorf("ciphertext sizes %d and %d, want both %d", a, b, 256+16)
	}
	// Sensitive payloads are not padded.
	put(t, s, counter, "abc")
	if n := size(counter); n != 3+16 {
		t.Errorf("sensitive ciphertext %d", n)
	}
	// The secrets come back exactly.
	k, err := s.Open(ctx, r24)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Destroy()
	if k.Len() != len(strings.Repeat("abandon ", 24)) {
		t.Errorf("opened %d bytes", k.Len())
	}
}

func mustTag(t *testing.T, s *Store, r ports.Ref) []byte {
	t.Helper()
	tag, err := s.tag(r)
	if err != nil {
		t.Fatal(err)
	}
	return tag
}

// ---- M3: guarded memory is released and its exhaustion is an error ----

func TestEveryBufferIsReleased(t *testing.T) {
	s, _, _ := scratch(t)
	putSecret(t, s, skey0, "the-key")
	start := liveBuffers()
	for i := 0; i < 25; i++ {
		putSecret(t, s, skey0, "the-key")
		k, err := s.Open(ctx, skey0)
		if err != nil {
			t.Fatal(err)
		}
		k.Destroy()
		put(t, s, counter, "x")
		// Failure paths: missing, wrong kind, a failing callback, a delete.
		s.Open(ctx, rf("nope", ports.KesSKey))
		s.Open(ctx, counter)
		sec := secret.Take([]byte("s"))
		s.Update(ctx, func(w ports.Writer) error {
			putKeyW(w, skey0, sec)
			return errors.New("abort")
		})
		sec.Destroy()
		s.Update(ctx, func(w ports.Writer) error { return w.Delete(counter) })
	}
	if got := liveBuffers(); got != start {
		t.Errorf("live guarded buffers: %d at the start, %d after 25 cycles", start, got)
	}
	// Opening and closing handles too.
	p := s.path
	s.Close()
	after := liveBuffers()
	for i := 0; i < 3; i++ {
		good, bad := pw(), passphrase("wrong")
		h, err := Open(p, good)
		if err != nil {
			t.Fatal(err)
		}
		h.Close()
		if _, err := Open(p, bad); err == nil {
			t.Fatal("opened with a wrong passphrase")
		}
		good.Destroy()
		bad.Destroy()
	}
	if got := liveBuffers(); got != after {
		t.Errorf("live guarded buffers after open/close cycles: %d, want %d", got, after)
	}
}

// R8 of the review: opening many secrets exhausted mlock and panicked (after
// wiping every buffer in the process). Now it is an error.
func TestManyOpenSecretsEndInAnErrorNotAPanic(t *testing.T) {
	// Finding 11: the test must not depend on the machine's limit. When it is
	// unlimited, run the test again in a child process with a finite one.
	if secret.Budget().Unlimited && os.Getenv("SPO_TEST_MEMLOCK") == "" {
		runWithMemlock(t, "TestManyOpenSecretsEndInAnErrorNotAPanic", 16<<20, nil)
		return
	}
	s, _, _ := scratch(t)
	putSecret(t, s, skey0, "k")
	var held []*secret.Buffer
	defer func() {
		for _, b := range held {
			b.Destroy()
		}
	}()
	var failed error
	for i := 0; i < 20000 && failed == nil; i++ {
		b, err := s.Open(ctx, skey0)
		if err != nil {
			failed = err
			break
		}
		held = append(held, b)
	}
	if failed == nil {
		t.Fatal("RLIMIT_MEMLOCK is still unlimited in the child process")
	}
	if !errors.Is(failed, secret.ErrMemoryLimit) {
		t.Fatalf("error after %d secrets: %v", len(held), failed)
	}
	// Everything held is intact (memguard did not purge), and the store works
	// as soon as some memory is released.
	if err := held[0].Use(func([]byte) error { return nil }); err != nil {
		t.Fatalf("a held secret was wiped: %v", err)
	}
	for _, b := range held[:50] {
		b.Destroy()
	}
	held = held[50:]
	if _, err := get(s, counter); !errors.Is(err, ports.ErrNotFound) {
		t.Errorf("store after the limit: %v", err)
	}
	if err := s.Update(ctx, func(w ports.Writer) error { return putKeyW(w, skey0, secret.Take([]byte("again"))) }); err != nil {
		t.Errorf("update after the limit: %v", err)
	}
}

// ---- M4: re-entrancy ----

func TestNestedCallsReturnErrReentrant(t *testing.T) {
	s, _, _ := scratch(t)
	putSecret(t, s, skey0, "k")
	short := func() (context.Context, context.CancelFunc) { return context.WithTimeout(ctx, 200*time.Millisecond) }
	nested := map[string]func(c context.Context) error{
		"Open inside Update": func(c context.Context) error { b, err := s.Open(c, skey0); b.Destroy(); return err },
		"View inside Update": func(c context.Context) error { return s.View(c, func(ports.Reader) error { return nil }) },
		"Verify":             func(c context.Context) error { return s.Verify(c) },
	}
	for name, f := range nested {
		var got error
		if err := s.Update(ctx, func(w ports.Writer) error {
			c, cancel := short()
			defer cancel()
			got = f(c)
			return nil
		}); err != nil {
			t.Errorf("%s: outer update failed: %v", name, err)
		}
		if !errors.Is(got, ErrReentrant) || !errors.Is(got, context.DeadlineExceeded) || !strings.Contains(got.Error(), "callback") {
			t.Errorf("%s: %v, want ErrReentrant wrapping the context error", name, got)
		}
	}
	var got error
	s.View(ctx, func(ports.Reader) error {
		c, cancel := short()
		defer cancel()
		got = s.Update(c, func(w ports.Writer) error { return nil })
		return nil
	})
	if !errors.Is(got, ErrReentrant) {
		t.Errorf("Update inside View: %v", got)
	}
	if _, err := s.Open(ctx, skey0); err != nil {
		t.Errorf("store after nested calls: %v", err)
	}
}

// Finding 6: legitimate concurrent callers on one handle wait; they are not
// refused after a timeout.
func TestConcurrentCallersWaitInsteadOfFailing(t *testing.T) {
	s, _, _ := scratch(t)
	put(t, s, counter, "1")
	var wg sync.WaitGroup
	errs := make(chan error, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- s.View(ctx, func(ports.Reader) error { time.Sleep(700 * time.Millisecond); return nil })
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Errorf("a concurrent View failed: %v", e)
		}
	}
}

// Finding 6: Close waits for a running operation, never fails for busy, and is
// idempotent.
func TestCloseWaitsAndIsIdempotent(t *testing.T) {
	s, _, _ := scratch(t)
	started := make(chan struct{})
	go s.View(ctx, func(ports.Reader) error { close(started); time.Sleep(600 * time.Millisecond); return nil })
	<-started
	t0 := time.Now()
	if err := s.Close(); err != nil {
		t.Fatalf("Close while busy: %v", err)
	}
	if time.Since(t0) < 300*time.Millisecond {
		t.Error("Close did not wait for the running operation")
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestOpenSecretInsideAnUpdate(t *testing.T) {
	s, _, _ := scratch(t)
	putSecret(t, s, skey0, "stored")
	err := s.Update(ctx, func(w ports.Writer) error {
		o, ok := w.(interface {
			OpenSecret(ports.Ref) (*secret.Buffer, error)
		})
		if !ok {
			t.Fatal("the writer has no OpenSecret")
		}
		b, err := o.OpenSecret(skey0)
		if err != nil {
			return err
		}
		b.Use(func(x []byte) error {
			if string(x) != "stored" {
				t.Errorf("read %q", x)
			}
			return nil
		})
		b.Destroy()
		// And it sees this update's own writes.
		putKeyW(w, skey0, secret.Take([]byte("staged")))
		b, err = o.OpenSecret(skey0)
		if err != nil {
			return err
		}
		defer b.Destroy()
		return b.Use(func(x []byte) error {
			if string(x) != "staged" {
				t.Errorf("staged read %q", x)
			}
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
}

// ---- L1: unlocking ----

func TestJunkSlotsDoNotBlockUnlock(t *testing.T) {
	p := fresh(t)
	db := rawDB(t, p)
	junk := []string{
		// A weak slot sorting before any real one (ids are 0x00...).
		`INSERT INTO keyslots (id,kind,kdf_memory_kib,kdf_passes,kdf_lanes,salt,key_commit,nonce,wrapped_key) VALUES (zeroblob(16),'passphrase',8,1,1,randomblob(16),randomblob(32),randomblob(24),randomblob(48))`,
		// Above the ceiling: refused before Argon2id runs (2 GiB would take seconds and memory).
		`INSERT INTO keyslots (id,kind,kdf_memory_kib,kdf_passes,kdf_lanes,salt,key_commit,nonce,wrapped_key) VALUES (x'00000000000000000000000000000001','passphrase',2097152,3,4,randomblob(16),randomblob(32),randomblob(24),randomblob(48))`,
		// Malformed: NULL salt.
		`INSERT INTO keyslots (id,kind,kdf_memory_kib,kdf_passes,kdf_lanes,salt,key_commit,nonce,wrapped_key) VALUES (x'00000000000000000000000000000002','passphrase',65536,3,1,NULL,randomblob(32),randomblob(24),randomblob(48))`,
	}
	for _, q := range junk {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	// Planted slot rows never make the credential "wrong"; they do fail the
	// verification Open runs (the slot set no longer matches the audit chain).
	if _, err := Open(p, pw()); !errors.Is(err, ErrVerify) || errors.Is(err, ErrWrongCredential) {
		t.Fatalf("junk slots, verifying open: %v", err)
	}
	s, err := OpenWithOptions(p, pw(), OpenOptions{SkipVerify: true})
	if err != nil {
		t.Fatalf("junk slots blocked the unlock: %v", err)
	}
	defer s.Close()
	if n := s.Notices(); len(n) < 3 {
		t.Errorf("skipped slots were not reported: %v", n)
	}
	for _, n := range s.Notices() {
		if strings.Contains(n, tmplRecovery) {
			t.Error("a notice contains the recovery key")
		}
	}
}

func TestUnlockWorkIsCapped(t *testing.T) {
	// Real slots at the accepted minimum cost 64 MiB x 3 passes = 192 each.
	// With the cap at 300 the unlock derives one key and skips the rest, and
	// the correct passphrase, sitting in a skipped slot, is not tried.
	old := maxUnlockWork
	maxUnlockWork = 300
	defer func() { maxUnlockWork = old }()
	p := fresh(t)
	s, err := Open(p, pw()) // not the recovery key: no slot is added on a recovery handle
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if _, err := s.AddPassphraseSlot(ctx, passphrase("x1")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPassphraseSlot(ctx, passphrase("x2")); err != nil {
		t.Fatal(err)
	}
	s.Close()
	db := rawDB(t, p)
	rows, _ := db.Query(`SELECT id FROM keyslots WHERE kind='passphrase' ORDER BY id`)
	var ids [][]byte
	for rows.Next() {
		var id []byte
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	db.Close()
	if len(ids) != 3 {
		t.Fatalf("%d passphrase slots", len(ids))
	}
	// Whichever slot holds the real passphrase, at most one derivation runs
	// before the cap, so at least one of the three is reported as skipped.
	_, err = Open(p, passphrase("matches none of them"))
	if !errors.Is(err, ErrWrongCredential) || strings.Count(err.Error(), "most key-derivation work") != 2 {
		t.Errorf("capped unlock: %v", err)
	}
}

// ---- L4: restore ----

func TestRestoreRefusesOtherWorkspaceAndOlderBackup(t *testing.T) {
	// a record that is not a KES counter: this test is about the head and the
	// refusals, not about the counter rule (restore_counters_test.go)
	counter := rf("p", ports.AddrFile)
	a, pa, _ := scratch(t)
	put(t, a, counter, "1")
	old := filepath.Join(t.TempDir(), "old.db")
	oldHead, err := a.BackupWithHead(ctx, old)
	if err != nil {
		t.Fatal(err)
	}
	if oldHead.Seq != 2 {
		t.Fatalf("backup head %v", oldHead)
	}
	put(t, a, counter, "2")
	cur := filepath.Join(t.TempDir(), "cur.db")
	curHead, _ := a.BackupWithHead(ctx, cur)
	if curHead.Seq != 3 {
		t.Fatalf("backup head %v", curHead)
	}
	a.Close()

	// An older backup over a newer workspace.
	if err := Restore(old, pa, pw(), true); !errors.Is(err, ErrOlderBackup) {
		t.Errorf("older backup: %v", err)
	}
	if b, err := func() ([]byte, error) { s := openAt2(t, pa); defer s.Close(); return get(s, counter) }(); err != nil || string(b) != "2" {
		t.Errorf("a refused restore changed the workspace: %q %v", b, err)
	}
	// Explicitly allowed.
	if err := RestoreWithOptions(old, pa, pw(), RestoreOptions{Overwrite: true, AllowOlder: true}); err != nil {
		t.Errorf("allowed older backup: %v", err)
	}
	// The head file followed the restore, so the restored workspace opens.
	if s := openAt2(t, pa); true {
		if seq, _ := s.Head(); seq != 2 {
			t.Errorf("head after restore: %d", seq)
		}
		s.Close()
	}
	// A newer (or equal) backup over an older workspace is fine.
	if err := Restore(cur, pa, pw(), true); err != nil {
		t.Errorf("newer backup: %v", err)
	}
	if err := Restore(cur, pa, pw(), true); err != nil {
		t.Errorf("equal backup: %v", err)
	}
	// A backup of another workspace.
	b, _, _ := scratch(t)
	other := filepath.Join(t.TempDir(), "other.db")
	b.Backup(ctx, other)
	b.Close()
	if err := Restore(other, pa, pw(), true); !errors.Is(err, ErrOtherWorkspace) {
		t.Errorf("other workspace: %v", err)
	}
	if err := RestoreWithOptions(other, pa, pw(), RestoreOptions{Overwrite: true, AllowOtherWorkspace: true}); err != nil {
		t.Errorf("allowed other workspace: %v", err)
	}
}

func openAt2(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(path, pw())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRestoreNeedsTheWorkspaceClosed(t *testing.T) {
	a, pa, _ := scratch(t)
	put(t, a, counter, "1")
	bk := filepath.Join(t.TempDir(), "b.db")
	if err := a.Backup(ctx, bk); err != nil {
		t.Fatal(err)
	}
	// Open handle: its shared lock excludes the restore's exclusive one (and
	// its -wal file is also refused).
	if err := Restore(bk, pa, pw(), true); err == nil {
		t.Fatal("restored over an open workspace")
	}
	a.Close()
	h := openAt2(t, pa)
	h.Close()
	if err := Restore(bk, pa, pw(), true); err != nil {
		t.Fatalf("after closing: %v", err)
	}
	// The lock itself, without WAL files in the way.
	l, err := lockFile(pa, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := Restore(bk, pa, pw(), true); !errors.Is(err, ErrLocked) {
		t.Errorf("restore while a handle holds the file: %v", err)
	}
	l.Close()
	// The counter rule reads the destination read-only, which can leave an empty
	// -wal and -shm (a read-only connection cannot delete them); the swap and the
	// next open remove them. Nothing of the workspace may be in them.
	if st, err := os.Stat(pa + "-wal"); err == nil && st.Size() != 0 {
		t.Errorf("a -wal file with %d bytes was left behind", st.Size())
	}
}

func TestBackupReturnsItsHead(t *testing.T) {
	s, _, _ := scratch(t)
	put(t, s, counter, "1")
	put(t, s, counter, "2")
	h, err := s.BackupWithHead(ctx, filepath.Join(t.TempDir(), "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	seq, mac := s.Head()
	if h.Seq != seq || !bytes.Equal(h.MAC, mac) {
		t.Errorf("backup head %v, store head %d %x", h, seq, mac)
	}
	res, err := s.VerifyDetailed(ctx)
	if err != nil || res.Head.Seq != seq || !bytes.Equal(res.Head.MAC, mac) {
		t.Errorf("verify head %v %v", res.Head, err)
	}
}

// ---- L5: a wrong credential does not touch the file ----

func TestWrongPassphraseDoesNotModifyTheFile(t *testing.T) {
	s, p, _ := scratch(t)
	put(t, s, counter, "1")
	bk := filepath.Join(t.TempDir(), "plain.db") // a backup is not in WAL mode
	if err := s.Backup(ctx, bk); err != nil {
		t.Fatal(err)
	}
	s.Close()
	before := readAll(t, bk)
	if _, err := Open(bk, passphrase("wrong")); !errors.Is(err, ErrWrongCredential) {
		t.Fatal(err)
	}
	if !bytes.Equal(before, readAll(t, bk)) {
		t.Error("a wrong passphrase modified the file (journal mode or migration)")
	}
	for _, side := range []string{"-wal", "-shm", ".head"} {
		if _, err := os.Stat(bk + side); err == nil {
			t.Errorf("a wrong passphrase created %s", side)
		}
	}
	// The right one then switches it to WAL mode and records a head.
	h, err := Open(bk, pw())
	if err != nil {
		t.Fatal(err)
	}
	h.Close()
	if bytes.Equal(before, readAll(t, bk)) {
		t.Error("expected the successful open to switch the journal mode")
	}
	_ = p
}

func TestFileOwnedByAnotherUserIsRefused(t *testing.T) {
	_, p, _ := scratch(t)
	old := currentUID
	defer func() { currentUID = old }()
	currentUID = func() int { return old() + 1 }
	if _, err := Open(p, pw()); err == nil || !strings.Contains(err.Error(), "owned by another user") {
		t.Errorf("foreign-owned file: %v", err)
	}
	currentUID = old
	s, err := Open(p, pw())
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
}

// ---- slot key commitment ----

func TestSlotCommitmentIsStoredAndChecked(t *testing.T) {
	_, p, rec := scratch(t)
	db := rawDB(t, p)
	var c []byte
	db.QueryRow(`SELECT key_commit FROM keyslots WHERE kind='recovery'`).Scan(&c)
	if len(c) != 32 {
		t.Fatalf("commitment %x", c)
	}
	db.Exec(`UPDATE keyslots SET key_commit = zeroblob(32) WHERE kind='recovery'`)
	db.Close()
	if _, err := OpenWithRecovery(p, secret.Take([]byte(rec))); !errors.Is(err, ErrWrongCredential) {
		t.Errorf("slot with a wrong commitment: %v", err)
	}
}

// ---- audit of slot operations ----

func TestSlotOperationsAreAudited(t *testing.T) {
	s, _, _ := scratch(t)
	put(t, s, counter, "1")
	if _, err := s.AddPassphraseSlot(ctx, passphrase("two")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPassphraseSlot(ctx, passphrase("two-b")); err != nil { // was AddRecoverySlot (format 2)
		t.Fatal(err)
	}
	rekeyTo(t, s, "three")
	rows, err := s.db.Query(`SELECT kind FROM audit ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for rows.Next() {
		var k string
		rows.Scan(&k)
		kinds = append(kinds, k)
	}
	rows.Close()
	if got := strings.Join(kinds, ","); got != "slots,update,slots,slots,rollover" {
		t.Errorf("audit kinds %s", got)
	}
	if err := s.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	// Nothing secret in the file's audit rows: the touched list holds ids,
	// versions and hashes, and the events are sealed.
	var ev []byte
	s.db.QueryRow(`SELECT event FROM audit WHERE seq = 3`).Scan(&ev)
	if bytes.Contains(ev, []byte("passphrase")) {
		t.Error("slot event is readable in the file")
	}
}

// ---- errors do not carry names ----

func TestErrorsDoNotContainOperatorNames(t *testing.T) {
	s, _, _ := scratch(t)
	const name = "MARKERPOOLNAME"
	ref := rf(name, ports.KesVKey)
	put(t, s, ref, "v")
	exec(t, s, `UPDATE records SET ciphertext = CAST(substr(ciphertext,1,1) || CASE WHEN substr(ciphertext,2,1) = x'00' THEN x'01' ELSE x'00' END || substr(ciphertext,3) AS BLOB)`)
	_, err := get(s, ref)
	if strings.Contains(fmt.Sprint(err), name) {
		t.Errorf("record map error contains the name: %q", err)
	}
	trustRows(t, s)
	_, err = get(s, ref)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatal(err)
	}
	if strings.Contains(err.Error(), name) {
		t.Errorf("error text contains the name: %q", err)
	}
	var re *RefError
	if !errors.As(err, &re) || re.Ref != ref {
		t.Errorf("the ref is not carried in a *RefError: %v", err)
	}
	// Secrets, sealing failures and PutSecret errors too.
	sref := rf(name, ports.KesSKey)
	empty := secret.Take(nil)
	err = s.Update(ctx, func(w ports.Writer) error { return putKeyW(w, sref, empty) })
	if err == nil || strings.Contains(err.Error(), name) {
		t.Errorf("PutSecret error: %v", err)
	}
	if _, err := s.Open(ctx, sref); !errors.Is(err, ports.ErrNotFound) || strings.Contains(err.Error(), name) {
		t.Errorf("Open error: %v", err)
	}
}

// ---- a ciphertext moved between workspaces ----

func TestRecordMovedToAnotherWorkspaceFails(t *testing.T) {
	a, _, _ := scratch(t)
	b, _, _ := scratch(t)
	ref := rf("p", ports.KesVKey)
	put(t, a, ref, "secret-ish")
	put(t, b, ref, "placeholder")
	// Same reference, so b has a row under its own tag for this ref. Replace
	// its payload parts by a's (same id too, so only the workspace differs).
	var id, nonce, wk, ow, ct []byte
	var ver int64
	if err := a.db.QueryRow(`SELECT id, version, nonce, wrapped_key, owner_sealed, ciphertext FROM records`).Scan(&id, &ver, &nonce, &wk, &ow, &ct); err != nil {
		t.Fatal(err)
	}
	exec(t, b, `UPDATE records SET id=?, version=?, nonce=?, wrapped_key=?, owner_sealed=?, ciphertext=?`, id, ver, nonce, wk, ow, ct)
	trustRows(t, b)
	if _, err := get(b, ref); !errors.Is(err, ErrCorrupt) {
		t.Errorf("record from another workspace opened: %v", err)
	}
	// Even with the other workspace's master key it is bound to its workspace:
	// seal-level test in the seal package (TestCiphertextMovedBetweenWorkspaces).
}
