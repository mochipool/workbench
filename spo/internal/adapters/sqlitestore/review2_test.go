package sqlitestore

// Regression tests for the second security review of the store. One section
// per finding; each fails without its fix.

import (
	"bytes"
	"errors"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// runWithMemlock runs one test of this package again in a child process whose
// RLIMIT_MEMLOCK is limit bytes, and fails t with the child's output if it
// fails.
func runWithMemlock(t *testing.T, name string, limit uint64, env []string) {
	t.Helper()
	cmd := osexec.Command(os.Args[0], "-test.run=^"+name+"$", "-test.count=1")
	cmd.Env = append(append(os.Environ(), "SPO_TEST_MEMLOCK="+strconv.FormatUint(limit, 10)), env...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child with RLIMIT_MEMLOCK=%d: %v\n%s", limit, err, out)
	}
}

func recordCount(t *testing.T, path string) (records, auditRows int) {
	t.Helper()
	db := rawDB(t, path)
	defer db.Close()
	db.QueryRow(`SELECT count(*) FROM records`).Scan(&records)
	db.QueryRow(`SELECT count(*) FROM audit`).Scan(&auditRows)
	return
}

// ---- 1: a handle that outlived another handle's rekey ----

func TestStaleHandleAfterRekeyDoesNothing(t *testing.T) {
	a, path, _ := scratch(t)
	put(t, a, counter, "1")
	b, err := Open(path, pw())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	// With b open, a cannot rekey: the exclusive lock is refused, nothing
	// changes, and both handles keep their locks.
	if _, err := a.ChangePassphraseRekey(ctx, passphrase("np")); !errors.Is(err, ErrLocked) {
		t.Fatalf("rekey with another handle open: %v, want ErrLocked", err)
	}
	if err := b.Update(ctx, func(w ports.Writer) error { return w.Put(counter, []byte("2")) }); err != nil {
		t.Fatalf("handle b after a refused rekey: %v", err)
	}
	if _, err := Open(path, pw()); err != nil { // shared lock still held by a and b: more shared opens work
		t.Fatalf("open after a refused rekey: %v", err)
	}

	// A process that does not honour the lock (an older binary, another
	// platform): simulate by dropping b's lock. Now the rekey goes through and
	// b is stale.
	b.lock.Close()
	rekeyTo(t, a, "np")
	records, rows := recordCount(t, path)
	stale := map[string]func() error{
		"Update": func() error {
			return b.Update(ctx, func(w ports.Writer) error { return w.Put(counter, []byte("stale")) })
		},
		"View":   func() error { return b.View(ctx, func(ports.Reader) error { return nil }) },
		"Open":   func() error { k, err := b.Open(ctx, skey0); k.Destroy(); return err },
		"Verify": func() error { return b.Verify(ctx) },
		"Slots":  func() error { _, err := b.Slots(ctx); return err },
		"AddPassphraseSlot": func() error {
			_, err := b.AddPassphraseSlot(ctx, passphrase("x"))
			return err
		},
		"AddRecoverySlot": func() error { _, _, err := b.AddRecoverySlot(ctx); return err },
		"Rekey": func() error {
			_, err := b.ChangePassphraseRekey(ctx, passphrase("y"))
			return err
		},
	}
	for name, f := range stale {
		if err := f(); !errors.Is(err, ErrStaleHandle) {
			t.Errorf("%s on a stale handle: %v, want ErrStaleHandle", name, err)
		}
	}
	if r2, rows2 := recordCount(t, path); r2 != records || rows2 != rows {
		t.Errorf("a stale handle changed the file: records %d->%d, audit rows %d->%d", records, r2, rows, rows2)
	}
	b.Close()
	a.Close()
	n, err := Open(path, passphrase("np")) // the new credential still opens, and verifies
	if err != nil {
		t.Fatalf("after the stale writes: %v", err)
	}
	if v, err := get(n, counter); err != nil || string(v) != "2" {
		t.Errorf("record after rekey: %q %v", v, err)
	}
	n.Close()
}

// ---- 2: unlock is gated on the slots and the key epoch only ----

func TestAuditCorruptionIsNeverAWrongCredential(t *testing.T) {
	s, path, rec := scratch(t)
	put(t, s, counter, "1")
	s.Close()
	db := rawDB(t, path)
	db.Exec(`UPDATE audit SET at = at + 1 WHERE seq = (SELECT max(seq) FROM audit)`)
	db.Close()
	for name, open := range map[string]func() (*Store, error){
		"passphrase": func() (*Store, error) { return Open(path, pw()) },
		"recovery":   func() (*Store, error) { return OpenWithRecovery(path, passphrase(rec)) },
	} {
		_, err := open()
		if !errors.Is(err, ErrVerify) || errors.Is(err, ErrWrongCredential) || errors.Is(err, ErrKeyEpoch) {
			t.Errorf("%s with a modified newest audit row: %v, want a verification error", name, err)
		}
	}
	o, err := OpenWithOptions(path, pw(), OpenOptions{SkipVerify: true})
	if err != nil {
		t.Fatalf("SkipVerify: %v", err)
	}
	if err := o.Verify(ctx); !errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), "MAC mismatch") {
		t.Errorf("Verify: %v", err)
	}
	o.Close()
	if err := VerifyFile(path, pw()); !errors.Is(err, ErrVerify) {
		t.Errorf("VerifyFile: %v", err)
	}
	// Deleting every audit row neither locks anyone out nor lets anything pass.
	db = rawDB(t, path)
	db.Exec(`DELETE FROM audit`)
	db.Close()
	os.Remove(path + ".head") // else the head file reports the rollback first
	if _, err := Open(path, pw()); !errors.Is(err, ErrVerify) {
		t.Errorf("Open without audit rows: %v", err)
	}
}

func TestOldSlotRowWithoutAuditIsRefusedByEpoch(t *testing.T) {
	s, path, _ := scratch(t)
	put(t, s, counter, "1")
	var row [9]any
	s.db.QueryRow(`SELECT id,kind,kdf_memory_kib,kdf_passes,kdf_lanes,salt,key_commit,nonce,wrapped_key FROM keyslots WHERE kind='passphrase'`).
		Scan(&row[0], &row[1], &row[2], &row[3], &row[4], &row[5], &row[6], &row[7], &row[8])
	rekeyTo(t, s, "np")
	s.Close()
	db := rawDB(t, path)
	db.Exec(`DELETE FROM audit`) // the review's bypass of the old gate
	db.Exec(`INSERT INTO keyslots (id,kind,kdf_memory_kib,kdf_passes,kdf_lanes,salt,key_commit,nonce,wrapped_key) VALUES (?,?,?,?,?,?,?,?,?)`, row[:]...)
	db.Close()
	os.Remove(path + ".head")
	for _, o := range []OpenOptions{{}, {SkipVerify: true}} {
		if _, err := OpenWithOptions(path, pw(), o); !errors.Is(err, ErrKeyEpoch) {
			t.Errorf("old slot put back, audit deleted (%+v): %v, want ErrKeyEpoch", o, err)
		}
	}
	// A credential that opens no slot at all stays a wrong credential.
	if _, err := Open(path, passphrase("nobody")); !errors.Is(err, ErrWrongCredential) || errors.Is(err, ErrKeyEpoch) {
		t.Errorf("unknown passphrase: %v", err)
	}
}

// ---- 3: a committed rekey always hands over its recovery key ----

func TestRekeyCleanupFailureStillReturnsTheRecoveryKey(t *testing.T) {
	a, path, _ := scratch(t)
	put(t, a, counter, "1")
	// A reader in another connection holds a snapshot: the truncating WAL
	// checkpoint is busy.
	raw := rawDB(t, path)
	tx, err := raw.Begin()
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM records`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	rk, err := a.ChangePassphraseRekey(ctx, passphrase("np"))
	if err != nil || rk == nil {
		t.Fatalf("rekey with a reader holding a snapshot: %v (key %v)", err, rk != nil)
	}
	var text string
	rk.Use(func(b []byte) error { text = string(b); return nil })
	rk.Destroy()
	if p := pendingFlag(t, path); p != 1 {
		t.Errorf("cleanup_pending = %d after Rekey, want 1 (Rekey leaves the cleanup to Cleanup)", p)
	}
	if err := a.Cleanup(ctx); err == nil {
		t.Error("Cleanup succeeded while a reader holds a snapshot")
	}
	if p := pendingFlag(t, path); p != 1 {
		t.Errorf("cleanup_pending = %d after a failed Cleanup, want 1", p)
	}
	a.Close() // the reader is still there: the retry fails quietly
	if p := pendingFlag(t, path); p != 1 {
		t.Errorf("cleanup_pending = %d after a failed retry, want 1", p)
	}
	tx.Rollback()
	raw.Close()
	// The recovery key that was returned works, and the next open finishes the cleanup.
	r, err := OpenWithRecovery(path, passphrase(text))
	if err != nil {
		t.Fatalf("the returned recovery key: %v", err)
	}
	defer r.Close()
	if p := pendingFlag(t, path); p != 0 {
		t.Errorf("cleanup_pending = %d after Open, want 0", p)
	}
	if v, err := get(r, counter); err != nil || string(v) != "1" {
		t.Errorf("record: %q %v", v, err)
	}
}

func TestRekeyHeadFileFailureStillReturnsTheRecoveryKey(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permissions do not bind root")
	}
	a, path, _ := scratch(t)
	put(t, a, counter, "1")
	dir := filepath.Dir(path)
	// The directory refuses new files: the head file cannot be replaced.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	rk, err := a.ChangePassphraseRekey(ctx, passphrase("np"))
	os.Chmod(dir, 0o700)
	if err != nil || rk == nil {
		t.Fatalf("rekey with an unwritable directory: %v", err)
	}
	rk.Destroy()
	if !hasNotice(a, "head file") {
		t.Errorf("no notice about the head file: %v", a.Notices())
	}
	a.Close()
	// The file is ahead of the head file; opening accepts that and catches up.
	if _, err := Open(path, passphrase("np")); err != nil {
		t.Fatal(err)
	}
}

func hasNotice(s *Store, sub string) bool {
	for _, n := range s.Notices() {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}

func pendingFlag(t *testing.T, path string) (n int) {
	t.Helper()
	db := rawDB(t, path)
	defer db.Close()
	if err := db.QueryRow(`SELECT cleanup_pending FROM meta`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return
}

// ---- 4: a rekey does not launder tampering ----

// rollBackCounter backs up the workspace, writes a newer counter and then puts
// the older authentic record back, leaving the audit chain alone: the review's
// "record rolled back inside one file".
func rollBackCounter(t *testing.T, s *Store, path string) {
	t.Helper()
	put(t, s, counter, "old")
	bk := filepath.Join(t.TempDir(), "bk.db")
	if err := s.Backup(ctx, bk); err != nil {
		t.Fatal(err)
	}
	put(t, s, counter, "new")
	old := rawDB(t, bk)
	defer old.Close()
	var v, at int64
	var n, wk, ow, ct []byte
	if err := old.QueryRow(`SELECT version,nonce,wrapped_key,owner_sealed,ciphertext,updated_at FROM records`).Scan(&v, &n, &wk, &ow, &ct, &at); err != nil {
		t.Fatal(err)
	}
	exec(t, s, `UPDATE records SET version=?,nonce=?,wrapped_key=?,owner_sealed=?,ciphertext=?,updated_at=?`, v, n, wk, ow, ct, at)
}

func TestRekeyRefusesATamperedWorkspace(t *testing.T) {
	s, path, _ := scratch(t)
	rollBackCounter(t, s, path)
	if err := s.Verify(ctx); !errors.Is(err, ErrVerify) {
		t.Fatalf("setup: Verify = %v", err)
	}
	_, rows := recordCount(t, path)
	rk, err := s.ChangePassphraseRekey(ctx, passphrase("np"))
	if !errors.Is(err, ErrVerify) || rk != nil {
		t.Fatalf("rekey of a rolled-back workspace: %v", err)
	}
	if _, rows2 := recordCount(t, path); rows2 != rows {
		t.Error("the refused rekey wrote an audit row")
	}
	s.Close()
	// Nothing changed: the old passphrase is still the passphrase.
	o, err := OpenWithOptions(path, pw(), OpenOptions{SkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	o.Close()
}

func TestRolloverHistoryHashCoversEverySegment(t *testing.T) {
	s, _, _ := scratch(t)
	put(t, s, counter, "1")
	put(t, s, counter, "2")
	rekeyTo(t, s, "second")
	put(t, s, counter, "3")
	if err := s.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	// One rekey: a change in the old segment that its (unverifiable) MACs
	// would hide is caught by the history hash.
	exec(t, s, `UPDATE audit SET at = at + 1 WHERE seq = 2`)
	err := s.Verify(ctx)
	if !errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), "history hash") {
		t.Fatalf("tampered oldest segment after one rekey: %v", err)
	}
	exec(t, s, `UPDATE audit SET at = at - 1 WHERE seq = 2`)
	if err := s.Verify(ctx); err != nil {
		t.Fatal(err)
	}
}

// Two rekeys: only the newest rollover is checked, and it covers the first
// rollover row, which covers the oldest segment.
func TestRolloverHistoryAfterTwoRekeys(t *testing.T) {
	build := func(t *testing.T) *Store {
		s, _, _ := scratch(t)
		put(t, s, counter, "1") // seq 2
		put(t, s, counter, "2") // seq 3
		rekeyTo(t, s, "second") // seq 4
		put(t, s, counter, "3") // seq 5
		rekeyTo(t, s, "third")  // seq 6
		put(t, s, counter, "4") // seq 7
		if err := s.Verify(ctx); err != nil {
			t.Fatal(err)
		}
		return s
	}
	for name, q := range map[string]string{
		"time in the oldest segment":     `UPDATE audit SET at = at + 1 WHERE seq = 2`,
		"touched in the oldest segment":  `UPDATE audit SET touched = x'80' WHERE seq = 3`,
		"first rollover row":             `UPDATE audit SET at = at + 1 WHERE seq = 4`,
		"slot set of the first rollover": `UPDATE audit SET slotset = zeroblob(32) WHERE seq = 4`,
		"row of the middle segment":      `UPDATE audit SET at = at + 1 WHERE seq = 5`,
		"remove a row of the oldest":     `DELETE FROM audit WHERE seq = 2`,
	} {
		t.Run(name, func(t *testing.T) {
			s := build(t)
			exec(t, s, q)
			if err := s.Verify(ctx); !errors.Is(err, ErrVerify) {
				t.Errorf("%v", err)
			}
		})
	}
	t.Run("untouched", func(t *testing.T) { build(t) })
}

// ---- 5: Verify covers slot rows, the lookup index and meta ----

func TestVerifyCoversSlotRowsIndexAndMeta(t *testing.T) {
	t.Run("slot row", func(t *testing.T) {
		s, path, _ := scratch(t)
		put(t, s, counter, "1")
		s.Close()
		db := rawDB(t, path)
		db.Exec(`UPDATE keyslots SET wrapped_key = CAST(CASE WHEN substr(wrapped_key,1,1) = x'00' THEN x'01' ELSE x'00' END || substr(wrapped_key,2) AS BLOB) WHERE kind='recovery'`)
		db.Close()
		err := VerifyFile(path, pw())
		if !errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), "key slots do not match") {
			t.Fatalf("one byte of a recovery slot row: %v", err)
		}
	})
	t.Run("lookup index", func(t *testing.T) {
		s, path, _ := scratch(t)
		put(t, s, counter, "1")
		tag := mustTag(t, s, counter)
		s.Close()
		b := readAll(t, path)
		i := bytes.LastIndex(b, tag)
		if i < 0 || bytes.Count(b, tag) < 2 {
			t.Fatalf("the lookup tag appears %d times in the file; cannot reach the index", bytes.Count(b, tag))
		}
		b[i+5] ^= 0xff
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		err := VerifyFile(path, pw())
		if !errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), "integrity check failed") {
			t.Fatalf("one byte of the lookup-tag index: %v", err)
		}
	})
	t.Run("epoch mac", func(t *testing.T) {
		s, path, _ := scratch(t)
		put(t, s, counter, "1")
		exec(t, s, `UPDATE meta SET epoch_mac = CAST(CASE WHEN substr(epoch_mac,1,1) = x'00' THEN x'01' ELSE x'00' END || substr(epoch_mac,2) AS BLOB)`)
		err := s.Verify(ctx)
		if !errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), "key epoch") {
			t.Fatalf("one byte of epoch_mac: %v", err)
		}
		s.Close()
		if _, err := Open(path, pw()); !errors.Is(err, ErrKeyEpoch) {
			t.Errorf("open with a modified epoch_mac: %v", err)
		}
	})
	t.Run("key epoch", func(t *testing.T) {
		s, path, _ := scratch(t)
		exec(t, s, `UPDATE meta SET key_epoch = CAST(CASE WHEN substr(key_epoch,1,1) = x'00' THEN x'01' ELSE x'00' END || substr(key_epoch,2) AS BLOB)`)
		if err := s.Verify(ctx); !errors.Is(err, ErrStaleHandle) {
			t.Errorf("live handle, modified key_epoch: %v", err)
		}
		s.Close()
		if _, err := Open(path, pw()); !errors.Is(err, ErrKeyEpoch) {
			t.Errorf("reopen, modified key_epoch: %v", err)
		}
	})
	t.Run("slot added behind the store's back", func(t *testing.T) {
		s, path, _ := scratch(t)
		s.Close()
		db := rawDB(t, path)
		db.Exec(`INSERT INTO keyslots (id,kind,kdf_memory_kib,kdf_passes,kdf_lanes,salt,key_commit,nonce,wrapped_key) VALUES (randomblob(16),'recovery',NULL,NULL,NULL,NULL,randomblob(32),randomblob(24),randomblob(48))`)
		db.Close()
		if err := VerifyFile(path, pw()); !errors.Is(err, ErrVerify) {
			t.Errorf("planted slot: %v", err)
		}
	})
}

// ---- 7: Open verifies ----

func TestOpenCatchesARecordRolledBackInsideTheFile(t *testing.T) {
	s, path, _ := scratch(t)
	rollBackCounter(t, s, path)
	s.Close()
	if err := os.Remove(path + ".head"); err != nil { // so that only the chain can notice
		t.Fatal(err)
	}
	for name, o := range map[string]OpenOptions{"default": {}, "AcceptRollback": {AcceptRollback: true}} {
		_, err := OpenWithOptions(path, pw(), o)
		if !errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), "rolled back or modified") {
			t.Errorf("%s: %v, want a verification error", name, err)
		}
	}
	o, err := OpenWithOptions(path, pw(), OpenOptions{SkipVerify: true})
	if err != nil {
		t.Fatalf("SkipVerify: %v", err)
	}
	o.Close()
}

// ---- 8, 9: the head file ----

func TestHeadFileOnlyMovesForward(t *testing.T) {
	s, path, _ := scratch(t)
	h1 := Head{Seq: 10, MAC: bytes.Repeat([]byte{1}, 32)}
	h2 := Head{Seq: 20, MAC: bytes.Repeat([]byte{2}, 32)}
	if err := advanceHeadFile(path, s.ws, h2); err != nil {
		t.Fatal(err)
	}
	if err := advanceHeadFile(path, s.ws, h1); err != nil { // a slow writer arriving late
		t.Fatal(err)
	}
	if _, got, _, _ := readHeadFile(path); got.Seq != 20 {
		t.Errorf("head moved backwards to %d", got.Seq)
	}
	// Many writers in any order end at the newest.
	var wg sync.WaitGroup
	for i := 1; i <= 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := advanceHeadFile(path, s.ws, Head{Seq: uint64(100 + i), MAC: bytes.Repeat([]byte{byte(i)}, 32)}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if _, got, _, _ := readHeadFile(path); got.Seq != 140 {
		t.Errorf("after concurrent writers: %d, want 140", got.Seq)
	}
	// A restore or an accepted rollback replaces it deliberately.
	if err := writeHeadFile(path, s.ws, h1); err != nil {
		t.Fatal(err)
	}
	if _, got, _, _ := readHeadFile(path); got.Seq != 10 {
		t.Errorf("deliberate replace: %d", got.Seq)
	}
}

func TestHeadFileReadIsHardened(t *testing.T) {
	s, path, _ := scratch(t)
	put(t, s, counter, "1")
	s.Close()
	good := readAll(t, path+".head")
	hp := path + ".head"
	cases := map[string]func(){
		"symlink": func() {
			os.Remove(hp)
			target := filepath.Join(t.TempDir(), "elsewhere")
			os.WriteFile(target, good, 0o600)
			os.Symlink(target, hp)
		},
		"directory": func() { os.Remove(hp); os.Mkdir(hp, 0o700) },
		"too large": func() {
			os.WriteFile(hp, append(append([]byte(nil), good...), bytes.Repeat([]byte("x"), 300)...), 0o600)
		},
		"upper-case hex":       func() { os.WriteFile(hp, []byte(upperMAC(string(good))), 0o600) },
		"leading zeros in seq": func() { os.WriteFile(hp, []byte(strings.Replace(string(good), "seq 2", "seq 02", 1)), 0o600) },
	}
	for name, setup := range cases {
		setup()
		if _, err := Open(path, pw()); !errors.Is(err, ErrHeadMismatch) {
			t.Errorf("%s: %v, want ErrHeadMismatch", name, err)
		}
		if name == "directory" { // the operator removes that by hand
			os.Remove(hp)
			os.WriteFile(hp, good, 0o600)
			continue
		}
		// The operator can accept the file's own state; that replaces the bad head file.
		if o, err := OpenWithOptions(path, pw(), OpenOptions{AcceptRollback: true}); err != nil {
			t.Errorf("%s with AcceptRollback: %v", name, err)
		} else {
			o.Close()
		}
		if _, _, found, err := readHeadFile(path); !found || err != nil {
			t.Errorf("%s: head file not repaired by AcceptRollback: %v", name, err)
		}
		os.Remove(hp)
		os.WriteFile(hp, good, 0o600)
	}
}

func upperMAC(s string) string {
	i := strings.Index(s, "mac ") + 4
	return s[:i] + strings.ToUpper(s[i:])
}

// ---- 11: memory budget ----

func TestMinimumBudgetOpensAMaxSecret(t *testing.T) {
	if p := os.Getenv("SPO_TEST_STORE"); p != "" { // the child
		s, err := Open(p, passphrase("child-pass"))
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		k, err := s.Open(ctx, skey0)
		if err != nil {
			t.Fatalf("opening a %d-byte secret with only the documented minimum: %v (budget %+v)", seal.MaxSecret, err, secret.Budget())
		}
		if k.Len() != seal.MaxSecret {
			t.Errorf("secret has %d bytes", k.Len())
		}
		k.Destroy()
		return
	}
	path := filepath.Join(t.TempDir(), "ws.db")
	rk, err := Init(path, passphrase("child-pass"))
	if err != nil {
		t.Fatal(err)
	}
	rk.Destroy()
	s, err := Open(path, passphrase("child-pass"))
	if err != nil {
		t.Fatal(err)
	}
	putSecret(t, s, skey0, strings.Repeat("k", seal.MaxSecret))
	s.Close()
	runWithMemlock(t, "TestMinimumBudgetOpensAMaxSecret", secret.MinimumBudget(seal.MaxSecret), []string{"SPO_TEST_STORE=" + path})
}

// ---- 13: lengths ----

func TestOwnerAndEventLengthsHideTheNames(t *testing.T) {
	s, path, _ := scratch(t)
	for _, name := range []string{"a", "pool-with-a-longer-name", strings.Repeat("n", 128)} {
		put(t, s, ports.Ref{Name: name, Kind: ports.KesCounter}, "x")
	}
	s.Close()
	db := rawDB(t, path)
	defer db.Close()
	var lens []int
	rows, _ := db.Query(`SELECT length(owner_sealed) FROM records`)
	for rows.Next() {
		var n int
		rows.Scan(&n)
		lens = append(lens, n)
	}
	rows.Close()
	if len(lens) != 3 || lens[0] != lens[1] || lens[1] != lens[2] || lens[0] != 24+160+16 {
		t.Errorf("owner blob lengths %v, want three of %d", lens, 24+160+16)
	}
	// Event payloads: the sealed ciphertext is a multiple of 256 plus the tag.
	rows, _ = db.Query(`SELECT length(event) FROM audit`)
	defer rows.Close()
	fixed := 24 + (24 + 48) + 2 + (24 + 160 + 16) + 16
	for rows.Next() {
		var n int
		rows.Scan(&n)
		if (n-fixed)%256 != 0 || n == fixed {
			t.Errorf("event of %d bytes is not a padded multiple of 256 (+%d)", n, fixed)
		}
	}
	// Padding round trip, and a malformed padding is refused.
	for _, n := range []int{0, 1, 251, 252, 253, 600} {
		b := bytes.Repeat([]byte{7}, n)
		p := padEvent(b)
		if len(p)%256 != 0 {
			t.Errorf("padEvent(%d) = %d bytes", n, len(p))
		}
		if got, err := unpadEvent(p); err != nil || !bytes.Equal(got, b) {
			t.Errorf("unpadEvent(%d): %v", n, err)
		}
	}
	bad := padEvent([]byte("x"))
	bad[100] = 1
	if _, err := unpadEvent(bad); err == nil {
		t.Error("non-zero event padding accepted")
	}
}
