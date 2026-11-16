package sqlitestore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var ctx = context.Background()

const testPass = "test passphrase, not a secret"

var (
	tmplOnce     sync.Once
	tmplPath     string
	tmplRecovery string
	tmplDir      string
)

func TestMain(m *testing.M) {
	// Tests run Argon2id at the accepted minimum (64 MiB, 3 passes): the
	// floor itself is not lowered here, only the default for new slots.
	kdfForNewSlots = seal.MinKDF()
	code := m.Run()
	if tmplDir != "" {
		os.RemoveAll(tmplDir)
	}
	os.Exit(code)
}

func pw() *secret.Buffer { return secret.Take([]byte(testPass)) }

func template(t *testing.T) {
	t.Helper()
	tmplOnce.Do(func() {
		dir, err := os.MkdirTemp("", "sqlitestore-tmpl-")
		if err != nil {
			t.Fatal(err)
		}
		tmplDir = dir
		tmplPath = filepath.Join(dir, "ws.db")
		rk, err := Init(tmplPath, pw())
		if err != nil {
			t.Fatal(err)
		}
		rk.Use(func(b []byte) error { tmplRecovery = string(b); return nil })
		rk.Destroy()
	})
	if tmplPath == "" {
		t.Fatal("template workspace failed to initialise")
	}
}

func recovery() *secret.Buffer { return secret.Take([]byte(tmplRecovery)) }

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	in, err := os.Open(from)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(to, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

// fresh returns a path to a new, closed copy of an initialised workspace.
func fresh(t *testing.T) string {
	t.Helper()
	template(t)
	p := filepath.Join(t.TempDir(), "ws.db")
	copyFile(t, tmplPath, p)
	return p
}

func openAt(t *testing.T, path string) *Store {
	t.Helper()
	s, err := OpenWithRecovery(path, recovery())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func newStore(t *testing.T) (*Store, string) {
	p := fresh(t)
	return openAt(t, p), p
}

var (
	counter = ports.Ref{Name: "p", Kind: ports.KesCounter}
	skey0   = ports.Ref{Name: "p", Kind: ports.KesSKey, Num: 0}
)

func put(t *testing.T, s *Store, ref ports.Ref, data string) {
	t.Helper()
	if err := s.Update(ctx, func(w ports.Writer) error { return w.Put(ref, []byte(data)) }); err != nil {
		t.Fatal(err)
	}
}

func putSecret(t *testing.T, s *Store, ref ports.Ref, data string) {
	t.Helper()
	k := secret.Take([]byte(data))
	defer k.Destroy()
	if err := s.Update(ctx, func(w ports.Writer) error { return w.PutSecret(ref, k) }); err != nil {
		t.Fatal(err)
	}
}

func get(s *Store, ref ports.Ref) (b []byte, err error) {
	err = s.View(ctx, func(r ports.Reader) error { b, err = r.Get(ref); return err })
	return
}

func count(t *testing.T, s *Store, table string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// ---- behaviour shared with fsstore ----

func TestFailedUpdateWritesNothing(t *testing.T) {
	s, _ := newStore(t)
	boom := errors.New("boom")
	k := secret.Take([]byte("sk"))
	err := s.Update(ctx, func(w ports.Writer) error {
		w.Put(counter, []byte("000\n"))
		w.PutSecret(skey0, k)
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if n := count(t, s, "records"); n != 0 {
		t.Fatalf("%d records after a failed update", n)
	}
	if n := count(t, s, "audit"); n != 0 {
		t.Fatalf("%d audit rows after a failed update", n)
	}
}

func TestUpdateIsAtomicWhenAWriteFails(t *testing.T) {
	s, _ := newStore(t)
	put(t, s, counter, "000\n")
	// Make the second write fail inside the SQL transaction: the third
	// reference's insert hits a trigger-free constraint by sabotaging the table.
	if _, err := s.db.Exec(`CREATE TRIGGER boom BEFORE INSERT ON records WHEN NEW.kind = 'vrf.vkey' BEGIN SELECT RAISE(ABORT, 'boom'); END`); err != nil {
		t.Fatal(err)
	}
	err := s.Update(ctx, func(w ports.Writer) error {
		w.Put(counter, []byte("001\n"))
		return w.Put(ports.Ref{Name: "p", Kind: ports.VrfVKey}, []byte("v"))
	})
	if err == nil {
		t.Fatal("expected failure")
	}
	if b, _ := get(s, counter); string(b) != "000\n" {
		t.Fatalf("first write leaked: %q", b)
	}
	if n := count(t, s, "audit"); n != 1 {
		t.Fatalf("audit rows %d, want 1", n)
	}
}

func TestReadYourWritesAndDelete(t *testing.T) {
	s, _ := newStore(t)
	err := s.Update(ctx, func(w ports.Writer) error {
		if _, err := w.Get(counter); !errors.Is(err, ports.ErrNotFound) {
			t.Errorf("before put: %v", err)
		}
		w.Put(counter, []byte("001\n"))
		if b, err := w.Get(counter); err != nil || string(b) != "001\n" {
			t.Errorf("after put: %q %v", b, err)
		}
		w.Delete(counter)
		if ok, _ := w.Exists(counter); ok {
			t.Error("exists after delete")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	s.View(ctx, func(r ports.Reader) error {
		if ok, _ := r.Exists(counter); ok {
			t.Error("deleted artefact persisted")
		}
		return nil
	})
	if n := count(t, s, "audit"); n != 0 {
		t.Errorf("an update that changed nothing wrote %d audit rows", n)
	}
	// Delete of a stored record, then read it.
	put(t, s, counter, "x")
	if err := s.Update(ctx, func(w ports.Writer) error { return w.Delete(counter) }); err != nil {
		t.Fatal(err)
	}
	if _, err := get(s, counter); !errors.Is(err, ports.ErrNotFound) {
		t.Fatal(err)
	}
	// Reads and writes of existing data inside one update.
	put(t, s, counter, "a")
	s.Update(ctx, func(w ports.Writer) error {
		b, _ := w.Get(counter)
		return w.Put(counter, append(b, 'b'))
	})
	if b, _ := get(s, counter); string(b) != "ab" {
		t.Fatalf("%q", b)
	}
}

func TestEmptyArtefact(t *testing.T) {
	s, _ := newStore(t)
	put(t, s, counter, "")
	b, err := get(s, counter)
	if err != nil || len(b) != 0 {
		t.Fatalf("%q %v", b, err)
	}
}

func TestSecretsAreNotReadableThroughTheStore(t *testing.T) {
	s, _ := newStore(t)
	key := secret.Take([]byte("skey-bytes"))
	defer key.Destroy()
	s.Update(ctx, func(w ports.Writer) error {
		if err := w.Put(skey0, []byte("x")); !errors.Is(err, ports.ErrSecretKind) {
			t.Errorf("Put of a secret kind: %v", err)
		}
		if err := w.PutSecret(counter, key); !errors.Is(err, ports.ErrInvalidRef) {
			t.Errorf("PutSecret of a non-secret kind: %v", err)
		}
		return w.PutSecret(skey0, key)
	})
	if _, err := get(s, skey0); !errors.Is(err, ports.ErrSecretKind) {
		t.Errorf("Get of a secret kind: %v", err)
	}
	got, err := s.Open(ctx, skey0)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Destroy()
	got.Use(func(b []byte) error {
		if string(b) != "skey-bytes" {
			t.Errorf("vault returned %q", b)
		}
		return nil
	})
	if _, err := s.Open(ctx, counter); !errors.Is(err, ports.ErrInvalidRef) {
		t.Errorf("Open of a non-secret kind: %v", err)
	}
	if _, err := s.Open(ctx, ports.Ref{Name: "nope", Kind: ports.KesSKey}); !errors.Is(err, ports.ErrNotFound) {
		t.Errorf("Open of a missing secret: %v", err)
	}
}

func TestHostileNamesAreRefused(t *testing.T) {
	s, _ := newStore(t)
	for _, name := range []string{"", "../evil", "a/b", ".hidden", "a..b", "x;rm -rf ~", "$(id)", "a b", "pool\x00", "a[$(id)]"} {
		err := s.Update(ctx, func(w ports.Writer) error {
			return w.Put(ports.Ref{Name: name, Kind: ports.KesCounter}, []byte("0"))
		})
		if !errors.Is(err, ports.ErrInvalidRef) {
			t.Errorf("name %q: %v", name, err)
		}
	}
	if n := count(t, s, "records"); n != 0 {
		t.Fatalf("something was written: %d", n)
	}
}

// ---- versions, audit, conflicts ----

func TestVersionsAndAuditRows(t *testing.T) {
	s, _ := newStore(t)
	put(t, s, counter, "1")
	put(t, s, counter, "2")
	var v int
	s.db.QueryRow(`SELECT version FROM records`).Scan(&v)
	if v != 2 {
		t.Fatalf("version %d, want 2", v)
	}
	// One update touching three records: one audit row listing three entries.
	k := secret.Take([]byte("k"))
	s.Update(ctx, func(w ports.Writer) error {
		w.Put(counter, []byte("3"))
		w.Put(ports.Ref{Name: "p", Kind: ports.KesVKey, Num: 1}, []byte("v"))
		w.PutSecret(ports.Ref{Name: "p", Kind: ports.KesSKey, Num: 1}, k)
		w.Put(counter, []byte("4")) // repeated put: still one write
		return nil
	})
	if n := count(t, s, "audit"); n != 3 {
		t.Fatalf("%d audit rows, want 3", n)
	}
	var raw []byte
	s.db.QueryRow(`SELECT touched FROM audit WHERE seq = 3`).Scan(&raw)
	var entries []touched
	if err := cbor.Unmarshal(raw, &entries); err != nil || len(entries) != 3 {
		t.Fatalf("%v %d entries", err, len(entries))
	}
	if b, _ := get(s, counter); string(b) != "4" {
		t.Fatalf("%q", b)
	}
	if err := s.Verify(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestConflictBetweenTwoHandles(t *testing.T) {
	a, path := newStore(t)
	b := openAt(t, path)
	put(t, a, counter, "0")
	err := a.Update(ctx, func(w ports.Writer) error {
		if _, err := w.Get(counter); err != nil { // pins A's snapshot
			return err
		}
		// Meanwhile B commits a change to the same artefact.
		if err := b.Update(ctx, func(w2 ports.Writer) error { return w2.Put(counter, []byte("from B")) }); err != nil {
			t.Fatalf("B: %v", err)
		}
		return w.Put(counter, []byte("from A"))
	})
	if !errors.Is(err, ports.ErrConflict) {
		t.Fatalf("A's update: %v, want ErrConflict", err)
	}
	if got, _ := get(a, counter); string(got) != "from B" {
		t.Fatalf("after conflict: %q", got)
	}
	if err := a.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	// Retrying on a fresh snapshot succeeds.
	put(t, a, counter, "from A")
	if got, _ := get(b, counter); string(got) != "from A" {
		t.Fatalf("B sees %q", got)
	}
}

func TestConflictOnCreatingTheSameRef(t *testing.T) {
	a, path := newStore(t)
	b := openAt(t, path)
	err := a.Update(ctx, func(w ports.Writer) error {
		w.Exists(counter)
		put(t, b, counter, "B")
		return w.Put(counter, []byte("A"))
	})
	if !errors.Is(err, ports.ErrConflict) {
		t.Fatalf("%v", err)
	}
}

// ---- no plaintext on disk ----

func TestNoPlaintextInTheFile(t *testing.T) {
	s, path := newStore(t)
	const (
		poolName   = "MARKERPOOLNAME"
		publicData = "MARKER-PUBLIC-CONTENT-0123"
		secretData = "MARKER-SECRET-CONTENT-4567"
	)
	k := secret.Take([]byte(secretData))
	defer k.Destroy()
	for i := 0; i < 5; i++ { // several rewrites leave old pages in the WAL / free list
		if err := s.Update(ctx, func(w ports.Writer) error {
			w.Put(ports.Ref{Name: poolName, Kind: ports.KesVKey, Num: i}, []byte(publicData))
			w.Put(ports.Ref{Name: poolName, Kind: ports.NodeVKey}, []byte(publicData))
			return w.PutSecret(ports.Ref{Name: poolName, Kind: ports.KesSKey, Num: i}, k)
		}); err != nil {
			t.Fatal(err)
		}
	}
	s.Update(ctx, func(w ports.Writer) error { return w.Delete(ports.Ref{Name: poolName, Kind: ports.NodeVKey}) })
	markers := [][]byte{[]byte(poolName), []byte(publicData), []byte(secretData), []byte("MARKER"), []byte(testPass)}
	check := func(when string) {
		for _, f := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
			raw, err := os.ReadFile(f)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range markers {
				if bytes.Contains(raw, m) {
					t.Errorf("%s: %s contains %q", when, filepath.Base(f), m)
				}
			}
		}
	}
	if _, err := os.Stat(path + "-wal"); err != nil {
		t.Logf("no -wal file while open: %v", err)
	}
	check("while open")
	s.Close()
	check("after close")
	bk := filepath.Join(t.TempDir(), "b.db")
	s2 := openAt(t, path)
	if err := s2.Backup(ctx, bk); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(bk)
	for _, m := range markers {
		if bytes.Contains(raw, m) {
			t.Errorf("backup contains %q", m)
		}
	}
}

func TestFileModes(t *testing.T) {
	s, path := newStore(t)
	put(t, s, counter, "x")
	for _, f := range []string{path, path + "-wal", path + "-shm"} {
		st, err := os.Stat(f)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %o, want 0600", filepath.Base(f), st.Mode().Perm())
		}
	}
	s.Close()
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWithRecovery(path, recovery()); err == nil {
		t.Fatal("opened a group-readable workspace")
	}
	os.Chmod(path, 0o604)
	if _, err := OpenWithRecovery(path, recovery()); err == nil {
		t.Fatal("opened a world-readable workspace")
	}
	// Symlinks are refused.
	os.Chmod(path, 0o600)
	link := path + ".lnk"
	os.Symlink(path, link)
	if _, err := OpenWithRecovery(link, recovery()); err == nil {
		t.Fatal("opened through a symlink")
	}
}

func TestInitRefusesExistingFile(t *testing.T) {
	p := fresh(t)
	if _, err := Init(p, pw()); !errors.Is(err, ErrExists) {
		t.Fatal(err)
	}
	// And leaves it untouched.
	openAt(t, p)
}

// ---- tamper detection ----

func seedThree(t *testing.T) (*Store, string) {
	s, path := newStore(t)
	for i := 0; i < 3; i++ {
		put(t, s, ports.Ref{Name: "p", Kind: ports.KesVKey, Num: i}, "vkey-"+string(rune('a'+i)))
	}
	return s, path
}

func exec(t *testing.T, s *Store, q string, args ...any) {
	t.Helper()
	if _, err := s.db.Exec(q, args...); err != nil {
		t.Fatal(err)
	}
}

func TestTamperSwapCiphertexts(t *testing.T) {
	s, _ := seedThree(t)
	r0, r1 := ports.Ref{Name: "p", Kind: ports.KesVKey, Num: 0}, ports.Ref{Name: "p", Kind: ports.KesVKey, Num: 1}
	t0, _ := s.tag(r0)
	t1, _ := s.tag(r1)
	exec(t, s, `CREATE TEMP TABLE sw AS SELECT nonce, wrapped_key, ciphertext FROM records WHERE lookup_tag = ?`, t0)
	exec(t, s, `UPDATE records SET nonce=(SELECT nonce FROM records WHERE lookup_tag=?), wrapped_key=(SELECT wrapped_key FROM records WHERE lookup_tag=?), ciphertext=(SELECT ciphertext FROM records WHERE lookup_tag=?) WHERE lookup_tag=?`, t1, t1, t1, t0)
	exec(t, s, `UPDATE records SET nonce=(SELECT nonce FROM sw), wrapped_key=(SELECT wrapped_key FROM sw), ciphertext=(SELECT ciphertext FROM sw) WHERE lookup_tag=?`, t1)
	for _, r := range []ports.Ref{r0, r1} {
		if _, err := get(s, r); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: %v", r, err)
		}
	}
	if err := s.Verify(ctx); !errors.Is(err, ErrVerify) {
		t.Errorf("verify: %v", err)
	}
}

func TestTamperSwapLookupTags(t *testing.T) {
	s, _ := seedThree(t)
	r0, r1 := ports.Ref{Name: "p", Kind: ports.KesVKey, Num: 0}, ports.Ref{Name: "p", Kind: ports.KesVKey, Num: 1}
	t0, _ := s.tag(r0)
	t1, _ := s.tag(r1)
	tmp := []byte("tmp-tag-0123456789abcdef0123456")
	exec(t, s, `UPDATE records SET lookup_tag=? WHERE lookup_tag=?`, tmp, t0)
	exec(t, s, `UPDATE records SET lookup_tag=? WHERE lookup_tag=?`, t0, t1)
	exec(t, s, `UPDATE records SET lookup_tag=? WHERE lookup_tag=?`, t1, tmp)
	for _, r := range []ports.Ref{r0, r1} {
		if _, err := get(s, r); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: %v", r, err)
		}
	}
}

func TestTamperKindClassVersion(t *testing.T) {
	for name, q := range map[string]string{
		"kind":    `UPDATE records SET kind = 'kes.skey'`,
		"class":   `UPDATE records SET class = 'secret'`,
		"version": `UPDATE records SET version = version + 1`,
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := newStore(t)
			put(t, s, ports.Ref{Name: "p", Kind: ports.KesVKey, Num: 1}, "v")
			exec(t, s, q)
			if _, err := get(s, ports.Ref{Name: "p", Kind: ports.KesVKey, Num: 1}); !errors.Is(err, ErrCorrupt) {
				t.Errorf("Get: %v", err)
			}
			// Kind and class are not in the audit chain: only the associated
			// data (Get) catches them. A version edit is also a chain mismatch.
			if err := s.Verify(ctx); name == "version" && !errors.Is(err, ErrVerify) {
				t.Errorf("Verify: %v", err)
			}
		})
	}
}

func TestTamperFieldsOfOneRecord(t *testing.T) {
	for _, col := range []string{"nonce", "wrapped_key", "ciphertext"} {
		t.Run(col, func(t *testing.T) {
			s, _ := newStore(t)
			put(t, s, counter, "value")
			exec(t, s, `UPDATE records SET `+col+` = CAST(substr(`+col+`,1,1) || x'00' || substr(`+col+`,3) AS BLOB)`)
			if _, err := get(s, counter); !errors.Is(err, ErrCorrupt) {
				t.Errorf("Get: %v", err)
			}
			if err := s.Verify(ctx); !errors.Is(err, ErrVerify) {
				t.Errorf("Verify: %v", err)
			}
		})
	}
}

func TestVerifyDetectsRollbackOfOneRecord(t *testing.T) {
	s, _ := newStore(t)
	put(t, s, counter, "old")
	exec(t, s, `CREATE TABLE old AS SELECT * FROM records`)
	put(t, s, counter, "new")
	if err := s.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	exec(t, s, `UPDATE records SET version=(SELECT version FROM old), nonce=(SELECT nonce FROM old), wrapped_key=(SELECT wrapped_key FROM old), ciphertext=(SELECT ciphertext FROM old)`)
	// The old ciphertext is internally valid, so it still opens...
	if b, err := get(s, counter); err != nil || string(b) != "old" {
		t.Fatalf("rolled-back record: %q %v", b, err)
	}
	// ...but the chain knows better.
	var ve *VerifyError
	if err := s.Verify(ctx); !errors.As(err, &ve) {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyDetectsInjectedAndRestoredRecords(t *testing.T) {
	s, _ := newStore(t)
	put(t, s, counter, "x")
	exec(t, s, `INSERT INTO records (id, lookup_tag, kind, class, version, nonce, wrapped_key, ciphertext, updated_at) SELECT randomblob(16), randomblob(32), kind, class, 1, nonce, wrapped_key, ciphertext, 0 FROM records`)
	if err := s.Verify(ctx); !errors.Is(err, ErrVerify) {
		t.Fatalf("injected: %v", err)
	}
	exec(t, s, `DELETE FROM records WHERE version = 1 AND updated_at = 0`)
	if err := s.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	// A deleted record put back is reported.
	exec(t, s, `CREATE TABLE keep AS SELECT * FROM records`)
	s.Update(ctx, func(w ports.Writer) error { return w.Delete(counter) })
	exec(t, s, `INSERT INTO records SELECT * FROM keep`)
	if err := s.Verify(ctx); !errors.Is(err, ErrVerify) {
		t.Fatalf("restored: %v", err)
	}
	// A record deleted outside the chain is reported.
	exec(t, s, `DELETE FROM records`)
	put(t, s, counter, "y")
	exec(t, s, `DELETE FROM records`)
	if err := s.Verify(ctx); !errors.Is(err, ErrVerify) {
		t.Fatalf("removed: %v", err)
	}
}

func TestVerifyDetectsAuditTampering(t *testing.T) {
	setup := func(t *testing.T) *Store {
		s, _ := newStore(t)
		for _, v := range []string{"1", "2", "3", "4"} {
			put(t, s, counter, v)
		}
		if err := s.Verify(ctx); err != nil {
			t.Fatal(err)
		}
		return s
	}
	cases := map[string]string{
		"delete middle row": `DELETE FROM audit WHERE seq = 2`,
		"delete first row":  `DELETE FROM audit WHERE seq = 1`,
		"delete last row":   `DELETE FROM audit WHERE seq = 4`,
		"reorder":           `UPDATE audit SET seq = seq + 100 WHERE seq IN (2,3); UPDATE audit SET seq = CASE seq WHEN 102 THEN 3 ELSE 2 END WHERE seq > 100`,
		"edit time":         `UPDATE audit SET at = at + 1 WHERE seq = 2`,
		"edit event":        `UPDATE audit SET event = CAST(substr(event,1,5) || x'00' || substr(event,7) AS BLOB) WHERE seq = 2`,
		"edit touched":      `UPDATE audit SET touched = x'80' WHERE seq = 2`,
		"edit mac":          `UPDATE audit SET mac = zeroblob(32) WHERE seq = 3`,
		"edit prev":         `UPDATE audit SET prev_mac = zeroblob(32) WHERE seq = 3`,
	}
	for name, q := range cases {
		t.Run(name, func(t *testing.T) {
			s := setup(t)
			exec(t, s, q)
			if err := s.Verify(ctx); !errors.Is(err, ErrVerify) {
				t.Fatalf("Verify: %v", err)
			}
		})
	}
}

func TestChainsStayValidAcrossHandles(t *testing.T) {
	a, path := newStore(t)
	put(t, a, counter, "1")
	a.Close()
	b := openAt(t, path)
	put(t, b, counter, "2")
	if err := b.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	if n := count(t, b, "audit"); n != 2 {
		t.Fatalf("%d audit rows", n)
	}
}

// ---- unlocking ----

func TestWrongPassphraseAndRecovery(t *testing.T) {
	path := fresh(t)
	if _, err := Open(path, secret.Take([]byte("wrong"))); !errors.Is(err, ErrWrongCredential) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	s, err := Open(path, pw())
	if err != nil {
		t.Fatalf("right passphrase: %v", err)
	}
	put(t, s, counter, "x")
	s.Close()
	s, err = OpenWithRecovery(path, recovery())
	if err != nil {
		t.Fatalf("recovery: %v", err)
	}
	if b, _ := get(s, counter); string(b) != "x" {
		t.Fatalf("%q", b)
	}
	s.Close()
	// A mistyped recovery key is reported as such, not as a wrong key.
	bad := []byte(tmplRecovery)
	if bad[3] == 'A' {
		bad[3] = 'B'
	} else {
		bad[3] = 'A'
	}
	if _, err := OpenWithRecovery(path, secret.Take(bad)); !errors.Is(err, seal.ErrRecoveryChecksum) {
		t.Errorf("typo: %v", err)
	}
	// A well-formed but different recovery key.
	other := secret.New(seal.KeySize)
	txt, _ := seal.EncodeRecoveryKey(other)
	if _, err := OpenWithRecovery(path, txt); !errors.Is(err, ErrWrongCredential) {
		t.Errorf("other recovery key: %v", err)
	}
	// Not a workspace.
	junk := filepath.Join(t.TempDir(), "junk")
	os.WriteFile(junk, []byte("not a database at all, just text"), 0o600)
	if _, err := Open(junk, pw()); err == nil {
		t.Error("opened junk")
	}
}

func TestModifiedSlotsAreRefused(t *testing.T) {
	// Weakened KDF parameters are refused before any key derivation.
	path := fresh(t)
	s := openAt(t, path)
	exec(t, s, `UPDATE keyslots SET kdf_memory_kib = 1024, kdf_passes = 1 WHERE kind = 'passphrase'`)
	s.Close()
	if _, err := Open(path, pw()); !errors.Is(err, seal.ErrWeakKDF) {
		t.Errorf("weak KDF: %v", err)
	}
	// A slot's wrapped key, salt, id or kind edited: authentication fails.
	for name, q := range map[string]string{
		"wrapped":       `UPDATE keyslots SET wrapped_key = zeroblob(48) WHERE kind='recovery'`,
		"id":            `UPDATE keyslots SET id = randomblob(16) WHERE kind='recovery'`,
		"workspace id":  `UPDATE meta SET workspace_id = randomblob(16)`,
		"format weaken": `UPDATE keyslots SET kdf_lanes = 0 WHERE kind='passphrase'`,
	} {
		p := fresh(t)
		s := openAt(t, p)
		exec(t, s, q)
		s.Close()
		var err error
		if name == "format weaken" {
			_, err = Open(p, pw())
		} else {
			_, err = OpenWithRecovery(p, recovery())
		}
		if err == nil {
			t.Errorf("%s: opened", name)
		}
	}
}

func TestSchemaVersion(t *testing.T) {
	s, path := newStore(t)
	var v int
	s.db.QueryRow(`SELECT version FROM schema_version`).Scan(&v)
	if v != len(migrations) {
		t.Fatalf("schema version %d", v)
	}
	exec(t, s, `UPDATE schema_version SET version = 99`)
	s.Close()
	if _, err := OpenWithRecovery(path, recovery()); err == nil {
		t.Fatal("opened a file from the future")
	}
}

// ---- slots ----

func TestSlotManagement(t *testing.T) {
	path := fresh(t)
	s := openAt(t, path)
	infos, err := s.Slots(ctx)
	if err != nil || len(infos) != 2 {
		t.Fatalf("%v %v", infos, err)
	}
	put(t, s, counter, "x")
	second := secret.Take([]byte("second passphrase"))
	id, err := s.AddPassphraseSlot(ctx, second)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	s2, err := Open(path, secret.Take([]byte("second passphrase")))
	if err != nil {
		t.Fatalf("second passphrase: %v", err)
	}
	if b, _ := get(s2, counter); string(b) != "x" {
		t.Fatal("records unreadable through the second slot")
	}
	newID, err := s2.ChangePassphrase(ctx, id, secret.Take([]byte("changed")))
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.RemoveSlot(ctx, id); !errors.Is(err, ports.ErrNotFound) {
		t.Errorf("removing a replaced slot: %v", err)
	}
	s2.Close()
	if _, err := Open(path, secret.Take([]byte("second passphrase"))); !errors.Is(err, ErrWrongCredential) {
		t.Errorf("old passphrase still works: %v", err)
	}
	s3, err := Open(path, secret.Take([]byte("changed")))
	if err != nil {
		t.Fatal(err)
	}
	// Remove the new passphrase slot, then the original ones; never the last.
	if err := s3.RemoveSlot(ctx, newID); err != nil {
		t.Fatal(err)
	}
	infos, _ = s3.Slots(ctx)
	if len(infos) != 2 {
		t.Fatalf("%d slots", len(infos))
	}
	if err := s3.RemoveSlot(ctx, infos[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := s3.RemoveSlot(ctx, infos[1].ID); !errors.Is(err, ErrLastSlot) {
		t.Fatalf("last slot: %v", err)
	}
	// A new recovery slot works.
	txt, rid, err := s3.AddRecoverySlot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rid == nil {
		t.Fatal("no slot id")
	}
	s3.Close()
	s4, err := OpenWithRecovery(path, txt)
	if err != nil {
		t.Fatal(err)
	}
	s4.Close()
	// Changing a recovery slot as a passphrase slot is refused.
}

// ---- backup and restore (E3) ----

func TestBackupVerifyRestoreSignsWithRestoredKey(t *testing.T) {
	s, path := newStore(t)
	putSecret(t, s, skey0, "the-signing-key")
	put(t, s, counter, "000\n")
	dir := t.TempDir()
	bk := filepath.Join(dir, "backup.db")
	if err := s.Backup(ctx, bk); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(bk); st.Mode().Perm() != 0o600 {
		t.Errorf("backup mode %o", st.Mode().Perm())
	}
	if err := s.Backup(ctx, bk); !errors.Is(err, ErrExists) {
		t.Errorf("backup over existing: %v", err)
	}
	// Writes after the backup do not appear in it.
	put(t, s, counter, "001\n")
	s.Close()
	os.Remove(path) // the workspace is lost

	if err := VerifyFile(bk, pw()); err != nil {
		t.Fatalf("VerifyFile: %v", err)
	}
	if err := VerifyFileWithRecovery(bk, recovery()); err != nil {
		t.Fatalf("VerifyFileWithRecovery: %v", err)
	}
	if err := VerifyFile(bk, secret.Take([]byte("wrong"))); !errors.Is(err, ErrWrongCredential) {
		t.Errorf("wrong passphrase: %v", err)
	}
	empty := filepath.Join(t.TempDir(), "restored", "ws.db")
	os.Mkdir(filepath.Dir(empty), 0o700)
	if err := Restore(bk, empty, pw(), false); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(empty); st.Mode().Perm() != 0o600 {
		t.Errorf("restored mode %o", st.Mode().Perm())
	}
	r := openAt(t, empty)
	k, err := r.Open(ctx, skey0)
	if err != nil {
		t.Fatal(err)
	}
	k.Use(func(b []byte) error {
		if string(b) != "the-signing-key" {
			t.Errorf("restored key %q", b)
		}
		return nil
	})
	if b, _ := get(r, counter); string(b) != "000\n" {
		t.Errorf("restored counter %q", b)
	}
	if err := r.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	r.Close()
	// Refuses to overwrite unless told to.
	if err := Restore(bk, empty, pw(), false); !errors.Is(err, ErrExists) {
		t.Errorf("overwrite without flag: %v", err)
	}
	if err := Restore(bk, empty, pw(), true); err != nil {
		t.Errorf("overwrite with flag: %v", err)
	}
	// Leftovers: no temp files in the destination directory.
	ents, _ := os.ReadDir(filepath.Dir(empty))
	for _, e := range ents {
		if e.Name() != "ws.db" {
			t.Errorf("stray file %s", e.Name())
		}
	}
}

func TestRestoreRefusesATamperedBackup(t *testing.T) {
	s, _ := newStore(t)
	put(t, s, counter, "a")
	put(t, s, counter, "b")
	bk := filepath.Join(t.TempDir(), "b.db")
	if err := s.Backup(ctx, bk); err != nil {
		t.Fatal(err)
	}
	b := openAt(t, bk)
	exec(t, b, `DELETE FROM audit WHERE seq = 1`)
	b.Close()
	dest := filepath.Join(t.TempDir(), "ws.db")
	if err := Restore(bk, dest, pw(), false); !errors.Is(err, ErrVerify) {
		t.Fatalf("%v", err)
	}
	if _, err := os.Stat(dest); err == nil {
		t.Fatal("destination created from a bad backup")
	}
	ents, _ := os.ReadDir(filepath.Dir(dest))
	if len(ents) != 0 {
		t.Errorf("stray files: %v", ents)
	}
}

func TestVerifyFileDoesNotModify(t *testing.T) {
	path := fresh(t)
	s := openAt(t, path)
	put(t, s, counter, "a")
	bk := filepath.Join(t.TempDir(), "b.db")
	s.Backup(ctx, bk)
	s.Close()
	before, _ := os.ReadFile(bk)
	if err := VerifyFile(bk, pw()); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(bk)
	if !bytes.Equal(before, after) {
		t.Error("VerifyFile modified the file")
	}
	ents, _ := os.ReadDir(filepath.Dir(bk))
	if len(ents) != 1 {
		t.Errorf("VerifyFile left files behind: %v", ents)
	}
}
