package sqlitestore

// Regression tests for the third security review of the store. Each asserts
// the fixed behaviour; the numbering follows the review (F1 schema allow-list,
// F2 failed open writes nothing, F3 record map, F5 messages, F6 lock lost,
// F7 head notice, F8 head file open, F11 cleanup, VerifyPayloads).

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// pwT and passT are pw and passphrase with the buffer destroyed when the test
// ends: the process may lock only a limited amount of memory, and a test run
// many times in one process (-count) must not use it up.
func pwT(t *testing.T) *secret.Buffer {
	t.Helper()
	b := pw()
	t.Cleanup(b.Destroy)
	return b
}

func passT(t *testing.T, p string) *secret.Buffer {
	t.Helper()
	b := passphrase(p)
	t.Cleanup(b.Destroy)
	return b
}

// trustRows rebuilds the handle's record map from the rows as they are now, as
// if the audit chain agreed with them. Tests of the sealing layer use it to get
// past the map, which otherwise answers first.
func trustRows(t *testing.T, s *Store) {
	t.Helper()
	rows, err := s.db.Query(`SELECT id, lookup_tag, kind, version, nonce, wrapped_key, owner_sealed, ciphertext FROM records`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	recs := map[string]chainState{}
	tags, tagOf := map[string]string{}, map[string]string{}
	for rows.Next() {
		var id, tag []byte
		var kind string
		var v int64
		var r seal.SealedRecord
		if err := rows.Scan(&id, &tag, &kind, &v, &r.Nonce, &r.WrappedKey, &r.Owner, &r.Ciphertext); err != nil {
			t.Fatal(err)
		}
		h, err := recordHash(kind, tag, r)
		if err != nil {
			t.Fatal(err)
		}
		recs[string(id)] = chainState{version: uint64(v), hash: h}
		tags[string(tag)], tagOf[string(id)] = string(id), string(tag)
	}
	head, err := chainHead(ctx, s.db)
	if err != nil {
		t.Fatal(err)
	}
	s.known = &chainKnown{head: head, recs: recs, tags: tags, tagOf: tagOf}
}

// snapshot hashes every file in dir (the store, -wal, -shm, the head file and
// its lock), so a test can see that nothing was written, created or removed.
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(b)
		out[e.Name()] = hex.EncodeToString(h[:])
	}
	return out
}

func auditRowCount(t *testing.T, path string) (n int) {
	t.Helper()
	if err := rawDB(t, path).QueryRow(`SELECT count(*) FROM audit`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return
}

// ---- F1: the schema allow-list ----

func TestSchemaAllowList(t *testing.T) {
	// A freshly initialised store passes everywhere.
	s, path, _ := scratch(t)
	put(t, s, counter, "1")
	if err := s.Verify(ctx); err != nil {
		t.Fatalf("fresh store: %v", err)
	}
	s.Close()
	if err := VerifyFile(path, pwT(t)); err != nil {
		t.Fatalf("fresh store, VerifyFile: %v", err)
	}
	base := filepath.Join(t.TempDir(), "base.db")
	copyFile(t, path, base)

	for _, c := range []struct{ name, sql, want string }{
		{"trigger", `CREATE TRIGGER evil AFTER UPDATE OF wrapped_key ON records BEGIN UPDATE records SET wrapped_key = old.wrapped_key WHERE id = new.id; END`, `trigger "evil"`},
		{"view", `CREATE VIEW vv AS SELECT 1`, `view "vv"`},
		{"table", `CREATE TABLE extra (x)`, `table "extra"`},
		{"index", `CREATE INDEX ix ON records (kind)`, `index "ix"`},
		{"column", `ALTER TABLE records ADD COLUMN spare INTEGER`, `table "records"`},
		{"renamed column", `ALTER TABLE keyslots RENAME COLUMN kind TO type`, `table "keyslots"`},
		{"dropped index", `DROP TABLE audit`, `audit`},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "ws.db")
			copyFile(t, base, p)
			db := rawDB(t, p)
			if _, err := db.Exec(c.sql); err != nil {
				t.Fatal(err)
			}
			db.Close()
			for name, open := range map[string]func() error{
				"Open":       func() error { _, err := Open(p, pwT(t)); return err },
				"SkipVerify": func() error { _, err := OpenWithOptions(p, pwT(t), OpenOptions{SkipVerify: true}); return err },
				"VerifyFile": func() error { return VerifyFile(p, pwT(t)) },
			} {
				err := open()
				if !errors.Is(err, ErrSchema) || !errors.Is(err, ErrVerify) {
					t.Errorf("%s: %v, want ErrVerify wrapping ErrSchema", name, err)
					continue
				}
				if !strings.Contains(err.Error(), c.want) {
					t.Errorf("%s: the error does not name the object (%s): %v", name, c.want, err)
				}
			}
		})
	}
}

// A trigger planted while a handle is open is refused by every write and by
// Verify; Rekey changes nothing.
func TestSchemaCheckedByWritesVerifyAndRekeyOnAnOpenHandle(t *testing.T) {
	s, path, _ := scratch(t)
	put(t, s, counter, "1")
	db := rawDB(t, path)
	if _, err := db.Exec(`CREATE TRIGGER evil AFTER UPDATE OF wrapped_key ON records BEGIN UPDATE records SET wrapped_key = old.wrapped_key, owner_sealed = old.owner_sealed WHERE id = new.id; END`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	before := auditRowCount(t, path)
	if err := s.Update(ctx, func(w ports.Writer) error { return w.Put(counter, []byte("2")) }); !errors.Is(err, ErrSchema) {
		t.Errorf("Update: %v", err)
	}
	if err := s.Verify(ctx); !errors.Is(err, ErrSchema) {
		t.Errorf("Verify: %v", err)
	}
	if rk, err := s.ChangePassphraseRekey(ctx, passT(t, "np")); !errors.Is(err, ErrSchema) || rk != nil {
		t.Errorf("Rekey: %v (key %v)", err, rk != nil)
	}
	if err := s.Backup(ctx, filepath.Join(t.TempDir(), "b.db")); !errors.Is(err, ErrSchema) {
		t.Errorf("Backup: %v", err)
	}
	if auditRowCount(t, path) != before {
		t.Error("a refused operation wrote an audit row")
	}
	s.Close()
	// Remove the trigger: the workspace is intact and the old passphrase still opens it.
	db = rawDB(t, path)
	db.Exec(`DROP TRIGGER evil`)
	db.Close()
	o, err := Open(path, pwT(t))
	if err != nil {
		t.Fatalf("after dropping the trigger: %v", err)
	}
	defer o.Close()
	if b, _ := get(o, counter); string(b) != "1" {
		t.Errorf("record %q", b)
	}
}

// The reviewer's two reproductions: a trigger no longer survives Open, so the
// "successful" rekey that destroyed everything cannot start.
func TestTriggerDoesNotTurnRekeyIntoLoss(t *testing.T) {
	for name, trig := range map[string]string{
		"records":  `CREATE TRIGGER evil AFTER UPDATE OF wrapped_key ON records BEGIN UPDATE records SET wrapped_key = old.wrapped_key, owner_sealed = old.owner_sealed WHERE id = new.id; END`,
		"keyslots": `CREATE TRIGGER evil2 AFTER INSERT ON keyslots BEGIN UPDATE keyslots SET wrapped_key = zeroblob(48) WHERE id = new.id; END`,
	} {
		t.Run(name, func(t *testing.T) {
			s, path, rec := scratch(t)
			putSecret(t, s, skey0, "the kes key")
			put(t, s, counter, "7")
			s.Close()
			db := rawDB(t, path)
			if _, err := db.Exec(trig); err != nil {
				t.Fatal(err)
			}
			db.Close()
			if _, err := Open(path, pwT(t)); !errors.Is(err, ErrSchema) {
				t.Fatalf("open with a planted trigger: %v", err)
			}
			if _, err := OpenWithRecovery(path, passT(t, rec)); !errors.Is(err, ErrSchema) {
				t.Fatalf("open with the recovery key and a planted trigger: %v", err)
			}
		})
	}
}

// onWriteConn makes every write connection run stmt before its transaction.
// Writes run on connections of their own, so a TEMP trigger (outside
// sqlite_master, where the allow-list does not look) must be created on each of
// them through a test hook.
func onWriteConn(t *testing.T, stmt string) {
	t.Helper()
	afterWriteConnect = func(c *sql.Conn) {
		if _, err := c.ExecContext(ctx, stmt); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { afterWriteConnect = nil })
}

// F1(c): even if the schema check were bypassed, what a rekey or an update
// wrote is read back before COMMIT. Only the write verification can catch a
// TEMP trigger.
func TestWriteVerificationCatchesRowsRewrittenBehindTheStore(t *testing.T) {
	t.Run("rekey, records", func(t *testing.T) {
		s, path, _ := scratchPresented(t)
		putSecret(t, s, skey0, "the kes key")
		put(t, s, counter, "7")
		onWriteConn(t, `CREATE TEMP TRIGGER evil AFTER UPDATE OF wrapped_key ON main.records BEGIN UPDATE main.records SET wrapped_key = old.wrapped_key, owner_sealed = old.owner_sealed WHERE id = new.id; END`)
		rk, err := s.ChangePassphraseRekey(ctx, passT(t, "np"))
		if !errors.Is(err, ErrVerify) || rk != nil {
			t.Fatalf("rekey: %v (key %v)", err, rk != nil)
		}
		s.Close()
		o, err := Open(path, pwT(t))
		if err != nil {
			t.Fatalf("the aborted rekey changed the workspace: %v", err)
		}
		o.Close()
	})
	t.Run("rekey, key slots", func(t *testing.T) {
		s, path, _ := scratchPresented(t)
		put(t, s, counter, "7")
		onWriteConn(t, `CREATE TEMP TRIGGER evil2 AFTER INSERT ON main.keyslots BEGIN UPDATE main.keyslots SET wrapped_key = zeroblob(48) WHERE id = new.id; END`)
		rk, err := s.ChangePassphraseRekey(ctx, passT(t, "np"))
		if !errors.Is(err, ErrVerify) || rk != nil {
			t.Fatalf("rekey: %v (key %v)", err, rk != nil)
		}
		s.Close()
		if o, err := Open(path, pwT(t)); err != nil {
			t.Fatalf("the aborted rekey changed the workspace: %v", err)
		} else {
			o.Close()
		}
	})
	t.Run("update", func(t *testing.T) {
		s, _, _ := scratchPresented(t)
		put(t, s, counter, "1")
		// A trigger that silently puts the old content back.
		onWriteConn(t, `CREATE TEMP TRIGGER undo AFTER UPDATE ON main.records BEGIN UPDATE main.records SET nonce = old.nonce, ciphertext = old.ciphertext, wrapped_key = old.wrapped_key, owner_sealed = old.owner_sealed, version = old.version WHERE id = new.id; END`)
		err := s.Update(ctx, func(w ports.Writer) error { return w.Put(counter, []byte("2")) })
		if !errors.Is(err, ErrVerify) {
			t.Fatalf("update: %v", err)
		}
		afterWriteConnect = nil
		if b, _ := get(s, counter); string(b) != "1" {
			t.Errorf("the refused update left %q", b)
		}
		if err := s.Verify(ctx); err != nil {
			t.Errorf("verify after the aborted update: %v", err)
		}
	})
	t.Run("audit row", func(t *testing.T) {
		s, _, _ := scratchPresented(t)
		onWriteConn(t, `CREATE TEMP TRIGGER undo AFTER INSERT ON main.audit BEGIN UPDATE main.audit SET at = 0 WHERE seq = new.seq; END`)
		err := s.Update(ctx, func(w ports.Writer) error { return w.Put(counter, []byte("2")) })
		if !errors.Is(err, ErrVerify) {
			t.Fatalf("update: %v", err)
		}
	})
}

func TestConnectionsAreHardened(t *testing.T) {
	s, path, _ := scratch(t)
	put(t, s, counter, "1")
	check := func(name string, db *sql.DB) {
		t.Helper()
		for pragma, want := range map[string]int{"trusted_schema": 0, "cell_size_check": 1, "foreign_keys": 1} {
			var got int
			if err := db.QueryRow(`PRAGMA ` + pragma).Scan(&got); err != nil || got != want {
				t.Errorf("%s: PRAGMA %s = %d (%v), want %d", name, pragma, got, err, want)
			}
		}
		// Defensive mode: this statement is a silent no-op.
		db.Exec(`PRAGMA writable_schema = ON`)
		var ws int
		if err := db.QueryRow(`PRAGMA writable_schema`).Scan(&ws); err != nil || ws != 0 {
			t.Errorf("%s: writable_schema = %d (%v): the connection is not defensive", name, ws, err)
		}
	}
	check("read-write", s.db)
	s.Close()
	for name, imm := range map[string]bool{"read-only": false, "read-only immutable": true} {
		db, err := openDB(path, true, imm)
		if err != nil {
			t.Fatal(err)
		}
		check(name, db)
		db.Close()
	}
}

// ---- F2: a failed open writes nothing ----

func TestFailedOpenLeavesEveryFileUntouched(t *testing.T) {
	cases := map[string]struct {
		prep func(t *testing.T, path string)
		open func(path string) error
		want error
	}{
		"wrong passphrase": {
			func(t *testing.T, path string) {},
			func(p string) error { _, err := Open(p, passT(t, "wrong")); return err },
			ErrWrongCredential,
		},
		"forged audit row": {
			func(t *testing.T, path string) {
				db := rawDB(t, path)
				defer db.Close()
				if _, err := db.Exec(`INSERT INTO audit (seq, at, kind, event, touched, slotset, mac, prev_mac) SELECT seq+1, at, kind, event, touched, slotset, randomblob(32), mac FROM audit WHERE seq = (SELECT max(seq) FROM audit)`); err != nil {
					t.Fatal(err)
				}
			},
			func(p string) error { _, err := Open(p, pwT(t)); return err },
			ErrVerify,
		},
		"forged audit row with AcceptRollback": {
			func(t *testing.T, path string) {
				db := rawDB(t, path)
				defer db.Close()
				db.Exec(`INSERT INTO audit (seq, at, kind, event, touched, slotset, mac, prev_mac) SELECT seq+1, at, kind, event, touched, slotset, randomblob(32), mac FROM audit WHERE seq = (SELECT max(seq) FROM audit)`)
			},
			func(p string) error {
				_, err := OpenWithOptions(p, pwT(t), OpenOptions{AcceptRollback: true})
				return err
			},
			ErrVerify,
		},
		"rolled-back record": {
			func(t *testing.T, path string) {}, // done by the test: it needs a handle
			func(p string) error { _, err := Open(p, pwT(t)); return err },
			ErrVerify,
		},
		"planted trigger": {
			func(t *testing.T, path string) {
				db := rawDB(t, path)
				defer db.Close()
				if _, err := db.Exec(`CREATE TRIGGER evil AFTER INSERT ON audit BEGIN SELECT 1; END`); err != nil {
					t.Fatal(err)
				}
			},
			func(p string) error { _, err := Open(p, pwT(t)); return err },
			ErrSchema,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s, path, _ := scratch(t)
			put(t, s, counter, "1")
			if name == "rolled-back record" {
				var v int64
				var n, wk, ow, ct []byte
				s.db.QueryRow(`SELECT version,nonce,wrapped_key,owner_sealed,ciphertext FROM records`).Scan(&v, &n, &wk, &ow, &ct)
				put(t, s, counter, "2")
				s.Close()
				db := rawDB(t, path)
				if _, err := db.Exec(`UPDATE records SET version=?,nonce=?,wrapped_key=?,owner_sealed=?,ciphertext=?`, v, n, wk, ow, ct); err != nil {
					t.Fatal(err)
				}
				db.Close()
			} else {
				s.Close()
				c.prep(t, path)
			}
			dir := filepath.Dir(path)
			before := snapshot(t, dir)
			if err := c.open(path); !errors.Is(err, c.want) {
				t.Fatalf("open: %v, want %v", err, c.want)
			}
			if after := snapshot(t, dir); !reflect.DeepEqual(before, after) {
				t.Errorf("a failed open changed the files:\nbefore %v\nafter  %v", before, after)
			}
		})
	}
}

// The reviewer's reproduction: a forged row used to move the head file, and the
// genuine file was then refused as rolled back.
func TestForgedRowDoesNotMoveTheHeadFile(t *testing.T) {
	s, path, _ := scratch(t)
	put(t, s, counter, "1")
	s.Close()
	headBefore := readAll(t, path+".head")
	db := rawDB(t, path)
	if _, err := db.Exec(`INSERT INTO audit (seq, at, kind, event, touched, slotset, mac, prev_mac) SELECT seq+1, at, kind, event, touched, slotset, randomblob(32), mac FROM audit WHERE seq = (SELECT max(seq) FROM audit)`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, err := Open(path, pwT(t)); !errors.Is(err, ErrVerify) {
		t.Fatalf("forged file: %v", err)
	}
	if !bytes.Equal(headBefore, readAll(t, path+".head")) {
		t.Error("a failed open moved the head file")
	}
	db = rawDB(t, path)
	db.Exec(`DELETE FROM audit WHERE seq = (SELECT max(seq) FROM audit)`)
	db.Close()
	o, err := Open(path, pwT(t))
	if err != nil {
		t.Fatalf("the genuine file afterwards: %v", err)
	}
	o.Close()
}

// A migration runs only after the file verified, and the schema is checked
// against the declared version before it and against the new one after it.
func TestMigrationOrderAndSchemaChecks(t *testing.T) {
	template(t)
	plain := fresh(t)
	planted := fresh(t)
	db := rawDB(t, planted)
	db.Exec(`CREATE VIEW vv AS SELECT 1`)
	db.Close()
	old := migrations
	defer func() { migrations = old }()
	migrations = append(append([]string{}, old...), `CREATE TABLE note (x INTEGER NOT NULL) STRICT;`)

	if err := VerifyFile(plain, pwT(t)); err == nil || !strings.Contains(err.Error(), "needs migration") {
		t.Errorf("read-only on a file that needs migration: %v", err)
	}
	before := snapshot(t, filepath.Dir(planted))
	if _, err := Open(planted, pwT(t)); !errors.Is(err, ErrSchema) {
		t.Errorf("planted view before migration: %v", err)
	}
	if after := snapshot(t, filepath.Dir(planted)); !reflect.DeepEqual(before, after) {
		t.Error("a refused file was migrated or written")
	}
	s, err := Open(plain, pwT(t))
	if err != nil {
		t.Fatalf("migrating open: %v", err)
	}
	defer s.Close()
	var v int
	s.db.QueryRow(`SELECT version FROM schema_version`).Scan(&v)
	if want := len(old) + 1; v != want || s.schemaV != want {
		t.Errorf("schema version %d / handle %d, want %d", v, s.schemaV, len(old)+1)
	}
	if err := s.Verify(ctx); err != nil {
		t.Errorf("verify after migration: %v", err)
	}
	put(t, s, counter, "1")
}

// F5: tampered meta and schema_version rows are integrity errors, and the
// sentinel messages say that the meta row may have been modified.
func TestTamperedMetaAndSchemaVersionAreIntegrityErrors(t *testing.T) {
	for _, m := range []error{ErrKeyEpoch, ErrStaleHandle} {
		if !strings.Contains(m.Error(), "meta row") {
			t.Errorf("%q does not mention the meta row", m)
		}
	}
	s, path, _ := scratch(t)
	s.Close()
	base := filepath.Join(t.TempDir(), "b.db")
	copyFile(t, path, base)
	for name, q := range map[string]string{
		"schema_version 0":      `UPDATE schema_version SET version = 0`,
		"schema_version empty":  `DELETE FROM schema_version`,
		"schema_version second": `INSERT INTO schema_version VALUES (1)`,
		"meta row removed":      `DELETE FROM meta`,
		"meta workspace id":     `UPDATE meta SET workspace_id = x'00'`,
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "ws.db")
			copyFile(t, base, p)
			db := rawDB(t, p)
			if _, err := db.Exec(q); err != nil {
				t.Fatal(err)
			}
			db.Close()
			_, err := Open(p, pwT(t))
			if !errors.Is(err, ErrVerify) || errors.Is(err, ErrNotWorkspace) {
				t.Errorf("%v, want an integrity error and not ErrNotWorkspace", err)
			}
		})
	}
	// A tampered key epoch: the credential is "of an earlier epoch", and the
	// message says the meta row may be the culprit.
	p := filepath.Join(t.TempDir(), "ws.db")
	copyFile(t, base, p)
	db := rawDB(t, p)
	db.Exec(`UPDATE meta SET key_epoch = randomblob(16)`)
	db.Close()
	if _, err := Open(p, pwT(t)); !errors.Is(err, ErrKeyEpoch) || !strings.Contains(err.Error(), "meta row") {
		t.Errorf("tampered key epoch: %v", err)
	}
	// Not a workspace at all stays "not a workspace".
	empty := filepath.Join(t.TempDir(), "empty.db")
	os.WriteFile(empty, nil, 0o600)
	if _, err := Open(empty, pwT(t)); !errors.Is(err, ErrNotWorkspace) {
		t.Errorf("empty file: %v", err)
	}
}

// ---- F3: the handle's record map ----

func TestRollbackWhileOpenIsNotLaundered(t *testing.T) {
	s, path, _ := scratch(t)
	put(t, s, counter, "1")
	var v int64
	var n, wk, ow, ct []byte
	s.db.QueryRow(`SELECT version,nonce,wrapped_key,owner_sealed,ciphertext FROM records`).Scan(&v, &n, &wk, &ow, &ct)
	put(t, s, counter, "2")
	put(t, s, counter, "3")
	db := rawDB(t, path) // a process that ignores the lock puts version 1 back
	if _, err := db.Exec(`UPDATE records SET version=?,nonce=?,wrapped_key=?,owner_sealed=?,ciphertext=?`, v, n, wk, ow, ct); err != nil {
		t.Fatal(err)
	}
	db.Close()
	rows := auditRowCount(t, path)
	err := s.Update(ctx, func(w ports.Writer) error {
		b, err := w.Get(counter)
		if err != nil {
			return err
		}
		return w.Put(counter, append(b, '+'))
	})
	if !errors.Is(err, ErrVerify) {
		t.Fatalf("read-modify-write on a rolled-back record: %v", err)
	}
	var ve *VerifyError
	if !errors.As(err, &ve) || strings.Contains(err.Error(), "p/") {
		t.Errorf("error is not a typed verification error without names: %v", err)
	}
	if got := auditRowCount(t, path); got != rows {
		t.Errorf("the refused update wrote %d audit row(s)", got-rows)
	}
	if err := s.View(ctx, func(r ports.Reader) error { _, err := r.Get(counter); return err }); !errors.Is(err, ErrVerify) {
		t.Errorf("View: %v", err)
	}
	s.Close()
	if _, err := Open(path, pwT(t)); !errors.Is(err, ErrVerify) {
		t.Errorf("reopen: %v (the rollback was laundered)", err)
	}
}

func TestSecretRolledBackWhileOpenIsRefused(t *testing.T) {
	s, path, _ := scratch(t)
	putSecret(t, s, skey0, "one")
	var v int64
	var n, wk, ow, ct []byte
	s.db.QueryRow(`SELECT version,nonce,wrapped_key,owner_sealed,ciphertext FROM records`).Scan(&v, &n, &wk, &ow, &ct)
	putSecret(t, s, skey0, "two")
	db := rawDB(t, path)
	db.Exec(`UPDATE records SET version=?,nonce=?,wrapped_key=?,owner_sealed=?,ciphertext=?`, v, n, wk, ow, ct)
	db.Close()
	if b, err := s.Open(ctx, skey0); !errors.Is(err, ErrVerify) {
		b.Destroy()
		t.Errorf("Open of a rolled-back secret: %v", err)
	}
}

func TestRowsDeletedOrInjectedWhileOpenAreNoticed(t *testing.T) {
	s, path, _ := scratch(t)
	put(t, s, counter, "1")
	db := rawDB(t, path)
	db.Exec(`DELETE FROM records`)
	db.Close()
	if err := s.Update(ctx, func(w ports.Writer) error { return w.Put(counter, []byte("2")) }); !errors.Is(err, ErrVerify) {
		t.Errorf("Update after the record row was removed: %v", err)
	}
	if err := s.View(ctx, func(ports.Reader) error { return nil }); !errors.Is(err, ErrVerify) {
		t.Errorf("View after the record row was removed: %v", err)
	}
}

// Another well-behaved handle may write; this one follows the chain.
func TestHandleFollowsAnotherHandlesWrites(t *testing.T) {
	a, path, _ := scratch(t)
	b, err := Open(path, pwT(t))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	put(t, a, counter, "1")
	put(t, b, counter, "2")
	if v, err := get(a, counter); err != nil || string(v) != "2" {
		t.Fatalf("a reads %q %v", v, err)
	}
	put(t, a, counter, "3")
	put(t, a, rf("q", ports.KesCounter), "x")
	if v, err := get(b, counter); err != nil || string(v) != "3" {
		t.Fatalf("b reads %q %v", v, err)
	}
	if err := b.Update(ctx, func(w ports.Writer) error { return w.Delete(counter) }); err != nil {
		t.Fatal(err)
	}
	if err := a.View(ctx, func(r ports.Reader) error {
		ok, err := r.Exists(counter)
		if ok || err != nil {
			t.Errorf("a still sees the deleted record: %v %v", ok, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// With SkipVerify the map is built by a full verification at first use.
func TestSkipVerifyBuildsTheMapAtFirstUse(t *testing.T) {
	s, path, _ := scratch(t)
	put(t, s, counter, "1")
	s.Close()
	o, err := OpenWithOptions(path, pwT(t), OpenOptions{SkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if o.known != nil {
		t.Error("the map exists before first use")
	}
	if v, err := get(o, counter); err != nil || string(v) != "1" {
		t.Fatalf("%q %v", v, err)
	}
	put(t, o, counter, "2")
	o.Close()

	// A workspace that fails verification cannot be read through such a handle
	// (it can still be verified and inspected with Verify).
	db := rawDB(t, path)
	db.Exec(`UPDATE records SET version = version - 1`)
	db.Close()
	o, err = OpenWithOptions(path, pwT(t), OpenOptions{SkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	if _, err := get(o, counter); !errors.Is(err, ErrVerify) {
		t.Errorf("read through a SkipVerify handle of a bad workspace: %v", err)
	}
}

func TestNoteEntryRejectsBackwardsRepeatedAndResurrectedRecords(t *testing.T) {
	h1, h2 := []byte{1}, []byte{2}
	id := []byte("id")
	cases := []struct {
		name    string
		entries []touched
		bad     bool
	}{
		{"put, put", []touched{{ID: id, Version: 1, Hash: h1}, {ID: id, Version: 2, Hash: h2}}, false},
		{"first mention at any version (rollover)", []touched{{ID: id, Version: 7, Hash: h1}, {ID: id, Version: 8, Hash: h2}}, false},
		{"put, delete at that version", []touched{{ID: id, Version: 3, Hash: h1}, {ID: id, Version: 3, Hash: []byte{}}}, false},
		{"backwards", []touched{{ID: id, Version: 3, Hash: h1}, {ID: id, Version: 2, Hash: h2}}, true},
		{"repeat with another hash", []touched{{ID: id, Version: 3, Hash: h1}, {ID: id, Version: 3, Hash: h2}}, true},
		{"skip", []touched{{ID: id, Version: 3, Hash: h1}, {ID: id, Version: 5, Hash: h2}}, true},
		{"delete another version", []touched{{ID: id, Version: 3, Hash: h1}, {ID: id, Version: 2, Hash: []byte{}}}, true},
		{"touched after delete", []touched{{ID: id, Version: 3, Hash: []byte{}}, {ID: id, Version: 4, Hash: h1}}, true},
	}
	for _, c := range cases {
		state := map[string]chainState{}
		bad := false
		for _, e := range c.entries {
			if noteEntry(state, e) != "" {
				bad = true
			}
		}
		if bad != c.bad {
			t.Errorf("%s: flagged %v, want %v", c.name, bad, c.bad)
		}
	}
}

// Verify flags a chain, genuinely MAC'd, whose entries go backwards.
func TestVerifyFlagsAVersionThatGoesBackInTheChain(t *testing.T) {
	for _, version := range []uint64{1, 2} { // backwards, and a repeat of the current one with another hash
		s, _, _ := scratch(t)
		put(t, s, counter, "1")
		put(t, s, counter, "2")
		var id []byte
		s.db.QueryRow(`SELECT id FROM records`).Scan(&id)
		prev, err := chainHead(ctx, s.db)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := appendAudit(ctx, s.db, s.ws, s.keys, auditUpdate, time.Now().Unix(), prev, [][]any{{"put", "x"}},
			[]touched{{ID: id, Version: version, Hash: bytes.Repeat([]byte{9}, 32)}}, nil); err != nil {
			t.Fatal(err)
		}
		err = s.Verify(ctx)
		if !errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), "version goes backwards") {
			t.Errorf("version %d: %v", version, err)
		}
	}
}

// ---- F6, F7, F8 ----

func TestLockLostMarksTheHandleBroken(t *testing.T) {
	t.Run("upgrade", func(t *testing.T) {
		s, _, _ := scratchPresented(t)
		s.lock.Close() // flock on a closed descriptor fails: stands in for a failed conversion
		if rk, err := s.ChangePassphraseRekey(ctx, passT(t, "np")); !errors.Is(err, ErrLockLost) || rk != nil {
			t.Fatalf("rekey: %v", err)
		}
		if err := s.View(ctx, func(ports.Reader) error { return nil }); !errors.Is(err, ErrLockLost) {
			t.Errorf("View: %v", err)
		}
		if _, err := s.Slots(ctx); !errors.Is(err, ErrLockLost) {
			t.Errorf("Slots: %v", err)
		}
		if err := s.Update(ctx, func(w ports.Writer) error { return w.Put(counter, []byte("x")) }); !errors.Is(err, ErrLockLost) {
			t.Errorf("Update: %v", err)
		}
		s.Close()
	})
	t.Run("downgrade", func(t *testing.T) {
		s, _, _ := scratchPresented(t)
		old := downgradeFile
		downgradeFile = func(*os.File) error { return errors.New("injected") }
		defer func() { downgradeFile = old }()
		rk, err := s.ChangePassphraseRekey(ctx, passT(t, "np"))
		if err != nil {
			t.Fatal(err)
		}
		rk.Destroy()
		if !hasNotice(s, "refuses every further operation") {
			t.Errorf("no notice: %v", s.Notices())
		}
		if err := s.View(ctx, func(ports.Reader) error { return nil }); !errors.Is(err, ErrLockLost) {
			t.Errorf("View: %v", err)
		}
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
}

func TestReadOnlyVerifyReportsAMissingHeadFileWithoutCreatingIt(t *testing.T) {
	s, path, _ := scratch(t)
	s.Close()
	os.Remove(path + ".head")
	before := snapshot(t, filepath.Dir(path))
	res, err := VerifyFileDetailed(path, pwT(t))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range res.Notices {
		found = found || strings.Contains(n, "no head file")
	}
	if !found {
		t.Errorf("no notice about the missing head file: %q", res.Notices)
	}
	checkUnchanged(t, before, snapshot(t, filepath.Dir(path)))
}

// checkUnchanged: every file that existed is byte for byte as it was (the -shm
// holds no data and may be rebuilt) and the only new files are the -wal and -shm
// that SQLite creates; the store removes nothing.
func checkUnchanged(t *testing.T, before, after map[string]string) {
	t.Helper()
	for f, h := range before {
		if strings.HasSuffix(f, "-shm") {
			continue
		}
		if after[f] != h {
			t.Errorf("%s changed or was removed", f)
		}
	}
	for f := range after {
		if _, had := before[f]; !had && !strings.HasSuffix(f, "-wal") && !strings.HasSuffix(f, "-shm") {
			t.Errorf("%s was created", f)
		}
	}
}

// ---- F11a, VerifyPayloads ----

func TestRekeyLeavesCleanupToCleanup(t *testing.T) {
	s, path, _ := scratchPresented(t)
	put(t, s, counter, "1")
	rk, err := s.ChangePassphraseRekey(ctx, passT(t, "np"))
	if err != nil {
		t.Fatal(err)
	}
	rk.Destroy()
	if p := pendingFlag(t, path); p != 1 {
		t.Fatalf("cleanup_pending = %d right after Rekey, want 1", p)
	}
	if err := s.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if p := pendingFlag(t, path); p != 0 {
		t.Errorf("cleanup_pending = %d after Cleanup", p)
	}
	if err := s.Cleanup(ctx); err != nil {
		t.Errorf("second Cleanup: %v", err)
	}
	if b, err := get(s, counter); err != nil || string(b) != "1" {
		t.Errorf("record after rekey and cleanup: %q %v", b, err)
	}
}

func TestVerifyPayloads(t *testing.T) {
	s, _, _ := scratch(t)
	put(t, s, counter, "1")
	putSecret(t, s, skey0, "k")
	live := liveBuffers()
	if err := s.VerifyPayloads(ctx); err != nil {
		t.Fatalf("good workspace: %v", err)
	}
	if liveBuffers() != live {
		t.Errorf("VerifyPayloads leaked guarded buffers: %d -> %d", live, liveBuffers())
	}
	// A record whose chain entry is genuine but whose bytes do not open:
	// Verify cannot know, VerifyPayloads does.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := seal.NewID()
	tag := bytes.Repeat([]byte{7}, 32)
	junk := seal.SealedRecord{Nonce: bytes.Repeat([]byte{1}, seal.NonceSize), WrappedKey: bytes.Repeat([]byte{2}, 80), Owner: bytes.Repeat([]byte{3}, 80), Ciphertext: bytes.Repeat([]byte{4}, 40)}
	if _, err := tx.Exec(`INSERT INTO records (id, lookup_tag, kind, version, nonce, wrapped_key, owner_sealed, ciphertext, updated_at) VALUES (?,?,?,?,?,?,?,?,?)`,
		id, tag, "kes.counter", 1, junk.Nonce, junk.WrappedKey, junk.Owner, junk.Ciphertext, 0); err != nil {
		t.Fatal(err)
	}
	h, _ := recordHash("kes.counter", tag, junk)
	prev, _ := chainHead(ctx, tx)
	if _, err := appendAudit(ctx, tx, s.ws, s.keys, auditUpdate, time.Now().Unix(), prev, [][]any{{"put", "x"}}, []touched{{ID: id, Version: 1, Hash: h}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(ctx); err != nil {
		t.Fatalf("Verify of a chain-consistent but unreadable record: %v", err)
	}
	err = s.VerifyPayloads(ctx)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("VerifyPayloads: %v, want ErrCorrupt", err)
	}
	var re *RefError
	if !errors.As(err, &re) || !re.Ref.Anchor.IsZero() {
		t.Errorf("the error carries a name: %v", err)
	}
}
