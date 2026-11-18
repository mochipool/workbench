package sqlitestore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/checkpoint"
	"github.com/mochipool/workbench/spo/internal/domain/sshsig"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
)

var ckRef = ports.NamedRef{Name: "checkpoint", Kind: ports.CheckpointKey}

// ckRecord is a canonical checkpoint key record of a fresh key, and its hash.
func ckRecord(t *testing.T) (raw, hash []byte) {
	t.Helper()
	p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	q, _ := p.PublicKey.Bytes()
	r := checkpoint.KeyRecord{Key: sshsig.Key{Q: q, Application: checkpoint.Application}, CredentialID: bytes.Repeat([]byte{7}, 48), Enrolled: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
	return r.Encode(), r.Hash()
}

func putCK(t *testing.T, s *Store, raw []byte) {
	t.Helper()
	if err := labels.Named(s).Update(ctx, func(w ports.NamedWriter) error { return w.Put(ckRef, raw) }); err != nil {
		t.Fatal(err)
	}
}

func getCK(t *testing.T, s *Store) []byte {
	t.Helper()
	var b []byte
	err := labels.Named(s).View(ctx, func(r ports.NamedReader) error {
		var err error
		b, err = r.Get(ckRef)
		if err == ports.ErrNotFound {
			b, err = nil, nil
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A restore over a workspace that has a checkpoint key, of a backup that has
// none, carries the key into the restored copy in the audited write; a backup
// with a DIFFERENT key keeps its own and the report names both hashes; the same
// key changes nothing; the restored file's key hash is always reported.
//
// spec: SPO-Xbackup-PRE-020
func TestRestoreKeepsOrReportsTheCheckpointKey(t *testing.T) {
	t.Run("the backup has none: the destination's is carried", func(t *testing.T) {
		s, path, _ := scratch(t)
		backup := filepath.Join(t.TempDir(), "b.bak")
		if err := s.Backup(ctx, backup); err != nil {
			t.Fatal(err)
		}
		raw, hash := ckRecord(t)
		putCK(t, s, raw)
		s.Close()
		var rep RestoreReport
		if err := restoreOlder(t, backup, path, RestoreOptions{Report: &rep}); err != nil {
			t.Fatal(err)
		}
		r := openPlain(t, path)
		if !bytes.Equal(getCK(t, r), raw) {
			t.Fatal("the checkpoint key was dropped by the restore")
		}
		if !rep.KeyCarried || !bytes.Equal(rep.KeyHash, hash) || !auditHas(t, r, "checkpoint-key-carried") {
			t.Fatalf("%+v", rep)
		}
	})
	t.Run("the backup has another key: the backup's is kept and both hashes are named", func(t *testing.T) {
		s, path, _ := scratch(t)
		rawB, hashB := ckRecord(t)
		putCK(t, s, rawB)
		backup := filepath.Join(t.TempDir(), "b.bak")
		if err := s.Backup(ctx, backup); err != nil {
			t.Fatal(err)
		}
		rawL, hashL := ckRecord(t)
		putCK(t, s, rawL)
		s.Close()
		var rep RestoreReport
		if err := restoreOlder(t, backup, path, RestoreOptions{Report: &rep}); err != nil {
			t.Fatal(err)
		}
		r := openPlain(t, path)
		if !bytes.Equal(getCK(t, r), rawB) {
			t.Fatal("the backup's own key was not kept")
		}
		if rep.KeyCarried || !bytes.Equal(rep.KeyHash, hashB) || !bytes.Equal(rep.KeyReplaced, hashL) {
			t.Fatalf("%+v (backup %s, replaced %s)", rep, hex.EncodeToString(hashB), hex.EncodeToString(hashL))
		}
		if !auditHas(t, r, "checkpoint-key-differs") {
			t.Error("no audit event for the different key")
		}
	})
	t.Run("the same key: nothing is carried", func(t *testing.T) {
		s, path, _ := scratch(t)
		raw, hash := ckRecord(t)
		putCK(t, s, raw)
		backup := filepath.Join(t.TempDir(), "b.bak")
		s.Backup(ctx, backup)
		putCounters(t, s, "poolA", cstate{issue: 1, kesCur: 0, kesNext: 1})
		s.Close()
		var rep RestoreReport
		if err := restoreOlder(t, backup, path, RestoreOptions{Report: &rep}); err != nil {
			t.Fatal(err)
		}
		if rep.KeyCarried || rep.KeyReplaced != nil || !bytes.Equal(rep.KeyHash, hash) || auditHas(t, openPlain(t, path), "checkpoint-key-carried") {
			t.Fatalf("%+v", rep)
		}
	})
	t.Run("a fresh directory reports the backup's key; no key reports none", func(t *testing.T) {
		s, _, _ := scratch(t)
		raw, hash := ckRecord(t)
		putCK(t, s, raw)
		backup := filepath.Join(t.TempDir(), "b.bak")
		s.Backup(ctx, backup)
		s.Close()
		var rep RestoreReport
		dest := filepath.Join(t.TempDir(), "ws.db")
		if err := RestoreWithOptions(backup, dest, pw(), RestoreOptions{Report: &rep}); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(rep.KeyHash, hash) || rep.KeyCarried {
			t.Fatalf("%+v", rep)
		}
		s2, _, _ := scratch(t)
		b2 := filepath.Join(t.TempDir(), "b2.bak")
		s2.Backup(ctx, b2)
		s2.Close()
		var rep2 RestoreReport
		if err := RestoreWithOptions(b2, filepath.Join(t.TempDir(), "w.db"), pw(), RestoreOptions{Report: &rep2}); err != nil || rep2.KeyHash != nil {
			t.Fatalf("%v %+v", err, rep2)
		}
	})
}

// store verify reports a checkpoint key record as present, and --deep parses it
// strictly and fails naming it when it is malformed (a record whose content was
// damaged before it was sealed, which the chain cannot tell).
//
// spec: SPO-Xbackup-PRE-021
func TestVerifyLooksAtTheCheckpointKeyRecord(t *testing.T) {
	s, path, _ := scratch(t)
	raw, hash := ckRecord(t)
	putCK(t, s, raw)
	s.Close()
	res, err := VerifyFileDetailed(path, pw())
	if err != nil || !res.CheckpointKey || !bytes.Equal(res.CheckpointKeyHash, hash) || !noticeHas(res.Notices, "a checkpoint key record is present") {
		t.Fatalf("plain verify: %v %+v", err, res)
	}
	if res, err := VerifyFilePayloads(path, pw()); err != nil || !res.CheckpointKey {
		t.Fatalf("deep verify of a good record: %v", err)
	}
	// a malformed record, sealed like any other
	s2, err := Open(path, pw())
	if err != nil {
		t.Fatal(err)
	}
	putCK(t, s2, []byte("spo/checkpoint-key/v1\nkey-type nothing\n"))
	s2.Close()
	if _, err := VerifyFileDetailed(path, pw()); err != nil {
		t.Fatalf("plain verify does not decrypt, so it does not fail: %v", err)
	}
	_, err = VerifyFilePayloads(path, pw())
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("checkpoint key record is malformed")) {
		t.Fatalf("deep verify of a malformed record: %v", err)
	}
}

func noticeHas(ns []string, sub string) bool {
	for _, n := range ns {
		if bytes.Contains([]byte(n), []byte(sub)) {
			return true
		}
	}
	return false
}
