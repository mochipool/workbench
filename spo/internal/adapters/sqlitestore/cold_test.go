package sqlitestore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/unlock"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
)

var coldRef = rf("pool", ports.NodeSKey)

type rawRow struct {
	id      []byte
	version int64
	sealed  seal.SealedRecord
}

func rowOf(t *testing.T, s *Store, ref ports.Ref) rawRow {
	t.Helper()
	tag, err := s.tag(ref)
	if err != nil {
		t.Fatal(err)
	}
	var r rawRow
	if err := s.db.QueryRow(`SELECT id, version, nonce, wrapped_key, owner_sealed, ciphertext FROM records WHERE lookup_tag = ?`, tag).
		Scan(&r.id, &r.version, &r.sealed.Nonce, &r.sealed.WrappedKey, &r.sealed.Owner, &r.sealed.Ciphertext); err != nil {
		t.Fatal(err)
	}
	return r
}

func headerOf(t *testing.T, s *Store, ref ports.Ref) (seal.ColdHeader, *seal.ColdOuter) {
	t.Helper()
	r := rowOf(t, s, ref)
	oc, err := s.keys.OpenColdOuter(metaOf(s.ws, r.id, ref, seal.ClassSecretCold, uint64(r.version)), r.sealed)
	if err != nil {
		t.Fatal(err)
	}
	return oc.Header, oc
}

func idOfKey(t *testing.T, s *Store, ref ports.Ref) identity.Ref {
	t.Helper()
	role, vk, _ := roleOfSKey(ref.Kind)
	b, err := get(s, ports.Ref{Anchor: ref.Anchor, Kind: vk, Num: ref.Num})
	if err != nil {
		t.Fatal(err)
	}
	id, err := ports.IdentityOfVKey(role, b)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func openString(t *testing.T, s *Store, ref ports.Ref) (string, error) {
	t.Helper()
	b, err := s.Open(ctx, ref)
	if err != nil {
		return "", err
	}
	defer b.Destroy()
	return string(secretBytes(b)), nil
}

// fileState is every row that makes up the file's logical content.
func fileState(t *testing.T, s *Store) string {
	t.Helper()
	h := sha256.New()
	for _, q := range []string{
		`SELECT id, lookup_tag, kind, version, nonce, wrapped_key, owner_sealed, ciphertext FROM records ORDER BY id`,
		`SELECT id, kind, key_commit, nonce, wrapped_key, rec_hash, factors FROM keyslots ORDER BY id`,
		`SELECT seq, mac FROM audit ORDER BY seq`,
		`SELECT workspace_id, key_epoch, policy, recovery_pub FROM meta`,
	} {
		rows, err := s.db.Query(q)
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			ptr := make([]any, len(cols))
			for i := range vals {
				ptr[i] = &vals[i]
			}
			if err := rows.Scan(ptr...); err != nil {
				t.Fatal(err)
			}
			b, _ := seal.EncodeCanonical(vals)
			h.Write(b)
		}
		rows.Close()
	}
	return string(h.Sum(nil))
}

func stdCold(t *testing.T, pass string) (*Store, string, string) {
	t.Helper()
	s, path, rec := scratch(t)
	src := coldPass(pass)
	src.Deriver = fakeDeriver{}
	s.SetColdSource(src)
	putSecret(t, s, coldRef, "cold-secret-one")
	return s, path, rec
}

// hardware workspace, opened through the daily authenticator, with a cold key in it.
func hwCold(t *testing.T) (s *Store, path string, f *fakeSource, rec string) {
	t.Helper()
	path, f, rec = hardwareWS(t)
	var err error
	if s, err = openHW(path, f, "devA", pinA); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	in := f.inputs("devA", pinA)
	s.SetColdSource(&ColdSource{Factors: &in, Deriver: fakeDeriver{}})
	putSecret(t, s, coldRef, "cold-secret-hw")
	return s, path, f, rec
}

// A record of a cold-role key opens only with a fresh factor: the master key alone
// opens its outer layer and nothing inside; a hot key opens with the master key;
// a wrong factor changes nothing; a good one rotates the salt in the same
// transaction as the open.
//
// spec: SPO-Xcustody-INV-009, SPO-Xcustody-OUT-009, SPO-Xcustody-OUT-010, SPO-Xcustody-MODE-003
func TestColdRecordOpensOnlyWithAFreshFactorAndRotatesItsSalt(t *testing.T) {
	s, _, _ := stdCold(t, "sub-key passphrase one")
	putSecret(t, s, rf("pool", ports.KesSKey, 1), "hot-secret")
	cold := rowOf(t, s, coldRef)
	if !seal.IsColdSealed(cold.sealed) {
		t.Fatal("a pool cold key is not sealed in the cold form")
	}
	if seal.IsColdSealed(rowOf(t, s, rf("pool", ports.KesSKey, 1)).sealed) {
		t.Fatal("a KES key is sealed in the cold form")
	}
	// the master key alone: the hot opener, and the outer layer only
	if _, err := s.keys.OpenSecret(metaOf(s.ws, cold.id, coldRef, seal.ClassSecret, uint64(cold.version)), cold.sealed); err == nil {
		t.Fatal("the ordinary data key opened a cold record")
	}
	hdr, oc := headerOf(t, s, coldRef)
	if hdr.Kind != seal.ColdPassphrase {
		t.Fatalf("header %+v", hdr)
	}
	if _, err := oc.OpenSecret(owned(secret.Take(bytes.Repeat([]byte{1}, 32)))); err == nil {
		t.Fatal("a made-up sub-key opened a cold record")
	}
	if v, err := openString(t, s, rf("pool", ports.KesSKey, 1)); err != nil || v != "hot-secret" {
		t.Fatalf("hot: %q %v", v, err)
	}
	// a wrong passphrase: refused, nothing written
	before := fileState(t, s)
	s.SetColdSource(coldPass("not the sub-key passphrase"))
	if _, err := s.Open(ctx, coldRef); !errors.Is(err, ErrColdFactorWrong) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	if fileState(t, s) != before {
		t.Error("a refused open changed the file")
	}
	// the right one: the secret, and a new version with a new salt
	s.SetColdSource(coldPass("sub-key passphrase one"))
	if v, err := openString(t, s, coldRef); err != nil || v != "cold-secret-one" {
		t.Fatalf("cold: %q %v", v, err)
	}
	after := rowOf(t, s, coldRef)
	if after.version != cold.version+1 {
		t.Errorf("version %d -> %d: an open writes the record again", cold.version, after.version)
	}
	hdr2, _ := headerOf(t, s, coldRef)
	if bytes.Equal(hdr2.Salt, hdr.Salt) {
		t.Error("the salt did not rotate")
	}
	// it still opens, and verifies
	if v, err := openString(t, s, coldRef); err != nil || v != "cold-secret-one" {
		t.Fatalf("second open: %q %v", v, err)
	}
	if err := s.Verify(ctx); err != nil {
		t.Fatal(err)
	}
}

// With no source wired a cold record is refused before anything is asked.
//
// spec: SPO-Xcustody-PRE-018
func TestColdRecordWithNoFactorSourceFailsBeforeAnyPrompt(t *testing.T) {
	s, _, _ := stdCold(t, "sub-key passphrase one")
	s.SetColdSource(nil)
	if _, err := s.Open(ctx, coldRef); !errors.Is(err, ErrColdFactorRequired) {
		t.Fatalf("no source: %v", err)
	}
	asked := 0
	s.SetColdSource(&ColdSource{Passphrase: nil, Factors: &FactorInputs{PIN: func(context.Context) (*secret.Buffer, error) { asked++; return nil, nil }}})
	if _, err := s.Open(ctx, coldRef); !errors.Is(err, ErrColdFactorRequired) || asked != 0 {
		t.Fatalf("a source without the factor of the policy: %v (asked %d)", err, asked)
	}
	k := owned(secret.Take([]byte("another cold key")))
	err := s.Update(ctx, func(w ports.Writer) error { return putKeyW(w, rf("pool2", ports.NodeSKey), k) })
	if !errors.Is(err, ErrColdFactorRequired) {
		t.Fatalf("a cold put with no source: %v", err)
	}
}

// spec: SPO-Xcustody-PR-003, SPO-Xcustody-PRE-019
func TestAKeyWithNoVerificationKeyOrNoRoleHistoryIsRefused(t *testing.T) {
	s, _, _ := scratch(t)
	s.SetColdSource(coldPass("sub-key passphrase one"))
	k := secret.Take([]byte("a signing key"))
	defer k.Destroy()
	n := count(t, s, "records")
	// no verification key beside it
	if err := s.Update(ctx, func(w ports.Writer) error { return w.PutSecret(rf("a", ports.AddrSKey), k) }); !errors.Is(err, labels.ErrNoKeyIdentity) {
		t.Fatalf("no vkey: %v", err)
	}
	// a verification key and no role history
	err := s.Update(ctx, func(w ports.Writer) error {
		if err := seedIdentity(w, rf("a", ports.AddrSKey), k); err != nil {
			return err
		}
		id := idOfSeed(t, w, rf("a", ports.AddrSKey))
		if err := w.Delete(ports.Ref{Anchor: id, Kind: ports.RoleHistory}); err != nil {
			return err
		}
		return w.PutSecret(rf("a", ports.AddrSKey), k)
	})
	if !errors.Is(err, labels.ErrNoRoleHistory) {
		t.Fatalf("no history: %v", err)
	}
	if count(t, s, "records") != n {
		t.Error("a refused put left records behind")
	}
}

func idOfSeed(t *testing.T, w ports.Writer, ref ports.Ref) identity.Ref {
	t.Helper()
	role, vk, _ := roleOfSKey(ref.Kind)
	b, err := w.Get(ports.Ref{Anchor: ref.Anchor, Kind: vk, Num: ref.Num})
	if err != nil {
		t.Fatal(err)
	}
	id, err := ports.IdentityOfVKey(role, b)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// A key that gains a cold role is sealed cold in the transaction that extends its
// role history; without the factor the history is not extended.
//
// spec: SPO-Xcustody-PR-004
func TestAKeyThatGainsAColdRoleIsResealedInTheSameTransaction(t *testing.T) {
	s, _, _ := scratch(t)
	ref := rf("w", ports.AddrSKey)
	putSecret(t, s, ref, "payment-key-bytes")
	if seal.IsColdSealed(rowOf(t, s, ref).sealed) {
		t.Fatal("a payment key is cold before it gains the role")
	}
	id := idOfKey(t, s, ref)
	addRole := func(w ports.Writer) error { return labels.RecordRole(w, id, custody.RolePoolCold) }
	before := fileState(t, s)
	if err := s.Update(ctx, addRole); !errors.Is(err, ErrColdFactorRequired) {
		t.Fatalf("a role change with no factor: %v", err)
	}
	if fileState(t, s) != before {
		t.Error("a refused role change changed the file")
	}
	s.SetColdSource(coldPass("sub-key passphrase one"))
	rows := count(t, s, "audit")
	if err := s.Update(ctx, addRole); err != nil {
		t.Fatal(err)
	}
	if count(t, s, "audit") != rows+1 {
		t.Error("the history and the re-sealed record are not one audit row")
	}
	if !seal.IsColdSealed(rowOf(t, s, ref).sealed) {
		t.Fatal("the record was not re-sealed")
	}
	if v, err := openString(t, s, ref); err != nil || v != "payment-key-bytes" {
		t.Fatalf("%q %v", v, err)
	}
}

// forgeRow replaces the stored sealed form of ref by sealed, with a consistent
// audit trail (what a holder of the master key can do): the row, its version and
// the audit row that covers it are all in step, so only the class binding can
// refuse it.
func forgeRow(t *testing.T, s *Store, ref ports.Ref, mk func(meta seal.RecordMeta) seal.SealedRecord) {
	t.Helper()
	release, err := s.enter(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	_, err = s.withWriteTx(ctx, func(q dbq) (*Head, error) {
		if err := s.catchUp(ctx, q); err != nil {
			return nil, err
		}
		tx := &txn{s: s, ctx: ctx, q: q, ops: map[ports.Ref]*op{}}
		row, err := tx.fetch(ref)
		if err != nil {
			return nil, err
		}
		forged := mk(metaOf(s.ws, row.id, ref, seal.ClassSecret, row.version+1))
		tag, _ := s.tag(ref)
		if _, err := q.ExecContext(ctx, `UPDATE records SET version=?, nonce=?, wrapped_key=?, owner_sealed=?, ciphertext=? WHERE id=?`,
			int64(row.version+1), forged.Nonce, forged.WrappedKey, forged.Owner, forged.Ciphertext, row.id); err != nil {
			return nil, err
		}
		h, _ := recordHash(string(ref.Kind), tag, forged)
		prev, _ := chainHead(ctx, q)
		return appendAudit(ctx, q, s.ws, s.keys, auditUpdate, time.Now().Unix(), prev, [][]any{{"put", "forged"}}, []touched{{ID: row.id, Version: row.version + 1, Hash: h}}, nil)
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
}

// A cold record replaced by a hot-form blob sealed under its own identity, with
// row, version and audit trail all consistent, is refused: the sealed class and
// the role history of its key identity disagree. The refusal is the class
// binding, not an integrity check. (The reverse, a cold form planted in a hot
// record, is covered by the verification of the sealed class of every key.)
//
// spec: SPO-Xcustody-INV-010
func TestRelabellingAColdRecordIsRefused(t *testing.T) {
	s, path, _ := stdCold(t, "sub-key passphrase one")
	kes := rf("pool", ports.KesSKey, 1)
	putSecret(t, s, kes, "hot")
	// the cold record becomes a hot-form record, sealed under its own identity
	forgeRow(t, s, coldRef, func(m seal.RecordMeta) seal.SealedRecord {
		r, err := s.keys.SealSecret(m, owned(secret.Take([]byte("attacker chosen"))))
		if err != nil {
			t.Fatal(err)
		}
		return r
	})
	if _, err := s.Open(ctx, coldRef); !errors.Is(err, ErrColdClassMismatch) {
		t.Fatalf("a cold record replaced by a hot-form blob: %v", err)
	}
	s.Close()
	s2, err := Open(path, pw())
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if _, err := s2.VerifyPayloadsReport(ctx); !errors.Is(err, ErrColdClassMismatch) {
		t.Fatalf("payload verification of a file with a cold record replaced by a hot-form blob: %v", err)
	}
}

func TestAMasterKeyHolderCannotReplaceAColdRecordByAHotOne(t *testing.T) {
	s, _, _ := stdCold(t, "sub-key passphrase one")
	release, err := s.enter(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.withWriteTx(ctx, func(q dbq) (*Head, error) {
		if err := s.catchUp(ctx, q); err != nil {
			return nil, err
		}
		tx := &txn{s: s, ctx: ctx, q: q, ops: map[ports.Ref]*op{}}
		row, err := tx.fetch(coldRef)
		if err != nil {
			return nil, err
		}
		meta := metaOf(s.ws, row.id, coldRef, seal.ClassSecret, row.version+1)
		attacker := owned(secret.Take([]byte("attacker chosen key")))
		hot, err := s.keys.SealSecret(meta, attacker)
		if err != nil {
			return nil, err
		}
		tag, _ := s.tag(coldRef)
		if _, err := q.ExecContext(ctx, `UPDATE records SET version=?, nonce=?, wrapped_key=?, owner_sealed=?, ciphertext=? WHERE id=?`,
			int64(row.version+1), hot.Nonce, hot.WrappedKey, hot.Owner, hot.Ciphertext, row.id); err != nil {
			return nil, err
		}
		h, _ := recordHash(string(coldRef.Kind), tag, hot)
		prev, _ := chainHead(ctx, q)
		return appendAudit(ctx, q, s.ws, s.keys, auditUpdate, time.Now().Unix(), prev, [][]any{{"put", "forged"}}, []touched{{ID: row.id, Version: row.version + 1, Hash: h}}, nil)
	}, nil)
	release()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Open(ctx, coldRef); !errors.Is(err, ErrColdClassMismatch) {
		t.Fatalf("a hot record for a cold identity was released: %v", err)
	}
}

// The sub-key passphrase must not open a passphrase slot.
//
// spec: SPO-Xcustody-PRE-020, SPO-Xcustody-IN-004
func TestTheSubKeyPassphraseMustDifferFromEverySlotPassphrase(t *testing.T) {
	s, _, _ := scratch(t)
	s.SetColdSource(coldPass(testPass))
	before := fileState(t, s)
	k := owned(secret.Take([]byte("a cold key")))
	err := s.Update(ctx, func(w ports.Writer) error { return putKeyW(w, coldRef, k) })
	if !errors.Is(err, ErrColdPassphraseReuse) {
		t.Fatalf("%v", err)
	}
	if fileState(t, s) != before {
		t.Error("a refused put changed the file")
	}
}

// Under hardware the factor is one assertion per operation, an impostor
// authenticator or a source without two-salt assertions is refused, and nothing
// is asked of a handle with no source.
//
// spec: SPO-Xcustody-MODE-004, SPO-Xcustody-INV-016, SPO-Xcustody-PRE-018
func TestHardwareColdRecordAsksTheAuthenticatorOncePerOperation(t *testing.T) {
	s, _, f, _ := hwCold(t)
	hdr, _ := headerOf(t, s, coldRef)
	if hdr.Kind != seal.ColdFIDO2 || len(hdr.Next) != 32 {
		t.Fatalf("header %+v", hdr)
	}
	n := f.asserts
	if v, err := openString(t, s, coldRef); err != nil || v != "cold-secret-hw" {
		t.Fatalf("%q %v", v, err)
	}
	if f.asserts != n+1 {
		t.Errorf("%d assertions for one signing operation", f.asserts-n)
	}
	hdr2, _ := headerOf(t, s, coldRef)
	if !bytes.Equal(hdr2.Salt, hdr.Next) || bytes.Equal(hdr2.Next, hdr.Next) {
		t.Error("the next salt did not become the current one")
	}
	// the master key without an authenticator
	s.SetColdSource(nil)
	n, p := f.asserts, f.profiles
	if _, err := s.Open(ctx, coldRef); !errors.Is(err, ErrColdFactorRequired) || f.asserts != n || f.profiles != p {
		t.Fatalf("no source: %v", err)
	}
	// a source that cannot do two-salt assertions: refused before the PIN
	weak := *f
	weak.profile = &ports.FactorProfile{HMACSecret: true, CredProtect3: true, UserVerification: true, CTAP21: true}
	pins := 0
	in := weak.inputs("devA", pinA)
	in.PIN = func(context.Context) (*secret.Buffer, error) { pins++; return secret.Take([]byte(pinA)), nil }
	s.SetColdSource(&ColdSource{Factors: &in})
	if _, err := s.Open(ctx, coldRef); !errors.Is(err, ports.ErrFactorCapability) || pins != 0 {
		t.Fatalf("weak source: %v (pins %d)", err, pins)
	}
	// an impostor authenticator
	before := fileState(t, s)
	imp := newFake()
	imp.auths["devA"].seed = "an impostor"
	iin := imp.inputs("devA", pinA)
	s.SetColdSource(&ColdSource{Factors: &iin})
	if _, err := s.Open(ctx, coldRef); !errors.Is(err, ErrColdFactorWrong) {
		t.Fatalf("an impostor authenticator: want ErrColdFactorWrong, got %v", err)
	}
	if fileState(t, s) != before {
		t.Error("a refused open changed the file")
	}
	// the real one
	rin := f.inputs("devA", pinA)
	s.SetColdSource(&ColdSource{Factors: &rin})
	if v, err := openString(t, s, coldRef); err != nil || v != "cold-secret-hw" {
		t.Fatalf("%q %v", v, err)
	}
}

// What verification and backup can and cannot say about cold-role records, without
// and with the factor.
//
// spec: SPO-Xcustody-INV-015
func TestDeepVerificationOfColdRecordsWithoutAndWithTheFactor(t *testing.T) {
	s, path, _ := stdCold(t, "sub-key passphrase one")
	s.SetColdSource(nil)
	rep, err := s.VerifyPayloadsReport(ctx)
	if err != nil {
		t.Fatalf("deep verification with no factor: %v", err)
	}
	if rep.Records != 1 || rep.OuterOnly != 1 {
		t.Errorf("report %+v", rep)
	}
	bak := path + ".bak"
	if err := s.Backup(ctx, bak); err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyColdPayloads(ctx); !errors.Is(err, ErrColdFactorRequired) {
		t.Fatalf("%v", err)
	}
	s.SetColdSource(coldPass("not it"))
	if _, err := s.VerifyColdPayloads(ctx); !errors.Is(err, ErrColdFactorWrong) {
		t.Fatalf("%v", err)
	}
	before := fileState(t, s)
	s.SetColdSource(coldPass("sub-key passphrase one"))
	if n, err := s.VerifyColdPayloads(ctx); err != nil || n != 1 {
		t.Fatalf("%d %v", n, err)
	}
	if fileState(t, s) != before {
		t.Error("a verification wrote")
	}
	// a backup verifies, and opens the record with the factor, without any other
	if _, err := os.Stat(bak); err != nil {
		t.Fatal(err)
	}
}

// Buffers of the sub-key, the passphrase and the outputs are released.
//
// spec: SPO-Xcustody-SEC-005
func TestColdOperationsReleaseEveryGuardedBuffer(t *testing.T) {
	s, _, f, _ := hwCold(t)
	live := liveBuffers()
	for i := 0; i < 3; i++ {
		b, err := s.Open(ctx, coldRef)
		if err != nil {
			t.Fatal(err)
		}
		b.Destroy()
	}
	if got := liveBuffers(); got != live {
		t.Errorf("hardware opens leaked guarded buffers: %d -> %d", live, got)
	}
	_ = f
	s2, _, _ := stdCold(t, "sub-key passphrase one")
	live = liveBuffers()
	for i := 0; i < 3; i++ {
		b, err := s2.Open(ctx, coldRef)
		if err != nil {
			t.Fatal(err)
		}
		b.Destroy()
	}
	if got := liveBuffers(); got != live {
		t.Errorf("standard opens leaked guarded buffers: %d -> %d", live, got)
	}
	_ = unlock.Standard
}
