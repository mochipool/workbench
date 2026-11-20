package sqlitestore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Cold-key recovery with a cold source WIRED, as the command line always wires one.

// spec: SPO-Xcustody-PRE-021, SPO-Xcustody-PRE-030
func TestHardwareRecoveryReestablishesColdRecordsThroughTheWrapWithAColdSourceWired(t *testing.T) {
	s, path, f, rec := hwCold(t)
	putMnemonic(t, s, "alpha bravo charlie")
	s.Close()
	// the daily authenticator (devA) is LOST: the recovery makes a new one (devC), it never
	// enrols the lost one again
	f.auths["devC"] = &fakeAuth{3, "seed-c", pinC}
	r, proof := recoveryHandle(t, path, f, rec)
	// the recovery authenticator wired as the cold source: it holds no credential of the
	// record, and the old factor must not be consulted for a record that has a wrap
	inB := f.inputs("devB", pinB)
	r.SetColdSource(&ColdSource{Factors: &inB, Deriver: fakeDeriver{}})
	plan, inC := hardwarePlanFor(t, r, f, proof, "devC", pinC)
	text, _, err := r.Rotate(ctx, plan)
	if err != nil {
		t.Fatalf("a recovery rotation with a cold source wired: %v", err)
	}
	text.Destroy()
	r.Close()
	if lost, err := openHW(path, f, "devA", pinA); err == nil {
		lost.Close()
		t.Fatal("the lost authenticator still opens the workspace")
	}
	n, err := openHW(path, f, "devC", pinC)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	n.SetColdSource(&ColdSource{Factors: &inC})
	if v, err := openString(t, n, coldRef); err != nil || v != "cold-secret-hw" {
		t.Fatalf("after recovery: %q %v", v, err)
	}
	if v, err := openString(t, n, mnRef); err != nil || v != "alpha bravo charlie" {
		t.Fatalf("the mnemonic after recovery: %q %v", v, err)
	}
}

// spec: SPO-Xcustody-PRE-021, SPO-Xcustody-PRE-030
func TestStandardRecoveryRotationWorksWhenTheColdPassphraseIsForgotten(t *testing.T) {
	s, path, rec := stdCold(t, "sub-key passphrase one")
	putMnemonic(t, s, "alpha bravo charlie")
	s.SetColdSource(coldPass("I forgot it"))
	f := newFake()
	plan, inA := hardwarePlan(t, s, f, presentStd(t, s, rec))
	plan.ColdNew.Mnemonic = fakeMnemonic{}
	text, _, err := s.Rotate(ctx, plan)
	if err != nil {
		t.Fatalf("a recovery rotation with a wrong cold passphrase wired: %v", err)
	}
	text.Destroy()
	s.Close()
	n, err := openHW(path, f, "devA", pinA)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	n.SetColdSource(&ColdSource{Factors: &inA})
	if v, err := openString(t, n, coldRef); err != nil || v != "cold-secret-one" {
		t.Fatalf("after recovery: %q %v", v, err)
	}
	if v, err := openString(t, n, mnRef); err != nil || v != "alpha bravo charlie" {
		t.Fatalf("the mnemonic after recovery: %q %v", v, err)
	}
}

// `store recover` re-establishes the cold records: afterwards each opens with the NEW
// cold factor and not with the lost one; the new cold passphrase is asked once, with
// no write lock held.
//
// spec: SPO-Xcustody-PRE-030
func TestRecoveryRekeyReestablishesColdRecordsUnderANewColdPassphrase(t *testing.T) {
	s, path, rec := stdCold(t, "sub-key passphrase one")
	putMnemonic(t, s, "alpha bravo charlie")
	s.Close()
	r, err := OpenWithRecovery(path, passphrase(rec))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.SetColdSource(coldPass("I forgot it"))
	held, done := lockStates()
	defer done()
	prompts := 0
	src := &ColdSource{Deriver: fakeDeriver{}, Mnemonic: fakeMnemonic{}, Passphrase: func(context.Context, bool) (*secret.Buffer, error) {
		prompts++
		return secret.Take([]byte("a new cold passphrase")), nil
	}}
	text, err := r.ChangePassphraseRekeyCold(ctx, passphrase("the recovered workspace passphrase"), src)
	if err != nil {
		t.Fatal(err)
	}
	text.Destroy()
	if prompts != 1 || len(*held) != 1 || (*held)[0] {
		t.Errorf("%d prompts, write lock held at each: %v", prompts, *held)
	}
	r.SetColdSource(coldPass("sub-key passphrase one"))
	if _, err := r.Open(ctx, coldRef); !errors.Is(err, ErrColdFactorWrong) {
		t.Fatalf("the lost cold passphrase still opens the key: %v", err)
	}
	r.SetColdSource(coldPass("a new cold passphrase"))
	if v, err := openString(t, r, coldRef); err != nil || v != "cold-secret-one" {
		t.Fatalf("the new cold passphrase: %q %v", v, err)
	}
	if v, err := openString(t, r, mnRef); err != nil || v != "alpha bravo charlie" {
		t.Fatalf("the mnemonic under the new cold passphrase: %q %v", v, err)
	}
	if err := r.Verify(ctx); err != nil {
		t.Fatal(err)
	}
}

// forgeColdNoWrap seals the cold record of ref again under pass with no recovery
// wrap, as a migrated record is (the audit trail is kept consistent, as a master-key
// holder can).
func forgeColdNoWrap(t *testing.T, s *Store, ref ports.Ref, pass, plain string) {
	t.Helper()
	ident := idOfKey(t, s, ref).Hash() // a read: before the gate is taken
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
		meta := metaOf(s.ws, row.id, ref, seal.ClassSecretCold, row.version+1)
		salt := bytes.Repeat([]byte{7}, seal.SaltSize)
		pw := owned(secret.Take([]byte(pass)))
		out, err := seal.PassphraseFactorOutput(pw, salt, kdfForNewSlots)
		if err != nil {
			return nil, err
		}
		cs := &coldSession{s: s}
		sub, err := cs.derive(out, ident)
		if err != nil {
			return nil, err
		}
		owned(sub)
		sealed, err := s.keys.SealSecretCold(meta, owned(secret.Take([]byte(plain))), seal.ColdSeal{Sub: sub, Header: seal.ColdHeader{Kind: seal.ColdPassphrase, KDF: kdfForNewSlots, Salt: salt}})
		if err != nil {
			return nil, err
		}
		tag, _ := s.tag(ref)
		if _, err := q.ExecContext(ctx, `UPDATE records SET version=?, nonce=?, wrapped_key=?, owner_sealed=?, ciphertext=? WHERE id=?`,
			int64(row.version+1), sealed.Nonce, sealed.WrappedKey, sealed.Owner, sealed.Ciphertext, row.id); err != nil {
			return nil, err
		}
		h, _ := recordHash(string(ref.Kind), tag, sealed)
		prev, _ := chainHead(ctx, q)
		return appendAudit(ctx, q, s.ws, s.keys, auditUpdate, time.Now().Unix(), prev, [][]any{{"put", "forged"}}, []touched{{ID: row.id, Version: row.version + 1, Hash: h}}, nil)
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
}

// A recovery rekey whose old cold factor is not available is REFUSED when it would leave
// a record under that factor (the record is named); only with --leave-unreachable for that
// record does it go on, and the record then keeps its old factor, is listed by the cold
// status and is named in the audit trail. An ordinary passphrase change in the same state
// is refused.
//
// spec: SPO-Xcustody-PRE-030, SPO-Xcustody-IF-009
func TestRecoveryRekeyLeavesRecordsItCannotReestablishOnlyOnRequest(t *testing.T) {
	s, path, rec := stdCold(t, "sub-key passphrase one")
	k := owned(secret.Take([]byte("cold key two")))
	if err := s.Update(ctx, func(w ports.Writer) error { return putKeyW(w, rf("pool2", ports.NodeSKey), k) }); err != nil {
		t.Fatal(err)
	}
	two := rf("pool2", ports.NodeSKey)
	forgeColdNoWrap(t, s, two, "sub-key passphrase one", "cold key two")
	if _, without, err := s.ColdWithoutWrap(ctx); err != nil || without != 1 {
		t.Fatalf("%d records without a wrap: %v", without, err)
	}
	// an ordinary passphrase change that must add a wrap without the factor: refused
	s.SetColdSource(coldPass("I forgot it"))
	presentStd(t, s, rec)
	before := fileState(t, s)
	if _, err := s.ChangePassphraseRekey(ctx, passphrase("another workspace passphrase")); !errors.Is(err, ErrColdFactorWrong) {
		t.Fatalf("an ordinary rekey with the wrong cold factor: %v", err)
	}
	if fileState(t, s) != before {
		t.Error("a refused rekey changed the file")
	}
	s.Close()
	open := func() *Store {
		r, err := OpenWithRecovery(path, passphrase(rec))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { r.Close() })
		r.SetColdSource(coldPass("I forgot it"))
		return r
	}
	src := func(leave ...string) *ColdSource {
		return &ColdSource{Deriver: fakeDeriver{}, LeaveUnreachable: leave, Passphrase: func(context.Context, bool) (*secret.Buffer, error) {
			return secret.Take([]byte("a new cold passphrase")), nil
		}}
	}
	// the recovery is refused, naming the record, and writes nothing
	r := open()
	before = fileState(t, r)
	if _, err := r.ChangePassphraseRekeyCold(ctx, passphrase("the recovered workspace passphrase"), src()); !errors.Is(err, ErrColdWouldStrand) || !strings.Contains(err.Error(), nameOfRef(two)) {
		t.Fatalf("the recovery that would strand a record: %v", err)
	}
	if fileState(t, r) != before {
		t.Error("a refused recovery changed the file")
	}
	r.Close()
	// with the record named it goes on
	r = open()
	text, err := r.ChangePassphraseRekeyCold(ctx, passphrase("the recovered workspace passphrase"), src(nameOfRef(two)))
	if err != nil {
		t.Fatalf("the recovery did not go on: %v", err)
	}
	text.Destroy()
	if !strings.Contains(strings.Join(r.Notices(), "\n"), "left under their old cold factor") {
		t.Errorf("the skipped record is not reported: %v", r.Notices())
	}
	if !auditHas(t, r, "cold-left") {
		t.Error("the left record is not named in the audit trail")
	}
	if st, err := r.ColdStatus(ctx); err != nil || len(st.Problems) != 1 || st.Problems[0].Record != nameOfRef(two) {
		t.Errorf("cold status: %+v %v", st, err)
	}
	if _, without, err := r.ColdWithoutWrap(ctx); err != nil || without != 1 {
		t.Errorf("%d records without a wrap after the recovery: %v", without, err)
	}
	r.SetColdSource(coldPass("a new cold passphrase"))
	if v, err := openString(t, r, coldRef); err != nil || v != "cold-secret-one" {
		t.Fatalf("the re-established record: %q %v", v, err)
	}
	r.SetColdSource(coldPass("sub-key passphrase one"))
	if v, err := openString(t, r, two); err != nil || v != "cold key two" {
		t.Fatalf("the record left under its old factor: %q %v", v, err)
	}
}

// A cold open that loses a race, or fails, leaves no plaintext key in guarded memory.
//
// spec: SPO-Xcustody-SEC-005
func TestARacedColdOpenLeavesNoPlaintextInGuardedMemory(t *testing.T) {
	s, path, _ := stdCold(t, "sub-key passphrase one")
	b, err := Open(path, pw())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	b.SetColdSource(coldPass("sub-key passphrase one"))
	prompts := 0
	s.SetColdSource(&ColdSource{Passphrase: func(context.Context, bool) (*secret.Buffer, error) {
		prompts++
		if prompts == 1 {
			v, err := b.Open(ctx, coldRef)
			if err != nil {
				t.Errorf("the other handle: %v", err)
			} else {
				v.Destroy()
			}
		}
		return secret.Take([]byte("sub-key passphrase one")), nil
	}})
	base := liveBuffers()
	v, err := s.Open(ctx, coldRef)
	if err != nil || prompts != 2 {
		t.Fatalf("%v (prompts %d)", err, prompts)
	}
	v.Destroy()
	if got := liveBuffers(); got != base {
		t.Errorf("guarded buffers after a raced open: %d, baseline %d", got, base)
	}
	// a wrong factor and a failed commit leave none either
	s.SetColdSource(coldPass("not it"))
	if _, err := s.Open(ctx, coldRef); !errors.Is(err, ErrColdFactorWrong) {
		t.Fatal(err)
	}
	if got := liveBuffers(); got != base {
		t.Errorf("guarded buffers after a refused open: %d, baseline %d", got, base)
	}
}

// A previous wrap is not pinned by a persistent fault: when the answer for the new
// salt does not verify the record is not rewritten (it still opens, with a warning
// each time); a one-off fault heals.
//
// spec: SPO-Xcustody-INV-020
func TestAPersistentlyFaultyAuthenticatorRewritesNothingAndWarns(t *testing.T) {
	s, _, f, _ := hwCold(t)
	f.corruptNext = 1 // open 1 seals the record under a wrong next-salt output
	if v, err := openString(t, s, coldRef); err != nil || v != "cold-secret-hw" {
		t.Fatalf("%q %v", v, err)
	}
	f.corruptNext = 1000 // now every next-salt answer is wrong
	before := fileState(t, s)
	for i := 0; i < 2; i++ {
		n := len(s.Notices())
		if v, err := openString(t, s, coldRef); err != nil || v != "cold-secret-hw" {
			t.Fatalf("open %d: %q %v", i, v, err)
		}
		if len(s.Notices()) != n+1 || !strings.Contains(s.Notices()[n], "inconsistent answer") {
			t.Errorf("open %d: no warning: %v", i, s.Notices())
		}
		if fileState(t, s) != before {
			t.Errorf("open %d rewrote the record", i)
		}
	}
	f.corruptNext = 0 // the fault is gone: the next open heals
	if v, err := openString(t, s, coldRef); err != nil || v != "cold-secret-hw" {
		t.Fatalf("%q %v", v, err)
	}
	if h, _ := headerOf(t, s, coldRef); h.Fallbacks != 1 || len(h.Prev) != 0 {
		t.Errorf("after the heal: %+v", h)
	}
	if v, err := openString(t, s, coldRef); err != nil || v != "cold-secret-hw" {
		t.Fatalf("%q %v", v, err)
	}
}

// An authenticator that answers a new salt inconsistently seals nothing, at creation
// and at rotation (one extra touch per record verifies each answer).
//
// spec: SPO-Xcustody-MODE-004
func TestAnInconsistentAnswerSealsNoNewColdRecord(t *testing.T) {
	s, _, f, _ := hwCold(t)
	before := fileState(t, s)
	f.corruptOnce = true
	k := owned(secret.Take([]byte("cold key two")))
	err := s.Update(ctx, func(w ports.Writer) error { return putKeyW(w, rf("pool2", ports.NodeSKey), k) })
	if !errors.Is(err, ErrColdAnswerInconsistent) {
		t.Fatalf("creation under an inconsistent answer: %v", err)
	}
	if fileState(t, s) != before {
		t.Error("a refused creation changed the file")
	}
	// rotation
	s2, path, rec := stdCold(t, "sub-key passphrase one")
	plan, _ := hardwarePlan(t, s2, f, presentStd(t, s2, rec))
	b2 := fileState(t, s2)
	f.corruptOnce = true
	if _, _, err := s2.Rotate(ctx, plan); !errors.Is(err, ErrColdAnswerInconsistent) {
		t.Fatalf("rotation under an inconsistent answer: %v", err)
	}
	if fileState(t, s2) != b2 {
		t.Error("a refused rotation changed the file")
	}
	_ = path
}

// A rotation presents its new factor before the file lock and the write transaction.
//
// spec: SPO-Xcustody-INV-021
func TestRotationAsksItsNewFactorOutsideTheWriteTransaction(t *testing.T) {
	s, _, rec := stdCold(t, "sub-key passphrase one")
	f := newFake()
	plan, _ := hardwarePlan(t, s, f, presentStd(t, s, rec))
	held, done := lockStates()
	defer done()
	text, _, err := s.Rotate(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	text.Destroy()
	if len(*held) == 0 {
		t.Fatal("the rotation asked for no cold factor")
	}
	for i, h := range *held {
		if h {
			t.Errorf("prompt %d was made with the write lock held", i)
		}
	}
}

// Verifying the cold payloads with the factor holds no read snapshot while the
// operator is asked: a truncating checkpoint from another handle is not busy.
//
// spec: SPO-Xcustody-INV-015
func TestVerifyColdPayloadsPresentsTheFactorWithNoReadSnapshotHeld(t *testing.T) {
	s, path, _ := stdCold(t, "sub-key passphrase one")
	b, err := Open(path, pw())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	busy := -1
	s.SetColdSource(&ColdSource{Deriver: fakeDeriver{}, Passphrase: func(context.Context, bool) (*secret.Buffer, error) {
		if err := b.Update(ctx, func(w ports.Writer) error { return w.Put(rf("other", ports.KesCounter), []byte("1")) }); err != nil {
			t.Errorf("a writer during the prompt: %v", err)
		}
		var logFrames, done int
		if err := b.db.QueryRow(`PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &done); err != nil {
			t.Errorf("checkpoint: %v", err)
		}
		return secret.Take([]byte("sub-key passphrase one")), nil
	}})
	if n, err := s.VerifyColdPayloads(ctx); err != nil || n != 1 {
		t.Fatalf("%d %v", n, err)
	}
	if busy != 0 {
		t.Errorf("a read snapshot was held while the factor was presented (checkpoint busy = %d)", busy)
	}
}

// The migration truncates the write-ahead log: the hot versions of the keys that are
// cold now do not stay in it.
//
// spec: SPO-Xcustody-PR-005
func TestMigrationTruncatesTheWriteAheadLog(t *testing.T) {
	p := format2Copy(t)
	old, err := OpenFormat2(p, legacyPW())
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	old.SetColdSource(coldPass("sub-key passphrase one"))
	if _, err := old.Migrate3(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(p + "-wal"); err == nil && st.Size() != 0 {
		t.Errorf("the write-ahead log holds %d bytes after the migration", st.Size())
	}
}

// A recovery presentation that was not used is dropped on request.
//
// spec: SPO-Xcustody-PRE-024
func TestADiscardedRecoveryPresentationAuthorisesNothing(t *testing.T) {
	s, _, rec := scratch(t)
	presentStd(t, s, rec)
	s.DiscardRecovery()
	noRecoveryMaterial(t, s, "after DiscardRecovery")
	if _, err := s.ChangePassphraseRekey(ctx, passphrase("a new passphrase")); !errors.Is(err, ErrRecoveryNotPresented) {
		t.Fatalf("a rekey after a discarded presentation: %v", err)
	}
}
