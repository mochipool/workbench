package sqlitestore

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/unlock"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func hardwarePlan(t *testing.T, s *Store, f *fakeSource, proof *RecoveryProof) (RotatePlan, FactorInputs) {
	t.Helper()
	fa, _, err := EnrolFactor(ctx, f.inputs("devA", "1234"), s.ws, nil)
	if err != nil {
		t.Fatal(err)
	}
	fb, _, err := EnrolFactor(ctx, f.inputs("devB", "5678"), s.ws, nil)
	if err != nil {
		t.Fatal(err)
	}
	inA := f.inputs("devA", "1234")
	return RotatePlan{Policy: unlock.Hardware, Proof: proof, Slots: []SlotPlan{
		{Kind: seal.SlotFIDO2HMAC, Factors: []FactorPlan{fa}},
		{Kind: seal.SlotComposite, Factors: []FactorPlan{{Params: seal.FactorParams{Kind: seal.FactorRecovery}}, fb}},
	}, ColdNew: &ColdSource{Factors: &inA, Deriver: fakeDeriver{}}}, inA
}

func recPrivOf(t *testing.T, text string) *secretKey {
	t.Helper()
	raw, err := seal.DecodeRecoveryKey(secret.Take([]byte(text)))
	if err != nil {
		t.Fatal(err)
	}
	priv, err := seal.RecoveryKeyPair(raw)
	if err != nil {
		t.Fatal(err)
	}
	return &secretKey{p: priv}
}

// A rotation re-seals the cold-role records under the new sub-key: changing standard
// to hardware, the passphrase sub-key becomes an authenticator sub-key, and a rotation
// that fails part way changes nothing.
//
// spec: SPO-Xcustody-PRE-022, SPO-Xcustody-INV-017
func TestRotationReSealsColdRecordsUnderTheNewSubKey(t *testing.T) {
	s, _, rec := stdCold(t, "sub-key passphrase one")
	putSecret(t, s, rf("pool", ports.KesSKey, 1), "hot-secret")
	putMnemonic(t, s, "alpha bravo charlie")
	f := newFake()
	plan, inA := hardwarePlan(t, s, f, presentStd(t, s, rec))
	plan.ColdNew.Mnemonic = fakeMnemonic{}
	before := fileState(t, s)
	// the new factor is required
	noCold := plan
	noCold.ColdNew = nil
	if _, _, err := s.Rotate(ctx, noCold); !errors.Is(err, ErrColdFactorRequired) {
		t.Fatalf("a rotation with cold records and no new factor: %v", err)
	}
	// a failure after the first record leaves the file as it was and the old factor valid
	rotateHook = func(done int) error {
		if done >= 1 {
			return errors.New("injected")
		}
		return nil
	}
	_, _, err := s.Rotate(ctx, plan)
	rotateHook = nil
	if err == nil {
		t.Fatal("the injected failure did not stop the rotation")
	}
	if fileState(t, s) != before {
		t.Fatal("a rotation that stopped half way changed the file")
	}
	if v, err := openString(t, s, coldRef); err != nil || v != "cold-secret-one" {
		t.Fatalf("the old factor no longer opens the record: %q %v", v, err)
	}
	// now for real
	plan, inA = hardwarePlan(t, s, f, presentStd(t, s, rec))
	plan.ColdNew.Mnemonic = fakeMnemonic{}
	text, _, err := s.Rotate(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	text.Destroy()
	hdr, _ := headerOf(t, s, coldRef)
	if hdr.Kind != seal.ColdFIDO2 || !bytes.Equal(hdr.Credential, plan.Slots[0].Factors[0].Params.CredentialID) {
		t.Fatalf("the record is not sealed under the new authenticator: %+v", hdr)
	}
	s.SetColdSource(&ColdSource{Factors: &inA})
	if v, err := openString(t, s, coldRef); err != nil || v != "cold-secret-one" {
		t.Fatalf("after the rotation: %q %v", v, err)
	}
	if v, err := openString(t, s, rf("pool", ports.KesSKey, 1)); err != nil || v != "hot-secret" {
		t.Fatalf("hot key: %q %v", v, err)
	}
	if v, err := openString(t, s, mnRef); err != nil || v != "alpha bravo charlie" {
		t.Fatalf("the mnemonic after the rotation: %q %v", v, err)
	}
	if err := s.Verify(ctx); err != nil {
		t.Fatal(err)
	}
}

type secretKey struct{ p *ecdh.PrivateKey }

func (k *secretKey) priv() *ecdh.PrivateKey { return k.p }

// recoveryHandle opens a hardware workspace through the recovery composite only
// (the recovery key and the second authenticator) and presents it.
func recoveryHandle(t *testing.T, path string, f *fakeSource, rec string) (*Store, *RecoveryProof) {
	t.Helper()
	in := f.inputs("devB", "5678")
	in.Recovery = recoveryRaw(t, rec)
	r, err := OpenWithFactors(path, in, OpenOptions{})
	if err != nil {
		t.Fatalf("open through the recovery composite: %v", err)
	}
	t.Cleanup(func() { r.Close() })
	return r, presentHW(t, r, f, rec)
}

// Recovery: a workspace opened through the recovery composite alone (no daily
// authenticator) is rotated onto new factors and the cold-role records, wrapped to
// the recovery public key, come with it.
//
// spec: SPO-Xcustody-OUT-011, SPO-Xcustody-PRE-021, SPO-Xcustody-INV-014
func TestRecoveryCompositeReEstablishesColdRecordsWithoutTheDailyFactor(t *testing.T) {
	s, path, f, rec := hwCold(t)
	putMnemonic(t, s, "alpha bravo charlie")
	oc := mustOuter(t, s, coldRef)
	if len(oc.RecoveryWrap()) != 32+32+16 {
		t.Fatalf("a hardware cold record carries a %d byte recovery wrap", len(oc.RecoveryWrap()))
	}
	s.Close()
	r, proof := recoveryHandle(t, path, f, rec)
	plan, inA := hardwarePlan(t, r, f, proof)
	plan.ColdNew.Mnemonic = fakeMnemonic{}
	text, _, err := r.Rotate(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	text.Destroy()
	r.Close()
	n, err := openHW(path, f, "devA", "1234")
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	n.SetColdSource(&ColdSource{Factors: &inA})
	if v, err := openString(t, n, coldRef); err != nil || v != "cold-secret-hw" {
		t.Fatalf("after recovery: %q %v", v, err)
	}
	if v, err := openString(t, n, mnRef); err != nil || v != "alpha bravo charlie" {
		t.Fatalf("the mnemonic after recovery: %q %v", v, err)
	}
	if err := n.Verify(ctx); err != nil {
		t.Fatal(err)
	}
}

func mustOuter(t *testing.T, s *Store, ref ports.Ref) *seal.ColdOuter {
	t.Helper()
	_, oc := headerOf(t, s, ref)
	return oc
}

// The planted-record attack: a cold record plus a matching recovery wrap of a key
// the attacker chose, made with only the public key, is refused at recovery
// because the key does not derive the record's identity.
//
// spec: SPO-Xcustody-PRE-021
func TestAPlantedColdRecordIsRefusedAtRecovery(t *testing.T) {
	s, path, f, rec := hwCold(t)
	var pub []byte
	if err := s.db.QueryRow(`SELECT recovery_pub FROM meta`).Scan(&pub); err != nil || len(pub) != 32 {
		t.Fatalf("recovery public key %x %v", pub, err)
	}
	ident := idOfKey(t, s, coldRef).Hash()
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
		meta := metaOf(s.ws, row.id, coldRef, seal.ClassSecretCold, row.version+1)
		hdr, _ := headerOf2(s, tx, coldRef, row)
		sub := secret.Take(bytes.Repeat([]byte{7}, 32))
		attacker := secret.Take([]byte("attacker chosen signing key"))
		planted, err := s.keys.SealSecretCold(meta, attacker, seal.ColdSeal{Sub: sub, Header: hdr, Recovery: &seal.ColdRecovery{Pub: pub, Identity: ident}})
		if err != nil {
			return nil, err
		}
		tag, _ := s.tag(coldRef)
		if _, err := q.ExecContext(ctx, `UPDATE records SET version=?, nonce=?, wrapped_key=?, owner_sealed=?, ciphertext=? WHERE id=?`,
			int64(row.version+1), planted.Nonce, planted.WrappedKey, planted.Owner, planted.Ciphertext, row.id); err != nil {
			return nil, err
		}
		h, _ := recordHash(string(coldRef.Kind), tag, planted)
		prev, _ := chainHead(ctx, q)
		return appendAudit(ctx, q, s.ws, s.keys, auditUpdate, time.Now().Unix(), prev, [][]any{{"put", "planted"}}, []touched{{ID: row.id, Version: row.version + 1, Hash: h}}, nil)
	}, nil)
	release()
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	r, proof := recoveryHandle(t, path, f, rec)
	plan, _ := hardwarePlan(t, r, f, proof)
	before := fileState(t, r)
	if _, _, err := r.Rotate(ctx, plan); !errors.Is(err, ErrRecoveredIdentity) {
		t.Fatalf("a planted record was carried through a recovery: %v", err)
	}
	if fileState(t, r) != before {
		t.Error("a refused recovery changed the file")
	}
}

func headerOf2(s *Store, tx *txn, ref ports.Ref, row *recRow) (seal.ColdHeader, error) {
	oc, err := s.keys.OpenColdOuter(metaOf(s.ws, row.id, ref, seal.ClassSecretCold, row.version), row.sealed)
	if err != nil {
		return seal.ColdHeader{}, err
	}
	return oc.Header, nil
}

// Under strict there is no recovery public key and no wrap.
//
// spec: SPO-Xcustody-MODE-005
func TestStrictColdRecordsCarryNoRecoveryWrap(t *testing.T) {
	path, _, f, _ := standardThenRotated(t, unlock.Strict)
	s, err := openHW(path, f, "devA", "1234")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	in := f.inputs("devA", "1234")
	s.SetColdSource(&ColdSource{Factors: &in})
	putSecret(t, s, coldRef, "strict cold key")
	if oc := mustOuter(t, s, coldRef); len(oc.RecoveryWrap()) != 0 {
		t.Fatal("a strict workspace wrapped a cold key to a recovery key")
	}
	var pub []byte
	if err := s.db.QueryRow(`SELECT recovery_pub FROM meta`).Scan(&pub); err != nil || pub != nil {
		t.Fatalf("recovery_pub %x %v", pub, err)
	}
	if v, err := openString(t, s, coldRef); err != nil || v != "strict cold key" {
		t.Fatalf("%q %v", v, err)
	}
	if oc := mustOuter(t, s, coldRef); len(oc.RecoveryWrap()) != 0 {
		t.Fatal("an open added a recovery wrap under strict")
	}
}

// A recovery public key that does not hash to the value the slots bind is never
// wrapped to.
//
// spec: SPO-Xcustody-PRE-023
func TestAReplacedRecoveryPublicKeyIsNotWrappedTo(t *testing.T) {
	s, _, _ := stdCold(t, "sub-key passphrase one")
	other := bytes.Repeat([]byte{9}, 32)
	exec(t, s, `UPDATE meta SET recovery_pub = ?`, other)
	k := secret.Take([]byte("a second cold key"))
	err := s.Update(ctx, func(w ports.Writer) error { return putKeyW(w, rf("pool2", ports.NodeSKey), k) })
	if !errors.Is(err, ErrRecoveryKeyMismatch) {
		t.Fatalf("%v", err)
	}
	// and an open, which writes the record again, does not wrap to it either
	if _, err := s.Open(ctx, coldRef); !errors.Is(err, ErrRecoveryKeyMismatch) {
		t.Fatalf("%v", err)
	}
}

// A rekey that makes a new recovery key wraps the cold records to it, without any
// sub-key factor, and the old recovery key no longer unwraps them.
//
// spec: SPO-Xcustody-OUT-011
func TestRekeyMovesTheRecoveryWrapOfColdRecordsToTheNewKey(t *testing.T) {
	s, _, rec := stdCold(t, "sub-key passphrase one")
	s.SetColdSource(nil) // the rekey needs no sub-key factor
	ident := idOfKey(t, s, coldRef).Hash()
	presentStd(t, s, rec)
	text, err := s.ChangePassphraseRekey(ctx, passphrase("a second workspace passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	var newKey string
	text.Use(func(b []byte) error { newKey = string(b); return nil })
	text.Destroy()
	oc := mustOuter(t, s, coldRef)
	if _, err := oc.RecoverDataKey(recPrivOf(t, rec).priv(), ident); err == nil {
		t.Error("the old recovery key still unwraps a cold record")
	}
	dk, err := oc.RecoverDataKey(recPrivOf(t, newKey).priv(), ident)
	if err != nil {
		t.Fatalf("the new recovery key does not unwrap: %v", err)
	}
	pt, err := oc.OpenSecretWithDataKey(dk)
	dk.Destroy()
	if err != nil || string(secretBytes(pt)) != "cold-secret-one" {
		t.Fatalf("%v", err)
	}
	pt.Destroy()
}

// A workspace of store format 2 with a pool cold key migrates only with a sub-key
// passphrase, and the key comes out in the cold form.
//
// spec: SPO-Xcustody-PR-005
func TestMigrationSealsColdKeysInTheColdFormat(t *testing.T) {
	p := format2Copy(t)
	old, err := OpenFormat2(p, legacyPW())
	if err != nil {
		t.Fatal(err)
	}
	orig, _ := os.ReadFile(p)
	if _, err := old.Migrate3(ctx, ""); !errors.Is(err, ErrColdFactorRequired) {
		t.Fatalf("a migration with cold keys and no sub-key passphrase: %v", err)
	}
	if now, _ := os.ReadFile(p); !bytes.Equal(orig, now) {
		t.Error("a refused migration changed the file")
	}
	old.SetColdSource(coldPass("sub-key passphrase one"))
	if _, err := old.Migrate3(ctx, ""); err != nil {
		t.Fatal(err)
	}
	old.Close()
	s, err := Open(p, legacyPW())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM records WHERE kind = 'node.skey' AND length(wrapped_key) <> 72`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("%d cold node.skey records, %v", n, err)
	}
	if rep, err := s.VerifyPayloadsReport(ctx); err != nil || rep.Records != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	s.SetColdSource(coldPass("sub-key passphrase one"))
	if n, err := s.VerifyColdPayloads(ctx); err != nil || n != 1 {
		t.Fatalf("%d %v", n, err)
	}
	// the legacy slots bind no recovery hash, so the migrated cold key has no recovery
	// wrap until a rekey adds one (SPO-Xcustody-PR-009)
	if cold, without, err := s.ColdWithoutWrap(ctx); err != nil || cold != 1 || without != 1 {
		t.Fatalf("cold records %d, without a recovery wrap %d: %v", cold, without, err)
	}
	_ = context.Background
}

// A backup and a restore of a workspace with cold-role records need no sub-key
// factor: they verify the file, and the restored file opens the record with it.
//
// spec: SPO-Xcustody-INV-015
func TestBackupAndRestoreOfColdRecordsNeedNoFactor(t *testing.T) {
	s, path, _ := stdCold(t, "sub-key passphrase one")
	s.SetColdSource(nil)
	bak := path + ".backup"
	if err := s.Backup(ctx, bak); err != nil {
		t.Fatal(err)
	}
	s.Close()
	dest := path + ".restored"
	if err := RestoreWithOptions(bak, dest, pw(), RestoreOptions{}); err != nil {
		t.Fatalf("restore needs the factor: %v", err)
	}
	r, err := Open(dest, pw())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if rep, err := r.VerifyPayloadsReport(ctx); err != nil || rep.Records != 1 || rep.OuterOnly != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	r.SetColdSource(coldPass("sub-key passphrase one"))
	if v, err := openString(t, r, coldRef); err != nil || v != "cold-secret-one" {
		t.Fatalf("%q %v", v, err)
	}
}
