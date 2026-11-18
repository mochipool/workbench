package sqlitestore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/unlock"
	"os"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
)

var (
	ccSKey  = rf("cc", ports.CCColdSKey)
	ccWords = rf("cc", ports.CCColdMnemonics)
)

// putCCCold writes a committee cold key and its mnemonic in one update, as
// `governance cc-cold generate --source mnemonic` does.
func putCCCold(s *Store) error {
	k := secret.Take([]byte("cc-cold-signing-key"))
	defer k.Destroy()
	words := secret.Take([]byte("alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike november oscar papa quebec romeo sierra tango uniform victor whiskey xray\n"))
	defer words.Destroy()
	return s.Update(ctx, func(w ports.Writer) error {
		if err := w.PutSecret(ccWords, words); err != nil {
			return err
		}
		return putKeyW(w, ccSKey, k)
	})
}

// The mnemonic of a committee cold key derives that key, so it is sealed in the
// cold form, bound to the key identity beside it; the master key alone does not
// open it, and a mnemonic with no verification key beside it is refused.
//
// spec: SPO-Xcustody-PRE-025
func TestTheMnemonicOfAColdRoleKeyIsSealedCold(t *testing.T) {
	s, _, _ := scratch(t)
	s.SetColdSource(coldPass("sub-key passphrase one"))
	if err := putCCCold(s); err != nil {
		t.Fatal(err)
	}
	row := rowOf(t, s, ccWords)
	if !seal.IsColdSealed(row.sealed) {
		t.Fatal("the mnemonic of a committee cold key is sealed hot")
	}
	if _, err := s.keys.OpenSecret(metaOf(s.ws, row.id, ccWords, seal.ClassSecret, uint64(row.version)), row.sealed); err == nil {
		t.Fatal("the master key alone opened a cold mnemonic")
	}
	s.SetColdSource(nil)
	if _, err := s.Open(ctx, ccWords); !errors.Is(err, ErrColdFactorRequired) {
		t.Fatalf("no factor: %v", err)
	}
	s.SetColdSource(coldPass("not the passphrase"))
	if _, err := s.Open(ctx, ccWords); !errors.Is(err, ErrColdFactorWrong) {
		t.Fatalf("wrong factor: %v", err)
	}
	s.SetColdSource(coldPass("sub-key passphrase one"))
	if v, err := openString(t, s, ccWords); err != nil || len(v) < 40 {
		t.Fatalf("%q %v", v, err)
	}
	// no verification key: nothing to bind it to, refused
	s2, _, _ := scratch(t)
	s2.SetColdSource(coldPass("sub-key passphrase one"))
	w := secret.Take([]byte("some words"))
	defer w.Destroy()
	err := s2.Update(ctx, func(w2 ports.Writer) error { return w2.PutSecret(rf("lone", ports.CCColdMnemonics), w) })
	if !errors.Is(err, labels.ErrNoKeyIdentity) {
		t.Fatalf("a cold mnemonic with no verification key: %v", err)
	}
	// the mnemonic of a hot role stays hot
	if err := s2.Update(ctx, func(w2 ports.Writer) error { return w2.PutSecret(rf("d", ports.DRepMnemonics), w) }); err != nil {
		t.Fatal(err)
	}
	if seal.IsColdSealed(rowOf(t, s2, rf("d", ports.DRepMnemonics)).sealed) {
		t.Error("a DRep mnemonic was sealed cold")
	}
}

func vkeyEnvelope(seed string) []byte {
	h := sha256.Sum256([]byte(seed))
	return pool.MarshalEnvelope(pool.Envelope{Type: "StakePoolVerificationKey_ed25519", CborHex: "5820" + hex.EncodeToString(h[:])})
}

// A kept upstream-encrypted key whose stem is a cold kind (<pool>.node) is sealed
// in the cold form through the verification key beside it, opens only with the
// factor (so key convert, which opens it first, needs the factor), and one with
// no verification key beside it is refused (ADR 0011 decision 2 and 6).
//
// spec: SPO-Xcustody-PRE-025, SPO-Xcustody-PR-001
func TestAKeptEncryptedColdKeyIsSealedColdOrRefused(t *testing.T) {
	s, _, _ := scratch(t)
	n := labels.Named(s)
	enc := []byte(`{"type":"StakePoolSigningKey_ed25519","description":"","encrHex":"00"}`)
	nref := ports.NamedRef{Name: "pool.node", Kind: ports.UpstreamEncryptedSKey}
	put := func() error {
		return n.Update(ctx, func(w ports.NamedWriter) error {
			return w.PutSecret(nref, secret.Take(append([]byte(nil), enc...)))
		})
	}
	// no verification key beside it: refused, not stored hot
	if err := put(); !errors.Is(err, labels.ErrColdNoSibling) {
		t.Fatalf("a cold stem with no sibling: %v", err)
	}
	if err := n.Update(ctx, func(w ports.NamedWriter) error {
		return w.Put(ports.NamedRef{Name: "pool", Kind: ports.NodeVKey}, vkeyEnvelope("pool cold"))
	}); err != nil {
		t.Fatal(err)
	}
	// with the sibling the record is cold: it needs the factor to be written
	if err := put(); !errors.Is(err, ErrColdFactorRequired) {
		t.Fatalf("no factor: %v", err)
	}
	s.SetColdSource(coldPass("sub-key passphrase one"))
	if err := put(); err != nil {
		t.Fatal(err)
	}
	refs, _ := s.ListRecords(ctx)
	var rec ports.Ref
	for _, r := range refs {
		if r.Kind == ports.UpstreamEncryptedSKey {
			rec = r
		}
	}
	if !seal.IsColdSealed(rowOf(t, s, rec).sealed) {
		t.Fatal("the kept cold key is sealed hot")
	}
	s.SetColdSource(nil)
	if _, err := n.Open(ctx, nref); !errors.Is(err, ErrColdFactorRequired) {
		t.Fatalf("opening it without the factor (key convert opens it first): %v", err)
	}
	s.SetColdSource(coldPass("sub-key passphrase one"))
	b, err := n.Open(ctx, nref)
	if err != nil || string(secretBytes(b)) != string(enc) {
		t.Fatalf("%v", err)
	}
	// a kept key of a hot stem stays hot
	if err := n.Update(ctx, func(w ports.NamedWriter) error {
		if err := w.Put(ports.NamedRef{Name: "w", Kind: ports.AddrVKey}, vkeyEnvelope("payment")); err != nil {
			return err
		}
		return w.PutSecret(ports.NamedRef{Name: "w.payment", Kind: ports.UpstreamEncryptedSKey}, secret.Take(append([]byte(nil), enc...)))
	}); err != nil {
		t.Fatal(err)
	}
}

// noRecoveryMaterial looks inside the handle for anything a recovery
// presentation left: the proof, its secret, the secret of an unlock through the
// recovery credential, and the claim that the handle came in that way.
func noRecoveryMaterial(t *testing.T, s *Store, when string) {
	t.Helper()
	if s.recProof != nil {
		t.Errorf("%s: the handle still holds a recovery proof", when)
	}
	if s.recSecret != nil {
		t.Errorf("%s: the handle still holds the recovery secret of its unlock", when)
	}
	if s.viaRecovery {
		t.Errorf("%s: the handle still counts as unlocked through the recovery credential", when)
	}
	if k := s.recoveryKeyOf(nil); k != nil {
		t.Errorf("%s: a recovery key can still be found: %v", when, k)
	}
}

// The recovery credential authorises one operation. After it, whatever its
// outcome, the handle holds no recovery proof and no recovery secret, a second
// guarded operation needs a new presentation, and no guarded buffer is left. A
// process that holds the master key of a long-lived handle then cannot derive the
// recovery private key and open the wraps of the cold records.
//
// spec: SPO-Xcustody-PRE-024
func TestTheRecoveryPresentationDoesNotOutliveTheOperationItAuthorises(t *testing.T) {
	// a handle that only the passphrase opened holds nothing
	s, _, rec := scratch(t)
	noRecoveryMaterial(t, s, "fresh handle")
	p2, p3, p4, p5 := passphrase("a second passphrase"), passphrase("a third passphrase"), passphrase(""), passphrase("a good passphrase")
	defer p2.Destroy()
	defer p3.Destroy()
	defer p4.Destroy()
	defer p5.Destroy()
	live := liveBuffers()

	// success
	presentStd(t, s, rec)
	if s.recProof == nil || s.recProof.key == nil {
		t.Fatal("the presentation holds no proof")
	}
	rk, err := s.ChangePassphraseRekey(ctx, p2)
	if err != nil {
		t.Fatal(err)
	}
	rk.Use(func(b []byte) error { rec = string(b); return nil })
	rk.Destroy()
	noRecoveryMaterial(t, s, "after a rekey")
	if _, err := s.ChangePassphraseRekey(ctx, p3); !errors.Is(err, ErrRecoveryNotPresented) {
		t.Fatalf("a second guarded operation without a new presentation: %v", err)
	}
	if got := liveBuffers(); got != live {
		t.Errorf("guarded buffers after a successful rekey: %d, baseline %d", got, live)
	}

	// failure: the operation is refused before any change, and still consumes
	presentStd(t, s, rec)
	if _, err := s.ChangePassphraseRekey(ctx, p4); !errors.Is(err, ErrRekeyCredentials) {
		t.Fatalf("an empty passphrase: %v", err)
	}
	noRecoveryMaterial(t, s, "after a refused rekey")
	if _, err := s.ChangePassphraseRekey(ctx, p5); !errors.Is(err, ErrRecoveryNotPresented) {
		t.Fatalf("an operation after a failed one: %v", err)
	}
	if got := liveBuffers(); got != live {
		t.Errorf("guarded buffers after a refused rekey: %d, baseline %d", got, live)
	}

	// a handle opened through the recovery credential is good for the recovery
	// operation and nothing else
	s2, path, rec2 := scratch(t)
	s2.Close()
	r, err := OpenWithRecovery(path, secret.Take([]byte(rec2)))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.recSecret == nil || !r.viaRecovery {
		t.Fatal("a handle opened through recovery holds no recovery secret")
	}
	p6, p7 := passphrase("the new passphrase after recovery"), passphrase("one more")
	defer p6.Destroy()
	defer p7.Destroy()
	nr, err := r.ChangePassphraseRekey(ctx, p6)
	if err != nil {
		t.Fatal(err)
	}
	nr.Destroy()
	noRecoveryMaterial(t, r, "after the recovery rekey")
	if _, err := r.ChangePassphraseRekey(ctx, p7); !errors.Is(err, ErrRecoveryNotPresented) {
		t.Fatalf("a second operation on a handle opened through recovery: %v", err)
	}
}

// The same for a hardware workspace: the composite slot key held as the proof is
// destroyed by a rotation, refused or not.
//
// spec: SPO-Xcustody-PRE-024
func TestTheHardwareRecoveryPresentationDoesNotOutliveTheOperationItAuthorises(t *testing.T) {
	s, _, f, rec := hwCold(t)
	p := presentHW(t, s, f, rec)
	if p.key == nil || p.key.secret == nil || !p.key.hardware {
		t.Fatal("no composite slot key was held")
	}
	live := liveBuffers() - 1 // the composite slot key is the one buffer the presentation keeps
	if _, _, err := s.Rotate(ctx, RotatePlan{Proof: p}); err == nil {
		t.Fatal("an empty plan was accepted")
	}
	noRecoveryMaterial(t, s, "after a refused rotation")
	tbl, err := s.currentTable(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.rotationGuard(RotatePlan{Policy: unlock.Hardware})(tbl); !errors.Is(err, ErrRecoveryNotPresented) {
		t.Fatalf("a second rotation: %v", err)
	}
	if got := liveBuffers(); got != live {
		t.Errorf("guarded buffers: %d, baseline %d", got, live)
	}
}

// A signing key of a cold role stored under a hot kind would be sealed hot, and a
// hot key under a cold kind misleads the classification: the store refuses both
// by the type of the envelope.
//
// spec: SPO-Xcustody-PRE-026
func TestAnEnvelopeTypeThatDoesNotMatchTheRecordKindIsRefused(t *testing.T) {
	s, _, _ := scratch(t)
	s.SetColdSource(coldPass("sub-key passphrase one"))
	cold := secret.Take([]byte(`{"type":"StakePoolSigningKey_ed25519","description":"","cborHex":"5820aa"}`))
	defer cold.Destroy()
	hot := secret.Take([]byte(`{"type":"PaymentSigningKeyShelley_ed25519","description":"","cborHex":"5820bb"}`))
	defer hot.Destroy()
	before := count(t, s, "records")
	for _, kind := range []ports.Kind{ports.AddrSKey, ports.StakingSKey, ports.DRepSKey} {
		err := s.Update(ctx, func(w ports.Writer) error { return putKeyW(w, rf("w", kind), cold) })
		if !errors.Is(err, ports.ErrEnvelopeKind) {
			t.Errorf("a pool cold envelope under %s: %v", kind, err)
		}
	}
	if count(t, s, "records") != before {
		t.Error("a refused put left records behind")
	}
	// the matching ones are accepted, and the cold one is sealed cold
	if err := s.Update(ctx, func(w ports.Writer) error { return putKeyW(w, rf("p", ports.NodeSKey), cold) }); err != nil {
		t.Fatal(err)
	}
	if !seal.IsColdSealed(rowOf(t, s, rf("p", ports.NodeSKey)).sealed) {
		t.Error("the pool cold key is not sealed cold")
	}
	if err := s.Update(ctx, func(w ports.Writer) error { return putKeyW(w, rf("w", ports.AddrSKey), hot) }); err != nil {
		t.Fatal(err)
	}
}

// A handle unlocked through the recovery composite does not create a cold record
// bound to the recovery authenticator.
//
// spec: SPO-Xcustody-PRE-028
func TestNoColdRecordIsBoundToTheRecoveryAuthenticator(t *testing.T) {
	_, path, f, rec := hwCold(t)
	raw, err := seal.DecodeRecoveryKey(secret.Take([]byte(rec)))
	if err != nil {
		t.Fatal(err)
	}
	in := f.inputs("devB", "5678")
	in.Recovery = func(context.Context) (*secret.Buffer, error) { return secret.Take(rawBytes(raw)), nil }
	r, err := OpenWithFactors(path, in, OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	cin := f.inputs("devB", "5678")
	r.SetColdSource(&ColdSource{Factors: &cin, Deriver: fakeDeriver{}})
	k := secret.Take([]byte("a second cold key"))
	defer k.Destroy()
	n := count(t, r, "records")
	err = r.Update(ctx, func(w ports.Writer) error { return putKeyW(w, rf("pool2", ports.NodeSKey), k) })
	if !errors.Is(err, ErrColdViaRecovery) {
		t.Fatalf("a cold record created through the recovery slot: %v", err)
	}
	if count(t, r, "records") != n {
		t.Error("a refused put left records behind")
	}
}

// When a key gains a cold role the hot versions of its records are not left in
// the write-ahead log.
//
// spec: SPO-Xcustody-PR-004
func TestAKeyThatGainsAColdRoleLeavesNoHotVersionInTheWAL(t *testing.T) {
	s, path, _ := scratch(t)
	s.SetColdSource(coldPass("sub-key passphrase one"))
	ref := rf("w", ports.AddrSKey)
	putSecret(t, s, ref, "payment-key-bytes-in-the-wal")
	if fi, err := os.Stat(path + "-wal"); err != nil || fi.Size() == 0 {
		t.Skip("no write-ahead log to truncate in this environment")
	}
	id := idOfKey(t, s, ref)
	if err := s.Update(ctx, func(w ports.Writer) error { return labels.RecordRole(w, id, custody.RolePoolCold) }); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path + "-wal"); err == nil && fi.Size() != 0 {
		t.Errorf("the -wal file holds %d bytes after the key gained a cold role", fi.Size())
	}
}

// Under standard a second cold record is not sealed under another sub-key
// passphrase: the store opens the outer layer with the master key and tries the
// offered passphrase on an existing record.
//
// spec: SPO-Xcustody-PRE-027
func TestASecondColdRecordNeedsTheSameColdPassphrase(t *testing.T) {
	s, _, _ := stdCold(t, "sub-key passphrase one")
	k := secret.Take([]byte("a second cold key"))
	defer k.Destroy()
	put := func() error {
		return s.Update(ctx, func(w ports.Writer) error { return putKeyW(w, rf("pool2", ports.NodeSKey), k) })
	}
	s.SetColdSource(coldPass("another passphrase"))
	n := count(t, s, "records")
	if err := put(); !errors.Is(err, ErrColdPassphraseDiffers) {
		t.Fatalf("a different cold passphrase: %v", err)
	}
	if count(t, s, "records") != n {
		t.Error("a refused put left records behind")
	}
	s.SetColdSource(coldPass("sub-key passphrase one"))
	if err := put(); err != nil {
		t.Fatalf("the same cold passphrase: %v", err)
	}
}

// A format 2 store may hold signing keys whose identity has no role history
// (Calidus and Catalyst voting keys were written without one). No on-disk format
// 2 fixture holds such keys: the committed one comes from the format 1 fixture,
// whose generator can no longer run and which holds none of those kinds, and a
// format 2 handle cannot be written to. The format 2 shape is built here instead:
// records hot-sealed, histories deleted, and the migration step run on it.
//
// spec: SPO-Xcustody-PR-005
func TestMigrationRecordsMissingRoleHistoriesFromTheStoredVerificationKeys(t *testing.T) {
	s, _, _ := scratch(t)
	s.SetColdSource(coldPass("sub-key passphrase one"))
	calidus, catalyst := rf("c", ports.CalidusSKey), rf("v", ports.VotingSKey)
	hotSecrets := map[ports.Ref]string{
		calidus: "calidus-key", catalyst: "catalyst-key", ccSKey: "cc-cold-signing-key",
		ccWords: "the committee words", coldRef: "pool-cold-key",
	}
	if err := s.Update(ctx, func(w ports.Writer) error {
		for _, r := range []ports.Ref{calidus, catalyst, ccSKey, coldRef} {
			k := secret.Take([]byte(hotSecrets[r]))
			err := putKeyW(w, r, k)
			k.Destroy()
			if err != nil {
				return err
			}
		}
		m := secret.Take([]byte(hotSecrets[ccWords]))
		defer m.Destroy()
		return w.PutSecret(ccWords, m)
	}); err != nil {
		t.Fatal(err)
	}
	// the shape of a format 2 store: no history for these keys; cold roles sealed hot
	ids := map[ports.Ref]identity.Ref{calidus: idOfKey(t, s, calidus), catalyst: idOfKey(t, s, catalyst), ccSKey: idOfKey(t, s, ccSKey)}
	if err := s.Update(ctx, func(w ports.Writer) error {
		for _, id := range ids {
			if err := w.Delete(ports.Ref{Anchor: id, Kind: ports.RoleHistory}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, r := range []ports.Ref{ccSKey, ccWords, coldRef} {
		r := r
		forgeRow(t, s, r, func(m seal.RecordMeta) seal.SealedRecord {
			sealed, err := s.keys.SealSecret(m, secret.Take([]byte(hotSecrets[r])))
			if err != nil {
				t.Fatal(err)
			}
			return sealed
		})
	}
	// the planner: classification fails today without the fix; with it the
	// histories are recorded from the verification keys and each key is classified
	prep, err := s.gatherColdCreate(ctx, 3) // the factor is gathered before the write transaction
	if err != nil {
		t.Fatal(err)
	}
	defer prep.destroy()
	release, err := s.enter(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	_, err = s.withWriteTx(ctx, func(q dbq) (*Head, error) {
		var h *Head
		var e error
		if e = s.catchUp(ctx, q); e != nil {
			return nil, e
		}
		n, h, e = s.sealColdRecordsH(ctx, q, prep, nil)
		return h, e
	}, nil)
	release()
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("%d records sealed cold, want 3 (pool cold, committee cold key and its mnemonic)", n)
	}
	for r, id := range ids {
		h, err := get(s, ports.Ref{Anchor: id, Kind: ports.RoleHistory})
		if err != nil || len(h) == 0 {
			t.Errorf("%s: no role history recorded: %v", r.Kind, err)
		}
	}
	for r, want := range map[ports.Ref]bool{calidus: false, catalyst: false, ccSKey: true, ccWords: true, coldRef: true} {
		if got := seal.IsColdSealed(rowOf(t, s, r).sealed); got != want {
			t.Errorf("%s: cold-sealed %v, want %v", r.Kind, got, want)
		}
	}
}

// No read path releases the payload of a cold record that a master-key holder
// replaced by a hot-form blob: the store's Open (which signers, export and key
// convert use, directly or through labels.Named, which only resolves the name) and an Open after a backup and a
// restore all refuse with ErrColdClassMismatch. Opening the file does not notice
// (only payload verification does), which is acceptable because no read releases
// the payload. The other readers of the sealed form either destroy what they open
// (verification) or re-seal it without releasing it (migration, rotation).
//
// spec: SPO-Xcustody-INV-010
func TestNoReadPathReleasesAColdRecordReplacedByAHotForm(t *testing.T) {
	s, path, _ := stdCold(t, "sub-key passphrase one")
	forgeRow(t, s, coldRef, func(m seal.RecordMeta) seal.SealedRecord {
		r, err := s.keys.SealSecret(m, secret.Take([]byte("attacker chosen")))
		if err != nil {
			t.Fatal(err)
		}
		return r
	})
	if _, err := s.Open(ctx, coldRef); !errors.Is(err, ErrColdClassMismatch) {
		t.Fatalf("Open: %v", err)
	}
	// a real read inside a view: the transaction's own opener (the one the label layer
	// uses) refuses the replaced record too
	var viaView error
	read := false
	if err := s.View(ctx, func(r ports.Reader) error {
		tt, ok := r.(*txn)
		if !ok {
			t.Fatalf("a view hands out %T, not the store's transaction", r)
		}
		read = true
		var b *secret.Buffer
		if b, viaView = tt.OpenSecret(coldRef); viaView == nil {
			b.Destroy()
		}
		return nil
	}); err != nil || !read {
		t.Fatalf("view: %v (read %v)", err, read)
	}
	if !errors.Is(viaView, ErrColdClassMismatch) && !errors.Is(viaView, ErrColdInTransaction) {
		t.Fatalf("OpenSecret inside a view: %v", viaView)
	}
	bak := path + ".backup"
	if err := s.Backup(ctx, bak); err != nil {
		t.Fatal(err)
	}
	s.Close()
	dest := path + ".restored"
	if err := RestoreWithOptions(bak, dest, pw(), RestoreOptions{}); err != nil {
		t.Fatal(err)
	}
	r, err := Open(dest, pw())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.Open(ctx, coldRef); !errors.Is(err, ErrColdClassMismatch) {
		t.Fatalf("Open after backup and restore: %v", err)
	}
}

// The factor is presented with no write lock held: a second writer is not blocked
// during the prompt; a record changed meanwhile makes the open repeat once; a
// read-only handle opens the record and writes nothing.
//
// spec: SPO-Xcustody-INV-016
func TestTheColdFactorIsPresentedOutsideTheWriteTransaction(t *testing.T) {
	s, path, _ := stdCold(t, "sub-key passphrase one")
	b, err := Open(path, pw())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	// 1. a second writer proceeds during the prompt
	var wrote error
	prompts := 0
	s.SetColdSource(&ColdSource{Passphrase: func(pctx context.Context, create bool) (*secret.Buffer, error) {
		prompts++
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		k := secret.Take([]byte("written during the prompt"))
		defer k.Destroy()
		wrote = b.Update(cctx, func(w ports.Writer) error { return w.Put(rf("other", ports.KesCounter), []byte("1")) })
		return secret.Take([]byte("sub-key passphrase one")), nil
	}})
	if v, err := openString(t, s, coldRef); err != nil || v != "cold-secret-one" {
		t.Fatalf("%q %v", v, err)
	}
	if wrote != nil {
		t.Errorf("a second writer was blocked or failed during the prompt: %v", wrote)
	}
	// 2. the record is rewritten by another handle during the prompt: one repeat
	prompts = 0
	b.SetColdSource(coldPass("sub-key passphrase one"))
	s.SetColdSource(&ColdSource{Passphrase: func(pctx context.Context, create bool) (*secret.Buffer, error) {
		prompts++
		if prompts == 1 {
			if v, err := b.Open(ctx, coldRef); err != nil {
				t.Errorf("the other handle: %v", err)
			} else {
				v.Destroy()
			}
		}
		return secret.Take([]byte("sub-key passphrase one")), nil
	}})
	if v, err := openString(t, s, coldRef); err != nil || v != "cold-secret-one" {
		t.Fatalf("after a race: %q %v", v, err)
	}
	if prompts != 2 {
		t.Errorf("%d prompts, want 2 (one repeat)", prompts)
	}
	// 3. a read-only handle opens it and rotates nothing
	s.Close()
	b.Close()
	ro, err := open(path, credential{kind: seal.SlotPassphrase, buf: pw()}, true, OpenOptions{AcceptRollback: true})
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	ro.SetColdSource(coldPass("sub-key passphrase one"))
	before := fileState(t, ro)
	if v, err := openString(t, ro, coldRef); err != nil || v != "cold-secret-one" {
		t.Fatalf("read-only open: %q %v", v, err)
	}
	if fileState(t, ro) != before {
		t.Error("a read-only open changed the file")
	}
}
