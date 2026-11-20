package sqlitestore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/unlock"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Cold-key recovery after the sixth review: what a rotation or recovery may leave
// behind, how a record is opened whatever the policy, the cold mnemonic, and what
// `store verify` says about records that are out of step.

var mnRef = ports.Ref{Anchor: anchorOf("cc"), Kind: ports.CCColdMnemonics}

// fakeMnemonic derives the verification key of the fixture's mnemonics from the words
// and the account and index the file records (0, 0 when it records none), the way
// putMnemonicAt wrote the sibling verification key.
type fakeMnemonic struct{}

func mnemonicVKeyAt(words string, account, index uint32) []byte {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%d", words, account, index)))
	return pool.MarshalEnvelope(pool.Envelope{Type: "VerificationKey_ed25519", Description: "", CborHex: "5820" + hex.EncodeToString(h[:])})
}

func (fakeMnemonic) DeriveColdMnemonicVKey(_ context.Context, f *secret.Buffer) ([]byte, error) {
	w, a, i, err := ports.SplitMnemonicFile(f)
	if err != nil {
		return nil, err
	}
	defer w.Destroy()
	return mnemonicVKeyAt(string(secretBytes(w)), a, i), nil
}

// putMnemonic stores the cold mnemonic record (derived at 0, 0).
func putMnemonic(t *testing.T, s *Store, words string) { putMnemonicAt(t, s, words, 0, 0, false) }

// putMnemonicAt stores the cold mnemonic record whose key was derived at account and
// index; with meta the file records that path (as the generator now writes it), without
// it the record is a legacy one that says nothing.
func putMnemonicAt(t *testing.T, s *Store, words string, account, index uint32, meta bool) {
	t.Helper()
	env := mnemonicVKeyAt(words, account, index)
	id, err := ports.IdentityOfVKey(custody.RoleCommitteeCold, env)
	if err != nil {
		t.Fatal(err)
	}
	hist, err := custody.NewRoleHistory(id, custody.RoleCommitteeCold)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := hist.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	k := owned(secret.Take([]byte(words)))
	if meta {
		k, err = ports.MnemonicFileWithDerivation(k, account, index)
		if err != nil {
			t.Fatal(err)
		}
	}
	defer k.Destroy()
	if err := s.Update(ctx, func(w ports.Writer) error {
		if err := w.Put(ports.Ref{Anchor: mnRef.Anchor, Kind: ports.CCColdVKey}, env); err != nil {
			return err
		}
		if err := w.Put(ports.Ref{Anchor: id, Kind: ports.RoleHistory}, hb); err != nil {
			return err
		}
		return w.PutSecret(mnRef, k)
	}); err != nil {
		t.Fatal(err)
	}
}

// recordName is how the store names a record that has no label.
func nameOfRef(ref ports.Ref) string {
	return string(ref.Kind) + "/" + hex.EncodeToString(ref.Anchor.Hash()[:6])
}

// forgeColdWith seals the cold record of ref again with the header given, a sub-key
// nobody holds, and a recovery wrap when wrap is set.
func forgeColdWith(t *testing.T, s *Store, ref ports.Ref, plain string, hdr seal.ColdHeader, wrap bool) {
	t.Helper()
	var ident []byte
	if ref.Kind == ports.CCColdMnemonics {
		b, err := get(s, ports.Ref{Anchor: ref.Anchor, Kind: ports.CCColdVKey})
		if err != nil {
			t.Fatal(err)
		}
		id, err := ports.IdentityOfVKey(custody.RoleCommitteeCold, b)
		if err != nil {
			t.Fatal(err)
		}
		ident = id.Hash()
	} else {
		ident = idOfKey(t, s, ref).Hash()
	}
	var pub []byte
	if err := s.db.QueryRow(`SELECT recovery_pub FROM meta`).Scan(&pub); err != nil {
		t.Fatal(err)
	}
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
		cs := seal.ColdSeal{Sub: owned(secret.Take(bytes.Repeat([]byte{7}, 32))), Header: hdr}
		if wrap {
			cs.Recovery = &seal.ColdRecovery{Pub: pub, Identity: ident}
		}
		sealed, err := s.keys.SealSecretCold(meta, owned(secret.Take([]byte(plain))), cs)
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

func passHeader(salt byte) seal.ColdHeader {
	return seal.ColdHeader{Kind: seal.ColdPassphrase, KDF: kdfForNewSlots, Salt: bytes.Repeat([]byte{salt}, seal.SaltSize)}
}

// hardwarePlanFor is hardwarePlan with the daily authenticator named (a NEW one when a
// daily authenticator was lost).
func hardwarePlanFor(t *testing.T, s *Store, f *fakeSource, proof *RecoveryProof, dailyDev, dailyPIN string) (RotatePlan, FactorInputs) {
	t.Helper()
	fa, _, err := enrolOwned(ctx, f.inputs(dailyDev, dailyPIN), s.ws, nil)
	if err != nil {
		t.Fatal(err)
	}
	fb, _, err := enrolOwned(ctx, f.inputs("devB", pinB), s.ws, nil)
	if err != nil {
		t.Fatal(err)
	}
	in := f.inputs(dailyDev, dailyPIN)
	return RotatePlan{Policy: unlock.Hardware, Proof: proof, Slots: []SlotPlan{
		{Kind: seal.SlotFIDO2HMAC, Factors: []FactorPlan{fa}},
		{Kind: seal.SlotComposite, Factors: []FactorPlan{{Params: seal.FactorParams{Kind: seal.FactorRecovery}}, fb}},
	}, ColdNew: &ColdSource{Factors: &in, Deriver: fakeDeriver{}, Mnemonic: fakeMnemonic{}}}, in
}

// stdTwoCold is a standard workspace with the pool cold key, the cold mnemonic and a
// second cold key without a recovery wrap (as a migrated one is).
func stdTwoCold(t *testing.T) (*Store, string, string, ports.Ref) {
	t.Helper()
	s, path, rec := stdCold(t, "sub-key passphrase one")
	putMnemonic(t, s, "alpha bravo charlie")
	two := rf("pool2", ports.NodeSKey)
	putSecret(t, s, two, "cold key two")
	forgeColdNoWrap(t, s, two, "sub-key passphrase one", "cold key two")
	return s, path, rec, two
}

// M3a: a rotation that changes the cold factor and would leave a record under the old
// one is refused before anything is written, and names the record. The opt-in leaves
// exactly the record named.
//
// spec: SPO-Xcustody-PRE-030, SPO-Xcustody-PRE-031
func TestRotationRefusesToLeaveColdRecordsUnderTheOldFactor(t *testing.T) {
	s, _, rec, two := stdTwoCold(t)
	s.SetColdSource(coldPass("I forgot it"))
	f := newFake()
	// every attempt presents the recovery credential again: a rotation consumes its proof
	mkPlan := func(leave ...string) RotatePlan {
		plan, _ := hardwarePlan(t, s, f, presentStd(t, s, rec))
		plan.ColdNew.Mnemonic = fakeMnemonic{}
		plan.ColdNew.LeaveUnreachable = leave
		return plan
	}
	before := fileState(t, s)
	_, _, err := s.Rotate(ctx, mkPlan())
	if !errors.Is(err, ErrColdWouldStrand) || !strings.Contains(err.Error(), nameOfRef(two)) {
		t.Fatalf("a rotation that would strand a record: %v", err)
	}
	if fileState(t, s) != before {
		t.Error("a refused rotation changed the file")
	}
	// naming a record that is not a cold record is refused too, and nothing is written
	if _, _, err := s.Rotate(ctx, mkPlan("pool.skey/nothing")); !errors.Is(err, ErrColdLeaveUnknown) {
		t.Fatalf("an unknown record named in --leave-unreachable: %v", err)
	}
	if fileState(t, s) != before {
		t.Error("a refused rotation changed the file")
	}
	// the opt-in
	text, _, err := s.Rotate(ctx, mkPlan(nameOfRef(two)))
	if err != nil {
		t.Fatalf("the rotation with the record left: %v", err)
	}
	text.Destroy()
	if !auditHas(t, s, "cold-left") {
		t.Error("no cold-left event in the audit trail")
	}
	// M3b: the record left under a passphrase header in a hardware workspace opens with its passphrase
	if h, _ := headerOf(t, s, two); h.Kind != seal.ColdPassphrase {
		t.Fatalf("the left record's header: %+v", h)
	}
	s.SetColdSource(coldPass("sub-key passphrase one"))
	if v, err := openString(t, s, two); err != nil || v != "cold key two" {
		t.Fatalf("a record under a passphrase header in a hardware workspace: %q %v", v, err)
	}
	// M5: the store names it
	st, err := s.ColdStatus(ctx)
	if err != nil || len(st.Problems) != 1 || st.Problems[0].Record != nameOfRef(two) {
		t.Fatalf("cold status: %+v %v", st, err)
	}
}

// The PoC of the review: a wrong cold passphrase wired, a rotation to hardware with the
// proof, a pool cold key and a cold mnemonic. The mnemonic is re-established through its
// recovery wrap, so nothing is stranded.
//
// spec: SPO-Xcustody-PRE-030
func TestRotationReestablishesTheColdMnemonicThroughItsWrap(t *testing.T) {
	s, _, rec := stdCold(t, "sub-key passphrase one")
	putMnemonic(t, s, "alpha bravo charlie")
	s.SetColdSource(coldPass("I forgot it"))
	f := newFake()
	plan, inA := hardwarePlan(t, s, f, presentStd(t, s, rec))
	plan.ColdNew.Mnemonic = fakeMnemonic{}
	text, _, err := s.Rotate(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	text.Destroy()
	for _, r := range []ports.Ref{coldRef, mnRef} {
		if h, _ := headerOf(t, s, r); h.Kind != seal.ColdFIDO2 {
			t.Fatalf("%s is still under %+v", r.Kind, h)
		}
	}
	s.SetColdSource(&ColdSource{Factors: &inA})
	if v, err := openString(t, s, mnRef); err != nil || v != "alpha bravo charlie" {
		t.Fatalf("the mnemonic after the rotation: %q %v", v, err)
	}
	if cold, without, err := s.ColdWithoutWrap(ctx); err != nil || cold != 2 || without != 0 {
		t.Fatalf("cold %d without a wrap %d: %v", cold, without, err)
	}
	if err := s.Verify(ctx); err != nil {
		t.Fatal(err)
	}
}

// M6: a cold mnemonic whose wrap does not derive the identity of the key beside it is
// refused as tampering, not skipped.
//
// spec: SPO-Xcustody-PRE-021
func TestAPlantedColdMnemonicIsRefusedAtRecovery(t *testing.T) {
	s, _, rec := stdCold(t, "sub-key passphrase one")
	putMnemonic(t, s, "alpha bravo charlie")
	forgeColdWith(t, s, mnRef, "attacker words", passHeader(5), true)
	s.SetColdSource(coldPass("I forgot it"))
	f := newFake()
	plan, _ := hardwarePlan(t, s, f, presentStd(t, s, rec))
	plan.ColdNew.Mnemonic = fakeMnemonic{}
	before := fileState(t, s)
	if _, _, err := s.Rotate(ctx, plan); !errors.Is(err, ErrRecoveredIdentity) {
		t.Fatalf("a planted mnemonic: %v", err)
	}
	if fileState(t, s) != before {
		t.Error("a refused recovery changed the file")
	}
	if isFactorError(ErrRecoveredIdentity) {
		t.Error("a planted record is reported as a factor error")
	}
}

// Hardware recovery of the mnemonic with a NEW daily authenticator: the lost one is not
// enrolled again, and afterwards it opens nothing.
//
// spec: SPO-Xcustody-PRE-021, SPO-Xcustody-PRE-030
func TestHardwareRecoveryReestablishesTheMnemonicOnANewAuthenticator(t *testing.T) {
	s, path, f, rec := hwCold(t)
	putMnemonic(t, s, "alpha bravo charlie")
	s.Close()
	f.auths["devC"] = &fakeAuth{3, "seed-c", pinC}
	r, proof := recoveryHandle(t, path, f, rec)
	enrolsBefore := f.enrols
	plan, inC := hardwarePlanFor(t, r, f, proof, "devC", pinC)
	text, _, err := r.Rotate(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	text.Destroy()
	if f.enrols != enrolsBefore+2 {
		t.Errorf("the recovery enrolled %d credentials, want the new daily and the recovery one", f.enrols-enrolsBefore)
	}
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
	for ref, want := range map[ports.Ref]string{coldRef: "cold-secret-hw", mnRef: "alpha bravo charlie"} {
		if v, err := openString(t, n, ref); err != nil || v != want {
			t.Fatalf("%s after recovery: %q %v", ref.Kind, v, err)
		}
	}
}

// M4: a recovery rekey re-seals every record the old factor opened under the new factor,
// so the workspace does not end with two cold passphrases.
//
// spec: SPO-Xcustody-PRE-030
func TestRecoveryRekeyReestablishesEveryRecordTheOldFactorOpened(t *testing.T) {
	s, path, rec, two := stdTwoCold(t)
	s.Close()
	r, err := OpenWithRecovery(path, passphrase(rec))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.SetColdSource(coldPass("sub-key passphrase one")) // the old cold passphrase is still known
	src := &ColdSource{Deriver: fakeDeriver{}, Mnemonic: fakeMnemonic{}, Passphrase: func(context.Context, bool) (*secret.Buffer, error) {
		return secret.Take([]byte("a new cold passphrase")), nil
	}}
	text, err := r.ChangePassphraseRekeyCold(ctx, passphrase("the recovered workspace passphrase"), src)
	if err != nil {
		t.Fatal(err)
	}
	text.Destroy()
	for _, ref := range []ports.Ref{coldRef, mnRef, two} {
		r.SetColdSource(coldPass("sub-key passphrase one"))
		if _, err := r.Open(ctx, ref); !errors.Is(err, ErrColdFactorWrong) {
			t.Errorf("%s still opens under the OLD cold passphrase: %v", ref.Kind, err)
		}
		r.SetColdSource(coldPass("a new cold passphrase"))
		if v, err := openString(t, r, ref); err != nil || v == "" {
			t.Errorf("%s under the new cold passphrase: %q %v", ref.Kind, v, err)
		}
	}
}

// M4: the check that a new cold passphrase is the one the existing records open with looks
// at every passphrase-sealed cold record, and a workspace that is already split says so.
//
// spec: SPO-Xcustody-INV-023
func TestAColdPassphraseThatOpensOnlySomeRecordsIsReportedAsASplit(t *testing.T) {
	s, _, _ := stdCold(t, "sub-key passphrase one")
	two := rf("pool2", ports.NodeSKey)
	putSecret(t, s, two, "cold key two")
	forgeColdWith(t, s, two, "cold key two", passHeader(9), true) // sealed under nothing the passphrase opens
	// make the second record open with another passphrase: forge it with that passphrase
	forgeColdNoWrap(t, s, two, "another passphrase", "cold key two")
	err := s.Update(ctx, func(w ports.Writer) error {
		return putKeyW(w, rf("pool3", ports.NodeSKey), owned(secret.Take([]byte("cold key three"))))
	})
	if !errors.Is(err, ErrColdSplit) || !strings.Contains(err.Error(), "store verify") {
		t.Fatalf("creating a cold record in a split workspace: %v", err)
	}
}

// M5: `store verify` counts and names records out of step with the policy, whose credential
// belongs to no daily slot, and records a recovery left behind; a cold status read that fails
// is a verification failure.
//
// spec: SPO-Xcustody-INV-023
func TestColdStatusNamesRecordsThatAreOutOfStep(t *testing.T) {
	s, path, f, _ := hwCold(t)
	two := rf("pool2", ports.NodeSKey)
	putSecret(t, s, two, "cold key two")
	forgeColdWith(t, s, two, "cold key two", seal.ColdHeader{Kind: seal.ColdFIDO2, Credential: bytes.Repeat([]byte{9}, 33), Salt: bytes.Repeat([]byte{1}, 32), Next: bytes.Repeat([]byte{2}, 32)}, true)
	three := rf("pool3", ports.NodeSKey)
	putSecret(t, s, three, "cold key three")
	forgeColdWith(t, s, three, "cold key three", passHeader(3), true)
	st, err := s.ColdStatus(ctx)
	if err != nil || st.Records != 3 || len(st.Problems) != 2 {
		t.Fatalf("%+v %v", st, err)
	}
	got := st.Problems[0].Record + " " + st.Problems[1].Record
	if !strings.Contains(got, nameOfRef(two)) || !strings.Contains(got, nameOfRef(three)) {
		t.Errorf("problems %+v", st.Problems)
	}
	in := f.inputs("devA", pinA)
	s.Close()
	res, err := VerifyFileFactors(path, in, false)
	if !errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), nameOfRef(two)) {
		t.Fatalf("store verify of a workspace with records out of step: %v (%+v)", err, res)
	}
	restore := setColdStatusHook(func(*Store, context.Context) (ColdStatus, error) {
		return ColdStatus{}, errors.New("injected status failure")
	})
	defer restore()
	if _, err := VerifyFileFactors(path, in, false); !errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), "injected status failure") {
		t.Fatalf("a failing cold status read: %v", err)
	}
}

// S5: the per-record fallback counter is shown by the cold status and by store verify.
//
// spec: SPO-Xcustody-INV-020
func TestColdStatusShowsTheFallbackCounter(t *testing.T) {
	s, path, f, _ := hwCold(t)
	f.corruptNext = 1
	if _, err := openString(t, s, coldRef); err != nil {
		t.Fatal(err)
	}
	f.corruptNext = 0
	if _, err := openString(t, s, coldRef); err != nil { // heals
		t.Fatal(err)
	}
	st, err := s.ColdStatus(ctx)
	if err != nil || len(st.Fallbacks) != 1 || st.Fallbacks[0].Count != 1 {
		t.Fatalf("%+v %v", st, err)
	}
	in := f.inputs("devA", pinA)
	s.Close()
	res, err := VerifyFileFactors(path, in, false)
	if err != nil || !strings.Contains(strings.Join(res.Notices, "\n"), "healed") {
		t.Fatalf("%v %v", err, res.Notices)
	}
}

// S1: a cold record written between the gather and the lock is not left under the old factor.
//
// spec: SPO-Xcustody-PRE-030
func TestAColdRecordWrittenDuringTheGatherFailsTheRotation(t *testing.T) {
	s, path, rec := stdCold(t, "sub-key passphrase one")
	proof := presentStd(t, s, rec)
	raced := false
	plan := RotatePlan{Policy: unlock.Standard, Proof: proof, Slots: []SlotPlan{
		{Kind: seal.SlotPassphrase, Passphrase: passphrase("a second workspace passphrase")}, {Kind: seal.SlotRecovery}},
		ColdNew: &ColdSource{Deriver: fakeDeriver{}, Passphrase: func(context.Context, bool) (*secret.Buffer, error) {
			if !raced {
				raced = true
				b, err := Open(path, pw())
				if err != nil {
					t.Error(err)
				} else {
					b.SetColdSource(coldPass("sub-key passphrase one"))
					putSecret(t, b, rf("pool2", ports.NodeSKey), "cold key two")
					b.Close()
				}
			}
			return secret.Take([]byte("a new cold passphrase")), nil
		}}}
	before := fileState(t, s)
	if _, _, err := s.Rotate(ctx, plan); !errors.Is(err, ErrColdWrapRaced) {
		t.Fatalf("a rotation that raced a cold write: %v", err)
	}
	// the raced write is the only change: the refused rotation wrote nothing of its own
	if after := fileState(t, s); after == before {
		t.Fatal("the other handle's cold write is not in the file")
	}
	if err := closed(Open(path, pw())); err != nil {
		t.Errorf("the old passphrase no longer opens the workspace after a refused rotation: %v", err)
	}
}

// S2: only a factor error lets a recovery skip a record; anything else aborts it.
//
// spec: SPO-Xcustody-PRE-030
func TestOnlyAFactorErrorLetsARecoveryGoOnWithoutARecord(t *testing.T) {
	s, path, rec, _ := stdTwoCold(t)
	s.Close()
	r, err := OpenWithRecovery(path, passphrase(rec))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	boom := errors.New("the cold passphrase prompt was interrupted")
	r.SetColdSource(&ColdSource{Passphrase: func(context.Context, bool) (*secret.Buffer, error) { return nil, boom }})
	src := &ColdSource{Deriver: fakeDeriver{}, Mnemonic: fakeMnemonic{}, Passphrase: func(context.Context, bool) (*secret.Buffer, error) {
		return secret.Take([]byte("a new cold passphrase")), nil
	}}
	_, err = r.ChangePassphraseRekeyCold(ctx, passphrase("the recovered workspace passphrase"), src)
	if !errors.Is(err, boom) || errors.Is(err, ErrColdWouldStrand) {
		t.Fatalf("an interrupted prompt: %v", err)
	}
}

// M2 (store): no slot is created on a handle opened through the recovery composite, and a
// credential of the recovery composite is no daily factor.
//
// spec: SPO-Xcustody-PRE-032
func TestNoDailySlotIsAddedThroughTheRecoveryComposite(t *testing.T) {
	_, path, f, rec := hwCold(t)
	r, _ := recoveryHandle(t, path, f, rec)
	fp, _, err := enrolOwned(ctx, f.inputs("devB", pinB), r.ws, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.AddFactorSlot(ctx, []FactorPlan{fp}); !errors.Is(err, ErrSlotViaRecovery) {
		t.Fatalf("a daily slot enrolled on the recovery token in a recovery session: %v", err)
	}
	r.Close()
	// from the daily session: a plan that reuses a credential of the recovery composite
	d, err := openHW(path, f, "devA", pinA)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	tbl, err := d.currentTable(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var recCred seal.FactorParams
	for _, ts := range tbl.slots {
		if !ts.isFactor() {
			continue
		}
		isRec := false
		for _, x := range ts.fs.Spec.Factors {
			isRec = isRec || x.Kind == seal.FactorRecovery
		}
		for _, x := range ts.fs.Spec.Factors {
			if isRec && x.Kind == seal.FactorFIDO2 {
				recCred = x
			}
		}
	}
	if len(recCred.CredentialID) == 0 {
		t.Fatal("no recovery credential found")
	}
	out := owned(secret.Take(bytes.Repeat([]byte{4}, 32)))
	if _, err := d.AddFactorSlot(ctx, []FactorPlan{{Params: recCred, Output: out}}); !errors.Is(err, ErrRecoveryCredentialAsDaily) {
		t.Fatalf("a credential of the recovery composite added as a daily factor: %v", err)
	}
	// and a rotation whose daily slot carries it
	proof := presentHW(t, d, f, rec)
	plan, _ := hardwarePlanFor(t, d, f, proof, "devA", pinA)
	plan.Slots[0].Factors[0].Params = recCred
	if _, _, err := d.Rotate(ctx, plan); !errors.Is(err, ErrRecoveryCredentialAsDaily) {
		t.Fatalf("a rotation whose daily factor is a recovery credential: %v", err)
	}
}

// S4/M3b: openKey dispatches on the record's own header, not on the workspace policy.
//
// spec: SPO-Xcustody-INV-017
func TestOpenKeyDispatchesOnTheHeaderKind(t *testing.T) {
	s, _, f, _ := hwCold(t)
	hdr, oc := headerOf(t, s, coldRef)
	if hdr.Kind != seal.ColdFIDO2 {
		t.Fatal(hdr)
	}
	in := f.inputs("devA", pinA)
	cs := s.newColdSession(unlock.Standard, &ColdSource{Factors: &in, Passphrase: func(context.Context, bool) (*secret.Buffer, error) {
		return nil, errors.New("a passphrase is not what this record opens with")
	}})
	dk, _, err := cs.openKey(ctx, oc, idOfKey(t, s, coldRef).Hash(), false)
	if err != nil {
		t.Fatalf("a FIDO2 record under a standard session: %v", err)
	}
	dk.Destroy()
}

var _ = os.Remove

// M1 (seventh review): a committee cold mnemonic made with an account other than 0 records
// its path, so a routine rotation and a recovery re-establish it through the wrap; a legacy
// record with no path is checked at 0, 0, falls back to the old factor, and is named and
// refused when that is lost too.
//
// spec: SPO-Xcustody-PRE-033
func TestAMnemonicDerivedAtAnotherAccountSurvivesRotationAndRecovery(t *testing.T) {
	const words = "alpha bravo charlie"
	// routine rotation (the old factor is wired and right)
	s, _, rec := stdCold(t, "sub-key passphrase one")
	putMnemonicAt(t, s, words, 1, 0, true)
	plan := RotatePlan{Policy: unlock.Standard, Proof: presentStd(t, s, rec), Slots: []SlotPlan{
		{Kind: seal.SlotPassphrase, Passphrase: passphrase("a second workspace passphrase")}, {Kind: seal.SlotRecovery}},
		ColdNew: &ColdSource{Deriver: fakeDeriver{}, Mnemonic: fakeMnemonic{}, Passphrase: func(context.Context, bool) (*secret.Buffer, error) {
			return secret.Take([]byte("a new cold passphrase")), nil
		}}}
	text, _, err := s.Rotate(ctx, plan)
	if err != nil {
		t.Fatalf("a routine rotation with a mnemonic at account 1: %v", err)
	}
	text.Destroy()
	s.SetColdSource(coldPass("a new cold passphrase"))
	if v, err := openString(t, s, mnRef); err != nil || strings.TrimSpace(v) != words {
		t.Fatalf("the mnemonic after the rotation: %q %v (the reader sees the words only)", v, err)
	}
	// recovery with the cold passphrase lost: through the wrap, at the recorded path
	s2, _, rec2 := stdCold(t, "sub-key passphrase one")
	putMnemonicAt(t, s2, words, 1, 2, true)
	s2.SetColdSource(coldPass("I forgot it"))
	f := newFake()
	hp, inA := hardwarePlan(t, s2, f, presentStd(t, s2, rec2))
	hp.ColdNew.Mnemonic = fakeMnemonic{}
	t2, _, err := s2.Rotate(ctx, hp)
	if err != nil {
		t.Fatalf("a recovery with the cold passphrase lost: %v", err)
	}
	t2.Destroy()
	s2.SetColdSource(&ColdSource{Factors: &inA})
	if v, err := openString(t, s2, mnRef); err != nil || strings.TrimSpace(v) != words {
		t.Fatalf("the recovered mnemonic: %q %v", v, err)
	}
	// a legacy record (no path recorded) at account 1: the old factor is the fallback
	s3, _, rec3 := stdCold(t, "sub-key passphrase one")
	putMnemonicAt(t, s3, words, 1, 0, false)
	hp3, in3 := hardwarePlan(t, s3, f, presentStd(t, s3, rec3))
	hp3.ColdNew.Mnemonic = fakeMnemonic{}
	t3, _, err := s3.Rotate(ctx, hp3)
	if err != nil {
		t.Fatalf("a legacy mnemonic with the old factor available: %v", err)
	}
	t3.Destroy()
	s3.SetColdSource(&ColdSource{Factors: &in3})
	if v, err := openString(t, s3, mnRef); err != nil || strings.TrimSpace(v) != words {
		t.Fatalf("the legacy mnemonic after the rotation: %q %v", v, err)
	}
	// the same with the old factor lost: named and refused, and left only on request
	s4, _, rec4 := stdCold(t, "sub-key passphrase one")
	putMnemonicAt(t, s4, words, 1, 0, false)
	s4.SetColdSource(coldPass("I forgot it"))
	mk := func(leave ...string) RotatePlan {
		p, _ := hardwarePlan(t, s4, f, presentStd(t, s4, rec4))
		p.ColdNew.Mnemonic = fakeMnemonic{}
		p.ColdNew.LeaveUnreachable = leave
		return p
	}
	if _, _, err := s4.Rotate(ctx, mk()); !errors.Is(err, ErrColdWouldStrand) || !strings.Contains(err.Error(), nameOfRef(mnRef)) {
		t.Fatalf("a legacy mnemonic with no old factor: %v", err)
	}
	t4, _, err := s4.Rotate(ctx, mk(nameOfRef(mnRef)))
	if err != nil {
		t.Fatal(err)
	}
	t4.Destroy()
	s4.SetColdSource(coldPass("sub-key passphrase one"))
	if v, err := openString(t, s4, mnRef); err != nil || strings.TrimSpace(v) != words {
		t.Fatalf("the left mnemonic with its old factor: %q %v", v, err)
	}
}

// S3: a record left under its old factor carries a mark in its authenticated cold record, so
// it is named without any factor and across further rekeys, and it does not block the creation
// of a cold key under another passphrase.
//
// spec: SPO-Xcustody-PRE-034
func TestALeftMarkSurvivesFurtherRekeysAndDoesNotBlockNewColdKeys(t *testing.T) {
	s, _, rec := stdCold(t, "sub-key passphrase one")
	plan := RotatePlan{Policy: unlock.Standard, Proof: presentStd(t, s, rec), Slots: []SlotPlan{
		{Kind: seal.SlotPassphrase, Passphrase: passphrase("a second workspace passphrase")}, {Kind: seal.SlotRecovery}},
		ColdNew: &ColdSource{Deriver: fakeDeriver{}, LeaveUnreachable: []string{nameOfRef(coldRef)}}}
	text, _, err := s.Rotate(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if st, err := s.ColdStatus(ctx); err != nil || len(st.Problems) != 1 || st.Problems[0].Record != nameOfRef(coldRef) {
			t.Fatalf("after %d further rekeys: %+v %v", i, st, err)
		}
		if i == 2 {
			break
		}
		var rk string
		text.Use(func(b []byte) error { rk = string(b); return nil })
		text.Destroy()
		if text, err = s.ChangePassphraseRekey(ctx, passphrase("another workspace passphrase "+string(rune('a'+i)))); err != nil {
			if !errors.Is(err, ErrRecoveryNotPresented) {
				t.Fatal(err)
			}
			presentStd(t, s, rk)
			if text, err = s.ChangePassphraseRekey(ctx, passphrase("another workspace passphrase "+string(rune('a'+i)))); err != nil {
				t.Fatal(err)
			}
		}
	}
	text.Destroy()
	// a new cold key under another passphrase is not refused because of the left record
	s.SetColdSource(coldPass("a brand new cold passphrase"))
	putSecret(t, s, rf("pool3", ports.NodeSKey), "cold key three")
	// and it still opens with its old factor
	s.SetColdSource(coldPass("sub-key passphrase one"))
	if v, err := openString(t, s, coldRef); err != nil || v != "cold-secret-one" {
		t.Fatalf("%q %v", v, err)
	}
	if st, _ := s.ColdStatus(ctx); len(st.Problems) != 1 {
		t.Errorf("after opening the left record: %+v", st)
	}
}

// S4: the cold passphrase is checked against every record once in the gather, and inside the
// transaction only against rows that changed since.
//
// spec: SPO-Xcustody-PRE-027
func TestTheColdPassphraseIsCheckedOncePerRecordNotTwice(t *testing.T) {
	s, _, _ := stdCold(t, "sub-key passphrase one")
	putSecret(t, s, rf("pool2", ports.NodeSKey), "cold key two")
	putSecret(t, s, rf("pool3", ports.NodeSKey), "cold key three")
	n := 0
	sameColdKDFHook = func() { n++ }
	defer func() { sameColdKDFHook = nil }()
	putSecret(t, s, rf("pool4", ports.NodeSKey), "cold key four")
	if n != 3 {
		t.Fatalf("%d Argon2id runs to create one cold key beside three, want 3 (one per record)", n)
	}
}
