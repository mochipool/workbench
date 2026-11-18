package sqlitestore

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/unlock"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
)

// COLD-ROLE SUB-KEYS (ADR 0011 decision 6).
//
// A signing-key record whose key identity has a cold role in its role history is
// sealed in the cold form of seal/cold.go: the master key alone opens only the
// outer layer. The store classifies a record when it is written, from the role
// history and the verification key stored beside it (labels.ClassifyKeyRecord),
// and again whenever it is opened; a signing key with no verification key, or
// whose identity has no role history, is refused (fail closed). A key that gains
// a cold role is re-sealed in the transaction that writes the role history.
//
// What opens a cold record is the cold sub-key, derived from a fresh factor
// presentation: under standard the sub-key passphrase through Argon2id with a
// per-record salt, under hardware and strict one hmac-secret assertion of the
// credential in the record's header with the record's current and next salt. A
// successful open writes the record again with the salt rotated (the data key
// wrapped under the next output), in the same transaction, and returns the
// secret only after that commit. Readers that verify integrity (Verify, backup,
// restore, labels.Check on open, listing, a rekey that keeps the recovery key)
// never need the sub-key: they see the outer layer.

var (
	// ErrColdFactorRequired: a record is sealed under the cold sub-key and no
	// factor source is wired to present it. Nothing was asked.
	ErrColdFactorRequired = errors.New("sqlitestore: this operation needs the cold sub-key factor (the key identity has a cold role) and no source for it is wired; nothing was asked")
	// ErrColdFactorWrong: the factor presented does not open the record.
	ErrColdFactorWrong = errors.New("sqlitestore: the cold sub-key factor presented does not open this record")
	// ErrColdClassMismatch: the sealed form of a record and the role history of
	// its key identity disagree about whether it is a cold-role record.
	ErrColdClassMismatch = errors.New("sqlitestore: the sealed class of a record disagrees with the role history of its key identity")
	// ErrColdPassphraseReuse: the sub-key passphrase opens a passphrase slot.
	ErrColdPassphraseReuse = errors.New("sqlitestore: the cold sub-key passphrase must differ from every slot passphrase")
	// ErrColdInTransaction: a cold record is opened through the vault only.
	ErrColdInTransaction = errors.New("sqlitestore: a cold-role record opens through the vault with a fresh factor, not inside a transaction")
	// ErrRecoveryKeyMismatch: the recovery public key stored for wrapping does
	// not hash to the value the slots bind.
	ErrRecoveryKeyMismatch = errors.New("sqlitestore: the recovery public key does not match the hash bound in the slots; no cold-role record is wrapped to it")
	// ErrColdPassphraseDiffers: a second cold record is being created under a
	// sub-key passphrase other than the one an existing cold record opens with.
	ErrColdPassphraseDiffers = errors.New("sqlitestore: this is not the cold sub-key passphrase the workspace's existing cold records open with; a workspace has one cold passphrase, and it is changed by rotation (spo workspace rotate)")
	// ErrColdViaRecovery: the handle was unlocked through a slot that holds the
	// recovery factor, whose authenticator is kept apart from the daily one; a cold
	// record created or re-bound now would be tied to it.
	ErrColdViaRecovery = errors.New("sqlitestore: this handle was unlocked through a slot that holds the recovery factor, so no cold-role record is created or bound to the recovery authenticator; open the workspace through the daily slot")
	// ErrRecoveredIdentity: a recovered signing key does not derive the key
	// identity of the record it was found in.
	ErrRecoveredIdentity = errors.New("sqlitestore: the recovered signing key does not derive the key identity of its record; it was not re-sealed (a record that was planted, or, for a cold mnemonic, one derived with an account or index other than 0, which the record does not say: pass --leave-unreachable for that record to leave it)")
	// ErrColdWouldStrand: a rotation or recovery that changes the cold factor would
	// leave cold records under the old factor, which it cannot present. ADR 0011:
	// "otherwise it is refused and the records are named".
	ErrColdWouldStrand = errors.New("sqlitestore: this change of the cold factor would leave cold-role records under the old factor, which could not be presented; nothing was changed")
	// ErrColdLeaveUnknown: --leave-unreachable names a record that is not a cold-role record of this workspace, or is given without the recovery credential.
	ErrColdLeaveUnknown = errors.New("sqlitestore: --leave-unreachable names no cold-role record of this workspace, or the recovery credential was not presented")
	// ErrColdSplit: the workspace's passphrase-sealed cold records are not all sealed under one cold passphrase.
	ErrColdSplit = errors.New("sqlitestore: the cold-role records of this workspace are sealed under more than one cold passphrase (this passphrase opens some of them and not others); run `spo store verify` and re-establish them under one by `spo workspace rotate`")
)

// ColdSource presents the factor of the cold sub-key. A nil source, or one that
// lacks what the workspace policy needs, makes every operation on a cold-role
// record fail before anything is asked.
type ColdSource struct {
	// Passphrase asks for the sub-key passphrase (the standard policy). create is
	// true when a new sub-key is being made: the caller asks twice.
	Passphrase func(ctx context.Context, create bool) (*secret.Buffer, error)
	// Factors presents the authenticator of the hardware and strict policies: the
	// source, the device and the PIN callback, as for an unlock. A fresh
	// assertion is made for every record.
	Factors *FactorInputs
	// Deriver derives a verification key from a signing key. The recovery path
	// uses it to check that a recovered key belongs to its record's identity.
	Deriver ports.VerificationKeyDeriver
	// Mnemonic derives the verification key of a cold mnemonic record (the
	// generator's derivation, account 0 and index 0), so the recovery path can check
	// a recovered mnemonic against the identity of the signing key beside it. With
	// none, a mnemonic cannot be checked and is re-established only through the old
	// factor.
	Mnemonic ports.ColdMnemonicVKeyDeriver
	// LeaveUnreachable names the cold-role records (as `store verify` and the
	// refusal name them: kind/label) that a rotation or recovery may leave under
	// their old cold factor. Without a name here a change of the cold factor that
	// would leave a record is refused. It is honoured only when the recovery
	// credential was presented.
	LeaveUnreachable []string
}

// SetColdSource wires the cold sub-key factor of this handle.
//
// A read-only layout handle takes none: a cold-role record is never opened from it,
// so no factor may be wired to it (defence in depth).
func (s *Store) SetColdSource(c *ColdSource) {
	if s.layoutRO {
		return
	}
	s.mu.Lock()
	s.cold = c
	s.mu.Unlock()
}

func (s *Store) coldSource() *ColdSource {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cold
}

// recoveryKey is the recovery secret a handle holds when the recovery credential
// was presented: the 32 raw bytes of the recovery key (standard) or the slot key
// of the recovery composite (hardware). The X25519 recovery private key is
// derived from it when a wrap is opened and not kept.
type recoveryKey struct {
	secret   *secret.Buffer
	hardware bool
}

func (k *recoveryKey) priv() (*ecdh.PrivateKey, error) {
	if k == nil || k.secret == nil {
		return nil, ErrRecoveryNotPresented
	}
	if k.hardware {
		return seal.RecoveryKeyPairHardware(k.secret)
	}
	return seal.RecoveryKeyPair(k.secret)
}

func (k *recoveryKey) destroy() {
	if k != nil && k.secret != nil {
		k.secret.Destroy()
	}
}

// writeRecoveryPub stores the recovery public key the slots of the table bind
// (nil when the table has none).
func writeRecoveryPub(ctx context.Context, q dbq, pub []byte) error {
	var v any
	if len(pub) > 0 {
		v = append([]byte{}, pub...)
	}
	_, err := q.ExecContext(ctx, `UPDATE meta SET recovery_pub = ?`, v)
	return err
}

// recoveryPubOf reads the recovery public key for wrapping cold-role records and
// checks it against the hash the slots bind (decision 6: the client "compares
// the key it is about to wrap to against the value bound in the slot", and
// refuses when the slots bind different values). It returns nil for a table with
// no recovery path: strict, or slots carried over from format 2 that bind none.
func recoveryPubOf(ctx context.Context, q dbq, t *table) ([]byte, error) {
	hash, any, ok := t.commonRecHash()
	if !ok {
		return nil, fmt.Errorf("%w: the slots bind different recovery public key hashes", ErrPolicyViolated)
	}
	if !any || len(hash) == 0 {
		return nil, nil
	}
	var pub []byte
	if err := q.QueryRowContext(ctx, `SELECT recovery_pub FROM meta WHERE id = 1`).Scan(&pub); err != nil {
		return nil, err
	}
	if len(pub) != 32 || !bytes.Equal(seal.RecoveryPubKeyHash(pub), hash) {
		return nil, ErrRecoveryKeyMismatch
	}
	return pub, nil
}

// commonPub is the recovery public key the slots built for a table share, and
// an error when they disagree.
func commonPub(slots []tslot) ([]byte, error) {
	var pub []byte
	for i, s := range slots {
		if i == 0 {
			pub = s.recPub
		} else if !bytes.Equal(pub, s.recPub) {
			return nil, fmt.Errorf("%w: the new slots carry different recovery public keys", ErrPolicyViolated)
		}
	}
	return pub, nil
}

// ---- the factor session --------------------------------------------------------------------

// coldSession presents the cold sub-key factor for the records of one operation.
// The sub-key passphrase is asked once and held in guarded memory until destroy;
// an authenticator assertion is made per record and its outputs are destroyed as
// soon as the sub-keys are derived. Nothing is cached across operations.
type coldSession struct {
	s      *Store
	policy unlock.Policy
	src    *ColdSource
	pass   *secret.Buffer
	// cred is the credential new hardware records bind (the daily FIDO2 factor).
	cred *seal.FactorParams
}

func (s *Store) newColdSession(policy unlock.Policy, src *ColdSource) *coldSession {
	return &coldSession{s: s, policy: policy, src: src}
}

func (c *coldSession) destroy() {
	if c.pass != nil {
		c.pass.Destroy()
		c.pass = nil
	}
}

// ready checks, before anything is asked, that the source can serve the policy.
func (c *coldSession) ready(ctx context.Context) error {
	if c.policy == unlock.Standard {
		return c.readyFor(ctx, seal.ColdPassphrase)
	}
	return c.readyFor(ctx, seal.ColdFIDO2)
}

// readyFor checks that the source can present the factor of a record of the kind
// (a record is opened with the factor its own header names, whatever the policy).
func (c *coldSession) readyFor(ctx context.Context, kind seal.ColdKind) error {
	if c.src == nil {
		return ErrColdFactorRequired
	}
	if kind == seal.ColdPassphrase {
		if c.src.Passphrase == nil {
			return ErrColdFactorRequired
		}
		return nil
	}
	if c.src.Factors == nil || c.src.Factors.Source == nil {
		return ErrColdFactorRequired
	}
	prof, err := c.src.Factors.Source.Profile(ctx, c.src.Factors.Device)
	if err != nil {
		return err
	}
	return ports.CheckFactorProfile(prof, ports.NeedsOfColdSubKey)
}

func (c *coldSession) passphrase(ctx context.Context, create bool, check func(*secret.Buffer) error) (*secret.Buffer, error) {
	if c.pass != nil {
		return c.pass, nil
	}
	if promptHook != nil {
		promptHook(c.s, "passphrase", c.s.writeHeld())
	}
	pw, err := c.src.Passphrase(ctx, create)
	if err != nil {
		return nil, err
	}
	if pw == nil || pw.Len() == 0 {
		pw.Destroy()
		return nil, errors.New("sqlitestore: an empty cold sub-key passphrase")
	}
	if check != nil {
		if err := check(pw); err != nil {
			pw.Destroy()
			return nil, err
		}
	}
	c.pass = pw
	return pw, nil
}

// assert makes one assertion of cred with the salt (and the next salt when
// given). The caller destroys the outputs.
func (c *coldSession) assert(ctx context.Context, cred []byte, rpid string, salt, next []byte) (out, nextOut *secret.Buffer, err error) {
	in := c.src.Factors
	if promptHook != nil {
		promptHook(c.s, "assertion", c.s.writeHeld())
	}
	var pin *secret.Buffer
	if in.PIN != nil {
		if pin, err = in.PIN(ctx); err != nil {
			return nil, nil, err
		}
		defer pin.Destroy()
	}
	if in.Notify != nil {
		in.Notify("touch the authenticator to open the cold key")
	}
	a, err := in.Source.Assert(ctx, ports.AssertRequest{Device: in.Device, CredentialID: cred, RPID: rpid, Salt: salt, NextSalt: next, UserPresence: true, PIN: pin})
	if err != nil {
		return nil, nil, err
	}
	if err := a.Require(ports.Requirement{UserPresence: true, UserVerification: true}); err != nil {
		a.Destroy()
		return nil, nil, err
	}
	if next != nil && a.NextOutput == nil {
		a.Destroy()
		return nil, nil, fmt.Errorf("%w: no output for the next salt", ports.ErrFactorMalformed)
	}
	return a.Output, a.NextOutput, nil
}

func (c *coldSession) rpid() string { return "spo." + hex.EncodeToString(c.s.ws) }

func (c *coldSession) derive(out *secret.Buffer, ident []byte) (*secret.Buffer, error) {
	defer out.Destroy()
	return seal.DeriveColdSubKey(out, c.s.ws, uint32(seal.ColdRecordFormat), ident)
}

// nextSub is the sub-key and header a record is sealed under after a successful
// open (the rotated salt), and, for an hmac-secret record, the sub-key of the
// previous salt that the open just proved good (it opens the previous wrap kept
// beside the current one; hdr.Prev names its salt).
type nextSub struct {
	sub  *secret.Buffer
	prev *secret.Buffer
	hdr  seal.ColdHeader
	// left carries the record's left mark across the rewrite of an open: the record is
	// still under its old factor, so the mark stays until it is sealed anew.
	left bool
}

func (n *nextSub) destroy() {
	if n != nil {
		if n.sub != nil {
			n.sub.Destroy()
		}
		if n.prev != nil {
			n.prev.Destroy()
		}
	}
}

// openKey opens the data key of an opened outer layer. With rotate it also
// derives what the record is sealed under after a successful open: under
// standard a fresh salt through Argon2id from the passphrase still held (a local,
// deterministic computation); under hardware and strict the output for the stored
// next salt, obtained in the same assertion, which nothing has verified. The next
// header holds that salt as the current one, and the salt this open proved good as
// the previous one, so the previous wrap (the data key under the proved sub-key)
// is kept beside it. A record whose current wrap does not open (the authenticator
// answered the previous session's next salt wrongly) is opened with its previous
// wrap after a second assertion, and the rotation then heals it: the current wrap
// is renewed under a fresh salt and the previous one is kept. The previous wrap is
// replaced only by an open that succeeded with the current one.
func (c *coldSession) openKey(ctx context.Context, oc *seal.ColdOuter, ident []byte, rotate bool) (*secret.Buffer, *nextSub, error) {
	h := oc.Header
	// The record's own header says what opens it, not the workspace policy: a record
	// left under a passphrase in a hardware workspace (or the other way round) still
	// opens with the factor it was sealed under, and can be re-established later.
	if err := c.readyFor(ctx, h.Kind); err != nil {
		return nil, nil, err
	}
	switch {
	case h.Kind == seal.ColdPassphrase:
		pw, err := c.passphrase(ctx, false, nil)
		if err != nil {
			return nil, nil, err
		}
		out, err := seal.PassphraseFactorOutput(pw, h.Salt, h.KDF)
		if err != nil {
			return nil, nil, err
		}
		sub, err := c.derive(out, ident)
		if err != nil {
			return nil, nil, err
		}
		dk, err := oc.OpenDataKey(sub)
		sub.Destroy()
		if err != nil {
			return nil, nil, err
		}
		if !rotate {
			return dk, nil, nil
		}
		salt := make([]byte, seal.SaltSize)
		if _, err := rand.Read(salt); err != nil {
			dk.Destroy()
			return nil, nil, err
		}
		nout, err := seal.PassphraseFactorOutput(pw, salt, h.KDF)
		if err != nil {
			dk.Destroy()
			return nil, nil, err
		}
		nsub, err := c.derive(nout, ident)
		if err != nil {
			dk.Destroy()
			return nil, nil, err
		}
		return dk, &nextSub{sub: nsub, hdr: seal.ColdHeader{Kind: seal.ColdPassphrase, KDF: h.KDF, Salt: salt}}, nil
	case h.Kind == seal.ColdFIDO2:
		var next []byte
		if rotate {
			next = h.Next
		}
		out, nout, err := c.assert(ctx, h.Credential, c.rpid(), h.Salt, next)
		if err != nil {
			return nil, nil, err
		}
		sub, err := c.derive(out, ident)
		if err != nil {
			nout.Destroy()
			return nil, nil, err
		}
		dk, oerr := oc.OpenDataKey(sub)
		if oerr == nil {
			if !rotate {
				sub.Destroy()
				return dk, nil, nil
			}
			fresh, err := freshSalt()
			if err != nil {
				sub.Destroy()
				dk.Destroy()
				nout.Destroy()
				return nil, nil, err
			}
			nsub, err := c.derive(nout, ident)
			if err != nil {
				sub.Destroy()
				dk.Destroy()
				return nil, nil, err
			}
			return dk, &nextSub{sub: nsub, prev: sub, hdr: seal.ColdHeader{Kind: seal.ColdFIDO2, Credential: h.Credential, Salt: h.Next, Next: fresh, Prev: h.Salt, Fallbacks: h.Fallbacks}}, nil
		}
		sub.Destroy()
		nout.Destroy()
		if !errors.Is(oerr, seal.ErrAuth) || !oc.HasPrevious() {
			return nil, nil, oerr
		}
		// the current wrap does not open: try the previous one (a second assertion)
		var fresh1 []byte
		if rotate {
			if fresh1, err = freshSalt(); err != nil {
				return nil, nil, err
			}
		}
		out2, nout2, err := c.assert(ctx, h.Credential, c.rpid(), h.Prev, fresh1)
		if err != nil {
			return nil, nil, err
		}
		psub, err := c.derive(out2, ident)
		if err != nil {
			nout2.Destroy()
			return nil, nil, err
		}
		dk, err = oc.OpenDataKeyPrevious(psub)
		if err != nil {
			psub.Destroy()
			nout2.Destroy()
			return nil, nil, err
		}
		if !rotate {
			psub.Destroy()
			return dk, nil, nil
		}
		// The answer for the new current salt is verified before it is sealed under:
		// the same salt is asserted a second time and the two answers are compared.
		// A mismatch (a persistent fault, or a corrupted current wrap that the
		// authenticator is not to blame for) rewrites nothing: the secret is still
		// released from the previous wrap, and the operator is told every time.
		out3, _, err := c.assert(ctx, h.Credential, c.rpid(), fresh1, nil)
		if err != nil {
			psub.Destroy()
			nout2.Destroy()
			dk.Destroy()
			return nil, nil, err
		}
		same := equalBuffers(nout2, out3)
		out3.Destroy()
		if !same {
			psub.Destroy()
			nout2.Destroy()
			c.s.notice("the authenticator returned an inconsistent answer; the record was not rotated (it still opens through its previous wrap)")
			return dk, nil, nil
		}
		psub.Destroy() // the new current wrap is verified; the previous one is no longer needed
		fresh2, err := freshSalt()
		if err != nil {
			dk.Destroy()
			nout2.Destroy()
			return nil, nil, err
		}
		nsub, err := c.derive(nout2, ident)
		if err != nil {
			dk.Destroy()
			return nil, nil, err
		}
		return dk, &nextSub{sub: nsub, hdr: seal.ColdHeader{Kind: seal.ColdFIDO2, Credential: h.Credential, Salt: fresh1, Next: fresh2, Fallbacks: h.Fallbacks + 1}}, nil
	}
	return nil, nil, fmt.Errorf("%w: the record's sub-key is of an unknown kind %d", ErrColdClassMismatch, h.Kind)
}

// isFactorError reports whether err says that a factor (a passphrase, an
// authenticator, the recovery credential) was wrong, absent or refused, as
// opposed to a record that is damaged: such an error is never reported as
// corruption.
func isFactorError(err error) bool {
	for _, e := range []error{ErrColdFactorWrong, ErrColdFactorRequired, ErrColdWrapRaced, ErrColdNotGathered, ErrColdAnswerInconsistent,
		ErrRecoveryNotPresented, ErrColdPassphraseReuse, ErrColdPassphraseDiffers, ErrColdViaRecovery,
		ports.ErrFactorNoDevice, ports.ErrFactorNoCredential, ports.ErrFactorPIN, ports.ErrFactorPINBlocked, ports.ErrFactorTimeout, ports.ErrFactorUPRefused, ports.ErrFactorUnsupported, ports.ErrFactorFlags, ports.ErrFactorCapability, ports.ErrFactorMalformed} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// equalBuffers compares two guarded buffers in constant time.
func equalBuffers(a, b *secret.Buffer) bool {
	eq := false
	_ = a.Use(func(x []byte) error {
		return b.Use(func(y []byte) error { eq = subtle.ConstantTimeCompare(x, y) == 1; return nil })
	})
	return eq
}

func freshSalt() ([]byte, error) {
	b := make([]byte, ports.FactorSaltSize)
	_, err := rand.Read(b)
	return b, err
}

// slotPassphraseCheck refuses a sub-key passphrase that opens a standalone
// passphrase slot of the table (decision 6: "the sub-key passphrase must differ
// from every slot passphrase"). A passphrase that is a factor inside a composite
// slot cannot be tested and is advice only.
func slotPassphraseCheck(t *table) func(*secret.Buffer) error {
	return func(pw *secret.Buffer) error {
		for _, ts := range t.slots {
			if ts.kind != seal.SlotPassphrase {
				continue
			}
			if mk, err := ts.ps.Unwrap(t.ws, pw); err == nil {
				mk.Destroy()
				return ErrColdPassphraseReuse
			}
		}
		return nil
	}
}

// coldCredential is the FIDO2 factor new hardware cold records bind: the one of
// the slot this handle unlocked through.
func coldCredential(t *table, slotID []byte) (*seal.FactorParams, error) {
	for _, ts := range t.slots {
		if !bytes.Equal(ts.id, slotID) || !ts.isFactor() {
			continue
		}
		for _, f := range ts.fs.Spec.Factors {
			if f.Kind == seal.FactorRecovery {
				return nil, ErrColdViaRecovery
			}
		}
		for _, f := range ts.fs.Spec.Factors {
			if f.Kind == seal.FactorFIDO2 {
				fp := f
				return &fp, nil
			}
		}
	}
	return nil, errors.New("sqlitestore: this handle was not unlocked through a daily FIDO2 slot, so no credential is known for a new cold-role record")
}

// ---- classification and sealing inside a transaction ---------------------------------------

// coldWork is the cold-role state of one transaction's writes: the
// classification of the signing keys it stages, one factor session, the table
// and the recovery public key.
type coldWork struct {
	t     *txn
	cs    *coldSession
	tbl   *table
	rec   []byte
	recOK bool
	info  map[ports.Ref]labels.KeyClass
	// preset gives a record the sub-key and header it is sealed under (the
	// rotated salt of an open), so no further presentation is asked.
	preset map[ports.Ref]*nextSub
	// resealed is set when a stored hot record was staged to be sealed cold
	// because its key gained a cold role.
	resealed bool
	// prep is the factor material gathered before the transaction for the cold
	// records it creates; probe makes seal count them (need) and use a throwaway
	// sub-key; checked says the new sub-key passphrase was re-checked against the
	// table in this transaction.
	prep    *coldPrep
	probe   bool
	need    int
	checked bool
}

func (w *coldWork) destroy() {
	if w == nil {
		return
	}
	if w.cs != nil {
		w.cs.destroy()
	}
	for _, p := range w.preset {
		p.destroy()
	}
}

// load reads the table, the recovery public key and wires the session. It is
// called when the first cold record of the transaction is sealed.
func (w *coldWork) load(policy unlock.Policy) error {
	if w.recOK {
		return nil
	}
	t := w.t
	m, err := loadMeta(t.ctx, t.q)
	if err != nil {
		return err
	}
	if w.tbl, err = loadTable(t.ctx, t.q, t.s.ws, uint64(m.format)); err != nil {
		return err
	}
	if w.rec, err = recoveryPubOf(t.ctx, t.q, w.tbl); err != nil {
		return err
	}
	w.cs = t.s.newColdSession(policy, t.s.coldSource())
	if policy != unlock.Standard {
		if w.cs.cred, err = coldCredential(w.tbl, t.s.slotID); err != nil && w.cs.src != nil && w.cs.src.Factors != nil {
			return err
		}
	}
	w.recOK = true
	return nil
}

// coldPrepare classifies every signing key the transaction stages and stages
// the re-sealing of the stored keys a new cold role reaches.
func (t *txn) coldPrepare() (*coldWork, error) {
	w := &coldWork{t: t, info: map[ports.Ref]labels.KeyClass{}, preset: t.preset, prep: t.prep, probe: t.probe}
	// 1. a role history that gains a cold role reaches the records of that identity
	for _, ref := range append([]ports.Ref(nil), t.order...) {
		o := t.ops[ref]
		if ref.Kind != ports.RoleHistory || o == nil || o.del {
			continue
		}
		next, err := labels.ParseHistory(o.data)
		if err != nil {
			continue // the label layer refuses a malformed history; the store does not parse what it does not need
		}
		if !next.HasColdRole() {
			continue
		}
		wasCold := false
		if old, err := t.fetch(ref); err == nil {
			if b, err := t.openData(ref, old); err == nil {
				if h, err := labels.ParseHistory(b); err == nil {
					wasCold = h.HasColdRole()
				}
			}
		}
		if wasCold {
			continue
		}
		cands, err := labels.KeyRecordsOf(t, t, next.Identity())
		if err != nil {
			return nil, err
		}
		for _, cand := range cands {
			if t.ops[cand] != nil {
				continue
			}
			row, err := t.fetch(cand)
			if err != nil {
				return nil, err
			}
			if seal.IsColdSealed(row.sealed) {
				continue
			}
			// opened as the hot record it is: the transaction already classifies the
			// identity as cold, which the ordinary opener would refuse
			buf, err := t.s.keys.OpenSecret(t.meta(cand, row), row.sealed)
			if err != nil {
				return nil, corrupt(cand, err)
			}
			t.stage(cand, &op{secret: buf})
			w.resealed = true
		}
	}
	// 2. classify what is staged
	for _, ref := range t.order {
		o := t.ops[ref]
		if o == nil || o.del || o.secret == nil || !labels.IsKeySecret(ref.Kind) {
			continue
		}
		// a signing key of a cold role is cold whatever kind it is stored under; the
		// store does not seal it hot under another kind but refuses it, so that the
		// sealed class never disagrees with the role history (fail closed)
		if !labels.IdentityUncheckable(ref.Kind) {
			var terr error
			o.secret.Use(func(b []byte) error { terr = ports.CheckEnvelopeKind(ref.Kind, b); return nil })
			if terr != nil {
				return nil, &RefError{ref, terr}
			}
		}
		cls, err := labels.ClassifyKeyRecord(t, ref)
		if err != nil {
			return nil, &RefError{ref, err}
		}
		w.info[ref] = cls
		if !cls.Cold {
			if row, err := t.fetch(ref); err == nil && seal.IsColdSealed(row.sealed) {
				return nil, &RefError{ref, ErrColdClassMismatch} // a role history only grows: a cold record is never rewritten hot
			}
		}
	}
	return w, nil
}

// rowStamp identifies a version of a record row: what a check of the cold passphrase
// remembers so the check inside the write transaction re-opens only rows that changed.
type rowStamp struct {
	version uint64
	hash    [32]byte
}

// sameColdKDFHook, when set, is called before each Argon2id run of the check; a test
// counts them.
var sameColdKDFHook func()

// sameColdPassphrase refuses a sub-key passphrase that does not open the existing
// passphrase-sealed cold records: the outer layer opens with the master key, so the
// store can tell, with one Argon2id run per record, whether the operator is about to
// hold a second cold passphrase. It looks at EVERY passphrase-sealed cold record. A
// passphrase that opens none of them is ErrColdPassphraseDiffers; one that opens some
// and not others means the workspace is already split (ErrColdSplit, which names
// `store verify`).
func (w *coldWork) sameColdPassphrase(pw *secret.Buffer, known map[string]rowStamp) (map[string]rowStamp, error) {
	t := w.t
	stamps := map[string]rowStamp{}
	// The rows are read raw (an unchecked read, justified): this is an advisory
	// check that stops the operator holding a second passphrase, not a security
	// boundary. Each row is opened with OpenColdOuter, so what it uses is
	// authenticated by the master key and the record's associated data; a row that
	// does not authenticate is counted, and when no other row can be used the check
	// refuses: a tampered row never lets it pass.
	// The rows are read raw: earlier records of this very transaction are already
	// written, and a checked read (fetchTag) compares each with the record map of
	// the handle, which is still the one from before the transaction.
	rows, err := t.q.QueryContext(t.ctx, `SELECT id, kind, version, nonce, wrapped_key, owner_sealed, ciphertext FROM records`)
	if err != nil {
		return nil, err
	}
	type cand struct {
		id      []byte
		kind    string
		version uint64
		sealed  seal.SealedRecord
	}
	var cands []cand
	for rows.Next() {
		var c cand
		var v int64
		if err := rows.Scan(&c.id, &c.kind, &v, &c.sealed.Nonce, &c.sealed.WrappedKey, &c.sealed.Owner, &c.sealed.Ciphertext); err != nil {
			rows.Close()
			return nil, err
		}
		c.version = uint64(v)
		if seal.IsColdSealed(c.sealed) {
			cands = append(cands, c)
		}
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	bad, opened, differs := 0, 0, 0
	for _, c := range cands {
		ref, err := t.s.refOf(c.id, c.kind, c.sealed)
		if err != nil {
			bad++ // a row whose owner blob does not open
			continue
		}
		if !labels.IsKeySecret(ref.Kind) || t.ops[ref] != nil {
			continue
		}
		cls, err := labels.ClassifyKeyRecord(t, ref)
		if err != nil || !cls.Cold {
			bad++
			continue
		}
		oc, err := t.s.keys.OpenColdOuter(metaOf(t.s.ws, c.id, ref, seal.ClassSecretCold, c.version), c.sealed)
		if err != nil {
			bad++ // a row that does not authenticate is never a reason to pass
			continue
		}
		if oc.Header.Kind != seal.ColdPassphrase || oc.Left {
			// a record left under its old factor on request is known to differ: it is
			// not compared, so a consented leave does not block a new cold key
			continue
		}
		stamp := rowStamp{version: c.version, hash: sha256.Sum256(c.sealed.WrappedKey)}
		if known[string(c.id)] == stamp {
			stamps[string(c.id)] = stamp // already opened with this passphrase, row unchanged since
			opened++
			continue
		}
		if sameColdKDFHook != nil {
			sameColdKDFHook()
		}
		out, err := seal.PassphraseFactorOutput(pw, oc.Header.Salt, oc.Header.KDF)
		if err != nil {
			return nil, err
		}
		sub, err := w.cs.derive(out, cls.Identity.Hash())
		if err != nil {
			return nil, err
		}
		pt, err := oc.OpenSecret(sub)
		sub.Destroy()
		if err != nil {
			if errors.Is(err, seal.ErrAuth) {
				differs++
				continue
			}
			return nil, corrupt(ref, err)
		}
		pt.Destroy()
		opened++
		stamps[string(c.id)] = stamp
	}
	switch {
	case opened > 0 && differs > 0:
		return nil, fmt.Errorf("%w: it opens %d of %d passphrase-sealed cold records that are not marked left; run `spo store verify --deep --with-cold-factor` to see which, and re-establish them under one passphrase with `spo workspace rotate`", ErrColdSplit, opened, opened+differs)
	case differs > 0:
		return nil, ErrColdPassphraseDiffers
	case opened == 0 && bad > 0:
		// cold-form rows exist and none of them could be used to check the
		// passphrase: refused rather than allowed, so a tampered row cannot be a way
		// to start a second cold passphrase
		return nil, fmt.Errorf("%w: %d cold-role record(s) do not authenticate, so the cold passphrase cannot be checked against them; nothing was created", ErrCorrupt, bad)
	}
	return stamps, nil
}

// seal seals the staged secret of ref as the class says.
func (w *coldWork) seal(ref ports.Ref, meta seal.RecordMeta, sec *secret.Buffer) (seal.SealedRecord, error) {
	t := w.t
	cls, ok := w.info[ref]
	if !ok || !cls.Cold {
		return t.s.keys.SealSecret(meta, sec)
	}
	if err := w.load(t.s.policy); err != nil {
		return seal.SealedRecord{}, err
	}
	meta = meta.ColdMeta()
	ident := cls.Identity.Hash()
	var sub, prevSub *secret.Buffer
	var hdr seal.ColdHeader
	if p := w.preset[ref]; p != nil {
		sub, hdr, prevSub = p.sub, p.hdr, p.prev
	} else if w.probe {
		// the first attempt of an Update: count the record, seal it under a
		// throwaway sub-key; the transaction is rolled back
		w.need++
		var err error
		if sub, hdr, err = probeSub(w.cs.policy, w.cs.cred); err != nil {
			return seal.SealedRecord{}, err
		}
		defer sub.Destroy()
	} else {
		var err error
		if sub, hdr, err = w.createPrepared(ident); err != nil {
			return seal.SealedRecord{}, err
		}
		defer sub.Destroy()
	}
	cs := seal.ColdSeal{Sub: sub, Prev: prevSub, Header: hdr}
	if p := w.preset[ref]; p != nil {
		cs.Left = p.left
	}
	if len(w.rec) > 0 {
		cs.Recovery = &seal.ColdRecovery{Pub: w.rec, Identity: ident}
	}
	return t.s.keys.SealSecretCold(meta, sec, cs)
}

// ---- the factor of a new cold record, gathered before the transaction ---------------------------

var (
	// ErrColdNotGathered: a write created a cold-role record for which no factor was
	// gathered before its transaction began; the factor is never asked for under
	// the write lock, so nothing was changed.
	ErrColdNotGathered = errors.New("sqlitestore: this write creates a cold-role record whose factor was not gathered before the write began; the factor is never asked for while the write lock is held, so nothing was changed")
	errNeedColdFactor  = errors.New("sqlitestore: cold factor needed")
)

// promptHook, when set, is called at the moment the store is about to ask for a
// cold sub-key factor (a passphrase prompt, an authenticator assertion) with
// whether a write transaction or the exclusive file lock is held on this handle.
// A test records it; production leaves it nil.
var promptHook func(s *Store, what string, writeHeld bool)

// coldPrep is the factor material of the cold records a write creates, gathered
// before its transaction: under standard the sub-key passphrase (checked against
// the slot passphrases and the existing cold records), under hardware and
// strict one authenticator output per record with the salts it was made for. It
// is held in guarded memory and destroyed at the end of the write.
type coldPrep struct {
	pass *secret.Buffer
	// stamps are the rows the gather opened with pass: the check inside the
	// transaction re-opens only the others.
	stamps map[string]rowStamp
	outs   []*prepOut
}

type prepOut struct {
	cred, salt, next []byte
	out              *secret.Buffer
}

func (p *coldPrep) destroy() {
	if p == nil {
		return
	}
	if p.pass != nil {
		p.pass.Destroy()
		p.pass = nil
	}
	for _, o := range p.outs {
		o.out.Destroy()
	}
	p.outs = nil
}

// gatherColdCreate presents the cold factor for need new cold records, with no
// transaction open. The source is checked before anything is asked.
func (s *Store) gatherColdCreate(ctx context.Context, need int) (*coldPrep, error) {
	rtx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	var tbl *table
	err = func() error {
		defer rtx.Rollback()
		if err := s.checkEpoch(ctx, rtx); err != nil {
			return err
		}
		m, err := loadMeta(ctx, rtx)
		if err != nil {
			return err
		}
		tbl, err = loadTable(ctx, rtx, s.ws, uint64(m.format))
		return err
	}()
	if err != nil {
		return nil, err
	}
	cs := s.newColdSession(s.policy, s.coldSource())
	if err := cs.ready(ctx); err != nil {
		return nil, err
	}
	prep := &coldPrep{}
	if s.policy == unlock.Standard {
		pw, err := cs.passphrase(ctx, true, slotPassphraseCheck(tbl))
		if err != nil {
			return nil, err
		}
		cs.pass = nil // the preparation owns it now
		prep.pass = pw
		// the same cold passphrase as the existing cold records: one Argon2id run per
		// passphrase-sealed record not marked left, here, and inside the transaction only
		// for rows that changed since (prep.stamps)
		rtx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			prep.destroy()
			return nil, err
		}
		defer rtx.Rollback()
		if err := s.checkEpoch(ctx, rtx); err != nil {
			prep.destroy()
			return nil, err
		}
		if err := s.catchUp(ctx, rtx); err != nil {
			prep.destroy()
			return nil, err
		}
		t := &txn{s: s, ctx: ctx, q: rtx, ops: map[ports.Ref]*op{}}
		w := &coldWork{t: t, cs: cs}
		stamps, err := w.sameColdPassphrase(pw, nil)
		if err != nil {
			prep.destroy()
			return nil, err
		}
		prep.stamps = stamps
		return prep, nil
	}
	if cs.cred, err = coldCredential(tbl, s.slotID); err != nil {
		return nil, err
	}
	for i := 0; i < need; i++ {
		cur, err := freshSalt()
		if err != nil {
			prep.destroy()
			return nil, err
		}
		next, err := freshSalt()
		if err != nil {
			prep.destroy()
			return nil, err
		}
		out, err := cs.assertVerified(ctx, cs.cred.CredentialID, cs.cred.RPID, cur)
		if err != nil {
			prep.destroy()
			return nil, err
		}
		prep.outs = append(prep.outs, &prepOut{cred: cs.cred.CredentialID, salt: cur, next: next, out: out})
	}
	return prep, nil
}

// createPrepared makes the sub-key and header of a new cold record from the
// material gathered before the transaction; it never asks.
func (w *coldWork) createPrepared(ident []byte) (*secret.Buffer, seal.ColdHeader, error) {
	p := w.prep
	if p == nil {
		return nil, seal.ColdHeader{}, ErrColdNotGathered
	}
	if w.cs.policy == unlock.Standard {
		if p.pass == nil {
			return nil, seal.ColdHeader{}, ErrColdNotGathered
		}
		if !w.checked {
			// a cold record may have been committed by another writer since the
			// passphrase was checked
			if err := slotPassphraseCheck(w.tbl)(p.pass); err != nil {
				return nil, seal.ColdHeader{}, err
			}
			if _, err := w.sameColdPassphrase(p.pass, p.stamps); err != nil {
				return nil, seal.ColdHeader{}, err
			}
			w.checked = true
		}
		salt := make([]byte, seal.SaltSize)
		if _, err := rand.Read(salt); err != nil {
			return nil, seal.ColdHeader{}, err
		}
		kdf := kdfForNewSlots
		out, err := seal.PassphraseFactorOutput(p.pass, salt, kdf)
		if err != nil {
			return nil, seal.ColdHeader{}, err
		}
		sub, err := w.cs.derive(out, ident)
		return sub, seal.ColdHeader{Kind: seal.ColdPassphrase, KDF: kdf, Salt: salt}, err
	}
	if len(p.outs) == 0 {
		return nil, seal.ColdHeader{}, ErrColdNotGathered
	}
	o := p.outs[0]
	p.outs = p.outs[1:]
	sub, err := w.cs.derive(o.out, ident)
	return sub, seal.ColdHeader{Kind: seal.ColdFIDO2, Credential: o.cred, Salt: o.salt, Next: o.next}, err
}

// probeSub is a throwaway sub-key and a valid header for the first attempt of an
// Update, whose transaction is rolled back.
func probeSub(policy unlock.Policy, cred *seal.FactorParams) (*secret.Buffer, seal.ColdHeader, error) {
	sub, err := secret.Fill(seal.KeySize, func(b []byte) error { _, e := rand.Read(b); return e })
	if err != nil {
		return nil, seal.ColdHeader{}, err
	}
	if policy == unlock.Standard {
		return sub, seal.ColdHeader{Kind: seal.ColdPassphrase, KDF: kdfForNewSlots, Salt: make([]byte, seal.SaltSize)}, nil
	}
	c := []byte("probe")
	if cred != nil {
		c = cred.CredentialID
	}
	return sub, seal.ColdHeader{Kind: seal.ColdFIDO2, Credential: c, Salt: make([]byte, 32), Next: make([]byte, 32)}, nil
}

// ---- opening a cold record through the vault ------------------------------------------------

// openCold opens the cold-role record ref with a fresh factor presentation and,
// on a writable handle, writes it again with the salt rotated. The outer layer is
// read in a read transaction and the factor is presented (passphrase, Argon2id,
// PIN, touch) with no transaction open, so no write lock is held while the
// operator is asked; then the write transaction begins, re-reads the row and, if
// its version changed meanwhile, the whole open is repeated once (a second change
// is ErrColdRaced). The secret is returned only after the rewrite committed; a
// read-only handle opens the record without rotating its salt and writes nothing.
func (s *Store) openCold(ctx context.Context, ref ports.Ref) (*secret.Buffer, error) {
	release, err := s.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	for attempt := 0; attempt < 2; attempt++ {
		out, raced, err := s.openColdOnce(ctx, ref)
		if !raced {
			if err == nil && labels.IsColdMnemonic(ref.Kind) {
				// the derivation line is for the recovery check; a reader sees the words
				stripped, serr := ports.StripDerivation(out)
				out.Destroy()
				return stripped, serr
			}
			return out, err
		}
	}
	return nil, ErrColdRaced
}

// ErrColdRaced: the cold record was rewritten by another writer while its factor
// was being presented, twice in a row; nothing was changed.
var ErrColdRaced = errors.New("sqlitestore: the cold-role record was changed by another writer while its factor was being presented; nothing was changed, try again")

func (s *Store) openColdOnce(ctx context.Context, ref ports.Ref) (out *secret.Buffer, raced bool, err error) {
	// phase 1: read the outer layer; no write lock
	rtx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	var (
		cls     labels.KeyClass
		oc      *seal.ColdOuter
		version uint64
		w       *coldWork
	)
	phase1 := func() error {
		defer rtx.Rollback()
		if err := s.checkEpoch(ctx, rtx); err != nil {
			return err
		}
		if err := s.catchUp(ctx, rtx); err != nil {
			return err
		}
		t := &txn{s: s, ctx: ctx, q: rtx, ops: map[ports.Ref]*op{}, preset: map[ports.Ref]*nextSub{}}
		row, err := t.fetch(ref)
		if err != nil {
			return err
		}
		if cls, err = labels.ClassifyKeyRecord(t, ref); err != nil {
			return &RefError{ref, err}
		}
		if !cls.IsKey || !cls.Cold || !seal.IsColdSealed(row.sealed) {
			return &RefError{ref, ErrColdClassMismatch}
		}
		version = row.version
		meta := metaOf(s.ws, row.id, ref, seal.ClassSecretCold, row.version)
		if oc, err = s.keys.OpenColdOuter(meta, row.sealed); err != nil {
			return corrupt(ref, err)
		}
		if w, err = t.coldPrepareFor(ref, cls); err != nil {
			return err
		}
		return w.load(s.policy)
	}
	if err := phase1(); err != nil {
		w.destroy()
		return nil, false, err
	}
	defer w.destroy()
	// the factor, with no transaction open
	rotate := !s.ro
	dk, nxt, err := w.cs.openKey(ctx, oc, cls.Identity.Hash(), rotate)
	if nxt != nil {
		nxt.left = oc.Left
	}
	if err != nil {
		if errors.Is(err, seal.ErrAuth) {
			return nil, false, &RefError{ref, ErrColdFactorWrong}
		}
		return nil, false, err
	}
	pt, oerr := oc.OpenSecretWithDataKey(dk)
	dk.Destroy()
	if oerr != nil {
		nxt.destroy()
		if errors.Is(oerr, seal.ErrAuth) {
			return nil, false, &RefError{ref, ErrColdFactorWrong}
		}
		return nil, false, corrupt(ref, oerr)
	}
	defer nxt.destroy()
	if s.ro {
		return pt, false, nil // no write: the salt is not rotated
	}
	// pt is destroyed on every return unless the transaction took it over (staged)
	staged := false
	defer func() {
		if !staged {
			pt.Destroy()
		}
	}()
	cp, err := copySecret(pt)
	if err != nil {
		return nil, false, err
	}
	out = cp
	if nxt == nil {
		// the record was not rotated (an inconsistent authenticator answer, S1): the
		// secret is released from the previous wrap and nothing is written
		return out, false, nil
	}
	// phase 2: write, after re-reading the row
	var stale bool
	committed, err := s.withWriteTx(ctx, func(q dbq) (*Head, error) {
		if err := s.catchUp(ctx, q); err != nil {
			return nil, err
		}
		t := &txn{s: s, ctx: ctx, q: q, writable: true, ops: map[ports.Ref]*op{}, preset: map[ports.Ref]*nextSub{}}
		defer t.discard()
		row, err := t.fetch(ref)
		if err != nil {
			return nil, err
		}
		if row.version != version {
			stale = true
			return nil, errColdStale
		}
		w2, err := t.coldPrepareFor(ref, cls)
		if err != nil {
			return nil, err
		}
		if err := w2.load(s.policy); err != nil {
			return nil, err
		}
		w2.cs.destroy()
		w2.cs = nil
		w2.preset[ref] = nxt
		t.stage(ref, &op{secret: pt}) // discard destroys it
		staged = true
		t.cold = w2
		return t.apply()
	}, nil)
	if stale {
		out.Destroy()
		return nil, true, nil
	}
	if err != nil || !committed {
		out.Destroy()
		if err == nil {
			err = errors.New("sqlitestore: the cold-role record was not written, so it is not released")
		}
		return nil, false, err
	}
	return out, false, nil
}

var errColdStale = errors.New("sqlitestore: cold record changed")

// coldPrepareFor is the work of a single-record rewrite: the classification is
// already known.
func (t *txn) coldPrepareFor(ref ports.Ref, cls labels.KeyClass) (*coldWork, error) {
	return &coldWork{t: t, info: map[ports.Ref]labels.KeyClass{ref: cls}, preset: t.preset}, nil
}

// ---- verification without the factor ------------------------------------------------------

// ColdCheck is what a payload verification could and could not say about the
// cold-role records.
type ColdCheck struct {
	// Records is the number of cold-role records.
	Records int
	// OuterOnly is the number whose outer layer authenticated (header, recovery
	// wrap, class and associated data) but whose payload was not opened: opening
	// it needs the factor.
	OuterOnly int
}

// ---- rekey and rotation of cold-role records ------------------------------------------------

// coldRekey carries what a rekey or rotation needs to carry its cold-role
// records across: the key identity of each, the old and new recovery public
// keys, and the sessions that present the old and the new sub-key factor.
type coldRekey struct {
	s      *Store
	reenc  bool
	idents map[string]identity.Ref // record id -> key identity
	oldPub []byte
	newPub []byte
	// newSess derives the factor of the new table (a rotation).
	newSess  *coldSession
	newTbl   *table
	rkey     *recoveryKey
	pre      *coldPre
	priv     *ecdh.PrivateKey
	kindOfID map[string]ports.Kind
}

// recPriv derives the X25519 recovery private key once for the whole rotation.
// The standard library gives no way to zero an ecdh.PrivateKey, so one key
// (not one per record) is left to the garbage collector.
func (c *coldRekey) recPriv() (*ecdh.PrivateKey, error) {
	if c.priv == nil {
		p, err := c.rkey.priv()
		if err != nil {
			return nil, err
		}
		c.priv = p
	}
	return c.priv, nil
}

func (c *coldRekey) destroy() {
	if c == nil {
		return
	}
	if c.newSess != nil {
		c.newSess.destroy()
	}
	c.pre.destroy()
}

// coldDerivers are the derivers the recovery path checks identities with: the ones
// of the handle's own cold source, else those of src.
func (s *Store) coldDerivers(src *ColdSource) (ports.VerificationKeyDeriver, ports.ColdMnemonicVKeyDeriver) {
	var vk ports.VerificationKeyDeriver
	var mn ports.ColdMnemonicVKeyDeriver
	for _, cs := range []*ColdSource{s.coldSource(), src} {
		if cs == nil {
			continue
		}
		if vk == nil {
			vk = cs.Deriver
		}
		if mn == nil {
			mn = cs.Mnemonic
		}
	}
	return vk, mn
}

// prepareColdRekey runs before any row is rewritten (it reads under the old
// keys). src presents the new factor of a rotation.
func (s *Store) prepareColdRekey(ctx context.Context, q dbq, slots []tslot, policy unlock.Policy, reencrypt bool, src *ColdSource, proof *RecoveryProof, all []oldRow, pre *coldPre) (*coldRekey, error) {
	var cold []oldRow
	for _, r := range all {
		if seal.IsColdSealed(r.sealed) {
			cold = append(cold, r)
		}
	}
	if len(cold) == 0 {
		return nil, nil
	}
	m, err := loadMeta(ctx, q)
	if err != nil {
		return nil, err
	}
	oldTbl, err := loadTable(ctx, q, s.ws, uint64(m.format))
	if err != nil {
		return nil, err
	}
	c := &coldRekey{s: s, reenc: reencrypt, idents: map[string]identity.Ref{}, kindOfID: map[string]ports.Kind{}, rkey: s.recoveryKeyOf(proof), pre: pre}
	if c.oldPub, err = recoveryPubOf(ctx, q, oldTbl); err != nil {
		return nil, err
	}
	if c.newPub, err = commonPub(slots); err != nil {
		return nil, err
	}
	t := &txn{s: s, ctx: ctx, q: q, ops: map[ports.Ref]*op{}}
	for _, r := range all {
		ref, err := s.refOf(r.id, r.kind, r.sealed)
		if err != nil {
			return nil, fmt.Errorf("%w: a record's owner blob does not open (%v); nothing was changed", ErrCorrupt, err)
		}
		if !labels.IsKeySecret(ref.Kind) {
			continue
		}
		cls, err := labels.ClassifyKeyRecord(t, ref)
		if err != nil {
			return nil, &RefError{ref, err}
		}
		if cls.Cold != seal.IsColdSealed(r.sealed) {
			return nil, &RefError{ref, ErrColdClassMismatch}
		}
		if cls.Cold {
			c.idents[string(r.id)] = cls.Identity
			c.kindOfID[string(r.id)] = ref.Kind
		}
	}
	// A cold row that appeared after the factors were gathered would keep its old
	// factor (or its old wrap) silently: refused, nothing written (a rotation, or a
	// recovery that re-establishes).
	if reencrypt || (pre != nil && pre.reestablish) {
		for _, r := range cold {
			if pre == nil || !pre.seen[string(r.id)] {
				return nil, ErrColdWrapRaced
			}
		}
	}
	if reencrypt || pre != nil {
		if policy == "" {
			policy = s.policy
		}
		c.newTbl = &table{ws: s.ws, format: seal.StoreFormat, policy: policy, slots: slots}
		c.newSess = s.newColdSession(policy, src)
		if policy != unlock.Standard {
			for _, ts := range slots {
				if ts.kind == seal.SlotFIDO2HMAC && len(ts.fs.Spec.Factors) == 1 {
					fp := ts.fs.Spec.Factors[0]
					c.newSess.cred = &fp
					break
				}
			}
		}
	}
	if reencrypt {
		if src == nil {
			return nil, fmt.Errorf("%w: the workspace holds %d cold-role record(s) and the rotation was given no factor for their new sub-key", ErrColdFactorRequired, len(cold))
		}
	} else if len(c.oldPub) > 0 && !bytes.Equal(c.oldPub, c.newPub) && c.rkey == nil {
		return nil, fmt.Errorf("%w: the workspace holds %d cold-role record(s) wrapped to the current recovery key; a rekey that makes a new recovery key needs the current one presented", ErrRecoveryNotPresented, len(cold))
	}
	return c, nil
}

// row carries one cold-role record across the rekey: m is the record as it is
// stored (cold class, its version).
func (c *coldRekey) row(ctx context.Context, to *seal.Keys, m seal.RecordMeta, r oldRow) (seal.SealedRecord, error) {
	id, ok := c.idents[string(r.id)]
	if !ok {
		return seal.SealedRecord{}, &RefError{ports.Ref{Kind: ports.Kind(r.kind)}, ErrColdClassMismatch}
	}
	ident := id.Hash()
	s := c.s
	oc, err := s.keys.OpenColdOuter(m, r.sealed)
	if err != nil {
		return seal.SealedRecord{}, corrupt(ports.Ref{Kind: ports.Kind(r.kind)}, err)
	}
	has := len(oc.RecoveryWrap()) > 0
	key := string(r.id)
	var rec *seal.ColdRecovery
	if len(c.newPub) > 0 {
		rec = &seal.ColdRecovery{Pub: c.newPub, Identity: ident}
	}
	// A record the old factor could not be presented for (a recovery that goes on
	// without it) keeps its inner wrap; only the outer layer moves, and its
	// recovery wrap moves to the new key when the recovery credential is present.
	skipped := c.pre != nil && c.pre.skip[key] != nil
	if c.pre != nil && c.pre.reseal[key] && !skipped {
		return c.reseal(ctx, to, m, r, oc, id, ident, rec)
	}
	if !skipped && !c.reenc {
		// a record with no recovery wrap gains one when the new table binds a recovery
		// key: its data key was opened with the cold factor before the transaction
		// (coldPre), never inside it
		if !has && len(c.newPub) > 0 {
			dk, err := c.pre.take(r)
			if err != nil {
				return seal.SealedRecord{}, err
			}
			return s.keys.RewrapColdRecovery(to, m, r.sealed, dk, rec)
		}
	}
	if !has || bytes.Equal(c.oldPub, c.newPub) {
		if skipped {
			return s.keys.RewrapColdLeft(to, m, r.sealed)
		}
		return s.keys.RewrapCold(to, m, r.sealed)
	}
	if len(c.oldPub) == 0 {
		return seal.SealedRecord{}, fmt.Errorf("%w: a record wrapped to no recovery key cannot be wrapped to a new one without its sub-key factor", ErrColdFactorRequired)
	}
	priv, err := c.recPriv()
	if err != nil {
		return seal.SealedRecord{}, err
	}
	dk, err := oc.RecoverDataKey(priv, ident)
	if err != nil {
		return seal.SealedRecord{}, err
	}
	defer dk.Destroy()
	if skipped {
		return s.keys.RewrapColdRecoveryLeft(to, m, r.sealed, dk, rec)
	}
	return s.keys.RewrapColdRecovery(to, m, r.sealed, dk, rec)
}

// reseal carries a cold record across a rotation or a recovery: the payload is
// opened (through its recovery wrap and the identity check when the recovery
// credential is present and the record has a wrap, else with the data key that
// the old factor opened before the transaction), then sealed again under the new
// keys, the new sub-key (its material gathered before the transaction) and the
// new recovery public key.
func (c *coldRekey) reseal(ctx context.Context, to *seal.Keys, m seal.RecordMeta, r oldRow, oc *seal.ColdOuter, id identity.Ref, ident []byte, rec *seal.ColdRecovery) (seal.SealedRecord, error) {
	// the data key was opened before the transaction (through the recovery wrap, checked
	// against the identity, or with the old factor); the row must be the one it came from
	pk := c.pre.keys[string(r.id)]
	if err := c.pre.check(r); err != nil {
		return seal.SealedRecord{}, err
	}
	pt, err := oc.OpenSecretWithDataKey(pk.dk)
	if err != nil {
		if errors.Is(err, seal.ErrAuth) {
			return seal.SealedRecord{}, ErrColdFactorWrong
		}
		return seal.SealedRecord{}, err
	}
	defer pt.Destroy()
	sub, hdr, err := c.pre.newSub(c.newSess, ident)
	if err != nil {
		return seal.SealedRecord{}, err
	}
	defer sub.Destroy()
	return to.SealSecretCold(m, pt, seal.ColdSeal{Sub: sub, Header: hdr, Recovery: rec})
}

// ---- recovery wraps for cold records that lack one ------------------------------------------

// ErrColdWrapRaced: a cold record changed while its factor was being presented
// for a rekey that adds the recovery wrap; nothing was changed.
var ErrColdWrapRaced = errors.New("sqlitestore: a cold-role record changed while its factor was being presented for the rekey; nothing was changed, try again")

// coldPre is what a rekey or rotation of a workspace with cold-role records
// gathers BEFORE the file lock is upgraded and the write transaction begins, so
// that no factor is ever asked for under the lock (it is held in guarded memory
// and destroyed at the end): the data keys that need the OLD factor (a record
// with no recovery wrap that must gain one, or that cannot be opened through its
// wrap), the material of the NEW factor for the records that are sealed again
// (the new sub-key passphrase, or one verified authenticator answer per record),
// and the records the operator asked to leave under their old factor
// (LeaveUnreachable).
type coldPre struct {
	keys   map[string]*preKey // record id -> data key opened with the old factor
	skip   map[string]error   // record id -> why it is left under its old factor
	reseal map[string]bool    // record id -> sealed again under the new factor
	// seen is every cold record the gather considered; reestablish says the gather
	// re-establishes records, so a row it did not see is refused (ErrColdWrapRaced).
	seen        map[string]bool
	reestablish bool
	// left are the ids of the records the operator asked to leave under their old factor.
	left [][]byte
	// the new factor
	newPass *secret.Buffer
	newOuts []*prepOut
}

type preKey struct {
	version uint64
	hash    [32]byte // SHA-256 of the wrapped-key column the data key was opened from
	dk      *secret.Buffer
}

func newColdPre() *coldPre {
	return &coldPre{keys: map[string]*preKey{}, skip: map[string]error{}, reseal: map[string]bool{}, seen: map[string]bool{}}
}

func (p *coldPre) destroy() {
	if p == nil {
		return
	}
	for _, k := range p.keys {
		k.dk.Destroy()
	}
	p.keys = nil
	if p.newPass != nil {
		p.newPass.Destroy()
		p.newPass = nil
	}
	for _, o := range p.newOuts {
		o.out.Destroy()
	}
	p.newOuts = nil
}

// check refuses when the row r is not the one its data key was opened from.
func (p *coldPre) check(r oldRow) error {
	var k *preKey
	if p != nil {
		k = p.keys[string(r.id)]
	}
	if k == nil {
		return fmt.Errorf("%w: a cold-role record needs its factor and it was not presented", ErrColdFactorRequired)
	}
	if k.version != r.version || k.hash != sha256.Sum256(r.sealed.WrappedKey) {
		return ErrColdWrapRaced
	}
	return nil
}

// take returns the data key opened for the row r.
func (p *coldPre) take(r oldRow) (*secret.Buffer, error) {
	if err := p.check(r); err != nil {
		return nil, err
	}
	return p.keys[string(r.id)].dk, nil
}

// newSub makes the sub-key and header of a record sealed again, from the material
// gathered before the transaction; it never asks.
func (p *coldPre) newSub(sess *coldSession, ident []byte) (*secret.Buffer, seal.ColdHeader, error) {
	if sess.policy == unlock.Standard {
		if p == nil || p.newPass == nil {
			return nil, seal.ColdHeader{}, ErrColdNotGathered
		}
		salt := make([]byte, seal.SaltSize)
		if _, err := rand.Read(salt); err != nil {
			return nil, seal.ColdHeader{}, err
		}
		kdf := kdfForNewSlots
		out, err := seal.PassphraseFactorOutput(p.newPass, salt, kdf)
		if err != nil {
			return nil, seal.ColdHeader{}, err
		}
		sub, err := sess.derive(out, ident)
		return sub, seal.ColdHeader{Kind: seal.ColdPassphrase, KDF: kdf, Salt: salt}, err
	}
	if p == nil || len(p.newOuts) == 0 {
		return nil, seal.ColdHeader{}, ErrColdNotGathered
	}
	o := p.newOuts[0]
	p.newOuts = p.newOuts[1:]
	sub, err := sess.derive(o.out, ident)
	return sub, seal.ColdHeader{Kind: seal.ColdFIDO2, Credential: o.cred, Salt: o.salt, Next: o.next}, err
}

// ColdNoWrapNotice is the sentence `store slots` and `store verify` print for cold
// records that have no recovery wrap.
func ColdNoWrapNotice(n int) string {
	return fmt.Sprintf("%d cold records without a recovery wrap: the recovery key does not reach them, so a lost cold-key passphrase or authenticator loses them; `spo store passphrase change` (or `spo store recovery-key new`) binds a recovery key and adds the wraps, and asks for the cold factor once", n)
}

// ColdWithoutWrap counts the cold-role records of the workspace whose recovery
// wrap is empty. The wrap's presence is visible without any factor: it is the
// third element of the wrapped-key column, authenticated by the outer layer (its
// hash is in the associated data of the outer layer), which the master key opens.
func (s *Store) ColdWithoutWrap(ctx context.Context) (cold, without int, err error) {
	release, err := s.enter(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	if err := s.checkEpoch(ctx, tx); err != nil {
		return 0, 0, err
	}
	if err := s.catchUp(ctx, tx); err != nil {
		return 0, 0, err
	}
	t := &txn{s: s, ctx: ctx, q: tx, ops: map[ports.Ref]*op{}}
	cands, err := t.coldRowsWithoutWrap()
	if err != nil {
		return 0, 0, err
	}
	n := 0
	for _, kind := range ports.AllKinds() {
		if !labels.IsKeySecret(kind) {
			continue
		}
		refs, err := t.Records(kind)
		if err != nil {
			return 0, 0, err
		}
		for _, ref := range refs {
			row, err := t.fetch(ref)
			if err != nil {
				return 0, 0, err
			}
			if seal.IsColdSealed(row.sealed) {
				n++
			}
		}
	}
	return n, len(cands), nil
}

type wrapCand struct {
	ref     ports.Ref
	id      []byte
	version uint64
	hash    [32]byte
	oc      *seal.ColdOuter
	ident   []byte
	has     bool // the record carries a recovery wrap
	identID identity.Ref
	// name is the record as the operator sees it: kind/label.
	name string
}

// recordName is how a cold record is named to the operator (never the anchor in
// full): the kind and the label of its owner, or the start of the owner's identity
// when it has no label.
func recordName(r ports.Reader, ref ports.Ref) string {
	if l, ok, err := labels.LabelOfReader(r, ref.Anchor); err == nil && ok && l.Name != "" {
		return string(ref.Kind) + "/" + l.Name
	}
	h := ref.Anchor.Hash()
	if len(h) > 6 {
		h = h[:6]
	}
	return string(ref.Kind) + "/" + hex.EncodeToString(h)
}

// coldRowsWithoutWrap lists the cold-role records whose outer layer opens (the
// master key) and whose recovery wrap is empty.
func (t *txn) coldRowsWithoutWrap() ([]wrapCand, error) {
	all, err := t.coldRows()
	var out []wrapCand
	for _, c := range all {
		if !c.has {
			out = append(out, c)
		}
	}
	return out, err
}

// coldRows lists every cold-role record whose outer layer opens.
func (t *txn) coldRows() ([]wrapCand, error) {
	var out []wrapCand
	for _, kind := range ports.AllKinds() {
		if !labels.IsKeySecret(kind) {
			continue
		}
		refs, err := t.Records(kind)
		if err != nil {
			return nil, err
		}
		for _, ref := range refs {
			row, err := t.fetch(ref)
			if err != nil {
				return nil, err
			}
			if !seal.IsColdSealed(row.sealed) {
				continue
			}
			cls, err := labels.ClassifyKeyRecord(t, ref)
			if err != nil {
				return nil, &RefError{ref, err}
			}
			oc, err := t.s.keys.OpenColdOuter(metaOf(t.s.ws, row.id, ref, seal.ClassSecretCold, row.version), row.sealed)
			if err != nil {
				return nil, corrupt(ref, err)
			}
			out = append(out, wrapCand{ref: ref, id: row.id, version: row.version, hash: sha256.Sum256(row.sealed.WrappedKey), oc: oc, ident: cls.Identity.Hash(), has: len(oc.RecoveryWrap()) > 0, identID: cls.Identity, name: recordName(t, ref)})
		}
	}
	return out, nil
}

// ErrColdAnswerInconsistent: the authenticator answered the same salt twice with
// different outputs, so a sub-key made from either would be unusable; nothing was
// sealed.
var ErrColdAnswerInconsistent = errors.New("sqlitestore: the authenticator returned two different answers for the same salt, so no cold key was sealed under it; nothing was written")

// assertVerified makes one assertion of salt and a second one of the same salt
// and compares the two outputs in constant time (one extra touch): a faulty answer
// would otherwise seal a key under an output nobody can reproduce, which is for
// good under strict.
func (c *coldSession) assertVerified(ctx context.Context, cred []byte, rpid string, salt []byte) (*secret.Buffer, error) {
	o1, _, err := c.assert(ctx, cred, rpid, salt, nil)
	if err != nil {
		return nil, err
	}
	o2, _, err := c.assert(ctx, cred, rpid, salt, nil)
	if err != nil {
		o1.Destroy()
		return nil, err
	}
	same := equalBuffers(o1, o2)
	o2.Destroy()
	if !same {
		o1.Destroy()
		return nil, ErrColdAnswerInconsistent
	}
	return o1, nil
}

// readCold lists the cold-role records in a read transaction (no factor).
func (s *Store) readCold(ctx context.Context) ([]wrapCand, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := s.checkEpoch(ctx, tx); err != nil {
		return nil, err
	}
	if err := s.catchUp(ctx, tx); err != nil {
		return nil, err
	}
	return (&txn{s: s, ctx: ctx, q: tx, ops: map[ports.Ref]*op{}}).coldRows()
}

// gatherColdRekey presents, before the file lock and the write transaction,
// every factor a rekey or rotation of cold-role records needs (see coldPre).
//
//   - Rotation, or a recovery rekey that re-establishes the records (a
//     passphrase change on a handle unlocked through the recovery credential,
//     given the new cold factor): a record with a recovery wrap is opened through
//     the wrap, with the identity check, when the recovery credential is present;
//     the old factor is used only for a record with no wrap or one that cannot
//     be checked against its identity (an upstream-encrypted key, or a mnemonic
//     when no mnemonic deriver is wired). EVERY record that the old factor
//     opens is sealed again under the new factor. A record whose old factor
//     cannot be presented is not left behind silently: the change is refused, with
//     the records named (ADR 0011: "otherwise it is refused and the records are
//     named"), unless the operator names the record in LeaveUnreachable and the
//     recovery credential is present, in which case it keeps its old factor and the
//     fact is recorded in the audit trail (cold-left).
//   - Any other rekey that binds a recovery key: a record with no recovery wrap
//     gains one, which needs the old factor (refused when it cannot be presented).
func (s *Store) gatherColdRekey(ctx context.Context, req rekeyReq, slots []tslot, policy unlock.Policy) (*coldPre, error) {
	if policy == "" {
		policy = s.policy
	}
	if !req.reencrypt && s.policy != unlock.Standard {
		return nil, nil // refused by the policy check inside the transaction
	}
	cands, err := s.readCold(ctx)
	if err != nil {
		return nil, err
	}
	var leaveNames []string
	if req.cold != nil {
		leaveNames = req.cold.LeaveUnreachable
	}
	if len(cands) == 0 {
		if len(leaveNames) > 0 {
			return nil, fmt.Errorf("%w: this workspace has no cold-role records", ErrColdLeaveUnknown)
		}
		return nil, nil
	}
	newPub, err := commonPub(slots)
	if err != nil {
		return nil, err
	}
	rkey := s.recoveryKeyOf(req.proof)
	reestablish := req.reencrypt || (s.viaRecovery && req.cold != nil && len(newPub) > 0)
	leave := map[string]bool{}
	for _, n := range leaveNames {
		found := false
		for _, c := range cands {
			found = found || c.name == n
		}
		if !found || rkey == nil || !reestablish {
			return nil, fmt.Errorf("%w: %q", ErrColdLeaveUnknown, n)
		}
		leave[n] = true
	}
	vkDer, mnDer := s.coldDerivers(req.cold)
	pre := newColdPre()
	pre.reestablish = reestablish
	ok := false
	defer func() {
		if !ok {
			pre.destroy()
		}
	}()
	var old *coldSession
	oldFactor := func(c wrapCand) (*secret.Buffer, error) {
		if old == nil {
			old = s.newColdSession(s.policy, s.coldSource())
		}
		dk, _, err := old.openKey(ctx, c.oc, c.ident, false)
		if err != nil {
			if errors.Is(err, seal.ErrAuth) {
				return nil, &RefError{c.ref, ErrColdFactorWrong}
			}
			return nil, err
		}
		pt, err := c.oc.OpenSecretWithDataKey(dk)
		if err != nil {
			dk.Destroy()
			return nil, corrupt(c.ref, err)
		}
		pt.Destroy()
		return dk, nil
	}
	defer func() {
		if old != nil {
			old.destroy()
		}
	}()
	nReseal := 0
	var stranded []string
	identityRefused := false
	var priv *ecdh.PrivateKey
	for _, c := range cands {
		id := string(c.id)
		pre.seen[id] = true
		if leave[c.name] {
			pre.skip[id] = errLeftOnRequest
			pre.left = append(pre.left, c.id)
			continue
		}
		needDK := false
		why := ""
		switch {
		case reestablish && rkey != nil && c.has && coldCheckable(c.ref.Kind, vkDer, mnDer):
			// the wrap is opened here, before the lock, with the recovery private key, and
			// the key it holds is checked against the record's identity
			if priv == nil {
				var perr error
				if priv, perr = rkey.priv(); perr != nil {
					return nil, perr
				}
			}
			dk, err := recoverChecked(ctx, c, priv, vkDer, mnDer)
			if err == nil {
				pre.keys[id] = &preKey{version: c.version, hash: c.hash, dk: dk}
				pre.reseal[id] = true
				nReseal++
				continue
			}
			if !errors.Is(err, ErrRecoveredIdentity) {
				return nil, err
			}
			// not the key of its record (planted, or a path the record does not say): the
			// operator's own old factor is the way, and it is not something a holder of
			// the master key alone can produce
			identityRefused = true
			why = " (" + err.Error() + ")"
			needDK = true
			pre.reseal[id] = true
		case reestablish:
			// every record the old factor opens moves to the new factor: leaving it
			// would split the workspace into two cold passphrases
			needDK = true
			pre.reseal[id] = true
		case !c.has && len(newPub) > 0:
			needDK = true
		}
		if !needDK {
			continue
		}
		dk, err := oldFactor(c)
		if err != nil {
			if reestablish && rkey != nil && isFactorError(err) {
				stranded = append(stranded, c.name+why)
				delete(pre.reseal, id)
				continue
			}
			return nil, err
		}
		pre.keys[id] = &preKey{version: c.version, hash: c.hash, dk: dk}
		if pre.reseal[id] {
			nReseal++
		}
	}
	if len(stranded) > 0 {
		var base error = ErrColdWouldStrand
		if identityRefused {
			base = fmt.Errorf("%w (%w)", ErrColdWouldStrand, ErrRecoveredIdentity)
		}
		return nil, fmt.Errorf("%w: %s; the recovery credential reaches the others, but these need the old cold factor. Present it, or pass --leave-unreachable <record> for each one you accept to leave (it keeps its old factor and is listed by `spo store verify` until it is re-established)", base, strings.Join(stranded, ", "))
	}
	if len(pre.left) > 0 {
		s.notice(fmt.Sprintf("%d cold-role record(s) were left under their old cold factor, as you asked (--leave-unreachable): they keep (or lack) the recovery wrap they had and open only with that factor; `spo store verify` lists them", len(pre.left)))
	}
	if nReseal > 0 {
		if req.cold == nil {
			return nil, fmt.Errorf("%w: the workspace holds %d cold-role record(s) to seal again and no factor for their new sub-key was given", ErrColdFactorRequired, nReseal)
		}
		sess := s.newColdSession(policy, req.cold)
		newTbl := &table{ws: s.ws, format: seal.StoreFormat, policy: policy, slots: slots}
		if policy != unlock.Standard {
			for _, ts := range slots {
				if ts.kind == seal.SlotFIDO2HMAC && len(ts.fs.Spec.Factors) == 1 {
					fp := ts.fs.Spec.Factors[0]
					sess.cred = &fp
					break
				}
			}
			if sess.cred == nil {
				return nil, errors.New("sqlitestore: the new table has no daily FIDO2 factor for the new cold sub-keys")
			}
		}
		if err := sess.ready(ctx); err != nil {
			return nil, err
		}
		if policy == unlock.Standard {
			pw, err := sess.passphrase(ctx, true, slotPassphraseCheck(newTbl))
			if err != nil {
				return nil, err
			}
			sess.pass = nil // the preparation owns it now
			pre.newPass = pw
		} else {
			for i := 0; i < nReseal; i++ {
				cur, err := freshSalt()
				if err != nil {
					return nil, err
				}
				next, err := freshSalt()
				if err != nil {
					return nil, err
				}
				out, err := sess.assertVerified(ctx, sess.cred.CredentialID, sess.cred.RPID, cur)
				if err != nil {
					return nil, err
				}
				pre.newOuts = append(pre.newOuts, &prepOut{cred: sess.cred.CredentialID, salt: cur, next: next, out: out})
			}
		}
	}
	ok = true
	return pre, nil
}

// errLeftOnRequest marks a record the operator asked to leave under its old factor.
var errLeftOnRequest = errors.New("left under its old cold factor on request")

// coldCheckable says whether a recovered record of the kind can be checked against
// its key identity with the derivers wired: an upstream-encrypted key never (the
// plaintext is a key still wrapped by gpg), a cold mnemonic only when a mnemonic
// deriver is wired.
func coldCheckable(kind ports.Kind, vk ports.VerificationKeyDeriver, mn ports.ColdMnemonicVKeyDeriver) bool {
	switch {
	case kind == ports.UpstreamEncryptedSKey:
		return false
	case labels.IsColdMnemonic(kind):
		return mn != nil
	}
	return true
}

// recoverChecked opens the data key of the record c through its recovery wrap and
// checks that the signing key (or mnemonic) it protects derives the key identity of the
// record, before anything is sealed again. The wrap is made with only the recovery
// public key, so anyone who can write the file can plant a record and a matching wrap
// of a key of their choice; this is what stops it. A failure of the check is
// ErrRecoveredIdentity, wrapped with the record's name.
func recoverChecked(ctx context.Context, c wrapCand, priv *ecdh.PrivateKey, vk ports.VerificationKeyDeriver, mn ports.ColdMnemonicVKeyDeriver) (*secret.Buffer, error) {
	dk, err := c.oc.RecoverDataKey(priv, c.ident)
	if err != nil {
		return nil, err
	}
	pt, err := c.oc.OpenSecretWithDataKey(dk)
	if err != nil {
		dk.Destroy()
		return nil, err
	}
	defer pt.Destroy()
	if err := checkRecoveredIdentity(ctx, pt, c.identID, c.ref.Kind, vk, mn); err != nil {
		dk.Destroy()
		return nil, fmt.Errorf("cold record %s: %w", c.name, err)
	}
	return dk, nil
}

// checkRecoveredIdentity derives the verification key of the recovered secret and
// compares its identity with want.
//
// A cold mnemonic is checked by deriving the committee cold verification key from its
// words with the generator's derivation, at the account and index the record's file
// records (the generator records them when they are not 0; a record without them is
// checked at 0, 0). A legacy mnemonic made with another path therefore mismatches and
// is re-established through the old factor, or named and refused.
func checkRecoveredIdentity(ctx context.Context, pt *secret.Buffer, want identity.Ref, kind ports.Kind, vkd ports.VerificationKeyDeriver, mnd ports.ColdMnemonicVKeyDeriver) error {
	if labels.IsColdMnemonic(kind) {
		if mnd == nil || !want.Is(identity.KindKeyHash) {
			return fmt.Errorf("%w: no way to derive the identity of this mnemonic", ErrRecoveredIdentity)
		}
		env, err := mnd.DeriveColdMnemonicVKey(ctx, pt)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrRecoveredIdentity, err)
		}
		role, _ := labels.RoleOfKind(kind)
		got, err := ports.IdentityOfVKey(role, env)
		if err != nil || got != want {
			return ErrRecoveredIdentity
		}
		return nil
	}
	if vkd == nil || !want.Is(identity.KindKeyHash) {
		return fmt.Errorf("%w: no way to derive the identity of this key", ErrRecoveredIdentity)
	}
	vk, err := vkd.DeriveVerificationKey(ctx, pt)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRecoveredIdentity, err)
	}
	got, err := identity.KeyHashOf(vk)
	if err != nil || got != want {
		return ErrRecoveredIdentity
	}
	return nil
}

// VerifyColdPayloads is VerifyPayloads for the cold-role records, with the factor:
// each one is opened with a fresh presentation of its sub-key (one touch, or one
// passphrase entry, per record) and unframed; nothing is written, so the salts do
// not rotate. It proves what VerifyPayloads cannot for these records: that the
// payload decrypts under the sub-key. It still cannot say that the key inside
// derives the record's identity (a verification-key derivation is not the
// store's), which is checked where the key is used or recovered.
func (s *Store) VerifyColdPayloads(ctx context.Context) (int, error) {
	if s.layoutRO {
		// a read-only layout handle never opens a cold-role record, and asks for no factor
		return 0, ErrLayoutColdRecord
	}
	release, err := s.enter(ctx)
	if err != nil {
		return 0, err
	}
	defer release()
	// the records are listed in a read transaction that is closed before any factor is
	// presented: no snapshot is held while the operator is asked
	cands, err := s.readCold(ctx)
	if err != nil {
		return 0, err
	}
	cs := s.newColdSession(s.policy, s.coldSource())
	defer cs.destroy()
	n := 0
	for _, c := range cands {
		dk, _, err := cs.openKey(ctx, c.oc, c.ident, false)
		if err != nil {
			if errors.Is(err, seal.ErrAuth) {
				return n, &RefError{c.ref, ErrColdFactorWrong}
			}
			return n, err
		}
		pt, err := c.oc.OpenSecretWithDataKey(dk)
		dk.Destroy()
		if err != nil {
			if errors.Is(err, seal.ErrAuth) {
				return n, &RefError{c.ref, ErrColdFactorWrong}
			}
			return n, corrupt(c.ref, err)
		}
		pt.Destroy()
		n++
	}
	return n, nil
}

// ColdProblem is a cold-role record that the workspace key alone shows to be out of
// step with the workspace: its header kind does not match the policy, its FIDO2
// credential belongs to no current daily slot, or a recovery left it under its old
// cold factor.
type ColdProblem struct {
	// Record is the record as `store verify` names it: kind/label.
	Record string
	Why    string
}

// ColdFallback is a cold-role record whose current wrap has been healed from its previous one n times.
type ColdFallback struct {
	Record string
	Count  uint64
}

// ColdStatus is what the workspace key alone says about the cold-role records.
type ColdStatus struct {
	Records, WithoutWrap int
	Problems             []ColdProblem
	Fallbacks            []ColdFallback
}

// ColdStatus reads the cold-role records' outer layers with the workspace key (no
// factor) and says what is out of step: a header kind that does not match the
// policy, a FIDO2 credential that belongs to no current daily slot, and the records a
// rotation or recovery was told to leave under their old factor (the cold-left events
// of the audit trail since the last rekey). Whether two records are sealed under
// different cold passphrases cannot be seen without the passphrase, and is not
// reported here.
func (s *Store) ColdStatus(ctx context.Context) (ColdStatus, error) {
	var st ColdStatus
	release, err := s.enter(ctx)
	if err != nil {
		return st, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return st, err
	}
	defer tx.Rollback()
	if err := s.checkEpoch(ctx, tx); err != nil {
		return st, err
	}
	if err := s.catchUp(ctx, tx); err != nil {
		return st, err
	}
	t := &txn{s: s, ctx: ctx, q: tx, ops: map[ports.Ref]*op{}}
	cands, err := t.coldRows()
	if err != nil {
		return st, err
	}
	if len(cands) == 0 {
		return st, nil
	}
	m, err := loadMeta(ctx, tx)
	if err != nil {
		return st, err
	}
	tbl, err := loadTable(ctx, tx, s.ws, uint64(m.format))
	if err != nil {
		return st, err
	}
	daily := map[string]bool{}
	for _, ts := range tbl.slots {
		if !ts.isFactor() || tslotHasRecovery(ts) {
			continue
		}
		for _, f := range ts.fs.Spec.Factors {
			if f.Kind == seal.FactorFIDO2 {
				daily[string(f.CredentialID)] = true
			}
		}
	}
	for _, c := range cands {
		st.Records++
		if !c.has {
			st.WithoutWrap++
		}
		h := c.oc.Header
		var why []string
		switch {
		case tbl.policy == unlock.Standard && h.Kind != seal.ColdPassphrase:
			why = append(why, "sealed under an authenticator, but the policy is standard")
		case tbl.policy != unlock.Standard && h.Kind == seal.ColdPassphrase:
			why = append(why, "sealed under a cold passphrase, but the policy is "+string(tbl.policy))
		case tbl.policy != unlock.Standard && h.Kind == seal.ColdFIDO2 && !daily[string(h.Credential)]:
			why = append(why, "its authenticator credential belongs to no current daily slot")
		}
		if c.oc.Left {
			why = append(why, "a rotation or recovery left it under its old cold factor on request; re-establish it by `spo workspace rotate`")
		}
		if len(why) > 0 {
			st.Problems = append(st.Problems, ColdProblem{Record: c.name, Why: strings.Join(why, "; ")})
		}
		if h.Fallbacks > 0 {
			st.Fallbacks = append(st.Fallbacks, ColdFallback{Record: c.name, Count: h.Fallbacks})
		}
	}
	return st, nil
}

func tslotHasRecovery(ts tslot) bool {
	for _, f := range ts.fs.Spec.Factors {
		if f.Kind == seal.FactorRecovery {
			return true
		}
	}
	return false
}

// coldStatusFn is ColdStatus; a test replaces it.
var coldStatusFn = (*Store).ColdStatus

var (
	// ErrSlotViaRecovery: a slot is created on a handle that was unlocked through a slot that holds the recovery factor.
	ErrSlotViaRecovery = errors.New("sqlitestore: this handle was unlocked through the recovery credential, so no slot is added on it: a daily slot made now would be tied to the recovery authenticator; recover with a rotation (spo workspace rotate), which names a new daily authenticator")
	// ErrRecoveryCredentialAsDaily: a credential of the recovery composite is offered as a daily factor.
	ErrRecoveryCredentialAsDaily = errors.New("sqlitestore: that credential belongs to the recovery composite and may not be a daily factor: the recovery authenticator is kept apart from the daily one")
)

// viaRecoverySlot says that this handle was unlocked through a slot that holds the
// recovery factor (the recovery key of a standard workspace, or the recovery
// composite of a hardware one).
func (s *Store) viaRecoverySlot(t *table) bool {
	if s.viaRecovery {
		return true
	}
	for _, ts := range t.slots {
		if bytes.Equal(ts.id, s.slotID) && ts.isFactor() && tslotHasRecovery(ts) {
			return true
		}
	}
	return false
}

// recoveryCredentials are the FIDO2 credential ids of the recovery composites of t.
func recoveryCredentials(t *table) [][]byte {
	var out [][]byte
	for _, ts := range t.slots {
		if ts.isFactor() && tslotHasRecovery(ts) {
			for _, f := range ts.fs.Spec.Factors {
				if f.Kind == seal.FactorFIDO2 {
					out = append(out, f.CredentialID)
				}
			}
		}
	}
	return out
}

// refuseRecoveryAsDaily refuses a FIDO2 factor whose credential is one of creds.
func refuseRecoveryAsDaily(creds [][]byte, factors []FactorPlan) error {
	for _, f := range factors {
		if f.Params.Kind != seal.FactorFIDO2 {
			continue
		}
		for _, c := range creds {
			if bytes.Equal(c, f.Params.CredentialID) {
				return ErrRecoveryCredentialAsDaily
			}
		}
	}
	return nil
}
