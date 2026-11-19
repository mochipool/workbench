package sqlitestore

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/mochipool/workbench/spo/internal/domain/unlock"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// FactorPlan is one factor of a slot to be made: its parameters (as bound in
// the slot) and the output the caller has already obtained for it (an
// hmac-secret output from EnrolFactor, the Argon2id output of a new passphrase
// factor from seal.PassphraseFactorOutput). A recovery factor has Kind
// seal.FactorRecovery and no Output and no ID: the store fills both.
type FactorPlan struct {
	Params seal.FactorParams
	Output *secret.Buffer
}

// SlotPlan is one slot of the table a rotation creates.
type SlotPlan struct {
	// Kind is seal.SlotPassphrase, SlotRecovery, SlotFIDO2HMAC or SlotComposite.
	Kind string
	// Passphrase is the text of a passphrase slot.
	Passphrase *secret.Buffer
	// Factors are the factors of a fido2-hmac or composite slot.
	Factors []FactorPlan
}

// RotatePlan is the table a rotation writes.
type RotatePlan struct {
	Policy unlock.Policy
	Slots  []SlotPlan
	// Proof is the presentation of the workspace's current recovery path
	// (PresentRecovery). A rotation of a workspace that has one (standard or
	// hardware) replaces the recovery key and so the recovery public key hash
	// bound in every slot, and ADR 0011 decision 6 says that value changes "only
	// in a rotation that presents that composite": without a proof for this
	// handle and this table the rotation is refused before anything is written
	// (ErrRecoveryNotPresented). A strict workspace has no recovery path and needs
	// none, and cannot be rotated to a weaker policy (ErrRotateWeakens). Weakening
	// a workspace that has a recovery path (hardware to standard) is allowed with
	// the proof.
	Proof *RecoveryProof
	// ColdNew presents the sub-key factor of the new table for the cold-role
	// records: the new sub-key passphrase (standard) or the daily authenticator of
	// the new table (hardware, strict). A workspace with cold-role records is not
	// rotated without it. Every cold record is sealed again under it: a record with a
	// recovery wrap is opened through the wrap with the recovery credential of Proof
	// (checked against its key identity, a cold mnemonic through ColdNew.Mnemonic); a
	// record that needs the old sub-key (no wrap, or not checkable) is opened by the
	// handle's own cold source. A record neither can open is NOT left behind: the
	// rotation is refused before anything is written and the records are named
	// (ErrColdWouldStrand), unless ColdNew.LeaveUnreachable names the record and Proof
	// was presented, which leaves it under its old factor and writes a cold-left event.
	ColdNew *ColdSource
	// KeepCopy, when not empty, is the path of an explicit copy of the file made
	// before the rotation (O_EXCL, mode 0600). The copy still opens with the OLD
	// credentials, which is what a rotation revokes: the operator destroys it once
	// the new factors are confirmed. It is removed when the rotation fails. A
	// rotation makes no copy otherwise (the transaction is atomic).
	KeepCopy string
	// ConfirmRemoved, when non-nil, is the set of slot ids (hex) the operator
	// confirmed removing; a rotation of a strict table is refused inside its
	// transaction unless every slot of the table that is actually there is in it.
	ConfirmRemoved map[string]bool
	// events are extra audit events of the rotation's slot row.
	events [][]any
}

// ErrRecoveryNotPresented: a rotation of a workspace with a recovery path needs
// the current recovery credential (the recovery key and, under hardware, the
// second authenticator) presented and checked against the recovery public key
// hash bound in the slots.
var ErrRecoveryNotPresented = errors.New("sqlitestore: a rotation needs the current recovery credential presented first (the recovery key and, under hardware, the recovery authenticator); a handle opened with the daily credential only cannot change the recovery path")

// ErrRemovalNotConfirmed: a strict rotation would remove a slot the operator did
// not confirm (the table changed after the confirmation, or it was never given).
var ErrRemovalNotConfirmed = errors.New("sqlitestore: a strict rotation removes a slot that was not confirmed")

// ErrRotateWeakens: a rotation to a policy weaker than the current one cannot
// be authorised. A strict workspace has no recovery credential to present, and
// ADR 0011 does not say how a strict workspace may be loosened; it is refused.
var ErrRotateWeakens = errors.New("sqlitestore: a rotation cannot weaken the policy of this workspace")

// RecoveryProof says that, on one handle, the current recovery credential was
// presented and matched the recovery public key hash bound in the slot table.
// It holds no secret and can be made only by PresentRecovery.
type RecoveryProof struct {
	s     *Store
	epoch []byte
	hash  []byte
	// key is the recovery secret the presentation reproduced (guarded memory,
	// destroyed with the handle or the next presentation). Cold-role records are
	// wrapped to the public key derived from it; a rotation or a recovery uses it
	// to open them without the daily factor.
	key *recoveryKey
}

// PresentRecovery checks the recovery credential against the table this handle
// unlocked and returns the proof a rotation needs (ADR 0011 decision 6: "a
// rotation compares the value against the recovery composite it is presented
// with"). Under standard, in.Recovery returns the recovery key (32 raw bytes)
// and it must open a recovery slot and reproduce the bound hash. Under
// hardware the recovery composite's other factors are asserted through
// in.Source (the second authenticator, with its own PIN and touch), the slot
// key is derived and the hardware recovery hash compared with the bound one. A
// strict workspace has no recovery path (ErrNoRecoveryPath). Nothing is written.
func (s *Store) PresentRecovery(ctx context.Context, in FactorInputs) (*RecoveryProof, error) {
	release, err := s.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	t, err := s.currentTable(ctx)
	if err != nil {
		return nil, err
	}
	if in.Recovery == nil {
		return nil, errors.New("sqlitestore: no recovery key to present")
	}
	hash, _, ok := t.commonRecHash()
	if !ok {
		return nil, fmt.Errorf("%w: the slots bind different recovery public key hashes", ErrPolicyViolated)
	}
	sameMaster := func(mk *secret.Buffer) bool {
		same := false
		mk.Use(func(a []byte) error {
			return s.master.Use(func(b []byte) error { same = len(a) == len(b) && hmac.Equal(a, b); return nil })
		})
		mk.Destroy()
		return same
	}
	switch t.policy {
	case unlock.Strict:
		return nil, ErrNoRecoveryPath
	case unlock.Standard:
		rk, err := in.Recovery(ctx)
		if err != nil {
			return nil, err
		}
		defer rk.Destroy()
		for _, ts := range t.slots {
			if ts.kind != seal.SlotRecovery {
				continue
			}
			if hash != nil && !ts.bound {
				continue // the table binds a hash: an unbound (legacy) recovery slot proves nothing
			}
			mk, err := ts.ps.Unwrap(t.ws, rk)
			if err != nil {
				continue
			}
			if !sameMaster(mk) {
				continue
			}
			if ts.bound {
				h, herr := seal.RecoveryPublicKeyHash(rk)
				if herr != nil || !hmac.Equal(h, hash) {
					continue
				}
			}
			cp, cerr := copySecret(rk)
			if cerr != nil {
				return nil, cerr
			}
			s.setProof(&RecoveryProof{s: s, epoch: append([]byte(nil), s.epoch...), hash: append([]byte(nil), hash...), key: &recoveryKey{secret: cp}})
			return s.recProof, nil
		}
		return nil, ErrWrongRecovery
	}
	// hardware
	if in.Source == nil {
		return nil, errors.New("sqlitestore: no factor source to present the recovery authenticator")
	}
	for _, ts := range t.slots {
		if !ts.isFactor() {
			continue
		}
		isRec := false
		for _, f := range ts.fs.Spec.Factors {
			if f.Kind == seal.FactorRecovery {
				isRec = true
			}
		}
		if !isRec {
			continue
		}
		var outs []*secret.Buffer
		destroy := func() {
			for _, o := range outs {
				o.Destroy()
			}
		}
		for _, f := range ts.fs.Spec.Factors {
			o, ferr := factorOutput(ctx, ts.fs.Spec, f, &in)
			if ferr != nil {
				destroy()
				if errors.Is(ferr, ports.ErrFactorNoCredential) {
					return nil, fmt.Errorf("%w: the authenticator presented holds no credential of the recovery composite", ErrWrongRecovery)
				}
				return nil, ferr
			}
			outs = append(outs, o)
		}
		mk, uerr := ts.fs.Unwrap(outs)
		var h []byte
		var held *secret.Buffer
		if uerr == nil {
			var sk *secret.Buffer
			if sk, uerr = ts.fs.Spec.DeriveKey(outs); uerr == nil {
				h, uerr = seal.RecoveryPublicKeyHashHardware(sk)
				held = sk
			}
		}
		destroy()
		if uerr != nil {
			held.Destroy()
			if errors.Is(uerr, seal.ErrAuth) {
				return nil, ErrWrongRecovery
			}
			return nil, uerr
		}
		if !sameMaster(mk) || !hmac.Equal(h, hash) {
			held.Destroy()
			return nil, ErrWrongRecovery
		}
		s.setProof(&RecoveryProof{s: s, epoch: append([]byte(nil), s.epoch...), hash: append([]byte(nil), hash...), key: &recoveryKey{secret: held, hardware: true}})
		return s.recProof, nil
	}
	return nil, ErrWrongRecovery
}

// ErrNoRecoveryPath: the workspace has no recovery credential (strict).
var ErrNoRecoveryPath = errors.New("sqlitestore: this workspace has no recovery path (policy strict)")

// ErrWrongRecovery: the credential presented is not the recovery credential of
// this workspace.
var ErrWrongRecovery = errors.New("sqlitestore: that is not the recovery credential of this workspace")

// rotationGuard is the store-layer rule of S1, run inside the rotation's
// transaction on the table as it is then, before anything is written.
func (s *Store) rotationGuard(plan RotatePlan) func(t *table) error {
	return func(t *table) error {
		if t.policy == unlock.Strict {
			// no recovery credential exists to authorise a weaker table (ADR 0011 is
			// silent on loosening a strict workspace): refused
			if unlock.Weakens(t.policy, plan.Policy) {
				return fmt.Errorf("%w: from %s to %s", ErrRotateWeakens, t.policy, plan.Policy)
			}
			return nil
		}
		// A weaker policy (hardware to standard) and a changed recovery path both
		// need the current recovery credential; so does every other rotation of a
		// table with a recovery path, because the new table binds a new recovery
		// public key hash.
		hash, _, ok := t.commonRecHash()
		p := plan.Proof
		if p == nil && s.viaRecovery && ok {
			return nil
		}
		if !ok || p == nil || p.s != s || !hmac.Equal(p.epoch, s.epoch) || !hmac.Equal(p.hash, hash) {
			return ErrRecoveryNotPresented
		}
		return nil
	}
}

// PreflightFactors checks, before any credential is made, that each authenticator
// in ins can serve (its profile has what a slot needs) and, where the source can
// check a PIN without a credential (ports.PINChecker), that its PIN is right.
// Each input has its own PIN callback and device, so the PIN of the recovery
// authenticator is never the daily one. The PINs are read here and again by
// EnrolFactor; a caller that wants one prompt each caches per input. A wrong PIN
// ends the preflight with ports.ErrFactorPIN and nothing was created on any
// authenticator.
func PreflightFactors(ctx context.Context, ins ...FactorInputs) error {
	for _, in := range ins {
		if in.Source == nil {
			return errors.New("sqlitestore: no factor source")
		}
		prof, err := in.Source.Profile(ctx, in.Device)
		if err != nil {
			return err
		}
		if err := ports.CheckFactorProfile(prof, ports.NeedsOfSlot); err != nil {
			return err
		}
	}
	for _, in := range ins {
		chk, ok := in.Source.(ports.PINChecker)
		if !ok || in.PIN == nil {
			continue
		}
		pin, err := in.PIN(ctx)
		if err != nil {
			return err
		}
		if pin == nil {
			continue
		}
		err = chk.CheckPIN(ctx, in.Device, pin)
		pin.Destroy()
		if err != nil {
			return err
		}
	}
	return nil
}

// EnrolFactor makes a FIDO2 credential bound to this workspace (relying-party
// id spo.<genesis nonce in hex>, ADR 0011 decision 4), draws the hmac-secret
// salt, and asserts once to obtain the output the slot key derives from. The
// source's Enrol refuses an authenticator that does not confirm credProtect
// level 3; the capability profile is checked before any prompt.
func EnrolFactor(ctx context.Context, in FactorInputs, genesisNonce []byte, rnd io.Reader) (FactorPlan, ports.Enrolment, error) {
	if in.Source == nil {
		return FactorPlan{}, ports.Enrolment{}, errors.New("sqlitestore: no factor source")
	}
	prof, err := in.Source.Profile(ctx, in.Device)
	if err != nil {
		return FactorPlan{}, ports.Enrolment{}, err
	}
	if err := ports.CheckFactorProfile(prof, ports.NeedsOfSlot); err != nil {
		return FactorPlan{}, ports.Enrolment{}, err
	}
	var pin *secret.Buffer
	if in.PIN != nil {
		if pin, err = in.PIN(ctx); err != nil {
			return FactorPlan{}, ports.Enrolment{}, err
		}
		defer pin.Destroy()
	}
	rpid := "spo." + hex.EncodeToString(genesisNonce)
	if in.Notify != nil {
		in.Notify("touch the authenticator to make the credential")
	}
	en, err := in.Source.Enrol(ctx, ports.EnrolRequest{Device: in.Device, RPID: rpid, PIN: pin})
	if err != nil {
		return FactorPlan{}, en, err
	}
	if en.CredProtect != ports.CredProtectRequired {
		return FactorPlan{}, en, fmt.Errorf("%w: credProtect level %d confirmed, 3 required", ports.ErrFactorUnsupported, en.CredProtect)
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	salt := make([]byte, ports.FactorSaltSize)
	if _, err := io.ReadFull(rnd, salt); err != nil {
		return FactorPlan{}, en, err
	}
	if in.Notify != nil {
		in.Notify("touch the authenticator again to read its secret")
	}
	a, err := in.Source.Assert(ctx, ports.AssertRequest{Device: in.Device, CredentialID: en.CredentialID, RPID: rpid, Salt: salt, UserPresence: true, PIN: pin})
	if err != nil {
		return FactorPlan{}, en, err
	}
	if err := a.Require(ports.Requirement{UserPresence: true, UserVerification: true}); err != nil {
		return FactorPlan{}, en, err
	}
	if a.NextOutput != nil {
		a.NextOutput.Destroy()
	}
	return FactorPlan{Params: seal.FactorParams{Kind: seal.FactorFIDO2, ID: en.FactorID, CredentialID: en.CredentialID, RPID: rpid, HMACSalt: salt, Touch: uint8(en.Touch)}, Output: a.Output}, en, nil
}

// recoveryFactorID is the id of the recovery factor of a hardware recovery
// composite. It cannot be the recovery public key hash (as under standard)
// because that hash is derived from this composite's slot key, and the slot key
// depends on the factor ids.
func recoveryFactorID(slotID []byte) []byte {
	h := sha256.Sum256(append([]byte("spo/factor-id/recovery-composite\x00"), slotID...))
	return h[:]
}

// factorSpec sorts the plan's factors with their outputs and returns the slot
// spec (without the recovery key hash) and the outputs in the spec's order.
func factorSpec(ws, id []byte, kind string, fps []FactorPlan, policy unlock.Policy, recHash []byte, rk *secret.Buffer) (seal.SlotSpec, []*secret.Buffer, error) {
	plans := append([]FactorPlan(nil), fps...)
	for i := range plans {
		if plans[i].Params.Kind == seal.FactorRecovery {
			if rk == nil {
				return seal.SlotSpec{}, nil, fmt.Errorf("%w: a recovery factor in a table with no recovery key", ErrPolicyViolated)
			}
			plans[i].Output = rk
			if policy == unlock.Hardware {
				plans[i].Params.ID = recoveryFactorID(id)
			} else {
				plans[i].Params.ID = recHash
			}
		}
	}
	sorted := make([]seal.FactorParams, len(plans))
	for i := range plans {
		sorted[i] = plans[i].Params
	}
	seal.SortFactors(sorted)
	outs := make([]*secret.Buffer, len(sorted))
	for i, sp := range sorted {
		for j := range plans {
			if plans[j].Params.Kind == sp.Kind && string(plans[j].Params.ID) == string(sp.ID) {
				outs[i] = plans[j].Output
			}
		}
		if outs[i] == nil {
			return seal.SlotSpec{}, nil, errors.New("sqlitestore: a factor has no output")
		}
	}
	return seal.SlotSpec{FormatVersion: seal.StoreFormat, GenesisNonce: ws, SlotID: id, Kind: kind, Factors: sorted, RecoveryPubKeyHash: recHash, Policy: string(policy)}, outs, nil
}

// buildFactorSlot makes a fido2-hmac or composite slot from a plan.
func buildFactorSlot(ws []byte, master *secret.Buffer, kind string, fps []FactorPlan, policy unlock.Policy, recHash []byte, rk *secret.Buffer) (tslot, error) {
	id, err := seal.NewID()
	if err != nil {
		return tslot{}, err
	}
	return buildFactorSlotID(ws, id, master, kind, fps, policy, recHash, rk)
}

func buildFactorSlotID(ws, id []byte, master *secret.Buffer, kind string, fps []FactorPlan, policy unlock.Policy, recHash []byte, rk *secret.Buffer) (tslot, error) {
	spec, outs, err := factorSpec(ws, id, kind, fps, policy, recHash, rk)
	if err != nil {
		return tslot{}, err
	}
	fs, err := seal.NewFactorSlot(spec, outs, master)
	if err != nil {
		return tslot{}, err
	}
	return tslot{id: id, kind: kind, fs: fs, bound: true}, nil
}

// hardwareRecoveryHash derives the recovery public key hash of a hardware
// workspace from the slot key of the recovery composite (ADR 0011 decision 6).
func hardwareRecoveryPub(ws, id []byte, fps []FactorPlan, rk *secret.Buffer) ([]byte, error) {
	spec, outs, err := factorSpec(ws, id, seal.SlotComposite, fps, unlock.Hardware, nil, rk)
	if err != nil {
		return nil, err
	}
	sk, err := spec.DeriveKey(outs)
	if err != nil {
		return nil, err
	}
	defer sk.Destroy()
	priv, err := seal.RecoveryKeyPairHardware(sk)
	if err != nil {
		return nil, err
	}
	return priv.PublicKey().Bytes(), nil
}

func hasRecovery(p RotatePlan) bool {
	for _, sp := range p.Slots {
		if sp.Kind == seal.SlotRecovery {
			return true
		}
		for _, f := range sp.Factors {
			if f.Params.Kind == seal.FactorRecovery {
				return true
			}
		}
	}
	return false
}

// Rotate replaces the master key, draws a fresh data key for every record,
// re-encrypts every payload, and writes the table of plan with its policy, in
// one transaction (ADR 0011, decision 6, "Rotation"). It is the only way to
// remove a slot or a factor and the only way to change to another policy that
// removes slots: a removal revokes nothing unless the keys change. The table is
// checked against the policy it declares before anything is written; a plan that
// breaks it is refused with ErrPolicyViolated and nothing changes. Every factor
// of every new slot must be present, which is why the plan carries their
// outputs.
//
// A rotation makes no copy of the file: a copy still opens with the credentials
// the rotation revokes. plan.KeepCopy asks for one explicitly. Every other
// handle must be closed (ErrLocked otherwise). The new
// recovery key is returned as text when the plan has a recovery path and nil
// under strict; the same rules as Rekey hold for it (ErrOutcomeUnknown returns
// the key with the error). What a rotation cannot delete: backups, snapshots,
// remnants on the medium, and any copy the removed party already holds.
func (s *Store) Rotate(ctx context.Context, plan RotatePlan) (recovery *secret.Buffer, backup string, err error) {
	defer func() {
		if plan.Proof != nil {
			plan.Proof.key.destroy()
		}
		s.consumeRecovery()
	}()
	if err := s.writable(); err != nil {
		return nil, "", err
	}
	if !plan.Policy.Valid() || len(plan.Slots) == 0 {
		return nil, "", fmt.Errorf("%w: a rotation needs a policy and at least one slot", ErrPolicyViolated)
	}
	for _, sp := range plan.Slots {
		for _, f := range sp.Factors {
			if f.Params.Kind == seal.FactorBackend {
				// the wrap at the backend is bound to a slot id the rotation has not drawn
				return nil, "", fmt.Errorf("%w: a rotation does not create a Vault or KMS backend slot; add it afterwards (workspace slot add-backend)", ErrPolicyViolated)
			}
		}
	}
	if err := s.checkPlanCredentials(ctx, plan); err != nil {
		return nil, "", err
	}
	if plan.KeepCopy != "" {
		if _, err := s.BackupWithHead(ctx, plan.KeepCopy); err != nil {
			return nil, "", fmt.Errorf("the copy before the rotation could not be made, so nothing was changed: %w", err)
		}
		backup = plan.KeepCopy
		defer func() {
			// a rotation that did not commit leaves no copy; one whose outcome is
			// unknown keeps it, because the old credentials may still be the valid ones
			if err != nil && !errors.Is(err, ErrOutcomeUnknown) {
				removeDB(plan.KeepCopy)
				backup = ""
			}
		}()
	}
	// A rotation replaces every slot: each old slot that the new table does not
	// carry over (by id) is named in the audit trail, so a strict rotation that one
	// daily factor makes leaves a record of the other holders' slots it removed. A
	// slot removal names its own slot in plan.events instead.
	var oldSlots []tslot
	guard := s.rotationGuard(plan)
	text, err := s.rekeyCore(ctx, rekeyReq{reencrypt: true, events: plan.events, cold: plan.ColdNew, proof: plan.Proof,
		guard: func(t *table) error {
			oldSlots = append([]tslot(nil), t.slots...)
			if plan.ConfirmRemoved != nil && t.policy == unlock.Strict {
				for _, sl := range t.slots {
					if !plan.ConfirmRemoved[hex.EncodeToString(sl.id)] {
						return fmt.Errorf("%w: slot %x is in the table now and was not confirmed for removal", ErrRemovalNotConfirmed, sl.id)
					}
				}
			}
			return guard(t)
		},
		lazyEvents: func(written []tslot) [][]any {
			if len(plan.events) > 0 {
				return nil
			}
			var ev [][]any
			for _, o := range oldSlots {
				kept := false
				for _, w := range written {
					kept = kept || bytes.Equal(w.id, o.id)
				}
				if !kept {
					ev = append(ev, []any{"slot-removed", string(o.kind), o.id})
				}
			}
			return ev
		},
		build: func(master *secret.Buffer) ([]tslot, unlock.Policy, *secret.Buffer, error) {
			var rk, text *secret.Buffer
			var recHash, recID, recPub []byte
			recIdx := -1
			if hasRecovery(plan) {
				var err error
				if rk, err = seal.NewMasterKey(); err != nil { // 32 random bytes
					return nil, "", nil, err
				}
				defer rk.Destroy()
				if plan.Policy == unlock.Hardware {
					// the recovery composite is the one slot with a recovery factor
					found := false
					for i, sp := range plan.Slots {
						for _, f := range sp.Factors {
							if sp.Kind == seal.SlotComposite && f.Params.Kind == seal.FactorRecovery && !found {
								found = true
								if recID, err = seal.NewID(); err != nil {
									return nil, "", nil, err
								}
								recIdx = i
								if recPub, err = hardwareRecoveryPub(s.ws, recID, sp.Factors, rk); err != nil {
									return nil, "", nil, err
								}
								recHash = seal.RecoveryPubKeyHash(recPub)
							}
						}
					}
					if !found {
						return nil, "", nil, fmt.Errorf("%w: hardware needs a recovery composite", ErrPolicyViolated)
					}
				} else {
					priv, perr := seal.RecoveryKeyPair(rk)
					if perr != nil {
						return nil, "", nil, perr
					}
					recPub = priv.PublicKey().Bytes()
					recHash = seal.RecoveryPubKeyHash(recPub)
				}
				if text, err = seal.EncodeRecoveryKey(rk); err != nil {
					return nil, "", nil, err
				}
			}
			fail := func(err error) ([]tslot, unlock.Policy, *secret.Buffer, error) {
				text.Destroy()
				return nil, "", nil, err
			}
			b := seal.SlotBinding{Policy: string(plan.Policy), RecoveryPubKeyHash: recHash}
			var out []tslot
			for _, sp := range plan.Slots {
				id, err := seal.NewID()
				if err != nil {
					return fail(err)
				}
				switch sp.Kind {
				case seal.SlotPassphrase:
					if sp.Passphrase == nil {
						return fail(errors.New("sqlitestore: a passphrase slot needs a passphrase"))
					}
					sl, err := seal.NewBoundPassphraseSlot(s.ws, id, master, sp.Passphrase, kdfForNewSlots, b)
					if err != nil {
						return fail(err)
					}
					out = append(out, tslot{id: id, kind: sp.Kind, ps: sl, bound: true, recPub: recPub})
				case seal.SlotRecovery:
					if rk == nil {
						return fail(fmt.Errorf("%w: a recovery slot in a table with no recovery key", ErrPolicyViolated))
					}
					sl, err := seal.NewBoundRecoverySlot(s.ws, id, master, rk, b)
					if err != nil {
						return fail(err)
					}
					out = append(out, tslot{id: id, kind: sp.Kind, ps: sl, bound: true, recPub: recPub})
				case seal.SlotFIDO2HMAC, seal.SlotComposite:
					var ts tslot
					if recIdx >= 0 && sp.Kind == seal.SlotComposite && len(out) == recIdx {
						ts, err = buildFactorSlotID(s.ws, recID, master, sp.Kind, sp.Factors, plan.Policy, recHash, rk)
					} else {
						ts, err = buildFactorSlot(s.ws, master, sp.Kind, sp.Factors, plan.Policy, recHash, rk)
					}
					if err != nil {
						return fail(err)
					}
					ts.recPub = recPub
					out = append(out, ts)
				default:
					return fail(fmt.Errorf("%w: slot kind %q", ErrPolicyViolated, sp.Kind))
				}
			}
			return out, plan.Policy, text, nil
		}})
	if text == nil && err != nil {
		return nil, backup, err
	}
	return text, backup, err
}

// checkPlanCredentials refuses a plan whose daily factor carries a credential of the
// recovery composite, of the table now or of the plan itself: the recovery
// authenticator is kept apart from the daily one (ADR 0011).
func (s *Store) checkPlanCredentials(ctx context.Context, plan RotatePlan) error {
	release, err := s.enter(ctx)
	if err != nil {
		return err
	}
	t, err := s.currentTable(ctx)
	release()
	if err != nil {
		return err
	}
	creds := recoveryCredentials(t)
	var daily [][]FactorPlan
	for _, sp := range plan.Slots {
		isRec := false
		for _, f := range sp.Factors {
			isRec = isRec || f.Params.Kind == seal.FactorRecovery
		}
		if !isRec {
			daily = append(daily, sp.Factors)
			continue
		}
		for _, f := range sp.Factors {
			if f.Params.Kind == seal.FactorFIDO2 {
				creds = append(creds, f.Params.CredentialID)
			}
		}
	}
	for _, d := range daily {
		if err := refuseRecoveryAsDaily(creds, d); err != nil {
			return err
		}
	}
	return nil
}

// AddFactorSlot adds a fido2-hmac slot (one factor) or a composite slot (two or
// more) whose factor outputs the caller has obtained (EnrolFactor, a passphrase
// factor's output). It needs no rotation (the master key is wrapped once more),
// and the table must stay inside its policy: under standard a FIDO2 slot is a
// convenience, not a strengthening. A workspace whose slots are all legacy has
// no recovery public key to bind yet and refuses the slot: rekey first.
func (s *Store) AddFactorSlot(ctx context.Context, factors []FactorPlan) ([]byte, error) {
	if err := s.writable(); err != nil {
		return nil, err
	}
	release, err := s.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	t, err := s.currentTable(ctx)
	if err != nil {
		return nil, err
	}
	if s.viaRecoverySlot(t) {
		return nil, ErrSlotViaRecovery
	}
	if err := refuseRecoveryAsDaily(recoveryCredentials(t), factors); err != nil {
		return nil, err
	}
	b, bound, err := t.binding()
	if err != nil {
		return nil, err
	}
	if !bound {
		return nil, fmt.Errorf("%w: no slot of this workspace binds a recovery public key yet (it was migrated from format 2); run a rekey first", ErrUseRekey)
	}
	kind := seal.SlotFIDO2HMAC
	if len(factors) > 1 {
		kind = seal.SlotComposite
	}
	ts, err := buildFactorSlot(s.ws, s.master, kind, factors, unlock.Policy(b.Policy), b.RecoveryPubKeyHash, nil)
	if err != nil {
		return nil, err
	}
	return ts.id, s.addSlot(ctx, ts, "slot-added")
}

// WorkspaceNonce returns the genesis nonce (the workspace id), the input of the
// relying-party id of every credential of this workspace.
func (s *Store) WorkspaceNonce() []byte { return append([]byte(nil), s.ws...) }

// EnrolAndAddFIDO2 enrols the authenticator named by in and adds a fido2-hmac
// slot for it.
func (s *Store) EnrolAndAddFIDO2(ctx context.Context, in FactorInputs) ([]byte, error) {
	fp, _, err := EnrolFactor(ctx, in, s.ws, nil)
	if err != nil {
		return nil, err
	}
	defer fp.Output.Destroy()
	return s.AddFactorSlot(ctx, []FactorPlan{fp})
}

// RemoveRequest is what removing a slot needs: the factors of the slots that stay
// (every one must be present, because a removal is a rotation and re-wraps them
// all), the proof of the current recovery credential, and the optional copy.
type RemoveRequest struct {
	SlotID []byte
	// Daily and Recovery present the authenticators of the remaining FIDO2
	// factors (the daily one and the recovery composite's); a FIDO2 factor is
	// asked of each in turn until one holds its credential. Daily.Passphrase
	// supplies the passphrase of a remaining passphrase slot.
	Daily, Recovery FactorInputs
	Proof           *RecoveryProof
	KeepCopy        string
}

// RemoveSlotByRotation removes a slot. A removal revokes nothing unless the
// master key changes (ADR 0011, decision 6: "Removing a factor is not
// revocation"), so it is a rotation that re-creates every other slot with its
// factors present. The table that would remain is checked against the policy
// before anything is asked of an authenticator: removing the last slot the
// policy needs (the last passphrase or recovery slot of standard, the last
// daily slot of hardware or strict) is refused with ErrLastSlot, and a table
// that breaks the policy in another way with ErrPolicyViolated. A recovery slot
// or composite that stays gets a new recovery key, returned as text. The audit
// chain records a `slot-removed` event.
func (s *Store) RemoveSlotByRotation(ctx context.Context, req RemoveRequest) (*secret.Buffer, string, error) {
	defer s.consumeRecovery()
	if err := s.writable(); err != nil {
		return nil, "", err
	}
	release, err := s.enter(ctx)
	if err != nil {
		return nil, "", err
	}
	t, err := s.currentTable(ctx)
	release()
	if err != nil {
		return nil, "", err
	}
	var gone *tslot
	var keep []tslot
	for i := range t.slots {
		if bytes.Equal(t.slots[i].id, req.SlotID) {
			gone = &t.slots[i]
		} else {
			keep = append(keep, t.slots[i])
		}
	}
	if gone == nil {
		return nil, "", fmt.Errorf("%w: no slot has that id", ErrNotFoundSlot)
	}
	rest := &table{ws: t.ws, format: t.format, policy: t.policy, slots: keep}
	if err := rest.check(); err != nil {
		return nil, "", err
	}
	plan := RotatePlan{Policy: t.policy, Proof: req.Proof, KeepCopy: req.KeepCopy, events: [][]any{{"slot-removed", string(gone.kind), gone.id}}}
	if cs := s.coldSource(); cs != nil {
		// a removal keeps the policy: the new sub-key is presented the way the old one is
		c := *cs
		if t.policy != unlock.Standard {
			d := req.Daily
			c.Factors = &d
		}
		plan.ColdNew = &c
	}
	var outs []*secret.Buffer
	defer func() {
		for _, o := range outs {
			o.Destroy()
		}
	}()
	present := func(f seal.FactorParams) (seal.FactorParams, *secret.Buffer, *secret.Buffer, error) {
		var last error
		for _, in := range []*FactorInputs{&req.Daily, &req.Recovery} {
			if in.Source == nil {
				continue
			}
			nf, o, old, err := refreshFactorOutput(ctx, f, in)
			if err == nil {
				return nf, o, old, nil
			}
			last = err
			if !errors.Is(err, ports.ErrFactorNoCredential) {
				return f, nil, nil, err
			}
		}
		if last == nil {
			last = errors.New("no authenticator was presented")
		}
		return f, nil, nil, fmt.Errorf("a remaining slot needs an authenticator that was not presented: %w", last)
	}
	for _, ts := range keep {
		switch ts.kind {
		case seal.SlotPassphrase:
			if req.Daily.Passphrase == nil {
				return nil, "", errors.New("a remaining passphrase slot needs its passphrase present")
			}
			pw, err := req.Daily.Passphrase(ctx)
			if err != nil {
				return nil, "", err
			}
			outs = append(outs, pw)
			if mk, err := ts.ps.Unwrap(t.ws, pw); err != nil {
				return nil, "", ErrWrongCredential
			} else {
				mk.Destroy()
			}
			plan.Slots = append(plan.Slots, SlotPlan{Kind: seal.SlotPassphrase, Passphrase: pw})
		case seal.SlotRecovery:
			plan.Slots = append(plan.Slots, SlotPlan{Kind: seal.SlotRecovery})
		default:
			for _, f := range ts.fs.Spec.Factors {
				if f.Kind == seal.FactorBackend {
					return nil, "", fmt.Errorf("%w: slot %x stays and has a Vault or KMS backend factor, which a rotation cannot re-create (its wrap at the backend is bound to the slot id); remove that slot first and add it again afterwards", ErrPolicyViolated, ts.id)
				}
			}
			var fps []FactorPlan
			// the old-salt outputs of ALL the slot's factors, in the slot's order:
			// the slot must open with them and give this handle's master key, or the
			// presented authenticator is not the slot's (an impostor answers too)
			var olds []*secret.Buffer
			defer func() {
				for _, o := range olds {
					o.Destroy()
				}
			}()
			for _, f := range ts.fs.Spec.Factors {
				switch f.Kind {
				case seal.FactorRecovery:
					rin := &req.Recovery
					if rin.Recovery == nil {
						rin = &req.Daily
					}
					if rin.Recovery == nil {
						return nil, "", fmt.Errorf("%w: a remaining slot holds the recovery key, which must be present to check it", ErrWrongCredential)
					}
					ro, err := rin.Recovery(ctx)
					if err != nil {
						return nil, "", err
					}
					olds = append(olds, ro)
					fps = append(fps, FactorPlan{Params: seal.FactorParams{Kind: seal.FactorRecovery}})
				case seal.FactorFIDO2:
					nf, o, old, err := present(f)
					if err != nil {
						return nil, "", err
					}
					outs = append(outs, o)
					olds = append(olds, old)
					fps = append(fps, FactorPlan{Params: nf, Output: o})
				default:
					return nil, "", fmt.Errorf("%w: a remaining slot has a %d factor this tool cannot re-create", ErrPolicyViolated, f.Kind)
				}
			}
			mk, uerr := ts.fs.Unwrap(olds)
			if uerr != nil {
				return nil, "", ErrWrongCredential
			}
			same := false
			mk.Use(func(a []byte) error {
				return s.master.Use(func(b []byte) error { same = len(a) == len(b) && hmac.Equal(a, b); return nil })
			})
			mk.Destroy()
			if !same {
				return nil, "", ErrWrongCredential
			}
			plan.Slots = append(plan.Slots, SlotPlan{Kind: ts.kind, Factors: fps})
		}
	}
	return s.Rotate(ctx, plan)
}

// ErrNotFoundSlot: no slot has the id given.
var ErrNotFoundSlot = errors.New("sqlitestore: slot not found")

// setProof records the proof of the last PresentRecovery on this handle and
// destroys the recovery secret of the one it replaces.
func (s *Store) setProof(p *RecoveryProof) {
	if s.recProof != nil {
		s.recProof.key.destroy()
	}
	s.recProof = p
}

// consumeRecovery destroys every piece of recovery material the handle holds: the
// proof of the last PresentRecovery, the recovery secret of an unlock through the
// recovery credential, and the claim that the handle was unlocked through it. The
// recovery credential authorises one operation (a rekey, a rotation, a recovery);
// whatever the outcome of that operation, nothing of it stays in a handle that a
// long-lived process holds, so that the master key held by that process cannot be
// used to derive the recovery private key and open the wraps of the cold records.
func (s *Store) consumeRecovery() {
	s.setProof(nil)
	s.viaRecovery = false
	s.recSecret.destroy()
	s.recSecret = nil
}

// DiscardRecovery destroys the recovery proof and secret this handle holds. A
// command that presented the recovery credential for an operation it then did not
// reach (a failed prompt, a failed enrolment) calls it, so a presentation never
// outlives the command that made it.
func (s *Store) DiscardRecovery() { s.consumeRecovery() }

// recoveryKeyOf is the recovery secret a rotation or rekey may use: the one the
// proof reproduced, else the recovery key this handle was unlocked with.
func (s *Store) recoveryKeyOf(p *RecoveryProof) *recoveryKey {
	if p != nil && p.s == s && p.key != nil {
		return p.key
	}
	if s.recProof != nil && s.recProof.s == s && bytes.Equal(s.recProof.epoch, s.epoch) && s.recProof.key != nil {
		return s.recProof.key
	}
	return s.recSecret
}
