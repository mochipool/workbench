package sqlitestore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/unlock"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Vault and KMS backend factors (ADR 0011, decision 5). A backend factor lives
// only inside a composite slot, beside a passphrase or FIDO2 factor of the slot's
// own (decision 6, checked by domain/unlock before the backend is asked). The
// slot stores the backend's public parameters and the wrapped B; the slot's
// associated data binds them. B is drawn here, wrapped at the backend under the
// context [genesis nonce, slot id], and unwrapped once before the slot is
// written, so a backend that does not give B back is refused at enrolment.

// ErrBackendFactor: the Vault or KMS factor of a slot failed. The unlock stops
// there (it fails closed); the error names the backend and wraps the port's
// error kind, never the backend's words or the credential.
var ErrBackendFactor = errors.New("sqlitestore: the Vault or KMS factor failed; nothing was opened or changed")

// backendRefOf is the reference a backend factor stores.
func backendRefOf(f seal.FactorParams) ports.BackendRef {
	return ports.BackendRef{Kind: ports.BackendKind(f.BackendKind), Address: f.BackendAddress, Namespace: f.BackendNamespace, Key: f.BackendKeyRef}
}

// backendFactorID is the factor id of a backend factor: SHA-256 over a label,
// a zero byte and the canonical CBOR of [kind, address, namespace, key]. Two
// slots on the same backend key have the same factor id.
func backendFactorID(ref ports.BackendRef) ([]byte, error) {
	enc, err := seal.EncodeCanonical([]any{string(ref.Kind), ref.Address, ref.Namespace, ref.Key})
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte("spo/factor-id/backend\x00"))
	h.Write(enc)
	return h.Sum(nil), nil
}

func backendErr(ref ports.BackendRef, err error) error {
	return fmt.Errorf("%w (%s at %s): %w", ErrBackendFactor, ref.Kind, ref.Address, err)
}

// backendOpenErr is the error of a backend factor during an open: it names the
// slot, says the open stopped there (fail closed: no other slot is tried after
// a backend failed) and that another way in is still there.
func backendOpenErr(slotID []byte, ref ports.BackendRef, err error) error {
	return fmt.Errorf("%w (slot %x, %s at %s): %w. The open stopped at this slot; another way in (--unlock passphrase, fido2 or recovery-composite, as the policy has them) is not affected",
		ErrBackendFactor, slotID[:min(4, len(slotID))], ref.Kind, ref.Address, err)
}

// checkBackendClaim checks the reference a slot claims against the local
// configuration, before anything is asked or sent. No check given is a
// refusal: a slot row alone never decides where a credential goes.
func checkBackendClaim(slotID []byte, ref ports.BackendRef, in *FactorInputs) error {
	if in.BackendCheck == nil {
		return backendOpenErr(slotID, ref, fmt.Errorf("%w: no local configuration was given to check the backend the slot names against", ports.ErrBackendMismatch))
	}
	if err := in.BackendCheck(ref); err != nil {
		return backendOpenErr(slotID, ref, err)
	}
	return nil
}

// backendOutput unwraps the B of a backend factor of the slot spec through the
// caller's backend client, after the slot's claim was checked against the
// local configuration (again here: every path to a backend passes the check).
func backendOutput(ctx context.Context, spec seal.SlotSpec, f seal.FactorParams, in *FactorInputs) (*secret.Buffer, error) {
	if in.Backend == nil {
		return nil, errSkipSlot
	}
	ref := backendRefOf(f)
	if err := checkBackendClaim(spec.SlotID, ref, in); err != nil {
		return nil, err
	}
	kb, err := in.Backend(ctx, ref)
	if err != nil {
		return nil, backendOpenErr(spec.SlotID, ref, err)
	}
	if kb == nil || kb.Ref() != ref {
		return nil, backendOpenErr(spec.SlotID, ref, fmt.Errorf("%w: the client given is not for the backend the slot names", ports.ErrBackendConfig))
	}
	// the resolver hands the client over: its credential lives for this unwrap only
	if c, ok := kb.(interface{ Close() }); ok {
		defer c.Close()
	}
	if in.Notify != nil {
		in.Notify(fmt.Sprintf("asking %s at %s to unwrap the factor secret", ref.Kind, ref.Address))
	}
	b, err := kb.Unwrap(ctx, f.BackendBlob, ports.WrapContext{GenesisNonce: spec.GenesisNonce, SlotID: spec.SlotID})
	if err != nil {
		return nil, backendOpenErr(spec.SlotID, ref, err)
	}
	if b == nil || b.Len() != ports.BackendSecretSize {
		b.Destroy()
		return nil, backendOpenErr(spec.SlotID, ref, fmt.Errorf("%w: the factor secret is not %d bytes", ports.ErrBackendResponse, ports.BackendSecretSize))
	}
	return b, nil
}

// NewPassphraseFactor makes the passphrase factor of a new composite slot: a
// random factor id, a fresh salt, the store's Argon2id parameters, and the
// output for passphrase. The caller destroys the output.
func NewPassphraseFactor(passphrase *secret.Buffer) (FactorPlan, error) {
	if passphrase == nil || passphrase.Len() == 0 {
		return FactorPlan{}, errors.New("sqlitestore: a passphrase factor needs a passphrase")
	}
	id := make([]byte, seal.IDSize)
	salt := make([]byte, seal.SaltSize)
	if _, err := rand.Read(id); err != nil {
		return FactorPlan{}, err
	}
	if _, err := rand.Read(salt); err != nil {
		return FactorPlan{}, err
	}
	out, err := seal.PassphraseFactorOutput(passphrase, salt, kdfForNewSlots)
	if err != nil {
		return FactorPlan{}, err
	}
	return FactorPlan{Params: seal.FactorParams{Kind: seal.FactorPassphrase, ID: id, KDF: kdfForNewSlots, KDFSalt: salt}, Output: out}, nil
}

// CheckBackendSlot runs every refusal of AddBackendSlot that needs neither the
// backend nor the other factor, for a composite of the backend ref and other
// factors of the kinds given (seal.FactorPassphrase or seal.FactorFIDO2): a
// read-only handle, a handle opened through the recovery credential, a table
// that binds no recovery public key yet (migrated from format 2), and the
// policy on the table with the new slot (each FIDO2 factor counted as a new
// credential). A caller runs it before it makes a FIDO2 credential or calls the
// backend, so a refused slot leaves nothing on the authenticator.
func (s *Store) CheckBackendSlot(ctx context.Context, ref ports.BackendRef, kinds []seal.FactorKind) error {
	plans := make([]FactorPlan, 0, len(kinds))
	for _, k := range kinds {
		id, err := seal.NewID()
		if err != nil {
			return err
		}
		// a fresh id: a new FIDO2 credential or a new passphrase is in no other slot
		plans = append(plans, FactorPlan{Params: seal.FactorParams{Kind: k, ID: id}})
	}
	_, _, err := s.checkBackendSlot(ctx, ref, plans)
	return err
}

// checkBackendSlot is the pre-check of a backend composite: it returns the new
// slot's id and the table's binding.
func (s *Store) checkBackendSlot(ctx context.Context, ref ports.BackendRef, others []FactorPlan) ([]byte, seal.SlotBinding, error) {
	var none seal.SlotBinding
	if err := s.writable(); err != nil {
		return nil, none, err
	}
	if err := ref.Validate(); err != nil {
		return nil, none, backendErr(ref, err)
	}
	for _, o := range others {
		if o.Params.Kind != seal.FactorPassphrase && o.Params.Kind != seal.FactorFIDO2 {
			return nil, none, fmt.Errorf("%w: the other factor of a backend composite is a passphrase or a FIDO2 credential", ErrPolicyViolated)
		}
	}
	fid, err := backendFactorID(ref)
	if err != nil {
		return nil, none, err
	}
	id, err := seal.NewID()
	if err != nil {
		return nil, none, err
	}
	release, err := s.enter(ctx)
	if err != nil {
		return nil, none, err
	}
	t, err := s.currentTable(ctx)
	release()
	if err != nil {
		return nil, none, err
	}
	if s.viaRecoverySlot(t) {
		return nil, none, ErrSlotViaRecovery
	}
	if err := refuseRecoveryAsDaily(recoveryCredentials(t), others); err != nil {
		return nil, none, err
	}
	b, bound, err := t.binding()
	if err != nil {
		return nil, none, err
	}
	if !bound {
		return nil, none, fmt.Errorf("%w: no slot of this workspace binds a recovery public key yet (it was migrated from format 2); run a rekey first", ErrUseRekey)
	}
	cand := unlock.Slot{ID: id, Kind: unlock.SlotComposite, RecoveryPubKeyHash: b.RecoveryPubKeyHash,
		Factors: []unlock.Factor{{Kind: unlock.Backend, ID: fid}}}
	for _, o := range others {
		k := unlock.Passphrase
		if o.Params.Kind == seal.FactorFIDO2 {
			k = unlock.FIDO2
		}
		cand.Factors = append(cand.Factors, unlock.Factor{Kind: k, ID: o.Params.ID})
	}
	ut := unlock.Table{Policy: t.policy, Slots: []unlock.Slot{cand}}
	for _, ts := range t.slots {
		ut.Slots = append(ut.Slots, ts.toUnlock())
	}
	if err := unlock.Check(ut); err != nil {
		return nil, none, fmt.Errorf("%w: %w", ErrPolicyViolated, err)
	}
	return id, b, nil
}

// AddBackendSlot adds a composite slot of the backend factor kb and the
// caller's other factors (a new passphrase factor from NewPassphraseFactor, or
// a FIDO2 credential from EnrolFactor that is in no other slot). The table with
// the new slot is checked against the policy before the backend is asked:
// decision 6 refuses a backend alone, and under hardware and strict a backend
// without a FIDO2 factor. B is wrapped at the backend for this workspace and
// slot id and unwrapped once, and an unwrap under another slot id must be
// refused (a backend that ignores the context is not accepted); then the slot
// is written in one transaction with its audit row. Adding a slot needs no
// rotation (the master key is wrapped once more).
func (s *Store) AddBackendSlot(ctx context.Context, kb ports.KeyWrapBackend, others []FactorPlan) ([]byte, error) {
	if kb == nil {
		return nil, errors.New("sqlitestore: no backend")
	}
	ref := kb.Ref()
	for _, o := range others {
		// another kind is refused by the pre-check with its own reason
		known := o.Params.Kind == seal.FactorPassphrase || o.Params.Kind == seal.FactorFIDO2
		if known && (o.Output == nil || o.Output.Len() != seal.KeySize) {
			return nil, errors.New("sqlitestore: a factor has no output")
		}
	}
	// 1. the policy, on the table as it is now with the new slot, before the backend is asked
	id, b, err := s.checkBackendSlot(ctx, ref, others)
	if err != nil {
		return nil, err
	}
	fid, err := backendFactorID(ref)
	if err != nil {
		return nil, err
	}
	// 2. B, wrapped for this workspace and slot, and given back once
	sec, err := seal.NewMasterKey() // 32 random bytes in guarded memory
	if err != nil {
		return nil, err
	}
	defer sec.Destroy()
	wc := ports.WrapContext{GenesisNonce: s.ws, SlotID: id}
	blob, err := kb.Wrap(ctx, sec, wc)
	if err != nil {
		return nil, backendErr(ref, err)
	}
	if len(blob) == 0 || len(blob) > ports.MaxWrappedBlob {
		return nil, backendErr(ref, fmt.Errorf("%w: a wrapped secret of %d bytes", ports.ErrBackendResponse, len(blob)))
	}
	back, err := kb.Unwrap(ctx, blob, wc)
	if err != nil {
		return nil, backendErr(ref, err)
	}
	same := false
	_ = back.Use(func(x []byte) error {
		return sec.Use(func(y []byte) error { same = len(x) == len(y) && subtle.ConstantTimeCompare(x, y) == 1; return nil })
	})
	back.Destroy()
	if !same {
		return nil, backendErr(ref, fmt.Errorf("%w: the backend did not give back the secret it wrapped", ports.ErrBackendResponse))
	}
	// the binding is made: an unwrap under another slot id must be refused. A
	// server that ignores the associated data (a Vault without associated_data
	// support that does not warn, a proxy that drops it) gives B back here, and
	// a slot on it would not be bound to its slot and workspace at the backend.
	other, err := seal.NewID()
	if err != nil {
		return nil, err
	}
	stray, err := kb.Unwrap(ctx, blob, ports.WrapContext{GenesisNonce: s.ws, SlotID: other})
	switch {
	case err == nil:
		stray.Destroy()
		return nil, backendErr(ref, fmt.Errorf("%w: the backend unwrapped the secret under another slot id, so it ignores the associated data (the wrap context); a Vault must be recent enough to support associated_data on Transit", ports.ErrBackendConfig))
	case !errors.Is(err, ports.ErrBackendRefused):
		return nil, backendErr(ref, fmt.Errorf("the check that the backend binds the wrap context failed: %w", err))
	}
	// 3. the slot
	params := seal.FactorParams{Kind: seal.FactorBackend, ID: fid, BackendKind: string(ref.Kind), BackendAddress: ref.Address,
		BackendNamespace: ref.Namespace, BackendKeyRef: ref.Key, BackendBlob: bytes.Clone(blob)}
	release, err := s.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	ts, err := buildFactorSlotID(s.ws, id, s.master, seal.SlotComposite, append(append([]FactorPlan(nil), others...), FactorPlan{Params: params, Output: sec}),
		unlock.Policy(b.Policy), b.RecoveryPubKeyHash, nil)
	if err != nil {
		return nil, err
	}
	return id, s.addSlot(ctx, ts, "slot-added")
}
