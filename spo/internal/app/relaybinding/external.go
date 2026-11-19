package relaybinding

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relaywallet"
)

// Print and import for an external wallet (ADR 0014 decision 3, "Any other
// wallet"; use-case half of `spo party relay bind --print` and `--import`, whose
// command flags are work package 8). The use case prints what a CIP-30 or CIP-8
// wallet must be given, and later verifies what it returns, against the prepared
// request, with the same relaybind verifiers the relay uses. It signs nothing and
// stores nothing: the caller keeps the Prepared value (it is plain data) between
// the two commands.

// PreparedLifetime is how long a prepared request can be imported: ten minutes on
// the injected clock. It is bounded so that an old printout cannot be matched to a
// wallet answer long afterwards.
const PreparedLifetime = 10 * time.Minute

const preparedLabel = "spo/relay-prepared/v1"

var (
	// ErrPrepared means the prepared request is not one PrepareBinding or
	// PrepareRevoke made, or was changed: its binding hash does not match its
	// content, its payload is not the rendering of its statement, or its times are
	// not a ten-minute window.
	ErrPrepared = errors.New("relaybinding: the prepared request is not one this tool made, or it was changed")
	// ErrPreparedExpired means the clock is past the prepared request's expiry:
	// prepare it again (the wallet is asked once more).
	ErrPreparedExpired = errors.New("relaybinding: the prepared request has expired: prepare it again")
	// ErrImport means the wallet's answer does not verify as the prepared request
	// signed by the prepared key; the reason from relaybind or the comparison is
	// wrapped.
	ErrImport = errors.New("relaybinding: the wallet's answer is not the prepared request signed by the prepared key")
)

// PreparedKind says what a prepared request is.
type PreparedKind uint8

const (
	// PreparedBindingKind is a binding.
	PreparedBindingKind PreparedKind = 1
	// PreparedRevokeKind is a wallet-signed revoke.
	PreparedRevokeKind PreparedKind = 2
)

// ExternalWallet names the wallet key of an external wallet: by its key hash, or
// by an address in one of the exact forms relaybind accepts (enterprise, base with
// K as payment part, reward). Exactly one is given.
type ExternalWallet struct {
	KeyHash relaybind.KeyHash
	Address []byte
}

// Prepared is a request for an external wallet to sign. SignFor is the address,
// as bytes, to hand to the wallet's signData (the address given, or the bare key
// hash when only a key hash was given); Payload is the exact message, which must
// be signed as it is, not hashed (Hashed is false). ID binds every other field, so
// an import cannot be matched to a different prepared request.
type Prepared struct {
	Kind       PreparedKind
	WalletKey  relaybind.KeyHash
	SignFor    []byte
	Payload    []byte
	Binding    relaybind.Binding // set for a binding
	Revoke     relaybind.Revoke  // set for a revoke
	PreparedAt int64
	ExpiresAt  int64
	ID         [32]byte
}

// PayloadText is the exact payload as text: one line of ASCII, to sign as it is.
func (p Prepared) PayloadText() string { return string(p.Payload) }

// PayloadHex is the payload as hex, for a wallet that takes hex.
func (p Prepared) PayloadHex() string { return hex.EncodeToString(p.Payload) }

// SignForHex is the address to sign for, as hex.
func (p Prepared) SignForHex() string { return hex.EncodeToString(p.SignFor) }

// Hashed is always false: the wallet must sign the payload itself, not its hash
// (the relay and the device need to see the text).
func (Prepared) Hashed() bool { return false }

// Instructions is the plain text for the operator and the wallet.
func (p Prepared) Instructions() string {
	what := "binding"
	if p.Kind == PreparedRevokeKind {
		what = "revoke"
	}
	return fmt.Sprintf("Sign this relay %s with the wallet key %x.\n"+
		"CIP-30 signData: address (hex) %s, payload (hex) %s.\n"+
		"The payload is the text: %s\n"+
		"Do not hash the payload. Give back the COSE_Sign1 and the COSE_Key (hex) within %d minutes.\n",
		what, p.WalletKey[:], p.SignForHex(), p.PayloadHex(), p.PayloadText(), int(PreparedLifetime/time.Minute))
}

// preparedID is the binding hash of a prepared request: Blake2b-256 of the
// canonical array [label, kind, K, address to sign for, payload, prepared at,
// expires at]. It does not include the ID itself.
func preparedID(p Prepared) ([32]byte, error) {
	if p.PreparedAt < 0 || p.ExpiresAt < 0 {
		return [32]byte{}, ErrPrepared
	}
	b, err := identity.EncodeCanonical([]any{preparedLabel, uint64(p.Kind), p.WalletKey[:], p.SignFor, p.Payload, uint64(p.PreparedAt), uint64(p.ExpiresAt)})
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrPrepared, err)
	}
	return cose.Blake2b256(b), nil
}

// resolveWallet reads K and the address to sign for.
func resolveWallet(w ExternalWallet) (relaybind.KeyHash, []byte, error) {
	switch {
	case len(w.Address) != 0 && w.KeyHash != (relaybind.KeyHash{}):
		return relaybind.KeyHash{}, nil, fmt.Errorf("%w: give a key hash or an address, not both", ErrPolicy)
	case len(w.Address) != 0:
		k, _, err := relaybind.KeyOfAddress(w.Address)
		if err != nil {
			return relaybind.KeyHash{}, nil, fmt.Errorf("%w: the address is not a form a relay statement accepts: %w", ErrPolicy, err)
		}
		return k, bytes.Clone(w.Address), nil
	case w.KeyHash != (relaybind.KeyHash{}):
		return w.KeyHash, bytes.Clone(w.KeyHash[:]), nil
	}
	return relaybind.KeyHash{}, nil, fmt.Errorf("%w: no wallet key hash or address", ErrPolicy)
}

// checkExternalKey applies the role-history rule to K when the key is known to
// this store: a history with any role outside payment and stake is refused
// (default-deny), a history that cannot be read is refused, and a key the store
// has no history of is allowed, because it lives in the external wallet. It says
// whether the store knew the key. With no history source the answer is refusal
// (ErrNoHistory), as for the vault path.
func (s Service) checkExternalKey(ctx context.Context, k relaybind.KeyHash) (known bool, err error) {
	if s.History == nil {
		return false, ErrNoHistory
	}
	id, err := identity.NewRef(identity.KindKeyHash, k[:])
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrPolicy, err)
	}
	h, known, herr := s.History(ctx, id)
	wk, err := relaywallet.FromRef(custody.KeyRef{Role: custody.RolePayment, Identity: id})
	if err != nil {
		return false, err
	}
	return known, wk.CheckHistoryAllowingUnknown(h, known, herr)
}

// CheckExternalKey is the role-history rule of an external wallet's key, as the
// print and import paths apply it: refused when known with a role outside
// payment and stake or unreadable; allowed when unknown, and known says which.
//
// spec: SPO-Xrelaybind-IF-004
func (s Service) CheckExternalKey(ctx context.Context, k relaybind.KeyHash) (known bool, err error) {
	return s.checkExternalKey(ctx, k)
}

// PrepareBinding builds the binding of an external wallet's key to the device and
// returns what the wallet must be given (SPO-Xrelaybind-IF-004). The planning is
// SignBinding's: the zero device, the lifetime, the tombstone, the clock and the
// wait rule are refused or answered before anything is printed. A key the store
// knows and that was ever in a role outside payment and stake is refused here
// too; a key the store does not know is allowed.
//
// spec: SPO-Xrelaybind-IF-004, SPO-Xrelaybind-PRE-018
func (s Service) PrepareBinding(ctx context.Context, w ExternalWallet, device party.Fingerprint, lifetime time.Duration, lastNotBefore int64) (Prepared, error) {
	pol, err := s.policy()
	if err != nil {
		return Prepared{}, err
	}
	k, signFor, err := resolveWallet(w)
	if err != nil {
		return Prepared{}, err
	}
	if _, err := s.checkExternalKey(ctx, k); err != nil {
		return Prepared{}, err
	}
	want, payload, now, err := s.planBinding(pol, device, lifetime, lastNotBefore)
	if err != nil {
		return Prepared{}, err
	}
	return finishPrepared(Prepared{Kind: PreparedBindingKind, WalletKey: k, SignFor: signFor, Payload: payload, Binding: want, PreparedAt: now})
}

// PrepareRevoke builds the wallet-signed revoke of one device or of all the
// devices of an external wallet's key, as PrepareBinding does for a binding.
//
// spec: SPO-Xrelaybind-IF-004
func (s Service) PrepareRevoke(ctx context.Context, w ExternalWallet, target RevokeTarget, notBefore int64) (Prepared, error) {
	pol, err := s.policy()
	if err != nil {
		return Prepared{}, err
	}
	k, signFor, err := resolveWallet(w)
	if err != nil {
		return Prepared{}, err
	}
	if _, err := s.checkExternalKey(ctx, k); err != nil {
		return Prepared{}, err
	}
	if !target.All && target.Device == (party.Fingerprint{}) {
		return Prepared{}, fmt.Errorf("%w: the zero fingerprint is no device (a revoke of every device says All)", ErrPolicy)
	}
	now, err := s.now()
	if err != nil {
		return Prepared{}, err
	}
	want := relaybind.Revoke{All: target.All, Device: target.Device, NotBefore: notBefore}
	payload, err := want.Render()
	if err != nil {
		return Prepared{}, fmt.Errorf("%w: %w", ErrPolicy, err)
	}
	if notBefore-pol.Skew > now {
		return Prepared{}, fmt.Errorf("%w: %w: not-before %d, the clock says %d", ErrPolicy, relaybind.ErrRevokeFuture, notBefore, now)
	}
	return finishPrepared(Prepared{Kind: PreparedRevokeKind, WalletKey: k, SignFor: signFor, Payload: payload, Revoke: want, PreparedAt: now})
}

func finishPrepared(p Prepared) (Prepared, error) {
	p.ExpiresAt = p.PreparedAt + int64(PreparedLifetime/time.Second)
	id, err := preparedID(p)
	if err != nil {
		return Prepared{}, err
	}
	p.ID = id
	return p, nil
}

// checkPrepared is what an import trusts before it looks at the wallet's answer:
// the binding hash matches the content, the payload is the rendering of the
// statement, the window is exactly the ten minutes, and the clock is inside it.
func checkPrepared(p Prepared, kind PreparedKind, now int64) error {
	if p.Kind != kind {
		return fmt.Errorf("%w: it is not a %s request", ErrPrepared, map[PreparedKind]string{PreparedBindingKind: "binding", PreparedRevokeKind: "revoke"}[kind])
	}
	id, err := preparedID(p)
	if err != nil || id != p.ID {
		return ErrPrepared
	}
	var payload []byte
	if kind == PreparedBindingKind {
		payload, err = p.Binding.Render()
	} else {
		payload, err = p.Revoke.Render()
	}
	if err != nil || !bytes.Equal(payload, p.Payload) {
		return fmt.Errorf("%w: the payload is not the rendering of the statement", ErrPrepared)
	}
	if p.ExpiresAt-p.PreparedAt != int64(PreparedLifetime/time.Second) {
		return fmt.Errorf("%w: the window is not %s", ErrPrepared, PreparedLifetime)
	}
	if now < p.PreparedAt {
		return fmt.Errorf("%w: it was prepared in the future of the clock", ErrPrepared)
	}
	if now > p.ExpiresAt {
		return ErrPreparedExpired
	}
	return nil
}

// ImportedBinding is a binding that an external wallet signed and that verified
// against the prepared request. AddressPart says which form of the address the
// wallet wrote (the relaxed forms of relaybind); KnownToStore is false when this
// store has no record of the key, which is allowed here because the key lives in
// the wallet.
type ImportedBinding struct {
	BindingResult
	AddressPart  relaybind.AddressPart
	KnownToStore bool
}

// ImportedRevoke is the same for a wallet-signed revoke.
type ImportedRevoke struct {
	RevokeResult
	AddressPart  relaybind.AddressPart
	KnownToStore bool
}

// ImportBinding verifies the COSE_Sign1 and COSE_Key an external wallet returned
// against the prepared request (SPO-Xrelaybind-IF-004, SEC-023): the prepared
// request is intact and has not expired on the clock; the bytes parse strictly and
// verify with relaybind.VerifyBinding for the prepared device and the clock
// (window, signature, canonical payload, key and address forms); the payload is
// byte-equal to the rendered request; the binding, and the key hash, are the
// prepared ones; the bytes are the canonical encoding; and the role history of K,
// if the store knows the key, has no role outside payment and stake. The address
// in the header may be any form relaybind accepts (the wallet signs for its own
// address), not only the bare key hash a vault writes; AddressPart reports it.
//
// spec: SPO-Xrelaybind-IF-004, SPO-Xrelaybind-SEC-023
func (s Service) ImportBinding(ctx context.Context, p Prepared, sign1, coseKey []byte) (ImportedBinding, error) {
	pol, err := s.policy()
	if err != nil {
		return ImportedBinding{}, err
	}
	now, err := s.now()
	if err != nil {
		return ImportedBinding{}, err
	}
	if err := checkPrepared(p, PreparedBindingKind, now); err != nil {
		return ImportedBinding{}, err
	}
	st, vkey, err := parseImport(sign1, coseKey)
	if err != nil {
		return ImportedBinding{}, err
	}
	vb, err := relaybind.VerifyBinding(st, vkey, p.Binding.Device, now, pol)
	if err != nil {
		return ImportedBinding{}, fmt.Errorf("%w: %w", ErrImport, err)
	}
	if err := sameImport(st, sign1, p, vb.Key(), p.Payload); err != nil {
		return ImportedBinding{}, err
	}
	if vb.Binding() != p.Binding {
		return ImportedBinding{}, fmt.Errorf("%w: the binding is %+v, not the prepared one", ErrImport, vb.Binding())
	}
	known, err := s.checkExternalKey(ctx, vb.Key())
	if err != nil {
		return ImportedBinding{}, err
	}
	return ImportedBinding{
		BindingResult: BindingResult{
			Statement: bytes.Clone(sign1), COSEKey: bytes.Clone(coseKey), WalletKey: vb.Key(),
			Binding: vb.Binding(), StatementID: vb.StatementID(), FullHash: vb.FullHash(),
		},
		AddressPart:  vb.AddressPart(),
		KnownToStore: known,
	}, nil
}

// ImportRevoke is ImportBinding for a wallet-signed revoke, verified with
// relaybind.VerifyRevoke.
//
// spec: SPO-Xrelaybind-IF-004, SPO-Xrelaybind-SEC-023
func (s Service) ImportRevoke(ctx context.Context, p Prepared, sign1, coseKey []byte) (ImportedRevoke, error) {
	pol, err := s.policy()
	if err != nil {
		return ImportedRevoke{}, err
	}
	now, err := s.now()
	if err != nil {
		return ImportedRevoke{}, err
	}
	if err := checkPrepared(p, PreparedRevokeKind, now); err != nil {
		return ImportedRevoke{}, err
	}
	st, vkey, err := parseImport(sign1, coseKey)
	if err != nil {
		return ImportedRevoke{}, err
	}
	vr, err := relaybind.VerifyRevoke(st, vkey, now, pol)
	if err != nil {
		return ImportedRevoke{}, fmt.Errorf("%w: %w", ErrImport, err)
	}
	if err := sameImport(st, sign1, p, vr.Key(), p.Payload); err != nil {
		return ImportedRevoke{}, err
	}
	if vr.Revoke() != p.Revoke {
		return ImportedRevoke{}, fmt.Errorf("%w: the revoke is %+v, not the prepared one", ErrImport, vr.Revoke())
	}
	known, err := s.checkExternalKey(ctx, vr.Key())
	if err != nil {
		return ImportedRevoke{}, err
	}
	return ImportedRevoke{
		RevokeResult: RevokeResult{
			Statement: bytes.Clone(sign1), COSEKey: bytes.Clone(coseKey), WalletKey: vr.Key(),
			Revoke: vr.Revoke(), StatementID: vr.StatementID(), FullHash: vr.FullHash(),
		},
		AddressPart:  vr.AddressPart(),
		KnownToStore: known,
	}, nil
}

// parseImport reads the wallet's answer with the strict parsers.
func parseImport(sign1, coseKey []byte) (relaybind.Statement, [32]byte, error) {
	st, err := relaybind.ParseStatement(sign1)
	if err != nil {
		return relaybind.Statement{}, [32]byte{}, fmt.Errorf("%w: %w", ErrImport, err)
	}
	vkey, err := relaybind.ParseCOSEKey(coseKey)
	if err != nil {
		return relaybind.Statement{}, [32]byte{}, fmt.Errorf("%w: %w", ErrImport, err)
	}
	return st, vkey, nil
}

// sameImport is what the verifiers do not say: the signer is the prepared wallet
// key, the payload is the prepared one byte for byte, and the bytes are canonical.
func sameImport(st relaybind.Statement, sign1 []byte, p Prepared, signedBy relaybind.KeyHash, payload []byte) error {
	switch {
	case signedBy != p.WalletKey:
		return fmt.Errorf("%w: signed by the key %x, not the prepared key %x", ErrImport, signedBy[:], p.WalletKey[:])
	case !bytes.Equal(st.Payload(), payload):
		return fmt.Errorf("%w: the payload is not the prepared one", ErrImport)
	case !bytes.Equal(st.Canonical(), sign1):
		return fmt.Errorf("%w: the statement is not in the canonical encoding", ErrImport)
	}
	return nil
}
