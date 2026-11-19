// Package relaybinding is the use case that signs the statements of ADR 0014
// with a wallet key or with the device key: the relay binding, the
// wallet-signed revoke and the device-signed revoke (work package 3, software
// keys; the hardware path is work package 4 and answers
// ports.ErrRelayStatementUnsupported).
//
// Nothing here stores anything and nothing sleeps. A caller that goes on to use
// the results must persist, per relay and device, the binding it holds (the
// statement bytes and the COSE key), its pending revokes (kept until the revoked
// binding's `until`, ADR 0014 decision 8) and the latest tombstone not-before it
// holds for the device (the `lastNotBefore` of SignBinding).
//
// What a signer returns is never trusted. Every result is parsed with
// relaybind.ParseStatement and verified with relaybind.VerifyBinding or
// VerifyRevoke (the device-signed revoke with VerifyDeviceRevoke), and then
// compared with the statement that was asked for; a signer that returns
// anything else is an error and nothing is returned (SPO-Xrelaybind-SEC-014 and
// SEC-015).
package relaybinding

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relaywallet"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// The refusals of the use case. A key whose role is refused is
// relaywallet.ErrRole, one with a cold history relaywallet.ErrColdHistory and an
// unreadable history relaywallet.ErrHistoryUnreadable (the signer's own failure
// keeps its error beside ErrSigner).
var (
	// ErrPolicy means the request is outside what the relay would accept: a
	// lifetime out of bounds, a not-before in the future or out of range, a
	// tombstone out of range, or a Policy looser than the ADR's. Nothing was
	// asked of the signer.
	ErrPolicy = errors.New("relaybinding: the request is outside the policy")
	// ErrWait means the client must wait before it can sign a binding that the
	// relay will accept (see WaitError). Nothing was asked of the signer.
	ErrWait = errors.New("relaybinding: wait before signing the binding")
	// ErrClock means the clock is outside the range statements can carry, 0 to
	// relaybind.MaxTime, or leaves no room for a binding.
	ErrClock = errors.New("relaybinding: the clock is outside the range of a statement")
	// ErrSigner means the signer failed; the error it returned is wrapped.
	ErrSigner = errors.New("relaybinding: the signer failed")
	// ErrSelfVerify means the signer returned something that is not exactly the
	// statement asked for, signed by the wallet key; it is not returned.
	ErrSelfVerify = errors.New("relaybinding: the signer's output is not the statement asked for")
	// ErrNoHistory means the use case was built without a source of role
	// histories. The cold-key rule fails closed, so it signs nothing.
	ErrNoHistory = errors.New("relaybinding: no role history source: the cold-key rule cannot be checked")
)

// WaitError is the answer when from = last not-before + 1 is beyond what a relay
// accepts yet (ADR 0014 decision 3, `PlanFrom`). Wait is how long to wait on the
// same clock before asking again; From is the from the binding will have then.
// The use case does not sleep and does not ask the wallet to sign.
type WaitError struct {
	Wait time.Duration
	From int64
}

func (e *WaitError) Error() string {
	return fmt.Sprintf("relaybinding: wait %s before binding: the latest revoke of this device is dated %d, and a relay accepts a binding only %d seconds before its from", e.Wait, e.From-1, relaybind.SkewSeconds)
}

// waitDuration is sec seconds as a Duration, clamped: negative is 0 and more than
// a Duration holds is the largest Duration, never a wrapped (negative) value.
func waitDuration(sec int64) time.Duration {
	const most = math.MaxInt64 / int64(time.Second)
	switch {
	case sec <= 0:
		return 0
	case sec > most:
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(sec) * time.Second
}

// Is makes errors.Is(err, ErrWait) true.
func (e *WaitError) Is(target error) bool { return target == ErrWait }

// Service signs the statements. All fields but Policy are required.
type Service struct {
	// Signer signs the two wallet-signed statements: the vault signer, or a
	// hardware signer that says it cannot.
	Signer ports.RelayStatementSigner
	// Clock is the client's clock, read once per call.
	Clock ports.Clock
	// History is the role history of a key identity (ports.RoleHistoryOf over
	// the workspace's key index). It is required: with none the use case signs
	// nothing.
	History func(ctx context.Context, id identity.Ref) (custody.RoleHistory, bool, error)
	// Policy is what the client assumes of the relay: the skew it allows and the
	// longest lifetime it accepts. The zero value is relaybind.DefaultPolicy().
	Policy relaybind.Policy
	// allowUnknownHistory lets a key with NO known role history pass the history
	// check (a known history is always checked in full). It is reserved for
	// device-only keys in work package 4, whose safety rests on the derivation-path
	// check, and nothing sets it today. The default is to refuse
	// (relaywallet.ErrNoHistory): a key the workspace has no record of cannot be
	// shown never to have been a cold key. It is unexported so that no literal
	// and no assignment of another package can set it; AllowingUnknownHistory is
	// the one way, and an architecture test refuses a production call of it.
	allowUnknownHistory bool
}

// AllowingUnknownHistory is s with the pass-through for a key of no known role
// history. Reserved for device-only hardware keys (work package 4); no
// production code calls it (SPO-Xmailbox-SEC-074).
func (s Service) AllowingUnknownHistory() Service {
	s.allowUnknownHistory = true
	return s
}

// DefaultLifetime is the lifetime of a binding when none is asked for: 90 days
// (ADR 0014 decision 3), or the policy's maximum when that is shorter.
const DefaultLifetime = time.Duration(relaybind.DefaultLifetimeSeconds) * time.Second

// BindingResult is a binding that verified. Statement and COSEKey travel to the
// relay together; WalletKey is K, the only name of the signer to show or log.
type BindingResult struct {
	Statement   []byte
	COSEKey     []byte
	WalletKey   relaybind.KeyHash
	Binding     relaybind.Binding
	StatementID [32]byte
	FullHash    [32]byte
}

// RevokeTarget is what a wallet-signed revoke names: one device, or all.
type RevokeTarget struct {
	All    bool
	Device party.Fingerprint
}

// RevokeResult is a wallet-signed revoke that verified.
type RevokeResult struct {
	Statement   []byte
	COSEKey     []byte
	WalletKey   relaybind.KeyHash
	Revoke      relaybind.Revoke
	StatementID [32]byte
	FullHash    [32]byte
}

// DeviceRevokeResult is a device-signed revoke that verified: what the Revoke
// frame carries (ADR 0014 decision 7).
type DeviceRevokeResult struct {
	Device    party.Fingerprint
	NotBefore int64
	Ed25519   party.Ed25519Public
	X25519    party.X25519Public
	Signature [64]byte
}

func (s Service) policy() (relaybind.Policy, error) {
	p := s.Policy
	if p == (relaybind.Policy{}) {
		p = relaybind.DefaultPolicy()
	}
	if err := p.Validate(); err != nil {
		return p, fmt.Errorf("%w: %w", ErrPolicy, err)
	}
	return p, nil
}

// now reads the clock once and refuses a time statements cannot carry.
func (s Service) now() (int64, error) {
	if s.Clock == nil {
		return 0, errors.New("relaybinding: no clock")
	}
	n := s.Clock.Now().Unix()
	if n < 0 || n > relaybind.MaxTime {
		return 0, fmt.Errorf("%w: unix time %d is not 0 to %d", ErrClock, n, relaybind.MaxTime)
	}
	return n, nil
}

// checkKey applies the role and history rules to a wallet key.
func (s Service) checkKey(ctx context.Context, key relaywallet.WalletKey) error {
	if key.IsZero() {
		return fmt.Errorf("%w: no key", relaywallet.ErrRole)
	}
	if s.History == nil {
		return ErrNoHistory
	}
	h, known, err := s.History(ctx, key.Ref().Identity)
	if s.allowUnknownHistory {
		return key.CheckHistoryAllowingUnknown(h, known, err)
	}
	return key.CheckHistory(h, known, err)
}

// lifetimeSeconds resolves the lifetime asked for: zero is the default (90
// days, or the policy's maximum when shorter); a negative one, a fraction of a
// second, and one outside one hour to the policy's maximum are refused.
func lifetimeSeconds(lifetime time.Duration, pol relaybind.Policy) (int64, error) {
	if lifetime == 0 {
		return min(relaybind.DefaultLifetimeSeconds, pol.MaxLifetime), nil
	}
	if lifetime < 0 || lifetime%time.Second != 0 {
		return 0, fmt.Errorf("%w: the lifetime %s is not a whole positive number of seconds", ErrPolicy, lifetime)
	}
	sec := int64(lifetime / time.Second)
	switch {
	case sec < relaybind.MinLifetimeSeconds || sec > relaybind.MaxLifetimeSeconds:
		return 0, fmt.Errorf("%w: %w: %s, want %d to %d seconds", ErrPolicy, relaybind.ErrLifetime, lifetime, relaybind.MinLifetimeSeconds, relaybind.MaxLifetimeSeconds)
	case sec > pol.MaxLifetime:
		return 0, fmt.Errorf("%w: %w: %w: %s, the relay's maximum is %d seconds", ErrPolicy, relaybind.ErrLifetimePolicy, relaybind.ErrLifetime, lifetime, pol.MaxLifetime)
	}
	return sec, nil
}

// planBinding is everything a binding needs before anyone signs it, shared by
// SignBinding and PrepareBinding: the device is a device, the lifetime and the
// tombstone are within the policy, the clock is in range, a tombstone is not
// further ahead than skew + 1 s, and the wait rule; it returns the binding and its
// rendered payload and the time of the clock.
func (s Service) planBinding(pol relaybind.Policy, device party.Fingerprint, lifetime time.Duration, lastNotBefore int64) (relaybind.Binding, []byte, int64, error) {
	if device == (party.Fingerprint{}) {
		return relaybind.Binding{}, nil, 0, fmt.Errorf("%w: the zero fingerprint is no device", ErrPolicy)
	}
	life, err := lifetimeSeconds(lifetime, pol)
	if err != nil {
		return relaybind.Binding{}, nil, 0, err
	}
	if lastNotBefore < relaybind.NoTombstone || lastNotBefore > relaybind.MaxTime {
		return relaybind.Binding{}, nil, 0, fmt.Errorf("%w: the tombstone time %d is not %d to %d", ErrPolicy, lastNotBefore, relaybind.NoTombstone, relaybind.MaxTime)
	}
	now, err := s.now()
	if err != nil {
		return relaybind.Binding{}, nil, 0, err
	}
	// A revoke's not-before is at most relay time plus the skew, so a tombstone
	// further ahead than skew + 1 s cannot be genuine; waiting for it would be
	// waiting for a forged or corrupt time (and the wait could overflow a Duration).
	if lastNotBefore-pol.Skew-1 > now {
		return relaybind.Binding{}, nil, 0, fmt.Errorf("%w: the tombstone time %d is more than the skew and one second ahead of the clock (%d)", ErrPolicy, lastNotBefore, now)
	}
	from, wait, err := relaybind.PlanFrom(now, lastNotBefore, pol.Skew)
	if err != nil {
		return relaybind.Binding{}, nil, 0, fmt.Errorf("%w: %w", ErrClock, err)
	}
	if wait > 0 {
		return relaybind.Binding{}, nil, 0, &WaitError{Wait: waitDuration(wait), From: from}
	}
	want := relaybind.Binding{Device: device, From: from, Until: from + life}
	payload, err := want.Render()
	if err != nil {
		// from + the lifetime is beyond the largest time: the clock is too close to its end
		return relaybind.Binding{}, nil, 0, fmt.Errorf("%w: %w", ErrClock, err)
	}
	return want, payload, now, nil
}

// SignBinding builds the binding of the wallet key to the device and has it
// signed.
//
// from is relaybind.PlanFrom(now, lastNotBefore, skew): max(now - 60 s, last
// not-before + 1 s). lastNotBefore is the latest tombstone time the client holds
// for the device, relaybind.NoTombstone (-1) if none. When the relay would not
// accept that from yet, the answer is a *WaitError and nothing is signed. until
// is from plus the lifetime; a lifetime of 0 means 90 days. The role and the
// role history of the key are checked before the signer is asked. The result
// has been parsed and verified as the relay verifies it, at the time of the
// call, for this device.
//
// spec: SPO-Xrelaybind-IF-001, SPO-Xrelaybind-PRE-018, SPO-Xrelaybind-PRE-019, SPO-Xrelaybind-PRE-020, SPO-Xrelaybind-SEC-014
func (s Service) SignBinding(ctx context.Context, key relaywallet.WalletKey, device party.Fingerprint, lifetime time.Duration, lastNotBefore int64) (BindingResult, error) {
	pol, err := s.policy()
	if err != nil {
		return BindingResult{}, err
	}
	if s.Signer == nil {
		return BindingResult{}, errors.New("relaybinding: no signer")
	}
	if err := s.checkKey(ctx, key); err != nil {
		return BindingResult{}, err
	}
	want, payload, now, err := s.planBinding(pol, device, lifetime, lastNotBefore)
	if err != nil {
		return BindingResult{}, err
	}
	sm, err := s.Signer.SignRelayBinding(ctx, key, want)
	if err != nil {
		return BindingResult{}, fmt.Errorf("%w: %w", ErrSigner, err)
	}
	st, vkey, err := parse(sm)
	if err != nil {
		return BindingResult{}, err
	}
	vb, err := relaybind.VerifyBinding(st, vkey, device, now, pol)
	if err != nil {
		return BindingResult{}, selfVerifyf("%w", err)
	}
	if err := sameStatement(st, sm, key, vb.Key(), vb.AddressPart(), payload); err != nil {
		return BindingResult{}, err
	}
	if vb.Binding() != want {
		return BindingResult{}, selfVerifyf("the binding is %+v, not the one asked for", vb.Binding())
	}
	return BindingResult{
		Statement:   bytes.Clone(sm.Sign1),
		COSEKey:     bytes.Clone(sm.Key),
		WalletKey:   vb.Key(),
		Binding:     vb.Binding(),
		StatementID: vb.StatementID(),
		FullHash:    vb.FullHash(),
	}, nil
}

// SignWalletRevoke builds the wallet-signed revoke of one device or of all the
// devices of the key, with the not-before given, and has it signed. A
// not-before later than now plus the skew is refused (a relay refuses it too),
// before the signer is asked. The role and the role history are checked as for
// a binding.
//
// spec: SPO-Xrelaybind-IF-002, SPO-Xrelaybind-PRE-018, SPO-Xrelaybind-SEC-015
func (s Service) SignWalletRevoke(ctx context.Context, key relaywallet.WalletKey, target RevokeTarget, notBefore int64) (RevokeResult, error) {
	pol, err := s.policy()
	if err != nil {
		return RevokeResult{}, err
	}
	if s.Signer == nil {
		return RevokeResult{}, errors.New("relaybinding: no signer")
	}
	if err := s.checkKey(ctx, key); err != nil {
		return RevokeResult{}, err
	}
	now, err := s.now()
	if err != nil {
		return RevokeResult{}, err
	}
	if !target.All && target.Device == (party.Fingerprint{}) {
		return RevokeResult{}, fmt.Errorf("%w: the zero fingerprint is no device (a revoke of every device says All)", ErrPolicy)
	}
	want := relaybind.Revoke{All: target.All, Device: target.Device, NotBefore: notBefore}
	payload, err := want.Render()
	if err != nil {
		return RevokeResult{}, fmt.Errorf("%w: %w", ErrPolicy, err)
	}
	if notBefore-pol.Skew > now {
		return RevokeResult{}, fmt.Errorf("%w: %w: not-before %d, the clock says %d", ErrPolicy, relaybind.ErrRevokeFuture, notBefore, now)
	}
	sm, err := s.Signer.SignRelayRevoke(ctx, key, want)
	if err != nil {
		return RevokeResult{}, fmt.Errorf("%w: %w", ErrSigner, err)
	}
	st, vkey, err := parse(sm)
	if err != nil {
		return RevokeResult{}, err
	}
	vr, err := relaybind.VerifyRevoke(st, vkey, now, pol)
	if err != nil {
		return RevokeResult{}, selfVerifyf("%w", err)
	}
	if err := sameStatement(st, sm, key, vr.Key(), vr.AddressPart(), payload); err != nil {
		return RevokeResult{}, err
	}
	if vr.Revoke() != want {
		return RevokeResult{}, selfVerifyf("the revoke is %+v, not the one asked for", vr.Revoke())
	}
	return RevokeResult{
		Statement:   bytes.Clone(sm.Sign1),
		COSEKey:     bytes.Clone(sm.Key),
		WalletKey:   vr.Key(),
		Revoke:      vr.Revoke(),
		StatementID: vr.StatementID(),
		FullHash:    vr.FullHash(),
	}, nil
}

// SignDeviceRevoke has the local identity sign its own revoke through the typed
// method (it signs only the labelled array of its own fingerprint and the
// not-before) and verifies the signature as the relay does. The not-before
// follows the rules of a wallet-signed one.
//
// spec: SPO-Xrelaybind-IF-003, SPO-Xrelaybind-SEC-015
func (s Service) SignDeviceRevoke(_ context.Context, dev relayport.DeviceRevokeSigner, notBefore int64) (DeviceRevokeResult, error) {
	pol, err := s.policy()
	if err != nil {
		return DeviceRevokeResult{}, err
	}
	if dev == nil {
		return DeviceRevokeResult{}, errors.New("relaybinding: no device identity")
	}
	now, err := s.now()
	if err != nil {
		return DeviceRevokeResult{}, err
	}
	if notBefore < 0 || notBefore > relaybind.MaxTime {
		return DeviceRevokeResult{}, fmt.Errorf("%w: %w: not-before %d is not 0 to %d", ErrPolicy, relaybind.ErrRange, notBefore, relaybind.MaxTime)
	}
	if notBefore-pol.Skew > now {
		return DeviceRevokeResult{}, fmt.Errorf("%w: %w: not-before %d, the clock says %d", ErrPolicy, relaybind.ErrRevokeFuture, notBefore, now)
	}
	id := dev.Identity()
	// the signer has no clock: the bound is the one this use case just checked
	sig, err := dev.SignRelayDeviceRevoke(notBefore, now+pol.Skew)
	if err != nil {
		return DeviceRevokeResult{}, fmt.Errorf("%w: %w", ErrSigner, err)
	}
	verified, err := relaybind.VerifyDeviceRevoke(id.Ed25519, id.X25519, notBefore, sig, now, pol)
	if err != nil {
		return DeviceRevokeResult{}, selfVerifyf("%w", err)
	}
	got := verified.Device()
	if got != id.Fingerprint() {
		return DeviceRevokeResult{}, selfVerifyf("the revoked device is not this identity")
	}
	return DeviceRevokeResult{Device: got, NotBefore: notBefore, Ed25519: id.Ed25519, X25519: id.X25519, Signature: sig}, nil
}

// parse reads what a signer returned with the strict parsers.
func parse(sm ports.SignedMessage) (relaybind.Statement, [32]byte, error) {
	st, err := relaybind.ParseStatement(sm.Sign1)
	if err != nil {
		return relaybind.Statement{}, [32]byte{}, selfVerifyf("%w", err)
	}
	vkey, err := relaybind.ParseCOSEKey(sm.Key)
	if err != nil {
		return relaybind.Statement{}, [32]byte{}, selfVerifyf("%w", err)
	}
	return st, vkey, nil
}

// sameStatement is what VerifyBinding and VerifyRevoke do not say: that the
// signer is the wallet key that was asked for, that the address is the bare
// 28-byte key hash (the verifiers also accept an enterprise, reward or base
// address, which a signer for this path never writes), that the payload is the
// one rendered, and that the bytes are the canonical encoding.
func sameStatement(st relaybind.Statement, sm ports.SignedMessage, key relaywallet.WalletKey, signedBy relaybind.KeyHash, part relaybind.AddressPart, payload []byte) error {
	switch {
	case signedBy != key.KeyHash():
		return selfVerifyf("signed by the key %x, not the wallet key %x", signedBy[:], key.KeyHash())
	case part != relaybind.PartKeyHash || !bytes.Equal(st.Address(), signedBy[:]):
		return selfVerifyf("the protected-header address is not the bare 28-byte key hash")
	case !bytes.Equal(st.Protected(), cose.ProtectedHeader(signedBy[:])):
		return selfVerifyf("the protected header is not the bytes the software path writes")
	case !bytes.Equal(st.Payload(), payload):
		return selfVerifyf("the payload is not the one rendered")
	case !bytes.Equal(st.Canonical(), sm.Sign1):
		return selfVerifyf("the statement is not in the canonical encoding")
	}
	return nil
}

// selfVerifyf wraps ErrSelfVerify with the reason. A %w operand in the format is
// the original error, which stays reachable with errors.Is.
func selfVerifyf(format string, a ...any) error {
	return fmt.Errorf("%w: %w", ErrSelfVerify, fmt.Errorf(format, a...))
}
