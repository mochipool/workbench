// Package relayself is the lifecycle of this device's own relay identity (ADR
// 0014 decisions 3, 7 and 8, work package 8; spec Xmailbox "Wallet-key identity
// on the client side"): its binding (made with a software key, or printed for an
// external wallet and imported), its pending revokes (the mailbox client's
// RevokeBook, kept across restarts) and the latest revoke not-before per device
// (the lastNotBefore of the next binding). Everything is one record in the
// encrypted store (ports.RelayOwn).
//
// Signing goes through app/relaybinding only, which takes the closed wallet key
// (relaywallet) and checks the role history; this package never names a signer
// port. The sending of revokes is a port (Service.Send) that the relay wiring
// supplies.
package relayself

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/relaybinding"
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relaywallet"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

var ref = ports.NamedRef{Name: "self", Kind: ports.RelayOwn}

// RenewMargin is how close to its end a binding is shown as due for renewal
// (ADR 0014 decision 3: 14 days).
const RenewMargin = 14 * 24 * time.Hour

// Refusals.
var (
	// ErrOlder: the binding starts before the one held (the relay refuses it too).
	ErrOlder = errors.New("relayself: the binding starts before the one this device holds")
	// ErrNoPrepared: there is no prepared request of that kind to import into.
	ErrNoPrepared = errors.New("relayself: nothing was prepared for an external wallet: run the command with --print first")
	// ErrBookFull: the pending revokes are at their bound and none has ended.
	ErrBookFull = errors.New("relayself: the revokes waiting to be sent are at their bound and none has ended yet: " +
		"see them with spo party relay status, and drop one you no longer need with spo party relay drop-revoke ID, or wait for one to end")
	// ErrSelf: forget --lost named this device; use forget.
	ErrSelf = errors.New("relayself: that is this device: use spo party relay forget")
	// ErrNoSender: there is no relay to send the revoke to; it is stored and goes
	// with the next relay connection.
	ErrNoSender = errors.New("relayself: no relay is configured: the revoke is stored and is sent at the next relay connection")
	// ErrNoBinding: the device holds no binding.
	ErrNoBinding = errors.New("relayself: this device has no binding")
	// ErrPoolID: the wallet key is the id of a pool this workspace knows. A pool
	// id is the hash of a pool cold key, which never signs a relay statement.
	ErrPoolID = errors.New("relayself: the wallet key is the id of a pool this workspace knows (a pool id is the hash of its cold key): " +
		"a relay wallet key is a payment or stake key, never a pool cold key")
	// ErrNoPoolSource: the use case has no source of the workspace's pool ids, so
	// the cold-key rule cannot be checked and nothing is signed.
	ErrNoPoolSource = errors.New("relayself: no source of this workspace's pool ids: a wallet key cannot be checked against them")
	// ErrLostMismatch: the request prepared for --lost is not a revoke of exactly
	// that device.
	ErrLostMismatch = errors.New("relayself: the prepared request is not a revoke of that device alone: print it again with spo party relay forget --lost DEVICE --print")
	// ErrNoRevoke: no pending revoke has that id.
	ErrNoRevoke = errors.New("relayself: no pending revoke has that id (see spo party relay status)")
)

// Service is the use cases. Store, Clock, Device and Sign are required, and
// PoolIDs for every path that names a wallet key.
type Service struct {
	Store ports.NamedStore
	Clock ports.Clock
	// Device is this device's party fingerprint.
	Device party.Fingerprint
	// Sign makes and verifies the statements (relaybinding.Service with the
	// vault signer, the clock and the role-history source).
	Sign relaybinding.Service
	// PoolIDs is every pool id this workspace knows: its own pools (by their
	// pool id records or cold verification keys) and every pool named in the
	// scope of an enrolled party. A wallet key that is one of them is refused on
	// every path that names a wallet key (ErrPoolID). Nil refuses those paths.
	PoolIDs func(ctx context.Context) (map[[28]byte]bool, error)
	// DeviceRevoke signs this device's own revoke through the typed method of
	// the local identity (relaybinding.Service.SignDeviceRevoke over it); the
	// composition root supplies it.
	DeviceRevoke func(ctx context.Context, notBefore int64) (relaybinding.DeviceRevokeResult, error)
	// Send sends the book's pending revokes on a revoke-only connection to every
	// listed relay (a mailbox.RevokeSender each, needing no binding) and returns
	// each relay's own error (nil: the exchange ran; what the relay recorded is
	// told to the book with its name); nil when no relay is wired.
	Send func(ctx context.Context, book relayport.RevokeBook) (map[string]error, error)
}

// Load reads the state.
func (s Service) Load(ctx context.Context) (State, error) {
	var st State
	err := s.Store.View(ctx, func(r ports.NamedReader) error {
		var err error
		st, err = load(r, s.Device)
		return err
	})
	return st, err
}

func load(r ports.NamedReader, self party.Fingerprint) (State, error) {
	b, err := r.Get(ref)
	if errors.Is(err, ports.ErrNotFound) {
		return State{}, nil
	}
	if err != nil {
		return State{}, err
	}
	return Decode(b, self)
}

func save(w ports.NamedWriter, st State) error {
	b, err := Encode(st)
	if err != nil {
		return err
	}
	return w.Put(ref, b)
}

// update runs fn on the state inside one transaction and stores the result. A
// foreign binding read from the record is not written back.
func (s Service) update(ctx context.Context, fn func(st *State) error) error {
	return s.Store.Update(ctx, func(w ports.NamedWriter) error {
		st, err := load(w, s.Device)
		if err != nil {
			return err
		}
		if err := fn(&st); err != nil {
			return err
		}
		return save(w, st)
	})
}

func (s Service) lastNotBefore(st State) int64 {
	if nb, ok := st.NotBefore[s.Device]; ok {
		return nb
	}
	return relaybind.NoTombstone
}

// checkNotPool refuses a wallet key that is a pool id this workspace knows.
func (s Service) checkNotPool(ctx context.Context, k [28]byte) error {
	if s.PoolIDs == nil {
		return ErrNoPoolSource
	}
	ids, err := s.PoolIDs(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNoPoolSource, err)
	}
	if ids[k] {
		return fmt.Errorf("%w: %x", ErrPoolID, k[:])
	}
	return nil
}

// keyOfExternal is K of an external wallet: its key hash, or the key-hash
// credential of the address.
func keyOfExternal(w relaybinding.ExternalWallet) ([28]byte, error) {
	if len(w.Address) != 0 {
		k, _, err := relaybind.KeyOfAddress(w.Address)
		return k, err
	}
	return w.KeyHash, nil
}

// CheckExternal checks the key of an external wallet before anything is printed
// for it: it is no pool id this workspace knows, and its role history here, when
// there is one, holds only payment and stake. known reports that this workspace
// has a history of the key; for an unknown key the command asks the operator to
// confirm that it is a payment or stake key.
//
// spec: SPO-Xmailbox-IF-021
func (s Service) CheckExternal(ctx context.Context, w relaybinding.ExternalWallet) (known bool, err error) {
	k, err := keyOfExternal(w)
	if err != nil {
		return false, err
	}
	if err := s.checkNotPool(ctx, k); err != nil {
		return false, err
	}
	return s.Sign.CheckExternalKey(ctx, k)
}

// setBinding is the client's SetBinding rule (SPO-Xmailbox-PRE-059): the
// binding verifies for this device on the clock; one that starts before the
// one held is ErrOlder; the same statement again is no change.
func (s Service) setBinding(st *State, statement, key []byte) error {
	pol := s.Sign.Policy
	if pol == (relaybind.Policy{}) {
		pol = relaybind.DefaultPolicy()
	}
	sm, err := relaybind.ParseStatement(statement)
	if err != nil {
		return err
	}
	vkey, err := relaybind.ParseCOSEKey(key)
	if err != nil {
		return err
	}
	vb, err := relaybind.VerifyBinding(sm, vkey, s.Device, s.Clock.Now().Unix(), pol)
	if err != nil {
		return err
	}
	b := vb.Binding()
	if cur := st.Binding; cur != nil {
		if bytes.Equal(cur.Statement, statement) && bytes.Equal(cur.Key, key) {
			return nil
		}
		if b.From < cur.From {
			return fmt.Errorf("%w: it starts at %d, the one held at %d", ErrOlder, b.From, cur.From)
		}
	}
	st.Binding = &Binding{Statement: bytes.Clone(statement), Key: bytes.Clone(key), WalletKey: party.WalletKey(vb.Key()), Device: b.Device, From: b.From, Until: b.Until}
	return nil
}

// SetBinding stores a binding this device got from elsewhere (a renewal signed
// on another path), by the rule of SPO-Xmailbox-PRE-059.
//
// spec: SPO-Xmailbox-PRE-059
func (s Service) SetBinding(ctx context.Context, statement, key []byte) error {
	return s.update(ctx, func(st *State) error { return s.setBinding(st, statement, key) })
}

// Bind signs a binding of this device with a key of the vault and stores it.
// The plan is relaybinding's: a *relaybinding.WaitError when a revoke of this
// device is too recent; nothing is signed or stored then. A key that is a pool
// id this workspace knows is refused before anything is signed.
//
// spec: SPO-Xmailbox-IF-021, SPO-Xmailbox-PRE-059, SPO-Xmailbox-SEC-075
func (s Service) Bind(ctx context.Context, key relaywallet.WalletKey, lifetime time.Duration) (relaybinding.BindingResult, error) {
	if err := s.checkNotPool(ctx, key.KeyHash()); err != nil {
		return relaybinding.BindingResult{}, err
	}
	st, err := s.Load(ctx)
	if err != nil {
		return relaybinding.BindingResult{}, err
	}
	res, err := s.Sign.SignBinding(ctx, key, s.Device, lifetime, s.lastNotBefore(st))
	if err != nil {
		return relaybinding.BindingResult{}, err
	}
	return res, s.update(ctx, func(st *State) error { return s.setBinding(st, res.Statement, res.COSEKey) })
}

// PrintBinding prepares a binding of this device for an external wallet and
// stores the prepared request, replacing any earlier one. A key that is a pool
// id this workspace knows is refused before anything is printed.
//
// spec: SPO-Xmailbox-IF-021, SPO-Xmailbox-PRE-059, SPO-Xmailbox-SEC-075
func (s Service) PrintBinding(ctx context.Context, w relaybinding.ExternalWallet, lifetime time.Duration) (relaybinding.Prepared, error) {
	if _, err := s.CheckExternal(ctx, w); err != nil {
		return relaybinding.Prepared{}, err
	}
	st, err := s.Load(ctx)
	if err != nil {
		return relaybinding.Prepared{}, err
	}
	p, err := s.Sign.PrepareBinding(ctx, w, s.Device, lifetime, s.lastNotBefore(st))
	if err != nil {
		return relaybinding.Prepared{}, err
	}
	return p, s.update(ctx, func(st *State) error { st.Prepared = &p; return nil })
}

func (s Service) prepared(ctx context.Context, kind relaybinding.PreparedKind) (relaybinding.Prepared, error) {
	st, err := s.Load(ctx)
	if err != nil {
		return relaybinding.Prepared{}, err
	}
	if st.Prepared == nil || st.Prepared.Kind != kind {
		return relaybinding.Prepared{}, ErrNoPrepared
	}
	return *st.Prepared, nil
}

// ImportBinding verifies the external wallet's answer against the stored
// request (relaybinding.ImportBinding), stores the binding and clears the
// request.
//
// spec: SPO-Xmailbox-IF-021, SPO-Xmailbox-PRE-059, SPO-Xmailbox-SEC-075
func (s Service) ImportBinding(ctx context.Context, sign1, coseKey []byte) (relaybinding.ImportedBinding, error) {
	p, err := s.prepared(ctx, relaybinding.PreparedBindingKind)
	if err != nil {
		return relaybinding.ImportedBinding{}, err
	}
	got, err := s.Sign.ImportBinding(ctx, p, sign1, coseKey)
	if err != nil {
		return relaybinding.ImportedBinding{}, err
	}
	if err := s.checkNotPool(ctx, got.WalletKey); err != nil {
		return relaybinding.ImportedBinding{}, err
	}
	return got, s.update(ctx, func(st *State) error {
		if err := s.setBinding(st, got.Statement, got.COSEKey); err != nil {
			return err
		}
		st.Prepared = nil
		return nil
	})
}

// revokeUntil is how long a revoke is owed: for a revoke of this device alone,
// the end of its binding when it holds one; otherwise (another device, every
// device of a key, or this device without a binding) the longest a binding
// signed by the not-before can live, because another device's binding may end
// as late as that.
func revokeUntil(st State, onlyThisDevice bool, notBefore int64) int64 {
	if onlyThisDevice && st.Binding != nil {
		return max(st.Binding.Until, notBefore)
	}
	return min(notBefore+relaybind.MaxLifetimeSeconds, relaybind.MaxTime)
}

// addRevoke puts r in the book (SPO-Xmailbox-OUT-098): a revoke already pending
// is not added again; ended ones are dropped first, and so are pending revokes
// that r supersedes (the same scope at the relay, a not-before and an end no
// later than r's: r's tombstone covers everything theirs does, for at least as
// long). Over the bound is ErrBookFull: protected revokes (this device's
// forget, a lost device, a rotation) may use all MaxPendingRevokes places,
// others MaxPendingRevokes - ReservedRevokes.
func (s Service) addRevoke(st *State, r relayport.Revoke, protected bool) error {
	id := revokeID(r)
	nv, err := viewOf(r)
	if err != nil {
		return err
	}
	for _, p := range st.Revokes {
		if revokeID(p) == id {
			return nil
		}
	}
	now := s.Clock.Now().Unix()
	kept := make([]relayport.Revoke, 0, len(st.Revokes)+1)
	for _, p := range st.Revokes {
		if p.Until < now {
			continue
		}
		if pv, err := viewOf(p); err == nil && scopeOf(pv) == scopeOf(nv) && pv.NotBefore <= nv.NotBefore && p.Until <= r.Until {
			continue // superseded by r
		}
		kept = append(kept, p)
	}
	if len(kept) >= limitOf(protected) {
		return ErrBookFull
	}
	st.Revokes = append(kept, r)
	return nil
}

func limitOf(protected bool) int {
	if protected {
		return MaxPendingRevokes
	}
	return MaxPendingRevokes - ReservedRevokes
}

// raise sets the stored not-before of a device to nb if that is later (never
// lower). At the bound, the entry of the device whose not-before is the oldest
// goes, but never the entry of keep (this device): only this device's entry is
// read, as the lastNotBefore of its next binding.
func raise(st *State, dev party.Fingerprint, nb int64, keep party.Fingerprint) {
	if st.NotBefore == nil {
		st.NotBefore = map[party.Fingerprint]int64{}
	}
	if cur, ok := st.NotBefore[dev]; ok {
		st.NotBefore[dev] = max(cur, nb)
		return
	}
	if len(st.NotBefore) >= MaxNotBefores {
		var oldest party.Fingerprint
		first := true
		for d, v := range st.NotBefore {
			if d == keep {
				continue
			}
			if first || v < st.NotBefore[oldest] {
				oldest, first = d, false
			}
		}
		if first {
			return // only keep's entry is left: nothing else can go
		}
		delete(st.NotBefore, oldest)
	}
	st.NotBefore[dev] = nb
}

// AddRevoke stores a revoke that was signed elsewhere (it must verify) as
// pending, as an ordinary revoke.
//
// spec: SPO-Xmailbox-OUT-098
func (s Service) AddRevoke(ctx context.Context, r relayport.Revoke) error {
	if _, err := revokeOf(toJSON(r), relaybind.DefaultPolicy()); err != nil {
		return err
	}
	return s.update(ctx, func(st *State) error { return s.addRevoke(st, r, false) })
}

func toJSON(r relayport.Revoke) revokeJSON {
	if r.Kind == relayport.RevokeByDeviceKey {
		return revokeJSON{Kind: "device", Until: r.Until, Ed25519: hx(r.Keys.Ed25519[:]), X25519: hx(r.Keys.X25519[:]), NotBefore: r.NotBefore, Signature: hx(r.Signature[:])}
	}
	return revokeJSON{Kind: "wallet", Until: r.Until, Statement: hx(r.Sign1), COSEKey: hx(r.Key)}
}

// checkRoom refuses before anything is signed when the book has no place left
// for a revoke of that class. A revoke that would supersede pending ones may
// still find room when it is added; the check before signing does not count on
// that.
func (s Service) checkRoom(st State, protected bool) error {
	now := s.Clock.Now().Unix()
	n := 0
	for _, p := range st.Revokes {
		if p.Until >= now {
			n++
		}
	}
	if n >= limitOf(protected) {
		return ErrBookFull
	}
	return nil
}

// storeWalletRevoke files a verified wallet-signed revoke: pending, and the
// not-before of the device it names (or of this device, for all of the key
// this device is bound to) raised.
func (s Service) storeWalletRevoke(ctx context.Context, res relaybinding.RevokeResult, protected bool, also func(st *State)) (relayport.Revoke, error) {
	var out relayport.Revoke
	err := s.update(ctx, func(st *State) error {
		only := !res.Revoke.All && res.Revoke.Device == s.Device
		out = relayport.Revoke{Kind: relayport.RevokeByWalletKey, Until: revokeUntil(*st, only, res.Revoke.NotBefore), Sign1: res.Statement, Key: res.COSEKey}
		if err := s.addRevoke(st, out, protected); err != nil {
			return err
		}
		if !res.Revoke.All {
			raise(st, res.Revoke.Device, res.Revoke.NotBefore, s.Device)
		} else if st.Binding != nil && st.Binding.WalletKey == party.WalletKey(res.WalletKey) {
			raise(st, s.Device, res.Revoke.NotBefore, s.Device)
		}
		if also != nil {
			also(st)
		}
		return nil
	})
	return out, err
}

// RevokeWallet signs a wallet-signed revoke of one device or of all devices of
// the key, with not-before now, with a key of the vault, and stores it as
// pending (SPO-Xmailbox-OUT-098). A full book refuses before anything is signed.
//
// spec: SPO-Xmailbox-IF-021, SPO-Xmailbox-OUT-098, SPO-Xmailbox-SEC-075
func (s Service) RevokeWallet(ctx context.Context, key relaywallet.WalletKey, target relaybinding.RevokeTarget) (relayport.Revoke, error) {
	return s.revokeWallet(ctx, key, target, false)
}

func (s Service) revokeWallet(ctx context.Context, key relaywallet.WalletKey, target relaybinding.RevokeTarget, protected bool) (relayport.Revoke, error) {
	if err := s.checkNotPool(ctx, key.KeyHash()); err != nil {
		return relayport.Revoke{}, err
	}
	st, err := s.Load(ctx)
	if err != nil {
		return relayport.Revoke{}, err
	}
	if err := s.checkRoom(st, protected); err != nil {
		return relayport.Revoke{}, err
	}
	res, err := s.Sign.SignWalletRevoke(ctx, key, target, s.Clock.Now().Unix())
	if err != nil {
		return relayport.Revoke{}, err
	}
	return s.storeWalletRevoke(ctx, res, protected, nil)
}

// PrintRevoke prepares a wallet-signed revoke for an external wallet and stores
// the request.
//
// spec: SPO-Xmailbox-IF-021, SPO-Xmailbox-SEC-075
func (s Service) PrintRevoke(ctx context.Context, w relaybinding.ExternalWallet, target relaybinding.RevokeTarget) (relaybinding.Prepared, error) {
	return s.printRevoke(ctx, w, target, false)
}

// PrintLost is PrintRevoke for forget --lost: a revoke of one other device,
// which may use the reserved places of the book.
//
// spec: SPO-Xmailbox-SEC-073, SPO-Xmailbox-OUT-098
func (s Service) PrintLost(ctx context.Context, w relaybinding.ExternalWallet, device party.Fingerprint) (relaybinding.Prepared, error) {
	if device == s.Device {
		return relaybinding.Prepared{}, ErrSelf
	}
	return s.printRevoke(ctx, w, relaybinding.RevokeTarget{Device: device}, true)
}

func (s Service) printRevoke(ctx context.Context, w relaybinding.ExternalWallet, target relaybinding.RevokeTarget, protected bool) (relaybinding.Prepared, error) {
	if _, err := s.CheckExternal(ctx, w); err != nil {
		return relaybinding.Prepared{}, err
	}
	st, err := s.Load(ctx)
	if err != nil {
		return relaybinding.Prepared{}, err
	}
	if err := s.checkRoom(st, protected); err != nil {
		return relaybinding.Prepared{}, err
	}
	p, err := s.Sign.PrepareRevoke(ctx, w, target, s.Clock.Now().Unix())
	if err != nil {
		return relaybinding.Prepared{}, err
	}
	return p, s.update(ctx, func(st *State) error { st.Prepared = &p; return nil })
}

// ImportRevoke verifies the external wallet's revoke against the stored request
// and stores it as pending.
//
// spec: SPO-Xmailbox-IF-021, SPO-Xmailbox-OUT-098, SPO-Xmailbox-SEC-075
func (s Service) ImportRevoke(ctx context.Context, sign1, coseKey []byte) (relayport.Revoke, error) {
	p, err := s.prepared(ctx, relaybinding.PreparedRevokeKind)
	if err != nil {
		return relayport.Revoke{}, err
	}
	return s.importRevoke(ctx, p, sign1, coseKey, false)
}

// ImportLost is ImportRevoke for forget --lost DEVICE: the prepared request must
// be a revoke of exactly that device (not of every device of the key, and not of
// this device), or nothing is imported.
//
// spec: SPO-Xmailbox-SEC-073
func (s Service) ImportLost(ctx context.Context, device party.Fingerprint, sign1, coseKey []byte) (relayport.Revoke, error) {
	if device == s.Device {
		return relayport.Revoke{}, ErrSelf
	}
	p, err := s.prepared(ctx, relaybinding.PreparedRevokeKind)
	if err != nil {
		return relayport.Revoke{}, err
	}
	if p.Revoke.All || p.Revoke.Device != device {
		return relayport.Revoke{}, ErrLostMismatch
	}
	return s.importRevoke(ctx, p, sign1, coseKey, true)
}

func (s Service) importRevoke(ctx context.Context, p relaybinding.Prepared, sign1, coseKey []byte, protected bool) (relayport.Revoke, error) {
	got, err := s.Sign.ImportRevoke(ctx, p, sign1, coseKey)
	if err != nil {
		return relayport.Revoke{}, err
	}
	if err := s.checkNotPool(ctx, got.WalletKey); err != nil {
		return relayport.Revoke{}, err
	}
	return s.storeWalletRevoke(ctx, got.RevokeResult, protected, func(st *State) { st.Prepared = nil })
}

// Forget revokes this device with its own key (not-before now), stores the
// revoke, raises this device's not-before and deletes its binding, in one
// transaction after the signature (SPO-Xmailbox-SEC-073). A failed signature
// changes nothing. It may use the reserved places of the book.
//
// spec: SPO-Xmailbox-SEC-073, SPO-Xmailbox-OUT-098
func (s Service) Forget(ctx context.Context) (relayport.Revoke, error) {
	return s.forget(ctx, false)
}

// ForgetRevoke is the first half of "forget this device" over relays
// (SPO-Xmailbox-OUT-109): it signs and stores the device-signed revoke of this
// device and raises its not-before, as Forget does, but keeps the binding, which
// DropBinding deletes once the revoke was sent and the clients were closed
// (ADR 0014 decision 8: the bindings are deleted last).
//
// spec: SPO-Xmailbox-OUT-109, SPO-Xmailbox-SEC-073
func (s Service) ForgetRevoke(ctx context.Context) (relayport.Revoke, error) {
	return s.forget(ctx, true)
}

// DropBinding deletes this device's binding and any prepared request: the last
// step of "forget this device" over relays. A new login needs a new binding.
//
// spec: SPO-Xmailbox-OUT-109
func (s Service) DropBinding(ctx context.Context) error {
	return s.update(ctx, func(st *State) error {
		st.Binding, st.Prepared = nil, nil
		return nil
	})
}

func (s Service) forget(ctx context.Context, keepBinding bool) (relayport.Revoke, error) {
	if s.DeviceRevoke == nil {
		return relayport.Revoke{}, errors.New("relayself: no device identity to sign the revoke")
	}
	st, err := s.Load(ctx)
	if err != nil {
		return relayport.Revoke{}, err
	}
	if err := s.checkRoom(st, true); err != nil {
		return relayport.Revoke{}, err
	}
	nb := s.Clock.Now().Unix()
	dr, err := s.DeviceRevoke(ctx, nb)
	if err != nil {
		return relayport.Revoke{}, err
	}
	if dr.Device != s.Device || dr.NotBefore != nb {
		return relayport.Revoke{}, fmt.Errorf("relayself: the device revoke is not this device's at %d", nb)
	}
	var out relayport.Revoke
	err = s.update(ctx, func(st *State) error {
		out = deviceRevoke(dr, revokeUntil(*st, true, nb))
		if err := s.addRevoke(st, out, true); err != nil {
			return err
		}
		raise(st, s.Device, nb, s.Device)
		if !keepBinding {
			st.Binding, st.Prepared = nil, nil
		}
		return nil
	})
	return out, err
}

func deviceRevoke(dr relaybinding.DeviceRevokeResult, until int64) relayport.Revoke {
	return relayport.Revoke{Kind: relayport.RevokeByDeviceKey, Until: until,
		Keys: wire.DeviceKeys{Ed25519: dr.Ed25519, X25519: dr.X25519}, NotBefore: dr.NotBefore, Signature: dr.Signature}
}

// RotationRevoke is the device-signed revoke of this device that a rotation of
// its party identity stores (ADR 0014 decision 11): signed with the OLD identity
// before the rotation replaces it. It is empty when this device holds no
// binding, so there is nothing to revoke.
type RotationRevoke struct {
	result *relaybinding.DeviceRevokeResult
}

// Needed reports whether the rotation has a revoke to store.
func (r RotationRevoke) Needed() bool { return r.result != nil }

// PrepareRotation is called before the identity is rotated, while the old keys
// still sign: when this device holds a binding it signs the device revoke of
// this device, not-before now. Nothing is stored here; OnRotated stores it in
// the rotation's own transaction. A revoke that cannot be signed refuses the
// rotation (nothing has changed yet): the old binding would otherwise stay
// live at the relays with nothing that could ever revoke it by this device.
//
// spec: SPO-Xmailbox-SEC-076
func (s Service) PrepareRotation(ctx context.Context) (RotationRevoke, error) {
	st, err := s.Load(ctx)
	if err != nil {
		return RotationRevoke{}, err
	}
	if st.Binding == nil {
		return RotationRevoke{}, nil
	}
	if s.DeviceRevoke == nil {
		return RotationRevoke{}, errors.New("relayself: no device identity to sign the revoke of the old device: nothing was rotated")
	}
	nb := s.Clock.Now().Unix()
	dr, err := s.DeviceRevoke(ctx, nb)
	if err != nil {
		return RotationRevoke{}, fmt.Errorf("relayself: the revoke of the old device could not be signed, nothing was rotated: %w", err)
	}
	if dr.Device != s.Device || dr.NotBefore != nb {
		return RotationRevoke{}, fmt.Errorf("relayself: the device revoke is not this device's at %d", nb)
	}
	return RotationRevoke{result: &dr}, nil
}

// RotationNote is what OnRotated did.
type RotationNote struct {
	// Revoked: the revoke of the old device is pending. False with Needed: the
	// book had no place even among the reserved ones; the old binding stays live
	// at relays until its end unless the operator revokes the old device with the
	// wallet key (the command says how).
	Revoked bool
	Needed  bool
	// DroppedBinding: the old device's binding was dropped.
	DroppedBinding bool
	Old            party.Fingerprint
	OldUntil       int64
}

// OnRotated is the rotation's hook (multisig.RotateIdentity), in its store
// transaction, after the identity check: the record is read as the old device's
// (s.Device must be old); the revoke PrepareRotation signed is stored as pending
// (it may use the reserved places), the old device's not-before is raised, and
// its binding and any prepared request are dropped, so the new device starts
// with no binding and its own not-before semantics (it was never revoked). The
// pending revokes are kept. A full book does not stop the rotation: the note
// says the revoke was not stored.
//
// spec: SPO-Xmailbox-SEC-076, SPO-Xmailbox-OUT-098
func (s Service) OnRotated(w ports.NamedWriter, rr RotationRevoke, old, next party.Fingerprint) (RotationNote, error) {
	note := RotationNote{Old: old, Needed: rr.Needed()}
	if old != s.Device {
		return note, fmt.Errorf("relayself: the rotation is of %s, this service is for %s", old, s.Device)
	}
	st, err := load(w, old)
	if err != nil {
		return note, err
	}
	if rr.result != nil {
		if rr.result.Device != old {
			return note, fmt.Errorf("relayself: the rotation's revoke names %s, not the old device", rr.result.Device)
		}
		r := deviceRevoke(*rr.result, revokeUntil(st, true, rr.result.NotBefore))
		switch err := s.addRevoke(&st, r, true); {
		case err == nil:
			note.Revoked = true
		case !errors.Is(err, ErrBookFull):
			return note, err
		}
		raise(&st, old, rr.result.NotBefore, next)
	}
	if st.Binding != nil {
		note.DroppedBinding, note.OldUntil = true, st.Binding.Until
	}
	st.Binding, st.Prepared = nil, nil
	return note, save(w, st)
}

// SendReport is what a send of the book did: how many revokes had each outcome,
// and each relay's own error (nil: the exchange with it ran).
type SendReport struct {
	Outcomes map[relayport.RevokeOutcome]int
	Relays   map[string]error
}

// ForgetLost revokes ANOTHER device of the wallet key with a key of the vault
// (wallet-signed, not-before now), stores it, and sends the pending revokes on a
// revoke-only connection (SPO-Xmailbox-SEC-073). Without a sender the revoke is
// stored and ErrNoSender says it waits for the next connection. The revokes stay
// pending whatever the relay answered. It may use the reserved places of the
// book.
//
// spec: SPO-Xmailbox-SEC-073, SPO-Xmailbox-SEC-075
func (s Service) ForgetLost(ctx context.Context, key relaywallet.WalletKey, device party.Fingerprint) (SendReport, error) {
	if device == s.Device {
		return SendReport{}, ErrSelf
	}
	if _, err := s.revokeWallet(ctx, key, relaybinding.RevokeTarget{Device: device}, true); err != nil {
		return SendReport{}, err
	}
	return s.SendPending(ctx)
}

// SendPending sends the pending revokes through Send and saves what the book
// learnt, the relays that recorded each revoke included. It needs no binding:
// it is how a revoke still owed to a relay is completed after forget deleted
// the binding (SPO-Xmailbox-OUT-111).
//
// spec: SPO-Xmailbox-SEC-073, SPO-Xmailbox-OUT-098, SPO-Xmailbox-OUT-111
func (s Service) SendPending(ctx context.Context) (SendReport, error) {
	if s.Send == nil {
		return SendReport{}, ErrNoSender
	}
	b, err := s.Book(ctx)
	if err != nil {
		return SendReport{}, err
	}
	relays, serr := s.Send(ctx, b)
	rep := b.Report()
	rep.Relays = relays
	if err := b.Save(ctx); err != nil {
		return rep, errors.Join(serr, err)
	}
	return rep, serr
}

// DropRevoke removes one pending revoke, named by its ShortID, and returns it.
// It is the operator's way out of a full book: the command shows the revoke
// and asks first, because a dropped revoke is no longer sent and a relay that
// never got it keeps the binding it revokes until that binding ends.
//
// spec: SPO-Xmailbox-OUT-098
func (s Service) DropRevoke(ctx context.Context, id string) (RevokeView, error) {
	var out RevokeView
	err := s.update(ctx, func(st *State) error {
		for i, r := range st.Revokes {
			if ShortID(r) != id {
				continue
			}
			v, err := viewOf(r)
			if err != nil {
				return err
			}
			out = v
			st.Revokes = append(st.Revokes[:i:i], st.Revokes[i+1:]...)
			return nil
		}
		return ErrNoRevoke
	})
	return out, err
}

// Status is what `spo party relay status` shows.
type Status struct {
	Binding  *Binding
	DaysLeft int
	RenewDue bool // within RenewMargin of its end
	Expired  bool
	Pending  int
	Revokes  []RevokeView
	Prepared *relaybinding.Prepared
	// Foreign is a stored binding of another device (from before a rotation);
	// ForeignPrepared a prepared binding request for another device. Both are
	// dropped at the next write.
	Foreign         *Binding
	ForeignPrepared bool
	// Relays are the names of the listed relays; Owed counts, per listed
	// relay, the pending revokes that have not ended and that it has not
	// recorded.
	Relays []string
	Owed   map[string]int
}

// Status reads the state and says how the binding stands, and which listed
// relay still owes which pending revoke (SPO-Xmailbox-OUT-111).
//
// spec: SPO-Xmailbox-IF-021, SPO-Xmailbox-OUT-097, SPO-Xmailbox-OUT-111
func (s Service) Status(ctx context.Context) (Status, error) {
	var st State
	var relays []Relay
	err := s.Store.View(ctx, func(r ports.NamedReader) error {
		var err error
		if st, err = load(r, s.Device); err != nil {
			return err
		}
		relays, err = readRelays(r)
		return err
	})
	if err != nil {
		return Status{}, err
	}
	out := Status{Binding: st.Binding, Pending: len(st.Revokes), Prepared: st.Prepared, Foreign: st.Foreign, ForeignPrepared: st.ForeignPrepared,
		Owed: map[string]int{}}
	for _, rl := range relays {
		out.Relays = append(out.Relays, rl.Name)
	}
	now := s.Clock.Now().Unix()
	for _, r := range st.Revokes {
		v, err := viewOf(r)
		if err != nil {
			return Status{}, err
		}
		v.RecordedAt = st.RecordedAt[revokeID(r)]
		for _, n := range out.Relays {
			if !slices.Contains(v.RecordedAt, n) && r.Until >= now {
				v.OwedTo = append(v.OwedTo, n)
				out.Owed[n]++
			}
		}
		out.Revokes = append(out.Revokes, v)
	}
	if b := st.Binding; b != nil {
		left := b.Until - s.Clock.Now().Unix()
		out.Expired = left < 0
		out.RenewDue = left <= int64(RenewMargin/time.Second)
		out.DaysLeft = int(max(left, 0) / 86400)
	}
	return out, nil
}
