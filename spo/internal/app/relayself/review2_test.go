package relayself_test

import (
	"context"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/app/relaybinding"
	"github.com/mochipool/workbench/spo/internal/app/relayself"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

func foreignStatus(t *testing.T, svc relayself.Service, dev party.Fingerprint) {
	t.Helper()
	s, err := svc.Status(ctx)
	if err != nil || s.Foreign == nil || s.Foreign.Device != dev || s.Pending != 1 || len(s.Revokes) != 1 {
		t.Fatalf("status %+v %v", s, err)
	}
}

// A prepared binding request for another device (from before a rotation) is
// dropped with a notice, never imported here.
//
// spec: SPO-Xmailbox-OUT-097
func TestForeignPreparedIsDropped(t *testing.T) {
	r := newRig(t)
	if _, err := r.svc.PrintBinding(ctx, relaybinding.ExternalWallet{KeyHash: r.wallet.Key}, 0); err != nil {
		t.Fatal(err)
	}
	other := r.service(r.store)
	other.Device = relayporttest.Device(2)
	st, err := other.Load(ctx)
	if err != nil || st.Prepared != nil || !st.ForeignPrepared {
		t.Fatalf("prepared %+v, notice %v, %v", st.Prepared, st.ForeignPrepared, err)
	}
	if _, err := other.ImportBinding(ctx, []byte{1}, []byte{1}); !errors.Is(err, relayself.ErrNoPrepared) {
		t.Fatalf("an import into another device's request: %v", err)
	}
}

// Every path that names a wallet key refuses a key that is a pool id this
// workspace knows (its own pool known only by id included), before anything is
// signed or printed; a pool id added between print and import refuses the
// import; without a pool-id source nothing is signed.
//
// spec: SPO-Xmailbox-SEC-075
func TestPoolIDIsRefusedOnEveryWalletPath(t *testing.T) {
	r := newRig(t)
	ext := relaybinding.ExternalWallet{KeyHash: r.wallet.Key}
	r.pools = map[[28]byte]bool{r.wallet.Key: true}
	if _, err := r.svc.Bind(ctx, r.key, 0); !errors.Is(err, relayself.ErrPoolID) {
		t.Errorf("bind: %v", err)
	}
	if _, err := r.svc.PrintBinding(ctx, ext, 0); !errors.Is(err, relayself.ErrPoolID) {
		t.Errorf("print: %v", err)
	}
	addr := relaybinding.ExternalWallet{Address: r.wallet.EnterpriseAddress(0)}
	if _, err := r.svc.PrintBinding(ctx, addr, 0); !errors.Is(err, relayself.ErrPoolID) {
		t.Errorf("print for an address: %v", err)
	}
	if _, err := r.svc.CheckExternal(ctx, ext); !errors.Is(err, relayself.ErrPoolID) {
		t.Errorf("check: %v", err)
	}
	if _, err := r.svc.RevokeWallet(ctx, r.key, relaybinding.RevokeTarget{All: true}); !errors.Is(err, relayself.ErrPoolID) {
		t.Errorf("revoke: %v", err)
	}
	if _, err := r.svc.PrintRevoke(ctx, ext, relaybinding.RevokeTarget{All: true}); !errors.Is(err, relayself.ErrPoolID) {
		t.Errorf("print revoke: %v", err)
	}
	if _, err := r.svc.PrintLost(ctx, ext, relayporttest.Device(5)); !errors.Is(err, relayself.ErrPoolID) {
		t.Errorf("print lost: %v", err)
	}
	if _, err := r.svc.ForgetLost(ctx, r.key, relayporttest.Device(5)); !errors.Is(err, relayself.ErrPoolID) {
		t.Errorf("forget --lost: %v", err)
	}
	if r.signed != 0 || len(r.state().Revokes) != 0 || r.state().Prepared != nil {
		t.Fatalf("a refused path signed %d or stored something", r.signed)
	}
	// the pool becomes known between print and import
	r.pools = nil
	p, err := r.svc.PrintBinding(ctx, ext, 0)
	if err != nil {
		t.Fatal(err)
	}
	r.pools = map[[28]byte]bool{r.wallet.Key: true}
	if _, err := r.svc.ImportBinding(ctx, r.wallet.Sign1(p.Payload, false), r.wallet.COSEKey()); !errors.Is(err, relayself.ErrPoolID) {
		t.Errorf("import binding: %v", err)
	}
	r.pools = nil
	pr, err := r.svc.PrintRevoke(ctx, ext, relaybinding.RevokeTarget{All: true})
	if err != nil {
		t.Fatal(err)
	}
	r.pools = map[[28]byte]bool{r.wallet.Key: true}
	if _, err := r.svc.ImportRevoke(ctx, r.wallet.Sign1(pr.Payload, false), r.wallet.COSEKey()); !errors.Is(err, relayself.ErrPoolID) {
		t.Errorf("import revoke: %v", err)
	}
	if st := r.state(); st.Binding != nil || len(st.Revokes) != 0 {
		t.Fatal("a refused import stored something")
	}
	r.svc.PoolIDs = nil
	r.pools = nil
	if _, err := r.svc.Bind(ctx, r.key, 0); !errors.Is(err, relayself.ErrNoPoolSource) {
		t.Errorf("no pool-id source: %v", err)
	}
}

// CheckExternal says whether the workspace knows the key, so the command asks
// for the typed confirmation for one it does not know.
//
// spec: SPO-Xmailbox-SEC-075
func TestCheckExternalSaysWhetherTheKeyIsKnown(t *testing.T) {
	r := newRig(t)
	known, err := r.svc.CheckExternal(ctx, relaybinding.ExternalWallet{KeyHash: r.wallet.Key})
	if err != nil || !known {
		t.Fatalf("a key with a payment history: %v %v", known, err)
	}
	r.svc.Sign.History = func(context.Context, identity.Ref) (custody.RoleHistory, bool, error) {
		return custody.RoleHistory{}, false, nil
	}
	known, err = r.svc.CheckExternal(ctx, relaybinding.ExternalWallet{KeyHash: r.wallet.Key})
	if err != nil || known {
		t.Fatalf("a key this workspace has no history of: %v %v", known, err)
	}
}

// The reserved places: an ordinary revoke stops at MaxPendingRevokes -
// ReservedRevokes, while forget, forget --lost (vault and imported) and the
// rotation revoke still find room up to MaxPendingRevokes; at the very bound
// the operator drops a named revoke (DropRevoke) and the next one fits.
//
// spec: SPO-Xmailbox-OUT-098
func TestReservedPlacesAndDrop(t *testing.T) {
	r := newRig(t)
	if _, err := r.svc.Bind(ctx, r.key, 0); err != nil {
		t.Fatal(err)
	}
	now := r.clk.Now().Unix()
	for i := range relayself.MaxPendingRevokes - relayself.ReservedRevokes {
		st := r.wallet.RevokeStatement(relayporttest.Device(byte(100+i)), false, now)
		if err := r.svc.AddRevoke(ctx, relayport.Revoke{Kind: relayport.RevokeByWalletKey, Until: now + 1000, Sign1: st.Sign1, Key: st.COSEKey}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.svc.RevokeWallet(ctx, r.key, relaybinding.RevokeTarget{Device: relayporttest.Device(7)}); !errors.Is(err, relayself.ErrBookFull) {
		t.Fatalf("an ordinary revoke past the ordinary bound: %v", err)
	}
	if _, err := r.svc.ForgetLost(ctx, r.key, relayporttest.Device(7)); !errors.Is(err, relayself.ErrNoSender) {
		t.Fatalf("forget --lost in the reserved places: %v", err)
	}
	ext := relaybinding.ExternalWallet{KeyHash: r.wallet.Key}
	p, err := r.svc.PrintLost(ctx, ext, relayporttest.Device(8))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.ImportLost(ctx, relayporttest.Device(8), r.wallet.Sign1(p.Payload, false), r.wallet.COSEKey()); err != nil {
		t.Fatalf("an imported --lost revoke in the reserved places: %v", err)
	}
	// fill the reserved places with lost devices
	for i := len(r.state().Revokes); i < relayself.MaxPendingRevokes-1; i++ {
		if _, err := r.svc.ForgetLost(ctx, r.key, relayporttest.Device(byte(200+i-48))); !errors.Is(err, relayself.ErrNoSender) {
			t.Fatalf("lost %d: %v", i, err)
		}
	}
	if _, err := r.svc.Forget(ctx); err != nil {
		t.Fatalf("forget in the last place: %v", err)
	}
	if n := len(r.state().Revokes); n != relayself.MaxPendingRevokes {
		t.Fatalf("%d pending", n)
	}
	if _, err := r.svc.ForgetLost(ctx, r.key, relayporttest.Device(99)); !errors.Is(err, relayself.ErrBookFull) {
		t.Fatalf("past the very bound: %v", err)
	}
	s, err := r.svc.Status(ctx)
	if err != nil || len(s.Revokes) != relayself.MaxPendingRevokes {
		t.Fatalf("status lists %d: %v", len(s.Revokes), err)
	}
	if _, err := r.svc.DropRevoke(ctx, "0000000000000000"); !errors.Is(err, relayself.ErrNoRevoke) {
		t.Fatalf("an unknown id: %v", err)
	}
	v, err := r.svc.DropRevoke(ctx, s.Revokes[0].ID)
	if err != nil || v.ID != s.Revokes[0].ID {
		t.Fatalf("drop: %+v %v", v, err)
	}
	if n := len(r.state().Revokes); n != relayself.MaxPendingRevokes-1 {
		t.Fatalf("%d pending after a drop", n)
	}
	if _, err := r.svc.ForgetLost(ctx, r.key, relayporttest.Device(99)); !errors.Is(err, relayself.ErrNoSender) {
		t.Fatalf("after the drop: %v", err)
	}
}

// A revoke of the same scope and a later not-before supersedes the pending one:
// forgetting this device twice keeps one device revoke, so the book does not
// fill with revokes of one device.
//
// spec: SPO-Xmailbox-OUT-098
func TestNewerRevokeOfTheSameScopeSupersedes(t *testing.T) {
	r := newRig(t)
	if _, err := r.svc.Forget(ctx); err != nil {
		t.Fatal(err)
	}
	r.clk.advance(90e9)
	if _, err := r.svc.Forget(ctx); err != nil {
		t.Fatal(err)
	}
	if st := r.state(); len(st.Revokes) != 1 || st.Revokes[0].NotBefore != r.clk.Now().Unix() {
		t.Fatalf("pending %+v", st.Revokes)
	}
	for range 2 {
		if _, err := r.svc.RevokeWallet(ctx, r.key, relaybinding.RevokeTarget{Device: relayporttest.Device(5)}); err != nil {
			t.Fatal(err)
		}
		r.clk.advance(1e9)
	}
	if n := len(r.state().Revokes); n != 2 {
		t.Fatalf("%d pending, want the device revoke and one wallet revoke of device 5", n)
	}
}

// forget --lost DEVICE --import imports only a prepared revoke of exactly that
// device: a prepared revoke of every device of the key, of another device, of
// this device, and a state that cannot be read are refused, and nothing is
// stored.
//
// spec: SPO-Xmailbox-SEC-073
func TestImportLostMustMatchTheDevice(t *testing.T) {
	r := newRig(t)
	ext := relaybinding.ExternalWallet{KeyHash: r.wallet.Key}
	all, err := r.svc.PrintRevoke(ctx, ext, relaybinding.RevokeTarget{All: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.ImportLost(ctx, relayporttest.Device(5), r.wallet.Sign1(all.Payload, false), r.wallet.COSEKey()); !errors.Is(err, relayself.ErrLostMismatch) {
		t.Fatalf("a prepared --all imported as --lost: %v", err)
	}
	other, err := r.svc.PrintLost(ctx, ext, relayporttest.Device(6))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.ImportLost(ctx, relayporttest.Device(5), r.wallet.Sign1(other.Payload, false), r.wallet.COSEKey()); !errors.Is(err, relayself.ErrLostMismatch) {
		t.Fatalf("a revoke of another device: %v", err)
	}
	if _, err := r.svc.PrintLost(ctx, ext, relayporttest.Device(r.dev)); !errors.Is(err, relayself.ErrSelf) {
		t.Fatalf("print --lost of this device: %v", err)
	}
	if _, err := r.svc.ImportLost(ctx, relayporttest.Device(r.dev), nil, nil); !errors.Is(err, relayself.ErrSelf) {
		t.Fatalf("import --lost of this device: %v", err)
	}
	if n := len(r.state().Revokes); n != 0 {
		t.Fatalf("%d stored", n)
	}
	if err := r.store.Update(ctx, func(w ports.NamedWriter) error {
		return w.Put(ports.NamedRef{Name: "self", Kind: ports.RelayOwn}, []byte(`{"v":2}`))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.ImportLost(ctx, relayporttest.Device(6), r.wallet.Sign1(other.Payload, false), r.wallet.COSEKey()); !errors.Is(err, relayself.ErrCorrupt) {
		t.Fatalf("an unreadable state: %v", err)
	}
}

// The rotation of this device's party identity: the revoke of the old device is
// signed by the old key before the rotation, stored in the rotation's own
// transaction, the old binding and the prepared request dropped; the new device
// then has no binding, sees the pending revoke, binds, revokes and forgets a lost
// device as any device does.
//
// spec: SPO-Xmailbox-SEC-076, SPO-Xmailbox-OUT-098
func TestRotationRevokesTheOldDevice(t *testing.T) {
	r := newRig(t)
	if _, err := r.svc.Bind(ctx, r.key, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.PrintBinding(ctx, relaybinding.ExternalWallet{KeyHash: r.wallet.Key}, 0); err != nil {
		t.Fatal(err)
	}
	old, next := relayporttest.Device(r.dev), relayporttest.Device(2)
	rr, err := r.svc.PrepareRotation(ctx)
	if err != nil || !rr.Needed() {
		t.Fatalf("prepare: %v %v", rr.Needed(), err)
	}
	var note relayself.RotationNote
	if err := r.store.Update(ctx, func(w ports.NamedWriter) error {
		var err error
		note, err = r.svc.OnRotated(w, rr, old, next)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !note.Revoked || !note.DroppedBinding {
		t.Fatalf("note %+v", note)
	}
	ns := r.service(r.store)
	ns.Device = next
	s, err := ns.Status(ctx)
	if err != nil {
		t.Fatalf("status after the rotation: %v", err)
	}
	if s.Binding != nil || s.Foreign != nil || s.Prepared != nil || len(s.Revokes) != 1 || !s.Revokes[0].ByDevice || s.Revokes[0].Device != old {
		t.Fatalf("status after the rotation: %+v", s)
	}
	b, err := ns.Book(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p := b.Pending()
	if len(p) != 1 || p[0].Keys.Fingerprint() != old {
		t.Fatalf("the book after the rotation: %+v", p)
	}
	if _, err := relaybind.VerifyDeviceRevoke(p[0].Keys.Ed25519, p[0].Keys.X25519, p[0].NotBefore, p[0].Signature, r.clk.Now().Unix(), relaybind.DefaultPolicy()); err != nil {
		t.Fatalf("the stored revoke of the old device: %v", err)
	}
	if _, err := ns.Bind(ctx, r.key, 0); err != nil {
		t.Fatalf("bind after the rotation: %v", err)
	}
	if _, err := ns.RevokeWallet(ctx, r.key, relaybinding.RevokeTarget{Device: old}); err != nil {
		t.Fatalf("revoke after the rotation: %v", err)
	}
	if _, err := ns.ForgetLost(ctx, r.key, relayporttest.Device(9)); !errors.Is(err, relayself.ErrNoSender) {
		t.Fatalf("forget --lost after the rotation: %v", err)
	}
	// a rotation with no binding has nothing to revoke
	r2 := newRig(t)
	if rr, err := r2.svc.PrepareRotation(ctx); err != nil || rr.Needed() {
		t.Fatalf("no binding: %v %v", rr.Needed(), err)
	}
}

// A full book does not stop a rotation: the revoke is not stored, the note says
// so (the command tells the operator to revoke the old device with the wallet
// key), and the old binding is still dropped.
//
// spec: SPO-Xmailbox-SEC-076
func TestRotationWithAFullBook(t *testing.T) {
	r := newRig(t)
	if _, err := r.svc.Bind(ctx, r.key, 0); err != nil {
		t.Fatal(err)
	}
	for i := range relayself.MaxPendingRevokes {
		if _, err := r.svc.ForgetLost(ctx, r.key, relayporttest.Device(byte(100+i))); !errors.Is(err, relayself.ErrNoSender) {
			t.Fatal(err)
		}
	}
	rr, err := r.svc.PrepareRotation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var note relayself.RotationNote
	if err := r.store.Update(ctx, func(w ports.NamedWriter) error {
		var err error
		note, err = r.svc.OnRotated(w, rr, relayporttest.Device(r.dev), relayporttest.Device(2))
		return err
	}); err != nil {
		t.Fatalf("a full book stopped the rotation: %v", err)
	}
	if note.Revoked || !note.Needed || !note.DroppedBinding {
		t.Fatalf("note %+v", note)
	}
}
