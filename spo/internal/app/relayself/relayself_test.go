package relayself_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/relaybinding"
	"github.com/mochipool/workbench/spo/internal/app/relayself"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relaywallet"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

var ctx = context.Background()

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// walletSigner signs relay statements with a test wallet, as the vault does,
// and counts the revokes it signed.
type walletSigner struct {
	w       *relayporttest.Wallet
	revokes *int
}

func (walletSigner) Profile() custody.Profile { return custody.Profile{} }
func (s walletSigner) SignRelayBinding(_ context.Context, _ relaywallet.WalletKey, b relaybind.Binding) (ports.SignedMessage, error) {
	p, err := b.Render()
	return ports.SignedMessage{Sign1: s.w.Sign1(p, false), Key: s.w.COSEKey()}, err
}
func (s walletSigner) SignRelayRevoke(_ context.Context, _ relaywallet.WalletKey, r relaybind.Revoke) (ports.SignedMessage, error) {
	*s.revokes++
	p, err := r.Render()
	return ports.SignedMessage{Sign1: s.w.Sign1(p, false), Key: s.w.COSEKey()}, err
}

type rig struct {
	t      *testing.T
	store  ports.NamedStore
	clk    *clock
	wallet *relayporttest.Wallet
	key    relaywallet.WalletKey
	dev    byte
	svc    relayself.Service
	signed int // revokes the wallet signed
	pools  map[[28]byte]bool
}

func keyOf(t *testing.T, w *relayporttest.Wallet) relaywallet.WalletKey {
	id, err := identity.NewRef(identity.KindKeyHash, w.Key[:])
	if err != nil {
		t.Fatal(err)
	}
	k, err := relaywallet.FromRef(custody.KeyRef{Role: custody.RolePayment, Identity: id})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func payment(_ context.Context, id identity.Ref) (custody.RoleHistory, bool, error) {
	h, err := custody.NewRoleHistory(id, custody.RolePayment)
	return h, true, err
}

// deviceSigner signs the device-signed revoke with the real keys of
// relayporttest.Device(n).
type deviceSigner struct{ n byte }

func newRig(t *testing.T) *rig {
	t.Helper()
	st, err := plainstore.OpenTestnet(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, store: st, clk: &clock{t: time.Unix(1_800_000_000, 0).UTC()}, wallet: relayporttest.NewWallet(3), dev: 1}
	r.key = keyOf(t, r.wallet)
	r.svc = r.service(st)
	return r
}

func (r *rig) service(st ports.NamedStore) relayself.Service {
	return relayself.Service{Store: st, Clock: r.clk, Device: relayporttest.Device(r.dev),
		Sign:    relaybinding.Service{Signer: walletSigner{w: r.wallet, revokes: &r.signed}, Clock: r.clk, History: payment},
		PoolIDs: func(context.Context) (map[[28]byte]bool, error) { return r.pools, nil },
		DeviceRevoke: func(_ context.Context, nb int64) (relaybinding.DeviceRevokeResult, error) {
			sig := relayporttest.DeviceRevokeSignature(r.t, r.dev, nb)
			k := relayporttest.DeviceKeysOf(r.dev)
			return relaybinding.DeviceRevokeResult{Device: relayporttest.Device(r.dev), NotBefore: nb, Ed25519: k.Ed25519, X25519: k.X25519, Signature: sig}, nil
		}}
}

func (r *rig) state() relayself.State {
	r.t.Helper()
	s, err := r.svc.Load(ctx)
	if err != nil {
		r.t.Fatal(err)
	}
	return s
}

// A software key binds this device and the binding is stored; a renewal
// replaces it; status shows it with the renewal warning near its end.
//
// spec: SPO-Xmailbox-PRE-059, SPO-Xmailbox-OUT-097, SPO-Xmailbox-IF-021
func TestBindStoresAndRenews(t *testing.T) {
	r := newRig(t)
	res, err := r.svc.Bind(ctx, r.key, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	st := r.state()
	if st.Binding == nil || !bytes.Equal(st.Binding.Statement, res.Statement) || st.Binding.WalletKey != party.WalletKey(r.wallet.Key) {
		t.Fatalf("stored %+v", st.Binding)
	}
	s, err := r.svc.Status(ctx)
	if err != nil || s.Binding == nil || s.RenewDue || s.Expired {
		t.Fatalf("status %+v %v", s, err)
	}
	r.clk.advance(20 * 24 * time.Hour)
	if s, _ := r.svc.Status(ctx); !s.RenewDue {
		t.Fatalf("no renewal warning 10 days before the end: %+v", s)
	}
	res2, err := r.svc.Bind(ctx, r.key, 0)
	if err != nil {
		t.Fatal(err)
	}
	if st := r.state(); !bytes.Equal(st.Binding.Statement, res2.Statement) || st.Binding.From <= res.Binding.From {
		t.Fatalf("not replaced by the renewal: %+v", st.Binding)
	}
	r.clk.advance(100 * 24 * time.Hour)
	if s, _ := r.svc.Status(ctx); !s.Expired {
		t.Fatalf("an ended binding is not shown as expired: %+v", s)
	}
}

// SetBinding's rule: a binding of another device, one that does not verify and
// an older one are refused and change nothing; the same one again is no change.
//
// spec: SPO-Xmailbox-PRE-059
func TestSetBindingRules(t *testing.T) {
	r := newRig(t)
	now := r.clk.Now().Unix()
	cur := r.wallet.BindingStatement(relayporttest.Device(r.dev), now-30, now+3600, false)
	if err := r.svc.SetBinding(ctx, cur.Sign1, cur.COSEKey); err != nil {
		t.Fatal(err)
	}
	older := r.wallet.BindingStatement(relayporttest.Device(r.dev), now-60, now+7200, false)
	if err := r.svc.SetBinding(ctx, older.Sign1, older.COSEKey); !errors.Is(err, relayself.ErrOlder) {
		t.Fatalf("an older binding: %v", err)
	}
	other := r.wallet.BindingStatement(relayporttest.Device(9), now-10, now+3600, false)
	if err := r.svc.SetBinding(ctx, other.Sign1, other.COSEKey); !errors.Is(err, relaybind.ErrDeviceMismatch) {
		t.Fatalf("another device's: %v", err)
	}
	bad := bytes.Clone(cur.Sign1)
	bad[len(bad)-1] ^= 1
	if err := r.svc.SetBinding(ctx, bad, cur.COSEKey); !errors.Is(err, relaybind.ErrBadSignature) {
		t.Fatalf("forged: %v", err)
	}
	if err := r.svc.SetBinding(ctx, cur.Sign1, cur.COSEKey); err != nil {
		t.Fatalf("the same again: %v", err)
	}
	if st := r.state(); !bytes.Equal(st.Binding.Statement, cur.Sign1) {
		t.Fatal("a refused binding changed the state")
	}
}

// Print stores the prepared request; import verifies the wallet's answer
// against it, stores the binding and clears it. A forged answer, an answer for
// another device, a replay of an older binding and an expired request are
// refused and store nothing.
//
// spec: SPO-Xmailbox-IF-021, SPO-Xmailbox-PRE-059
func TestPrintAndImportBinding(t *testing.T) {
	r := newRig(t)
	if _, err := r.svc.ImportBinding(ctx, []byte{1}, []byte{1}); !errors.Is(err, relayself.ErrNoPrepared) {
		t.Fatalf("import with nothing prepared: %v", err)
	}
	p, err := r.svc.PrintBinding(ctx, relaybinding.ExternalWallet{KeyHash: r.wallet.Key}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if st := r.state(); st.Prepared == nil || st.Prepared.ID != p.ID {
		t.Fatal("the prepared request is not stored")
	}
	forged := r.wallet.Sign1(p.Payload, false)
	forged[len(forged)-1] ^= 1
	if _, err := r.svc.ImportBinding(ctx, forged, r.wallet.COSEKey()); !errors.Is(err, relaybinding.ErrImport) {
		t.Fatalf("forged: %v", err)
	}
	wrongDev := r.wallet.BindingStatement(relayporttest.Device(7), p.Binding.From, p.Binding.Until, false)
	if _, err := r.svc.ImportBinding(ctx, wrongDev.Sign1, wrongDev.COSEKey); !errors.Is(err, relaybinding.ErrImport) {
		t.Fatalf("another device: %v", err)
	}
	if r.state().Binding != nil {
		t.Fatal("a refused import stored a binding")
	}
	got, err := r.svc.ImportBinding(ctx, r.wallet.Sign1(p.Payload, false), r.wallet.COSEKey())
	if err != nil {
		t.Fatal(err)
	}
	st := r.state()
	if st.Prepared != nil || st.Binding == nil || !bytes.Equal(st.Binding.Statement, got.Statement) {
		t.Fatalf("after import %+v", st)
	}
	// a replay of the same answer: nothing prepared any more
	if _, err := r.svc.ImportBinding(ctx, got.Statement, got.COSEKey); !errors.Is(err, relayself.ErrNoPrepared) {
		t.Fatalf("a replayed import: %v", err)
	}
	// a request kept past ten minutes
	if _, err := r.svc.PrintBinding(ctx, relaybinding.ExternalWallet{KeyHash: r.wallet.Key}, 0); err != nil {
		t.Fatal(err)
	}
	r.clk.advance(11 * time.Minute)
	p2 := r.state().Prepared
	if _, err := r.svc.ImportBinding(ctx, r.wallet.Sign1(p2.Payload, false), r.wallet.COSEKey()); !errors.Is(err, relaybinding.ErrPreparedExpired) {
		t.Fatalf("expired request: %v", err)
	}
}

// A wallet-signed revoke is stored as pending, raises the not-before of its
// device, and the next binding of that device waits for it (PlanFrom); the book
// survives a restart, drops a final outcome and keeps a recorded one.
//
// spec: SPO-Xmailbox-OUT-098, SPO-Xmailbox-PRE-059
func TestRevokeIsPendingAndRaisesTheNotBefore(t *testing.T) {
	r := newRig(t)
	if _, err := r.svc.Bind(ctx, r.key, 0); err != nil {
		t.Fatal(err)
	}
	now := r.clk.Now().Unix()
	pend, err := r.svc.RevokeWallet(ctx, r.key, relaybinding.RevokeTarget{Device: relayporttest.Device(r.dev)})
	if err != nil {
		t.Fatal(err)
	}
	st := r.state()
	if len(st.Revokes) != 1 || st.NotBefore[relayporttest.Device(r.dev)] != now || pend.Until != st.Binding.Until {
		t.Fatalf("after the revoke: %+v %+v", st, pend)
	}
	// the same revoke again is not stored twice
	if err := r.svc.AddRevoke(ctx, pend); err != nil || len(r.state().Revokes) != 1 {
		t.Fatalf("a duplicate: %v %d", err, len(r.state().Revokes))
	}
	// the next binding of the device is later than the tombstone
	res, err := r.svc.Bind(ctx, r.key, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Binding.From <= now {
		t.Fatalf("a binding from %d not after the not-before %d", res.Binding.From, now)
	}
	// a fresh service over the same store (a restart) sees the pending revoke
	b, err := r.service(r.store).Book(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ps := b.Pending()
	if len(ps) != 1 || ps[0].Kind != relayport.RevokeByWalletKey {
		t.Fatalf("pending after restart %+v", ps)
	}
	b.Result(ps[0], relayport.RevokeRecorded)
	if err := b.Save(ctx); err != nil || len(r.state().Revokes) != 1 {
		t.Fatalf("a recorded revoke is not kept: %v", err)
	}
	b.Result(ps[0], relayport.RevokeExpired)
	if len(b.Pending()) != 0 {
		t.Fatal("a revoke with a final outcome is still listed as pending")
	}
	if err := b.Save(ctx); err != nil || len(r.state().Revokes) != 0 {
		t.Fatalf("a final outcome is not dropped: %v %d", err, len(r.state().Revokes))
	}
	// a revoke made with an earlier clock never lowers the stored not-before
	r.clk.advance(-30 * time.Second)
	if _, err := r.svc.RevokeWallet(ctx, r.key, relaybinding.RevokeTarget{Device: relayporttest.Device(r.dev)}); err != nil {
		t.Fatal(err)
	}
	if got := r.state().NotBefore[relayporttest.Device(r.dev)]; got != now {
		t.Fatalf("the not-before went from %d to %d", now, got)
	}
}

// A prepared revoke is not imported as a binding, and the reverse.
//
// spec: SPO-Xmailbox-PRE-059
func TestPreparedKindMustMatch(t *testing.T) {
	r := newRig(t)
	p, err := r.svc.PrintRevoke(ctx, relaybinding.ExternalWallet{KeyHash: r.wallet.Key}, relaybinding.RevokeTarget{All: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.ImportBinding(ctx, r.wallet.Sign1(p.Payload, false), r.wallet.COSEKey()); !errors.Is(err, relayself.ErrNoPrepared) {
		t.Fatalf("a revoke imported as a binding: %v", err)
	}
	if _, err := r.svc.ImportRevoke(ctx, r.wallet.Sign1(p.Payload, false), r.wallet.COSEKey()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.PrintBinding(ctx, relaybinding.ExternalWallet{KeyHash: r.wallet.Key}, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.ImportRevoke(ctx, []byte{1}, []byte{1}); !errors.Is(err, relayself.ErrNoPrepared) {
		t.Fatalf("a binding imported as a revoke: %v", err)
	}
}

// Forget takes only this device's own revoke at the time asked, and a stored
// device revoke that does not verify refuses the record.
//
// spec: SPO-Xmailbox-SEC-073, SPO-Xmailbox-OUT-097
func TestForgetChecksTheDeviceRevoke(t *testing.T) {
	r := newRig(t)
	if _, err := r.svc.Bind(ctx, r.key, 0); err != nil {
		t.Fatal(err)
	}
	good := r.svc.DeviceRevoke
	r.svc.DeviceRevoke = func(ctx context.Context, nb int64) (relaybinding.DeviceRevokeResult, error) {
		d, err := good(ctx, nb)
		d.Device = relayporttest.Device(9)
		return d, err
	}
	if _, err := r.svc.Forget(ctx); err == nil || r.state().Binding == nil {
		t.Fatal("another device's revoke was taken")
	}
	r.svc.DeviceRevoke = good
	if _, err := r.svc.Forget(ctx); err != nil {
		t.Fatal(err)
	}
	ref := ports.NamedRef{Name: "self", Kind: ports.RelayOwn}
	var raw []byte
	if err := r.store.View(ctx, func(rd ports.NamedReader) error { var err error; raw, err = rd.Get(ref); return err }); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	v := m["revokes"].([]any)[0].(map[string]any)
	s := []byte(v["signature"].(string))
	if s[0] == '0' {
		s[0] = '1'
	} else {
		s[0] = '0'
	}
	v["signature"] = string(s)
	bad, _ := json.Marshal(m)
	if err := r.store.Update(ctx, func(w ports.NamedWriter) error { return w.Put(ref, bad) }); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.Load(ctx); !errors.Is(err, relayself.ErrCorrupt) {
		t.Fatalf("a tampered device revoke: %v", err)
	}
}

// The book is bounded: an ordinary revoke is refused (with nothing signed for
// it) at MaxPendingRevokes - ReservedRevokes unless an expired one can go;
// expired ones are dropped at load.
//
// spec: SPO-Xmailbox-OUT-098
func TestRevokeBookBounds(t *testing.T) {
	r := newRig(t)
	now := r.clk.Now().Unix()
	ordinary := relayself.MaxPendingRevokes - relayself.ReservedRevokes
	for i := range ordinary {
		dev := relayporttest.Device(byte(100 + i))
		st := r.wallet.RevokeStatement(dev, false, now)
		if err := r.svc.AddRevoke(ctx, relayport.Revoke{Kind: relayport.RevokeByWalletKey, Until: now + int64(i) + 10, Sign1: st.Sign1, Key: st.COSEKey}); err != nil {
			t.Fatalf("revoke %d: %v", i, err)
		}
	}
	if _, err := r.svc.RevokeWallet(ctx, r.key, relaybinding.RevokeTarget{All: true}); !errors.Is(err, relayself.ErrBookFull) || r.signed != 0 {
		t.Fatalf("over the bound: %v, %d signed", err, r.signed)
	}
	extra := r.wallet.RevokeStatement(relayporttest.Device(250), false, now)
	if err := r.svc.AddRevoke(ctx, relayport.Revoke{Kind: relayport.RevokeByWalletKey, Until: now + 100, Sign1: extra.Sign1, Key: extra.COSEKey}); !errors.Is(err, relayself.ErrBookFull) {
		t.Fatalf("one more added at the bound: %v", err)
	}
	r.clk.advance(15 * time.Second) // the first five have ended
	if _, err := r.svc.RevokeWallet(ctx, r.key, relaybinding.RevokeTarget{All: true}); err != nil {
		t.Fatalf("with ended ones to drop: %v", err)
	}
	if n := len(r.state().Revokes); n > relayself.MaxPendingRevokes {
		t.Fatalf("%d pending", n)
	}
	b, _ := r.svc.Book(ctx)
	for _, p := range b.Pending() {
		if p.Until < r.clk.Now().Unix() {
			t.Fatal("an ended revoke is pending after a load")
		}
	}
	// a restart after every revoke has ended: the book offers none, with no write between
	r.clk.advance(200 * 24 * time.Hour)
	b, _ = r.service(r.store).Book(ctx)
	if n := len(b.Pending()); n != 0 {
		t.Fatalf("%d ended revokes pending after a restart", n)
	}
}

// Forget: a device-signed revoke of this device is stored before the binding
// is deleted, and the not-before of this device is raised.
//
// spec: SPO-Xmailbox-SEC-073, SPO-Xmailbox-OUT-098
func TestForgetThisDevice(t *testing.T) {
	r := newRig(t)
	if _, err := r.svc.Bind(ctx, r.key, 0); err != nil {
		t.Fatal(err)
	}
	p, err := r.svc.Forget(ctx)
	if err != nil {
		t.Fatal(err)
	}
	st := r.state()
	if st.Binding != nil || len(st.Revokes) != 1 || st.Revokes[0].Kind != relayport.RevokeByDeviceKey || p.Keys.Fingerprint() != relayporttest.Device(r.dev) {
		t.Fatalf("after forget %+v", st)
	}
	if _, err := relaybind.VerifyDeviceRevoke(p.Keys.Ed25519, p.Keys.X25519, p.NotBefore, p.Signature, r.clk.Now().Unix(), relaybind.DefaultPolicy()); err != nil {
		t.Fatalf("the stored revoke does not verify: %v", err)
	}
	if st.NotBefore[relayporttest.Device(r.dev)] != p.NotBefore {
		t.Fatal("the not-before of this device was not raised")
	}
	// a failing signer stores nothing and keeps the binding
	r2 := newRig(t)
	if _, err := r2.svc.Bind(ctx, r2.key, 0); err != nil {
		t.Fatal(err)
	}
	r2.svc.DeviceRevoke = func(context.Context, int64) (relaybinding.DeviceRevokeResult, error) {
		return relaybinding.DeviceRevokeResult{}, errors.New("no identity")
	}
	if _, err := r2.svc.Forget(ctx); err == nil || r2.state().Binding == nil {
		t.Fatal("a failed revoke deleted the binding")
	}
}

// Forget --lost: a wallet-signed revoke of ANOTHER device, sent by the
// revoke-only sender; this device is refused; the outcomes come back and the
// revoke stays pending.
//
// spec: SPO-Xmailbox-SEC-073
func TestForgetLost(t *testing.T) {
	r := newRig(t)
	if _, err := r.svc.ForgetLost(ctx, r.key, relayporttest.Device(r.dev)); !errors.Is(err, relayself.ErrSelf) {
		t.Fatalf("this device with --lost: %v", err)
	}
	var sent []relayport.Revoke
	r.svc.Send = func(_ context.Context, b relayport.RevokeBook) error {
		sent = b.Pending()
		for _, p := range sent {
			b.Result(p, relayport.RevokeRecorded)
		}
		return nil
	}
	rep, err := r.svc.ForgetLost(ctx, r.key, relayporttest.Device(5))
	if err != nil {
		t.Fatal(err)
	}
	if len(sent) != 1 || rep.Outcomes[relayport.RevokeRecorded] != 1 || len(r.state().Revokes) != 1 {
		t.Fatalf("sent %d, report %+v, pending %d", len(sent), rep, len(r.state().Revokes))
	}
	r.svc.Send = nil
	if _, err := r.svc.ForgetLost(ctx, r.key, relayporttest.Device(6)); !errors.Is(err, relayself.ErrNoSender) {
		t.Fatalf("no sender wired: %v", err)
	}
	if len(r.state().Revokes) != 2 {
		t.Fatal("the revoke was not kept for a later connection")
	}
}

// A tampered, truncated, oversize or unknown-field record is refused, and so is a
// stored binding that does not verify.
//
// spec: SPO-Xmailbox-OUT-097
func TestTamperedRecordIsRefused(t *testing.T) {
	r := newRig(t)
	if _, err := r.svc.Bind(ctx, r.key, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.RevokeWallet(ctx, r.key, relaybinding.RevokeTarget{Device: relayporttest.Device(4)}); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	ref := ports.NamedRef{Name: "self", Kind: ports.RelayOwn}
	if err := r.store.View(ctx, func(rd ports.NamedReader) error { var err error; raw, err = rd.Get(ref); return err }); err != nil {
		t.Fatal(err)
	}
	put := func(b []byte) error {
		if err := r.store.Update(ctx, func(w ports.NamedWriter) error { return w.Put(ref, b) }); err != nil {
			t.Fatal(err)
		}
		_, err := r.svc.Load(ctx)
		return err
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	mutate := func(f func(map[string]any)) []byte {
		var c map[string]any
		_ = json.Unmarshal(raw, &c)
		f(c)
		b, _ := json.Marshal(c)
		return b
	}
	cases := map[string][]byte{
		"truncated":     raw[:len(raw)/2],
		"oversize":      append(bytes.Repeat([]byte(" "), relayself.MaxRecordBytes), raw...),
		"unknown field": mutate(func(c map[string]any) { c["future"] = 1 }),
		"version":       mutate(func(c map[string]any) { c["v"] = 2 }),
		"binding bit": mutate(func(c map[string]any) {
			b := c["binding"].(map[string]any)
			s := []byte(b["statement"].(string))
			if s[len(s)-1] == '0' {
				s[len(s)-1] = '1'
			} else {
				s[len(s)-1] = '0'
			}
			b["statement"] = string(s)
		}),
		"revoke bit": mutate(func(c map[string]any) {
			v := c["revokes"].([]any)[0].(map[string]any)
			s := []byte(v["statement"].(string))
			s[20] ^= 1
			v["statement"] = string(s)
		}),
		"not-before count": mutate(func(c map[string]any) {
			var nbs []any
			for i := range relayself.MaxNotBefores + 1 {
				d := relayporttest.Device(byte(i))
				nbs = append(nbs, map[string]any{"device": hexFP(d), "at": 1})
			}
			c["not_before"] = nbs
		}),
	}
	for name, b := range cases {
		if err := put(b); !errors.Is(err, relayself.ErrCorrupt) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// (the binding of another device is dropped with a notice, not refused:
	// TestForeignBindingIsDroppedWithANotice)
	if err := put(raw); err != nil {
		t.Fatal(err)
	}
}

func hexFP(fp party.Fingerprint) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, 40)
	for _, b := range fp {
		out = append(out, d[b>>4], d[b&15])
	}
	return string(out)
}

// FuzzDecode: any bytes as the stored record either decode into a state whose
// binding verifies for the device, or are refused; nothing panics.
func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{"v":1}`))
	f.Add([]byte(`{"v":1,"revokes":[],"not_before":[]}`))
	f.Add([]byte(`{"v":1,"binding":{"statement":"00","cose_key":"00"}}`))
	dev := relayporttest.Device(1)
	f.Fuzz(func(t *testing.T, b []byte) {
		st, err := relayself.Decode(b, dev)
		if err != nil {
			return
		}
		if len(st.Revokes) > relayself.MaxPendingRevokes || len(st.NotBefore) > relayself.MaxNotBefores {
			t.Fatal("over a bound")
		}
		if st.Binding != nil && st.Binding.Device != dev {
			t.Fatal("another device's binding decoded")
		}
		if _, err := relayself.Encode(st); err != nil {
			t.Fatalf("a decoded state does not encode: %v", err)
		}
	})
}
