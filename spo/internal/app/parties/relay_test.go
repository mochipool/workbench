package parties_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/app/parties"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relaypeer"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

// histories is a role-history source: a key hash maps to its recorded roles.
type histories map[[28]byte][]custody.Role

func (h histories) of(_ context.Context, id identity.Ref) (custody.RoleHistory, bool, error) {
	var k [28]byte
	copy(k[:], id.Hash())
	roles, ok := h[k]
	if !ok {
		return custody.RoleHistory{}, false, nil
	}
	rh, err := custody.NewRoleHistory(id, roles[0])
	for _, r := range roles[1:] {
		rh, _ = rh.With(r)
	}
	return rh, true, err
}

func (w *ws) relayCheck(h histories) parties.RelayCheck {
	return parties.RelayCheck{History: h.of, Network: 0, PoolIDs: func(context.Context) (map[[28]byte]bool, error) { return nil, nil }}
}

// A wallet key that is one of this workspace's own pool ids is refused at
// enrollment even when the pool is known only by its id (no cold key, so no
// role history of it here), and the check refuses every binding without a
// source of the own pool ids.
//
// spec: SPO-Xparty-PRE-008
func TestEnrollRefusesAnOwnPoolID(t *testing.T) {
	a, b := newWS(t), newWS(t)
	a.init("alpha")
	rb := b.init("beta")
	now := a.clk.t.Unix()
	wal := relayporttest.NewWallet(4)
	uc := a.enroll()
	uc.Relay = a.relayCheck(nil)
	uc.Relay.PoolIDs = func(context.Context) (map[[28]byte]bool, error) { return map[[28]byte]bool{wal.Key: true}, nil }
	req := parties.EnrollRequest{Document: rb.Document, Name: "beta", Roles: []party.Role{party.RoleSigner}, Confirmation: typed(rb.Fingerprint),
		Binding: a.bindingOf(wal, rb.Fingerprint, now-60, now+3600)}
	if _, err := uc.Run(ctx, req); !errors.Is(err, relaypeer.ErrColdKey) {
		t.Fatalf("the workspace's own pool id: %v", err)
	}
	if _, err := uc.InspectBinding(ctx, rb.Document, req.Binding); !errors.Is(err, relaypeer.ErrColdKey) {
		t.Fatalf("the workspace's own pool id (inspect): %v", err)
	}
	uc.Relay.PoolIDs = nil
	if _, err := uc.Run(ctx, req); !errors.Is(err, parties.ErrNoPoolSource) {
		t.Fatalf("no pool-id source: %v", err)
	}
}

func (w *ws) bindingOf(wallet *relayporttest.Wallet, fp party.Fingerprint, from, until int64) *parties.BindingEvidence {
	st := wallet.BindingStatement(fp, from, until, false)
	return &parties.BindingEvidence{Statement: st.Sign1, Key: st.COSEKey}
}

func (w *ws) listed(name string) party.Party {
	w.t.Helper()
	var p party.Party
	if err := w.store.View(ctx, func(r ports.NamedReader) error {
		var err error
		p, err = w.reg.ByName(r, name)
		return err
	}); err != nil {
		w.t.Fatal(err)
	}
	return p
}

// Enrollment with the party's binding records its wallet key with the evidence;
// Inspect shows the evidence (key hash, window, address form) before anything is
// typed; and the typed groups stay required: a valid binding with no or wrong
// groups enrolls nothing.
//
// spec: SPO-Xparty-PRE-008, SPO-Xparty-PR-007, SPO-Xparty-OUT-007
func TestEnrollWithBindingEvidence(t *testing.T) {
	a, b := newWS(t), newWS(t)
	a.init("alpha")
	rb := b.init("beta")
	now := a.clk.t.Unix()
	wal := relayporttest.NewWallet(4)
	ev := a.bindingOf(wal, rb.Fingerprint, now-60, now+30*24*3600)
	uc := a.enroll()
	uc.Relay = a.relayCheck(nil)
	view, err := uc.InspectBinding(ctx, rb.Document, ev)
	if err != nil {
		t.Fatal(err)
	}
	if view.WalletKey != party.WalletKey(wal.Key) || view.From != now-60 || view.Until != now+30*24*3600 || view.Part != relaybind.PartKeyHash || len(view.Shared) != 0 {
		t.Fatalf("view %+v", view)
	}
	req := parties.EnrollRequest{Document: rb.Document, Name: "beta", Roles: []party.Role{party.RoleSigner}, Binding: ev}
	for _, c := range []string{"", "aaaa-aaaa-aaaa-aaaa"} {
		r := req
		r.Confirmation = c
		if _, err := uc.Run(ctx, r); !errors.Is(err, party.ErrConfirmation) {
			t.Fatalf("typed %q with a valid binding: %v", c, err)
		}
	}
	req.Confirmation = typed(rb.Fingerprint)
	p, err := uc.Run(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if p.Relay == nil || p.Relay.WalletKey != party.WalletKey(wal.Key) {
		t.Fatalf("enrolled %+v", p.Relay)
	}
	if got := a.listed("beta"); got.Relay == nil || got.Relay.Device != rb.Fingerprint {
		t.Fatalf("stored %+v", got.Relay)
	}
}

// The hostile bindings at enrollment: another device's, expired, not yet valid,
// forged, on another network, a cold or other-role key of this store, a pool id,
// and an evidence check with no history source. Nothing is enrolled.
//
// spec: SPO-Xparty-PRE-008
func TestEnrollRefusesBadEvidence(t *testing.T) {
	a, b, c := newWS(t), newWS(t), newWS(t)
	a.init("alpha")
	rb := b.init("beta")
	rc := c.init("gamma")
	now := a.clk.t.Unix()
	wal := relayporttest.NewWallet(4)
	cold := relayporttest.NewWallet(5)
	drep := relayporttest.NewWallet(6)
	hist := histories{cold.Key: {custody.RolePayment, custody.RolePoolCold}, drep.Key: {custody.RoleDRep}}
	main := wal.BindingStatementAt(wal.EnterpriseAddress(1), rb.Fingerprint, now-60, now+3600)
	forged := a.bindingOf(wal, rb.Fingerprint, now-60, now+3600)
	forged.Statement[len(forged.Statement)-1] ^= 1
	cases := map[string]struct {
		ev   *parties.BindingEvidence
		want error
	}{
		"another device's":   {a.bindingOf(wal, rc.Fingerprint, now-60, now+3600), relaybind.ErrDeviceMismatch},
		"expired":            {a.bindingOf(wal, rb.Fingerprint, now-7200, now-1), relaybind.ErrExpired},
		"not yet valid":      {a.bindingOf(wal, rb.Fingerprint, now+600, now+7200), relaybind.ErrNotYetValid},
		"forged":             {forged, relaybind.ErrBadSignature},
		"mainnet address":    {&parties.BindingEvidence{Statement: main.Sign1, Key: main.COSEKey}, relaypeer.ErrNetwork},
		"cold history":       {a.bindingOf(cold, rb.Fingerprint, now-60, now+3600), relaypeer.ErrColdKey},
		"drep history":       {a.bindingOf(drep, rb.Fingerprint, now-60, now+3600), relaypeer.ErrColdKey},
		"empty":              {&parties.BindingEvidence{}, relaypeer.ErrTooLarge},
		"oversize":           {&parties.BindingEvidence{Statement: make([]byte, 600), Key: []byte{1}}, relaypeer.ErrTooLarge},
		"key of a statement": {&parties.BindingEvidence{Statement: wal.COSEKey(), Key: wal.COSEKey()}, relaypeer.ErrEvidence},
	}
	for name, cs := range cases {
		uc := a.enroll()
		uc.Relay = a.relayCheck(hist)
		_, err := uc.Run(ctx, parties.EnrollRequest{Document: rb.Document, Name: "beta", Roles: []party.Role{party.RoleSigner}, Confirmation: typed(rb.Fingerprint), Binding: cs.ev})
		if !errors.Is(err, cs.want) {
			t.Errorf("%s: %v, want %v", name, err, cs.want)
		}
		if _, err := uc.InspectBinding(ctx, rb.Document, cs.ev); !errors.Is(err, cs.want) {
			t.Errorf("%s (inspect): %v", name, err)
		}
	}
	// a pool id named in a scope is a cold key hash
	var pool chain.PoolID
	copy(pool[:], wal.Key[:])
	uc := a.enroll()
	uc.Relay = a.relayCheck(nil)
	if _, err := uc.Run(ctx, parties.EnrollRequest{Document: rc.Document, Name: "gamma", Roles: []party.Role{party.RoleCoordinator}, KeyRoles: []custody.Role{custody.RoleStake},
		Pools: []string{pool.Bech32()}, Confirmation: typed(rc.Fingerprint)}); err != nil {
		t.Fatal(err)
	}
	if _, err := uc.Run(ctx, parties.EnrollRequest{Document: rb.Document, Name: "beta", Roles: []party.Role{party.RoleSigner}, Confirmation: typed(rb.Fingerprint),
		Binding: a.bindingOf(wal, rb.Fingerprint, now-60, now+3600)}); !errors.Is(err, relaypeer.ErrColdKey) {
		t.Errorf("a pool id: %v", err)
	}
	// no history source: the cold-key rule cannot be checked, so nothing is taken
	uc = a.enroll()
	if _, err := uc.Run(ctx, parties.EnrollRequest{Document: rb.Document, Name: "beta", Roles: []party.Role{party.RoleSigner}, Confirmation: typed(rb.Fingerprint),
		Binding: a.bindingOf(wal, rb.Fingerprint, now-60, now+3600)}); !errors.Is(err, parties.ErrNoHistory) {
		t.Errorf("no history source: %v", err)
	}
	if ps, _ := (parties.List{Store: a.store, Registry: a.reg}).Run(ctx); len(ps) != 1 {
		t.Fatalf("enrolled %d parties, want only gamma", len(ps))
	}
}

// Updating a party's relay identity asks for the typed groups again, refuses an
// older binding of the same key, takes a newer one or one of another key, and
// clears it.
//
// spec: SPO-Xparty-PR-007, SPO-Xparty-PRE-008
func TestSetPeerRelay(t *testing.T) {
	a, b := newWS(t), newWS(t)
	a.init("alpha")
	rb := b.init("beta")
	now := a.clk.t.Unix()
	wal := relayporttest.NewWallet(4)
	uc := a.enroll()
	uc.Relay = a.relayCheck(nil)
	if _, err := uc.Run(ctx, parties.EnrollRequest{Document: rb.Document, Name: "beta", Roles: []party.Role{party.RoleSigner}, Confirmation: typed(rb.Fingerprint),
		Binding: a.bindingOf(wal, rb.Fingerprint, now-60, now+3600)}); err != nil {
		t.Fatal(err)
	}
	set := parties.SetPeerRelay{Store: a.store, Registry: a.reg, SetRelay: a.reg.SetRelay, Clock: a.clk, Relay: a.relayCheck(nil)}
	newer := a.bindingOf(wal, rb.Fingerprint, now-30, now+7200)
	if _, err := set.Run(ctx, "beta", "aaaa-aaaa-aaaa-aaaa", newer); !errors.Is(err, party.ErrConfirmation) {
		t.Fatalf("wrong groups: %v", err)
	}
	if _, err := set.Run(ctx, "beta", typed(rb.Fingerprint), newer); err != nil {
		t.Fatal(err)
	}
	if got := a.listed("beta"); got.Relay.From != now-30 {
		t.Fatalf("not replaced: %+v", got.Relay)
	}
	older := a.bindingOf(wal, rb.Fingerprint, now-60, now+3600)
	if _, err := set.Run(ctx, "beta", typed(rb.Fingerprint), older); !errors.Is(err, relaypeer.ErrOlder) {
		t.Fatalf("a replayed older binding: %v", err)
	}
	moved := a.bindingOf(relayporttest.NewWallet(7), rb.Fingerprint, now-60, now+3600)
	if _, err := set.Run(ctx, "beta", typed(rb.Fingerprint), moved); err != nil {
		t.Fatalf("another wallet key: %v", err)
	}
	if _, err := set.Run(ctx, "beta", typed(rb.Fingerprint), nil); err != nil {
		t.Fatal(err)
	}
	if got := a.listed("beta"); got.Relay != nil {
		t.Fatalf("not cleared: %+v", got.Relay)
	}
	if _, err := set.Run(ctx, "nobody", "x", nil); !errors.Is(err, ports.ErrNotFound) {
		t.Fatalf("unknown party: %v", err)
	}
}

// A recorded relay identity that no longer verifies is repaired by any binding
// that passes, an older one of the same key included: its own from is not
// trusted to compare with.
//
// spec: SPO-Xparty-PRE-008, SPO-Xparty-OUT-007
func TestSetPeerRelayRepairsAnUnverifiedIdentity(t *testing.T) {
	a, b := newWS(t), newWS(t)
	a.init("alpha")
	rb := b.init("beta")
	now := a.clk.t.Unix()
	wal := relayporttest.NewWallet(4)
	uc := a.enroll()
	uc.Relay = a.relayCheck(nil)
	if _, err := uc.Run(ctx, parties.EnrollRequest{Document: rb.Document, Name: "beta", Roles: []party.Role{party.RoleSigner}, Confirmation: typed(rb.Fingerprint),
		Binding: a.bindingOf(wal, rb.Fingerprint, now-30, now+3600)}); err != nil {
		t.Fatal(err)
	}
	ref := ports.NamedRef{Name: "all", Kind: ports.PartyRecords}
	if err := a.store.Update(ctx, func(w ports.NamedWriter) error {
		raw, err := w.Get(ref)
		if err != nil {
			return err
		}
		i := bytes.Index(raw, []byte(`"statement":"`)) + len(`"statement":"`) + 200
		raw = bytes.Clone(raw)
		if raw[i] == '0' {
			raw[i] = '1'
		} else {
			raw[i] = '0'
		}
		return w.Put(ref, raw)
	}); err != nil {
		t.Fatal(err)
	}
	if got := a.listed("beta"); got.Relay == nil || got.Relay.Unverified == "" {
		t.Fatalf("not marked unverified: %+v", got.Relay)
	}
	set := parties.SetPeerRelay{Store: a.store, Registry: a.reg, SetRelay: a.reg.SetRelay, Clock: a.clk, Relay: a.relayCheck(nil)}
	older := a.bindingOf(wal, rb.Fingerprint, now-60, now+3600)
	if _, err := set.Run(ctx, "beta", typed(rb.Fingerprint), older); err != nil {
		t.Fatalf("repair with an older binding of the same key: %v", err)
	}
	if got := a.listed("beta"); got.Relay == nil || got.Relay.Unverified != "" || got.Relay.From != now-60 {
		t.Fatalf("after the repair: %+v", got.Relay)
	}
}

// One wallet key may be the relay identity of at most 8 active parties; the
// evidence of the others is shown.
//
// spec: SPO-Xparty-PRE-008, SPO-Xparty-PR-007
func TestSharedWalletKeyIsShownAndCapped(t *testing.T) {
	a := newWS(t)
	a.init("alpha")
	now := a.clk.t.Unix()
	wal := relayporttest.NewWallet(4)
	uc := a.enroll()
	uc.Relay = a.relayCheck(nil)
	for i := range relaypeer.MaxDevicesPerWalletKey + 1 {
		o := newWS(t)
		ro := o.init("o")
		ev := a.bindingOf(wal, ro.Fingerprint, now-60, now+3600)
		view, verr := uc.InspectBinding(ctx, ro.Document, ev)
		_, err := uc.Run(ctx, parties.EnrollRequest{Document: ro.Document, Name: "p" + string(rune('a'+i)), Roles: []party.Role{party.RoleSigner}, Confirmation: typed(ro.Fingerprint), Binding: ev})
		switch {
		case i < relaypeer.MaxDevicesPerWalletKey:
			if err != nil || verr != nil || len(view.Shared) != i {
				t.Fatalf("party %d: %v %v shared %v", i, err, verr, view.Shared)
			}
		default:
			if !errors.Is(err, relaypeer.ErrTooManyDevices) || !errors.Is(verr, relaypeer.ErrTooManyDevices) {
				t.Fatalf("the ninth: %v / %v", err, verr)
			}
		}
	}
}
