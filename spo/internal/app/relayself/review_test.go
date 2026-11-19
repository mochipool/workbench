package relayself_test

import (
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/relaybinding"
	"github.com/mochipool/workbench/spo/internal/app/relayself"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

func putRecord(t *testing.T, r *rig, st relayself.State) {
	t.Helper()
	b, err := relayself.Encode(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.store.Update(ctx, func(w ports.NamedWriter) error {
		return w.Put(ports.NamedRef{Name: "self", Kind: ports.RelayOwn}, b)
	}); err != nil {
		t.Fatal(err)
	}
}

// A revoke of every device of the key is owed for the longest a binding signed
// by its not-before can live, not only until this device's binding ends: the
// key's other devices may hold bindings that end later.
//
// spec: SPO-Xmailbox-OUT-098
func TestRevokeAllIsOwedForTheMaximumLifetime(t *testing.T) {
	r := newRig(t)
	if _, err := r.svc.Bind(ctx, r.key, 2*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	nb := r.clk.Now().Unix()
	got, err := r.svc.RevokeWallet(ctx, r.key, relaybinding.RevokeTarget{All: true})
	if err != nil {
		t.Fatal(err)
	}
	if want := nb + relaybind.MaxLifetimeSeconds; got.Until != want {
		t.Fatalf("a --all revoke is owed until %d, want %d (not-before plus the maximum lifetime)", got.Until, want)
	}
}

// This device's own not-before is never evicted nor lowered when the table of
// not-befores is full: otherwise the next binding would be signed before its own
// tombstone.
//
// spec: SPO-Xmailbox-OUT-098
func TestOwnNotBeforeIsNeverEvicted(t *testing.T) {
	r := newRig(t)
	self := relayporttest.Device(r.dev)
	nb := map[party.Fingerprint]int64{self: 1000} // the oldest of all
	for i := range relayself.MaxNotBefores - 1 {
		nb[relayporttest.Device(byte(100+i))] = 2000 + int64(i)
	}
	putRecord(t, r, relayself.State{NotBefore: nb})
	if _, err := r.svc.RevokeWallet(ctx, r.key, relaybinding.RevokeTarget{Device: relayporttest.Device(250)}); err != nil {
		t.Fatal(err)
	}
	st := r.state()
	if got, ok := st.NotBefore[self]; !ok || got != 1000 {
		t.Fatalf("this device's not-before is %d (kept %v) after a revoke of another device at the bound", got, ok)
	}
	if len(st.NotBefore) > relayself.MaxNotBefores {
		t.Fatalf("%d not-befores", len(st.NotBefore))
	}
	// the next binding is later than the tombstone this device keeps
	res, err := r.svc.Bind(ctx, r.key, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Binding.From <= 1000 {
		t.Fatalf("a binding from %d not after the own not-before", res.Binding.From)
	}
}

// A record whose binding is another device's (the device rotated before this
// version cleared it) does not make the revokes unreadable: the binding is
// dropped with a notice, the revokes stay. A binding that does not verify for
// the device it names is still a corrupt record.
//
// spec: SPO-Xmailbox-OUT-097
func TestForeignBindingIsDroppedWithANotice(t *testing.T) {
	r := newRig(t)
	if _, err := r.svc.Bind(ctx, r.key, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.RevokeWallet(ctx, r.key, relaybinding.RevokeTarget{Device: relayporttest.Device(4)}); err != nil {
		t.Fatal(err)
	}
	other := r.service(r.store)
	other.Device = relayporttest.Device(2)
	st, err := other.Load(ctx)
	if err != nil {
		t.Fatalf("a record holding another device's binding: %v", err)
	}
	if st.Binding != nil || len(st.Revokes) != 1 {
		t.Fatalf("binding %+v, %d revokes", st.Binding, len(st.Revokes))
	}
	foreignStatus(t, other, relayporttest.Device(r.dev))
}
