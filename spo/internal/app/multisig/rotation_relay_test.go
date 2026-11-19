package multisig_test

import (
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relaypeer"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
	"github.com/mochipool/workbench/spo/test/multiparty/partyrig"
)

// relayOf is the relay identity a binding of wallet gives the device fp.
func relayOf(t *testing.T, w *partyrig.Workspace, wallet *relayporttest.Wallet, fp party.Fingerprint) *party.RelayIdentity {
	t.Helper()
	now := w.Clock.Now().Unix()
	st := wallet.BindingStatement(fp, now-60, now+3600, false)
	ev, err := relaypeer.Verify(st.Sign1, st.COSEKey, fp, now, relaybind.DefaultPolicy(), relaypeer.NetworkAny)
	if err != nil {
		t.Fatal(err)
	}
	return &ev.Relay
}

// putParty writes a party into the registry directly, as an earlier command
// would have left it.
func putParty(t *testing.T, w *partyrig.Workspace, p party.Party) {
	t.Helper()
	if err := w.Store.Update(ctx, func(wr ports.NamedWriter) error { return w.Registry.Put(wr, p) }); err != nil {
		t.Fatal(err)
	}
}

func sharer(t *testing.T, w *partyrig.Workspace, n byte, wallet *relayporttest.Wallet) party.Party {
	k := relayporttest.DeviceKeysOf(n)
	id := party.Identity{Label: "o", Ed25519: k.Ed25519, X25519: k.X25519, Created: w.Clock.Now().UTC().Truncate(1e9)}
	p := party.Party{Identity: id, Fingerprint: id.Fingerprint(), Name: "share" + string(rune('a'+n)), Roles: []party.Role{party.RoleSigner},
		State: party.StateActive, EnrolledAt: w.Clock.Now().UTC().Truncate(1e9)}
	p.Relay = relayOf(t, w, wallet, p.Fingerprint)
	return p
}

// Accepting a rotation with a binding goes through AcceptRotation, which checks
// the wallet-key claim again in its own transaction, against the registry as it
// is then: a key that became the relay identity of 8 other active parties, or a
// pool id named in a scope, since the binding was shown, is refused and nothing
// changes; otherwise the new identity is enrolled with it.
//
// spec: SPO-Xparty-INV-042, SPO-Xparty-PRE-008
func TestRotationAcceptanceChecksTheClaimInItsTransaction(t *testing.T) {
	wallet := relayporttest.NewWallet(9)
	t.Run("eight others", func(t *testing.T) {
		s := newScene(t, sceneOpt{})
		done, env := s.bobRotates()
		if _, err := s.C.Coordinator().Handle(ctx, partyrig.Received(env, ports.ViaFile)); err != nil {
			t.Fatal(err)
		}
		a := s.coordTyped(done.New)
		a.Relay = relayOf(t, s.C, wallet, done.New) // checked and shown with 7 others
		for i := range relaypeer.MaxDevicesPerWalletKey {
			putParty(t, s.C, sharer(t, s.C, byte(40+i), wallet)) // the eighth arrives meanwhile
		}
		if _, err := s.C.Node().AcceptRotation(ctx, "bob", a); !errors.Is(err, relaypeer.ErrTooManyDevices) {
			t.Fatalf("accepted with 8 other parties on the key: %v", err)
		}
		if p := partyNamed(t, s.C, "bob"); p.Fingerprint == done.New {
			t.Fatal("the refused acceptance changed the registry")
		}
	})
	t.Run("pool id", func(t *testing.T) {
		s := newScene(t, sceneOpt{})
		done, env := s.bobRotates()
		if _, err := s.C.Coordinator().Handle(ctx, partyrig.Received(env, ports.ViaFile)); err != nil {
			t.Fatal(err)
		}
		a := s.coordTyped(done.New)
		a.Relay = relayOf(t, s.C, wallet, done.New)
		var pool chain.PoolID
		copy(pool[:], wallet.Key[:])
		other := sharer(t, s.C, 60, relayporttest.NewWallet(10))
		other.Scope = party.Scope{Pools: []string{pool.Bech32()}}
		putParty(t, s.C, other)
		if _, err := s.C.Node().AcceptRotation(ctx, "bob", a); !errors.Is(err, relaypeer.ErrColdKey) {
			t.Fatalf("accepted a wallet key that is a pool id in a scope: %v", err)
		}
	})
	t.Run("recorded", func(t *testing.T) {
		s := newScene(t, sceneOpt{})
		done, env := s.bobRotates()
		if _, err := s.C.Coordinator().Handle(ctx, partyrig.Received(env, ports.ViaFile)); err != nil {
			t.Fatal(err)
		}
		a := s.coordTyped(done.New)
		a.Relay = relayOf(t, s.C, wallet, done.New)
		for i := range relaypeer.MaxDevicesPerWalletKey - 1 {
			putParty(t, s.C, sharer(t, s.C, byte(40+i), wallet))
		}
		// the old identity had the same wallet key: it becomes revoked in this
		// transaction, so it is not one of the 8
		oldFP := partyNamed(t, s.C, "bob").Fingerprint
		if err := s.C.Store.Update(ctx, func(w ports.NamedWriter) error {
			_, err := s.C.Registry.SetRelay(w, "bob", relayOf(t, s.C, wallet, oldFP))
			return err
		}); err != nil {
			t.Fatal(err)
		}
		res, err := s.C.Node().AcceptRotation(ctx, "bob", a)
		if err != nil {
			t.Fatal(err)
		}
		if p := partyNamed(t, s.C, "bob"); p.Relay == nil || p.Relay.WalletKey != party.WalletKey(wallet.Key) || res.Party.Fingerprint != done.New {
			t.Fatalf("the new identity's relay identity: %+v", p.Relay)
		}
	})
}
