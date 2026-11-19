package native

import (
	"context"
	"errors"
	"path/filepath"
	"runtime/debug"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/sqlitestore"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relaywallet"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
	"github.com/mochipool/workbench/spo/internal/ports/porttest"
)

// The vault signer over the REAL encrypted store and its production index
// (labels.Index.RoleHistory, the stored record written by labels.RecordRole): a
// key with a cold role, or any other role, in its history is refused, a key the
// store has no history of is refused, and a payment-only (and a payment-and-stake)
// history signs. Plain run only: this package opens a real store, so no -race.
//
// spec: SPO-Xrelaybind-SEC-013, SPO-Xrelaybind-SEC-019, SPO-Xrelaybind-SEC-020
func TestVaultSignerOverTheRealStoreAndItsIndexChecksTheRoleHistory(t *testing.T) {
	// every Open derives a key with 256 MiB of Argon2id memory
	old := debug.SetMemoryLimit(512 << 20)
	defer debug.SetMemoryLimit(old)
	ctx := context.Background()
	const pass = "native relay real store passphrase"
	path := filepath.Join(t.TempDir(), "ws.db")
	rk, err := sqlitestore.Init(path, secret.Take([]byte(pass)))
	if err != nil {
		t.Fatal(err)
	}
	rk.Destroy()
	s, err := sqlitestore.Open(path, secret.Take([]byte(pass)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetColdSource(&sqlitestore.ColdSource{Passphrase: func(context.Context, bool) (*secret.Buffer, error) {
		return secret.Take([]byte("cold sub-key passphrase")), nil
	}})
	named := labels.Named(s)

	newKey := func(name string, extra ...custody.Role) relaywallet.WalletKey {
		t.Helper()
		pair, err := SoftwareKeys{}.GeneratePayment(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer pair.SKey.Destroy()
		if err := named.Update(ctx, func(w ports.NamedWriter) error {
			if err := w.Put(ports.NamedRef{Name: name, Kind: ports.AddrVKey}, pair.VKey); err != nil {
				return err
			}
			return w.PutSecret(ports.NamedRef{Name: name, Kind: ports.AddrSKey}, pair.SKey)
		}); err != nil {
			t.Fatal(err)
		}
		ref := porttest.Key(t, named, custody.RolePayment, name)
		for _, role := range extra {
			if err := s.Update(ctx, func(w ports.Writer) error { return labels.RecordRole(w, ref.Identity, role) }); err != nil {
				t.Fatalf("record %s: %v", role, err)
			}
		}
		w, err := relaywallet.FromRef(ref)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	signer := VaultSignatures{VaultSigner{Vault: s}} // the index is labels.NewIndex(s), the production one
	b := relaybind.Binding{Device: fp(1), From: 1000, Until: 1000 + relaybind.DefaultLifetimeSeconds}

	// payment only, and payment and stake: signs
	pay := newKey("pay")
	for name, w := range map[string]relaywallet.WalletKey{"payment only": pay, "payment and stake": newKey("both", custody.RoleStake)} {
		sm, err := signer.SignRelayBinding(ctx, w, b)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		verifyBinding(t, sm, b.Device, 1000)
	}
	// another role, or a cold one, in the history: refused, nothing returned
	for _, role := range []custody.Role{custody.RoleDRep, custody.RoleCommitteeHot, custody.RolePolicy, custody.RoleKES, custody.RolePoolCold, custody.RoleCommitteeCold} {
		w := newKey("k-"+string(role), role)
		sm, err := signer.SignRelayBinding(ctx, w, b)
		want := relaywallet.ErrOtherRoleHistory
		if role.IsCold() {
			want = relaywallet.ErrColdHistory
		}
		if !errors.Is(err, want) || sm.Sign1 != nil || sm.Key != nil {
			t.Errorf("history with %s: %v", role, err)
		}
		if sm, err := signer.SignRelayRevoke(ctx, w, relaybind.Revoke{All: true, NotBefore: 5}); !errors.Is(err, want) || sm.Sign1 != nil {
			t.Errorf("revoke, history with %s: %v", role, err)
		}
	}
	// a key the store has no history of: refused with ErrNoHistory, before any key is opened
	nobody, err := identity.KeyHashOf(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	none, err := relaywallet.FromRef(custody.KeyRef{Role: custody.RolePayment, Identity: nobody})
	if err != nil {
		t.Fatal(err)
	}
	if _, known, err := labels.NewIndex(s).RoleHistory(ctx, nobody); err != nil || known {
		t.Fatalf("the index knows a history of nobody: %v %v", known, err)
	}
	if sm, err := signer.SignRelayBinding(ctx, none, b); !errors.Is(err, relaywallet.ErrNoHistory) || sm.Sign1 != nil {
		t.Errorf("a key with no history: %v", err)
	}
}
