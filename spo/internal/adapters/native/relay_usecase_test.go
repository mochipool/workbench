package native

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/relaybinding"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relaywallet"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

// The use case over the real vault signer and the plain test store (whose index
// derives role histories from the key files): with the clock at the vector's now
// and no tombstone, SignBinding reproduces the "typical" vector of relaybind
// byte for byte. The cold-history refusal at the end is given through a fake
// index (coldIndex), because the plain store keeps no written history; the
// refusal over the production index and a real encrypted store is
// TestVaultSignerOverTheRealStoreAndItsIndexChecksTheRoleHistory.
//
// spec: SPO-Xrelaybind-IF-001, SPO-Xrelaybind-SEC-017, SPO-Xrelaybind-SEC-013
func TestUseCaseWithTheVaultSignerReproducesTheVector(t *testing.T) {
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var vf struct {
		Seed       string `json:"software_key_seed"`
		Statements []struct {
			Name   string `json:"name"`
			Device string `json:"device"`
			From   int64  `json:"from"`
			Until  int64  `json:"until"`
			Sign1  string `json:"sign1_hex"`
			Key    string `json:"cose_key_hex"`
			Hash   string `json:"canonical_hash_hex"`
			ID     string `json:"statement_id_hex"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatal(err)
	}
	seed, _ := hex.DecodeString(vf.Seed)
	st, _ := plainstore.OpenTestnet(t.TempDir())
	putSeededPayment(t, st, "w", seed)
	w := walletOf(t, st, custody.RolePayment, "w")
	idx := labels.NewIndex(st.AnchorStore())
	svc := relaybinding.Service{
		Signer: vaultSigner(st),
		Clock:  fixedClock{time.Unix(1800000000, 0)},
		History: func(ctx context.Context, id identity.Ref) (custody.RoleHistory, bool, error) {
			return ports.RoleHistoryOf(ctx, idx, id)
		},
	}
	for _, v := range vf.Statements {
		if v.Name != "typical" {
			continue
		}
		dev, _ := hex.DecodeString(v.Device)
		var d party.Fingerprint
		copy(d[:], dev)
		res, err := svc.SignBinding(context.Background(), w, d, 0, relaybind.NoTombstone)
		if err != nil {
			t.Fatal(err)
		}
		if res.Binding.From != v.From || res.Binding.Until != v.Until {
			t.Errorf("binding %+v, vector %d to %d", res.Binding, v.From, v.Until)
		}
		if hex.EncodeToString(res.Statement) != v.Sign1 || hex.EncodeToString(res.COSEKey) != v.Key {
			t.Error("the use case's statement is not the vector's")
		}
		if hex.EncodeToString(res.FullHash[:]) != v.Hash || hex.EncodeToString(res.StatementID[:]) != v.ID {
			t.Error("the identifiers are not the vector's")
		}
		// a wallet revoke too, and the cold history refusal through the store's own index
		if _, err := svc.SignWalletRevoke(context.Background(), w, relaybinding.RevokeTarget{All: true}, 1800000000); err != nil {
			t.Errorf("revoke: %v", err)
		}
		svc.History = func(ctx context.Context, id identity.Ref) (custody.RoleHistory, bool, error) {
			return coldIndex{st: st, cold: custody.RoleCommitteeCold}.RoleHistory(ctx, id)
		}
		if _, err := svc.SignBinding(context.Background(), w, d, 0, relaybind.NoTombstone); !errors.Is(err, relaywallet.ErrColdHistory) {
			t.Errorf("cold history: %v", err)
		}
		return
	}
	t.Fatal("no 'typical' vector")
}
