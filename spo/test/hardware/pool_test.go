package hardware_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/poolops"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/world"
)

const hwPoolDescriptor = `{
  "poolName": "mypool",
  "poolOwner": [
    {"ownerName": "hw", "ownerWitness": "local"}
  ],
  "poolRewards": "hw",
  "poolPledge": "100000000000",
  "poolCost": "340000000",
  "poolMargin": "0.10",
  "poolRelays": [
    {"relayType": "dns", "relayEntry": "relay.example.org", "relayPort": "3001"}
  ],
  "poolMetaName": "My Pool",
  "poolMetaDescription": "A pool for tests",
  "poolMetaTicker": "MYPL",
  "poolMetaHomepage": "https://example.org",
  "poolMetaUrl": "https://example.org/mypool.metadata.json",
  "poolExtendedMetaUrl": "",
  "---": "--- DO NOT EDIT OR DELETE BELOW THIS LINE ---"
}
`

type noPools struct{}

func (noPools) Source() chain.Source { return "fake chain" }
func (noPools) PoolState(context.Context, chain.PoolID) (chain.Reading[chain.PoolState], error) {
	return chain.None[chain.PoolState](), nil
}

// A pool registration whose cold key, paying key and owner stake key are all on
// one Ledger (05c): the registration is canonicalised before it is shown, the
// device witnesses it three times, only the registration certificate is attached
// (a hardware wallet is involved, SPO-05c-INV-006), and the transaction that was
// submitted carries the three witnesses.
//
// spec: SPO-05c-EXT-004, SPO-05c-EXT-006, SPO-05c-INV-006, SPO-05c-EXT-003, SPO-05c-PRE-009
func TestPoolRegistrationWithLedgerColdKeyPayerAndOwner(t *testing.T) {
	ctx := context.Background()
	w := world.New(t)
	w.UseHardware("Ledger", "8.0.8")
	w.Bodies = world.LegacyInputs{Ledger: w.Ledger}
	w.Chain.Params.StakePoolDeposit, w.Chain.Params.MinPoolCost, w.Chain.Params.PoolRetireMaxEpoch = 500_000_000, 170_000_000, 18
	acc := account(t, w, "hw", custody.PlaceHardware, 900_000_000)
	cold, err := (poolops.GenerateColdKeys{Store: w.Store, KeyGen: native.SoftwareKeys{}, Hardware: w.Exporter()}).
		Run(ctx, poolops.GenerateColdKeysRequest{Pool: "mypool", Place: custody.PlaceHardware})
	if err != nil {
		t.Fatal(err)
	}
	// The owner's delegation certificate (05b) is a file the registration reads even
	// when it is not attached.
	skEnv, err := pool.ParseEnvelope(acc.StakeVKey)
	if err != nil {
		t.Fatal(err)
	}
	skRaw, _ := skEnv.Key32()
	dc, err := w.Ledger.BuildCertificate(stake.Spec{Kind: stake.CertPoolDelegation, Stake: stake.KeyHash(txbuild.HashKey(skRaw)), Pool: cold.PoolID})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Store.Update(ctx, func(wr ports.Writer) error {
		return wr.Put(ports.Ref{Name: "hw", Kind: ports.DelegCert}, dc.Envelope)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := (poolops.GenerateVrfKeys{Store: w.Store, KeyGen: native.KeyGen{}}).Run(ctx, poolops.GenerateVrfKeysRequest{Pool: "mypool"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w.Dir, "mypool.pool.json"), []byte(hwPoolDescriptor), 0o600); err != nil {
		t.Fatal(err)
	}
	gen := poolops.GeneratePoolCertificate{Store: w.Store, Params: w.Chain, Certs: w.Ledger, Hasher: w.Ledger, Clock: fixedClock{}, NetworkID: w.Network}
	if _, err := gen.Run(ctx, poolops.GenerateRequest{Pool: "mypool"}); err != nil {
		t.Fatal(err)
	}
	uc := poolops.RegisterPool{Store: w.Store, Addresses: w.Ledger, Params: w.Chain, Tip: w.Chain, Utxos: w.Chain, Pipeline: w.Pipeline(),
		PoolCerts: w.Ledger, StakeCerts: w.Ledger, TxIDs: w.Ledger, Hasher: w.Ledger, Clock: fixedClock{},
		Pools: noPools{}, Sources: poolops.SingleSourceAcknowledged, OnSingle: noopSingle}
	res, err := uc.Run(ctx, poolops.RegisterRequest{Pool: "mypool", Payer: "hw.payment"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Submitted || res.Type != pool.PoolRegistration || len(w.Chain.Submitted) != 1 {
		t.Fatalf("%+v", res)
	}
	ws, err := (native.TxViewer{}).Witnesses(w.Chain.Submitted[0])
	if err != nil || len(ws) != 3 {
		t.Fatalf("witnesses %d %v", len(ws), err)
	}
	coldEnv, _ := pool.ParseEnvelope(cold.VKey)
	coldRaw, _ := coldEnv.Key32()
	found := false
	for _, x := range ws {
		found = found || string(x.VKey[:]) == string(coldRaw)
	}
	if !found {
		t.Error("the pool's cold key did not witness the registration")
	}
	if n := w.HW.Count("transaction", "witness"); n != 3 {
		t.Errorf("%d witness calls: %v", n, w.HW.Calls())
	}
	// The body shown was the canonical one: no transform follows the first witness.
	seen := false
	for _, c := range w.HW.Calls() {
		if len(c) > 1 && c[0] == "transaction" && c[1] == "witness" {
			seen = true
		}
		if len(c) > 1 && c[0] == "transaction" && c[1] == "transform" && seen {
			t.Error("a transform after a witness")
		}
	}
	if strings.Contains(fmt.Sprint(w.HW.Calls()), "--allow-unrestricted-mode") {
		t.Error("unrestricted mode was implied")
	}
}
