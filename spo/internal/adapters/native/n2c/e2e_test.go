package n2c

import (
	"context"
	"testing"
	"time"

	pcommon "github.com/blinklabs-io/gouroboros/protocol/common"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/query"
	"github.com/mochipool/workbench/spo/internal/app/wallet"
)

// The use cases of the app layer run on the client unchanged: this is the
// composition the online mode needs. The address query reads UTxOs, the sync
// state, the reward account and the pool state through one connection.
func TestAddressQueryThroughTheNodeClient(t *testing.T) {
	n := registeredNode(t)
	n.set("system-start", systemStartReply())
	n.set("era-history", eraHistoryReply())
	n.set("chain-point", pcommon.NewPoint(600, fill(1, 32)))
	addr, _ := testAddr(t, fill(0xaa, 28))
	n.setRaw("utxo-by-address", "81"+"a2"+
		txin(0x11, "00")+"82"+addrHex(0xaa)+"1a001e8480"+
		txin(0x22, "01")+"82"+addrHex(0xaa)+"82"+"1a00989680"+"a1581c"+hx(0x77, 28)+"a1"+"44"+"74657374"+"05")
	// The registered pool of the delegation.
	params := "89" + "581c" + hx(0x0f, 28) + "5820" + hx(0x41, 32) + "1a3b9aca00" + "1a0a21fe80" + "d81e" + "82" + "03" + "1864" +
		"581d" + "e0" + hx(0x51, 28) + "d90102" + "81" + "581c" + hx(0x61, 28) + "80" + "f6"
	n.setRaw("pool-state", "81"+"84"+"a1"+"581c"+hx(0x0f, 28)+params+"a0"+"a0"+"a0")

	cfg := n.config()
	cfg.Clock = fixedClock(previewStart.Add(2500*time.Second + 20*time.Second))
	c, err := Dial(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	uc := query.QueryAddress{Addresses: native.Ledger{}, Utxos: c, Rewards: c, Pools: c, Sync: c}
	rep, err := uc.Run(context.Background(), string(addr))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Kind != "payment" || rep.TotalLovelace != 12_000_000 || len(rep.Utxos) != 2 || rep.Source != "node socket preview" {
		t.Fatalf("payment report %+v", rep)
	}
	if len(rep.Assets) != 1 || rep.Assets[0].Quantity != 5 || rep.Assets[0].NameText != "test" {
		t.Fatalf("assets %+v", rep.Assets)
	}

	sa := stakeAddr(t, false, false, fill(9, 28))
	rep, err = uc.Run(context.Background(), string(sa))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Kind != "stake" || rep.Rewards != 1_000_000 {
		t.Fatalf("stake report %+v", rep)
	}
	if d, _ := rep.Deposit.Get(); d != 2_000_000 {
		t.Errorf("deposit %+v", rep.Deposit)
	}
	if v, _ := rep.VoteDelegation.Get(); v != koiosDRep {
		t.Errorf("vote delegation %+v", rep.VoteDelegation)
	}
	if ps, ok := rep.PoolInfo.Get(); !ok || ps.Margin != "0.03" {
		t.Errorf("pool %+v", rep.PoolInfo)
	}

	// A node that is behind refuses the payment query (SPO-01queryAddress-PRE-002).
	n.set("chain-point", pcommon.NewPoint(100, fill(1, 32)))
	if _, err := uc.Run(context.Background(), string(addr)); err == nil {
		t.Fatal("an unsynced node answered a payment query")
	}
}

// The ports compose into the needs of a send: the client is the UTxO reader,
// the parameter reader, the tip reader and the submitter of the online mode.
func TestClientFillsTheSendLovelacesNeeds(t *testing.T) {
	var c *Client
	_ = wallet.SendLovelaces{Utxos: c, Params: c, Tip: c, Submitter: c}
}
