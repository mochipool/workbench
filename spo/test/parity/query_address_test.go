package parity

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/fsstore"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/adapters/transferfile"
	"github.com/mochipool/workbench/spo/internal/app/query"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// 01_queryAddress in offline mode against a crafted snapshot. The script's
// output is display only, so the oracle here is the snapshot itself: the facts
// the read model returns are the facts the file holds. Upstream is run to pin
// its exit codes, which the use case turns into one error (an address that is
// not in the file) or into typed refusals (a Handle offline).
//
// spec: SPO-01queryAddress-IN-002, SPO-01queryAddress-MODE-001, SPO-01queryAddress-MODE-002, SPO-01queryAddress-PRE-004,
// spec: SPO-01queryAddress-PRE-006, SPO-01queryAddress-PRE-007, SPO-01queryAddress-OUT-001, SPO-01queryAddress-OUT-002,
// spec: SPO-01queryAddress-IN-004, SPO-01queryAddress-IN-005, SPO-01queryAddress-EXT-001, SPO-01queryAddress-EXT-003,
// spec: SPO-01queryAddress-IN-006, SPO-01queryAddress-IN-001, SPO-01queryAddress-IF-002
func TestQueryAddressOfflineMatchesTheSnapshot(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	dir := e.upstreamWorkspace(t)
	for _, a := range [][]string{{"02_genPaymentAddrOnly.sh", "w", "cli"}, {"03a_genStakingPaymentAddr.sh", "s", "cli"}} {
		if code, out := e.upstreamOut(t, dir, append([]string{"exec"}, a...)...); code != 0 {
			t.Fatalf("upstream %v exited %d\n%s", a, code, out)
		}
	}
	addr := strings.TrimSpace(readFile(t, dir, "w.addr"))
	stake := strings.TrimSpace(readFile(t, dir, "s.staking.addr"))

	writeTransfer(t, dir, addr, fixtureUtxos(true))
	raw, _ := os.ReadFile(filepath.Join(dir, "offlineTransfer.json"))
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var addrs map[string]json.RawMessage
	_ = json.Unmarshal(doc["address"], &addrs)
	addrs[stake] = json.RawMessage(`{"name":"s.staking","type":"stake","date":"Mon, 16 Nov 2026 09:51:02 +0100","used":"no","totalamount":4200,"rewardsJSON":[{"address":"` + stake +
		`","stakeDelegation":{"stakePoolBech32":"pool1ynszxwjunhjc0zm4k7k7udczu2y4leldk3p2sgtazfgu64qrh04"},` +
		`"stakeRegistrationDeposit":2000000,"rewardAccountBalance":4200,"voteDelegation":"alwaysAbstain","govActionDeposits":{}}]}`)
	doc["address"], _ = json.Marshal(addrs)
	b, _ := json.MarshalIndent(doc, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "offlineTransfer.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}

	store, err := fsstore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	file := &transferfile.File{Path: filepath.Join(dir, "offlineTransfer.json")}
	uc := query.QueryAddress{Store: store, Addresses: native.Ledger{}, Utxos: file, Rewards: file, Snapshot: file}

	// Upstream shows the report for the stored name, the address and the stake name; the use case
	// reads the same facts out of the file.
	for _, word := range []string{"w", addr} {
		if code, out := e.upstreamOut(t, dir, "exec", "01_queryAddress.sh", word); code != 0 {
			t.Fatalf("upstream 01_queryAddress %s exited %d\n%s", word, code, stripANSI(out))
		}
		rep, err := uc.Run(ctx, word)
		if err != nil {
			t.Fatalf("port %s: %v", word, err)
		}
		want := map[string]uint64{}
		var total uint64
		for _, u := range fixtureUtxos(true) {
			want[u.hash+"#"+itoa(u.index)] = u.lovelace
			total += u.lovelace
		}
		if rep.Kind != "payment" || rep.Address != addr || rep.TotalLovelace != chain.Lovelace(total) || len(rep.Utxos) != len(want) || rep.Source != transferfile.Source {
			t.Errorf("%s: %+v", word, rep)
		}
		for _, u := range rep.Utxos {
			if want[u.Ref] != uint64(u.Lovelace) {
				t.Errorf("%s: %s holds %d, the snapshot says %d", word, u.Ref, u.Lovelace, want[u.Ref])
			}
		}
		// The assets of the fixture: policy A name "" (1) and "41" (24), policy B "746f6b" (7).
		got := map[string]uint64{}
		for _, a := range rep.Assets {
			got[a.Policy+"."+a.NameHex] = a.Quantity
			if a.Fingerprint == "" || !strings.HasPrefix(a.Fingerprint, "asset1") {
				t.Errorf("fingerprint %q", a.Fingerprint)
			}
		}
		wantAssets := map[string]uint64{policyA + ".": 1, policyA + "." + hex.EncodeToString([]byte("A")): 24, policyB + "." + hex.EncodeToString([]byte("tok")): 7}
		if len(got) != len(wantAssets) {
			t.Errorf("%s: assets %v, want %v", word, got, wantAssets)
		}
		for k, v := range wantAssets {
			if got[k] != v {
				t.Errorf("%s: asset %s: %d, want %d", word, k, got[k], v)
			}
		}
		if !rep.FromSnapshot || rep.SnapshotDate != "Mon, 16 Nov 2026 09:51:02 +0100" || rep.SnapshotUsed {
			t.Errorf("%s: the snapshot's date and used flag are not reported: %+v", word, rep)
		}
	}
	if code, out := e.upstreamOut(t, dir, "exec", "01_queryAddress.sh", "s.staking"); code != 0 {
		t.Fatalf("upstream stake query exited %d\n%s", code, stripANSI(out))
	}
	srep, err := uc.Run(ctx, "s.staking")
	if err != nil || srep.Kind != "stake" || srep.Rewards != 4200 || !srep.FromSnapshot {
		t.Fatalf("port stake: %+v %v", srep, err)
	}
	if d, _ := srep.Deposit.Get(); d != 2_000_000 {
		t.Errorf("deposit %v", srep.Deposit)
	}
	if v, _ := srep.VoteDelegation.Get(); v != "alwaysAbstain" {
		t.Errorf("vote delegation %v", srep.VoteDelegation)
	}
	if p, ok := srep.Pool.Get(); !ok || p.Bech32() != "pool1ynszxwjunhjc0zm4k7k7udczu2y4leldk3p2sgtazfgu64qrh04" {
		t.Errorf("pool %v", srep.Pool)
	}

	// An address that is not in the file. Upstream: the payment branch exits 1, the stake branch
	// exits 0 (SPO-01queryAddress-PRE-006); the use case has one error for both.
	other := t.TempDir()
	copyDir(t, dir, other)
	for _, a := range [][]string{{"02_genPaymentAddrOnly.sh", "x", "cli"}, {"03a_genStakingPaymentAddr.sh", "y", "cli"}} {
		if code, out := e.upstreamOut(t, other, append([]string{"exec"}, a...)...); code != 0 {
			t.Fatalf("upstream %v exited %d\n%s", a, code, out)
		}
	}
	ostore, _ := fsstore.Open(other)
	ouc := query.QueryAddress{Store: ostore, Addresses: native.Ledger{}, Utxos: file, Rewards: file, Snapshot: file}
	if code, _ := e.upstreamOut(t, other, "exec", "01_queryAddress.sh", "x"); code != 1 {
		t.Errorf("upstream, payment address not in the file, exited %d, want 1", code)
	}
	if code, _ := e.upstreamOut(t, other, "exec", "01_queryAddress.sh", "y.staking"); code != 0 {
		t.Errorf("upstream, stake address not in the file, exited %d, want 0", code)
	}
	for _, w := range []string{"x", "y.staking"} {
		if _, err := ouc.Run(ctx, w); !errors.Is(err, query.ErrNotInSnapshot) {
			t.Errorf("port %s: %v", w, err)
		}
	}

	// A Handle needs a connection: upstream refuses offline; the use case does not support Handles.
	if code, _ := e.upstreamOut(t, dir, "exec", "01_queryAddress.sh", "$somehandle"); code != 1 {
		t.Errorf("upstream, a Handle offline, exited %d, want 1", code)
	}
	if _, err := uc.Run(ctx, "$somehandle"); !errors.Is(err, query.ErrAdaHandleUnsupported) {
		t.Errorf("port Handle: %v", err)
	}
	// Neither a name, an address nor a Handle: exit 1 and a typed refusal.
	if code, _ := e.upstreamOut(t, dir, "exec", "01_queryAddress.sh", "nobody"); code != 1 {
		t.Errorf("upstream, an unresolvable argument, exited %d, want 1", code)
	}
	if _, err := uc.Run(ctx, "nobody"); !errors.Is(err, query.ErrUnresolved) {
		t.Errorf("port unresolved: %v", err)
	}
}
