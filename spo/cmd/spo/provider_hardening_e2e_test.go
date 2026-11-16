package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/native/n2c"
	"github.com/mochipool/workbench/spo/internal/adapters/native/n2c/n2ctest"
	"github.com/mochipool/workbench/spo/internal/app/query"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// F6: a node that is the second source passes the sync gate; a web provider
// that is the second source needs a recent tip. Either way the second source
// does not answer, so the read is refused (or goes on only with --single-source).
func TestSecondSourceMustBeSyncedAndFresh(t *testing.T) {
	cfg := koiosSection + "[provider]\norder = \"koios,node\"\nsame_host_ok = true\n"
	r := newOnlineRig(t, cfg)
	r.writeConfig("light", cfg)
	pool := opcertPool(t)
	five := uint64(5)
	r.node.SetOpCertCounter(pool[:], &five)
	r.web.koiosCounter(pool, 5)

	// The node is behind (its tip is hours old): it does not corroborate.
	r.node.SetTipAt(time.Now().Add(-3 * time.Hour))
	out, err := r.run("pool", "opcert", "counter", hex.EncodeToString(pool[:]))
	if err == nil || !strings.Contains(out+err.Error(), "did not answer") || !strings.Contains(out+err.Error(), "synced") {
		t.Fatalf("an unsynced node corroborated: %v\n%s", err, out)
	}
	// Synced: both agree.
	r.syncedNode()
	if out, err = r.run("pool", "opcert", "counter", hex.EncodeToString(pool[:])); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}

	// Node first, Koios second with a tip from hours ago: refused with the reason.
	cfg2 := koiosSection + "[provider]\norder = \"node,koios\"\nsame_host_ok = true\n"
	r2 := newOnlineRig(t, cfg2)
	r2.syncedNode()
	r2.node.SetOpCertCounter(pool[:], &five)
	r2.web.handlers[koiosLoopback] = func(req *http.Request) (int, string) {
		switch req.Method + " " + req.URL.Path {
		case "GET /api/v1/tip":
			return 200, fmt.Sprintf(`[{"epoch_no":1,"abs_slot":2,"block_time":%d}]`, time.Now().Add(-5*time.Hour).Unix())
		case "POST /api/v1/pool_info":
			return 200, fmt.Sprintf(`[{"pool_id_bech32":"%s","op_cert_counter":5}]`, pool.Bech32())
		}
		return 404, `"unexpected"`
	}
	out, err = r2.run("pool", "opcert", "counter", hex.EncodeToString(pool[:]))
	if err == nil || !strings.Contains(out+err.Error(), "its tip is") || !strings.Contains(out+err.Error(), "may be stale") {
		t.Fatalf("a stale web provider corroborated: %v\n%s", err, out)
	}
}

// F7: nothing the node gives the Env can be asserted to a state reader that
// skips the sync gate. The tip, sync, parameters, submission and genesis
// fields hold narrow views of the node that implement only their own port, and
// the state readers are the gated type; the raw client is in no field. Every
// state reader of every field is asked on an unsynced node and refuses.
func TestNodeEnvFieldsHaveNoUngatedStateReader(t *testing.T) {
	node := n2ctest.Start(t)
	node.SetTipAt(time.Now().Add(-6 * time.Hour)) // unsynced
	env := &cli.Env{Mode: cli.ModeOnline, Endpoints: map[string]string{}}
	o := cli.WireOptions{Mode: cli.ModeOnline, Preset: cli.NetworkPreset{Magic: "2"},
		Config: cli.WorkspaceConfig{Network: "preview", Mode: "online", Node: &cli.NodeConfig{Address: node.Path()}}}
	if err := wireNodeFirst(env, o, toConfig(o.Config), io.Discard); err != nil {
		t.Fatal(err)
	}
	defer env.Close()

	// The state-reader ports: a field whose type has any of these methods must
	// be the gated type.
	stateMethods := []string{"Utxos", "ResolveUtxos", "RewardAccount", "PoolState", "PoolInfo", "DRepState", "OpCertCounter",
		"GovActions", "CommitteeMember", "CommitteeMemberByHot", "Constitution", "LastEnacted", "DRepDistribution", "PoolDistribution", "CommitteeComposition"}
	rv := reflect.ValueOf(env).Elem()
	seen := 0
	for i := 0; i < rv.NumField(); i++ {
		f := rv.Field(i)
		if f.Kind() != reflect.Interface || f.IsNil() {
			continue
		}
		dyn := f.Elem().Type()
		if dyn == reflect.TypeOf((*n2c.Client)(nil)) {
			t.Errorf("Env.%s holds the raw node client", rv.Type().Field(i).Name)
		}
		for _, m := range stateMethods {
			if _, ok := dyn.MethodByName(m); ok && dyn != reflect.TypeOf(gatedNode{}) {
				t.Errorf("Env.%s (%s) has the state read %s outside the gate", rv.Type().Field(i).Name, dyn, m)
			}
		}
		seen++
	}
	if seen < 8 {
		t.Fatalf("only %d interface fields were set", seen)
	}
	// And the gate refuses on an unsynced node.
	ctx := context.Background()
	if _, err := env.Utxos.Utxos(ctx, chain.Address("addr_test1")); !errors.Is(err, query.ErrNotSynced) {
		t.Errorf("Utxos: %v", err)
	}
	if _, err := env.Rewards.RewardAccount(ctx, chain.StakeAddress("stake_test1")); !errors.Is(err, query.ErrNotSynced) {
		t.Errorf("RewardAccount: %v", err)
	}
	if _, err := env.Pools.PoolState(ctx, chain.PoolID{}); !errors.Is(err, query.ErrNotSynced) {
		t.Errorf("PoolState: %v", err)
	}
}

type recordingFetcher struct {
	out   *strings.Builder
	calls int
}

func (r *recordingFetcher) Fetch(context.Context, string) ([]byte, error) {
	r.calls++
	r.out.WriteString("[fetch]")
	return []byte("{}"), nil
}

// (b): a fetch of an anchor or pool metadata contacts a host the chain names; the
// host is printed before the first fetch to it, and once.
func TestFetchesAnnounceTheHostBeforeContactingIt(t *testing.T) {
	var out strings.Builder
	inner := &recordingFetcher{out: &out}
	a := &announcing{inner: inner, w: &out, what: "an anchor document"}
	for _, u := range []string{"https://anchors.example/a.json", "https://anchors.example/b.json", "https://other.example/c.json"} {
		if _, err := a.Fetch(context.Background(), u); err != nil {
			t.Fatal(err)
		}
	}
	want := "Fetching an anchor document from \"anchors.example\", a host named on chain (not one you configured).\n[fetch][fetch]" +
		"Fetching an anchor document from \"other.example\", a host named on chain (not one you configured).\n[fetch]"
	if out.String() != want {
		t.Fatalf("%q\nwant %q", out.String(), want)
	}
}

func TestCapabilitiesSayOnlineModeStillFetchesFromChainNamedHosts(t *testing.T) {
	r := newOnlineRig(t, "")
	out, err := r.run("capabilities")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Network reads to hosts the chain names", "including online mode", "prints the host before its first such fetch")
}

// A web provider that answers a harmful-class read alone (the primary) needs a
// recent tip as much as a second source does: a stale tip makes its answer
// Unknown, and the message gives both times and says the local clock may be
// the wrong one.
//
// spec: ADR 0006 (a web source must have a recent tip)
func TestStalePrimaryWebProviderIsUnknownAndNamesBothClocks(t *testing.T) {
	cfg := koiosSection + "[provider]\norder = \"koios,node\"\nsame_host_ok = true\n"
	r := newOnlineRig(t, cfg)
	r.writeConfig("light", cfg)
	r.syncedNode()
	five := uint64(5)
	pool := opcertPool(t)
	r.node.SetOpCertCounter(pool[:], &five)
	serve := func(age time.Duration) {
		r.web.handlers[koiosLoopback] = func(req *http.Request) (int, string) {
			switch req.Method + " " + req.URL.Path {
			case "GET /api/v1/tip":
				return 200, fmt.Sprintf(`[{"epoch_no":1,"abs_slot":2,"block_time":%d}]`, time.Now().Add(-age).Unix())
			case "POST /api/v1/pool_info":
				return 200, fmt.Sprintf(`[{"pool_id_bech32":"%s","op_cert_counter":5}]`, pool.Bech32())
			}
			return 404, `"unexpected"`
		}
	}
	serve(5 * time.Hour)
	out, err := r.run("pool", "opcert", "counter", hex.EncodeToString(pool[:]))
	all := out
	if err != nil {
		all += err.Error()
	}
	if err == nil || !strings.Contains(all, "its tip is") || !strings.Contains(all, "tip time 20") || !strings.Contains(all, "this machine's clock says 20") || !strings.Contains(all, "clock may be wrong") {
		t.Fatalf("a stale primary web provider answered: %v\n%s", err, out)
	}
	serve(30 * time.Second)
	if out, err = r.run("pool", "opcert", "counter", hex.EncodeToString(pool[:])); err != nil {
		t.Fatalf("a fresh primary: %v\n%s", err, out)
	}
}
