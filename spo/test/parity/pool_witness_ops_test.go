package parity

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/poolops"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
)

type yesApprover struct{ shown []party.TxView }

func (a *yesApprover) ApproveSigning(_ context.Context, _ string, v party.TxView) (bool, error) {
	a.shown = append(a.shown, v)
	return true, nil
}

// The signer's side of 05d against upstream's script, on the transfer file
// upstream's 05c wrote for an external owner: `sign` gives the same
// `signedWitness` (an Ed25519 signature is deterministic), refuses the same
// way once signed, and `info` and `clear` leave the descriptor in the same
// state (upstream's `clear` leaves it unlocked at 0600, the port locked at
// 0400: SPO-05d-OUT-005 is not reproduced).
//
// spec: SPO-05d-EXT-002, SPO-05d-OUT-001, SPO-05d-OUT-002, SPO-05d-PRE-004, SPO-05d-PRE-006, SPO-05d-PR-001, SPO-05d-OUT-005, SPO-05d-PRE-012, SPO-05d-PRE-013, SPO-05d-INV-002, SPO-05d-IF-003
func TestPoolWitnessSignInfoClearMatchUpstream(t *testing.T) {
	e := setup(t)
	b := e.poolBase(t)
	r := e.registerBoth(t, b, poolDescriptor([]string{"own1", "own2"}, map[string]string{"own2": "external"}, ""))
	if code := e.upstreamAnswers(t, r.up, "y\ny\nn\nn\n", "05c_regStakepoolCert.sh", "mypool", "w.payment"); code != 1 {
		t.Fatalf("upstream 05c exited %d, want 1 (a missing witness)", code)
	}
	matches, _ := filepath.Glob(filepath.Join(r.up, "mypool_own2_*.witness"))
	if len(matches) != 1 {
		t.Fatalf("upstream wrote %v", matches)
	}
	name := filepath.Base(matches[0])
	original, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	var uf struct {
		ID  int64  `json:"id"`
		TTL uint64 `json:"ttl"`
	}
	if err := json.Unmarshal(original, &uf); err != nil {
		t.Fatal(err)
	}
	tipSlot := uf.TTL - 100000

	// upstream: info (an incomplete collection exits 0), sign, and sign again (exit 1).
	if code := e.upstream(t, r.up, "exec", "05d_poolWitness.sh", "info", "mypool"); code != 0 {
		t.Errorf("upstream info exited %d", code)
	}
	if code := e.upstream(t, r.up, "exec", "05d_poolWitness.sh", "sign", name, "own2"); code != 0 {
		t.Fatalf("upstream 05d sign exited %d", code)
	}
	if code := e.upstream(t, r.up, "exec", "05d_poolWitness.sh", "sign", name, "own2"); code != 1 {
		t.Errorf("upstream signed twice, exit %d", code)
	}
	upSigned, _ := os.ReadFile(filepath.Join(r.up, name))

	// the port opens the same collection (same clock second, same tip), then
	// signs the unsigned original with the port workspace's keys
	if _, err := r.goRegister(t, tipSlot, 0, time.Unix(uf.ID, 0), func(uc *poolops.RegisterPool) { uc.AllowPending = true; uc.Attach = nil }); err != nil {
		t.Fatal(err)
	}
	store, _, led, tip, clock := e.poolKit(t, r.port, tipSlot, 0, time.Now())
	appr := &yesApprover{}
	sign := poolops.SignWitnessFile{Store: store, Tip: tip, Clock: clock, Viewer: native.TxViewer{}, TxIDs: led,
		Signers: native.Signers{Vault: store}, Approver: appr, NetworkMagic: 2}
	res, err := sign.Run(bg, poolops.SignRequest{File: original, Key: "./own2"})
	if err != nil {
		t.Fatal(err)
	}
	if len(appr.shown) != 1 || len(appr.shown[0].Certificates) == 0 {
		t.Errorf("the signer was shown %+v", appr.shown)
	}
	field := func(b []byte, k string) string {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		return string(m[k])
	}
	if field(res.File, "signedWitness") != field(upSigned, "signedWitness") {
		t.Errorf("signedWitness differs\n  upstream: %s\n  port:     %s", field(upSigned, "signedWitness"), field(res.File, "signedWitness"))
	}
	for _, k := range []string{"id", "ttl", "type", "signing-name", "signing-vkey", "txBody", "poolMetaTicker"} {
		if field(res.File, k) != field(upSigned, k) {
			t.Errorf("%s differs", k)
		}
	}
	if ds := field(res.File, "date-signed"); !strings.Contains(ds, "20") || ds == "{}" {
		t.Errorf("date-signed %s", ds)
	}
	if _, err := sign.Run(bg, poolops.SignRequest{File: res.File, Key: "own2"}); err == nil {
		t.Error("the port signed a signed file")
	}
	if _, err := sign.Run(bg, poolops.SignRequest{File: original, Key: "own1"}); err == nil {
		t.Error("the port signed with the wrong key")
	}
	if code := e.upstream(t, r.up, "exec", "05d_poolWitness.sh", "sign", name, "own1"); code != 1 {
		// the file is signed now, so upstream refuses for that reason; the wrong-key refusal is upstream's order-dependent twin
		t.Logf("upstream signing a signed file with the wrong key exited %d", code)
	}

	// info of the port (the collection is incomplete: one open slot)
	info, err := poolops.WitnessInfo{Store: store, Tip: tip, TxIDs: led}.Run(bg, "mypool")
	if err != nil || info.State != pool.CollectionOpenIncomplete || len(info.Slots) != 4 {
		t.Fatalf("%+v %v", info, err)
	}

	// clear: upstream on a terminal answering yes, the port confirmed
	if code := e.upstreamAnswers(t, r.up, "y\n", "05d_poolWitness.sh", "clear", "mypool"); code != 0 {
		t.Errorf("upstream clear exited %d", code)
	}
	cleared, err := poolops.ClearWitnesses{Store: store, TxIDs: led}.Run(bg, poolops.ClearRequest{Pool: "mypool", Confirmed: true})
	if err != nil || !cleared.Cleared {
		t.Fatalf("%+v %v", cleared, err)
	}
	if strings.Contains(readFile(t, r.up, "mypool.pool.json"), "regWitness") || strings.Contains(readFile(t, r.port, "mypool.pool.json"), "regWitness") {
		t.Error("regWitness is still in a descriptor")
	}
	if code := e.upstream(t, r.up, "exec", "05d_poolWitness.sh", "info", "mypool"); code != 0 {
		t.Errorf("upstream info after clear exited %d", code)
	}
	if again, err := (poolops.ClearWitnesses{Store: store, TxIDs: led}).Run(bg, poolops.ClearRequest{Pool: "mypool", Confirmed: true}); err != nil || again.Present {
		t.Errorf("%+v %v", again, err)
	}
}
