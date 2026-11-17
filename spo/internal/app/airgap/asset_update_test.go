package airgap

import (
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/transfer"
	"github.com/mochipool/workbench/spo/internal/ports"
)

const carried = `{"txid":"0000","record":"p.tok","policy":"aa","nameHex":"746f6b","hexTyped":false,"delta":"100","validBefore":"unlimited","action":"mint 100 (only Offline proof)"}`

// The submit of a mint returns across the air gap in the history of the file;
// the executor applies nothing and tells the operator that confirmation is what
// applies the update (SPO-Xconfirm-PR-021).
func TestExecuteReportsAnAssetUpdateInTheHistory(t *testing.T) {
	r := newRig(t)
	if _, err := r.add().Run(bg, "w"); err != nil {
		t.Fatal(err)
	}
	if err := r.file.Enqueue(bg, ports.QueuedTx{Type: transfer.TypeAssetMinting, FromName: "w", FromAddr: payAddr, ToName: "w", ToAddr: payAddr,
		Tx: txOf(cborA), Description: "minted 100 'tok' on 'w'", Extra: []ports.QueuedField{{Key: transfer.KeyAssetPending, Value: carried}}}); err != nil {
		t.Fatal(err)
	}
	uc, _, _ := r.executor()
	res, err := uc.Run(bg, 1)
	if err != nil || !res.Submitted {
		t.Fatalf("%v %+v", err, res)
	}
	if len(res.Notices) != 1 || !strings.Contains(res.Notices[0], "only once it is confirmed") {
		t.Errorf("notices: %v", res.Notices)
	}
	// The history says submitted and nothing about confirmation.
	if oc, err := mustBundle(t, r).Outcomes(); err != nil || len(oc) != 0 {
		t.Errorf("outcomes: %v %v", err, oc)
	}
	b, _, _ := r.file.ReadBundle(bg)
	subs, err := b.SubmittedAssetUpdates()
	if err != nil || len(subs) != 1 || !strings.Contains(subs[0], `"txid":"`+res.TxID.String()+`"`) || !strings.Contains(subs[0], `"delta":"100"`) {
		t.Fatalf("history: %v %v", err, subs)
	}
	// Upstream's text is in the same entry, and the file still reads as before.
	in, err := (InspectBundle{r.file}).Run(bg)
	if err != nil || !strings.HasPrefix(in.LastAction, "tx submit "+res.TxID.String()+" - utxo from 'w' to 'w'") || in.PendingTransactions() != 0 {
		t.Errorf("info: %v %+v", err, in)
	}
	if text := r.readText(); !strings.Contains(text, `"spoAssetSubmitted"`) {
		t.Errorf("the file:\n%s", text)
	}
}

// An entry without the field behaves as before: no hook call, no extra key.
func TestExecuteWithoutAnAssetUpdate(t *testing.T) {
	r := prepared(t)
	uc, _, _ := r.executor()
	if res, err := uc.Run(bg, 1); err != nil || len(res.Notices) != 0 || strings.Contains(r.readText(), "spoAsset") {
		t.Errorf("%v %v", err, res.Notices)
	}
}

func mustBundle(t *testing.T, r *rig) *transfer.Bundle {
	t.Helper()
	b, _, err := r.file.ReadBundle(bg)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
