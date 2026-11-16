package airgap

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/transfer"
	"github.com/mochipool/workbench/spo/internal/ports"
)

type updateHook struct {
	got []string
	ids []chain.TxID
	err error
}

func (h *updateHook) OnSubmittedUpdate(_ context.Context, id chain.TxID, update string) error {
	h.got, h.ids = append(h.got, update), append(h.ids, id)
	return h.err
}

const carried = `{"txid":"0000","record":"p.tok","policy":"aa","nameHex":"746f6b","hexTyped":false,"delta":"100","validBefore":"unlimited","action":"mint 100 (only Offline proof)"}`

// The result of a submitted mint returns across the air gap in the history of
// the file, and the hook of the executing machine is told.
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
	hook := &updateHook{}
	uc.Assets = hook
	res, err := uc.Run(bg, 1)
	if err != nil || !res.Submitted {
		t.Fatalf("%v %+v", err, res)
	}
	if len(hook.got) != 1 || hook.got[0] != carried || hook.ids[0] != res.TxID {
		t.Errorf("hook: %+v", hook)
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

// A hook that fails never undoes the submission: the update is in the history
// and the result carries a notice.
func TestExecuteAssetHookFailureIsANotice(t *testing.T) {
	r := newRig(t)
	if _, err := r.add().Run(bg, "w"); err != nil {
		t.Fatal(err)
	}
	if err := r.file.Enqueue(bg, ports.QueuedTx{Type: transfer.TypeAssetBurning, FromName: "w", FromAddr: payAddr, ToName: "w", ToAddr: payAddr,
		Tx: txOf(cborA), Description: "burned", Extra: []ports.QueuedField{{Key: transfer.KeyAssetPending, Value: carried}}}); err != nil {
		t.Fatal(err)
	}
	uc, _, _ := r.executor()
	uc.Assets = &updateHook{err: errors.New("record locked")}
	res, err := uc.Run(bg, 1)
	if err != nil || !res.Submitted || len(res.Notices) != 1 || !strings.Contains(res.Notices[0], "record locked") {
		t.Fatalf("%v %+v", err, res)
	}
	b, _, _ := r.file.ReadBundle(bg)
	if subs, _ := b.SubmittedAssetUpdates(); len(subs) != 1 {
		t.Error("the update must be in the history")
	}
}

// An entry without the field behaves as before: no hook call, no extra key.
func TestExecuteWithoutAnAssetUpdate(t *testing.T) {
	r := prepared(t)
	uc, _, _ := r.executor()
	hook := &updateHook{}
	uc.Assets = hook
	if _, err := uc.Run(bg, 1); err != nil || len(hook.got) != 0 || strings.Contains(r.readText(), "spoAsset") {
		t.Errorf("%v %v", err, hook.got)
	}
}
