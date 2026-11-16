package assets

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/fsstore"
	"github.com/mochipool/workbench/spo/internal/adapters/transferfile"
	"github.com/mochipool/workbench/spo/internal/domain/assets"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/transfer"
)

// carry is a transfer file in the world's directory that the mint queues to.
func carry(t *testing.T, w *world) *transferfile.File {
	t.Helper()
	path := filepath.Join(w.dir, "offlineTransfer.json")
	doc := `{"protocol":{"era":"conway","parameters":{"txFeePerByte":44}},"history":[]}`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return &transferfile.File{Path: path}
}

func queuedMint(t *testing.T, w *world, f *transferfile.File, asset, amount string) Result {
	t.Helper()
	b := w.base(true)
	b.Queue = f
	return mustMint(t, b, mintReq(asset, amount))
}

// complete does what the online machine's ExecuteTx does to the file after a
// submit.
func complete(t *testing.T, f *transferfile.File, id chain.TxID) {
	t.Helper()
	b, _, err := f.ReadBundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	q, _ := b.Queue()
	for _, e := range q {
		p, err := assets.ParsePending([]byte(e.AssetPending))
		if err == nil && p.TxID == id.String() {
			if err := f.MutateBundle(context.Background(), func(nb *transfer.Bundle) error { return nb.CompleteSubmit(e.CborHex, id.String(), "date") }); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatalf("transaction %s is not queued", id)
}

func (w *world) settler(f *transferfile.File) SettleFromBundle {
	return SettleFromBundle{Store: w.store, Lister: w.store, Bundle: f, Clock: w.clock}
}

// Step 1: the queue entry carries the update, next to the pending record.
func TestQueuedMintEntryCarriesTheAssetUpdate(t *testing.T) {
	w := newWorld(t)
	w.policy("free", 0)
	f := carry(t, w)
	res := queuedMint(t, w, f, "free.tok", "100")
	b, _, _ := f.ReadBundle(context.Background())
	q, err := b.Queue()
	if err != nil || len(q) != 1 || q[0].Type != transfer.TypeAssetMinting {
		t.Fatalf("%v %+v", err, q)
	}
	p, err := assets.ParsePending([]byte(q[0].AssetPending))
	if err != nil || p.TxID != res.TxID.String() || p.Record != "free.tok" || p.Delta != "100" || p.Action != "mint 100 (only Offline proof)" {
		t.Fatalf("the carried update: %v %+v", err, p)
	}
	if !w.exists(res.TxID.String() + ".asset-pending") {
		t.Error("the queuing machine keeps its own pending record")
	}
	// A mint submitted at once carries nothing: there is no queue.
	if r := mustMint(t, w.base(false), mintReq("free.tok", "1")); r.Queued {
		t.Error("queued")
	}
}

// Steps 3 and 4: settle applies exactly once, waits for a queued one, and
// discards what left the queue unsubmitted.
func TestSettleFromBundle(t *testing.T) {
	w := newWorld(t)
	w.policy("free", 0)
	f := carry(t, w)
	a := queuedMint(t, w, f, "free.tok", "100")
	b := queuedMint(t, w, f, "free.tok", "7")
	ctx := context.Background()

	// Nothing submitted yet: both wait, nothing changes.
	res, err := w.settler(f).Run(ctx)
	if err != nil || len(res.Waiting) != 2 || !res.Nothing() || w.exists("free.tok.asset") {
		t.Fatalf("before the submit: %v %+v", err, res)
	}

	complete(t, f, a.TxID)
	plan, err := w.settler(f).Plan(ctx)
	if err != nil || len(plan.Applied) != 1 || plan.Applied[0].TxID != a.TxID.String() || w.exists("free.tok.asset") {
		t.Fatalf("plan: %v %+v (a plan writes nothing)", err, plan)
	}
	res, err = w.settler(f).Run(ctx)
	if err != nil || len(res.Applied) != 1 || len(res.Waiting) != 1 || res.Waiting[0].TxID != b.TxID.String() {
		t.Fatalf("run: %v %+v", err, res)
	}
	rec, _ := assets.ParseRecord([]byte(w.file("free.tok.asset")))
	if rec.Get("minted") != "100" || rec.Get("lastAction") != "mint 100 (only Offline proof)" || w.exists(a.TxID.String()+".asset-pending") {
		t.Fatalf("record: %s", w.file("free.tok.asset"))
	}

	// Idempotent: a second run applies nothing.
	res, err = w.settler(f).Run(ctx)
	if err != nil || len(res.Applied) != 0 || len(res.Waiting) != 1 {
		t.Fatalf("second run: %v %+v", err, res)
	}
	if r, _ := assets.ParseRecord([]byte(w.file("free.tok.asset"))); r.Get("minted") != "100" {
		t.Error("applied twice")
	}

	// The queue is cleared with b still in it: b was never submitted, so its
	// update is discarded with its record, never applied.
	if err := f.MutateBundle(ctx, func(nb *transfer.Bundle) error { return nb.ClearTransactions("date") }); err != nil {
		t.Fatal(err)
	}
	// Without the operator's word the update is reported and kept: the file
	// might be the wrong one.
	res, err = w.settler(f).Run(ctx)
	if err != nil || len(res.Unmatched) != 1 || len(res.Discarded) != 0 || !w.exists(b.TxID.String()+".asset-pending") {
		t.Fatalf("unmatched must be kept: %v %+v", err, res)
	}
	sd := w.settler(f)
	sd.DiscardUnmatched = true
	res, err = sd.Run(ctx)
	if err != nil || len(res.Discarded) != 1 || res.Discarded[0].TxID != b.TxID.String() || len(res.Applied) != 0 {
		t.Fatalf("discard: %v %+v", err, res)
	}
	if w.exists(b.TxID.String()+".asset-pending") || func() bool {
		r, _ := assets.ParseRecord([]byte(w.file("free.tok.asset")))
		return r.Get("minted") != "100"
	}() {
		t.Error("the discarded update was applied or kept")
	}
	if res, _ = w.settler(f).Run(ctx); !res.Nothing() || len(res.Waiting) != 0 {
		t.Errorf("after the discard: %+v", res)
	}
}

func TestSettleFromBundleNeedsTheFile(t *testing.T) {
	w := newWorld(t)
	f := &transferfile.File{Path: filepath.Join(w.dir, "missing.json")}
	if _, err := w.settler(f).Run(context.Background()); err == nil {
		t.Fatal("a missing file")
	}
	if _, err := (SettleFromBundle{}).Run(context.Background()); err == nil {
		t.Fatal("misconfigured")
	}
}

// Step 2: the hook of the executing machine applies the carried update when it
// holds the pending record or the asset record, and does nothing otherwise.
func TestUpdateHook(t *testing.T) {
	w := newWorld(t)
	w.policy("free", 0)
	f := carry(t, w)
	r := queuedMint(t, w, f, "free.tok", "100")
	bundle, _, _ := f.ReadBundle(context.Background())
	q, _ := bundle.Queue()
	update := q[0].AssetPending
	ctx := context.Background()

	// An online workspace that holds neither: nothing.
	other, err := fsstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := (UpdateHook{Store: other, Clock: w.clock}).OnSubmittedUpdate(ctx, r.TxID, update); err != nil {
		t.Fatal(err)
	}
	if err := (UpdateHook{Store: other, Clock: w.clock}).OnSubmittedUpdate(ctx, r.TxID, "{broken"); err == nil {
		t.Error("a damaged update")
	}
	if entries, _ := os.ReadDir(w.dir); strings.Contains(listNames(entries), "free.tok.asset ") {
		t.Fatal("the record appeared")
	}

	// The queuing machine itself: the pending record is applied and removed.
	if err := (UpdateHook{Store: w.store, Clock: w.clock}).OnSubmittedUpdate(ctx, r.TxID, update); err != nil {
		t.Fatal(err)
	}
	if rec, _ := assets.ParseRecord([]byte(w.file("free.tok.asset"))); rec.Get("minted") != "100" || w.exists(r.TxID.String()+".asset-pending") {
		t.Fatalf("record: %s", w.file("free.tok.asset"))
	}
	// Told again, with no pending record left, the record it holds is
	// updated from the carried data: the executing machine runs once per entry.
	if err := (UpdateHook{Store: w.store, Clock: w.clock}).OnSubmittedUpdate(ctx, r.TxID, update); err != nil {
		t.Fatal(err)
	}
	if rec, _ := assets.ParseRecord([]byte(w.file("free.tok.asset"))); rec.Get("minted") != "200" {
		t.Fatalf("an online copy of the record: %s", w.file("free.tok.asset"))
	}
}

func listNames(es []os.DirEntry) string {
	var b strings.Builder
	for _, e := range es {
		b.WriteString(e.Name() + " ")
	}
	return b.String()
}
