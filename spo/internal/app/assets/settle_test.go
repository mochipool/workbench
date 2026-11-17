package assets

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/transferfile"
	"github.com/mochipool/workbench/spo/internal/domain/assets"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/transfer"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/plainstore"
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

// confirm records, in the history of the file, what the online machine's tx
// settle (or the wait of offline execute) records once a provider says the
// transaction is in a block.
func confirm(t *testing.T, f *transferfile.File, id chain.TxID) {
	t.Helper()
	err := f.MutateBundle(context.Background(), func(nb *transfer.Bundle) error {
		_, err := nb.RecordOutcome(transfer.Outcome{TxID: id.String(), Depth: 3, Sources: []string{"koios", "blockfrost"}}, "date", "confirmed")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
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
	if !w.exists(res.TxID.String() + ".pending") {
		t.Error("the queuing machine keeps its own pending record")
	}
	// A mint submitted at once carries nothing: there is no queue.
	if r := mustMint(t, w.base(false), mintReq("free.tok", "1")); r.Queued {
		t.Error("queued")
	}
}

// Steps 3 and 4: settle applies exactly once, and only what the history
// records as confirmed; it waits for a queued one and for one that is only
// submitted, and discards what left the queue unsubmitted.
//
// spec: SPO-Xconfirm-PR-023, SPO-Xconfirm-PR-024
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
	// Submitted is not confirmed: the update waits and the record is untouched.
	res, err = w.settler(f).Run(ctx)
	if err != nil || len(res.Applied) != 0 || len(res.Submitted) != 1 || res.Submitted[0].TxID != a.TxID.String() || len(res.Waiting) != 1 || w.exists("free.tok.asset") {
		t.Fatalf("submitted only: %v %+v", err, res)
	}
	// Only --accept-submitted applies it on the submit alone (a plan writes nothing).
	trusting := w.settler(f)
	trusting.AcceptSubmitted = true
	plan, err := trusting.Plan(ctx)
	if err != nil || len(plan.Applied) != 1 || !plan.Applied[0].Trusted || w.exists("free.tok.asset") {
		t.Fatalf("accept-submitted plan: %v %+v", err, plan)
	}
	confirm(t, f, a.TxID)
	plan, err = w.settler(f).Plan(ctx)
	if err != nil || len(plan.Applied) != 1 || plan.Applied[0].TxID != a.TxID.String() || plan.Applied[0].Trusted || plan.Applied[0].Depth != 3 || w.exists("free.tok.asset") {
		t.Fatalf("plan: %v %+v (a plan writes nothing)", err, plan)
	}
	res, err = w.settler(f).Run(ctx)
	if err != nil || len(res.Applied) != 1 || len(res.Waiting) != 1 || res.Waiting[0].TxID != b.TxID.String() {
		t.Fatalf("run: %v %+v", err, res)
	}
	rec, _ := assets.ParseRecord([]byte(w.file("free.tok.asset")))
	if rec.Get("minted") != "100" || rec.Get("lastAction") != "mint 100 (only Offline proof)" || w.exists(a.TxID.String()+".pending") {
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
	if err != nil || len(res.Unmatched) != 1 || len(res.Discarded) != 0 || !w.exists(b.TxID.String()+".pending") {
		t.Fatalf("unmatched must be kept: %v %+v", err, res)
	}
	sd := w.settler(f)
	sd.DiscardUnmatched = true
	res, err = sd.Run(ctx)
	if err != nil || len(res.Discarded) != 1 || res.Discarded[0].TxID != b.TxID.String() || len(res.Applied) != 0 {
		t.Fatalf("discard: %v %+v", err, res)
	}
	if w.exists(b.TxID.String()+".pending") || func() bool {
		r, _ := assets.ParseRecord([]byte(w.file("free.tok.asset")))
		return r.Get("minted") != "100"
	}() {
		t.Error("the discarded update was applied or kept")
	}
	if res, _ = w.settler(f).Run(ctx); !res.Nothing() || len(res.Waiting) != 0 {
		t.Errorf("after the discard: %+v", res)
	}
}

// An expiry recorded in the history discards the update and never applies it.
//
// spec: SPO-Xconfirm-PR-025
func TestSettleFromBundleDiscardsAnExpiredTransaction(t *testing.T) {
	w := newWorld(t)
	w.policy("free", 0)
	f := carry(t, w)
	a := queuedMint(t, w, f, "free.tok", "100")
	complete(t, f, a.TxID)
	if err := f.MutateBundle(context.Background(), func(nb *transfer.Bundle) error {
		_, err := nb.RecordOutcome(transfer.Outcome{TxID: a.TxID.String(), Expired: true}, "date", "expired")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	res, err := w.settler(f).Run(context.Background())
	if err != nil || len(res.Expired) != 1 || len(res.Applied) != 0 || w.exists("free.tok.asset") || w.exists(a.TxID.String()+".pending") {
		t.Fatalf("%v %+v", err, res)
	}
}

// The outcome entries of a transfer file are not authenticated. One counts only
// for a transaction this workspace queued that the file records as submitted
// and gone from its queue; an expiry only discards when the bound stored here is
// the one that was queued.
//
// spec: SPO-Xconfirm-PR-023
func TestSettleFromBundleRefusesInconsistentOutcomes(t *testing.T) {
	ctx := context.Background()
	t.Run("confirmed for a transaction still queued", func(t *testing.T) {
		w := newWorld(t)
		w.policy("free", 0)
		f := carry(t, w)
		a := queuedMint(t, w, f, "free.tok", "100")
		confirm(t, f, a.TxID) // never submitted: still in the queue
		res, err := w.settler(f).Run(ctx)
		if err != nil || len(res.Applied) != 0 || len(res.Inconsistent) != 1 || !w.exists(a.TxID.String()+".pending") || w.exists("free.tok.asset") {
			t.Fatalf("%v %+v", err, res)
		}
	})
	t.Run("confirmed for a transaction never recorded as submitted", func(t *testing.T) {
		w := newWorld(t)
		w.policy("free", 0)
		f := carry(t, w)
		a := queuedMint(t, w, f, "free.tok", "100")
		// Taken out of the queue without a submit, then an edited file claims it was confirmed.
		if err := f.MutateBundle(ctx, func(nb *transfer.Bundle) error { return nb.ClearTransactions("date") }); err != nil {
			t.Fatal(err)
		}
		confirm(t, f, a.TxID)
		res, err := w.settler(f).Run(ctx)
		if err != nil || len(res.Applied) != 0 || len(res.Inconsistent) != 1 || !w.exists(a.TxID.String()+".pending") || w.exists("free.tok.asset") {
			t.Fatalf("%v %+v", err, res)
		}
	})
	t.Run("expired with a bound that is not the stored one", func(t *testing.T) {
		w := newWorld(t)
		w.policy("free", 0)
		f := carry(t, w)
		a := queuedMint(t, w, f, "free.tok", "100")
		complete(t, f, a.TxID)
		// The file's carried record is edited to a bound this workspace never stored.
		raw, _ := os.ReadFile(f.Path)
		edited := regexp.MustCompile(`"validUntil":\s*\d+`).ReplaceAllString(string(raw), `"validUntil": 1`)
		if edited == string(raw) {
			t.Fatal("no bound to edit")
		}
		_ = os.WriteFile(f.Path, []byte(edited), 0o600)
		if err := f.MutateBundle(ctx, func(nb *transfer.Bundle) error {
			_, err := nb.RecordOutcome(transfer.Outcome{TxID: a.TxID.String(), Expired: true}, "date", "expired")
			return err
		}); err != nil {
			t.Fatal(err)
		}
		res, err := w.settler(f).Run(ctx)
		if err != nil || len(res.Expired) != 0 || len(res.Inconsistent) != 1 || !w.exists(a.TxID.String()+".pending") {
			t.Fatalf("%v %+v", err, res)
		}
	})
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
//
// spec: SPO-Xconfirm-PR-027
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
	other, err := plainstore.OpenTestnet(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := (UpdateHook{Store: other, Clock: w.clock}).OnConfirmedUpdate(ctx, r.TxID, update); err != nil {
		t.Fatal(err)
	}
	if err := (UpdateHook{Store: other, Clock: w.clock}).OnConfirmedUpdate(ctx, r.TxID, "{broken"); err == nil {
		t.Error("a damaged update")
	}
	if entries, _ := os.ReadDir(w.dir); strings.Contains(listNames(entries), "free.tok.asset ") {
		t.Fatal("the record appeared")
	}

	// The queuing machine itself: the pending record is applied and removed.
	if err := (UpdateHook{Store: w.store, Clock: w.clock}).OnConfirmedUpdate(ctx, r.TxID, update); err != nil {
		t.Fatal(err)
	}
	if rec, _ := assets.ParseRecord([]byte(w.file("free.tok.asset"))); rec.Get("minted") != "100" || w.exists(r.TxID.String()+".pending") {
		t.Fatalf("record: %s", w.file("free.tok.asset"))
	}
	// Told again, with no pending record left, the record it holds is
	// updated from the carried data, once it matches the transaction itself:
	// the executing machine runs once per entry.
	tx, err := q[0].TxBytes()
	if err != nil {
		t.Fatal(err)
	}
	carried, _ := assets.ParsePending([]byte(update))
	pol, _ := hex.DecodeString(carried.Policy)
	var polID [28]byte
	copy(polID[:], pol)
	nm, _ := hex.DecodeString(carried.NameHex)
	mintOf := func(q int64) mintViewer {
		return mintViewer{view: party.TxView{Mint: []party.ViewAsset{{Policy: polID, Name: nm, Quantity: q}}}}
	}
	hook := func(v mintViewer) UpdateHook {
		return UpdateHook{Store: w.store, Clock: w.clock, Tx: tx, TxIDs: idCalc{}, Viewer: v}
	}
	// What does not match the transaction is refused and changes nothing.
	for name, c := range map[string]struct {
		hook   UpdateHook
		update string
	}{
		"the amount differs from the mint field": {hook(mintOf(101)), update},
		"another transaction id":                 {hook(mintOf(100)), strings.Replace(update, r.TxID.String(), strings.Repeat("0", 64), 1)},
		"no way to check":                        {UpdateHook{Store: w.store, Clock: w.clock}, update},
		"another asset name":                     {hook(mintViewer{view: party.TxView{Mint: []party.ViewAsset{{Policy: polID, Name: []byte("other"), Quantity: 100}}}}), update},
	} {
		if err := c.hook.OnConfirmedUpdate(ctx, r.TxID, c.update); !errors.Is(err, ErrCarriedUpdateRefused) {
			t.Errorf("%s: %v", name, err)
		}
		if rec, _ := assets.ParseRecord([]byte(w.file("free.tok.asset"))); rec.Get("minted") != "100" {
			t.Fatalf("%s changed the record: %s", name, w.file("free.tok.asset"))
		}
	}
	if err := hook(mintOf(100)).OnConfirmedUpdate(ctx, r.TxID, update); err != nil {
		t.Fatal(err)
	}
	if rec, _ := assets.ParseRecord([]byte(w.file("free.tok.asset"))); rec.Get("minted") != "200" {
		t.Fatalf("an online copy of the record: %s", w.file("free.tok.asset"))
	}
}

type idCalc struct{}

func (idCalc) TransactionID(tx []byte) (chain.TxID, error) { return txIDOf(tx), nil }

// mintViewer is a TxViewer whose decoded body is fixed.
type mintViewer struct{ view party.TxView }

func (mintViewer) BodyOf(tx []byte) ([]byte, error)      { return tx, nil }
func (m mintViewer) View([]byte) (party.TxView, error)   { return m.view, nil }
func (mintViewer) AuxOf([]byte) ([]byte, error)          { return nil, nil }
func (mintViewer) ViewAux([]byte) (party.AuxView, error) { return party.AuxView{}, nil }

func listNames(es []os.DirEntry) string {
	var b strings.Builder
	for _, e := range es {
		b.WriteString(e.Name() + " ")
	}
	return b.String()
}

// The settle from the transfer file serves every kind of pending update: a pool
// registration is routed to its applier, only when its confirmation is
// recorded, and a kind with no applier is an error that keeps the update.
//
// spec: SPO-Xconfirm-PR-023, SPO-Xconfirm-PR-001
func TestSettleFromBundleRoutesByKind(t *testing.T) {
	w := newWorld(t)
	f := carry(t, w)
	ctx := context.Background()
	id := chain.TxID{0x44}
	p := assets.Pending{Kind: assets.PendingPoolRegistration, TxID: id.String(), Queued: true, Pool: "mypool", Epoch: "7", Stamp: "stamp"}
	pb, _ := p.Marshal()
	var compact strings.Builder
	compact.WriteString(strings.Join(strings.Fields(string(pb)), ""))
	if err := w.store.Update(ctx, func(wr ports.Writer) error { return wr.Put(ports.Ref{Name: p.TxID, Kind: ports.PendingUpdate}, pb) }); err != nil {
		t.Fatal(err)
	}
	if err := f.Enqueue(ctx, ports.QueuedTx{Type: transfer.TypePoolRegistration, FromName: "w", FromAddr: "a", ToName: "w", ToAddr: "a",
		Tx: txbuild.SignedTx{CBOR: []byte{0x44}, ID: id}, Description: "d", Extra: []ports.QueuedField{{Key: transfer.KeyAssetPending, Value: compact.String()}}}); err != nil {
		t.Fatal(err)
	}
	if err := f.MutateBundle(ctx, func(nb *transfer.Bundle) error { return nb.CompleteSubmit("44", id.String(), "date") }); err != nil {
		t.Fatal(err)
	}
	applied := 0
	apply := func(_ ports.Writer, got assets.Pending, _ time.Time) error {
		if got.Pool != "mypool" || got.Epoch != "7" {
			t.Errorf("%+v", got)
		}
		applied++
		return nil
	}
	uc := w.settler(f)
	uc.Appliers = map[string]Applier{assets.PendingPoolRegistration: apply}
	// Submitted only: kept, the pool applier not called.
	if res, err := uc.Run(ctx); err != nil || len(res.Submitted) != 1 || res.Submitted[0].Kind != assets.PendingPoolRegistration || applied != 0 {
		t.Fatalf("%v %+v", err, res)
	}
	confirm(t, f, id)
	// No applier: an error, nothing lost.
	if _, err := w.settler(f).Run(ctx); err == nil || !strings.Contains(err.Error(), "no applier") || !w.exists(id.String()+".pending") {
		t.Fatalf("no applier: %v", err)
	}
	res, err := uc.Run(ctx)
	if err != nil || len(res.Applied) != 1 || applied != 1 || w.exists(id.String()+".pending") {
		t.Fatalf("%v %+v applied %d", err, res, applied)
	}
	if res, err = uc.Run(ctx); err != nil || len(res.Applied) != 0 || applied != 1 {
		t.Fatalf("a second run: %v %+v", err, res)
	}
}
