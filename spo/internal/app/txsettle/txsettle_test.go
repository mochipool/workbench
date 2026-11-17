package txsettle

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/transferfile"
	"github.com/mochipool/workbench/spo/internal/app/assets"
	"github.com/mochipool/workbench/spo/internal/app/txconfirm"
	domassets "github.com/mochipool/workbench/spo/internal/domain/assets"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/transfer"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

var bg = context.Background()

const txconfirmSlack = txconfirm.DefaultExpirySlack

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }
func (c *clock) Sleep(_ context.Context, d time.Duration) error {
	c.now = c.now.Add(d)
	return nil
}

type fakeStatus struct {
	name  string
	reads []chain.Reading[chain.TxStatus]
	n     int
}

func (f *fakeStatus) Source() chain.Source { return chain.Source(f.name) }
func (f *fakeStatus) TxStatus(context.Context, ports.TxStatusQuery) (chain.Reading[chain.TxStatus], error) {
	i := f.n
	if i >= len(f.reads) {
		i = len(f.reads) - 1
	}
	f.n++
	return f.reads[i], nil
}

type tipAt uint64

func (tipAt) Source() chain.Source { return "tip" }
func (t tipAt) Tip(context.Context) (chain.Tip, error) {
	return chain.Tip{Slot: uint64(t)}, nil
}

func inBlock(d uint64) chain.Reading[chain.TxStatus] {
	return chain.Value(chain.TxStatus{State: chain.TxInBlock, Confirmations: d, HaveConfirmations: true})
}

var (
	notSeen = chain.None[chain.TxStatus]()
	down    = chain.Unknown[chain.TxStatus]("provider down")
)

type rig struct {
	t     *testing.T
	dir   string
	store *plainstore.Store
	clk   *clock
}

func newRig(t *testing.T) *rig {
	t.Helper()
	dir := t.TempDir()
	st, err := plainstore.OpenTestnet(dir)
	if err != nil {
		t.Fatal(err)
	}
	return &rig{t: t, dir: dir, store: st, clk: &clock{now: time.Unix(1_700_000_000, 0)}}
}

// pend stores an asset pending update of the given transaction and returns it.
func (r *rig) pend(idByte byte, validUntil *uint64) domassets.Pending {
	r.t.Helper()
	id := chain.TxID{idByte}
	p := domassets.Pending{Kind: domassets.PendingAsset, TxID: id.String(), ValidUntil: validUntil, Record: "p.tok", Policy: strings.Repeat("aa", 28),
		NameHex: "746f6b", Delta: "100", ValidBefore: "unlimited", Action: "mint 100"}
	b, err := p.Marshal()
	if err != nil {
		r.t.Fatal(err)
	}
	if err := r.store.Update(bg, func(w ports.Writer) error {
		return w.Put(ports.Ref{Name: p.TxID, Kind: ports.PendingUpdate}, b)
	}); err != nil {
		r.t.Fatal(err)
	}
	return p
}

// stubTx reads the fake transactions of these tests: the id is the first byte
// of the bytes, the validity bound is ttl.
type stubTx struct{ ttl uint64 }

func (stubTx) TransactionID(c []byte) (chain.TxID, error) { return chain.TxID{c[0]}, nil }
func (stubTx) BodyOf(tx []byte) ([]byte, error)           { return tx, nil }
func (s stubTx) View([]byte) (party.TxView, error)        { t := s.ttl; return party.TxView{TTL: &t}, nil }
func (stubTx) AuxOf([]byte) ([]byte, error)               { return nil, nil }
func (stubTx) ViewAux([]byte) (party.AuxView, error)      { return party.AuxView{}, nil }

func (r *rig) settler(ws ...ports.TxWatcher) Settler {
	return Settler{Settle: assets.Settle{Store: r.store, Clock: r.clk}, Lister: r.store, Watchers: ws, Sleep: r.clk.Sleep, Now: r.clk.Now, Depth: 1,
		TxIDs: stubTx{1000}, Viewer: stubTx{1000}}
}

func (r *rig) record() (string, bool) {
	b, err := os.ReadFile(filepath.Join(r.dir, "p.tok.asset"))
	return string(b), err == nil
}

func (r *rig) pending(id byte) bool {
	_, found, err := assets.PendingOf(bg, r.store, chain.TxID{id})
	if err != nil {
		r.t.Fatal(err)
	}
	return found
}

func u64(n uint64) *uint64 { return &n }

// Confirmed on every provider at the depth: applied once, the pending record
// removed; a second run finds nothing.
//
// spec: SPO-Xconfirm-PR-011, SPO-Xconfirm-PR-013
func TestConfirmedIsAppliedExactlyOnce(t *testing.T) {
	r := newRig(t)
	r.pend(1, nil)
	st := r.settler(ports.TxWatcher{Status: &fakeStatus{name: "a", reads: []chain.Reading[chain.TxStatus]{inBlock(2)}}},
		ports.TxWatcher{Status: &fakeStatus{name: "b", reads: []chain.Reading[chain.TxStatus]{inBlock(3)}}})
	items, err := st.Run(bg)
	if err != nil || len(items) != 1 || items[0].State != Applied || items[0].Depth != 2 || len(items[0].Sources) != 2 {
		t.Fatalf("%v %+v", err, items)
	}
	rec, ok := r.record()
	if !ok || !strings.Contains(rec, `"minted": "100"`) || r.pending(1) {
		t.Fatalf("record %v %s, pending %v", ok, rec, r.pending(1))
	}
	items, err = st.Run(bg)
	if err != nil || len(items) != 0 {
		t.Fatalf("second run: %v %+v", err, items)
	}
	if again, _ := r.record(); again != rec {
		t.Error("applied twice")
	}
}

// Not applied on anything but a confirmation: waiting, unknown, disagree and
// the depth not reached all keep the pending record and leave the record out.
//
// spec: SPO-Xconfirm-PR-012
func TestNothingButConfirmationApplies(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reads [][]chain.Reading[chain.TxStatus]
		want  State
	}{
		{"not seen, no bound", [][]chain.Reading[chain.TxStatus]{{notSeen}}, Waiting},
		{"too shallow", [][]chain.Reading[chain.TxStatus]{{inBlock(1)}}, Waiting}, // depth 2 wanted below
		{"unknown", [][]chain.Reading[chain.TxStatus]{{down}}, Unknown},
		{"disagree", [][]chain.Reading[chain.TxStatus]{{inBlock(5)}, {notSeen}}, Disagree},
		{"partial", [][]chain.Reading[chain.TxStatus]{{inBlock(5)}, {down}}, Waiting},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			r.pend(1, nil)
			var ws []ports.TxWatcher
			for i, reads := range tc.reads {
				ws = append(ws, ports.TxWatcher{Status: &fakeStatus{name: string(rune('a' + i)), reads: reads}})
			}
			st := r.settler(ws...)
			st.Depth = 2
			items, err := st.Run(bg)
			if err != nil || len(items) != 1 || items[0].State != tc.want {
				t.Fatalf("%v %+v", err, items)
			}
			if _, ok := r.record(); ok || !r.pending(1) {
				t.Errorf("applied or lost: record %v, pending %v", ok, r.pending(1))
			}
		})
	}
}

// Expired by the strict rule (a stored bound, every provider's own tip past it
// by more than the slack, every provider saying not seen, two polls): the
// update is discarded and never applied. Without a stored bound, never.
//
// spec: SPO-Xconfirm-PR-012
func TestExpiredIsDiscardedNeverApplied(t *testing.T) {
	r := newRig(t)
	r.pend(1, u64(1000))
	r.pend(2, nil) // no stored bound: cannot be called expired
	r.pend(3, u64(1000))
	late := tipAt(1000 + txconfirmSlack + 1)
	ws := ports.TxWatcher{Status: &fakeStatus{name: "a", reads: []chain.Reading[chain.TxStatus]{notSeen}}, Tip: late}
	st := r.settler(ws)
	// The one provider has the tip past the bound for tx 1 and 3 and says not seen for all.
	items, err := st.Run(bg)
	if err != nil || len(items) != 3 {
		t.Fatalf("%v %+v", err, items)
	}
	byTx := map[string]Item{}
	for _, it := range items {
		byTx[it.TxID] = it
	}
	if byTx[chain.TxID{1}.String()].State != Expired || byTx[chain.TxID{3}.String()].State != Expired || byTx[chain.TxID{2}.String()].State != Waiting {
		t.Fatalf("%+v", items)
	}
	if _, ok := r.record(); ok || r.pending(1) || r.pending(3) || !r.pending(2) {
		t.Errorf("expired updates are discarded, the one without a bound kept: record %v", ok)
	}
}

// --dry-run decides and changes nothing.
//
// spec: SPO-Xconfirm-PR-015
func TestDryRunChangesNothing(t *testing.T) {
	r := newRig(t)
	r.pend(1, nil)
	st := r.settler(ports.TxWatcher{Status: &fakeStatus{name: "a", reads: []chain.Reading[chain.TxStatus]{inBlock(1)}}})
	st.DryRun = true
	items, err := st.Run(bg)
	if err != nil || len(items) != 1 || items[0].State != Applied {
		t.Fatalf("%v %+v", err, items)
	}
	if _, ok := r.record(); ok || !r.pending(1) {
		t.Error("a dry run changed something")
	}
}

// Settling needs a lister to find the pending updates.
func TestSettleNeedsALister(t *testing.T) {
	r := newRig(t)
	st := r.settler()
	st.Lister = nil
	if _, err := st.Run(bg); err != ErrNoLister {
		t.Fatalf("%v", err)
	}
}

// A pool registration pending update settles through the same path as soon as
// the composition gives it an applier; without one it is an error, never
// silently skipped.
func TestUnknownKindWithoutAnApplierIsAnError(t *testing.T) {
	r := newRig(t)
	p := domassets.Pending{Kind: domassets.PendingPoolRegistration, TxID: chain.TxID{9}.String(), Pool: "mypool", Epoch: "7", Stamp: "x"}
	b, _ := p.Marshal()
	if err := r.store.Update(bg, func(w ports.Writer) error {
		return w.Put(ports.Ref{Name: p.TxID, Kind: ports.PendingUpdate}, b)
	}); err != nil {
		t.Fatal(err)
	}
	st := r.settler(ports.TxWatcher{Status: &fakeStatus{name: "a", reads: []chain.Reading[chain.TxStatus]{inBlock(1)}}})
	items, err := st.Run(bg)
	if err != nil || len(items) != 1 || items[0].State != Failed || items[0].Err == nil || !strings.Contains(items[0].Err.Error(), "no applier") {
		t.Fatalf("%v %+v", err, items)
	}
	if !r.pending(9) {
		t.Error("the pending update was lost")
	}
}

// One pending update that cannot be applied does not stop the others from being
// settled; it is reported as a failed item.
//
// spec: SPO-Xconfirm-PR-016
func TestOneBadPendingUpdateDoesNotBlockTheRest(t *testing.T) {
	r := newRig(t)
	bad := domassets.Pending{Kind: domassets.PendingPoolRegistration, TxID: chain.TxID{1}.String(), Pool: "mypool", Epoch: "7", Stamp: "x"}
	b, _ := bad.Marshal()
	if err := r.store.Update(bg, func(w ports.Writer) error {
		return w.Put(ports.Ref{Name: bad.TxID, Kind: ports.PendingUpdate}, b)
	}); err != nil {
		t.Fatal(err)
	}
	r.pend(2, u64(1000)) // sorts after the bad one
	st := r.settler(ports.TxWatcher{Status: &fakeStatus{name: "a", reads: []chain.Reading[chain.TxStatus]{inBlock(1)}}})
	items, err := st.Run(bg)
	if err != nil || len(items) != 2 || items[0].State != Failed || items[1].State != Applied {
		t.Fatalf("%v %+v", err, items)
	}
	if r.pending(2) || !r.pending(1) {
		t.Error("the good update was not applied, or the bad one was lost")
	}
	if _, ok := r.record(); !ok {
		t.Error("the good update's record was not written")
	}
}

// RecordInTransferFile writes the outcome of what offline execute submitted,
// once, as its own history entry; the offline machine applies on it.
//
// spec: SPO-Xconfirm-PR-022
func TestRecordInTransferFile(t *testing.T) {
	r := newRig(t)
	path := filepath.Join(r.dir, "offlineTransfer.json")
	if err := os.WriteFile(path, []byte(`{"protocol":{"era":"conway","parameters":{"txFeePerByte":44}},"history":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &transferfile.File{Path: path}
	ids := []byte{1, 2, 3}
	for _, b := range ids {
		upd := domassets.Pending{TxID: chain.TxID{b}.String(), ValidUntil: u64(1000), Record: "p.tok", Delta: "1"}
		raw, _ := upd.Marshal()
		if err := f.Enqueue(bg, ports.QueuedTx{Type: transfer.TypeAssetMinting, FromName: "w", FromAddr: "a", ToName: "w", ToAddr: "a",
			Tx: txbuild.SignedTx{CBOR: []byte{b}, ID: chain.TxID{b}}, Description: "d", Extra: []ports.QueuedField{{Key: transfer.KeyAssetPending, Value: string(raw)}}}); err != nil {
			t.Fatal(err)
		}
		if err := f.MutateBundle(bg, func(nb *transfer.Bundle) error {
			return nb.CompleteSubmit(string(hexOf(b)), chain.TxID{b}.String(), "date")
		}); err != nil {
			t.Fatal(err)
		}
	}
	watch := func(reads ...chain.Reading[chain.TxStatus]) Settler {
		st := r.settler(ports.TxWatcher{Status: &fakeStatus{name: "koios", reads: reads}, Tip: tipAt(1000 + txconfirmSlack + 1)})
		return st
	}
	stConfirmed := watch(inBlock(4))
	items, err := stConfirmed.RecordInTransferFile(bg, f)
	if err != nil || len(items) != 3 {
		t.Fatalf("%v %+v", err, items)
	}
	// Everything answered "in a block": all three are recorded confirmed.
	b, _, _ := f.ReadBundle(bg)
	oc, _ := b.Outcomes()
	if len(oc) != 3 || oc[chain.TxID{1}.String()].Depth != 4 || oc[chain.TxID{1}.String()].Sources[0] != "koios" || oc[chain.TxID{1}.String()].Expired {
		t.Fatalf("outcomes: %+v", oc)
	}
	// An expiry is recorded the same way, for a transaction without an outcome.
	r2 := newRig(t)
	path2 := filepath.Join(r2.dir, "offlineTransfer.json")
	_ = os.WriteFile(path2, []byte(`{"protocol":{"era":"conway","parameters":{"txFeePerByte":44}},"history":[]}`), 0o600)
	f2 := &transferfile.File{Path: path2}
	upd := domassets.Pending{TxID: chain.TxID{7}.String(), ValidUntil: u64(1000), Record: "p.tok", Delta: "1"}
	raw, _ := upd.Marshal()
	_ = f2.Enqueue(bg, ports.QueuedTx{Type: transfer.TypeAssetMinting, FromName: "w", FromAddr: "a", ToName: "w", ToAddr: "a",
		Tx: txbuild.SignedTx{CBOR: []byte{7}, ID: chain.TxID{7}}, Description: "d", Extra: []ports.QueuedField{{Key: transfer.KeyAssetPending, Value: string(raw)}}})
	_ = f2.MutateBundle(bg, func(nb *transfer.Bundle) error { return nb.CompleteSubmit("07", chain.TxID{7}.String(), "date") })
	late := r2.settler(ports.TxWatcher{Status: &fakeStatus{name: "koios", reads: []chain.Reading[chain.TxStatus]{notSeen}}, Tip: tipAt(1000 + txconfirmSlack + 1)})
	if items, err := late.RecordInTransferFile(bg, f2); err != nil || len(items) != 1 || items[0].State != Expired {
		t.Fatalf("expired: %v %+v", err, items)
	}
	b2, _, _ := f2.ReadBundle(bg)
	if oc2, _ := b2.Outcomes(); !oc2[chain.TxID{7}.String()].Expired {
		t.Errorf("%+v", oc2)
	}
	// Once: a second run records nothing and writes nothing new.
	before, _ := os.ReadFile(path)
	if items, err = stConfirmed.RecordInTransferFile(bg, f); err != nil || len(items) != 0 {
		t.Fatalf("second run: %v %+v", err, items)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Error("the file changed on a second run")
	}
}

// The record a transfer file carries is the file's claim: its transaction id and
// its validity bound must be those of the transaction stored beside it, or
// nothing is recorded. An edited bound cannot produce an expiry.
//
// spec: SPO-Xconfirm-PR-022, SPO-Xconfirm-PR-026
func TestCarriedRecordMustMatchTheTransaction(t *testing.T) {
	for name, tc := range map[string]struct {
		carriedID  byte
		carriedTTL uint64
		why        string
	}{
		"edited bound": {5, 1, "validity bound"},
		"edited id":    {6, 1000, "names transaction"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			path := filepath.Join(r.dir, "offlineTransfer.json")
			_ = os.WriteFile(path, []byte(`{"protocol":{"era":"conway","parameters":{"txFeePerByte":44}},"history":[]}`), 0o600)
			f := &transferfile.File{Path: path}
			upd := domassets.Pending{TxID: chain.TxID{tc.carriedID}.String(), ValidUntil: u64(tc.carriedTTL), Record: "p.tok", Delta: "1"}
			raw, _ := upd.Marshal()
			_ = f.Enqueue(bg, ports.QueuedTx{Type: transfer.TypeAssetMinting, FromName: "w", FromAddr: "a", ToName: "w", ToAddr: "a",
				Tx: txbuild.SignedTx{CBOR: []byte{5}, ID: chain.TxID{5}}, Description: "d", Extra: []ports.QueuedField{{Key: transfer.KeyAssetPending, Value: string(raw)}}})
			if err := f.MutateBundle(bg, func(nb *transfer.Bundle) error {
				return nb.CompleteSubmit("05", chain.TxID{tc.carriedID}.String(), "date")
			}); err != nil {
				t.Fatal(err)
			}
			// Every provider has not seen it and its tip is past the edited bound only.
			st := r.settler(ports.TxWatcher{Status: &fakeStatus{name: "koios", reads: []chain.Reading[chain.TxStatus]{notSeen}}, Tip: tipAt(1 + txconfirmSlack + 1)})
			items, err := st.RecordInTransferFile(bg, f)
			if err != nil || len(items) != 1 || items[0].State != Inconsistent || !strings.Contains(items[0].Why, tc.why) {
				t.Fatalf("%v %+v", err, items)
			}
			b, _, _ := f.ReadBundle(bg)
			if oc, _ := b.Outcomes(); len(oc) != 0 {
				t.Errorf("an outcome was recorded for an inconsistent record: %+v", oc)
			}
		})
	}
}

func hexOf(b byte) []byte { return []byte(strings.ToLower(hexString([]byte{b}))) }
func hexString(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, d[c>>4], d[c&15])
	}
	return string(out)
}
