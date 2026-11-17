package assets

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/app/wallet"
	"github.com/mochipool/workbench/spo/internal/domain/assets"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/domain/txparam"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

// ---- fakes ---------------------------------------------------------------

type fakeChain struct {
	slot    uint64
	utxos   []chain.Utxo
	queries int
	tipErr  error
}

func (f *fakeChain) Source() chain.Source { return "fake" }
func (f *fakeChain) Tip(context.Context) (chain.Tip, error) {
	return chain.Tip{Slot: f.slot}, f.tipErr
}
func (f *fakeChain) Utxos(context.Context, chain.Address) ([]chain.Utxo, error) {
	f.queries++
	return f.utxos, nil
}
func (f *fakeChain) ProtocolParameters(context.Context) (chain.ProtocolParameters, error) {
	return chain.ProtocolParameters{ProtocolMajor: 11, MaxTxSize: 16384, TxFeePerByte: 44, TxFeeFixed: 155381, CoinsPerUTxOByte: 4310}, nil
}

type fakeQueue struct {
	got []ports.QueuedTx
	err error
}

func (q *fakeQueue) Enqueue(_ context.Context, tx ports.QueuedTx) error {
	if q.err != nil {
		return q.err
	}
	q.got = append(q.got, tx)
	return nil
}

type fakeSubmitter struct {
	got [][]byte
	err error
	// wrongID makes the provider accept the transaction and answer another id.
	wrongID bool
}

func (s *fakeSubmitter) Source() chain.Source { return "fake" }
func (s *fakeSubmitter) Submit(_ context.Context, tx []byte) (chain.TxID, error) {
	if s.err != nil {
		return chain.TxID{}, s.err
	}
	s.got = append(s.got, tx)
	if s.wrongID {
		return chain.TxID{0xee}, nil
	}
	return txIDOf(tx), nil
}

func txIDOf(tx []byte) chain.TxID {
	var items []cbor.RawMessage
	if err := cbor.Unmarshal(tx, &items); err != nil {
		panic(err)
	}
	return chain.TxID(blake2b.Sum256(items[0]))
}

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

type countingEncrypter struct{ n int }

func (c *countingEncrypter) EncryptMessages(l []string, _ *ports.Secret) ([]string, error) {
	c.n++
	return []string{"x"}, nil
}

type world struct {
	t     *testing.T
	dir   string
	store *plainstore.Store
	chain *fakeChain
	queue *fakeQueue
	sub   *fakeSubmitter
	addr  chain.Address
	clock fixedClock
}

func newWorld(t *testing.T) *world {
	t.Helper()
	dir := t.TempDir()
	store, err := plainstore.OpenTestnet(dir)
	if err != nil {
		t.Fatal(err)
	}
	led := native.Ledger{}
	acc, err := wallet.GeneratePaymentAccount{Store: store, KeyGen: native.SoftwareKeys{}, Addresses: led, NetworkID: ports.NetworkTestnet}.
		Run(context.Background(), wallet.GeneratePaymentRequest{Name: "w"})
	if err != nil {
		t.Fatal(err)
	}
	w := &world{t: t, dir: dir, store: store, addr: acc.Address, queue: &fakeQueue{}, sub: &fakeSubmitter{},
		clock: fixedClock{time.Date(2026, 11, 16, 9, 51, 2, 0, time.FixedZone("", 3600))}}
	w.chain = &fakeChain{slot: 1000, utxos: []chain.Utxo{{TxID: chain.TxID{1}, Index: 0, Lovelace: 50_000_000}}}
	return w
}

func (w *world) policy(name string, lifetime uint64) PolicyGenerated {
	w.t.Helper()
	g, err := GeneratePolicy{Store: w.store, KeyGen: native.SoftwareKeys{}, Policies: native.Ledger{}, Tip: w.chain}.
		Run(context.Background(), GeneratePolicyRequest{Name: name, Lifetime: lifetime})
	if err != nil {
		w.t.Fatal(err)
	}
	return g
}

func (w *world) base(queue bool) Base {
	led := native.Ledger{}
	b := Base{Store: w.store, Signers: native.Signers{Vault: w.store}, Utxos: w.chain, Params: w.chain, Tip: w.chain, Addresses: led,
		Policies: led, Min: led, Fees: led, Bodies: led, Assembler: led, Clock: w.clock, NetworkID: ports.NetworkTestnet, Approval: txflow.ApprovalSkip}
	if queue {
		b.Queue = w.queue
	} else {
		b.Submitter = w.sub
	}
	return b
}

func (w *world) file(name string) string {
	b, err := os.ReadFile(filepath.Join(w.dir, name))
	if err != nil {
		w.t.Fatal(err)
	}
	return string(b)
}

func (w *world) exists(name string) bool {
	_, err := os.Stat(filepath.Join(w.dir, name))
	return err == nil
}

func holds(w *world, policyID, name string, q uint64) {
	var p [28]byte
	b, _ := hex.DecodeString(policyID)
	copy(p[:], b)
	w.chain.utxos[0].Assets = []chain.AssetAmount{{Asset: chain.AssetID{Policy: p, Name: []byte(name)}, Quantity: q}}
}

// ---- policy --------------------------------------------------------------

// The four artefacts, written together; the script is the one upstream
// writes; the id is its hash with a newline; a lifetime is measured from the
// tip. A second run is refused and an existing artefact, whichever it is,
// stops everything before any key is made.
//
// spec: SPO-10-IF-001, SPO-10-IF-003, SPO-10-INV-001, SPO-10-INV-002, SPO-10-IN-001, SPO-10-IN-002, SPO-10-MODE-001,
// spec: SPO-10-PRE-001, SPO-10-OUT-002, SPO-10-OUT-005, SPO-10-OUT-006, SPO-10-EXT-001, SPO-10-EXT-003, SPO-10-EXT-004,
// spec: SPO-10-INV-004, SPO-10-INV-005, SPO-Pfiles-OUT-031, SPO-Pfiles-OUT-032
func TestGeneratePolicy(t *testing.T) {
	w := newWorld(t)
	free := w.policy("free", 0)
	locked := w.policy("locked", 5000) // the tip is slot 1000
	if free.Limited || !locked.Limited || locked.Expiry != 6000 {
		t.Errorf("free %+v locked %+v", free, locked)
	}
	for _, n := range []string{"free", "locked"} {
		for _, ext := range []string{".policy.vkey", ".policy.skey", ".policy.script", ".policy.id"} {
			info, err := os.Stat(filepath.Join(w.dir, n+ext))
			if err != nil || info.Mode().Perm() != 0o400 {
				t.Errorf("%s%s: %v %v", n, ext, info, err)
			}
		}
	}
	if w.file("free.policy.id") != free.PolicyID+"\n" || !strings.Contains(w.file("free.policy.script"), free.KeyHash) {
		t.Errorf("id file %q script %q", w.file("free.policy.id"), w.file("free.policy.script"))
	}
	if got, want := w.file("locked.policy.script"), string(assets.PolicyScript(locked.KeyHash, 6000, true)); got != want {
		t.Errorf("script %q, want %q", got, want)
	}
	h, _ := native.Ledger{}.PolicyID([]byte(w.file("locked.policy.script")))
	if hex.EncodeToString(h[:]) != locked.PolicyID {
		t.Errorf("id %s, hash of the script %x", locked.PolicyID, h)
	}
	if !strings.Contains(w.file("locked.policy.skey"), "PaymentSigningKeyShelley_ed25519") {
		t.Errorf("the policy key is a payment-type key: %s", w.file("locked.policy.skey"))
	}

	// an existing artefact of any kind refuses the name and writes nothing
	for _, kind := range []string{".policy.vkey", ".policy.script", ".policy.id", ".policy.hwsfile", ".policy.skey"} {
		if err := os.WriteFile(filepath.Join(w.dir, "taken"+kind), []byte("x"), 0o400); err != nil {
			t.Fatal(err)
		}
		_, err := GeneratePolicy{Store: w.store, KeyGen: native.SoftwareKeys{}, Policies: native.Ledger{}}.Run(context.Background(), GeneratePolicyRequest{Name: "taken"})
		if !errors.Is(err, ErrPolicyExists) {
			t.Errorf("%s: %v", kind, err)
		}
		os.Remove(filepath.Join(w.dir, "taken"+kind))
	}
	if w.exists("taken.policy.vkey") || w.exists("taken.policy.id") {
		t.Error("a refused policy left artefacts behind")
	}
	// a failed tip read aborts before anything is created (upstream goes on with a bogus expiry)
	w.chain.tipErr = errors.New("no tip")
	_, err := GeneratePolicy{Store: w.store, KeyGen: native.SoftwareKeys{}, Policies: native.Ledger{}, Tip: w.chain}.Run(context.Background(), GeneratePolicyRequest{Name: "late", Lifetime: 10})
	if err == nil || w.exists("late.policy.vkey") {
		t.Errorf("a failed tip read: %v", err)
	}
	// the tip is not read for an unlimited policy; a lifetime without a tip reader is a wiring error
	w.chain.tipErr = errors.New("no tip")
	if _, err := (GeneratePolicy{Store: w.store, KeyGen: native.SoftwareKeys{}, Policies: native.Ledger{}}).Run(context.Background(), GeneratePolicyRequest{Name: "nolife"}); err != nil {
		t.Errorf("an unlimited policy needs no tip: %v", err)
	}
	if _, err := (GeneratePolicy{Store: w.store, KeyGen: native.SoftwareKeys{}, Policies: native.Ledger{}}).Run(context.Background(), GeneratePolicyRequest{Name: "nt", Lifetime: 5}); !errors.Is(err, ErrMisconfigured) {
		t.Errorf("%v", err)
	}
	// a hardware policy key is refused up front; a directory part is not a name
	for _, req := range []GeneratePolicyRequest{{Name: "hw", Holder: custody.HolderHardware}, {Name: "dir/p"}, {Name: ""}, {Name: ".hidden"}} {
		if _, err := (GeneratePolicy{Store: w.store, KeyGen: native.SoftwareKeys{}, Policies: native.Ledger{}}).Run(context.Background(), req); err == nil {
			t.Errorf("%+v accepted", req)
		}
	}
	if w.exists("hw.policy.vkey") {
		t.Error("a hardware policy was half-made")
	}
}

// ---- mint and burn --------------------------------------------------------

func mintReq(asset, amount string, extra ...string) Request {
	ex, err := txparam.Parse(extra, txparam.ForMint)
	if err != nil {
		panic(err)
	}
	return Request{Asset: asset, Amount: amount, Payer: "w", Extras: &ex}
}

func mustMint(t *testing.T, b Base, req Request) Result {
	t.Helper()
	res, err := MintAsset{Base: b}.Run(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// A direct submission keeps the record as it is and writes a pending update
// under the transaction id (SPO-Xconfirm-PR-004); settling applies it once. The
// TTL is at the policy's before slot; the transaction carries the mint, two
// witnesses and the native script.
//
// spec: SPO-Xconfirm-PR-004
// spec: SPO-11a-IF-001, SPO-11a-IN-001, SPO-11a-IN-002, SPO-11a-IN-003, SPO-11a-INV-001, SPO-11a-INV-002, SPO-11a-INV-003,
// spec: SPO-11a-EXT-001, SPO-11a-EXT-003, SPO-11a-EXT-004, SPO-11a-MODE-001, SPO-11a-OUT-002, SPO-11a-OUT-003,
// spec: SPO-11a-INV-005, SPO-11a-SEC-001, SPO-11a-INV-017, SPO-11a-INV-014
func TestMintSubmitsAndKeepsAPendingUpdate(t *testing.T) {
	w := newWorld(t)
	locked := w.policy("pol", 5000)
	res := mustMint(t, w.base(false), mintReq("pol.tok", "100"))
	if !res.Submitted || res.Queued || !res.RecordPending || res.TTL != 6000 || !res.Limited || res.Expiry != 6000 || res.PolicyID != locked.PolicyID {
		t.Errorf("%+v", res)
	}
	if len(w.sub.got) != 1 {
		t.Fatalf("submitted %d", len(w.sub.got))
	}
	// Nothing in the record changes on an accepted submit; the update waits.
	if w.exists("pol.tok.asset") {
		t.Fatal("the record was written on the accepted submit")
	}
	pend, found, err := PendingOf(context.Background(), w.store, res.TxID)
	if err != nil || !found || pend.ValidUntil == nil || *pend.ValidUntil != 6000 || pend.Queued || pend.Delta != "100" {
		t.Fatalf("the pending update: %v %v %+v", err, found, pend)
	}
	// Applied once, on confirmation: a second settle finds nothing.
	st := Settle{Store: w.store, Clock: w.clock}
	if _, found, err := st.Apply(context.Background(), res.TxID); err != nil || !found {
		t.Fatalf("apply: %v %v", err, found)
	}
	if _, found, err := st.Apply(context.Background(), res.TxID); err != nil || found {
		t.Fatalf("a second apply: %v %v", err, found)
	}
	rec, err := assets.ParseRecord([]byte(w.file("pol.tok.asset")))
	if err != nil || rec.Get("minted") != "100" || rec.Get("policyValidBeforeSlot") != "6000" || rec.Get("lastAction") != "mint 100" ||
		rec.Get("lastUpdate") != "Mon, 16 Nov 2026 09:51:02 +0100" || rec.Get("policyID") != locked.PolicyID {
		t.Errorf("record: %v\n%s", err, w.file("pol.tok.asset"))
	}
	if info, _ := os.Stat(filepath.Join(w.dir, "pol.tok.asset")); info.Mode().Perm() != 0o400 {
		t.Errorf("record mode %v", info.Mode())
	}
	// the transaction: key 9, the script and two vkey witnesses
	var items []cbor.RawMessage
	if err := cbor.Unmarshal(w.sub.got[0], &items); err != nil {
		t.Fatal(err)
	}
	var body map[uint64]cbor.RawMessage
	cbor.Unmarshal(items[0], &body)
	var ws map[uint64]cbor.RawMessage
	cbor.Unmarshal(items[1], &ws)
	var vk cbor.Tag
	cbor.Unmarshal(ws[0], &vk)
	if _, ok := body[9]; !ok || len(vk.Content.([]any)) != 2 || ws[1] == nil {
		t.Errorf("body keys %v, witness keys %v", len(body), len(ws))
	}
	// the second mint adds to the record (a plain sig policy, no lock)
	w.policy("free", 0)
	for _, amount := range []string{"5", "7"} {
		r := mustMint(t, w.base(false), mintReq("free.tok", amount))
		if _, found, err := st.Apply(context.Background(), r.TxID); err != nil || !found {
			t.Fatalf("apply: %v %v", err, found)
		}
	}
	if r, _ := assets.ParseRecord([]byte(w.file("free.tok.asset"))); r.Get("minted") != "12" || r.Get("policyValidBeforeSlot") != "unlimited" {
		t.Errorf("%s", w.file("free.tok.asset"))
	}
	// an unlimited policy is valid for defTTL more slots
	if res := mustMint(t, w.base(false), mintReq("free.tok", "1")); res.TTL != 101000 || res.Limited {
		t.Errorf("ttl %d", res.TTL)
	} else if _, _, err := st.Apply(context.Background(), res.TxID); err != nil {
		t.Fatal(err)
	}
	// a hex name is filed under hex-
	hx := mustMint(t, w.base(false), mintReq("free.{00010203}", "1"))
	if _, _, err := st.Apply(context.Background(), hx.TxID); err != nil {
		t.Fatal(err)
	}
	if r, _ := assets.ParseRecord([]byte(w.file("free.hex-00010203.asset"))); r.Get("hexname") != "00010203" || r.Get("name") != "00010203" {
		t.Errorf("%s", w.file("free.hex-00010203.asset"))
	}
	// a refused submission keeps no pending update; one whose outcome is
	// unknown keeps it, the transaction may be in a block
	recBefore := w.file("free.tok.asset")
	w.sub.err = errors.New("node said no")
	if _, err := (MintAsset{Base: w.base(false)}).Run(context.Background(), mintReq("free.tok", "9")); err == nil || w.pendingFiles() != 0 {
		t.Errorf("a refused submission: %v", err)
	}
	w.sub.err = chain.NewOutcomeUnknown("the node did not answer")
	if _, err := (MintAsset{Base: w.base(false)}).Run(context.Background(), mintReq("free.tok", "9")); err == nil || !strings.Contains(err.Error(), "stays pending") || w.pendingFiles() != 1 {
		t.Errorf("an unknown outcome: %v (%d pending)", err, w.pendingFiles())
	}
	if w.file("free.tok.asset") != recBefore {
		t.Error("a submission that was refused or unknown changed the record")
	}
	// A provider that accepted the transaction and named another id left it
	// in flight: the pending record stays too (SPO-Xconfirm-PR-008).
	w.sub.err, w.sub.wrongID = nil, true
	before := w.pendingFiles()
	if _, err := (MintAsset{Base: w.base(false)}).Run(context.Background(), mintReq("free.tok", "7")); err == nil ||
		!strings.Contains(err.Error(), "stays pending") || !strings.Contains(err.Error(), "spo tx status") || w.pendingFiles() != before+1 {
		t.Errorf("an id mismatch: %v (%d pending, %d before)", err, w.pendingFiles(), before)
	}
}

// pendingFiles counts the pending update files of the workspace.
func (w *world) pendingFiles() int {
	es, _ := os.ReadDir(w.dir)
	n := 0
	for _, e := range es {
		if strings.HasSuffix(e.Name(), ".pending") || strings.HasSuffix(e.Name(), ".asset-pending") {
			n++
		}
	}
	return n
}

// Hazard H9: a queued mint changes no record; the update waits under the
// transaction id and is applied when the transaction is confirmed, once.
//
// spec: SPO-11a-MODE-002, SPO-11b-MODE-002, SPO-11a-OUT-002, SPO-11a-INV-017, SPO-11b-INV-015, SPO-Ptx-OUT-004, SPO-Xconfirm-PR-004
func TestQueuedMintUpdatesTheRecordOnConfirmation(t *testing.T) {
	w := newWorld(t)
	w.policy("free", 0)
	res := mustMint(t, w.base(true), mintReq("free.tok", "100"))
	if !res.Queued || !res.RecordPending {
		t.Fatalf("%+v", res)
	}
	if w.exists("free.tok.asset") {
		t.Fatal("the record was written when the transaction was queued")
	}
	pending := res.TxID.String() + ".pending"
	if !w.exists(pending) {
		t.Fatal("nothing waits for the confirmation")
	}
	q := w.queue.got[0]
	if q.Type != "Asset-Minting" || q.FromName != "w" || q.ToName != "w" || q.ToAddr != w.addr || q.Description != "minted 100 'tok' on 'w'" {
		t.Errorf("queue entry %+v", q)
	}
	// The queue entry carries the update, with the transaction's validity bound.
	if len(q.Extra) != 1 || !strings.Contains(q.Extra[0].Value, `"queued":true`) || !strings.Contains(q.Extra[0].Value, `"validUntil":`) {
		t.Errorf("carried update: %+v", q.Extra)
	}

	// Confirmation applies it, once, and removes the pending record.
	st := Settle{Store: w.store, Clock: w.clock}
	if _, found, err := st.Apply(context.Background(), res.TxID); err != nil || !found {
		t.Fatalf("apply: %v %v", err, found)
	}
	rec, _ := assets.ParseRecord([]byte(w.file("free.tok.asset")))
	if rec.Get("minted") != "100" || rec.Get("lastAction") != "mint 100 (only Offline proof)" || w.exists(pending) {
		t.Errorf("record after the confirmation: %s", w.file("free.tok.asset"))
	}
	if rec.Get("lastUpdate") != "Mon, 16 Nov 2026 09:51:02 +0100" {
		t.Errorf("lastUpdate is the time of the submission: %s", w.file("free.tok.asset"))
	}
	if _, found, err := st.Apply(context.Background(), res.TxID); err != nil || found {
		t.Fatalf("a repeat: %v %v", err, found)
	}
	if r, _ := assets.ParseRecord([]byte(w.file("free.tok.asset"))); r.Get("minted") != "100" {
		t.Error("the record was updated twice")
	}
	// a damaged pending update is an error and changes nothing
	res2 := mustMint(t, w.base(true), mintReq("free.tok", "5"))
	p2 := filepath.Join(w.dir, res2.TxID.String()+".pending")
	os.Chmod(p2, 0o600)
	os.WriteFile(p2, []byte("{broken"), 0o400)
	if _, _, err := st.Apply(context.Background(), res2.TxID); err == nil {
		t.Error("a damaged pending update was applied")
	}
	if r, _ := assets.ParseRecord([]byte(w.file("free.tok.asset"))); r.Get("minted") != "100" {
		t.Error("a damaged pending update changed the record")
	}
	// a queue that fails leaves no pending update behind
	w.queue.err = errors.New("disk full")
	n := w.pendingFiles()
	if _, err := (MintAsset{Base: w.base(true)}).Run(context.Background(), mintReq("free.tok", "3")); err == nil {
		t.Error("a failed queue")
	}
	if m := w.pendingFiles(); m != n {
		t.Errorf("pending updates: %d before, %d after a failed queue", n, m)
	}
}

// A crash between the application of an update and the removal of the pending
// record must not apply it twice: both are one store commit. The commit is
// simulated by an applier that fails after changing the record: neither stays.
//
// spec: SPO-Xconfirm-PR-014
func TestApplyIsOneCommitWithTheRemoval(t *testing.T) {
	w := newWorld(t)
	w.policy("free", 0)
	res := mustMint(t, w.base(false), mintReq("free.tok", "100"))
	boom := errors.New("crash between the apply and the removal")
	// An update whose removal cannot happen: the store refuses the delete.
	broken := Settle{Store: failDelete{w.store, boom}, Clock: w.clock}
	if _, _, err := broken.Apply(context.Background(), res.TxID); !errors.Is(err, boom) {
		t.Fatalf("apply: %v", err)
	}
	if w.exists("free.tok.asset") {
		t.Fatal("the record changed although the commit failed: a retry would apply twice")
	}
	if _, found, _ := (Settle{Store: w.store, Clock: w.clock}).Apply(context.Background(), res.TxID); !found {
		t.Fatal("the pending update was lost")
	}
	if r, _ := assets.ParseRecord([]byte(w.file("free.tok.asset"))); r.Get("minted") != "100" {
		t.Errorf("%s", w.file("free.tok.asset"))
	}
}

// failDelete is a store whose writer cannot delete: the commit rolls back.
type failDelete struct {
	ports.Store
	err error
}

func (f failDelete) Update(ctx context.Context, fn func(ports.Writer) error) error {
	return f.Store.Update(ctx, func(w ports.Writer) error {
		return fn(noDelete{w, f.err})
	})
}

type noDelete struct {
	ports.Writer
	err error
}

func (n noDelete) Delete(ports.Ref) error { return n.err }

// A workspace written by the first version holds `<txid>.asset-pending`, a
// record without a kind: it still settles, as an asset update.
//
// spec: SPO-Xconfirm-PR-005
func TestLegacyAssetPendingStillSettles(t *testing.T) {
	w := newWorld(t)
	w.policy("free", 0)
	res := mustMint(t, w.base(true), mintReq("free.tok", "100"))
	// Rewrite the pending update as the first version wrote it.
	cur, err := os.ReadFile(filepath.Join(w.dir, res.TxID.String()+".pending"))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := assets.ParsePending(cur)
	legacy := fmt.Sprintf(`{"txid":%q,"record":%q,"policy":%q,"nameHex":%q,"hexTyped":false,"delta":"100","validBefore":%q,"action":%q}`,
		p.TxID, p.Record, p.Policy, p.NameHex, p.ValidBefore, p.Action)
	os.Remove(filepath.Join(w.dir, res.TxID.String()+".pending"))
	if err := os.WriteFile(filepath.Join(w.dir, res.TxID.String()+".asset-pending"), []byte(legacy), 0o400); err != nil {
		t.Fatal(err)
	}
	list, ok, err := ListPending(context.Background(), w.store, w.store)
	if err != nil || !ok || len(list) != 1 || list[0].KindOrAsset() != assets.PendingAsset {
		t.Fatalf("list: %v %v %+v", err, ok, list)
	}
	if _, found, err := (Settle{Store: w.store, Clock: w.clock}).Apply(context.Background(), res.TxID); err != nil || !found {
		t.Fatalf("apply: %v %v", err, found)
	}
	if r, _ := assets.ParseRecord([]byte(w.file("free.tok.asset"))); r.Get("minted") != "100" || w.exists(res.TxID.String()+".asset-pending") {
		t.Errorf("%s", w.file("free.tok.asset"))
	}
}

// spec: SPO-11a-IF-002, SPO-11a-IF-003, SPO-11a-IF-004, SPO-11a-PRE-001, SPO-11a-PRE-002, SPO-11a-PRE-003, SPO-11a-PRE-004, SPO-11a-IN-001,
// spec: SPO-11a-IN-002, SPO-11a-IN-003, SPO-11b-IN-001, SPO-11b-IN-002, SPO-11a-PR-001, SPO-11a-INV-004, SPO-11a-EXT-002,
// spec: SPO-11a-INV-007, SPO-11b-INV-005
func TestMintRefusals(t *testing.T) {
	w := newWorld(t)
	w.policy("pol", 5000)
	w.policy("free", 0)
	run := func(req Request) error {
		_, err := MintAsset{Base: w.base(false)}.Run(context.Background(), req)
		return err
	}
	// the words, before any file or query
	for _, req := range []Request{
		mintReq("free", "1"), mintReq("free.a.b", "1"), mintReq("free.my token", "1"), mintReq("free."+strings.Repeat("a", 33), "1"),
		mintReq("free.{00}", "0"), mintReq("free.tok", "-1"), mintReq("free.tok", "x"), mintReq("free.tok", "9223372036854775808"), mintReq("a/b.tok", "1"),
	} {
		if err := run(req); err == nil {
			t.Errorf("%+v accepted", req)
		}
	}
	if w.chain.queries != 0 {
		t.Error("a bad word reached the chain")
	}
	// missing files
	if err := run(mintReq("nopolicy.tok", "1")); !errors.Is(err, ErrPolicyFiles) {
		t.Errorf("no policy: %v", err)
	}
	os.Chmod(filepath.Join(w.dir, "free.policy.skey"), 0o600)
	os.Remove(filepath.Join(w.dir, "free.policy.skey"))
	if err := run(mintReq("free.tok", "1")); !errors.Is(err, ErrPolicyFiles) {
		t.Errorf("no policy key: %v", err)
	}
	w.policy("free2", 0)
	// a hardware-held policy key cannot sign here
	os.WriteFile(filepath.Join(w.dir, "free2.policy.hwsfile"), []byte("{}"), 0o400)
	if err := run(mintReq("free2.tok", "1")); err == nil {
		t.Error("a hardware policy key")
	}
	os.Remove(filepath.Join(w.dir, "free2.policy.hwsfile"))
	// payer
	r := mintReq("free2.tok", "1")
	r.Payer = "nobody"
	if err := run(r); !errors.Is(err, ErrNoPayer) {
		t.Errorf("no payer: %v", err)
	}
	r.Payer = "w.addr"
	if err := run(r); err != nil {
		t.Errorf("a payer name with .addr: %v", err)
	}
	os.WriteFile(filepath.Join(w.dir, "hw.addr"), []byte(w.addr), 0o400)
	os.WriteFile(filepath.Join(w.dir, "hw.hwsfile"), []byte("{}"), 0o400)
	w.chain.queries = 0
	r.Payer = "hw"
	if err := run(r); err == nil || w.chain.queries == 0 && false {
		t.Errorf("a hardware payer: %v", err)
	}
	// the id file and the key must belong to the script
	os.Chmod(filepath.Join(w.dir, "free2.policy.id"), 0o600)
	os.WriteFile(filepath.Join(w.dir, "free2.policy.id"), []byte(strings.Repeat("ab", 28)+"\n"), 0o400)
	if err := run(mintReq("free2.tok", "1")); !errors.Is(err, ErrPolicyMismatch) {
		t.Errorf("a wrong id file: %v", err)
	}
	// an expired policy is refused before any UTxO query (upstream exit 2)
	w.chain.slot = 6000
	w.chain.queries = 0
	if err := run(mintReq("pol.tok", "1")); !errors.Is(err, ErrPolicyExpired) || w.chain.queries != 0 {
		t.Errorf("expired: %v, %d queries", err, w.chain.queries)
	}
	w.chain.slot = 5999
	if err := run(mintReq("pol.tok", "1")); err != nil {
		t.Errorf("one slot before the expiry: %v", err)
	}
	w.chain.slot = 1000
	// the filters of 11a: only the UTxO list; the sibling's tokens are not known
	if _, err := txparam.Parse([]string{"utxolimit:2"}, txparam.ForMint); err == nil {
		t.Error("utxolimit is not an 11a token")
	}
	// no funds
	w.policy("ok", 0)
	w.chain.utxos = nil
	if err := run(mintReq("ok.tok", "1")); !errors.Is(err, txbuild.ErrNoFunds) {
		t.Errorf("no funds: %v", err)
	}
	// the change must hold its minimum: 1 lovelace short is refused, nothing submitted
	w.chain.utxos = []chain.Utxo{{TxID: chain.TxID{1}, Lovelace: 300_000}}
	n := len(w.sub.got)
	var below *txbuild.BelowMinimumError
	if err := run(mintReq("ok.tok", "1")); err == nil || (!errors.As(err, &below) && !errors.Is(err, txbuild.ErrInsufficient)) || len(w.sub.got) != n {
		t.Errorf("a change below the minimum: %v", err)
	}
}

// spec: SPO-11b-IF-001, SPO-11b-IF-003, SPO-11b-INV-001, SPO-11b-PRE-001, SPO-11b-PRE-002, SPO-11b-PRE-003, SPO-11b-EXT-001,
// spec: SPO-11b-MODE-001, SPO-11b-OUT-001, SPO-11b-OUT-002, SPO-11b-INV-003, SPO-11b-SEC-001
func TestBurn(t *testing.T) {
	w := newWorld(t)
	g := w.policy("free", 0)
	holds(w, g.PolicyID, "tok", 100)
	burn := func(amount string, extra ...string) (Result, error) {
		req := mintReq("free.tok", amount, extra...)
		return BurnAsset{Base: w.base(false)}.Run(context.Background(), req)
	}
	// more than is held: refused with the holding, before a body is built, with a non-zero exit (upstream exits 0)
	if _, err := burn("101"); !errors.Is(err, txbuild.ErrBurnExceedsHolding) || !strings.Contains(err.Error(), "100") || len(w.sub.got) != 0 {
		t.Errorf("burn too much: %v", err)
	}
	// an asset not held at all is refused the same way
	holds(w, g.PolicyID, "other", 5)
	if _, err := burn("1"); !errors.Is(err, txbuild.ErrBurnExceedsHolding) {
		t.Errorf("not held: %v", err)
	}
	holds(w, g.PolicyID, "tok", 100)
	res, err := burn("30")
	if err != nil || !res.RecordPending || w.exists("free.tok.asset") {
		t.Fatalf("%v %+v", err, res)
	}
	if _, _, err := (Settle{Store: w.store, Clock: w.clock}).Apply(context.Background(), res.TxID); err != nil {
		t.Fatal(err)
	}
	rec, _ := assets.ParseRecord([]byte(w.file("free.tok.asset")))
	if rec.Get("minted") != "-30" || rec.Get("lastAction") != "burn 30" {
		t.Errorf("%s", w.file("free.tok.asset"))
	}
	// one record name for every mode: a queued burn files under the same name
	res, err = BurnAsset{Base: w.base(true)}.Run(context.Background(), mintReq("free.tok", "70"))
	if err != nil || !res.Queued || w.queue.got[0].Type != "Asset-Burning" || w.queue.got[0].Description != "burned 70 'tok' on 'w'" {
		t.Fatalf("%v %+v", err, w.queue.got)
	}
	if _, _, err := (Settle{Store: w.store, Clock: w.clock}).Apply(context.Background(), res.TxID); err != nil {
		t.Fatal(err)
	}
	if r, _ := assets.ParseRecord([]byte(w.file("free.tok.asset"))); r.Get("minted") != "-100" || r.Get("lastAction") != "burn 70 (only Offline proof)" {
		t.Errorf("%s", w.file("free.tok.asset"))
	}
	if w.exists("free.746f6b.asset") {
		t.Error("an offline burn started a second record under the hex name")
	}
	// no UTxOs: an error, not upstream's exit 0
	w.chain.utxos = nil
	if _, err := burn("1"); !errors.Is(err, txbuild.ErrNoFunds) {
		t.Errorf("no funds: %v", err)
	}
	// a message goes through the encrypter once
	w.chain.utxos = []chain.Utxo{{TxID: chain.TxID{1}, Lovelace: 50_000_000}}
	holds(w, g.PolicyID, "tok", 10)
	enc := &countingEncrypter{}
	b := w.base(false)
	b.Encrypter = enc
	if _, err := (BurnAsset{Base: b}).Run(context.Background(), mintReq("free.tok", "1", "msg:hi", "enc:basic")); err != nil || enc.n != 1 {
		t.Errorf("%v %d", err, enc.n)
	}
	_ = fmt.Sprint
}
