package wallet

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/porttest"
)

// ---- fakes -----------------------------------------------------------------

// log records the order of effects.
type log struct{ calls []string }

func (l *log) add(s string) { l.calls = append(l.calls, s) }
func (l *log) index(prefix string) int {
	for i, c := range l.calls {
		if strings.HasPrefix(c, prefix) {
			return i
		}
	}
	return -1
}
func (l *log) count(prefix string) (n int) {
	for _, c := range l.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return
}

type memReader map[ports.Ref][]byte

func (m memReader) Get(r ports.Ref) ([]byte, error) {
	if b, ok := m[r]; ok {
		return b, nil
	}
	return nil, ports.ErrNotFound
}
func (m memReader) Exists(r ports.Ref) (bool, error) { _, ok := m[r]; return ok, nil }

type memStore struct {
	files memReader
	views int
}

// List implements ports.SourceLister: every stored file.
func (s *memStore) List(context.Context) (ports.SourceListing, error) {
	var l ports.SourceListing
	for r := range s.files {
		l.Entries = append(l.Entries, ports.SourceEntry{Ref: r})
	}
	return l, nil
}

func (s *memStore) View(_ context.Context, fn func(ports.Reader) error) error {
	s.views++
	return fn(s.files)
}
func (s *memStore) Update(context.Context, func(ports.Writer) error) error {
	panic("a payment writes no artefact")
}

// Fake addresses: "addr_test_<name>" is a payment address of the testnet,
// "addr_main_<name>" of the mainnet, "stake_test_<name>" a reward address.
// The key hash of "addr_test_src" is that of the fake key.
type fakeInspector struct{ srcHash txbuild.KeyHash }

func (f fakeInspector) InspectAddress(a chain.Address) (ports.AddressInfo, error) {
	s := string(a)
	var info ports.AddressInfo
	switch {
	case strings.HasPrefix(s, "addr_test_"):
		info = ports.AddressInfo{Kind: ports.AddrEnterprise, NetworkID: ports.NetworkTestnet}
	case strings.HasPrefix(s, "addr_main_"):
		info = ports.AddressInfo{Kind: ports.AddrEnterprise, NetworkID: ports.NetworkMainnet}
	case strings.HasPrefix(s, "stake_test_"):
		return ports.AddressInfo{Kind: ports.AddrReward, NetworkID: ports.NetworkTestnet}, nil
	case strings.HasPrefix(s, "addr_script_"):
		return ports.AddressInfo{Kind: ports.AddrEnterprise, PaymentIsScript: true}, nil
	default:
		return ports.AddressInfo{}, errors.New("not an address")
	}
	h := f.srcHash
	if s != "addr_test_src" {
		h = txbuild.HashKey([]byte(s))
	}
	info.PaymentKeyHash = &h
	return info, nil
}

type fakeLedger struct {
	l       *log
	utxoMin chain.Lovelace
}

func (f *fakeLedger) MinOutput(_ chain.ProtocolParameters, o txbuild.Output) (chain.Lovelace, error) {
	return 1_000_000 + chain.Lovelace(len(o.Assets))*10_000, nil
}
func (f *fakeLedger) EstimateFee(_ chain.ProtocolParameters, b txbuild.TxBody, n uint) (chain.Lovelace, error) {
	f.l.add(fmt.Sprintf("fee witnesses=%d", n))
	return chain.Lovelace(150_000 + 10*len(b.CBOR)), nil
}
func (f *fakeLedger) EstimateSize(b txbuild.TxBody, _ uint) (int, error) {
	return len(b.CBOR) + 100, nil
}
func (f *fakeLedger) BuildBody(s txbuild.BodySpec) (txbuild.TxBody, error) {
	f.l.add("build")
	b, _ := json.Marshal(s)
	return txbuild.TxBody{CBOR: b, ID: sha256.Sum256(b)}, nil
}
func (f *fakeLedger) Assemble(b txbuild.TxBody, ws []txbuild.Witness) (txbuild.SignedTx, error) {
	f.l.add("assemble")
	out := append(append([]byte(nil), b.CBOR...), ws[0].Signature[:]...)
	return txbuild.SignedTx{CBOR: out, ID: b.ID}, nil
}

// fakeSigner holds one Ed25519 key. mode corrupts what it returns.
type fakeSigner struct {
	l       *log
	profile custody.Profile
	priv    ed25519.PrivateKey
	other   ed25519.PrivateKey
	mode    string // "", "wrong-key", "bad-signature", "error"
}

func (s *fakeSigner) Profile() custody.Profile { return s.profile }
func (s *fakeSigner) Witness(_ context.Context, key custody.KeyRef, body txbuild.TxBody) (txbuild.Witness, error) {
	s.l.add("witness w")
	k := s.priv
	switch s.mode {
	case "wrong-key":
		k = s.other
	case "error":
		return txbuild.Witness{}, errors.New("the device refused")
	}
	var w txbuild.Witness
	copy(w.VKey[:], k.Public().(ed25519.PublicKey))
	msg := body.ID[:]
	if s.mode == "bad-signature" {
		msg = []byte("something else")
	}
	copy(w.Signature[:], ed25519.Sign(k, msg))
	return w, nil
}

// vkeyEnv is a verification key envelope of a fake key.
func vkeyEnv(typ string, pub ed25519.PublicKey) []byte {
	return pool.MarshalEnvelope(pool.Envelope{Type: typ, Description: "fake", CborHex: "5820" + fmt.Sprintf("%x", []byte(pub))})
}

// fakeDir serves one signer for the keys whose signing key the store holds.
func fakeDir(st ports.Store, s ports.Signer) ports.SignerDirectory { return porttest.VaultOnly(st, s) }

type fakeChain struct {
	l       *log
	utxos   []chain.Utxo
	utxoErr error
	params  chain.ProtocolParameters
	parErr  error
	tipErr  error
	slot    uint64
}

func (f *fakeChain) Source() chain.Source { return "fake" }
func (f *fakeChain) Tip(context.Context) (chain.Tip, error) {
	f.l.add("tip")
	return chain.Tip{Slot: f.slot}, f.tipErr
}
func (f *fakeChain) Utxos(_ context.Context, a chain.Address) ([]chain.Utxo, error) {
	f.l.add("utxos " + string(a))
	return f.utxos, f.utxoErr
}
func (f *fakeChain) ProtocolParameters(context.Context) (chain.ProtocolParameters, error) {
	f.l.add("params")
	return f.params, f.parErr
}

type fakeConfirmer struct {
	l   *log
	yes bool
	err error
	got ports.TxSummary
}

func (c *fakeConfirmer) Confirm(_ context.Context, s ports.TxSummary) (bool, error) {
	c.l.add("confirm")
	c.got = s
	return c.yes, c.err
}

type fakeSubmitter struct {
	l   *log
	err error
	id  *chain.TxID // overrides the answer
	got []byte
}

func (s *fakeSubmitter) Source() chain.Source { return "fake" }
func (s *fakeSubmitter) Submit(_ context.Context, tx []byte) (chain.TxID, error) {
	s.l.add("submit")
	s.got = tx
	if s.err != nil {
		return chain.TxID{}, s.err
	}
	if s.id != nil {
		return *s.id, nil
	}
	// The fake ledger puts the id in front of nothing; recompute from the body.
	return chain.TxID{}, errors.New("test must set id")
}

type fakeQueue struct {
	l   *log
	err error
	got []ports.QueuedTx
}

func (q *fakeQueue) Enqueue(_ context.Context, tx ports.QueuedTx) error {
	q.l.add("enqueue")
	q.got = append(q.got, tx)
	return q.err
}

// ---- rig -------------------------------------------------------------------

type rig struct {
	l       *log
	store   *memStore
	chain   *fakeChain
	ledger  *fakeLedger
	signer  *fakeSigner
	conf    *fakeConfirmer
	queue   *fakeQueue
	submit  *fakeSubmitter
	uc      SendLovelaces
	srcAddr string
}

func newRig(t *testing.T) *rig {
	t.Helper()
	l := &log{}
	pub, priv, _ := ed25519.GenerateKey(nil)
	_, other, _ := ed25519.GenerateKey(nil)
	r := &rig{l: l, srcAddr: "addr_test_src"}
	r.store = &memStore{files: memReader{
		{Name: "w", Kind: ports.AddrFile}:         []byte("addr_test_src\n"),
		{Name: "w", Kind: ports.AddrSKey}:         nil,
		{Name: "w", Kind: ports.AddrVKey}:         vkeyEnv("PaymentVerificationKeyShelley_ed25519", pub),
		{Name: "d", Kind: ports.AddrFile}:         []byte("addr_test_dst\n"),
		{Name: "w.payment", Kind: ports.AddrFile}: []byte("addr_test_src\n"),
		{Name: "w.payment", Kind: ports.AddrSKey}: nil,
		{Name: "w.payment", Kind: ports.AddrVKey}: vkeyEnv("PaymentVerificationKeyShelley_ed25519", pub),
	}}
	var id chain.TxID
	id[0] = 1
	r.chain = &fakeChain{l: l, slot: 1000, utxos: []chain.Utxo{
		{TxID: id, Index: 0, Lovelace: 30_000_000},
		{TxID: chain.TxID{2}, Index: 1, Lovelace: 20_000_000, Assets: []chain.AssetAmount{{Asset: chain.AssetID{Policy: [28]byte{9}, Name: []byte("t")}, Quantity: 4}}},
	}, params: chain.ProtocolParameters{ProtocolMajor: 11, MaxTxSize: 16384, CoinsPerUTxOByte: 4310}}
	r.ledger = &fakeLedger{l: l}
	r.signer = &fakeSigner{l: l, priv: priv, other: other,
		profile: custody.NewProfile("fake").Allow(custody.RolePayment, custody.OpWitnessTx)}
	r.conf = &fakeConfirmer{l: l, yes: true}
	r.queue = &fakeQueue{l: l}
	r.submit = &fakeSubmitter{l: l}
	r.uc = SendLovelaces{
		Store: r.store, Signers: fakeDir(r.store, r.signer), Utxos: r.chain, Params: r.chain, Tip: r.chain,
		Addresses: fakeInspector{srcHash: txbuild.HashKey(pub)}, Min: r.ledger, Fees: r.ledger, Bodies: r.ledger, Assembler: r.ledger,
		Confirmer: r.conf, Queue: r.queue, NetworkID: ports.NetworkTestnet,
	}
	return r
}

func (r *rig) run(amount string) (SendResult, error) {
	return r.uc.Run(context.Background(), SendRequest{Source: "w", Destination: "d", Amount: amount})
}

// ---- tests -----------------------------------------------------------------

// The whole pipeline, offline composition: queue, with the order of effects
// the spec fixes. The plan is made before any body is built (ADR 0008), the
// operator is asked before anything is signed, and the body is built only
// before the confirmation (hazard H2; SPO-Ptx-INV-010).
//
// spec: SPO-01sendLovelaces-IF-001, SPO-01sendLovelaces-INV-002, SPO-01sendLovelaces-INV-003, SPO-01sendLovelaces-INV-004,
// spec: SPO-01sendLovelaces-INV-005, SPO-01sendLovelaces-INV-006, SPO-01sendLovelaces-INV-007, SPO-01sendLovelaces-INV-008,
// spec: SPO-01sendLovelaces-INV-009, SPO-01sendLovelaces-INV-010, SPO-01sendLovelaces-INV-011, SPO-01sendLovelaces-INV-012,
// spec: SPO-01sendLovelaces-INV-013, SPO-01sendLovelaces-OUT-007, SPO-01sendLovelaces-OUT-008, SPO-01sendLovelaces-PR-001,
// spec: SPO-Ptx-INV-010, SPO-Ptx-INV-006, SPO-Ptx-INV-001, SPO-Ptx-INV-002, SPO-Ptx-PR-002, SPO-Ptx-MODE-010, SPO-Ptx-INV-008,
// spec: SPO-Ptx-EXT-006, SPO-Ptransfer-OUT-010, SPO-01sendLovelaces-IN-002, SPO-Ptx-OUT-002
func TestSendQueuesWhatWasConfirmed(t *testing.T) {
	r := newRig(t)
	res, err := r.run("5000000")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Queued || res.Submitted {
		t.Errorf("queued=%v submitted=%v", res.Queued, res.Submitted)
	}
	// Order: query, plan-checked build, confirm, then witness, assemble, queue.
	lastBuild := -1
	for i, c := range r.l.calls {
		if c == "build" {
			lastBuild = i
		}
	}
	if !(r.l.index("tip") < r.l.index("build") && lastBuild < r.l.index("confirm") &&
		r.l.index("confirm") < r.l.index("witness") && r.l.index("witness") < r.l.index("assemble") &&
		r.l.index("assemble") < r.l.index("enqueue")) {
		t.Errorf("order of effects: %v", r.l.calls)
	}
	// Nothing is rebuilt after the confirmation.
	for _, c := range r.l.calls[r.l.index("confirm"):] {
		if c == "build" {
			t.Errorf("the body was rebuilt after the confirmation: %v", r.l.calls)
		}
	}
	// What the operator saw is what was queued.
	if r.conf.got.TxID != res.TxID || r.queue.got[0].Tx.ID != res.TxID {
		t.Errorf("confirmed %s, queued %s, result %s", r.conf.got.TxID, r.queue.got[0].Tx.ID, res.TxID)
	}
	// Every UTxO of the paying address is spent (INV-002); TTL = tip + 100000 (INV-001).
	if res.Inputs != 2 || res.TTL != 101000 {
		t.Errorf("inputs %d, ttl %d", res.Inputs, res.TTL)
	}
	// The fee is estimated for one witness, the constant of INV-006.
	if r.l.count("fee witnesses=1") == 0 || r.l.count("fee witnesses=2") != 0 {
		t.Errorf("fee witness counts: %v", r.l.calls)
	}
	q := r.queue.got[0]
	if q.Type != "Transaction" || q.FromName != "w" || q.ToName != "d" || q.FromAddr != "addr_test_src" || q.ToAddr != "addr_test_dst" {
		t.Errorf("queue entry %+v", q)
	}
	if q.Description != "signed utxo-transaction from 'w' to 'd'" {
		t.Errorf("history text %q", q.Description)
	}
	if r.conf.got.Route != "queue" || r.conf.got.Fee != res.Fee {
		t.Errorf("summary %+v", r.conf.got)
	}
}

// Online composition: the transaction is submitted.
//
// spec: SPO-Ptx-MODE-008, SPO-Ptx-MODE-009, SPO-Ptx-INV-010, SPO-01sendLovelaces-OUT-008
func TestSendSubmits(t *testing.T) {
	r := newRig(t)
	r.uc.Queue, r.uc.Submitter = nil, r.submit
	// The fake chain returns the id the body has: fake it from the summary.
	r.submit.id = new(chain.TxID)
	r.uc.Confirmer = confirmerFunc(func(s ports.TxSummary) { *r.submit.id = s.TxID })
	res, err := r.run("5000000")
	if err != nil || !res.Submitted || res.Queued {
		t.Fatalf("%+v %v", res, err)
	}
	if string(r.submit.got) != string(res.SignedTx) {
		t.Error("the submitted bytes are not the signed transaction of the result")
	}

	// A provider that answers another id is an error.
	r2 := newRig(t)
	r2.uc.Queue, r2.uc.Submitter = nil, r2.submit
	r2.submit.id = &chain.TxID{0xff}
	if _, err := r2.run("5000000"); err == nil || !strings.Contains(err.Error(), "answered transaction id") {
		t.Errorf("a different id: %v", err)
	}

	// Decision (SPO-Ptx-MODE-008, MODE-009 quirk): a failed submit is an
	// error. Upstream exits 0 in light mode and in 06, 08b, 22b, 23c, 23e.
	r3 := newRig(t)
	r3.uc.Queue, r3.uc.Submitter = nil, r3.submit
	r3.submit.err = errors.New("HTTP 500")
	if _, err := r3.run("5000000"); err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("a failed submit: %v", err)
	}
}

type confirmerFunc func(ports.TxSummary)

func (f confirmerFunc) Confirm(_ context.Context, s ports.TxSummary) (bool, error) {
	f(s)
	return true, nil
}

// Exactly one way out.
func TestOneOfSubmitterAndQueue(t *testing.T) {
	r := newRig(t)
	r.uc.Submitter = r.submit
	if _, err := r.run("5"); !errors.Is(err, ErrMisconfigured) {
		t.Errorf("both: %v", err)
	}
	r.uc.Queue, r.uc.Submitter = nil, nil
	if _, err := r.run("5"); !errors.Is(err, ErrMisconfigured) {
		t.Errorf("neither: %v", err)
	}
}

// A decline is an error that nothing follows: no witness, no submission, no
// queue entry. The default of the confirmation is No: an error from the
// confirmer is a refusal too.
//
// spec: SPO-Ptx-PR-002
func TestDeclineStopsBeforeSigning(t *testing.T) {
	r := newRig(t)
	r.conf.yes = false
	if _, err := r.run("5000000"); !errors.Is(err, ErrDeclined) {
		t.Fatalf("%v", err)
	}
	for _, c := range []string{"witness", "assemble", "enqueue", "submit"} {
		if r.l.count(c) != 0 {
			t.Errorf("%s ran after a decline: %v", c, r.l.calls)
		}
	}
	r.conf.err = errors.New("input closed")
	if _, err := r.run("5000000"); err == nil || r.l.count("witness") != 0 {
		t.Errorf("a failed confirmation proceeded: %v", err)
	}
}

// Skipping the confirmation is an explicit policy, recorded in the result;
// without a policy and without a confirmer nothing proceeds.
//
// spec: SPO-Ptx-SEC-003, SPO-Ptx-PR-003, SPO-01sendLovelaces-SEC-002
func TestApprovalPolicy(t *testing.T) {
	r := newRig(t)
	r.uc.Confirmer = nil
	if _, err := r.run("5000000"); !errors.Is(err, ErrNoConfirmer) {
		t.Errorf("no confirmer, no policy: %v", err)
	}
	if r.l.count("witness") != 0 {
		t.Error("signed without approval")
	}
	r.uc.Approval = ApprovalSkip
	res, err := r.run("5000000")
	if err != nil || !res.ApprovalSkipped || !res.Queued {
		t.Errorf("%+v %v", res, err)
	}
	if r.l.count("confirm") != 0 {
		t.Error("the confirmer was asked under the skip policy")
	}
	if (SendLovelaces{}).Approval != ApprovalAsk {
		t.Error("the default policy must be to ask")
	}
}

// A bad amount is refused before any store or chain access.
//
// spec: SPO-01sendLovelaces-IF-002, SPO-01sendLovelaces-IF-001, SPO-Ptx-IF-002
//
// Decision (IF-001, Ptx-IF-002): upstream prints usage and exits 1 when a word is
// missing; the use case refuses a request with an empty source, destination or
// amount, and the usage text is the command's.
func TestBadAmountTouchesNothing(t *testing.T) {
	for _, amount := range []string{"", "ten", "1.5", "-3", "010"} {
		r := newRig(t)
		if _, err := r.run(amount); err == nil {
			t.Errorf("%q accepted", amount)
		}
		if r.store.views != 0 || len(r.l.calls) != 0 {
			t.Errorf("%q: store views %d, calls %v", amount, r.store.views, r.l.calls)
		}
	}
	r := newRig(t)
	if _, err := r.uc.Run(context.Background(), SendRequest{Source: "w", Amount: "5"}); err == nil {
		t.Error("a missing destination was accepted")
	}
}

// A message line over 64 bytes is refused before any access.
//
// spec: SPO-Pparam-PRE-001
func TestLongMessageRefused(t *testing.T) {
	r := newRig(t)
	_, err := r.uc.Run(context.Background(), SendRequest{Source: "w", Destination: "d", Amount: "5000000", Message: []string{strings.Repeat("x", 65)}})
	if !errors.Is(err, txbuild.ErrBadMessage) || r.store.views != 0 {
		t.Errorf("%v (views %d)", err, r.store.views)
	}
	res, err := r.uc.Run(context.Background(), SendRequest{Source: "w", Destination: "d", Amount: "5000000", Message: []string{"hi"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := r.queue.got[0]; got.Type != "Transaction" || res.Queued != true {
		t.Error(got)
	}
	if !strings.Contains(string(res.SignedTx), `"Message":["hi"]`) {
		t.Errorf("the message did not reach the body: %s", res.SignedTx)
	}
}

// The source: name normalisation, missing files and their order.
//
// spec: SPO-Ptx-IN-001, SPO-Ptx-IN-002, SPO-01sendLovelaces-IN-001, SPO-Pfiles-IN-001, SPO-Pfiles-OUT-001, SPO-Pfiles-INV-002
func TestSourceFiles(t *testing.T) {
	// `w`, `w.addr` and `./w.addr` are the same artefact (IN-001); a wallet
	// made by 03a is `w.payment`.
	for _, name := range []string{"w", "w.addr", "./w.addr", "w.payment", "w.payment.addr"} {
		r := newRig(t)
		if _, err := r.uc.Run(context.Background(), SendRequest{Source: name, Destination: "d", Amount: "5000000"}); err != nil {
			t.Errorf("source %q: %v", name, err)
		}
	}
	// A directory part cannot name an artefact in the store.
	r := newRig(t)
	if _, err := r.uc.Run(context.Background(), SendRequest{Source: "dir/w", Destination: "d", Amount: "5"}); err == nil {
		t.Error("a directory part was accepted")
	}

	// No address file.
	r = newRig(t)
	delete(r.store.files, ports.Ref{Name: "w", Kind: ports.AddrFile})
	if _, err := r.run("5"); !errors.Is(err, ErrNoSourceAddress) {
		t.Errorf("no .addr: %v", err)
	}
	// Neither skey nor hwsfile: refused before the destination is looked at
	// (the destination here would fail too) and before any query.
	r = newRig(t)
	delete(r.store.files, ports.Ref{Name: "w", Kind: ports.AddrSKey})
	_, err := r.uc.Run(context.Background(), SendRequest{Source: "w", Destination: "unknown-destination", Amount: "5"})
	if !errors.Is(err, ErrNoSigningKey) || len(r.l.calls) != 0 {
		t.Errorf("no key: %v, calls %v", err, r.l.calls)
	}
	// The first line of the file is the address.
	r = newRig(t)
	r.store.files[ports.Ref{Name: "w", Kind: ports.AddrFile}] = []byte("addr_test_src\nignored second line\n")
	if _, err := r.run("5000000"); err != nil {
		t.Error(err)
	}
}

// A hardware file wins over a key file when both exist (SPO-Pfiles-INV-002),
// and a hardware-held key whose signer is not configured is refused by the
// plan, before any body is built or shown.
//
// spec: SPO-Pfiles-INV-002, SPO-Ptx-INV-008, SPO-Xidentity-INV-016
func TestHardwareFileWinsAndIsPlanned(t *testing.T) {
	r := newRig(t)
	r.store.files[ports.Ref{Name: "w", Kind: ports.AddrHwsFile}] = []byte("{}")
	_, err := r.run("5000000")
	var unsupported *custody.UnsupportedError
	if !errors.As(err, &unsupported) || !strings.Contains(err.Error(), "no hardware signer") {
		t.Fatalf("%v", err)
	}
	if r.l.count("build") != 0 || r.l.count("confirm") != 0 {
		t.Errorf("a body was built or shown before the plan: %v", r.l.calls)
	}
}

// The plan is made from the draft's features: a signer that cannot witness
// a multi-asset output is refused before the body is built.
//
// spec: SPO-Ptx-INV-004
func TestPlanUsesTheDraftFeatures(t *testing.T) {
	r := newRig(t)
	r.signer.profile = custody.NewProfile("limited").AllowTx(custody.RolePayment) // no features
	_, err := r.run("5000000")
	if err == nil || !strings.Contains(err.Error(), "multi-asset-output") {
		t.Fatalf("%v", err)
	}
	if r.l.count("build") != 0 {
		t.Error("a body was built for a signer that cannot sign it")
	}
	// Without assets the same signer is accepted... but it is not a TxWitnesser
	// for the plan's sake only: its profile claims AllowTx, and the fake
	// implements Witness, so the run proceeds.
	r.chain.utxos = r.chain.utxos[:1]
	if _, err := r.run("5000000"); err != nil {
		t.Errorf("a plain payment for the limited signer: %v", err)
	}
	// A signer that does not implement TxWitnesser is refused.
	r2 := newRig(t)
	r2.uc.Signers = fakeDir(r2.store, bareSigner{r2.signer.profile})
	if _, err := r2.run("5000000"); !errors.Is(err, ErrNoSigner) {
		t.Errorf("%v", err)
	}
}

type bareSigner struct{ p custody.Profile }

func (b bareSigner) Profile() custody.Profile { return b.p }

// Destination forms: the first match wins.
//
// spec: SPO-01sendLovelaces-IF-004, SPO-01sendLovelaces-IF-005, SPO-01sendLovelaces-IF-006, SPO-01sendLovelaces-IF-007,
// spec: SPO-01sendLovelaces-IF-008, SPO-01sendLovelaces-MODE-001, SPO-01sendLovelaces-SEC-001, SPO-Pfiles-IN-002,
// spec: SPO-Caddr-OUT-002, SPO-Caddr-OUT-004, SPO-Caddr-OUT-005, SPO-Caddr-OUT-006, SPO-Caddr-PRE-001
func TestDestinationForms(t *testing.T) {
	ok := func(t *testing.T, dest, wantName, wantAddr string) {
		t.Helper()
		r := newRig(t)
		r.store.files[ports.Ref{Name: "addr_test_shadow", Kind: ports.AddrFile}] = []byte("addr_test_other\n")
		res, err := r.uc.Run(context.Background(), SendRequest{Source: "w", Destination: dest, Amount: "5000000"})
		if err != nil {
			t.Fatalf("%q: %v", dest, err)
		}
		if res.Destination != wantName || string(r.queue.got[0].ToAddr) != wantAddr {
			t.Errorf("%q: sent to %q (%s), want %q (%s)", dest, res.Destination, r.queue.got[0].ToAddr, wantName, wantAddr)
		}
	}
	t.Run("a stored name, with or without the extension", func(t *testing.T) {
		ok(t, "d", "d", "addr_test_dst")
		ok(t, "d.addr", "d", "addr_test_dst")
		ok(t, "./d.addr", "d", "addr_test_dst")
	})
	t.Run("a literal address, trimmed, kept in memory", func(t *testing.T) {
		ok(t, "  addr_test_lit  ", "addr_test_lit", "addr_test_lit")
	})
	t.Run("a stored name shadows a literal that is also a file name (IF-004)", func(t *testing.T) {
		ok(t, "addr_test_shadow", "addr_test_shadow", "addr_test_other")
	})
	refuse := func(t *testing.T, dest string, want error) {
		t.Helper()
		r := newRig(t)
		_, err := r.uc.Run(context.Background(), SendRequest{Source: "w", Destination: dest, Amount: "5000000"})
		if !errors.Is(err, want) {
			t.Errorf("%q: %v, want %v", dest, err, want)
		}
		if r.l.count("utxos") != 0 || r.l.count("tip") != 0 {
			t.Errorf("%q: the chain was queried before the destination was refused", dest)
		}
	}
	t.Run("a stake address (IF-005)", func(t *testing.T) { refuse(t, "stake_test_abc", ErrBadDestination) })
	t.Run("garbage (IF-005)", func(t *testing.T) { refuse(t, "nonsense!", ErrBadDestination) })
	t.Run("an ADA Handle is not supported yet, in both forms and any case", func(t *testing.T) {
		refuse(t, "$alice", ErrAdaHandleUnsupported)
		refuse(t, "$Alice@Bob", ErrAdaHandleUnsupported)
		refuse(t, "$a-b_c.d", ErrAdaHandleUnsupported)
		refuse(t, "$"+strings.Repeat("a", 16), ErrBadDestination) // 16 characters is not a handle
	})
	// Decision (IF-008 quirk): upstream accepts any address in a destination
	// file. The port requires a payment address there too.
	t.Run("a destination file holding a stake address is refused", func(t *testing.T) {
		r := newRig(t)
		r.store.files[ports.Ref{Name: "d", Kind: ports.AddrFile}] = []byte("stake_test_abc\n")
		if _, err := r.run("5000000"); !errors.Is(err, ErrBadDestination) {
			t.Errorf("%v", err)
		}
	})
}

// A destination or a source of another network is refused up front.
//
// spec: SPO-01sendLovelaces-IF-008, SPO-Caddr-PRE-001
func TestNetworkMismatch(t *testing.T) {
	r := newRig(t)
	r.store.files[ports.Ref{Name: "d", Kind: ports.AddrFile}] = []byte("addr_main_dst\n")
	if _, err := r.run("5000000"); !errors.Is(err, ErrNetworkMismatch) || r.l.count("utxos") != 0 {
		t.Errorf("destination: %v", err)
	}
	r = newRig(t)
	r.uc.NetworkID = ports.NetworkMainnet
	if _, err := r.run("5000000"); !errors.Is(err, ErrNetworkMismatch) {
		t.Errorf("source: %v", err)
	}
	// A source that is not spent with a key.
	r = newRig(t)
	r.store.files[ports.Ref{Name: "w", Kind: ports.AddrFile}] = []byte("addr_script_x\n")
	if _, err := r.run("5000000"); !errors.Is(err, ErrSourceNotKey) {
		t.Errorf("script source: %v", err)
	}
}

// Every failure of a query is a returned error. Upstream exits 0 after a
// failed UTxO query in online and light mode (decision for H3).
//
// spec: SPO-01sendLovelaces-PRE-001, SPO-Ptx-MODE-001, SPO-Ptx-MODE-002, SPO-Ptx-MODE-003, SPO-Ptx-MODE-004, SPO-Ptx-MODE-006, SPO-Ptx-IN-004
func TestFailedQueriesAreErrors(t *testing.T) {
	r := newRig(t)
	r.chain.utxoErr = errors.New("koios: HTTP 500")
	if _, err := r.run("5000000"); err == nil || !strings.Contains(err.Error(), "HTTP 500") || r.l.count("enqueue") != 0 {
		t.Errorf("utxo query: %v", err)
	}
	r = newRig(t)
	r.chain.parErr = errors.New("no parameters")
	if _, err := r.run("5000000"); err == nil || !strings.Contains(err.Error(), "no parameters") {
		t.Errorf("parameters: %v", err)
	}
	r = newRig(t)
	r.chain.tipErr = errors.New("clock")
	if _, err := r.run("5000000"); err == nil || !strings.Contains(err.Error(), "clock") {
		t.Errorf("tip: %v", err)
	}
	r = newRig(t)
	r.chain.params.ProtocolMajor = 6
	if _, err := r.run("5000000"); !errors.Is(err, ErrProtocolTooOld) {
		t.Errorf("old protocol: %v", err)
	}
}

// No UTxOs: refused with nothing built.
//
// spec: SPO-Ptx-PRE-001
func TestNoFunds(t *testing.T) {
	r := newRig(t)
	r.chain.utxos = nil
	if _, err := r.run("5000000"); !errors.Is(err, txbuild.ErrNoFunds) || r.l.count("build") != 0 {
		t.Errorf("%v", err)
	}
}

// Minimum-value refusals are errors for the caller. Upstream exits 1 here
// in 01_sendLovelaces and 0 in the other pipeline scripts.
//
// spec: SPO-Ptx-PRE-002, SPO-Ptx-PRE-003, SPO-01sendLovelaces-PRE-004
func TestBelowMinimumIsAnErrorAndNothingIsSent(t *testing.T) {
	r := newRig(t)
	_, err := r.run("500000")
	var below *txbuild.BelowMinimumError
	if !errors.As(err, &below) {
		t.Fatalf("%v", err)
	}
	if r.l.count("confirm") != 0 || r.l.count("witness") != 0 || r.l.count("enqueue") != 0 {
		t.Errorf("went on after a refusal: %v", r.l.calls)
	}
}

// An oversize transaction is refused before the operator is asked.
//
// spec: SPO-Ptx-PRE-007, SPO-01sendLovelaces-INV-011, SPO-Ptx-IN-004
func TestOversizeRefusedBeforeConfirmation(t *testing.T) {
	r := newRig(t)
	r.chain.params.MaxTxSize = 50
	if _, err := r.run("5000000"); err == nil || !strings.Contains(err.Error(), "above the maximum") {
		t.Fatalf("%v", err)
	}
	if r.l.count("confirm") != 0 {
		t.Error("the operator was asked about a transaction that cannot be sent")
	}
}

// A signer that returns a witness for another key, or a corrupt one, or an
// error, stops the run before anything is assembled or sent.
//
// spec: SPO-Ptx-EXT-006, SPO-Ptx-INV-010
func TestWitnessesAreVerified(t *testing.T) {
	for mode, want := range map[string]error{"wrong-key": txbuild.ErrWitnessKey, "bad-signature": txbuild.ErrWitnessSignature} {
		r := newRig(t)
		r.signer.mode = mode
		if _, err := r.run("5000000"); !errors.Is(err, want) {
			t.Errorf("%s: %v", mode, err)
		}
		if r.l.count("assemble") != 0 || r.l.count("enqueue") != 0 {
			t.Errorf("%s: went on: %v", mode, r.l.calls)
		}
	}
	r := newRig(t)
	r.signer.mode = "error"
	if _, err := r.run("5000000"); err == nil || !strings.Contains(err.Error(), "the device refused") || r.l.count("enqueue") != 0 {
		t.Errorf("signer error: %v", err)
	}
}

// A queue that fails to write or read back is an error.
//
// spec: SPO-Ptransfer-OUT-012, SPO-Ptx-MODE-010
func TestQueueFailureIsAnError(t *testing.T) {
	r := newRig(t)
	r.queue.err = errors.New("read back differs")
	res, err := r.run("5000000")
	if err == nil || res.Queued {
		t.Errorf("%+v %v", res, err)
	}
}

// Nothing secret reaches a result or an error: the vault is never asked for
// a key by the use case, only the signer.
//
// spec: SPO-Ptx-SEC-001, SPO-Ptx-SEC-002
func TestNoSecretInResultOrError(t *testing.T) {
	r := newRig(t)
	res, err := r.run("5000000")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(res)
	for _, forbidden := range [][]byte{[]byte(r.signer.priv), r.signer.priv.Seed()} {
		if strings.Contains(string(b), string(forbidden)) {
			t.Error("the signing key is in the result")
		}
	}
}

// The witness count the fee is estimated for equals the planned signatures.
//
// spec: SPO-Ptx-INV-006
func TestWitnessCountIsTheConstant(t *testing.T) {
	if txbuild.SendWitnesses != 1 {
		t.Fatal("upstream's constant for 01_sendLovelaces is 1")
	}
}

// A UTxO that carries a datum hash is spent like any other input: no script
// input is ever added, so a script address as the source is refused.
//
// spec: SPO-Ptx-OUT-001
func TestDatumHashUtxosAreSpentAsPlainInputs(t *testing.T) {
	r := newRig(t)
	r.chain.utxos[0].HasDatumHash = true
	res, err := r.run("5000000")
	if err != nil || res.Inputs != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	if strings.Contains(string(res.SignedTx), "Redeemer") {
		t.Error("a script input was added")
	}
}

// A co-signer key that is the payer's own key needs one witness: the plan has
// two slots, one witness is made and assembled, and no required slot is dropped
// (the body lists the key as a required signer and the key has signed).
//
// spec: SPO-13b-INV-001
func TestACoSignerKeyEqualToThePayerKeyIsWitnessedOnce(t *testing.T) {
	r := newRig(t)
	payKey := porttest.Key(t, r.store, custody.RolePayment, "w")
	pub := r.signer.priv.Public().(ed25519.PublicKey)
	_, err := r.uc.Run(context.Background(), SendRequest{Source: "w", Destination: "d", Amount: "5000000",
		CoSign: &CoSigner{Label: "co", Key: payKey, Hash: txbuild.HashKey(pub), RequiredSigner: true}})
	if err != nil {
		t.Fatal(err)
	}
	if n := r.l.count("witness"); n != 1 {
		t.Errorf("%d witnesses were made, want 1: %v", n, r.l.calls)
	}
	if r.l.count("assemble") != 1 || r.l.count("enqueue") != 1 {
		t.Errorf("the transaction was not assembled and queued: %v", r.l.calls)
	}
}
