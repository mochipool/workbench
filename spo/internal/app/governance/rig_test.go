package governance

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/porttest"
)

// ---- fakes -----------------------------------------------------------------

type log struct{ calls []string }

func (l *log) add(s string) { l.calls = append(l.calls, s) }
func (l *log) count(prefix string) (n int) {
	for _, c := range l.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return
}

type memStore struct {
	l       *log
	files   map[ports.Ref][]byte
	secrets map[ports.Ref][]byte
	writes  int
}

// List implements ports.SourceLister: every stored file.
func (s *memStore) List(context.Context) (ports.SourceListing, error) {
	var l ports.SourceListing
	for r := range s.files {
		l.Entries = append(l.Entries, ports.SourceEntry{Ref: r})
	}
	return l, nil
}

type memView struct{ s *memStore }

func (v memView) Get(r ports.Ref) ([]byte, error) {
	if b, ok := v.s.files[r]; ok {
		return b, nil
	}
	if _, ok := v.s.secrets[r]; ok {
		return nil, ports.ErrSecretKind
	}
	return nil, ports.ErrNotFound
}
func (v memView) Exists(r ports.Ref) (bool, error) {
	_, a := v.s.files[r]
	_, b := v.s.secrets[r]
	return a || b, nil
}

type memWriter struct{ memView }

func (w memWriter) Put(r ports.Ref, b []byte) error {
	w.s.writes++
	w.s.l.add("put " + r.String())
	w.s.files[r] = append([]byte(nil), b...)
	return nil
}
func (w memWriter) PutSecret(r ports.Ref, s *secret.Buffer) error {
	w.s.writes++
	w.s.l.add("put-secret " + r.String())
	return s.Use(func(b []byte) error { w.s.secrets[r] = append([]byte(nil), b...); return nil })
}
func (w memWriter) Delete(r ports.Ref) error {
	w.s.l.add("delete " + r.String())
	delete(w.s.files, r)
	delete(w.s.secrets, r)
	return nil
}

func (s *memStore) View(_ context.Context, fn func(ports.Reader) error) error {
	return fn(memView{s})
}
func (s *memStore) Update(_ context.Context, fn func(ports.Writer) error) error {
	return fn(memWriter{memView{s}})
}

// fakeInspector: "addr_test_pay" is a payment address.
type fakeInspector struct{ payHash txbuild.KeyHash }

func (f fakeInspector) InspectAddress(a chain.Address) (ports.AddressInfo, error) {
	if strings.HasPrefix(string(a), "addr_test_") {
		h := f.payHash
		return ports.AddressInfo{Kind: ports.AddrEnterprise, NetworkID: ports.NetworkTestnet, PaymentKeyHash: &h}, nil
	}
	return ports.AddressInfo{}, errors.New("not an address")
}

type fakeLedger struct {
	l    *log
	last chain.TxID
	// specs are the body specs built, in order.
	specs []txbuild.BodySpec
}

func (f *fakeLedger) MinOutput(chain.ProtocolParameters, txbuild.Output) (chain.Lovelace, error) {
	return 1_000_000, nil
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
	f.specs = append(f.specs, s)
	f.l.add(fmt.Sprintf("body certs=%d votes=%d proposals=%d ttl=%d", len(s.Certificates), len(s.Votes), len(s.Proposals), s.TTL))
	b, _ := json.Marshal(s)
	f.last = sha256.Sum256(b)
	body := txbuild.TxBody{CBOR: b, ID: f.last}
	if s.Plutus != nil && s.Plutus.TotalCollateral != 0 {
		// What the native builder reads back from the encoded body.
		risk := s.Plutus.TotalCollateral
		body.CollateralAtRisk = &risk
	}
	return body, nil
}
func (f *fakeLedger) Assemble(b txbuild.TxBody, ws []txbuild.Witness) (txbuild.SignedTx, error) {
	f.l.add(fmt.Sprintf("assemble witnesses=%d", len(ws)))
	out := append([]byte(nil), b.CBOR...)
	for _, w := range ws {
		out = append(out, w.Signature[:4]...)
	}
	return txbuild.SignedTx{CBOR: out, ID: b.ID}, nil
}

// fakeCerts: the CBOR is the JSON of the spec, the envelope says so.
type fakeCerts struct{ l *log }

func (f fakeCerts) BuildCertificate(s stake.Spec) (stake.Certificate, error) {
	f.l.add("make-cert " + string(s.Kind))
	if err := s.Validate(); err != nil {
		return stake.Certificate{}, err
	}
	b, _ := json.Marshal(s)
	return stake.Certificate{Spec: s, CBOR: b, Envelope: append([]byte("envelope:"), b...)}, nil
}

// fakeSigner holds one key per role.
type fakeSigner struct {
	l    *log
	keys map[custody.Role]ed25519.PrivateKey
}

func (s *fakeSigner) Profile() custody.Profile { return custody.NewProfile("fake") }
func (s *fakeSigner) Witness(_ context.Context, key custody.KeyRef, body txbuild.TxBody) (txbuild.Witness, error) {
	s.l.add("witness " + string(key.Role) + " " + map[custody.Role]string{custody.RolePayment: "w.payment", custody.RoleDRep: "d",
		custody.RoleCommitteeCold: "m", custody.RoleCommitteeHot: "h", custody.RolePoolCold: "mypool"}[key.Role])
	k := s.keys[key.Role]
	var w txbuild.Witness
	copy(w.VKey[:], k.Public().(ed25519.PublicKey))
	copy(w.Signature[:], ed25519.Sign(k, body.ID[:]))
	return w, nil
}

// fakeDir serves the fake signer for the keys whose signing key the store
// holds. Profile of the fake: everything is witnessed.
func fakeDir(st ports.Store, s *fakeSigner) ports.SignerDirectory {
	return porttest.VaultOnly(st, fullSigner{s})
}

// fullSigner claims every operation on every role.
type fullSigner struct{ *fakeSigner }

func (fullSigner) Profile() custody.Profile {
	p := custody.NewProfile("fake")
	for _, r := range custody.Roles() {
		p = p.Allow(r, custody.OpWitnessTx)
	}
	return p
}

type fakeChain struct {
	l      *log
	utxos  []chain.Utxo
	params chain.ProtocolParameters
	slot   uint64
	epoch  uint64
}

func (f *fakeChain) Source() chain.Source { return "fake" }
func (f *fakeChain) Tip(context.Context) (chain.Tip, error) {
	f.l.add("tip")
	return chain.Tip{Slot: f.slot}, nil
}
func (f *fakeChain) Utxos(_ context.Context, a chain.Address) ([]chain.Utxo, error) {
	f.l.add("utxos " + string(a))
	return f.utxos, nil
}
func (f *fakeChain) ProtocolParameters(context.Context) (chain.ProtocolParameters, error) {
	f.l.add("params")
	return f.params, nil
}
func (f *fakeChain) Epoch(context.Context) (uint64, error) { return f.epoch, nil }

type fakeDReps struct {
	src chain.Source
	l   *log
	r   chain.Reading[chain.DRepState]
	err error
}

func (f *fakeDReps) Source() chain.Source { return f.src }
func (f *fakeDReps) DRepState(context.Context, chain.DRepID) (chain.Reading[chain.DRepState], error) {
	f.l.add("drep-state " + string(f.src))
	return f.r, f.err
}

type fakeCommittee struct {
	l     *log
	cold  chain.Reading[governance.CommitteeMember]
	byHot chain.Reading[governance.CommitteeMember]
	err   error
}

func (f *fakeCommittee) Source() chain.Source { return "committee" }
func (f *fakeCommittee) CommitteeMember(context.Context, governance.Credential) (chain.Reading[governance.CommitteeMember], error) {
	f.l.add("committee-state")
	return f.cold, f.err
}
func (f *fakeCommittee) CommitteeMemberByHot(context.Context, governance.Credential) (chain.Reading[governance.CommitteeMember], error) {
	f.l.add("committee-state-by-hot")
	return f.byHot, f.err
}

type fakeConfirmer struct {
	l   *log
	yes bool
	got ports.TxSummary
}

func (c *fakeConfirmer) Confirm(_ context.Context, s ports.TxSummary) (bool, error) {
	c.l.add("confirm")
	c.got = s
	return c.yes, nil
}

type fakeQueue struct {
	l   *log
	got []ports.QueuedTx
}

func (q *fakeQueue) Enqueue(_ context.Context, tx ports.QueuedTx) error {
	q.l.add("enqueue")
	q.got = append(q.got, tx)
	return nil
}

type fakeSubmitter struct {
	l      *log
	ledger *fakeLedger
}

func (s *fakeSubmitter) Source() chain.Source { return "fake" }
func (s *fakeSubmitter) Submit(context.Context, []byte) (chain.TxID, error) {
	s.l.add("submit")
	return s.ledger.last, nil
}

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

// ---- rig -------------------------------------------------------------------

type rig struct {
	l       *log
	store   *memStore
	chain   *fakeChain
	ledger  *fakeLedger
	certs   fakeCerts
	signer  *fakeSigner
	conf    *fakeConfirmer
	queue   *fakeQueue
	insp    fakeInspector
	base    Base
	drep    stake.KeyHash
	cold    stake.KeyHash
	hot     stake.KeyHash
	poolKey stake.KeyHash
}

func vkeyEnvelope(pub ed25519.PublicKey) []byte {
	return pool.MarshalEnvelope(pool.Envelope{Type: "DRepVerificationKey_ed25519", Description: "k", CborHex: "5820" + fmt.Sprintf("%x", []byte(pub))})
}

func newRig(t *testing.T) *rig {
	t.Helper()
	l := &log{}
	keys := map[custody.Role]ed25519.PrivateKey{}
	pubs := map[custody.Role]ed25519.PublicKey{}
	for _, r := range []custody.Role{custody.RolePayment, custody.RoleDRep, custody.RoleCommitteeCold, custody.RoleCommitteeHot, custody.RolePoolCold} {
		pub, priv, _ := ed25519.GenerateKey(nil)
		keys[r], pubs[r] = priv, pub
	}
	r := &rig{l: l, certs: fakeCerts{l}}
	r.insp = fakeInspector{payHash: txbuild.HashKey(pubs[custody.RolePayment])}
	r.drep = stake.KeyHash(txbuild.HashKey(pubs[custody.RoleDRep]))
	r.cold = stake.KeyHash(txbuild.HashKey(pubs[custody.RoleCommitteeCold]))
	r.hot = stake.KeyHash(txbuild.HashKey(pubs[custody.RoleCommitteeHot]))
	r.poolKey = stake.KeyHash(txbuild.HashKey(pubs[custody.RolePoolCold]))
	hexh := func(h stake.KeyHash) []byte { return []byte(fmt.Sprintf("%x\n", h[:])) }
	r.store = &memStore{l: l, secrets: map[ports.Ref][]byte{}, files: map[ports.Ref][]byte{
		{Name: "w.payment", Kind: ports.AddrFile}: []byte("addr_test_pay\n"),
		{Name: "w.payment", Kind: ports.AddrSKey}: nil,
		{Name: "w.payment", Kind: ports.AddrVKey}: vkeyEnvelope(pubs[custody.RolePayment]),
		{Name: "d", Kind: ports.DRepVKey}:         vkeyEnvelope(pubs[custody.RoleDRep]),
		{Name: "d", Kind: ports.DRepSKey}:         nil,
		{Name: "m", Kind: ports.CCColdVKey}:       vkeyEnvelope(pubs[custody.RoleCommitteeCold]),
		{Name: "m", Kind: ports.CCColdHash}:       hexh(r.cold),
		{Name: "m", Kind: ports.CCColdSKey}:       nil,
		{Name: "h", Kind: ports.CCHotVKey}:        vkeyEnvelope(pubs[custody.RoleCommitteeHot]),
		{Name: "h", Kind: ports.CCHotHash}:        hexh(r.hot),
		{Name: "h", Kind: ports.CCHotSKey}:        nil,
		{Name: "mypool", Kind: ports.NodeVKey}:    vkeyEnvelope(pubs[custody.RolePoolCold]),
		{Name: "mypool", Kind: ports.NodeSKey}:    nil,
	}}
	var id chain.TxID
	id[0] = 1
	r.chain = &fakeChain{l: l, slot: 1000, epoch: 500, utxos: []chain.Utxo{{TxID: id, Index: 0, Lovelace: 900_000_000}},
		params: chain.ProtocolParameters{ProtocolMajor: 10, MaxTxSize: 16384, CoinsPerUTxOByte: 4310, DRepDeposit: 500_000_000, GovActionDeposit: 100_000_000_000}}
	r.ledger = &fakeLedger{l: l}
	r.signer = &fakeSigner{l: l, keys: keys}
	r.conf = &fakeConfirmer{l: l, yes: true}
	r.queue = &fakeQueue{l: l}
	r.base = Base{Store: r.store, Addresses: r.insp, Params: r.chain, Tip: r.chain, Utxos: r.chain, NetworkID: ports.NetworkTestnet,
		Pipeline: txflow.Pipeline{Signers: fakeDir(r.store, r.signer), Min: r.ledger, Fees: r.ledger, Bodies: r.ledger, Assembler: r.ledger,
			Confirmer: r.conf, Queue: r.queue}}
	return r
}

// online switches the pipeline to a submitter.
func (r *rig) online() *fakeSubmitter {
	s := &fakeSubmitter{l: r.l, ledger: r.ledger}
	r.base.Pipeline.Queue, r.base.Pipeline.Submitter = nil, s
	return s
}

func (r *rig) nothingWritten(t *testing.T) {
	t.Helper()
	if r.store.writes != 0 || len(r.queue.got) != 0 || r.l.count("witness") != 0 || r.l.count("enqueue") != 0 || r.l.count("submit") != 0 {
		t.Errorf("a refusal had effects: writes=%d calls=%v", r.store.writes, r.l.calls)
	}
}

func (r *rig) hardware(ref ports.Ref, hws ports.Kind) {
	delete(r.store.files, ref)
	r.store.files[ports.Ref{Name: ref.Name, Kind: hws}] = []byte("hw")
}

func registeredDRep(deposit chain.Lovelace, anchorURL string) chain.Reading[chain.DRepState] {
	return chain.Value(chain.DRepState{Deposit: deposit, AnchorURL: anchorURL, Expiry: chain.Value(uint64(520))})
}
