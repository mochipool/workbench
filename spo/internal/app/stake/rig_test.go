package stake

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	stk "github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ---- fakes -----------------------------------------------------------------

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

// memStore is a store with transactional Update; writes counts the artefacts
// written, so a refusal can be shown to write nothing.
type memStore struct {
	l      *log
	files  map[ports.Ref][]byte
	writes int
}

type memView struct{ m map[ports.Ref][]byte }

func (v memView) Get(r ports.Ref) ([]byte, error) {
	if b, ok := v.m[r]; ok {
		return b, nil
	}
	return nil, ports.ErrNotFound
}
func (v memView) Exists(r ports.Ref) (bool, error) { _, ok := v.m[r]; return ok, nil }

type memWriter struct {
	memView
	s *memStore
}

func (w memWriter) Put(r ports.Ref, b []byte) error {
	w.s.writes++
	w.s.l.add("put " + r.String())
	w.s.files[r] = append([]byte(nil), b...)
	return nil
}
func (w memWriter) PutSecret(ports.Ref, *secret.Buffer) error { panic("no secrets here") }
func (w memWriter) Delete(r ports.Ref) error                  { delete(w.s.files, r); return nil }

func (s *memStore) View(_ context.Context, fn func(ports.Reader) error) error {
	return fn(memView{s.files})
}
func (s *memStore) Update(_ context.Context, fn func(ports.Writer) error) error {
	return fn(memWriter{memView{s.files}, s})
}

// fakeInspector: "addr_test_<n>" is a payment address, "stake_test_<n>" a
// reward address; "stake_main_<n>" is on the mainnet, "addr_script" a script.
type fakeInspector struct{ payHash, stakeHash txbuild.KeyHash }

func (f fakeInspector) InspectAddress(a chain.Address) (ports.AddressInfo, error) {
	s := string(a)
	switch {
	case strings.HasPrefix(s, "addr_test_"):
		h := f.payHash
		if s != "addr_test_pay" {
			h = txbuild.HashKey([]byte(s))
		}
		return ports.AddressInfo{Kind: ports.AddrEnterprise, NetworkID: ports.NetworkTestnet, PaymentKeyHash: &h}, nil
	case strings.HasPrefix(s, "stake_test_"):
		h := f.stakeHash
		return ports.AddressInfo{Kind: ports.AddrReward, NetworkID: ports.NetworkTestnet, StakeKeyHash: &h}, nil
	case strings.HasPrefix(s, "stake_main_"):
		h := f.stakeHash
		return ports.AddressInfo{Kind: ports.AddrReward, NetworkID: ports.NetworkMainnet, StakeKeyHash: &h}, nil
	case s == "stake_script":
		return ports.AddressInfo{Kind: ports.AddrReward, NetworkID: ports.NetworkTestnet}, nil
	case s == "addr_script":
		return ports.AddressInfo{Kind: ports.AddrEnterprise, NetworkID: ports.NetworkTestnet, PaymentIsScript: true}, nil
	}
	return ports.AddressInfo{}, errors.New("not an address")
}

// fakeLedger builds JSON bodies; the fee depends on the size and on the
// witness count it is asked for.
type fakeLedger struct{ l *log }

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
	f.l.add(fmt.Sprintf("assemble witnesses=%d", len(ws)))
	out := append([]byte(nil), b.CBOR...)
	for _, w := range ws {
		out = append(out, w.Signature[:4]...)
	}
	return txbuild.SignedTx{CBOR: out, ID: b.ID}, nil
}

// fakeCerts stands for the ledger's certificate encoding: the CBOR is the
// JSON of the spec and the envelope says so.
type fakeCerts struct{ l *log }

func (f fakeCerts) BuildCertificate(s stk.Spec) (stk.Certificate, error) {
	f.l.add("make-cert " + string(s.Kind))
	if err := s.Validate(); err != nil {
		return stk.Certificate{}, err
	}
	b, _ := json.Marshal(s)
	return stk.Certificate{Spec: s, CBOR: b, Envelope: append([]byte("envelope:"), b...)}, nil
}

func (f fakeCerts) DecodeCertificate(env []byte) (stk.Certificate, error) {
	f.l.add("decode-cert")
	b, ok := strings.CutPrefix(string(env), "envelope:")
	if !ok {
		return stk.Certificate{}, errors.New("not a certificate envelope")
	}
	var s stk.Spec
	if err := json.Unmarshal([]byte(b), &s); err != nil {
		return stk.Certificate{}, err
	}
	return stk.Certificate{Spec: s, CBOR: []byte(b), Envelope: env}, nil
}

type fakeBuilder struct{}

func (fakeBuilder) BuildAddress(uint8, txbuild.KeyHash, *txbuild.KeyHash) (chain.Address, error) {
	return "", errors.New("unused")
}
func (fakeBuilder) BuildStakeAddress(uint8, txbuild.KeyHash) (chain.StakeAddress, error) {
	return "stake_test_w", nil
}

// fakeSigner holds a payment key and a stake key. mode corrupts the answer.
type fakeSigner struct {
	l          *log
	profile    custody.Profile
	pay, stake ed25519.PrivateKey
	mode       string // "", "stake-with-payment-key"
}

func (s *fakeSigner) Profile() custody.Profile { return s.profile }
func (s *fakeSigner) Witness(_ context.Context, key custody.KeyRef, body txbuild.TxBody) (txbuild.Witness, error) {
	s.l.add("witness " + string(key.Role) + " " + key.Owner)
	k := s.pay
	if key.Role == custody.RoleStake && s.mode != "stake-with-payment-key" {
		k = s.stake
	}
	var w txbuild.Witness
	copy(w.VKey[:], k.Public().(ed25519.PublicKey))
	copy(w.Signature[:], ed25519.Sign(k, body.ID[:]))
	return w, nil
}

type fakeDir struct{ signer ports.Signer }

func (d fakeDir) SignerFor(k custody.KeyRef) (ports.Signer, error) {
	if k.Holder == custody.HolderHardware {
		return nil, errors.New("no hardware signer is configured")
	}
	return d.signer, nil
}

type fakeChain struct {
	l      *log
	utxos  []chain.Utxo
	params chain.ProtocolParameters
	slot   uint64
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

// fakeRewards answers for any address with one reading.
type fakeRewards struct {
	l   *log
	src chain.Source
	r   chain.Reading[chain.RewardAccount]
	err error
}

func (f *fakeRewards) Source() chain.Source { return f.src }
func (f *fakeRewards) RewardAccount(_ context.Context, a chain.StakeAddress) (chain.Reading[chain.RewardAccount], error) {
	f.l.add("reward-account " + string(a) + " " + string(f.src))
	return f.r, f.err
}

type fakePools struct {
	r   chain.Reading[chain.PoolState]
	err error
}

func (f *fakePools) Source() chain.Source { return "pools" }
func (f *fakePools) PoolState(context.Context, chain.PoolID) (chain.Reading[chain.PoolState], error) {
	return f.r, f.err
}

type fakeDReps struct {
	r   chain.Reading[chain.DRepState]
	got *chain.DRepID
}

func (f *fakeDReps) Source() chain.Source { return "dreps" }
func (f *fakeDReps) DRepState(_ context.Context, id chain.DRepID) (chain.Reading[chain.DRepState], error) {
	f.got = &id
	return f.r, nil
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
	err error
	got []ports.QueuedTx
}

func (q *fakeQueue) Enqueue(_ context.Context, tx ports.QueuedTx) error {
	q.l.add("enqueue")
	q.got = append(q.got, tx)
	return q.err
}

type fakeSubmitter struct {
	l   *log
	id  *chain.TxID
	err error
}

func (s *fakeSubmitter) Source() chain.Source { return "fake" }
func (s *fakeSubmitter) Submit(context.Context, []byte) (chain.TxID, error) {
	s.l.add("submit")
	if s.err != nil {
		return chain.TxID{}, s.err
	}
	return *s.id, nil
}

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
	rewards *fakeRewards
	insp    fakeInspector
	base    Base
	stakeID stk.KeyHash
}

func registered(m func(*chain.RewardAccount)) chain.Reading[chain.RewardAccount] {
	a := chain.RewardAccount{Address: "stake_test_w", DelegatedPool: chain.None[chain.PoolID](), VoteDelegation: chain.None[string](),
		Deposit: chain.Value(chain.Lovelace(2_000_000)), GovActionDeposits: chain.Value([]chain.GovActionDeposit(nil))}
	if m != nil {
		m(&a)
	}
	return chain.Value(a)
}

func newRig(t *testing.T) *rig {
	t.Helper()
	l := &log{}
	payPub, payPriv, _ := ed25519.GenerateKey(nil)
	stkPub, stkPriv, _ := ed25519.GenerateKey(nil)
	r := &rig{l: l, certs: fakeCerts{l}}
	r.insp = fakeInspector{payHash: txbuild.HashKey(payPub), stakeHash: txbuild.HashKey(stkPub)}
	r.stakeID = stk.KeyHash(r.insp.stakeHash)
	r.store = &memStore{l: l, files: map[ports.Ref][]byte{
		{Name: "w.payment", Kind: ports.AddrFile}: []byte("addr_test_pay\n"),
		{Name: "w.payment", Kind: ports.AddrSKey}: nil,
		{Name: "w", Kind: ports.StakingAddr}:      []byte("stake_test_w\n"),
		{Name: "w", Kind: ports.StakingSKey}:      nil,
		{Name: "w", Kind: ports.StakingVKey}:      vkeyEnvelope(stkPub),
		{Name: "mypool", Kind: ports.NodeVKey}:    vkeyEnvelope(payPub),
		{Name: "d", Kind: ports.DRepVKey}:         vkeyEnvelope(payPub),
	}}
	var id chain.TxID
	id[0] = 1
	r.chain = &fakeChain{l: l, slot: 1000, utxos: []chain.Utxo{
		{TxID: id, Index: 0, Lovelace: 30_000_000},
		{TxID: chain.TxID{2}, Index: 1, Lovelace: 20_000_000, Assets: []chain.AssetAmount{{Asset: chain.AssetID{Policy: [28]byte{9}, Name: []byte("t")}, Quantity: 4}}},
	}, params: chain.ProtocolParameters{ProtocolMajor: 11, MaxTxSize: 16384, CoinsPerUTxOByte: 4310, StakeAddressDeposit: 2_000_000}}
	r.ledger = &fakeLedger{l}
	r.signer = &fakeSigner{l: l, profile: custody.NewProfile("fake").
		AllowTx(custody.RolePayment, custody.FeatMultiAssetOutput, custody.FeatMetadata, custody.FeatStakeRegistration, custody.FeatStakeDeregistration,
			custody.FeatStakeDelegation, custody.FeatVoteDelegation, custody.FeatWithdrawal).
		AllowTx(custody.RoleStake, custody.FeatMultiAssetOutput, custody.FeatMetadata, custody.FeatStakeRegistration, custody.FeatStakeDeregistration,
			custody.FeatStakeDelegation, custody.FeatVoteDelegation, custody.FeatWithdrawal),
		pay: payPriv, stake: stkPriv}
	r.conf = &fakeConfirmer{l: l, yes: true}
	r.queue = &fakeQueue{l: l}
	r.rewards = &fakeRewards{l: l, src: "koios", r: chain.None[chain.RewardAccount]()}
	r.base = Base{Store: r.store, Addresses: r.insp, Params: r.chain, Tip: r.chain, Utxos: r.chain, NetworkID: ports.NetworkTestnet,
		Pipeline: txflow.Pipeline{Signers: fakeDir{r.signer}, Min: r.ledger, Fees: r.ledger, Bodies: r.ledger, Assembler: r.ledger,
			Confirmer: r.conf, Queue: r.queue}}
	return r
}

func vkeyEnvelope(pub ed25519.PublicKey) []byte {
	return pool.MarshalEnvelope(pool.Envelope{Type: "StakeVerificationKeyShelley_ed25519", Description: "Stake Verification Key", CborHex: "5820" + fmt.Sprintf("%x", []byte(pub))})
}

// nothingWritten asserts that a refusal wrote no artefact and queued and
// signed nothing.
func (r *rig) nothingWritten(t *testing.T) {
	t.Helper()
	if r.store.writes != 0 || len(r.queue.got) != 0 || r.l.count("witness") != 0 || r.l.count("enqueue") != 0 || r.l.count("submit") != 0 {
		t.Errorf("a refusal had effects: writes=%d calls=%v", r.store.writes, r.l.calls)
	}
}

func (r *rig) holder(t *testing.T, ref ports.Ref, h custody.Holder) {
	t.Helper()
	delete(r.store.files, ref)
	if h == custody.HolderHardware {
		hws := ref
		switch ref.Kind {
		case ports.AddrSKey:
			hws.Kind = ports.AddrHwsFile
		case ports.StakingSKey:
			hws.Kind = ports.StakingHwsFile
		}
		r.store.files[hws] = []byte("hw")
	} else {
		r.store.files[ref] = nil
	}
}

// signerPub is the public key the pool "mypool" is stored with.
func (r *rig) signerPub() []byte {
	e, _ := pool.ParseEnvelope(r.store.files[ports.Ref{Name: "mypool", Kind: ports.NodeVKey}])
	raw, _ := e.Key32()
	return raw
}
