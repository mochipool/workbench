package poolops

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	appassets "github.com/mochipool/workbench/spo/internal/app/assets"
	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/domain/assets"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

// The pool rig runs the use cases over the real store (plainstore), the real
// ledger (native: certificates, bodies, fees, addresses, assembly) and the
// real vault signer. Only what is outside the process is faked: the chain
// readers, the confirmation, the queue and the submitter.

type pcalls struct{ l []string }

func (c *pcalls) add(s string) { c.l = append(c.l, s) }
func (c *pcalls) count(prefix string) (n int) {
	for _, x := range c.l {
		if strings.HasPrefix(x, prefix) {
			n++
		}
	}
	return
}

type pchain struct {
	c      *pcalls
	tip    chain.Tip
	utxos  []chain.Utxo
	params chain.ProtocolParameters
}

func (f *pchain) Source() chain.Source { return "fake chain" }
func (f *pchain) Tip(context.Context) (chain.Tip, error) {
	f.c.add("tip")
	return f.tip, nil
}
func (f *pchain) Utxos(_ context.Context, a chain.Address) ([]chain.Utxo, error) {
	f.c.add("utxos")
	return f.utxos, nil
}
func (f *pchain) ProtocolParameters(context.Context) (chain.ProtocolParameters, error) {
	f.c.add("params")
	return f.params, nil
}

type pconf struct {
	c      *pcalls
	answer []bool // per call; the last repeats
	got    []ports.TxSummary
}

func (f *pconf) Confirm(_ context.Context, s ports.TxSummary) (bool, error) {
	f.c.add("confirm " + s.Stage)
	f.got = append(f.got, s)
	i := len(f.got) - 1
	if i >= len(f.answer) {
		i = len(f.answer) - 1
	}
	return f.answer[i], nil
}

type pqueue struct {
	c   *pcalls
	got []ports.QueuedTx
}

func (q *pqueue) Enqueue(_ context.Context, tx ports.QueuedTx) error {
	q.c.add("enqueue")
	q.got = append(q.got, tx)
	return nil
}

type psub struct {
	c    *pcalls
	sent [][]byte
	err  error
	// wrongID makes the provider accept the transaction and answer another id.
	wrongID bool
}

func (s *psub) Source() chain.Source { return "fake chain" }
func (s *psub) Submit(_ context.Context, tx []byte) (chain.TxID, error) {
	s.c.add("submit")
	if s.err != nil {
		return chain.TxID{}, s.err
	}
	s.sent = append(s.sent, tx)
	if s.wrongID {
		return chain.TxID{0xee}, nil
	}
	return native.Ledger{}.TransactionID(tx)
}

type ppools struct {
	c   *pcalls
	src chain.Source
	r   chain.Reading[chain.PoolState]
	err error
}

func (f *ppools) Source() chain.Source { return f.src }
func (f *ppools) PoolState(context.Context, chain.PoolID) (chain.Reading[chain.PoolState], error) {
	f.c.add("pool-state " + string(f.src))
	return f.r, f.err
}

// recFees records the witness count the fee is asked for.
type recFees struct {
	native.Ledger
	c *pcalls
}

func (f recFees) EstimateFee(p chain.ProtocolParameters, b txbuild.TxBody, n uint) (chain.Lovelace, error) {
	f.c.add(fmt.Sprintf("fee witnesses=%d", n))
	return f.Ledger.EstimateFee(p, b, n)
}

// pdir serves the vault signer for vault keys only: a hardware or remote
// holder has no signer here.
type pdir struct{ s ports.Signer }

func (d pdir) SignerFor(k custody.KeyRef) (ports.Signer, error) {
	if k.Holder != custody.HolderVault {
		return nil, fmt.Errorf("no signer for %s", k.Holder)
	}
	return d.s, nil
}

type pfixedClock struct{ t time.Time }

func (c pfixedClock) Now() time.Time { return c.t }

type prig struct {
	t      *testing.T
	dir    string
	store  *plainstore.Store
	calls  *pcalls
	chain  *pchain
	conf   *pconf
	queue  *pqueue
	sub    *psub
	led    native.Ledger
	clock  pfixedClock
	keys   map[string]ed25519.PrivateKey
	poolID chain.PoolID
}

func (r *prig) path(n string) string { return filepath.Join(r.dir, n) }

func (r *prig) write(name string, b []byte) {
	r.t.Helper()
	os.Chmod(r.path(name), 0o600)
	if err := os.WriteFile(r.path(name), b, 0o600); err != nil {
		r.t.Fatal(err)
	}
}

func (r *prig) read(name string) string {
	r.t.Helper()
	b, err := os.ReadFile(r.path(name))
	if err != nil {
		r.t.Fatal(err)
	}
	return string(b)
}

func (r *prig) exists(name string) bool { _, err := os.Stat(r.path(name)); return err == nil }

func (r *prig) remove(name string) {
	r.t.Helper()
	os.Chmod(r.path(name), 0o600)
	if err := os.Remove(r.path(name)); err != nil {
		r.t.Fatal(err)
	}
}

// snapshot is every file with its content: a refusal leaves it unchanged.
func (r *prig) snapshot() string {
	r.t.Helper()
	ents, _ := os.ReadDir(r.dir)
	var out []string
	for _, e := range ents {
		b, _ := os.ReadFile(r.path(e.Name()))
		out = append(out, e.Name()+"="+string(b))
	}
	sort.Strings(out)
	return strings.Join(out, "\n--\n")
}

func (r *prig) key(name string) ed25519.PrivateKey {
	if k, ok := r.keys[name]; ok {
		return k
	}
	seed := sha256.Sum256([]byte("pool rig key " + name))
	k := ed25519.NewKeyFromSeed(seed[:])
	r.keys[name] = k
	return k
}

func env(typ, desc string, raw []byte) []byte {
	return pool.MarshalEnvelope(pool.Envelope{Type: typ, Description: desc, CborHex: "5820" + hex.EncodeToString(raw)})
}

func (r *prig) putKey(vk, sk, vkType, skType, vkDesc string) {
	k := r.key(strings.SplitN(vk, ".", 2)[0] + "|" + vkType)
	r.write(vk, env(vkType, vkDesc, k.Public().(ed25519.PublicKey)))
	if sk != "" {
		r.write(sk, env(skType, "", k.Seed()))
	}
}

func (r *prig) hashOf(vkFile string) txbuild.KeyHash {
	e, err := pool.ParseEnvelope([]byte(r.read(vkFile)))
	if err != nil {
		r.t.Fatal(err)
	}
	raw, _ := e.Key32()
	return txbuild.HashKey(raw)
}

const descriptorFmt = `{
  "poolName": "mypool",
  "poolOwner": [
    {"ownerName": "alice", "ownerWitness": "local"},
    {"ownerName": "bob", "ownerWitness": %q}
  ],
  "poolRewards": "alice",
  "poolPledge": "100000000000",
  "poolCost": "340000000",
  "poolMargin": "0.10",
  "poolRelays": [
    {"relayType": "dns", "relayEntry": "relay.example.org", "relayPort": "3001"}
  ],
  "poolMetaName": "My Pool",
  "poolMetaDescription": "A pool for tests",
  "poolMetaTicker": "MYPL",
  "poolMetaHomepage": "https://example.org",
  "poolMetaUrl": "https://example.org/mypool.metadata.json",
  "poolExtendedMetaUrl": "",
  "---": "--- DO NOT EDIT OR DELETE BELOW THIS LINE ---"
}
`

// newPoolRig builds a workspace with a pool, two owners (alice is the reward
// account) and a payer, and the descriptor of a pool ready for generation.
func newPoolRig(t *testing.T) *prig {
	t.Helper()
	dir := t.TempDir()
	st, err := plainstore.OpenTestnet(dir)
	if err != nil {
		t.Fatal(err)
	}
	c := &pcalls{}
	r := &prig{t: t, dir: dir, store: st, calls: c, keys: map[string]ed25519.PrivateKey{},
		clock: pfixedClock{time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)}}
	r.putKey("mypool.node.vkey", "mypool.node.skey", "StakePoolVerificationKey_ed25519", "StakePoolSigningKey_ed25519", "Stake Pool Operator Verification Key")
	r.putKey("mypool.vrf.vkey", "mypool.vrf.skey", "VrfVerificationKey_PraosVRF", "VrfSigningKey_PraosVRF", "VRF Verification Key")
	for _, o := range []string{"alice", "bob"} {
		r.putKey(o+".staking.vkey", o+".staking.skey", "StakeVerificationKeyShelley_ed25519", "StakeSigningKeyShelley_ed25519", "Stake Verification Key")
	}
	r.putKey("pay.vkey", "pay.skey", "PaymentVerificationKeyShelley_ed25519", "PaymentSigningKeyShelley_ed25519", "Payment Verification Key")
	var pk [32]byte
	copy(pk[:], r.key("mypool|StakePoolVerificationKey_ed25519").Public().(ed25519.PublicKey))
	r.poolID, _ = chain.PoolIDOf(pk[:])
	addr, err := native.Ledger{}.BuildAddress(0, r.hashOf("pay.vkey"), nil)
	if err != nil {
		t.Fatal(err)
	}
	r.write("pay.addr", []byte(addr+"\n"))
	for _, o := range []string{"alice", "bob"} {
		cert, err := native.Ledger{}.BuildCertificate(stake.Spec{Kind: stake.CertPoolDelegation, Stake: stake.KeyHash(r.hashOf(o + ".staking.vkey")), Pool: r.poolID})
		if err != nil {
			t.Fatal(err)
		}
		r.write(o+".deleg.cert", cert.Envelope)
	}
	r.write("mypool.pool.json", []byte(fmt.Sprintf(descriptorFmt, "local")))
	r.chain = &pchain{c: c, tip: chain.Tip{Slot: 1000, Epoch: 7},
		utxos: []chain.Utxo{{TxID: chain.TxID{1}, Index: 0, Lovelace: 800_000_000}, {TxID: chain.TxID{2}, Index: 1, Lovelace: 700_000_000}},
		params: chain.ProtocolParameters{TxFeePerByte: 44, TxFeeFixed: 155381, CoinsPerUTxOByte: 4310, StakeAddressDeposit: 2_000_000,
			StakePoolDeposit: 500_000_000, MaxTxSize: 16384, ProtocolMajor: 11, MinPoolCost: 170_000_000, PoolRetireMaxEpoch: 18}}
	r.conf = &pconf{c: c, answer: []bool{true}}
	r.queue = &pqueue{c: c}
	r.sub = &psub{c: c}
	return r
}

func (r *prig) generate(opts ...func(*GeneratePoolCertificate)) (GeneratedPool, error) {
	uc := GeneratePoolCertificate{Store: r.store, Params: r.chain, Certs: r.led, Hasher: r.led, Clock: r.clock, NetworkID: 0}
	for _, o := range opts {
		if o != nil {
			o(&uc)
		}
	}
	return uc.Run(context.Background(), GenerateRequest{Pool: "mypool"})
}

func (r *prig) mustGenerate() GeneratedPool {
	r.t.Helper()
	g, err := r.generate()
	if err != nil {
		r.t.Fatal(err)
	}
	return g
}

func (r *prig) pipeline(queue bool) txflow.Pipeline {
	signer := native.VaultSigner{Vault: r.store}
	p := txflow.Pipeline{Signers: pdir{signer}, Min: r.led, Fees: recFees{r.led, r.calls}, Bodies: r.led, Assembler: r.led, Confirmer: r.conf, Canonicalizer: idCanon{}}
	if queue {
		p.Queue = r.queue
	} else {
		p.Submitter = r.sub
	}
	return p
}

func (r *prig) register(queue bool, opts ...func(*RegisterPool)) RegisterPool {
	uc := RegisterPool{Store: r.store, Addresses: r.led, Params: r.chain, Tip: r.chain, Utxos: r.chain, Pipeline: r.pipeline(queue),
		PoolCerts: r.led, StakeCerts: r.led, TxIDs: r.led, Hasher: r.led, Clock: r.clock}
	for _, o := range opts {
		if o != nil {
			o(&uc)
		}
	}
	return uc
}

func (r *prig) importer() ImportWitness {
	return ImportWitness{Store: r.store, Tip: r.chain, TxIDs: r.led}
}

func (r *prig) retire(queue bool) RetirePool {
	return RetirePool{Store: r.store, Addresses: r.led, Params: r.chain, Tip: r.chain, Utxos: r.chain, Pipeline: r.pipeline(queue), PoolCerts: r.led, Clock: r.clock}
}

// descriptor reads the stored descriptor.
func (r *prig) descriptor() *pool.Descriptor {
	r.t.Helper()
	d, err := pool.ParseDescriptor([]byte(r.read("mypool.pool.json")))
	if err != nil {
		r.t.Fatal(err)
	}
	return d
}

func (r *prig) collection() *pool.Collection {
	r.t.Helper()
	c, err := r.descriptor().Collection(r.led.TransactionID)
	if err != nil {
		r.t.Fatal(err)
	}
	return c
}

// signWitness signs a transfer file for a slot with the named key, as the
// owner's machine would.
func (r *prig) signWitness(tf pool.TransferFile, keyName, keyType string) pool.TransferFile {
	r.t.Helper()
	cbor, err := pool.ParseTxEnvelope(tf.TxBody)
	if err != nil {
		r.t.Fatal(err)
	}
	id, _ := r.led.TransactionID(cbor)
	k := r.key(keyName + "|" + keyType)
	var w txbuild.Witness
	copy(w.VKey[:], k.Public().(ed25519.PublicKey))
	copy(w.Signature[:], ed25519.Sign(k, id[:]))
	tf.SignedWitness, tf.DateSigned = pool.WitnessEnvelope(w), "signed"
	return tf
}

func (r *prig) transferFile(name string) pool.TransferFile {
	r.t.Helper()
	tf, err := pool.ParseTransferFile([]byte(r.read(name + ".witness")))
	if err != nil {
		r.t.Fatal(err)
	}
	return tf
}

func (r *prig) setOwnerWitness(word string) {
	r.edit("poolOwner", []map[string]string{{"ownerName": "alice", "ownerWitness": "local"}, {"ownerName": "bob", "ownerWitness": word}})
}

func isErr(err error, targets ...error) bool {
	for _, t := range targets {
		if !errors.Is(err, t) {
			return false
		}
	}
	return err != nil
}

func (r *prig) nothingChanged(before string, what string) {
	r.t.Helper()
	if after := r.snapshot(); after != before {
		r.t.Errorf("%s changed the workspace", what)
	}
}

// readerOf gives a read-only view of the rig's store.
func readerOf(r *prig) ports.Reader {
	var out ports.Reader
	_ = r.store.View(context.Background(), func(rd ports.Reader) error { out = rd; return nil })
	return out
}

// confirm is what settling does when the providers say the transaction is in a
// block: it applies the pending update of the transaction, once. It says
// whether there was one.
func (r *prig) confirm(id chain.TxID) bool {
	r.t.Helper()
	st := appassets.Settle{Store: r.store, Clock: r.clock, Appliers: map[string]appassets.Applier{
		assets.PendingPoolRegistration: ApplyRegistration, assets.PendingPoolRetirement: ApplyRetirement}}
	_, found, err := st.Apply(context.Background(), id)
	if err != nil {
		r.t.Fatal(err)
	}
	return found
}

// pending reads the pending update of the transaction.
func (r *prig) pending(id chain.TxID) (assets.Pending, bool) {
	r.t.Helper()
	p, found, err := appassets.PendingOf(context.Background(), r.store, id)
	if err != nil {
		r.t.Fatal(err)
	}
	return p, found
}
