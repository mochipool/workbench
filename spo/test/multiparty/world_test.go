package multiparty

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/app/poolops"
	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/multiparty/partyrig"
)

var ctx = context.Background()

var t0 = time.Unix(1_800_000_000, 0).UTC()

// ---- what is outside the process: the chain, the confirmation, the submission ----

type chainData struct {
	*partyrig.Chain
	utxos  []chain.Utxo
	params chain.ProtocolParameters
}

func (c chainData) Utxos(context.Context, chain.Address) ([]chain.Utxo, error) { return c.utxos, nil }
func (c chainData) ProtocolParameters(context.Context) (chain.ProtocolParameters, error) {
	return c.params, nil
}

type confirmer struct {
	mu     sync.Mutex
	stages []string
}

func (c *confirmer) Confirm(_ context.Context, s ports.TxSummary) (bool, error) {
	c.mu.Lock()
	c.stages = append(c.stages, s.Stage)
	c.mu.Unlock()
	return true, nil
}

type submitter struct {
	mu   sync.Mutex
	sent [][]byte
}

func (s *submitter) Source() chain.Source { return "rig" }
func (s *submitter) Submit(_ context.Context, tx []byte) (chain.TxID, error) {
	s.mu.Lock()
	s.sent = append(s.sent, tx)
	s.mu.Unlock()
	return native.Ledger{}.TransactionID(tx)
}

func (s *submitter) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.sent) }

// ---- the world: a pool with two owners, one of them on another machine ------------

const descriptor = `{
  "poolName": "mypool",
  "poolOwner": [
    {"ownerName": "alice", "ownerWitness": "local"},
    {"ownerName": "bob", "ownerWitness": "bobparty"}
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

type world struct {
	t      *testing.T
	clock  *partyrig.Clock
	chain  chainData
	C, B   *partyrig.Workspace
	led    native.Ledger
	conf   *confirmer
	sub    *submitter
	poolID chain.PoolID
	bech   string
	// otherBech is a second pool id both sides know, for the cold-key tests.
	otherBech string
	otherID   chain.PoolID
	bobHash   txbuild.KeyHash
	keys      map[string]ed25519.PrivateKey
}

func (w *world) key(name string) ed25519.PrivateKey {
	if k, ok := w.keys[name]; ok {
		return k
	}
	seed := sha256.Sum256([]byte("multiparty key " + name))
	k := ed25519.NewKeyFromSeed(seed[:])
	w.keys[name] = k
	return k
}

func env(typ, desc string, raw []byte) []byte {
	return pool.MarshalEnvelope(pool.Envelope{Type: typ, Description: desc, CborHex: "5820" + hex.EncodeToString(raw)})
}

func write(t *testing.T, dir, name string, b []byte) {
	t.Helper()
	p := filepath.Join(dir, name)
	os.Chmod(p, 0o600)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// putKey writes a key pair under the cardano-cli names, from a fixed seed, so
// that two machines can hold the same key.
func (w *world) putKey(dir, vk, sk, vkType, skType, vkDesc string, withSecret bool) {
	k := w.key(strings.SplitN(vk, ".", 2)[0] + "|" + vkType)
	write(w.t, dir, vk, env(vkType, vkDesc, k.Public().(ed25519.PublicKey)))
	if withSecret {
		write(w.t, dir, sk, env(skType, "", k.Seed()))
	}
}

func (w *world) hashOf(vkFile string) txbuild.KeyHash {
	b, err := os.ReadFile(filepath.Join(w.C.Dir, vkFile))
	if err != nil {
		w.t.Fatal(err)
	}
	e, err := pool.ParseEnvelope(b)
	if err != nil {
		w.t.Fatal(err)
	}
	raw, _ := e.Key32()
	return txbuild.HashKey(raw)
}

// newWorld builds the coordinator's workspace (the pool's keys, alice, the
// payer, a descriptor whose second owner is the remote party "bobparty") and
// bob's (his stake key), enrolls each at the other, and generates the pool
// certificate. nodeB is bob's tailcat node key, nil for none.
func newWorld(t *testing.T, nodeB *party.NodeKey) *world {
	t.Helper()
	return newWorldOpt(t, worldOpt{nodeB: nodeB})
}

// worldOpt shapes the world: the tailcat node keys the two parties publish, and
// whether the scopes are wide (the cold-key tests, which ask for a pool cold
// key of the other pool) or as an operator would set them for a registration
// of one pool: the stake role and that pool.
type worldOpt struct {
	nodeB, nodeC *party.NodeKey
	wide         bool
	// coordScope, when set, is the scope bob's machine enrolls the coordinator
	// with, in place of the registration's; it can name the world's pools.
	coordScope func(w *world) party.Scope
}

func newWorldOpt(t *testing.T, o worldOpt) *world {
	t.Helper()
	nodeB := o.nodeB
	clock := partyrig.NewClock(t0)
	ch := partyrig.NewChain(clock.Now())
	w := &world{t: t, clock: clock, keys: map[string]ed25519.PrivateKey{}, conf: &confirmer{}, sub: &submitter{}}
	w.chain = chainData{Chain: ch,
		utxos: []chain.Utxo{{TxID: chain.TxID{1}, Index: 0, Lovelace: 800_000_000}, {TxID: chain.TxID{2}, Index: 1, Lovelace: 700_000_000}},
		params: chain.ProtocolParameters{TxFeePerByte: 44, TxFeeFixed: 155381, CoinsPerUTxOByte: 4310, StakeAddressDeposit: 2_000_000,
			StakePoolDeposit: 500_000_000, MaxTxSize: 16384, ProtocolMajor: 11, MinPoolCost: 170_000_000, PoolRetireMaxEpoch: 18}}
	w.C = partyrig.NewWithNode(t, "coordinator", clock, ch, o.nodeC)
	w.B = partyrig.NewWithNode(t, "bob", clock, ch, nodeB)

	w.putKey(w.C.Dir, "mypool.node.vkey", "mypool.node.skey", "StakePoolVerificationKey_ed25519", "StakePoolSigningKey_ed25519", "Stake Pool Operator Verification Key", true)
	w.putKey(w.C.Dir, "mypool.vrf.vkey", "mypool.vrf.skey", "VrfVerificationKey_PraosVRF", "VrfSigningKey_PraosVRF", "VRF Verification Key", true)
	w.putKey(w.C.Dir, "alice.staking.vkey", "alice.staking.skey", "StakeVerificationKeyShelley_ed25519", "StakeSigningKeyShelley_ed25519", "Stake Verification Key", true)
	w.putKey(w.C.Dir, "bob.staking.vkey", "bob.staking.skey", "StakeVerificationKeyShelley_ed25519", "StakeSigningKeyShelley_ed25519", "Stake Verification Key", false)
	w.putKey(w.C.Dir, "pay.vkey", "pay.skey", "PaymentVerificationKeyShelley_ed25519", "PaymentSigningKeyShelley_ed25519", "Payment Verification Key", true)
	// Bob's machine holds his own stake key and nothing else.
	w.putKey(w.B.Dir, "bob.staking.vkey", "bob.staking.skey", "StakeVerificationKeyShelley_ed25519", "StakeSigningKeyShelley_ed25519", "Stake Verification Key", true)

	var pk [32]byte
	copy(pk[:], w.key("mypool|StakePoolVerificationKey_ed25519").Public().(ed25519.PublicKey))
	w.poolID, _ = chain.PoolIDOf(pk[:])
	w.bech = w.poolID.Bech32()
	// Bob also holds the cold key of another pool: the cold-key tests ask
	// him to sign for it.
	w.putKey(w.B.Dir, "otherpool.node.vkey", "otherpool.node.skey", "StakePoolVerificationKey_ed25519", "StakePoolSigningKey_ed25519", "Stake Pool Operator Verification Key", true)
	var ok [32]byte
	copy(ok[:], w.key("otherpool|StakePoolVerificationKey_ed25519").Public().(ed25519.PublicKey))
	w.otherID, _ = chain.PoolIDOf(ok[:])
	w.otherBech = w.otherID.Bech32()
	w.B.AddKnownKey(custody.RolePoolCold, "otherpool", [28]byte(w.otherID))
	w.bobHash = w.hashOf("bob.staking.vkey")

	addr, err := w.led.BuildAddress(0, w.hashOf("pay.vkey"), nil)
	if err != nil {
		t.Fatal(err)
	}
	write(t, w.C.Dir, "pay.addr", []byte(addr+"\n"))
	for _, o := range []string{"alice", "bob"} {
		cert, err := w.led.BuildCertificate(stake.Spec{Kind: stake.CertPoolDelegation, Stake: stake.KeyHash(w.hashOf(o + ".staking.vkey")), Pool: w.poolID})
		if err != nil {
			t.Fatal(err)
		}
		write(t, w.C.Dir, o+".deleg.cert", cert.Envelope)
	}
	write(t, w.C.Dir, "mypool.pool.json", []byte(descriptor))
	if _, err := (poolops.GeneratePoolCertificate{Store: w.C.Store, Params: w.chain, Certs: w.led, Hasher: w.led, Clock: clock}).Run(ctx, poolops.GenerateRequest{Pool: "mypool"}); err != nil {
		t.Fatal(err)
	}

	// Each side enrolls the other with the scope an operator names: for a
	// registration of this pool, the stake role and this pool. The cold-key
	// tests widen it to the pool cold key and another pool id.
	scope := party.Scope{KeyRoles: []custody.Role{custody.RoleStake}, Pools: []string{w.bech}}
	if o.wide {
		scope = party.Scope{KeyRoles: []custody.Role{custody.RoleStake, custody.RolePoolCold}, Pools: []string{w.bech, w.otherBech}}
	}
	w.C.EnrollScoped(w.B, "bobparty", []party.Role{party.RoleSigner}, scope)
	if o.coordScope != nil {
		scope = o.coordScope(w)
	}
	w.B.EnrollScoped(w.C, "coordinator", []party.Role{party.RoleCoordinator}, scope)
	return w
}

// registerPool is the pool registration use case, wired to leave the slot of
// a remote owner empty.
func (w *world) registerPool() poolops.RegisterPool {
	return poolops.RegisterPool{Store: w.C.Store, Addresses: w.led, Params: w.chain, Tip: w.chain, Utxos: w.chain,
		Pipeline:  txflow.Pipeline{Signers: native.Signers{Vault: w.C.Store.Anchor()}, Min: w.led, Fees: w.led, Bodies: w.led, Assembler: w.led, Confirmer: w.conf, Submitter: w.sub},
		PoolCerts: w.led, StakeCerts: w.led, TxIDs: w.led, Hasher: w.led, Clock: w.clock, AllowPending: true, Parties: w.C.Registry}
}

// open registers the pool with the remote owner's slot pending.
func (w *world) open() poolops.RegisterResult {
	w.t.Helper()
	res, err := w.registerPool().Run(ctx, poolops.RegisterRequest{Pool: "mypool", Payer: "pay"})
	if err != nil {
		w.t.Fatal(err)
	}
	if res.State != pool.CollectionOpenIncomplete || len(res.Missing) != 1 || res.Missing[0] != "bob.staking" {
		w.t.Fatalf("registration = %+v", res)
	}
	return res
}

var poolRef = multisig.CollectionRef{Kind: multisig.KindPool, Name: "mypool"}

// coordinator is the coordinator role with the completion wired to the
// registration use case, as a CLI wires it.
func (w *world) coordinator() multisig.Coordinator {
	c := w.C.Coordinator()
	c.Complete = func(ctx context.Context, ref multisig.CollectionRef) (multisig.Completion, error) {
		res, err := w.registerPool().Run(ctx, poolops.RegisterRequest{Pool: "mypool", Payer: "pay"})
		if err != nil {
			return multisig.Completion{}, err
		}
		return multisig.Completion{Submitted: res.Submitted, TxID: res.TxID}, nil
	}
	return c
}

func (w *world) collection() pool.Collection {
	w.t.Helper()
	var c *pool.Collection
	err := w.C.Store.View(ctx, func(r ports.NamedReader) error {
		raw, err := r.Get(ports.NamedRef{Name: "mypool", Kind: ports.PoolDescriptor})
		if err != nil {
			return err
		}
		d, err := pool.ParseDescriptor(raw)
		if err != nil {
			return err
		}
		c, err = d.Collection(w.led.TransactionID)
		return err
	})
	if err != nil || c == nil {
		w.t.Fatalf("collection: %v", err)
	}
	return *c
}

// snapshot is what must not change when an attack is refused.
func (w *world) snapshot() string {
	c := w.collection()
	var b strings.Builder
	fmt.Fprintf(&b, "v%d %s ", c.Version, c.Body.ID)
	for _, s := range c.Slots {
		fmt.Fprintf(&b, "[%s %s filled=%v unauth=%v]", s.Name, s.PartyFingerprint, s.Filled(), s.Unauthenticated)
	}
	return b.String()
}

// bobSigner is bob's signer role, which holds the key by its hash.
func (w *world) bobSigner() multisig.Signer {
	w.B.AddKnownKey(custody.RoleStake, "bob", [28]byte(w.bobHash))
	return w.B.Signer()
}

// reviewAndApprove is what bob's operator does: read the decoded body, answer
// yes. It returns the review for assertions.
func (w *world) reviewAndApprove(s multisig.Signer) multisig.Review {
	w.t.Helper()
	pend, err := s.Pending(ctx)
	if err != nil || len(pend) != 1 {
		w.t.Fatalf("pending = %+v, %v", pend, err)
	}
	rv, err := s.ReviewRequest(ctx, pend[0].ID)
	if err != nil {
		w.t.Fatal(err)
	}
	a, err := rv.Approval()
	if err != nil {
		w.t.Fatal(err)
	}
	if _, err := s.Approve(ctx, a); err != nil {
		w.t.Fatal(err)
	}
	return rv
}

var _ = time.Second

func nativeViewer() native.TxViewer { return native.TxViewer{} }

func bodyMap(t *testing.T, b txbuild.TxBody) []byte {
	t.Helper()
	m, err := native.TxViewer{}.BodyOf(b.CBOR)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func containsAny(s, sub string) bool { return sub != "" && strings.Contains(s, sub) }
