package wallet

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/domain/txparam"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// claimInspector knows the payment address "addr_test_*" (the key hash of the
// payer for "addr_test_p", a derived one for the rest) and "stake_test_*".
type claimInspector struct{ payHash, stakeHash txbuild.KeyHash }

func (f claimInspector) InspectAddress(a chain.Address) (ports.AddressInfo, error) {
	s := string(a)
	switch {
	case strings.HasPrefix(s, "addr_test_"):
		h := txbuild.HashKey([]byte(s))
		if s == "addr_test_p" {
			h = f.payHash
		}
		return ports.AddressInfo{Kind: ports.AddrEnterprise, NetworkID: ports.NetworkTestnet, PaymentKeyHash: &h}, nil
	case strings.HasPrefix(s, "stake_test_"):
		h := f.stakeHash
		return ports.AddressInfo{Kind: ports.AddrReward, NetworkID: ports.NetworkTestnet, StakeKeyHash: &h}, nil
	case strings.HasPrefix(s, "stake_main_"):
		h := f.stakeHash
		return ports.AddressInfo{Kind: ports.AddrReward, NetworkID: ports.NetworkMainnet, StakeKeyHash: &h}, nil
	}
	return ports.AddressInfo{}, errors.New("not an address")
}

type claimSigner struct {
	l          *log
	pay, stake ed25519.PrivateKey
}

func (s *claimSigner) Profile() custody.Profile {
	return custody.NewProfile("fake").
		AllowTx(custody.RolePayment, custody.FeatMultiAssetOutput, custody.FeatMetadata, custody.FeatWithdrawal).
		AllowTx(custody.RoleStake, custody.FeatMultiAssetOutput, custody.FeatMetadata, custody.FeatWithdrawal)
}
func (s *claimSigner) Witness(_ context.Context, key custody.KeyRef, body txbuild.TxBody) (txbuild.Witness, error) {
	s.l.add("witness " + string(key.Role) + " " + key.Owner)
	k := s.pay
	if key.Role == custody.RoleStake {
		k = s.stake
	}
	var w txbuild.Witness
	copy(w.VKey[:], k.Public().(ed25519.PublicKey))
	copy(w.Signature[:], ed25519.Sign(k, body.ID[:]))
	return w, nil
}

type fakeRewards struct {
	l   *log
	r   chain.Reading[chain.RewardAccount]
	err error
}

func (f *fakeRewards) Source() chain.Source { return "koios" }
func (f *fakeRewards) RewardAccount(_ context.Context, a chain.StakeAddress) (chain.Reading[chain.RewardAccount], error) {
	f.l.add("reward-account " + string(a))
	return f.r, f.err
}

func rewardsOf(balance chain.Lovelace, vote chain.Reading[string]) chain.Reading[chain.RewardAccount] {
	return chain.Value(chain.RewardAccount{Withdrawable: balance, VoteDelegation: vote})
}

type claimRig struct {
	l       *log
	store   *memStore
	chain   *fakeChain
	ledger  *fakeLedger
	conf    *fakeConfirmer
	queue   *fakeQueue
	rewards *fakeRewards
	uc      ClaimRewards
}

func newClaimRig(t *testing.T) *claimRig {
	t.Helper()
	l := &log{}
	payPub, payPriv, _ := ed25519.GenerateKey(nil)
	stkPub, stkPriv, _ := ed25519.GenerateKey(nil)
	r := &claimRig{l: l}
	r.store = &memStore{files: memReader{
		{Name: "w", Kind: ports.StakingAddr}:      []byte("stake_test_w\n"),
		{Name: "w", Kind: ports.StakingSKey}:      nil,
		{Name: "p", Kind: ports.AddrFile}:         []byte("addr_test_p\n"),
		{Name: "p", Kind: ports.AddrSKey}:         nil,
		{Name: "d", Kind: ports.AddrFile}:         []byte("addr_test_d\n"),
		{Name: "d", Kind: ports.AddrSKey}:         nil,
		{Name: "w.payment", Kind: ports.AddrFile}: []byte("addr_test_p\n"),
		{Name: "w.payment", Kind: ports.AddrSKey}: nil,
	}}
	r.chain = &fakeChain{l: l, slot: 1000, utxos: []chain.Utxo{
		{TxID: chain.TxID{1}, Lovelace: 30_000_000},
		{TxID: chain.TxID{2}, Index: 1, Lovelace: 20_000_000, Assets: []chain.AssetAmount{{Asset: chain.AssetID{Policy: [28]byte{9}, Name: []byte("t")}, Quantity: 4}}},
	}, params: chain.ProtocolParameters{ProtocolMajor: 10, MaxTxSize: 16384, CoinsPerUTxOByte: 4310}}
	r.ledger = &fakeLedger{l: l}
	r.conf = &fakeConfirmer{l: l, yes: true}
	r.queue = &fakeQueue{l: l}
	r.rewards = &fakeRewards{l: l, r: rewardsOf(5_000_000, chain.Value("alwaysAbstain"))}
	signer := &claimSigner{l: l, pay: payPriv, stake: stkPriv}
	r.uc = ClaimRewards{Store: r.store, Signers: fakeDir{signer: signer}, Utxos: r.chain, Params: r.chain, Tip: r.chain,
		Addresses: claimInspector{payHash: txbuild.HashKey(payPub), stakeHash: txbuild.HashKey(stkPub)},
		Min:       r.ledger, Fees: r.ledger, Bodies: r.ledger, Assembler: r.ledger, Confirmer: r.conf, Rewards: r.rewards, Queue: r.queue,
		NetworkID: ports.NetworkTestnet}
	return r
}

func claimBody(t *testing.T, q ports.QueuedTx) txbuild.BodySpec {
	t.Helper()
	var s txbuild.BodySpec
	if err := json.NewDecoder(strings.NewReader(string(q.Tx.CBOR))).Decode(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

var ctx = context.Background()

// With the destination as the fee payer there is one output holding the inputs
// less the fee plus the whole balance; the withdrawal is that balance, read
// at the start of the run; two witnesses, payment first.
//
// spec: SPO-01claimRewards-INV-006, SPO-01claimRewards-INV-007, SPO-01claimRewards-INV-008, SPO-01claimRewards-INV-009,
// spec: SPO-01claimRewards-INV-014, SPO-01claimRewards-INV-016, SPO-01claimRewards-INV-017, SPO-01claimRewards-OUT-004,
// spec: SPO-01claimRewards-IF-001, SPO-01claimRewards-IF-002, SPO-01claimRewards-IF-005, SPO-01claimRewards-IN-002,
// spec: SPO-01claimRewards-INV-001, SPO-01claimRewards-INV-002, SPO-01claimRewards-OUT-001, SPO-01claimRewards-INV-004,
// spec: SPO-01claimRewards-INV-011, SPO-01claimRewards-INV-012, SPO-01claimRewards-OUT-003, SPO-01claimRewards-PR-001, SPO-Ptx-INV-006
func TestClaimOneOutput(t *testing.T) {
	for _, stakeWord := range []string{"w", "w.staking", "./w.staking"} {
		r := newClaimRig(t)
		res, err := r.uc.Run(ctx, ClaimRequest{Stake: stakeWord, Destination: "p"})
		if err != nil {
			t.Fatalf("%s: %v", stakeWord, err)
		}
		if !res.Queued || res.Withdrawn != 5_000_000 || res.Payer != "p" || res.Destination != "p" {
			t.Fatalf("%+v", res)
		}
		body := claimBody(t, r.queue.got[0])
		if len(body.Outputs) != 1 || body.Outputs[0].Lovelace != 50_000_000-body.Fee+5_000_000 || len(body.Outputs[0].Assets) != 1 {
			t.Errorf("%+v fee %d", body.Outputs, body.Fee)
		}
		if len(body.Withdrawals) != 1 || body.Withdrawals[0].Amount != 5_000_000 || body.Withdrawals[0].Reward != "stake_test_w" {
			t.Errorf("%+v", body.Withdrawals)
		}
		if r.l.count("fee witnesses=2") == 0 || r.l.index("witness payment") > r.l.index("witness stake") || r.l.index("confirm") > r.l.index("witness payment") {
			t.Errorf("%v", r.l.calls)
		}
		q := r.queue.got[0]
		if q.Type != "Withdrawal" || q.FromName != "p" || q.ToName != "p" || len(q.Extra) != 2 ||
			q.Extra[0] != (ports.QueuedField{Key: "stakeAddr", Value: "w.staking"}) || q.Extra[1] != (ports.QueuedField{Key: "stakingAddr", Value: "stake_test_w"}) ||
			q.Description != "signed rewards withdrawal from 'w.staking' to 'p', payment via 'p'" {
			t.Errorf("%+v", q)
		}
		if r.conf.got.Kind != "rewards withdrawal" || r.conf.got.Withdrawal != 5_000_000 {
			t.Errorf("%+v", r.conf.got)
		}
	}
}

// With another fee payer the payer's change comes first and keeps every asset,
// the destination gets exactly the rewards.
//
// spec: SPO-01claimRewards-IF-001, SPO-01claimRewards-OUT-002, SPO-01claimRewards-IF-003, SPO-01claimRewards-OUT-003
func TestClaimTwoOutputs(t *testing.T) {
	r := newClaimRig(t)
	res, err := r.uc.Run(ctx, ClaimRequest{Stake: "w", Destination: "d", Payer: "p.addr"})
	if err != nil {
		t.Fatal(err)
	}
	body := claimBody(t, r.queue.got[0])
	if len(body.Outputs) != 2 || body.Outputs[0].Address != "addr_test_p" || body.Outputs[1].Address != "addr_test_d" ||
		body.Outputs[0].Lovelace != 50_000_000-body.Fee || len(body.Outputs[0].Assets) != 1 ||
		body.Outputs[1].Lovelace != 5_000_000 || len(body.Outputs[1].Assets) != 0 {
		t.Errorf("%+v fee %d", body.Outputs, body.Fee)
	}
	if res.Payer != "p" || res.Destination != "d" || r.queue.got[0].ToName != "d" || r.queue.got[0].FromName != "p" ||
		r.queue.got[0].Description != "signed rewards withdrawal from 'w.staking' to 'd', payment via 'p'" {
		t.Errorf("%+v %+v", res, r.queue.got[0])
	}
	// A literal payment address is a destination too, but needs a fee payer.
	r = newClaimRig(t)
	if _, err := r.uc.Run(ctx, ClaimRequest{Stake: "w", Destination: "addr_test_zzz"}); !errors.Is(err, ErrNoFeePayer) {
		t.Errorf("%v", err)
	}
	if _, err := r.uc.Run(ctx, ClaimRequest{Stake: "w", Destination: "addr_test_zzz", Payer: "p"}); err != nil {
		t.Errorf("%v", err)
	}
}

// The refusals come in upstream's order and write nothing. Unknown is not
// "not registered" and a failing query is an error, not exit 0.
//
// Decision (SPO-01claimRewards-PRE-005): the vote-delegation refusal applies
// from protocol major 10 and never below. A vote delegation the source did not
// state is not "none": it is refused as unknown.
//
// spec: SPO-01claimRewards-PRE-004, SPO-01claimRewards-PRE-005, SPO-01claimRewards-PRE-006, SPO-01claimRewards-PRE-001,
// spec: SPO-01claimRewards-IN-001, SPO-01claimRewards-PRE-002, SPO-01claimRewards-PRE-003, SPO-01claimRewards-MODE-001,
// spec: SPO-01claimRewards-MODE-002, SPO-01claimRewards-INV-003, SPO-01claimRewards-PRE-008, SPO-Ptx-PR-002
func TestClaimRefusals(t *testing.T) {
	cases := []struct {
		name  string
		setup func(r *claimRig)
		want  error
		// chainFree: refused before any chain read.
		chainFree bool
	}{
		{"not registered", func(r *claimRig) { r.rewards.r = chain.None[chain.RewardAccount]() }, ErrStakeNotRegistered, false},
		{"unknown state is not 'not registered'", func(r *claimRig) { r.rewards.r = chain.Unknown[chain.RewardAccount]("not in file") }, ErrRewardUnknown, false},
		{"the query fails", func(r *claimRig) { r.rewards.err = errors.New("boom") }, nil, false},
		{"no vote delegation at protocol 10", func(r *claimRig) { r.rewards.r = rewardsOf(5_000_000, chain.None[string]()) }, ErrNoVoteDelegation, false},
		{"notSet is no vote delegation", func(r *claimRig) { r.rewards.r = rewardsOf(5_000_000, chain.Value("notSet")) }, ErrNoVoteDelegation, false},
		{"the vote delegation is unknown", func(r *claimRig) { r.rewards.r = rewardsOf(5_000_000, chain.Unknown[string]("absent")) }, ErrRewardUnknown, false},
		{"no rewards", func(r *claimRig) { r.rewards.r = rewardsOf(0, chain.Value("alwaysAbstain")) }, ErrNoRewards, false},
		{"no reward reader", func(r *claimRig) { r.uc.Rewards = nil }, ErrNoRewardReader, true},
		{"no stake address file", func(r *claimRig) { delete(r.store.files, ports.Ref{Name: "w", Kind: ports.StakingAddr}) }, ErrNoStakeAddress, true},
		{"no stake key", func(r *claimRig) { delete(r.store.files, ports.Ref{Name: "w", Kind: ports.StakingSKey}) }, ErrNoStakeKey, true},
		{"no payer key", func(r *claimRig) { delete(r.store.files, ports.Ref{Name: "p", Kind: ports.AddrSKey}) }, ErrNoSigningKey, true},
		{"a hardware stake key", func(r *claimRig) {
			delete(r.store.files, ports.Ref{Name: "w", Kind: ports.StakingSKey})
			r.store.files[ports.Ref{Name: "w", Kind: ports.StakingHwsFile}] = []byte("hw")
		}, nil, true},
		{"a hardware payer key", func(r *claimRig) {
			r.store.files[ports.Ref{Name: "p", Kind: ports.AddrHwsFile}] = []byte("hw")
		}, nil, true},
		{"the stake file holds a payment address", func(r *claimRig) {
			r.store.files[ports.Ref{Name: "w", Kind: ports.StakingAddr}] = []byte("addr_test_p\n")
		}, ErrNotStakeAddress, true},
		{"a mainnet stake address", func(r *claimRig) {
			r.store.files[ports.Ref{Name: "w", Kind: ports.StakingAddr}] = []byte("stake_main_w\n")
		}, ErrNotStakeAddress, true},
		{"declined", func(r *claimRig) { r.conf.yes = false }, ErrDeclined, false},
		{"no confirmer", func(r *claimRig) { r.uc.Confirmer = nil }, ErrNoConfirmer, false},
		{"a destination that is nothing", func(r *claimRig) {}, ErrBadDestination, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newClaimRig(t)
			c.setup(r)
			dest := "p"
			if c.want == ErrBadDestination {
				dest = "nothing-at-all"
			}
			_, err := r.uc.Run(ctx, ClaimRequest{Stake: "w", Destination: dest})
			if err == nil || (c.want != nil && !errors.Is(err, c.want)) {
				t.Fatalf("%v", err)
			}
			if r.l.count("enqueue") != 0 || r.l.count("witness") != 0 {
				t.Errorf("effects: %v", r.l.calls)
			}
			if c.chainFree && (r.l.count("reward-account") != 0 || r.l.count("utxos") != 0 || r.l.count("params") != 0 || r.l.count("tip") != 0) {
				t.Errorf("the refusal must come before any chain read: %v", r.l.calls)
			}
		})
	}
	// Below protocol 10 the vote delegation is not required.
	r := newClaimRig(t)
	r.chain.params.ProtocolMajor = 9
	r.rewards.r = rewardsOf(5_000_000, chain.None[string]())
	if _, err := r.uc.Run(ctx, ClaimRequest{Stake: "w", Destination: "p"}); err != nil {
		t.Errorf("protocol 9: %v", err)
	}
	// A pre-Babbage protocol is refused.
	r = newClaimRig(t)
	r.chain.params.ProtocolMajor = 6
	if _, err := r.uc.Run(ctx, ClaimRequest{Stake: "w", Destination: "p"}); !errors.Is(err, ErrProtocolTooOld) {
		t.Errorf("%v", err)
	}
}

// Hazard H2: upstream does not check the final build and signs the body an
// earlier run left behind (SPO-01claimRewards-PRE-009). Here the body is a
// value built once in memory: when the build fails nothing is signed,
// confirmed or queued, and a second claim never carries the first one's body.
//
// spec: SPO-01claimRewards-PRE-009, SPO-01claimRewards-SEC-003, SPO-Ptx-INV-010
// spec: SPO-01claimRewards-INV-013
func TestClaimFixesTheStaleBodyHazardByConstruction(t *testing.T) {
	r := newClaimRig(t)
	if _, err := r.uc.Run(ctx, ClaimRequest{Stake: "w", Destination: "p"}); err != nil {
		t.Fatal(err)
	}
	first := string(r.queue.got[0].Tx.CBOR)
	r.l.calls = nil
	failing := &failingBodies{inner: r.ledger}
	r.uc.Bodies = failing
	_, err := r.uc.Run(ctx, ClaimRequest{Stake: "w", Destination: "d", Payer: "p"})
	if err == nil || !strings.Contains(err.Error(), "cannot build") {
		t.Fatalf("a failed build must be an error: %v", err)
	}
	if len(r.queue.got) != 1 || r.l.count("confirm") != 0 || r.l.count("witness") != 0 || r.l.count("assemble") != 0 {
		t.Errorf("the failed run signed or queued something: %v", r.l.calls)
	}
	// A later successful run for another destination is its own body.
	r.uc.Bodies = r.ledger
	if _, err := r.uc.Run(ctx, ClaimRequest{Stake: "w", Destination: "d", Payer: "p"}); err != nil {
		t.Fatal(err)
	}
	if string(r.queue.got[1].Tx.CBOR) == first || r.queue.got[1].ToName != "d" {
		t.Error("the second claim carried the first one's transaction")
	}
}

type failingBodies struct{ inner *fakeLedger }

func (f *failingBodies) BuildBody(txbuild.BodySpec) (txbuild.TxBody, error) {
	return txbuild.TxBody{}, errors.New("cardano-cli cannot build the body")
}

// Decision (SPO-01claimRewards-INV-005): upstream makes no size check for a
// claim and the node rejects an oversize transaction at submission; the use
// case applies the check of SPO-Ptx-PRE-007 as the port note says.
//
// spec: SPO-01claimRewards-INV-005, SPO-Ptx-PRE-007
// spec: SPO-01claimRewards-INV-015
func TestClaimChecksTheSize(t *testing.T) {
	r := newClaimRig(t)
	r.chain.params.MaxTxSize = 100
	if _, err := r.uc.Run(ctx, ClaimRequest{Stake: "w", Destination: "p"}); err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Errorf("%v", err)
	}
	if r.l.count("enqueue") != 0 || r.l.count("confirm") != 0 {
		t.Error("an oversize claim was confirmed or queued")
	}
}

// Decision (SPO-01claimRewards-PRE-007): each output is held to its own
// minimum; upstream compares the payer's output with the minimum computed for
// the destination and never checks the reward output.
//
// spec: SPO-01claimRewards-PRE-007, SPO-Ptx-PRE-002
func TestClaimChecksEachOutputItsOwnMinimum(t *testing.T) {
	r := newClaimRig(t)
	r.rewards.r = rewardsOf(500_000, chain.Value("alwaysAbstain"))
	_, err := r.uc.Run(ctx, ClaimRequest{Stake: "w", Destination: "d", Payer: "p"})
	var below *txbuild.BelowMinimumError
	if !errors.As(err, &below) || below.Which != "destination" {
		t.Errorf("rewards below the minimum to another address: %v", err)
	}
	// The same rewards into the payer's own address pass: the sum is above.
	if _, err := r.uc.Run(ctx, ClaimRequest{Stake: "w", Destination: "p"}); err != nil {
		t.Errorf("%v", err)
	}
}

// Both routes set, or neither, is a wiring error before anything happens.
func TestClaimNeedsExactlyOneRoute(t *testing.T) {
	r := newClaimRig(t)
	r.uc.Queue = nil
	if _, err := r.uc.Run(ctx, ClaimRequest{Stake: "w", Destination: "p"}); !errors.Is(err, ErrMisconfigured) {
		t.Errorf("%v", err)
	}
}

// Parameters are read before the reward state (SPO-01claimRewards-INV-010);
// an ADA Handle destination is refused (not ported yet, and refused offline
// upstream); an unusable transfer file is refused by the snapshot reader
// before any claim is built (SPO-Ptransfer-IN-001, tested in transferfile).
//
// spec: SPO-01claimRewards-INV-010, SPO-01claimRewards-MODE-003, SPO-01claimRewards-IF-003
func TestClaimReadsParametersFirstAndRefusesHandles(t *testing.T) {
	r := newClaimRig(t)
	if _, err := r.uc.Run(ctx, ClaimRequest{Stake: "w", Destination: "p"}); err != nil {
		t.Fatal(err)
	}
	if r.l.index("params") > r.l.index("reward-account") || r.l.index("params") < 0 {
		t.Errorf("%v", r.l.calls)
	}
	r = newClaimRig(t)
	if _, err := r.uc.Run(ctx, ClaimRequest{Stake: "w", Destination: "$myhandle", Payer: "p"}); !errors.Is(err, ErrAdaHandleUnsupported) {
		t.Errorf("%v", err)
	}
	if r.l.count("enqueue") != 0 || r.l.count("reward-account") != 0 {
		t.Errorf("%v", r.l.calls)
	}
}

// The destination is the caller's choice and may differ from the account's
// owner: the summary names it, and with the explicit skip policy it is
// still the caller who chose to go without the question; the skip is
// recorded. A literal destination never goes through a file: the store is
// read-only here and holds nothing about it (SPO-01claimRewards-SEC-002).
//
// spec: SPO-01claimRewards-SEC-001, SPO-01claimRewards-SEC-002, SPO-01claimRewards-PR-001, SPO-Ptx-PR-003
func TestClaimSkipIsExplicitAndTheDestinationIsShown(t *testing.T) {
	r := newClaimRig(t)
	if _, err := r.uc.Run(ctx, ClaimRequest{Stake: "w", Destination: "addr_test_zzz", Payer: "p"}); err != nil {
		t.Fatal(err)
	}
	if r.conf.got.Destination != "addr_test_zzz" || r.conf.got.DestAddr != "addr_test_zzz" || r.conf.got.Withdrawal != 5_000_000 {
		t.Errorf("%+v", r.conf.got)
	}
	r = newClaimRig(t)
	r.uc.Approval = ApprovalSkip
	res, err := r.uc.Run(ctx, ClaimRequest{Stake: "w", Destination: "d", Payer: "p"})
	if err != nil || !res.ApprovalSkipped || r.l.count("confirm") != 0 {
		t.Errorf("%+v %v", res, err)
	}
}

type memFiles map[string][]byte

func (m memFiles) ReadMetadataFile(p string) ([]byte, error) {
	if b, ok := m[p]; ok {
		return b, nil
	}
	return nil, ports.ErrNotFound
}

// The extra parameters of a certificate script reach a claim: a metadata file
// and a message are in the body, a missing file is the domain's refusal before
// anything is read from the chain.
func TestClaimTakesMessageAndMetadataExtras(t *testing.T) {
	r := newClaimRig(t)
	r.uc.Files = memFiles{"m.json": []byte(`{"721":{"name":"demo"}}`)}
	ex, err := txparam.Parse([]string{"m.json", "msg:hello"}, txparam.ForCertificate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.uc.Run(ctx, ClaimRequest{Stake: "w", Destination: "p", Extras: &ex}); err != nil {
		t.Fatal(err)
	}
	body := claimBody(t, r.queue.got[0])
	if len(body.MetadataFiles) != 1 || body.MetadataFiles[0].Name != "m.json" || len(body.Message) != 1 || body.Message[0] != "hello" {
		t.Errorf("metadata %+v message %v", body.MetadataFiles, body.Message)
	}

	r = newClaimRig(t)
	r.uc.Files = memFiles{}
	ex, _ = txparam.Parse([]string{"gone.json"}, txparam.ForCertificate)
	if _, err := r.uc.Run(ctx, ClaimRequest{Stake: "w", Destination: "p", Extras: &ex}); !errors.Is(err, txparam.ErrBadMetadataFile) {
		t.Errorf("a missing file: %v", err)
	}
	if len(r.queue.got) != 0 || r.l.count("confirm") != 0 {
		t.Error("something ran before the refusal")
	}
	// Without extras nothing changes.
	r = newClaimRig(t)
	if _, err := r.uc.Run(ctx, ClaimRequest{Stake: "w", Destination: "p", Message: []string{"x"}}); err != nil {
		t.Fatal(err)
	}
	if b := claimBody(t, r.queue.got[0]); len(b.MetadataFiles) != 0 || len(b.Message) != 1 {
		t.Errorf("%+v", b)
	}
}
