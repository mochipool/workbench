package hardware_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/assets"
	"github.com/mochipool/workbench/spo/internal/app/governance"
	"github.com/mochipool/workbench/spo/internal/app/poolops"
	"github.com/mochipool/workbench/spo/internal/app/stake"
	"github.com/mochipool/workbench/spo/internal/app/wallet"
	dassets "github.com/mochipool/workbench/spo/internal/domain/assets"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	dgov "github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/world"
)

// storedKeyHash is the key hash of the verification key the workspace holds
// for a name: the key the operator expects to sign.
func storedKeyHash(t *testing.T, w *world.World, name string, kind ports.Kind) txbuild.KeyHash {
	t.Helper()
	env, err := pool.ParseEnvelope(get(t, w, name, kind))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := env.Key32()
	if err != nil {
		t.Fatal(err)
	}
	return txbuild.HashKey(raw)
}

// verifyAgainstShown checks the transaction at index i of the chain's
// submissions against what the operator was shown and who was meant to sign:
// the id of the last confirmation (the summary the operator approved) is the id
// of the submitted transaction and of the result, and the transaction carries
// exactly one witness for each of the expected keys, every one an Ed25519
// signature over that shown id. It returns the number of witnesses.
func verifyAgainstShown(t *testing.T, w *world.World, i int, result chain.TxID, want ...txbuild.KeyHash) int {
	t.Helper()
	if len(w.Conf.Seen) == 0 {
		t.Fatal("the operator was shown nothing")
	}
	shown := w.Conf.Seen[len(w.Conf.Seen)-1].TxID
	if result != shown {
		t.Errorf("the result is transaction %s, the operator was shown %s", result, shown)
	}
	signed := w.Chain.Submitted[i]
	id, err := w.Ledger.TransactionID(signed)
	if err != nil || id != shown {
		t.Fatalf("the submitted transaction is %s (%v), the operator was shown %s", id, err, shown)
	}
	ws, err := (native.TxViewer{}).Witnesses(signed)
	if err != nil {
		t.Fatal(err)
	}
	left := map[txbuild.KeyHash]int{}
	for _, k := range want {
		left[k]++
	}
	for _, x := range ws {
		if !ed25519.Verify(x.VKey[:], id[:], x.Signature[:]) {
			t.Errorf("a witness does not verify over the shown body id")
		}
		h := txbuild.HashKey(x.VKey[:])
		if left[h] == 0 {
			t.Errorf("a witness by the key %x, which is none of the %d expected (or a second one by the same key)", h[:], len(want))
			continue
		}
		left[h]--
	}
	for h, n := range left {
		if n > 0 {
			t.Errorf("no witness by the expected key %x", h[:])
		}
	}
	return len(ws)
}

// refusedWhenMisbehaving runs `run` while the fake tool does each misbehaviour of
// modes and demands an error and no new submission; the tool is put right again.
func refusedWhenMisbehaving(t *testing.T, w *world.World, modes []string, run func() error) {
	t.Helper()
	for _, m := range modes {
		w.HW.Set("misbehave", m)
		before := len(w.Chain.Submitted)
		if err := run(); err == nil {
			t.Errorf("%s: the run was accepted", m)
		}
		if len(w.Chain.Submitted) != before {
			t.Errorf("%s: something was submitted", m)
		}
	}
	w.HW.Set("misbehave", "")
}

var witnessMisbehaviour = []string{"wrongkey", "badsig", "truncated", "exitafter"}

type accountReader struct {
	deposit   chain.Lovelace
	withdraw  chain.Lovelace
	voteDeleg bool
}

func (accountReader) Source() chain.Source { return "fake chain" }
func (a accountReader) RewardAccount(_ context.Context, addr chain.StakeAddress) (chain.Reading[chain.RewardAccount], error) {
	vote := chain.None[string]()
	if a.voteDeleg {
		vote = chain.Value("drep_always_abstain")
	}
	return chain.Value(chain.RewardAccount{Address: addr, DelegatedPool: chain.None[chain.PoolID](), VoteDelegation: vote,
		Withdrawable: a.withdraw, Deposit: chain.Value(a.deposit), GovActionDeposits: chain.Value([]chain.GovActionDeposit(nil))}), nil
}

// 08b: a stake address is deregistered by a payment key and a stake key on a Ledger.
// The deposit is refunded, the device signs the canonical body the operator was
// shown, and a tool that signs with another key or over another body is refused.
//
// spec: SPO-08b-EXT-002, SPO-08b-INV-002, SPO-Ptx-EXT-005, SPO-Xparty-INV-012
func TestStakeDeregistrationOnLedger(t *testing.T) {
	ctx := context.Background()
	w := world.New(t)
	w.UseHardware("Ledger", "8.0.8")
	w.Bodies = world.LegacyInputs{Ledger: w.Ledger}
	account(t, w, "hw", custody.PlaceHardware, 50_000_000)
	acct := accountReader{deposit: 2_000_000}
	gen := stake.GenerateDeregistrationCertificate{Store: w.Store, Addresses: w.Ledger, Certs: w.Ledger, Account: acct, Sources: stake.SingleSourceAcknowledged, OnSingle: noopSingle, NetworkID: w.Network}
	if _, err := gen.Run(ctx, "hw"); err != nil {
		t.Fatal(err)
	}
	uc := stake.DeregisterStakeAddress{Base: stake.Base{Store: w.Store, Addresses: w.Ledger, Params: w.Chain, Tip: w.Chain, Utxos: w.Chain, NetworkID: w.Network, Pipeline: w.Pipeline()},
		Certs: w.Ledger, Account: acct, Sources: stake.SingleSourceAcknowledged, OnSingle: noopSingle}
	refusedWhenMisbehaving(t, w, witnessMisbehaviour, func() error {
		_, err := uc.Run(ctx, stake.RegisterRequest{Stake: "hw", Payer: "hw.payment"})
		return err
	})
	res, err := uc.Run(ctx, stake.RegisterRequest{Stake: "hw", Payer: "hw.payment"})
	if err != nil || !res.Submitted {
		t.Fatalf("%+v %v", res, err)
	}
	if n := verifyAgainstShown(t, w, 0, res.TxID, storedKeyHash(t, w, "hw.payment", ports.AddrVKey), storedKeyHash(t, w, "hw", ports.StakingVKey)); n != 2 {
		t.Errorf("%d witnesses", n)
	}
}

// 22b: a vote delegation is submitted with the payment and stake keys on a Ledger.
//
// spec: SPO-22b-EXT-001, SPO-Ptx-EXT-005, SPO-Xparty-INV-012
func TestVoteDelegationOnLedger(t *testing.T) {
	ctx := context.Background()
	w := world.New(t)
	w.UseHardware("Ledger", "8.0.8")
	w.Bodies = world.LegacyInputs{Ledger: w.Ledger}
	account(t, w, "hw", custody.PlaceHardware, 50_000_000)
	if _, err := (stake.GenerateVoteDelegationCertificate{Store: w.Store, Certs: w.Ledger, Params: w.Chain}).Run(ctx, stake.VoteDelegationRequest{Target: "always-abstain", Delegator: "hw"}); err != nil {
		t.Fatal(err)
	}
	uc := stake.RegisterVoteDelegation{Base: stake.Base{Store: w.Store, Addresses: w.Ledger, Params: w.Chain, Tip: w.Chain, Utxos: w.Chain, NetworkID: w.Network, Pipeline: w.Pipeline()},
		Certs: w.Ledger, Builder: w.Ledger, AllowUnverified: true}
	refusedWhenMisbehaving(t, w, witnessMisbehaviour, func() error {
		_, err := uc.Run(ctx, stake.DelegationRegisterRequest{Delegator: "hw", Payer: "hw.payment"})
		return err
	})
	res, err := uc.Run(ctx, stake.DelegationRegisterRequest{Delegator: "hw", Payer: "hw.payment"})
	if err != nil || !res.Submitted {
		t.Fatalf("%+v %v", res, err)
	}
	if n := verifyAgainstShown(t, w, 0, res.TxID, storedKeyHash(t, w, "hw.payment", ports.AddrVKey), storedKeyHash(t, w, "hw", ports.StakingVKey)); n != 2 {
		t.Errorf("%d witnesses", n)
	}
}

// 07b: a pool is retired by its cold key and a payment key, both on a Ledger (and
// on a Keystone); a Trezor has no cold key to begin with.
//
// spec: SPO-07b-EXT-001, SPO-07b-INV-001, SPO-07b-INV-004, SPO-Ptx-EXT-005, SPO-Xparty-INV-012
func TestPoolRetirementWithLedgerColdKey(t *testing.T) {
	for _, dev := range [][2]string{{"Ledger", "8.0.8"}, {"Keystone", "1.7.7"}} {
		ctx := context.Background()
		w := world.New(t)
		w.UseHardware(dev[0], dev[1])
		w.Bodies = world.LegacyInputs{Ledger: w.Ledger}
		w.Chain.Params.PoolRetireMaxEpoch = 18
		account(t, w, "hw", custody.PlaceHardware, 50_000_000)
		if _, err := (poolops.GenerateColdKeys{Store: w.Store, KeyGen: native.SoftwareKeys{}, Hardware: w.Exporter()}).
			Run(ctx, poolops.GenerateColdKeysRequest{Pool: "mypool", Place: custody.PlaceHardware}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(w.Dir, "mypool.pool.json"), []byte(hwPoolDescriptor), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := (poolops.GenerateRetirementCertificate{Store: w.Store, Params: w.Chain, Tip: w.Chain, Certs: w.Ledger, Clock: fixedClock{}}).
			Run(ctx, poolops.RetirementRequest{Pool: "mypool"}); err != nil {
			t.Fatal(err)
		}
		uc := poolops.RetirePool{Store: w.Store, Addresses: w.Ledger, Params: w.Chain, Tip: w.Chain, Utxos: w.Chain, Pipeline: w.Pipeline(),
			PoolCerts: w.Ledger, Clock: fixedClock{}, NetworkID: w.Network}
		refusedWhenMisbehaving(t, w, witnessMisbehaviour, func() error {
			_, err := uc.Run(ctx, poolops.RetireRequest{Pool: "mypool", Payer: "hw.payment"})
			return err
		})
		res, err := uc.Run(ctx, poolops.RetireRequest{Pool: "mypool", Payer: "hw.payment"})
		if err != nil || !res.Submitted {
			t.Fatalf("%s: %+v %v", dev[0], res, err)
		}
		if n := verifyAgainstShown(t, w, 0, res.TxID, storedKeyHash(t, w, "hw.payment", ports.AddrVKey), storedKeyHash(t, w, "mypool", ports.NodeVKey)); n != 2 {
			t.Errorf("%s: %d witnesses", dev[0], n)
		}
	}
}

type fakeCommittee struct {
	member chain.Reading[dgov.CommitteeMember]
}

func (fakeCommittee) Source() chain.Source { return "fake chain" }
func (f fakeCommittee) CommitteeMember(context.Context, dgov.Credential) (chain.Reading[dgov.CommitteeMember], error) {
	return f.member, nil
}
func (f fakeCommittee) CommitteeMemberByHot(context.Context, dgov.Credential) (chain.Reading[dgov.CommitteeMember], error) {
	return f.member, nil
}

func committeeKeys(t *testing.T, w *world.World, cold custody.Placement) {
	t.Helper()
	ctx := context.Background()
	if _, err := (governance.GenerateCommitteeColdKeys{Store: w.Store, Keys: native.SoftwareKeys{}, Hardware: w.Exporter()}).
		Run(ctx, governance.GenerateKeysRequest{Name: "cc", Place: cold, Source: governance.KeysRandom}); err != nil {
		t.Fatal(err)
	}
	if _, err := (governance.GenerateCommitteeHotKeys{Store: w.Store, Keys: native.SoftwareKeys{}, Hardware: w.Exporter()}).
		Run(ctx, governance.GenerateKeysRequest{Name: "hot", Source: governance.KeysRandom}); err != nil {
		t.Fatal(err)
	}
}

// 23c and 23e: a committee cold key and the payment key on a Ledger (or a
// Keystone) authorise a hot key and later resign.
//
// spec: SPO-23c-INV-006, SPO-23c-EXT-001, SPO-23e-EXT-001, SPO-23e-EXT-002, SPO-Ptx-EXT-005, SPO-Xparty-INV-012
func TestCommitteeAuthorizationAndResignationOnDevice(t *testing.T) {
	for _, dev := range [][2]string{{"Ledger", "8.0.8"}, {"Keystone", "1.7.7"}} {
		ctx := context.Background()
		w := world.New(t)
		w.UseHardware(dev[0], dev[1])
		w.Bodies = world.LegacyInputs{Ledger: w.Ledger}
		account(t, w, "hw", custody.PlaceHardware, 50_000_000)
		committeeKeys(t, w, custody.PlaceHardware)
		base := govBase(w)

		auth := governance.AuthorizeCommitteeHotKey{Base: base, Certs: w.Ledger, Committee: fakeCommittee{member: chain.None[dgov.CommitteeMember]()}}
		refusedWhenMisbehaving(t, w, witnessMisbehaviour, func() error {
			_, err := auth.Run(ctx, governance.AuthorizeRequest{Cold: "cc", Hot: "hot", Payer: "hw.payment"})
			return err
		})
		res, err := auth.Run(ctx, governance.AuthorizeRequest{Cold: "cc", Hot: "hot", Payer: "hw.payment"})
		if err != nil || !res.Submitted {
			t.Fatalf("%s authorise: %+v %v", dev[0], res, err)
		}
		if n := verifyAgainstShown(t, w, 0, res.TxID, storedKeyHash(t, w, "hw.payment", ports.AddrVKey), storedKeyHash(t, w, "cc", ports.CCColdVKey)); n != 2 {
			t.Errorf("%s authorise: %d witnesses", dev[0], n)
		}

		member := chain.Value(dgov.CommitteeMember{Auth: dgov.HotAuthorized})
		resign := governance.ResignCommitteeColdKey{Base: base, Certs: w.Ledger, Committee: fakeCommittee{member: member}}
		refusedWhenMisbehaving(t, w, witnessMisbehaviour, func() error {
			_, err := resign.Run(ctx, governance.ResignRequest{Cold: "cc", Payer: "hw.payment"})
			return err
		})
		res, err = resign.Run(ctx, governance.ResignRequest{Cold: "cc", Payer: "hw.payment"})
		if err != nil || !res.Submitted {
			t.Fatalf("%s resign: %+v %v", dev[0], res, err)
		}
		if n := verifyAgainstShown(t, w, 1, res.TxID, storedKeyHash(t, w, "hw.payment", ports.AddrVKey), storedKeyHash(t, w, "cc", ports.CCColdVKey)); n != 2 {
			t.Errorf("%s resign: %d witnesses", dev[0], n)
		}
	}
	// A Trezor has no committee cold key: refused before the device is asked.
	w := world.New(t)
	w.UseHardware("Ledger", "8.0.8")
	account(t, w, "hw", custody.PlaceHardware, 50_000_000)
	committeeKeys(t, w, custody.PlaceHardware)
	hw := w.UseHardware("Trezor", "2.7.2")
	hw.Lazy.Profile()
	before := hw.Prompts()
	_, err := (governance.ResignCommitteeColdKey{Base: govBase(w), Certs: w.Ledger, Committee: fakeCommittee{member: chain.Value(dgov.CommitteeMember{})}}).
		Run(context.Background(), governance.ResignRequest{Cold: "cc", Payer: "hw.payment"})
	var ue *custody.UnsupportedError
	if !errors.As(err, &ue) || hw.Prompts() != before || len(w.Chain.Submitted) != 0 {
		t.Errorf("trezor: %v (%d prompts)", err, hw.Prompts()-before)
	}
}

// 11a: a token is minted with the policy key and the payment key on a Ledger; the
// policy id the device gave is the one in the transaction.
//
// spec: SPO-11a-EXT-002, SPO-10-EXT-005, SPO-Ptx-EXT-005, SPO-Xparty-INV-012
func TestMintWithLedgerPolicyKey(t *testing.T) {
	ctx := context.Background()
	w := world.New(t)
	w.UseHardware("Ledger", "8.0.8")
	w.Bodies = world.LegacyInputs{Ledger: w.Ledger}
	account(t, w, "hw", custody.PlaceHardware, 50_000_000)
	pol, err := (assets.GeneratePolicy{Store: w.Store, KeyGen: native.SoftwareKeys{}, Policies: w.Ledger, Hardware: w.Exporter(), PolicyIDer: w.HW.Lazy}).
		Run(ctx, assets.GeneratePolicyRequest{Name: "pol", Place: custody.PlaceHardware})
	if err != nil {
		t.Fatal(err)
	}
	uc := assets.MintAsset{Base: assets.Base{Store: w.Store, Signers: w.Signers(), Utxos: w.Chain, Params: w.Chain, Tip: w.Chain, Addresses: w.Ledger,
		Policies: w.Ledger, Min: w.Ledger, Fees: w.Ledger, Bodies: w.Bodies, Assembler: w.Ledger, Confirmer: w.Conf, Submitter: w.Chain,
		Clock: fixedClock{}, NetworkID: w.Network, Canonicalizer: w.Canonicalizer()}}
	refusedWhenMisbehaving(t, w, witnessMisbehaviour, func() error {
		_, err := uc.Run(ctx, assets.Request{Asset: "pol.token", Amount: "10", Payer: "hw.payment"})
		return err
	})
	res, err := uc.Run(ctx, assets.Request{Asset: "pol.token", Amount: "10", Payer: "hw.payment"})
	if err != nil || !res.Submitted || res.PolicyID != pol.PolicyID {
		t.Fatalf("%+v %v", res, err)
	}
	if n := verifyAgainstShown(t, w, 0, res.TxID, storedKeyHash(t, w, "hw.payment", ports.AddrVKey), storedKeyHash(t, w, "pol", ports.PolicyVKey)); n != 2 {
		t.Errorf("%d witnesses", n)
	}
}

// 01 send assets: native assets are sent from a hardware payment key.
//
// spec: SPO-01sendAssets-EXT-003, SPO-Ptx-EXT-005, SPO-Xparty-INV-012
func TestSendAssetsFromLedger(t *testing.T) {
	ctx := context.Background()
	w := world.New(t)
	w.UseHardware("Ledger", "8.0.8")
	w.Bodies = world.LegacyInputs{Ledger: w.Ledger}
	src := account(t, w, "hw", custody.PlaceHardware, 0)
	account(t, w, "dst", custody.PlaceVault, 0)
	var pid [28]byte
	pid[0] = 7
	var txid chain.TxID
	txid[0] = 0x42
	w.Chain.Funds[src.PaymentAddress] = []chain.Utxo{{TxID: txid, Lovelace: 20_000_000, Assets: []chain.AssetAmount{{Asset: chain.AssetID{Policy: pid, Name: []byte("tok")}, Quantity: 100}}}}
	sels, err := dassets.ParseSelections("ALLASSETS", "")
	if err != nil {
		t.Fatal(err)
	}
	uc := wallet.SendAssets{Store: w.Store, Signers: w.Signers(), Utxos: w.Chain, Params: w.Chain, Tip: w.Chain, Addresses: w.Ledger, Min: w.Ledger, Fees: w.Ledger,
		Bodies: w.Bodies, Assembler: w.Ledger, Confirmer: w.Conf, Submitter: w.Chain, NetworkID: w.Network, Canonicalizer: w.Canonicalizer()}
	req := wallet.SendAssetsRequest{Source: "hw.payment", Destination: "dst.payment", Selections: sels}
	refusedWhenMisbehaving(t, w, witnessMisbehaviour, func() error { _, err := uc.Run(ctx, req); return err })
	res, err := uc.Run(ctx, req)
	if err != nil || !res.Submitted || len(res.Sent) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if n := verifyAgainstShown(t, w, 0, res.TxID, storedKeyHash(t, w, "hw.payment", ports.AddrVKey)); n != 1 {
		t.Errorf("%d witnesses", n)
	}
}

// 01 claim rewards: the rewards are withdrawn with the payment and stake keys on a Ledger.
//
// spec: SPO-01claimRewards-INV-014, SPO-01claimRewards-INV-003, SPO-Ptx-EXT-005, SPO-Xparty-INV-012
func TestClaimRewardsOnLedger(t *testing.T) {
	ctx := context.Background()
	w := world.New(t)
	w.UseHardware("Ledger", "8.0.8")
	w.Bodies = world.LegacyInputs{Ledger: w.Ledger}
	account(t, w, "hw", custody.PlaceHardware, 50_000_000)
	uc := wallet.ClaimRewards{Store: w.Store, Signers: w.Signers(), Utxos: w.Chain, Params: w.Chain, Tip: w.Chain, Addresses: w.Ledger, Min: w.Ledger, Fees: w.Ledger,
		Bodies: w.Bodies, Assembler: w.Ledger, Confirmer: w.Conf, Rewards: accountReader{deposit: 2_000_000, withdraw: 7_000_000, voteDeleg: true}, Submitter: w.Chain,
		NetworkID: w.Network, Canonicalizer: w.Canonicalizer()}
	req := wallet.ClaimRequest{Stake: "hw", Destination: "hw.payment", Payer: "hw.payment"}
	refusedWhenMisbehaving(t, w, witnessMisbehaviour, func() error { _, err := uc.Run(ctx, req); return err })
	res, err := uc.Run(ctx, req)
	if err != nil || !res.Submitted || res.Withdrawn != 7_000_000 {
		t.Fatalf("%+v %v", res, err)
	}
	if n := verifyAgainstShown(t, w, 0, res.TxID, storedKeyHash(t, w, "hw.payment", ports.AddrVKey), storedKeyHash(t, w, "hw", ports.StakingVKey)); n != 2 {
		t.Errorf("%d witnesses", n)
	}
	_ = strings.Contains
	_ = ports.NetworkTestnet
}
