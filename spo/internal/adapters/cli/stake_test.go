package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/stake"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

type stakeParams struct{}

func (stakeParams) Source() chain.Source { return "fake params" }
func (stakeParams) ProtocolParameters(context.Context) (chain.ProtocolParameters, error) {
	return chain.ProtocolParameters{TxFeePerByte: 44, TxFeeFixed: 155381, CoinsPerUTxOByte: 4310, StakeAddressDeposit: 2_000_000,
		MaxTxSize: 16384, MaxValueSize: 5000, ProtocolMajor: 10}, nil
}

// fakeRewards answers every stake address with one reading and counts asks.
type fakeRewards struct {
	name  chain.Source
	r     chain.Reading[chain.RewardAccount]
	calls int
}

func (f *fakeRewards) Source() chain.Source { return f.name }
func (f *fakeRewards) RewardAccount(context.Context, chain.StakeAddress) (chain.Reading[chain.RewardAccount], error) {
	f.calls++
	return f.r, nil
}

func registered(balance chain.Lovelace) chain.Reading[chain.RewardAccount] {
	return chain.Value(chain.RewardAccount{
		DelegatedPool: chain.None[chain.PoolID](), VoteDelegation: chain.Value("drep_always_abstain"),
		Withdrawable: balance, Deposit: chain.Value(chain.Lovelace(2_000_000)),
		GovActionDeposits: chain.Value([]chain.GovActionDeposit{}),
	})
}

type fakePools struct {
	r chain.Reading[chain.PoolState]
}

func (fakePools) Source() chain.Source { return "fake pools" }
func (f fakePools) PoolState(context.Context, chain.PoolID) (chain.Reading[chain.PoolState], error) {
	return f.r, nil
}

// stakeFix is an upstream-layout workspace with an Env whose readers the test
// sets before it runs.
type stakeFix struct {
	*sendFixture
	rewards, cross ports.RewardAccountReader
	pools          ports.PoolStateReader
	dreps          ports.DRepStateReader
	// absent removes capabilities, with a reason.
	absent map[Cap]string
}

func newStakeFix(t *testing.T) *stakeFix {
	t.Helper()
	f := &stakeFix{sendFixture: newSendFixture(t), absent: map[Cap]string{}}
	f.deps.Wire = func(st ports.Store, o WireOptions) (*Env, error) {
		led := native.Ledger{}
		soft := native.SoftwareKeys{}
		env := &Env{Mode: o.Mode, NetworkID: ports.NetworkTestnet, Clock: cliClock{},
			AddressInspector: led, MinOutputCalculator: led, FeeEstimator: led, TxBodyBuilder: led, TxAssembler: led,
			Addresses: led, Certs: led, CertDecoder: led, PaymentKeys: soft, StakeKeys: soft,
			Genesis: cliGenesis{}, Tip: cliTip{}, Params: stakeParams{}, Utxos: fakeUtxos{}, Queue: f.queue,
			Rewards: f.rewards, CrossCheck: f.cross, Pools: f.pools, DReps: f.dreps}
		var v ports.Vault
		if st != nil {
			v = st.(ports.Vault)
		}
		env.Signers = native.Signers{Vault: v}
		env.Absent(CapSubmit, "offline mode has no transaction submitter; queue to a transfer file instead")
		for c, why := range f.absent {
			switch c {
			case CapCerts:
				env.Certs = nil
			case CapCertDecode:
				env.CertDecoder = nil
			case CapRewards:
				env.Rewards = nil
			}
			env.Absent(c, why)
		}
		return env, nil
	}
	return f
}

// newWallet makes wallet s with a stake key through the command itself.
func (f *stakeFix) newWallet(t *testing.T) {
	t.Helper()
	if err := f.run(t, &scriptTerm{t: t}, "wallet", "new", "s", "--stake"); err != nil {
		t.Fatal(err)
	}
	f.out.Reset()
}

func (f *stakeFix) has(name string) bool {
	_, err := os.Stat(filepath.Join(f.dir, name))
	return err == nil
}

func (f *stakeFix) queued(t *testing.T, n int) {
	t.Helper()
	if len(f.queue.got) != n {
		t.Fatalf("queued %d transactions, want %d\n%s", len(f.queue.got), n, f.out.String())
	}
}

func mustContain(t *testing.T, out string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in:\n%s", w, out)
		}
	}
}

const poolHex = "abababababababababababababababababababababababababababab"

// Registration: the policy flag reaches the use case only when given; the
// refusal names it; a decline queues nothing and stores no certificate.
func TestStakeRegisterFlagsAndRefusals(t *testing.T) {
	f := newStakeFix(t)
	f.newWallet(t)
	f.rewards = &fakeRewards{name: "fake rewards", r: chain.Unknown[chain.RewardAccount]("not in the file")}

	err := f.run(t, &scriptTerm{t: t}, "stake", "register", "s", "s.payment", "--yes")
	if err == nil || !errors.Is(err, stake.ErrNoChainReader) && !strings.Contains(err.Error(), "--allow-unverified") {
		t.Fatalf("an unknown answer without the flag: %v", err)
	}
	if !strings.Contains(err.Error(), "--allow-unverified") {
		t.Errorf("the refusal does not name the flag: %v", err)
	}
	f.queued(t, 0)
	if f.has("s.staking.cert") {
		t.Error("a certificate was stored by a refused run")
	}

	// Declined: nothing queued, no certificate.
	term := &scriptTerm{t: t, lines: []string{"n"}}
	err = f.run(t, term, "stake", "register", "s", "s.payment", "--allow-unverified", "--message", "one", "--message", "two")
	if !errors.Is(err, stake.ErrDeclined) || !strings.Contains(err.Error(), "nothing was signed") {
		t.Fatalf("declined: %v", err)
	}
	f.queued(t, 0)
	if f.has("s.staking.cert") {
		t.Error("a declined run stored the certificate")
	}
	out := f.out.String()
	mustContain(t, out, "Stake registration", "account      s", "stake addr   stake_test", "deposit      2.000000 ADA", "message      one", "message      two", "NOT CHECKED")
	f.out.Reset()

	// Given the flag and --yes: queued, summary lists the skipped check.
	if err := f.run(t, &scriptTerm{t: t}, "stake", "register", "s", "s.payment", "--yes", "--allow-unverified"); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	f.queued(t, 1)
	id := f.queue.got[0].Tx.ID.String()
	mustContain(t, f.out.String(), "NOT CHECKED", "Queued transaction "+id, "Stored s.staking.cert")
	if !f.has("s.staking.cert") {
		t.Error("no certificate stored after queueing")
	}
}

func TestStakeRegisterCheckedWhenTheChainSays(t *testing.T) {
	f := newStakeFix(t)
	f.newWallet(t)
	f.rewards = &fakeRewards{name: "fake rewards", r: chain.None[chain.RewardAccount]()}
	if err := f.run(t, &scriptTerm{t: t}, "stake", "register", "s", "s.payment", "--yes"); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	out := f.out.String()
	mustContain(t, out, "checked via  fake rewards")
	if strings.Contains(out, "NOT CHECKED") {
		t.Errorf("a made check is listed as skipped:\n%s", out)
	}
	// Registered already: refused by the use case.
	f2 := newStakeFix(t)
	f2.newWallet(t)
	f2.rewards = &fakeRewards{name: "fake rewards", r: registered(0)}
	if err := f2.run(t, &scriptTerm{t: t}, "stake", "register", "s", "s.payment", "--yes"); err == nil {
		t.Error("registered an address that is registered")
	}
	f2.queued(t, 0)
}

// ADR 0008: every missing capability, listed once, before any prompt.
func TestStakeCommandsListEveryMissingCapabilityBeforeAnyPrompt(t *testing.T) {
	f := newStakeFix(t)
	f.absent[CapCerts] = "no certificate encoder"
	f.absent[CapCertDecode] = "no certificate decoder"
	f.absent[CapRewards] = "no reward reader"
	for _, args := range [][]string{
		{"stake", "deregister", "s", "s.payment"},
		{"stake", "register", "s", "s.payment"},
		{"stake", "status", "s"},
		{"wallet", "claim-rewards", "s", sendTo},
	} {
		d := f.deps
		d.Terminal = failTerm{t}
		d.OpenUpstream = func(string) (ports.Store, error) {
			t.Error("the workspace was opened before the needs were checked")
			return nil, errors.New("opened")
		}
		root := NewRoot(d)
		root.SetArgs(append([]string{"--upstream-layout", "-C", f.dir}, args...))
		err := root.ExecuteContext(context.Background())
		if err == nil {
			t.Fatalf("%v ran without its needs", args)
		}
		msg := err.Error()
		var want []string
		switch args[1] {
		case "deregister":
			want = []string{"certificate-building: no certificate encoder", "certificate-decoding: no certificate decoder", "reward-account: no reward reader"}
		case "register":
			want = []string{"certificate-building: no certificate encoder"}
		default:
			want = []string{"reward-account: no reward reader"}
		}
		mustContain(t, msg, want...)
		if args[1] == "register" && strings.Contains(msg, "reward-account") {
			t.Errorf("register lists a need it does not have:\n%s", msg)
		}
	}
	f.queued(t, 0)
}

func TestStakeDelegateFlagsReachTheUseCaseOnlyWhenGiven(t *testing.T) {
	f := newStakeFix(t)
	f.newWallet(t)
	f.rewards = &fakeRewards{name: "fake rewards", r: registered(0)}

	// No pool reader: refused, naming --allow-unverified.
	err := f.run(t, &scriptTerm{t: t}, "stake", "delegate", "s", poolHex, "--yes")
	if err == nil || !strings.Contains(err.Error(), "--allow-unverified") || !errors.Is(err, stake.ErrNoChainReader) {
		t.Fatalf("%v", err)
	}
	f.queued(t, 0)
	// Pool reader with one source: refused, naming --single-source and the risk.
	f.pools = fakePools{r: chain.Value(chain.PoolState{Ticker: "TST"})}
	err = f.run(t, &scriptTerm{t: t}, "stake", "delegate", "s", poolHex, "--yes", "--allow-unverified")
	if err == nil || !strings.Contains(err.Error(), "--single-source") || !strings.Contains(err.Error(), "deposit or the rewards") || !errors.Is(err, stake.ErrSingleSource) {
		t.Fatalf("--allow-unverified must not stand in for --single-source: %v", err)
	}
	f.queued(t, 0)
	f.out.Reset()
	if err := f.run(t, &scriptTerm{t: t}, "stake", "delegate", "s", poolHex, "--yes", "--single-source", "--message", "hi"); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	f.queued(t, 1)
	out := f.out.String()
	mustContain(t, out, "Pool delegation", "WARNING", "ONE source", "message      hi", "Stored s.deleg.cert", "paid by      s.payment")
	if f.queue.got[0].Type != "DelegationCertRegistration" {
		t.Errorf("queue type %q", f.queue.got[0].Type)
	}
}

func TestStakeDelegateInTwoSteps(t *testing.T) {
	f := newStakeFix(t)
	f.newWallet(t)
	f.rewards = &fakeRewards{name: "fake rewards", r: registered(0)}
	f.pools = fakePools{r: chain.Value(chain.PoolState{})}

	// The stored certificate is missing: said, nothing queued.
	err := f.run(t, &scriptTerm{t: t}, "stake", "delegate", "s", "--stored-cert", "--yes", "--single-source")
	if !errors.Is(err, stake.ErrMissingFile) {
		t.Fatalf("%v", err)
	}
	if err := f.run(t, &scriptTerm{t: t}, "stake", "delegation-cert", poolHex, "s"); err != nil {
		t.Fatal(err)
	}
	mustContain(t, f.out.String(), "Stored s.deleg.cert")
	f.queued(t, 0)
	if err := f.run(t, &scriptTerm{t: t}, "stake", "delegate", "s", "--stored-cert", "--yes", "--single-source"); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	f.queued(t, 1)
	// A pool and --stored-cert together are a usage error.
	if err := f.run(t, &scriptTerm{t: t}, "stake", "delegate", "s", poolHex, "--stored-cert"); err == nil {
		t.Error("accepted a pool with --stored-cert")
	}
}

func TestStakeVoteDelegate(t *testing.T) {
	f := newStakeFix(t)
	f.newWallet(t)
	f.rewards = &fakeRewards{name: "fake rewards", r: registered(0)}
	if err := f.run(t, &scriptTerm{t: t}, "stake", "vote-delegate", "s", "always-abstain", "--yes", "--payer", "s.payment"); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	f.queued(t, 1)
	mustContain(t, f.out.String(), "Vote delegation", "Stored s.vote-deleg.cert")
}

// Deregistration rests on one read: refused without a second source or
// --single-source; a second agreeing source needs no flag.
func TestStakeDeregisterSources(t *testing.T) {
	f := newStakeFix(t)
	f.newWallet(t)
	f.rewards = &fakeRewards{name: "fake rewards", r: registered(0)}
	err := f.run(t, &scriptTerm{t: t}, "stake", "deregister", "s", "s.payment", "--yes")
	if !errors.Is(err, stake.ErrSingleSource) || !strings.Contains(err.Error(), "--single-source") || !strings.Contains(err.Error(), "deposit or the rewards") {
		t.Fatalf("%v", err)
	}
	f.queued(t, 0)
	if f.has("s.staking.dereg-cert") {
		t.Error("a certificate was stored by a refused run")
	}
	// Declined at the prompt.
	err = f.run(t, &scriptTerm{t: t, lines: []string{"no"}}, "stake", "deregister", "s", "s.payment", "--single-source")
	if !errors.Is(err, stake.ErrDeclined) {
		t.Fatalf("%v", err)
	}
	f.queued(t, 0)
	mustContain(t, f.out.String(), "Stake deregistration", "refund       2.000000 ADA", "WARNING")
	f.out.Reset()
	if err := f.run(t, &scriptTerm{t: t}, "stake", "deregister", "s", "s.payment", "--yes", "--single-source"); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	f.queued(t, 1)
	mustContain(t, f.out.String(), "Stored s.staking.dereg-cert", "WARNING")

	// Two agreeing sources: no flag.
	g := newStakeFix(t)
	g.newWallet(t)
	g.rewards = &fakeRewards{name: "first", r: registered(0)}
	g.cross = &fakeRewards{name: "second", r: registered(0)}
	if err := g.run(t, &scriptTerm{t: t}, "stake", "deregister", "s", "s.payment", "--yes"); err != nil {
		t.Fatalf("%v\n%s", err, g.out.String())
	}
	g.queued(t, 1)
	out := g.out.String()
	mustContain(t, out, "checked via  first, second")
	if strings.Contains(out, "WARNING") {
		t.Errorf("a corroborated read is called single-source:\n%s", out)
	}
}

func TestClaimRewards(t *testing.T) {
	f := newStakeFix(t)
	f.newWallet(t)
	f.rewards = &fakeRewards{name: "fake rewards", r: registered(7_000_000)}
	err := f.run(t, &scriptTerm{t: t, lines: []string{""}}, "wallet", "claim-rewards", "s", "s.payment")
	if !errors.Is(err, stake.ErrDeclined) && !strings.Contains(err.Error(), "not approved") {
		t.Fatalf("%v", err)
	}
	f.queued(t, 0)
	mustContain(t, f.out.String(), "Rewards withdrawal", "withdrawal   7.000000 ADA", "account      s", "checked via  fake rewards")
	f.out.Reset()
	if err := f.run(t, &scriptTerm{t: t}, "wallet", "claim-rewards", "s", sendTo, "--payer", "s.payment", "--yes", "--message", "m"); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	f.queued(t, 1)
	mustContain(t, f.out.String(), "withdrawal   7.000000 ADA", "message      m", "Queued transaction")
}

func TestStakeStatus(t *testing.T) {
	f := newStakeFix(t)
	f.newWallet(t)
	f.rewards = &fakeRewards{name: "fake rewards", r: registered(3_000_000)}
	if err := f.run(t, &scriptTerm{t: t}, "stake", "status", "s"); err != nil {
		t.Fatal(err)
	}
	out := f.out.String()
	mustContain(t, out, "registered    yes [fake rewards]", "rewards       3.000000 ADA (3000000 lovelace) [fake rewards]", "not delegated [fake rewards]", "drep_always_abstain [fake rewards]")
	f.out.Reset()
	f.rewards = &fakeRewards{name: "fake rewards", r: chain.None[chain.RewardAccount]()}
	err := f.run(t, &scriptTerm{t: t}, "stake", "status", "s")
	if !errors.Is(err, ErrStakeNotRegistered) {
		t.Fatalf("%v", err)
	}
	mustContain(t, f.out.String(), "registered    no [fake rewards]")
	f.rewards = &fakeRewards{name: "fake rewards", r: chain.Unknown[chain.RewardAccount]("no idea")}
	if err := f.run(t, &scriptTerm{t: t}, "stake", "status", "s"); err == nil || errors.Is(err, ErrStakeNotRegistered) {
		t.Errorf("an unknown answer is not 'not registered': %v", err)
	}
}

func TestStakeOutputNeverHoldsKeyMaterial(t *testing.T) {
	f := newStakeFix(t)
	f.newWallet(t)
	f.rewards = &fakeRewards{name: "fake rewards", r: chain.None[chain.RewardAccount]()}
	if err := f.run(t, &scriptTerm{t: t}, "stake", "register", "s", "s.payment", "--yes"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"cborHex", "SigningKey", ".skey"} {
		if strings.Contains(f.out.String(), bad) {
			t.Errorf("output holds %q:\n%s", bad, f.out.String())
		}
	}
}
