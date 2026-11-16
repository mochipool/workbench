package cli

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/governance"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	dgov "github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ---- fakes -----------------------------------------------------------------------------

type govParams struct{}

func (govParams) Source() chain.Source { return "fake params" }
func (govParams) ProtocolParameters(context.Context) (chain.ProtocolParameters, error) {
	return chain.ProtocolParameters{TxFeePerByte: 44, TxFeeFixed: 155381, CoinsPerUTxOByte: 4310, StakeAddressDeposit: 2_000_000,
		DRepDeposit: 5_000_000, GovActionDeposit: 10_000_000, MaxTxSize: 16384, MaxValueSize: 5000, ProtocolMajor: 10,
		Raw: []byte(`{"dRepVotingThresholds":{},"poolVotingThresholds":{},"committeeMaxTermLength":146}`)}, nil
}

type fakeDReps struct {
	name  chain.Source
	r     chain.Reading[chain.DRepState]
	calls int
}

func (f *fakeDReps) Source() chain.Source { return f.name }
func (f *fakeDReps) DRepState(context.Context, chain.DRepID) (chain.Reading[chain.DRepState], error) {
	f.calls++
	return f.r, nil
}

type fakeCommittee struct {
	r chain.Reading[dgov.CommitteeMember]
}

func (fakeCommittee) Source() chain.Source { return "fake committee" }
func (f fakeCommittee) CommitteeMember(context.Context, dgov.Credential) (chain.Reading[dgov.CommitteeMember], error) {
	return f.r, nil
}
func (f fakeCommittee) CommitteeMemberByHot(context.Context, dgov.Credential) (chain.Reading[dgov.CommitteeMember], error) {
	return chain.None[dgov.CommitteeMember](), nil
}

type fakeGovActions struct{ list []dgov.ActionState }

func (fakeGovActions) Source() chain.Source { return "fake gov-state" }
func (f fakeGovActions) GovActions(context.Context, *dgov.ActionID) (chain.Reading[[]dgov.ActionState], error) {
	return chain.Value(f.list), nil
}

type fakeEpoch struct{}

func (fakeEpoch) Source() chain.Source                  { return "fake epoch" }
func (fakeEpoch) Epoch(context.Context) (uint64, error) { return 500, nil }

type fakeConstitution struct{}

func (fakeConstitution) Source() chain.Source { return "fake constitution" }
func (fakeConstitution) Constitution(context.Context) (chain.Reading[dgov.Constitution], error) {
	return chain.Value(dgov.Constitution{}), nil
}

type fakeLastEnacted struct{}

func (fakeLastEnacted) Source() chain.Source { return "fake last-enacted" }
func (fakeLastEnacted) LastEnacted(context.Context, dgov.Purpose) (chain.Reading[dgov.ActionID], error) {
	return chain.None[dgov.ActionID](), nil
}

type fakeDist struct{}

func (fakeDist) Source() chain.Source { return "fake distribution" }
func (fakeDist) DRepDistribution(context.Context) (chain.Reading[dgov.DRepDistribution], error) {
	return chain.Value(dgov.DRepDistribution{Active: map[dgov.Credential]chain.Lovelace{}}), nil
}
func (fakeDist) PoolDistribution(context.Context) (chain.Reading[[]dgov.PoolStake], error) {
	return chain.Value([]dgov.PoolStake{}), nil
}
func (fakeDist) CommitteeComposition(context.Context) (chain.Reading[dgov.CommitteeComposition], error) {
	return chain.Value(dgov.CommitteeComposition{ActiveHot: map[dgov.Credential]bool{}}), nil
}

type fakeSummaries struct{}

func (fakeSummaries) Source() chain.Source { return "fake summary" }
func (fakeSummaries) VotingSummary(context.Context, dgov.ActionID) (chain.Reading[dgov.VotingSummary], error) {
	return chain.Value(dgov.VotingSummary{DRepYes: 7000, PoolYes: 5500, CommitteeYes: 8000}), nil
}
func (fakeSummaries) CommitteeThreshold(context.Context) (chain.Reading[chain.Rational], error) {
	return chain.Value(chain.Rational{Num: 2, Den: 3}), nil
}

// paramChangeMapped is what the composition root does with the native adapter:
// the sentinel of an unbuilt parameter-change file becomes the port's.
type paramChangeMapped struct{ ports.ActionFileBuilder }

func (a paramChangeMapped) BuildActionFile(act dgov.Action) (ports.ActionFile, error) {
	f, err := a.ActionFileBuilder.BuildActionFile(act)
	if errors.Is(err, native.ErrParameterChangeUnsupported) {
		return f, fmt.Errorf("%w: %w", ports.ErrParameterChangeUnsupported, err)
	}
	return f, err
}

type recSubmit struct{ got [][]byte }

func (*recSubmit) Source() chain.Source { return "fake submitter" }
func (r *recSubmit) Submit(_ context.Context, tx []byte) (chain.TxID, error) {
	r.got = append(r.got, tx)
	return native.Ledger{}.TransactionID(tx)
}

type fakeFetch struct{ doc string }

func (f fakeFetch) Fetch(context.Context, string) ([]byte, error) { return []byte(f.doc), nil }

// govFix is an upstream-layout workspace with wallet w whose Env has every
// governance capability; a test replaces a reader or removes a capability.
type govFix struct {
	*sendFixture
	sub       *recSubmit
	submit    bool // submit through a provider instead of queueing
	dreps     ports.DRepStateReader
	committee ports.CommitteeStateReader
	actions   ports.GovActionReader
	dist      ports.StakeDistributionReader
	summaries ports.VotingSummaryReader
	drepCross ports.DRepStateReader
	rewards   ports.RewardAccountReader
	fetcher   ports.MetadataFetcher
	absent    map[Cap]string
}

const govActionTx = 1

func newGovFix(t *testing.T) *govFix {
	t.Helper()
	f := &govFix{sendFixture: newSendFixture(t), sub: &recSubmit{}, absent: map[Cap]string{}}
	f.actions = fakeGovActions{list: []dgov.ActionState{{ID: dgov.ActionID{TxID: chain.TxID{govActionTx}, Index: 1}, Kind: dgov.InfoAction,
		ExpiresAfter: 600, Security: chain.Unknown[bool]("not stated")}}}
	f.dist = fakeDist{}
	// A provider that submits is light mode; queueing is offline mode.
	load := f.deps.Config.Load
	f.deps.Config.Load = func(dir string) (WorkspaceConfig, error) {
		c, err := load(dir)
		if f.submit {
			c.Mode = ModeLight
		}
		return c, err
	}
	f.deps.Wire = func(st ports.Store, o WireOptions) (*Env, error) {
		led := native.Ledger{}
		soft := native.SoftwareKeys{}
		env := &Env{Mode: o.Mode, NetworkID: ports.NetworkTestnet, Clock: cliClock{},
			AddressInspector: led, MinOutputCalculator: led, FeeEstimator: led, TxBodyBuilder: led, TxAssembler: led,
			Addresses: led, Certs: led, CertDecoder: led, PaymentKeys: soft, StakeKeys: soft, Mnemonics: soft, WalletDeriver: soft,
			DRepKeys: soft, ComColdKeys: soft, ComHotKeys: soft, GovDeriver: soft, VoteFiles: led, ActionFiles: paramChangeMapped{led},
			Genesis: cliGenesis{}, Tip: cliTip{}, Params: govParams{}, Utxos: fakeUtxos{},
			DReps: f.dreps, Committee: f.committee, GovActions: f.actions, StakeDists: f.dist, Summaries: f.summaries, DRepCross: f.drepCross, Rewards: f.rewards,
			Constitution: fakeConstitution{}, LastEnacted: fakeLastEnacted{}, Epochs: fakeEpoch{}, AnchorFetcher: f.fetcher}
		if f.submit {
			env.Submitter = f.sub
			env.Absent(CapQueue, "light mode submits through the provider")
		} else {
			env.Queue = f.queue
			env.Absent(CapSubmit, "offline mode has no transaction submitter; queue to a transfer file instead")
		}
		var v ports.Vault
		if st != nil {
			v = st.(ports.Vault)
		}
		env.Signers = native.Signers{Vault: v}
		env.Absent(CapAnchorVerify, "no verifier is built")
		for c, why := range f.absent {
			switch c {
			case CapCerts:
				env.Certs = nil
			case CapDReps:
				env.DReps = nil
			case CapCommittee:
				env.Committee = nil
			case CapGovActions:
				env.GovActions = nil
			case CapStakeDist:
				env.StakeDists = nil
			case CapVotingSummary:
				env.Summaries = nil
			case CapEpoch:
				env.Epochs = nil
			case CapConstitution:
				env.Constitution = nil
			case CapLastEnacted:
				env.LastEnacted = nil
			case CapVoteFiles:
				env.VoteFiles = nil
			case CapActionFiles:
				env.ActionFiles = nil
			case CapGovDeriver:
				env.GovDeriver = nil
			}
			env.Absent(c, why)
		}
		return env, nil
	}
	return f
}

func (f *govFix) cmd(t *testing.T, lines []string, args ...string) (string, error) {
	t.Helper()
	f.out.Reset()
	err := f.run(t, &scriptTerm{t: t, lines: lines}, args...)
	return f.out.String(), err
}

func (f *govFix) must(t *testing.T, args ...string) string {
	t.Helper()
	out, err := f.cmd(t, nil, args...)
	if err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return out
}

func (f *govFix) has(name string) bool {
	_, err := os.Stat(filepath.Join(f.dir, name))
	return err == nil
}

func (f *govFix) glob(t *testing.T, pattern string) string {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(f.dir, pattern))
	if len(m) != 1 {
		t.Fatalf("%s matches %v", pattern, m)
	}
	return filepath.Base(m[0])
}

func (f *govFix) queuedN(t *testing.T, n int) {
	t.Helper()
	if got := len(f.queue.got) + len(f.sub.got); got != n {
		t.Fatalf("queued or submitted %d transactions, want %d\n%s", got, n, f.out.String())
	}
}

func govNoKeys(t *testing.T, f *govFix, out string) {
	t.Helper()
	for _, bad := range []string{hex.EncodeToString(f.seed), "SigningKey", "cborHex", ".skey", "abandon "} {
		if strings.Contains(out, bad) {
			t.Errorf("output holds key material %q:\n%s", bad, out)
		}
	}
}

func registeredDRep(deposit chain.Lovelace, url string) chain.Reading[chain.DRepState] {
	return chain.Value(chain.DRepState{Deposit: deposit, AnchorURL: url, AnchorHash: strings.Repeat("ab", 32)})
}

const govHash = "5555555555555555555555555555555555555555555555555555555555555555"
const govURL = "https://example.com/doc.json"

// stakeAddr is a testnet stake address (key credential) for the deposit return.
func stakeAddr() string { return bech32("stake_test", append([]byte{0xe0}, make([]byte, 28)...)) }

// ---- keys ---------------------------------------------------------------------------------

func TestGovernanceKeyCommandsStoreFilesAndShowNoKeyMaterial(t *testing.T) {
	f := newGovFix(t)
	out := f.must(t, "drep", "keys", "generate", "d")
	mustContain(t, out, "Generated the DRep keys of d", "drep1")
	for _, n := range []string{"d.drep.vkey", "d.drep.skey", "d.drep.id"} {
		if !f.has(n) {
			t.Errorf("no %s", n)
		}
	}
	govNoKeys(t, f, out)
	if _, err := f.cmd(t, nil, "drep", "keys", "generate", "d"); err == nil || !errors.Is(err, governance.ErrExists) {
		t.Errorf("a second generation must be refused: %v", err)
	}

	f.must(t, "committee", "keys", "generate-cold", "c")
	out = f.must(t, "committee", "keys", "generate-hot", "h")
	mustContain(t, out, "committee hot keys of h", "cc_hot1")
	if _, err := f.cmd(t, nil, "committee", "keys", "generate-hot", "h"); !errors.Is(err, governance.ErrExists) {
		t.Errorf("an existing hot key is refused without --replace: %v", err)
	}
	before, _ := os.ReadFile(filepath.Join(f.dir, "h.cc-hot.vkey"))
	f.must(t, "committee", "keys", "generate-hot", "h", "--replace")
	if after, _ := os.ReadFile(filepath.Join(f.dir, "h.cc-hot.vkey")); string(after) == string(before) {
		t.Error("--replace kept the old key")
	}
	// --replace belongs to the hot key only.
	if _, err := f.cmd(t, nil, "committee", "keys", "generate-cold", "c", "--replace"); err == nil {
		t.Error("--replace was accepted for a cold key")
	}

	// A mnemonic key: the phrase is stored and not shown.
	out = f.must(t, "drep", "keys", "generate", "m", "--mnemonic", "--account", "2", "--index", "3")
	mustContain(t, out, "recovery phrase was generated", "not shown")
	govNoKeys(t, f, out)
	if !f.has("m.drep.mnemonics") {
		t.Error("the phrase was not stored")
	}
	// Derivation flags without a mnemonic are refused before the workspace opens.
	d := f.deps
	d.Terminal = failTerm{t}
	d.OpenUpstream = func(string) (ports.Store, error) { t.Error("opened"); return nil, errors.New("opened") }
	root := NewRoot(d)
	root.SetArgs([]string{"--upstream-layout", "-C", f.dir, "drep", "keys", "generate", "x", "--account", "1"})
	if err := root.ExecuteContext(context.Background()); !errors.Is(err, governance.ErrOptionNotUsed) {
		t.Errorf("--account without a mnemonic: %v", err)
	}
	// An absent deriver is a capability refusal naming the reason.
	f.absent[CapGovDeriver] = "no deriver here"
	if _, err := f.cmd(t, nil, "drep", "keys", "generate", "z", "--mnemonic"); err == nil || !strings.Contains(err.Error(), "governance-derivation: no deriver here") {
		t.Errorf("%v", err)
	}
}

// ---- DRep ---------------------------------------------------------------------------------

func TestDRepRegisterFlagsAndRefusals(t *testing.T) {
	f := newGovFix(t)
	f.must(t, "drep", "keys", "generate", "d")
	f.dreps = &fakeDReps{name: "fake dreps", r: chain.None[chain.DRepState]()}

	// An anchor with no verifier is refused until --anchor-unverified, which is never implied.
	for i := 0; i < 2; i++ {
		_, err := f.cmd(t, nil, "drep", "register", "d", "w", "--yes", "--anchor-url", govURL, "--anchor-hash", govHash)
		if !errors.Is(err, governance.ErrAnchorVerifierMissing) || !strings.Contains(err.Error(), "--anchor-unverified") {
			t.Fatalf("%v", err)
		}
	}
	f.queuedN(t, 0)

	// An anchor URL alone: the document cannot be fetched here, so the hash is needed and named.
	out, err := f.cmd(t, nil, "drep", "register", "d", "w", "--yes", "--anchor-unverified", "--anchor-url", govURL)
	if err == nil || !strings.Contains(err.Error(), "--anchor-hash") {
		t.Fatalf("%v\n%s", err, out)
	}
	f.queuedN(t, 0)

	// Declined: nothing queued, no certificate.
	out, err = f.cmd(t, []string{"n"}, "drep", "register", "d", "w", "--anchor-unverified", "--anchor-url", govURL, "--anchor-hash", govHash)
	if !errors.Is(err, governance.ErrDeclined) || !strings.Contains(err.Error(), "nothing was signed") {
		t.Fatalf("declined: %v", err)
	}
	mustContain(t, out, "DRep registration", "account      d", "paid by      w", "deposit      5.000000 ADA", "fee", "valid until",
		"DRep id       drep1", "anchor url   "+govURL, "anchor hash  "+govHash, "NOT CHECKED  the anchor document is not checked against CIP-119", "checked via  fake dreps")
	f.queuedN(t, 0)
	if f.has("d.drep-reg.cert") {
		t.Error("a declined run stored the certificate")
	}

	out = f.must(t, "drep", "register", "d", "w", "--yes", "--anchor-unverified", "--anchor-url", govURL, "--anchor-hash", govHash, "--message", "hi")
	f.queuedN(t, 1)
	// the --yes path prints the same summary as the interactive one, attachments included
	mustContain(t, out, "DRep registration", "message      hi", "attaches     ", "deposit      5.000000 ADA", "Decision: the anchor document was not verified", "Queued transaction "+f.queue.got[0].Tx.ID.String(), "Stored d.drep-reg.cert")
	govNoKeys(t, f, out)
	if !f.has("d.drep-reg.cert") {
		t.Error("no certificate stored after queueing")
	}
}

func TestDRepUpdateClearingTheAnchorNeedsItsFlag(t *testing.T) {
	f := newGovFix(t)
	f.must(t, "drep", "keys", "generate", "d")
	f.dreps = &fakeDReps{name: "fake dreps", r: registeredDRep(5_000_000, govURL)}
	_, err := f.cmd(t, nil, "drep", "register", "d", "w", "--yes")
	if !errors.Is(err, governance.ErrAnchorWouldBeCleared) || !strings.Contains(err.Error(), "--allow-anchor-clear") {
		t.Fatalf("%v", err)
	}
	f.queuedN(t, 0)
	out := f.must(t, "drep", "register", "d", "w", "--yes", "--allow-anchor-clear")
	mustContain(t, out, "DRep update", "Decision: the update clears the anchor")
	f.queuedN(t, 1)
}

func TestDRepRetireSingleSourceIsNeverImplied(t *testing.T) {
	f := newGovFix(t)
	f.must(t, "drep", "keys", "generate", "d")
	f.dreps = &fakeDReps{name: "fake dreps", r: registeredDRep(123_456_789, "")}
	for i := 0; i < 2; i++ { // the second run proves nothing was remembered
		_, err := f.cmd(t, nil, "drep", "retire", "d", "w", "--yes")
		if !errors.Is(err, governance.ErrSingleSource) || !strings.Contains(err.Error(), "--single-source") || !strings.Contains(err.Error(), "cost the deposit") {
			t.Fatalf("%v", err)
		}
	}
	f.queuedN(t, 0)
	out := f.must(t, "drep", "retire", "d", "w", "--yes", "--single-source")
	mustContain(t, out, "DRep retirement", "refund       123.456789 ADA", "WARNING      a read this transaction rests on came from ONE source", "Stored d.drep-ret.cert", "DRep id       drep1")
	f.queuedN(t, 1)
	if !f.has("d.drep-ret.cert") {
		t.Error("no certificate")
	}
}

func TestDRepStatusPrintsStandingAndSource(t *testing.T) {
	f := newGovFix(t)
	f.must(t, "drep", "keys", "generate", "d")
	st := registeredDRep(5_000_000, "")
	f.dreps = &fakeDReps{name: "fake dreps", r: st}
	out := f.must(t, "drep", "status", "d")
	mustContain(t, out, "DRep registered", "source        fake dreps", "epoch         500", "deposit       5.000000 ADA")
	f.dreps = &fakeDReps{name: "fake dreps", r: chain.None[chain.DRepState]()}
	out = f.must(t, "drep", "status", "d")
	mustContain(t, out, "DRep not registered")
}

// Registration, deposit and anchor are reported with no epoch source; the expiry
// is said to be unknown, with the reason, and a stated expiry is shown.
func TestDRepStatusWithoutAnEpochSource(t *testing.T) {
	f := newGovFix(t)
	f.must(t, "drep", "keys", "generate", "d")
	st := chain.DRepState{Deposit: 5_000_000, Expiry: chain.Unknown[uint64]("drep_info states no expires_epoch_no"), DelegatedStake: chain.Value(chain.Lovelace(42_000_000))}
	f.dreps = &fakeDReps{name: "fake dreps", r: chain.Value(st)}
	f.absent[CapEpoch] = "no epoch here"
	out := f.must(t, "drep", "status", "d")
	mustContain(t, out, "DRep registered (expiry not assessed)", "source        fake dreps", "epoch         unknown: no epoch source in this mode",
		"deposit       5.000000 ADA", "expires       unknown: drep_info states no expires_epoch_no", "stake         42.000000 ADA", "anchor        none")
}

// A second DRep-state source (capability drep-state-crosscheck) corroborates the
// refund, so --single-source is not needed; without it the flag stays required.
func TestDRepRetireUsesTheCrossCheckSource(t *testing.T) {
	f := newGovFix(t)
	f.must(t, "drep", "keys", "generate", "d")
	f.dreps = &fakeDReps{name: "fake dreps", r: registeredDRep(123_456_789, "")}
	f.drepCross = &fakeDReps{name: "second dreps", r: registeredDRep(123_456_789, "")}
	out := f.must(t, "drep", "retire", "d", "w", "--yes")
	mustContain(t, out, "DRep retirement", "refund       123.456789 ADA", "checked via  fake dreps, second dreps")
	if strings.Contains(out, "ONE source") {
		t.Errorf("a corroborated read is not single-source:\n%s", out)
	}
	// they disagree: refused
	f.drepCross = &fakeDReps{name: "second dreps", r: registeredDRep(1, "")}
	if _, err := f.cmd(t, nil, "drep", "retire", "d", "w", "--yes"); !errors.Is(err, governance.ErrSourcesDisagree) {
		t.Fatalf("%v", err)
	}
}

// ---- committee ---------------------------------------------------------------------------

func TestCommitteeAuthorizeAndResign(t *testing.T) {
	f := newGovFix(t)
	f.submit = true
	f.must(t, "committee", "keys", "generate-cold", "c")
	f.must(t, "committee", "keys", "generate-hot", "h")
	f.committee = fakeCommittee{r: chain.None[dgov.CommitteeMember]()}
	out := f.must(t, "committee", "authorize", "c", "h", "w", "--yes")
	mustContain(t, out, "Committee hot key authorisation", "account      c", "checked via  fake committee", "cold key hash", "hot key hash", "Submitted transaction", "Stored h.cc-hot.cert")
	if len(f.sub.got) != 1 || !f.has("h.cc-hot.cert") {
		t.Fatalf("submitted %d", len(f.sub.got))
	}
	govNoKeys(t, f, out)

	// Not on chain: resignation has nothing to resign.
	if _, err := f.cmd(t, nil, "committee", "resign", "c", "w", "--yes"); !errors.Is(err, dgov.ErrNotOnChain) {
		t.Fatalf("%v", err)
	}
	f.committee = fakeCommittee{r: chain.Value(dgov.CommitteeMember{Auth: dgov.HotAuthorized, Status: "Active"})}
	if _, err := f.cmd(t, nil, "committee", "resign", "c", "w", "--yes", "--anchor-url", govURL, "--anchor-hash", govHash); !errors.Is(err, governance.ErrAnchorVerifierMissing) || !strings.Contains(err.Error(), "--anchor-unverified") {
		t.Fatalf("an anchor with no verifier: %v", err)
	}
	out = f.must(t, "committee", "resign", "c", "w", "--yes", "--anchor-unverified", "--anchor-url", govURL, "--anchor-hash", govHash)
	mustContain(t, out, "Committee cold key resignation", "anchor url   "+govURL, "NOT CHECKED  the anchor document is not checked against CIP-100", "Stored c.cc-cold-ret.cert")
	if len(f.sub.got) != 2 {
		t.Fatalf("submitted %d", len(f.sub.got))
	}
	out = f.must(t, "committee", "status", "c")
	mustContain(t, out, "Committee credential", "source        fake committee", "cold key of a member", "authorisation MemberAuthorized")
}

func TestCommitteeAuthorizeIsRefusedWhenQueueing(t *testing.T) {
	f := newGovFix(t)
	f.must(t, "committee", "keys", "generate-cold", "c")
	f.must(t, "committee", "keys", "generate-hot", "h")
	f.committee = fakeCommittee{r: chain.None[dgov.CommitteeMember]()}
	_, err := f.cmd(t, nil, "committee", "authorize", "c", "h", "w", "--yes")
	if !errors.Is(err, governance.ErrOfflineUnsupported) || !strings.Contains(err.Error(), "light mode") {
		t.Fatalf("%v", err)
	}
	f.queuedN(t, 0)
}

// ---- votes --------------------------------------------------------------------------------

func TestVoteCreateSubmitAndTheAnchorPolicy(t *testing.T) {
	f := newGovFix(t)
	f.submit = true
	f.must(t, "drep", "keys", "generate", "d")
	id := dgov.ActionID{TxID: chain.TxID{govActionTx}, Index: 1}.Hex()

	// No prompt with an explicit id and decision (the terminal has no lines to give).
	out := f.must(t, "vote", "create", "d", id, "yes")
	mustContain(t, out, "Stored ", ".drep.vote: DRep vote yes on "+id, "Submit them with")
	file := f.glob(t, "d_*.drep.vote")
	govNoKeys(t, f, out)

	// A vote with an anchor and no verifier is refused until --anchor-unverified, which is never implied.
	for i := 0; i < 2; i++ {
		_, err := f.cmd(t, nil, "vote", "create", "d", id, "no", "--anchor-url", govURL, "--anchor-hash", govHash)
		if !errors.Is(err, governance.ErrAnchorVerifierMissing) || !strings.Contains(err.Error(), "--anchor-unverified") ||
			!strings.Contains(err.Error(), "not checked against CIP-100/108/119") {
			t.Fatalf("%v", err)
		}
	}
	out = f.must(t, "vote", "create", "d", id, "abstain", "--anchor-url", govURL, "--anchor-hash", govHash, "--anchor-unverified")
	mustContain(t, out, "NOT CHECKED", "was not checked against CIP-100/108/119", "the hash is recorded as given", "DRep vote abstain")

	// Decision words and `all` mixes are refused up front.
	for _, args := range [][]string{{"vote", "create", "d", id}, {"vote", "create", "d", id, "maybe"}, {"vote", "create", "d", "all", "yes"}} {
		if _, err := f.cmd(t, nil, args...); err == nil {
			t.Errorf("%v was accepted", args)
		}
	}
	// `all` asks per action; the default answer cancels.
	out, err := f.cmd(t, []string{""}, "vote", "create", "d", "all")
	if err != nil {
		t.Fatalf("%v", err)
	}
	mustContain(t, out, "Action "+id, "Cancelled")

	// Submit: the voter comes from the file name; the summary names the vote.
	out, err = f.cmd(t, []string{"n"}, "vote", "submit", "w", file)
	if !errors.Is(err, governance.ErrDeclined) {
		t.Fatalf("%v", err)
	}
	mustContain(t, out, "Vote", "account      d", "attaches     DRep vote yes on "+id, "Details", "DRep vote yes on "+id+" (gov_action1", "anchor none")
	f.queuedN(t, 0)
	out = f.must(t, "vote", "submit", "w", file, "--yes")
	f.queuedN(t, 1)
	mustContain(t, out, "Submitted transaction")
	// --yes prints the same summary as the interactive path, attachments included
	mustContain(t, out, "attaches     DRep vote yes on "+id)
	// A file name that does not say the voter: the signer is not guessed, and --voter names it.
	raw, err := os.ReadFile(filepath.Join(f.dir, file))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "x_250304050607.drep.vote"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.cmd(t, nil, "vote", "submit", "w", "x_250304050607.drep.vote", "--yes"); !errors.Is(err, governance.ErrNoVoterKey) || !strings.Contains(err.Error(), "--voter") {
		t.Errorf("a file name that does not say the voter: %v", err)
	}
	f.queuedN(t, 1)
	f.must(t, "vote", "submit", "w", "x_250304050607.drep.vote", "--voter", "d", "--yes")
	f.queuedN(t, 2)
}

func TestVoteTallyPrintsSourcesAndIsAProjection(t *testing.T) {
	f := newGovFix(t)
	f.submit = true
	out := f.must(t, "vote", "tally")
	mustContain(t, out, "Epoch 500", "Sources: governance state fake gov-state; stake distribution fake distribution; protocol parameters fake params; epoch fake epoch",
		"nothing is decided or gated by it", "Action ", "result     n/a")
}

// In light mode there is no stake distribution: the percentages are the
// provider's own voting summary and the sources line says so.
func TestVoteTallyFromTheProvidersSummary(t *testing.T) {
	f := newGovFix(t)
	f.submit = true
	f.dist, f.summaries = nil, fakeSummaries{}
	out := f.must(t, "vote", "tally")
	mustContain(t, out, "Epoch 500", "percentages are the provider's voting summary fake summary", "nothing is decided or gated by it",
		"Committee  80.00 % yes, threshold 66.66 %", "result     n/a")
	// neither source: one refusal naming both
	f.summaries = nil
	if _, err := f.cmd(t, nil, "vote", "tally"); err == nil || !strings.Contains(err.Error(), "one of stake-distribution, voting-summary") {
		t.Errorf("%v", err)
	}
}

// ---- actions ------------------------------------------------------------------------------

func TestActionCreateAndSubmit(t *testing.T) {
	f := newGovFix(t)
	f.submit = true
	ret := stakeAddr()
	f.rewards = &fakeRewards{name: "fake rewards", r: registered(0)}

	out := f.must(t, "action", "create", "info", ret, "--anchor-url", govURL, "--anchor-hash", govHash)
	mustContain(t, out, "InfoAction proposal", "deposit 10.000000 ADA", "returned to "+ret, "anchor  "+govURL, "Stored ")
	file := f.glob(t, "infoaction_*.action")
	hf := f.must(t, "action", "create", "hard-fork", ret, "--anchor-url", govURL, "--anchor-hash", govHash, "--version", "11")
	mustContain(t, hf, "hard fork to protocol version 11.0")

	// Kind flags of another kind are refused by name.
	if _, err := f.cmd(t, nil, "action", "create", "info", ret, "--anchor-url", govURL, "--anchor-hash", govHash, "--amount", "5"); err == nil || !strings.Contains(err.Error(), "--amount does not apply") {
		t.Errorf("%v", err)
	}
	if _, err := f.cmd(t, nil, "action", "create", "nonsense", ret); err == nil || !strings.Contains(err.Error(), "info, no-confidence") {
		t.Errorf("%v", err)
	}
	// parameter-change: the typed unsupported error, surfaced clearly; nothing written.
	_, err := f.cmd(t, nil, "action", "create", "parameter-change", ret, "--anchor-url", govURL, "--anchor-hash", govHash, "--param", "maxTxSize=20000")
	if !errors.Is(err, governance.ErrParameterChangeUnsupported) || !strings.Contains(err.Error(), "cannot be written yet") || !strings.Contains(err.Error(), "no file was written") {
		t.Errorf("parameter-change: %v", err)
	}

	// Submit: the summary shows the kind, the deposit and the return address.
	out, err = f.cmd(t, []string{"n"}, "action", "submit", "w", file)
	if !errors.Is(err, governance.ErrDeclined) {
		t.Fatalf("%v", err)
	}
	mustContain(t, out, "Governance action proposal", "attaches     InfoAction proposal, deposit 10000000 lovelace", "InfoAction proposal", "returned to "+ret, "checked via  fake rewards")
	f.queuedN(t, 0)
	out = f.must(t, "action", "submit", "w", file, "--yes")
	f.queuedN(t, 1)
	mustContain(t, out, "Proposal 1 will be action ", "Submitted transaction")
	govNoKeys(t, f, out)

	// Guardrails kinds: the use case's typed error, printed exactly.
	f.must(t, "action", "create", "treasury-withdrawal", ret, "--anchor-url", govURL, "--anchor-hash", govHash, "--amount", "1000000")
	tw := f.glob(t, "treasurywithdrawals_*.action")
	_, err = f.cmd(t, nil, "action", "submit", "w", tw, "--yes")
	var ge *governance.GuardrailsError
	if !errors.As(err, &ge) {
		t.Fatalf("%v", err)
	}
	mustContain(t, err.Error(), "TreasuryWithdrawals", "guardrails script", "What is missing", "a collateral UTxO", "execution units", "Nothing was signed")
	f.queuedN(t, 1)
}

// An info action needs no chain reader: it is written with no epoch, constitution
// or last-enacted reader at all (offline, from a snapshot's parameters).
func TestActionCreateInfoNeedsNoChainReader(t *testing.T) {
	f := newGovFix(t)
	for _, c := range []Cap{CapEpoch, CapConstitution, CapLastEnacted, CapGovActions, CapStakeDist} {
		f.absent[c] = "no " + string(c) + " here"
	}
	out := f.must(t, "action", "create", "info", stakeAddr(), "--anchor-url", govURL, "--anchor-hash", govHash)
	mustContain(t, out, "InfoAction proposal", "Stored ")
	if _, err := f.cmd(t, nil, "action", "create", "hard-fork", stakeAddr(), "--anchor-url", govURL, "--anchor-hash", govHash, "--version", "11"); err == nil || !strings.Contains(err.Error(), "last-enacted-action: no last-enacted-action here") {
		t.Errorf("a hard fork needs the last enacted action: %v", err)
	}
}

func TestActionSubmitNamesAllowUnverifiedWhenTheReturnAddressCannotBeChecked(t *testing.T) {
	f := newGovFix(t)
	ret := stakeAddr()
	f.must(t, "action", "create", "info", ret, "--anchor-url", govURL, "--anchor-hash", govHash)
	file := f.glob(t, "infoaction_*.action")
	for i := 0; i < 2; i++ {
		_, err := f.cmd(t, nil, "action", "submit", "w", file, "--yes")
		if err == nil || !strings.Contains(err.Error(), "--allow-unverified") {
			t.Fatalf("%v", err)
		}
	}
	f.queuedN(t, 0)
	out := f.must(t, "action", "submit", "w", file, "--yes", "--allow-unverified")
	mustContain(t, out, "NOT CHECKED", "the registration of "+ret+" was not checked")
	f.queuedN(t, 1)
}

func TestActionCreateAnchorUnverifiedOnlyWhenGiven(t *testing.T) {
	f := newGovFix(t)
	f.fetcher = fakeFetch{doc: `{"body":{"title":"x"}}`}
	ret := stakeAddr()
	for i := 0; i < 2; i++ {
		_, err := f.cmd(t, nil, "action", "create", "info", ret, "--anchor-url", govURL)
		if !errors.Is(err, governance.ErrAnchorVerifierMissing) || !strings.Contains(err.Error(), "--anchor-unverified") {
			t.Fatalf("%v", err)
		}
	}
	out := f.must(t, "action", "create", "info", ret, "--anchor-url", govURL, "--anchor-unverified")
	mustContain(t, out, "NOT CHECKED", "the hash is recorded as given", "Decision: the anchor document was not verified")
}

// ---- needs ------------------------------------------------------------------------------

// ADR 0008: every missing capability, listed once, before any prompt and
// before the workspace is opened.
func TestGovernanceCommandsListEveryMissingCapabilityBeforeAnyPrompt(t *testing.T) {
	f := newGovFix(t)
	reason := func(c Cap) string { return "no " + string(c) + " here" }
	for _, c := range []Cap{CapCerts, CapDReps, CapCommittee, CapGovActions, CapStakeDist, CapVotingSummary, CapEpoch, CapConstitution, CapLastEnacted, CapVoteFiles, CapActionFiles} {
		f.absent[c] = reason(c)
	}
	cases := []struct {
		args    []string
		want    []Cap
		notWant []Cap // not needed by this command (an optional or kind-specific reader)
	}{
		{[]string{"drep", "register", "d", "w"}, []Cap{CapCerts, CapDReps}, nil},
		{[]string{"drep", "retire", "d", "w"}, []Cap{CapCerts, CapDReps}, nil},
		{[]string{"drep", "status", "d"}, []Cap{CapDReps}, []Cap{CapEpoch}},
		{[]string{"committee", "authorize", "c", "h", "w"}, []Cap{CapCerts, CapCommittee}, nil},
		{[]string{"committee", "resign", "c", "w"}, []Cap{CapCerts, CapCommittee}, nil},
		{[]string{"committee", "status", "c"}, []Cap{CapCommittee}, nil},
		{[]string{"vote", "create", "d", "all"}, []Cap{CapGovActions, CapEpoch, CapVoteFiles}, nil},
		{[]string{"vote", "submit", "w", "d_240101000001.drep.vote"}, []Cap{CapVoteFiles}, nil},
		{[]string{"vote", "tally"}, []Cap{CapGovActions, CapEpoch}, nil},
		// each kind asks only for what it reads
		{[]string{"action", "create", "info", "stake_test1x"}, []Cap{CapActionFiles}, []Cap{CapEpoch, CapConstitution, CapLastEnacted}},
		{[]string{"action", "create", "hard-fork", "stake_test1x", "--version", "11"}, []Cap{CapActionFiles, CapLastEnacted}, []Cap{CapEpoch, CapConstitution}},
		{[]string{"action", "create", "treasury-withdrawal", "stake_test1x", "--amount", "1"}, []Cap{CapActionFiles, CapConstitution}, []Cap{CapEpoch, CapLastEnacted}},
		{[]string{"action", "create", "update-committee", "stake_test1x", "--threshold", "2/3"}, []Cap{CapActionFiles, CapEpoch, CapLastEnacted}, []Cap{CapConstitution}},
		{[]string{"action", "submit", "w", "x.action"}, []Cap{CapActionFiles}, nil},
	}
	for _, tc := range cases {
		d := f.deps
		d.Terminal = failTerm{t}
		d.OpenUpstream = func(string) (ports.Store, error) {
			t.Errorf("%v: the workspace was opened before the needs were checked", tc.args)
			return nil, errors.New("opened")
		}
		root := NewRoot(d)
		root.SetArgs(append([]string{"--upstream-layout", "-C", f.dir}, tc.args...))
		err := root.ExecuteContext(context.Background())
		if err == nil {
			t.Fatalf("%v ran without its needs", tc.args)
		}
		for _, c := range tc.want {
			mustContain(t, err.Error(), string(c)+": "+reason(c))
		}
		for _, c := range tc.notWant {
			if strings.Contains(err.Error(), string(c)+": "+reason(c)) {
				t.Errorf("%v needs %s, which it does not read:\n%s", tc.args, c, err)
			}
		}
		if n := strings.Count(err.Error(), "this command cannot run here"); n != 1 {
			t.Errorf("%v: the refusal is not one error:\n%s", tc.args, err)
		}
	}
	f.queuedN(t, 0)
}
