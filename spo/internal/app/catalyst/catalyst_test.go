package catalyst

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

	"github.com/mochipool/workbench/spo/internal/adapters/fsstore"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

const phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

// The voting key of the public phrase at 1694H/1815H/0H/0/0, from cardano-signer.
const phraseVote = "cvote_vk1693fwq7zfn9vmdky59786wwc8tf3a4pvx360tcp8ma2kfw0c233sg8y667"

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

type fixedTip struct{ slot uint64 }

func (fixedTip) Source() chain.Source { return "test" }
func (f fixedTip) Tip(context.Context) (chain.Tip, error) {
	return chain.Tip{Slot: f.slot}, nil
}

type rig struct {
	dir   string
	store *fsstore.Store
	clock fixedClock
}

func newRig(t *testing.T) rig {
	t.Helper()
	dir := t.TempDir()
	st, err := fsstore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return rig{dir, st, fixedClock{time.Date(2026, 11, 16, 12, 34, 56, 0, time.Local)}}
}

func (r rig) keyUC() GenerateVotingKey {
	return GenerateVotingKey{Store: r.store, Deriver: native.SoftwareKeys{}, Mnemonics: native.SoftwareKeys{}}
}

func (r rig) regUC() GenerateRegistration {
	return GenerateRegistration{Store: r.store, Signers: native.NewSignatureSigners(r.store), Clock: r.clock,
		Tip: fixedTip{424242}, NetworkID: ports.NetworkTestnet}
}

func (r rig) files(t *testing.T) []string {
	t.Helper()
	es, err := os.ReadDir(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

func (r rig) mode(t *testing.T, name string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(filepath.Join(r.dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func (r rig) put(t *testing.T, ref ports.Ref, b []byte) {
	t.Helper()
	err := r.store.Update(context.Background(), func(w ports.Writer) error {
		if ref.Kind.Secret() {
			return w.PutSecret(ref, secret.Take(append([]byte(nil), b...)))
		}
		return w.Put(ref, b)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// stakeAccount stores a random stake key pair as <name>.staking.* and returns
// a testnet enterprise address for the rewards.
func (r rig) stakeAccount(t *testing.T, name string) (stakePub [32]byte) {
	t.Helper()
	pair, err := native.SoftwareKeys{}.GenerateStake(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer pair.SKey.Destroy()
	r.put(t, ports.Ref{Name: name, Kind: ports.StakingVKey}, pair.VKey)
	if err := r.store.Update(context.Background(), func(w ports.Writer) error {
		return w.PutSecret(ports.Ref{Name: name, Kind: ports.StakingSKey}, pair.SKey)
	}); err != nil {
		t.Fatal(err)
	}
	pub, err := cose.VKeyFromEnvelope(pair.VKey)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func enterprise(hrp string, header byte) string {
	a, _ := chain.Bech32Encode(hrp, append([]byte{header}, make([]byte, 28)...))
	return a
}

// A voting key from the public phrase: four artefacts locked at 0400, the
// public key text of cardano-signer in the .pkey, no secret in the result.
//
// spec: SPO-09a-IF-002, SPO-09a-PRE-002, SPO-09a-EXT-001, SPO-09a-OUT-001, SPO-09a-OUT-002, SPO-09a-OUT-003, SPO-09a-SEC-001, SPO-09a-INV-001, SPO-Pfiles-OUT-035
func TestGenerateVotingKey(t *testing.T) {
	r := newRig(t)
	m := secret.Take([]byte(strings.ToUpper(phrase[:15]) + phrase[15:] + "\n"))
	defer m.Destroy()
	res, err := r.keyUC().Run(context.Background(), GenerateVotingKeyRequest{Name: "./vote", Mnemonic: m})
	if err != nil {
		t.Fatal(err)
	}
	if res.Name != "vote" || res.PKey != phraseVote {
		t.Errorf("result %+v", res)
	}
	want := []string{"vote.voting.mnemonics", "vote.voting.pkey", "vote.voting.skey", "vote.voting.vkey"}
	if got := r.files(t); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("files %v", got)
	}
	for _, f := range want {
		if r.mode(t, f) != 0o400 {
			t.Errorf("%s mode %v", f, r.mode(t, f))
		}
	}
	if b, _ := os.ReadFile(filepath.Join(r.dir, "vote.voting.pkey")); string(b) != phraseVote+"\n" {
		t.Errorf("pkey %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(r.dir, "vote.voting.mnemonics")); string(b) != phrase+"\n" {
		t.Error("mnemonics file")
	}
	if s := fmt.Sprintf("%+v", res); strings.Contains(s, "abandon") {
		t.Error("the result carries the phrase")
	}
	// A fresh phrase, and the 24-word rule.
	if _, err := r.keyUC().Run(context.Background(), GenerateVotingKeyRequest{Name: "fresh"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(r.dir, "fresh.voting.mnemonics"))
	if len(strings.Fields(string(b))) != 24 {
		t.Error("fresh phrase is not 24 words")
	}
	short := secret.Take([]byte("one two"))
	defer short.Destroy()
	n := len(r.files(t))
	if _, err := r.keyUC().Run(context.Background(), GenerateVotingKeyRequest{Name: "s", Mnemonic: short}); !errors.Is(err, custody.ErrMnemonicWords) || len(r.files(t)) != n {
		t.Errorf("short phrase: %v", err)
	}
}

// Existing voting key files refuse before any derivation; a hardware holder
// is refused up front.
//
// spec: SPO-09a-PRE-001, SPO-09a-EXT-002
func TestGenerateVotingKeyRefusals(t *testing.T) {
	r := newRig(t)
	if _, err := r.keyUC().Run(context.Background(), GenerateVotingKeyRequest{Name: "v"}); err != nil {
		t.Fatal(err)
	}
	n := len(r.files(t))
	if _, err := r.keyUC().Run(context.Background(), GenerateVotingKeyRequest{Name: "v"}); !errors.Is(err, ErrExists) {
		t.Errorf("again: %v", err)
	}
	r.put(t, ports.Ref{Name: "h", Kind: ports.VotingHwsFile}, []byte("{}"))
	if _, err := r.keyUC().Run(context.Background(), GenerateVotingKeyRequest{Name: "h"}); !errors.Is(err, ErrExists) {
		t.Errorf("hwsfile: %v", err)
	}
	var ue *custody.UnsupportedError
	if _, err := r.keyUC().Run(context.Background(), GenerateVotingKeyRequest{Name: "x", Holder: custody.HolderHardware}); !errors.As(err, &ue) {
		t.Errorf("hardware: %v", err)
	}
	if got := len(r.files(t)); got != n+1 {
		t.Errorf("refusals wrote files (%d, want %d)", got, n+1)
	}
}

// The delegation argument: one key or several joined with a bar, optional
// weights, digits only.
//
// spec: SPO-09a-IF-003, SPO-09a-PRE-004
func TestParseDelegation(t *testing.T) {
	got, err := ParseDelegation("myvote 3|other 1|third")
	want := []DelegationWord{{"myvote", 3}, {"other", 1}, {"third", 1}}
	if err != nil || fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("%v %v", got, err)
	}
	if got, err := ParseDelegation("solo"); err != nil || got[0].Weight != 1 {
		t.Errorf("single: %v %v", got, err)
	}
	// Zero is accepted by the parser as upstream accepts it.
	if got, err := ParseDelegation("k 0|j 2"); err != nil || got[0].Weight != 0 {
		t.Errorf("zero: %v %v", got, err)
	}
	for _, bad := range []string{"k x", "k -1", "k 1 2", "", "k 1.5", "k +3"} {
		if _, err := ParseDelegation(bad); !errors.Is(err, ErrBadDelegation) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// The registration: two voting keys with weights (a stored .pkey and a hex
// key), signed by the stake key through the vault signer; the file is named
// from the stake account and the local time, public, mode default, verifies;
// the nonce is the tip slot; the plan is checked first.
//
// spec: SPO-09a-EXT-003, SPO-09a-OUT-005, SPO-09a-OUT-006, SPO-09a-INV-003, SPO-09a-INV-005, SPO-09a-IN-002, SPO-09a-IN-004, SPO-09a-PRE-005, SPO-09a-MODE-001, SPO-09a-SEC-003, SPO-Pfiles-OUT-035
func TestGenerateRegistration(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	m := secret.Take([]byte(phrase))
	defer m.Destroy()
	if _, err := r.keyUC().Run(ctx, GenerateVotingKeyRequest{Name: "v1", Mnemonic: m}); err != nil {
		t.Fatal(err)
	}
	stakePub := r.stakeAccount(t, "w")
	r.put(t, ports.Ref{Name: "pay", Kind: ports.AddrFile}, []byte(enterprise("addr_test", 0x60)+"\n"))
	hexKey := strings.Repeat("ab", 32)

	deleg, _ := ParseDelegation("v1 3|" + hexKey + " 1")
	res, err := r.regUC().Run(ctx, RegistrationRequest{Delegation: deleg, Stake: "./w.staking.addr", Rewards: "pay.addr", Purpose: 0})
	if err != nil {
		t.Fatal(err)
	}
	// "w.staking.addr" loses ".addr" then ".staking".
	if res.Ref.Name != "w_261116123456" || res.Nonce != 424242 {
		t.Errorf("ref %v nonce %d", res.Ref, res.Nonce)
	}
	if r.mode(t, "w_261116123456.vote-registration.cbor") != 0o644 {
		t.Errorf("mode %v", r.mode(t, "w_261116123456.vote-registration.cbor"))
	}
	file, _ := os.ReadFile(filepath.Join(r.dir, "w_261116123456.vote-registration.cbor"))
	if string(file) != string(res.CBOR) {
		t.Error("the stored file is not the registration")
	}
	reg, err := cose.VerifyCip36(file)
	if err != nil {
		t.Fatal(err)
	}
	if reg.StakePub != stakePub || reg.Nonce != 424242 || reg.Purpose != 0 || len(reg.Delegations) != 2 ||
		reg.Delegations[0].Weight != 3 || reg.Delegations[1].Weight != 1 || hex.EncodeToString(reg.Delegations[1].VotePub[:]) != hexKey {
		t.Errorf("registration %+v", reg)
	}
	if res.Keys[0].Source != "v1/voting.pkey" || res.Keys[1].Source != "hex" || res.Rewards != chain.Address(enterprise("addr_test", 0x60)) {
		t.Errorf("resolution %+v %s", res.Keys, res.Rewards)
	}
	// The vote registration carries no secret: only the voting key's public key, the stake public key, the address.
	for _, f := range []string{"w.staking.skey"} {
		if strings.Contains(string(file), f) {
			t.Error("secret in the registration")
		}
	}
	// A literal address works as rewards; an explicit nonce wins; the purpose is carried.
	later := r.regUC()
	later.Clock = fixedClock{r.clock.t.Add(time.Minute)}
	deleg1, _ := ParseDelegation(hexKey)
	res2, err := later.Run(ctx, RegistrationRequest{Delegation: deleg1, Stake: "w", Rewards: enterprise("addr_test", 0x60), Nonce: 7, Purpose: 3})
	if err != nil || res2.Nonce != 7 {
		t.Fatalf("%v %d", err, res2.Nonce)
	}
	if got, _ := cose.VerifyCip36(res2.CBOR); got.Purpose != 3 || got.Delegations[0].Weight != 1 {
		t.Errorf("%+v", got)
	}
	// The same second is refused (SPO-09a-OUT-005) and writes nothing.
	n := len(r.files(t))
	if _, err := r.regUC().Run(ctx, RegistrationRequest{Delegation: deleg, Stake: "w", Rewards: "pay"}); !errors.Is(err, ErrExists) || len(r.files(t)) != n {
		t.Errorf("same second: %v", err)
	}
}

// The voting key reference: a .pkey wins over a .vkey for the same name (the
// upstream quirk, kept and visible); a .vkey alone is used; 128 hex digits are
// cut to the first 64; a bech32 key works; anything else is refused.
//
// spec: SPO-09a-IF-006
func TestResolveVotingKey(t *testing.T) {
	r := newRig(t)
	pubA, pubB := strings.Repeat("aa", 32), strings.Repeat("bb", 32)
	bechA, _ := chain.Bech32Encode("cvote_vk", mustHex(t, pubA))
	r.put(t, ports.Ref{Name: "both", Kind: ports.VotingPKey}, []byte(bechA+"\n"))
	r.put(t, ports.Ref{Name: "both", Kind: ports.VotingVKey}, []byte(`{"type":"x","description":"","cborHex":"5820`+pubB+`"}`))
	r.put(t, ports.Ref{Name: "vonly", Kind: ports.VotingVKey}, []byte(`{"type":"x","description":"","cborHex":"5820`+pubB+`"}`))
	check := func(ref, wantPub, wantSrc string) {
		t.Helper()
		_ = r.store.View(context.Background(), func(rd ports.Reader) error {
			k, err := resolveVotingKey(rd, DelegationWord{Ref: ref, Weight: 1})
			if err != nil {
				t.Errorf("%s: %v", ref, err)
				return nil
			}
			if hex.EncodeToString(k.PublicKey[:]) != wantPub || k.Source != wantSrc {
				t.Errorf("%s: %x from %s, want %s from %s", ref, k.PublicKey, k.Source, wantPub, wantSrc)
			}
			return nil
		})
	}
	check("both", pubA, "both/voting.pkey")
	check("both.voting.pkey", pubA, "both/voting.pkey")
	check("vonly", pubB, "vonly/voting.vkey")
	check(pubA+pubB, pubA, "hex")
	check(pubB, pubB, "hex")
	check(bechA, pubA, "bech32")
	_ = r.store.View(context.Background(), func(rd ports.Reader) error {
		for _, bad := range []string{"nothing", strings.Repeat("g", 64), "cvote_vk1qqqqqq"} {
			if _, err := resolveVotingKey(rd, DelegationWord{Ref: bad}); !errors.Is(err, ErrBadVotingKey) {
				t.Errorf("%q: %v", bad, err)
			}
		}
		return nil
	})
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The refusals: no stake signing key, a zero total weight, a stake address or
// a mainnet address as rewards, an ADA Handle, an unknown key, no nonce, a
// hardware stake key (refused up front, nothing written), a failing signer.
//
// spec: SPO-09a-PRE-003, SPO-09a-PRE-004, SPO-09a-PRE-005, SPO-09a-IN-004, SPO-09a-EXT-004, SPO-09a-INV-004, SPO-09a-PRE-006, SPO-09a-PRE-007
func TestGenerateRegistrationRefusals(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	hexKey := strings.Repeat("ab", 32)
	deleg, _ := ParseDelegation(hexKey)
	addr := enterprise("addr_test", 0x60)
	if _, err := r.regUC().Run(ctx, RegistrationRequest{Delegation: deleg, Stake: "nostake", Rewards: addr}); !errors.Is(err, ErrNoStakeSigner) {
		t.Errorf("no stake key: %v", err)
	}
	r.stakeAccount(t, "w")
	n := len(r.files(t))
	zero, _ := ParseDelegation(hexKey + " 0")
	for name, tc := range map[string]struct {
		req  RegistrationRequest
		want error
	}{
		"zero weight":     {RegistrationRequest{Delegation: zero, Stake: "w", Rewards: addr}, cose.ErrCip36},
		"stake address":   {RegistrationRequest{Delegation: deleg, Stake: "w", Rewards: enterprise("stake_test", 0xe0)}, ErrBadRewards},
		"mainnet address": {RegistrationRequest{Delegation: deleg, Stake: "w", Rewards: enterprise("addr", 0x61)}, ErrBadRewards},
		"handle":          {RegistrationRequest{Delegation: deleg, Stake: "w", Rewards: "$rewards"}, ErrAdaHandle},
		"unknown key":     {RegistrationRequest{Delegation: []DelegationWord{{Ref: "nobody", Weight: 1}}, Stake: "w", Rewards: addr}, ErrBadVotingKey},
		"no delegation":   {RegistrationRequest{Stake: "w", Rewards: addr}, ErrBadDelegation},
	} {
		if _, err := r.regUC().Run(ctx, tc.req); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	noTip := r.regUC()
	noTip.Tip = nil
	if _, err := noTip.Run(ctx, RegistrationRequest{Delegation: deleg, Stake: "w", Rewards: addr}); !errors.Is(err, ErrNoNonce) {
		t.Errorf("no nonce: %v", err)
	}
	// A hardware stake file beside a software key wins and is refused up front.
	r.put(t, ports.Ref{Name: "w", Kind: ports.StakingHwsFile}, []byte("{}"))
	n++
	var ue *custody.UnsupportedError
	if _, err := r.regUC().Run(ctx, RegistrationRequest{Delegation: deleg, Stake: "w", Rewards: addr}); !errors.As(err, &ue) {
		t.Errorf("hardware stake key: %v", err)
	}
	if got := len(r.files(t)); got != n {
		t.Errorf("refusals wrote files (%d, want %d)", got, n)
	}
	// A signer that fails is an error and no file (upstream exits 0).
	r2 := newRig(t)
	r2.stakeAccount(t, "w")
	uc := r2.regUC()
	uc.Signers = failingDir{}
	if _, err := uc.Run(ctx, RegistrationRequest{Delegation: deleg, Stake: "w", Rewards: addr}); err == nil || len(r2.files(t)) != 2 {
		t.Errorf("failing signer: %v, files %v", err, r2.files(t))
	}
}

type failingDir struct{}

func (failingDir) SignerFor(custody.KeyRef) (ports.Signer, error) { return failingSigner{}, nil }

type failingSigner struct{}

func (failingSigner) Profile() custody.Profile {
	return custody.NewProfile("failing").Allow(custody.RoleStake, custody.OpSignCip36)
}
func (failingSigner) SignCip36(context.Context, custody.Key[custody.Stake], cose.Cip36) (ports.Registration, error) {
	return ports.Registration{}, errors.New("device gone")
}
