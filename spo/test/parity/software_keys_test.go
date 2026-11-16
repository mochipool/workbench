package parity

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/fsstore"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/poolops"
	"github.com/mochipool/workbench/spo/internal/app/wallet"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// keySnapshot is snapshot with the content that differs by design redacted:
// an address is reduced to its human-readable part and length, a mnemonics
// file to its word count. Key files are already compared by envelope type,
// description and length.
func keySnapshot(t *testing.T, dir, prefix string) state {
	t.Helper()
	out := snapshot(t, dir, prefix)
	for name, desc := range out {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		mode := desc[:strings.Index(desc, " ")+1]
		switch {
		case strings.HasSuffix(name, ".addr"):
			a := strings.TrimSuffix(string(raw), "\n")
			hrp := a[:strings.LastIndex(a, "1")]
			out[name] = mode + "address hrp=" + hrp + " len=" + itoa(len(a)) + " newline=" + itoa(len(raw)-len(a))
		case strings.HasSuffix(name, ".mnemonics"):
			out[name] = mode + "words=" + itoa(len(strings.Fields(string(raw)))) + " newline=" + itoa(strings.Count(string(raw), "\n"))
		}
	}
	return out
}

func (e env) latest(t *testing.T, args ...execx.Arg) string {
	t.Helper()
	cli, err := e.tc.Tool(context.Background(), ports.CardanoCLI)
	if err != nil {
		t.Fatal(err)
	}
	res, err := execx.OS{}.Run(context.Background(), execx.Cmd{Path: cli.Path, Args: append(execx.Lits("latest"), args...)})
	if err != nil {
		t.Fatalf("cardano-cli: %v\n%s", err, res.Stderr)
	}
	return strings.TrimSpace(string(res.Stdout))
}

func openStore(t *testing.T) (*fsstore.Store, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := fsstore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return st, dir
}

func counterTail(t *testing.T, dir, name string) (prefix, tail string) {
	t.Helper()
	var env envelope
	if err := jsonUnmarshal([]byte(readFile(t, dir, name)), &env); err != nil {
		t.Fatal(err)
	}
	return env.CborHex[:8], env.CborHex[8:]
}

// 04a and 04b: the upstream scripts against the use cases.
//
// spec: SPO-04a-PRE-001, SPO-04a-EXT-001, SPO-04a-OUT-001, SPO-Pfiles-OUT-010, SPO-Pfiles-OUT-011, SPO-Pfiles-INV-003
// spec: SPO-04b-PRE-001, SPO-04b-EXT-001, SPO-04b-OUT-001, SPO-Pfiles-OUT-012
func TestPoolKeyGenerationParity(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	upDir := e.upstreamWorkspace(t)
	st, portDir := openStore(t)

	if code := e.upstream(t, upDir, "exec", "04a_genNodeKeys.sh", "mypool", "cli"); code != 0 {
		t.Fatalf("upstream 04a exited %d", code)
	}
	if code := e.upstream(t, upDir, "exec", "04b_genVRFKeys.sh", "mypool", "cli"); code != 0 {
		t.Fatalf("upstream 04b exited %d", code)
	}
	res, err := poolops.GenerateColdKeys{Store: st, KeyGen: native.SoftwareKeys{}}.Run(ctx, poolops.GenerateColdKeysRequest{Pool: "mypool"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (poolops.GenerateVrfKeys{Store: st, KeyGen: native.KeyGen{}}).Run(ctx, poolops.GenerateVrfKeysRequest{Pool: "mypool"}); err != nil {
		t.Fatal(err)
	}
	up := keySnapshot(t, upDir, "mypool")
	for _, want := range []string{"mypool.node.vkey", "mypool.node.skey", "mypool.node.counter", "mypool.vrf.vkey", "mypool.vrf.skey"} {
		if _, ok := up[want]; !ok {
			t.Fatalf("upstream did not write %s: %v", want, up)
		}
	}
	diff(t, "04a and 04b", up, keySnapshot(t, portDir, "mypool"))

	// The counter is [0, cold vkey]: the same shape under both, each holding
	// its own key. (The description, mode and length are compared above.)
	for _, d := range []string{upDir, portDir} {
		prefix, tail := counterTail(t, d, "mypool.node.counter")
		var v envelope
		jsonUnmarshal([]byte(readFile(t, d, "mypool.node.vkey")), &v)
		if prefix != "82005820" || tail != v.CborHex[4:] {
			t.Errorf("%s: counter cborHex is not [0, vkey]: %s %s", d, prefix, tail)
		}
	}
	if raw, _ := hex.DecodeString(strings.TrimPrefix(mustVKey(t, portDir, "mypool.node.vkey"), "5820")); chain.PoolID(mustPoolID(t, raw)) != res.PoolID {
		t.Error("the result's pool id is not the id of the stored vkey")
	}

	// Both refuse a second run, and the refusal writes nothing.
	before := keySnapshot(t, portDir, "mypool")
	if code := e.upstream(t, upDir, "exec", "04a_genNodeKeys.sh", "mypool", "cli"); code != 2 {
		t.Errorf("upstream second 04a exited %d, want 2", code)
	}
	if code := e.upstream(t, upDir, "exec", "04b_genVRFKeys.sh", "mypool", "cli"); code != 2 {
		t.Errorf("upstream second 04b exited %d, want 2", code)
	}
	if _, err := (poolops.GenerateColdKeys{Store: st, KeyGen: native.SoftwareKeys{}}).Run(ctx, poolops.GenerateColdKeysRequest{Pool: "mypool"}); err == nil {
		t.Error("port second cold generation succeeded")
	}
	if _, err := (poolops.GenerateVrfKeys{Store: st, KeyGen: native.KeyGen{}}).Run(ctx, poolops.GenerateVrfKeysRequest{Pool: "mypool"}); err == nil {
		t.Error("port second VRF generation succeeded")
	}
	diff(t, "after refusals", up, keySnapshot(t, upDir, "mypool"))
	diff(t, "after port refusals", before, keySnapshot(t, portDir, "mypool"))
}

func mustVKey(t *testing.T, dir, name string) string {
	var v envelope
	if err := jsonUnmarshal([]byte(readFile(t, dir, name)), &v); err != nil {
		t.Fatal(err)
	}
	return v.CborHex
}

func mustPoolID(t *testing.T, raw []byte) chain.PoolID {
	id, err := chain.PoolIDOf(raw)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// 02: upstream against GeneratePaymentAccount on the preview (testnet) network.
//
// spec: SPO-02-PRE-001, SPO-02-EXT-001, SPO-02-EXT-004, SPO-Pfiles-OUT-001, SPO-Pfiles-OUT-002, SPO-Pfiles-INV-003
func TestPaymentAccountParity(t *testing.T) {
	e := setup(t)
	upDir := e.upstreamWorkspace(t)
	st, portDir := openStore(t)
	if code := e.upstream(t, upDir, "exec", "02_genPaymentAddrOnly.sh", "w", "cli"); code != 0 {
		t.Fatalf("upstream 02 exited %d", code)
	}
	uc := wallet.GeneratePaymentAccount{Store: st, KeyGen: native.SoftwareKeys{}, Addresses: native.Ledger{}, NetworkID: ports.NetworkTestnet}
	if _, err := uc.Run(context.Background(), wallet.GeneratePaymentRequest{Name: "w"}); err != nil {
		t.Fatal(err)
	}
	up := keySnapshot(t, upDir, "w")
	if len(up) != 3 {
		t.Fatalf("upstream artefacts: %v", up)
	}
	diff(t, "02", up, keySnapshot(t, portDir, "w"))
	if !strings.HasPrefix(readFile(t, portDir, "w.addr"), "addr_test1v") {
		t.Errorf("not an enterprise testnet address")
	}
	if code := e.upstream(t, upDir, "exec", "02_genPaymentAddrOnly.sh", "w", "cli"); code != 2 {
		t.Errorf("upstream second 02 exited %d, want 2", code)
	}
	if _, err := uc.Run(context.Background(), wallet.GeneratePaymentRequest{Name: "w"}); err == nil {
		t.Error("port second run succeeded")
	}
	diff(t, "02 after refusal", up, keySnapshot(t, portDir, "w"))
}

// 03a with random keys (`cli`).
//
// spec: SPO-03a-PRE-001, SPO-03a-EXT-001, SPO-03a-EXT-004, SPO-03a-EXT-005, SPO-03a-OUT-004, SPO-03a-IF-003
func TestWalletCliParity(t *testing.T) {
	e := setup(t)
	upDir := e.upstreamWorkspace(t)
	st, portDir := openStore(t)
	if code := e.upstream(t, upDir, "exec", "03a_genStakingPaymentAddr.sh", "owner", "cli"); code != 0 {
		t.Fatalf("upstream 03a exited %d", code)
	}
	uc := walletUC(st, ports.NetworkTestnet)
	if _, err := uc.Run(context.Background(), wallet.GenerateWalletRequest{Name: "owner", Source: wallet.WalletKeysRandom}); err != nil {
		t.Fatal(err)
	}
	up := keySnapshot(t, upDir, "owner")
	if len(up) != 6 {
		t.Fatalf("upstream artefacts: %v", up)
	}
	diff(t, "03a cli", up, keySnapshot(t, portDir, "owner"))
	if code := e.upstream(t, upDir, "exec", "03a_genStakingPaymentAddr.sh", "owner", "cli"); code != 2 {
		t.Errorf("upstream second 03a exited %d, want 2", code)
	}
	if _, err := uc.Run(context.Background(), wallet.GenerateWalletRequest{Name: "owner", Source: wallet.WalletKeysRandom}); err == nil {
		t.Error("port second run succeeded")
	}
	diff(t, "03a cli after refusal", up, keySnapshot(t, portDir, "owner"))
}

func walletUC(st ports.Store, network uint8) wallet.GenerateWalletAccount {
	k := native.SoftwareKeys{}
	return wallet.GenerateWalletAccount{Store: st, Payment: k, Stake: k, Mnemonics: k, Deriver: k, Addresses: native.Ledger{}, NetworkID: network}
}

// 03a `mnemonics` with a fixed phrase: the upstream script (cardano-signer
// keygen, cardano-cli key non-extended-key) and the native derivation must
// give the same files byte for byte, for account 0 index 0 and for another
// account and index. Given words are passed to the script on its command
// line (SPO-03a-SEC-002); this phrase is a public test vector.
//
// spec: SPO-03a-EXT-003, SPO-03a-INV-001, SPO-03a-OUT-002, SPO-03a-OUT-003, SPO-03a-OUT-004, SPO-03a-IF-004, SPO-03a-PRE-002, SPO-Pfiles-OUT-002, SPO-Pfiles-OUT-005
func TestWalletMnemonicParity(t *testing.T) {
	e := setup(t)
	e.needSigner(t)
	const phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
	for _, tc := range []struct {
		name         string
		account, idx string
		a, i         uint32
	}{{"zero", "0", "0", 0, 0}, {"nonzero", "1", "3", 1, 3}, {"larger", "17", "4000", 17, 4000}} {
		t.Run(tc.name, func(t *testing.T) {
			upDir := e.upstreamWorkspace(t)
			st, portDir := openStore(t)
			if code := e.upstream(t, upDir, "exec", "03a_genStakingPaymentAddr.sh", "owner", "mnemonics",
				"acc:"+tc.account, "idx:"+tc.idx, "mnemonics:"+phrase); code != 0 {
				t.Fatalf("upstream 03a exited %d", code)
			}
			m := secret.Take([]byte(phrase))
			defer m.Destroy()
			_, err := walletUC(st, ports.NetworkTestnet).Run(context.Background(), wallet.GenerateWalletRequest{
				Name: "owner", Source: wallet.WalletKeysMnemonic, Account: tc.a, Index: tc.i, Mnemonic: m})
			if err != nil {
				t.Fatal(err)
			}
			up := keySnapshot(t, upDir, "owner")
			if len(up) != 7 {
				t.Fatalf("upstream artefacts: %v", up)
			}
			diff(t, "03a mnemonics", up, keySnapshot(t, portDir, "owner"))
			// Everything is deterministic here: every file must be identical.
			// Signing keys are compared without being printed.
			for name := range up {
				if a, b := readFile(t, upDir, name), readFile(t, portDir, name); a != b {
					if strings.HasSuffix(name, ".skey") {
						t.Errorf("%s differs (not shown: signing key)", name)
					} else {
						t.Errorf("%s differs\n  upstream: %q\n  native:   %q", name, a, b)
					}
				}
			}
		})
	}
}

// Upstream generates the phrase; the native derivation of that phrase must
// give the files the script made, and the native generator's phrase must
// have the shape of upstream's.
//
// spec: SPO-03a-EXT-003, SPO-03a-OUT-003, SPO-Pfiles-OUT-005, SPO-03a-INV-001
func TestWalletFreshMnemonicParity(t *testing.T) {
	e := setup(t)
	e.needSigner(t)
	upDir := e.upstreamWorkspace(t)
	st, portDir := openStore(t)
	if code := e.upstream(t, upDir, "exec", "03a_genStakingPaymentAddr.sh", "owner", "mnemonics"); code != 0 {
		t.Fatalf("upstream 03a exited %d", code)
	}
	if _, err := walletUC(st, ports.NetworkTestnet).Run(context.Background(), wallet.GenerateWalletRequest{Name: "owner", Source: wallet.WalletKeysMnemonic}); err != nil {
		t.Fatal(err)
	}
	diff(t, "03a fresh mnemonics", keySnapshot(t, upDir, "owner"), keySnapshot(t, portDir, "owner"))

	// Feed the words upstream generated to the native derivation (path 0/0).
	words := secret.Take([]byte(strings.TrimSpace(readFile(t, upDir, "owner.payment.mnemonics"))))
	defer words.Destroy()
	keys, err := native.SoftwareKeys{}.DeriveWallet(context.Background(), words, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Payment.SKey.Destroy()
	defer keys.Stake.SKey.Destroy()
	if string(keys.Payment.VKey) != readFile(t, upDir, "owner.payment.vkey") || string(keys.Stake.VKey) != readFile(t, upDir, "owner.staking.vkey") {
		t.Error("native derivation of upstream's generated phrase gives other verification keys")
	}
}

// The oracle: cardano-cli accepts the native keys, derives the same
// verification key from each signing key, and builds the same addresses
// (testnet and mainnet, enterprise and base) and pool id as the native code.
//
// spec: SPO-04a-EXT-001, SPO-02-EXT-001, SPO-02-EXT-004, SPO-03a-EXT-001, SPO-03a-EXT-004, SPO-03a-EXT-005
func TestNativeSoftwareKeysMatchCardanoCLI(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	k := native.SoftwareKeys{}
	nets := []struct {
		id   uint8
		flag []string
	}{{ports.NetworkTestnet, []string{"--testnet-magic", "2"}}, {ports.NetworkMainnet, []string{"--mainnet"}}}

	rawOf := func(vkey []byte) []byte {
		env, err := pool.ParseEnvelope(vkey)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := env.Key32()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	vkeyFile := func(vkey []byte) string {
		p := filepath.Join(t.TempDir(), "k.vkey")
		if err := os.WriteFile(p, vkey, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	check := func(label string, pair ports.KeyPair) {
		defer pair.SKey.Destroy()
		out := e.latest(t, execx.Lit("key"), execx.Lit("verification-key"), execx.Lit("--signing-key-file"), execx.SecretIn(pair.SKey),
			execx.Lit("--verification-key-file"), execx.Lit("/dev/stdout"))
		var theirs, ours envelope
		jsonUnmarshal([]byte(out), &theirs)
		jsonUnmarshal(pair.VKey, &ours)
		if theirs.Type != ours.Type || theirs.CborHex != ours.CborHex {
			t.Fatalf("%s: verification key differs\n  cardano-cli: %+v\n  native:      %+v", label, theirs, ours)
		}
	}
	for i := 0; i < 5; i++ {
		pay, err := k.GeneratePayment(ctx)
		if err != nil {
			t.Fatal(err)
		}
		stk, err := k.GenerateStake(ctx)
		if err != nil {
			t.Fatal(err)
		}
		cold, err := k.GenerateCold(ctx)
		if err != nil {
			t.Fatal(err)
		}
		payV, stkV, coldV := pay.VKey, stk.VKey, cold.VKey
		check("payment", pay)
		check("stake", stk)
		check("cold", cold)

		payH, stkH := txbuild.HashKey(rawOf(payV)), txbuild.HashKey(rawOf(stkV))
		for _, n := range nets {
			wantEnt := e.latest(t, append(lits("address", "build", "--payment-verification-key-file", vkeyFile(payV)), lits(n.flag...)...)...)
			wantBase := e.latest(t, append(lits("address", "build", "--payment-verification-key-file", vkeyFile(payV), "--stake-verification-key-file", vkeyFile(stkV)), lits(n.flag...)...)...)
			wantStake := e.latest(t, append(lits("stake-address", "build", "--stake-verification-key-file", vkeyFile(stkV)), lits(n.flag...)...)...)
			ent, err := native.Ledger{}.BuildAddress(n.id, payH, nil)
			base, err2 := native.Ledger{}.BuildAddress(n.id, payH, &stkH)
			rew, err3 := native.Ledger{}.BuildStakeAddress(n.id, stkH)
			if err != nil || err2 != nil || err3 != nil {
				t.Fatal(err, err2, err3)
			}
			if string(ent) != wantEnt || string(base) != wantBase || string(rew) != wantStake {
				t.Fatalf("network %d addresses differ\n  cardano-cli: %s %s %s\n  native:      %s %s %s", n.id, wantEnt, wantBase, wantStake, ent, base, rew)
			}
		}
		wantID := e.latest(t, lits("stake-pool", "id", "--cold-verification-key-file", vkeyFile(coldV))...)
		if got := mustPoolID(t, rawOf(coldV)).Bech32(); got != wantID {
			t.Fatalf("pool id: cardano-cli %s, native %s", wantID, got)
		}
	}
}

// Derived keys are accepted by cardano-cli too: it turns the extended signing
// key into the extended verification key, `key non-extended-key` makes the
// non-extended one, and that is the verification key stored. Addresses built
// by cardano-cli from the stored verification keys equal the native ones.
//
// spec: SPO-03a-OUT-002, SPO-03a-EXT-005, SPO-Pfiles-OUT-002
func TestDerivedKeysMatchCardanoCLI(t *testing.T) {
	e := setup(t)
	phrase := secret.Take([]byte("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"))
	defer phrase.Destroy()
	for _, ai := range [][2]uint32{{0, 0}, {1, 3}, {5, 77}} {
		keys, err := native.SoftwareKeys{}.DeriveWallet(context.Background(), phrase, ai[0], ai[1])
		if err != nil {
			t.Fatal(err)
		}
		for label, pair := range map[string]ports.KeyPair{"payment": keys.Payment, "stake": keys.Stake} {
			ext := e.latest(t, execx.Lit("key"), execx.Lit("verification-key"), execx.Lit("--signing-key-file"), execx.SecretIn(pair.SKey),
				execx.Lit("--verification-key-file"), execx.Lit("/dev/stdout"))
			extFile := filepath.Join(t.TempDir(), "ext.vkey")
			os.WriteFile(extFile, []byte(ext), 0o600)
			plain := e.latest(t, lits("key", "non-extended-key", "--extended-verification-key-file", extFile, "--verification-key-file", "/dev/stdout")...)
			var theirs, ours envelope
			jsonUnmarshal([]byte(plain), &theirs)
			jsonUnmarshal(pair.VKey, &ours)
			if theirs.CborHex != ours.CborHex {
				t.Fatalf("%s %v: non-extended verification key\n  cardano-cli: %s\n  native:      %s", label, ai, theirs.CborHex, ours.CborHex)
			}
			pair.SKey.Destroy()
		}
	}
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

// A lone .payment.mnemonics file stops 03a with exit 1 (not 2: SPO-03a-PRE-002
// comes after SPO-03a-PRE-001), and the port refuses the same state without
// touching anything.
//
// spec: SPO-03a-PRE-002
func TestWalletMnemonicsFileRefusalParity(t *testing.T) {
	e := setup(t)
	upDir := e.upstreamWorkspace(t)
	st, portDir := openStore(t)
	for _, d := range []string{upDir, portDir} {
		if err := os.WriteFile(filepath.Join(d, "owner.payment.mnemonics"), []byte("x\n"), 0o400); err != nil {
			t.Fatal(err)
		}
	}
	if code := e.upstream(t, upDir, "exec", "03a_genStakingPaymentAddr.sh", "owner", "mnemonics"); code != 1 {
		t.Errorf("upstream exited %d, want 1", code)
	}
	_, err := walletUC(st, ports.NetworkTestnet).Run(context.Background(), wallet.GenerateWalletRequest{Name: "owner", Source: wallet.WalletKeysMnemonic})
	if !errors.Is(err, wallet.ErrMnemonicsExist) {
		t.Errorf("port: %v", err)
	}
	diff(t, "after refusal", keySnapshot(t, upDir, "owner"), keySnapshot(t, portDir, "owner"))
}
