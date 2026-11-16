package cli

import (
	"bytes"
	"context"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/fsstore"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

const (
	genSKeyHex = "5820deadbeefcafe0123456789abcdef0123456789abcdef0123456789abcdef"
	genVKeyHex = "5820" + "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	genWords   = "zebra yellow xylophone walnut violin umbrella tiger sugar rabbit quartz pencil owl nest mango lemon kite jelly iron hat goat fox elf dog cat"
)

// genFake is every generator and builder `pool keys`, `pool vrf` and
// `wallet new` use. It counts calls, so a test sees that a refused command
// generated nothing.
type genFake struct {
	calls      int
	lastPhrase string
}

func (g *genFake) pair() ports.KeyPair {
	g.calls++
	return ports.KeyPair{
		VKey: []byte(`{"type":"VerificationKey_ed25519","description":"","cborHex":"` + genVKeyHex + `"}`),
		SKey: secret.Take([]byte(`{"type":"SigningKey_ed25519","description":"","cborHex":"` + genSKeyHex + `"}`)),
	}
}
func (g *genFake) GenerateCold(context.Context) (ports.KeyPair, error)    { return g.pair(), nil }
func (g *genFake) GenerateVRF(context.Context) (ports.KeyPair, error)     { return g.pair(), nil }
func (g *genFake) GeneratePayment(context.Context) (ports.KeyPair, error) { return g.pair(), nil }
func (g *genFake) GenerateStake(context.Context) (ports.KeyPair, error)   { return g.pair(), nil }
func (g *genFake) GenerateMnemonic(context.Context) (*secret.Buffer, error) {
	g.calls++
	return secret.Take([]byte(genWords)), nil
}
func (g *genFake) DeriveWallet(_ context.Context, m *secret.Buffer, _, _ uint32) (ports.WalletKeys, error) {
	g.calls++
	g.lastPhrase = ""
	m.Use(func(b []byte) error { g.lastPhrase = string(b); return nil })
	return ports.WalletKeys{Payment: g.pair(), Stake: g.pair()}, nil
}
func (g *genFake) BuildAddress(uint8, txbuild.KeyHash, *txbuild.KeyHash) (chain.Address, error) {
	return "addr_test1fakepaymentaddress", nil
}
func (g *genFake) BuildStakeAddress(uint8, txbuild.KeyHash) (chain.StakeAddress, error) {
	return "stake_test1fakestakeaddress", nil
}

func genDeps(out *bytes.Buffer, g *genFake, drop ...Cap) Deps {
	return Deps{
		Out: out, Err: out,
		OpenUpstream: func(dir string) (ports.Store, error) { return fsstore.Open(dir) },
		Wire: func(ports.Store, WireOptions) (*Env, error) {
			env := &Env{NetworkID: ports.NetworkTestnet, ColdKeys: g, VrfKeys: g, PaymentKeys: g, StakeKeys: g,
				Mnemonics: g, WalletDeriver: g, Addresses: g}
			for _, c := range drop {
				switch c {
				case CapMnemonics:
					env.Mnemonics = nil
				case CapStakeKeys:
					env.StakeKeys = nil
				}
				env.Absent(c, "removed by the test")
			}
			return env, nil
		},
	}
}

func runGen(t *testing.T, d Deps, dir string, args ...string) error {
	t.Helper()
	root := NewRoot(d)
	root.SetArgs(append([]string{"--upstream-layout", "-C", dir}, args...))
	return root.ExecuteContext(context.Background())
}

func fdWith(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "fd")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(content)
	f.Seek(0, 0)
	t.Cleanup(func() { f.Close() })
	return strconv.Itoa(int(f.Fd()))
}

func noKeyMaterial(t *testing.T, out string) {
	t.Helper()
	for _, bad := range []string{genSKeyHex, "SigningKey", "zebra", "xylophone", "abandon", "cborHex\":\"" + genSKeyHex} {
		if strings.Contains(out, bad) {
			t.Errorf("output holds %q:\n%s", bad, out)
		}
	}
}

func TestPoolKeysAndVrfGenerateShowNoSigningKey(t *testing.T) {
	var out bytes.Buffer
	g := &genFake{}
	dir := t.TempDir()
	if err := runGen(t, genDeps(&out, g), dir, "pool", "keys", "generate", "p"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Pool id (hex)") || !strings.Contains(out.String(), "Pool id (bech32) pool1") {
		t.Errorf("pool id missing:\n%s", out.String())
	}
	if err := runGen(t, genDeps(&out, g), dir, "pool", "vrf", "generate", "p"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), genVKeyHex) {
		t.Errorf("verification key missing:\n%s", out.String())
	}
	noKeyMaterial(t, out.String())
	// A second run is refused by the use case and shows nothing either.
	out.Reset()
	if err := runGen(t, genDeps(&out, g), dir, "pool", "keys", "generate", "p"); err == nil {
		t.Error("cold keys generated twice")
	}
	noKeyMaterial(t, out.String())
}

func TestWalletNewVariantsShowNoKeyMaterial(t *testing.T) {
	phraseFD := fdWith(t, genWords+"\n")
	for name, tc := range map[string]struct {
		args []string
		want []string
		not  []string
	}{
		"payment only": {[]string{"wallet", "new", "a"}, []string{"Address addr_test1fakepaymentaddress"}, []string{"Stake address"}},
		"stake":        {[]string{"wallet", "new", "b", "--stake"}, []string{"Payment address addr_test1fake", "Stake address   stake_test1fake"}, []string{"recovery phrase"}},
		"mnemonic":     {[]string{"wallet", "new", "c", "--mnemonic", "--account", "1", "--index", "2"}, []string{"stored sealed", "not shown", "does not exist yet"}, nil},
		"mnemonic fd":  {[]string{"wallet", "new", "d", "--mnemonic-in-fd", phraseFD}, []string{"Stake address"}, []string{"recovery phrase"}},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			g := &genFake{}
			if err := runGen(t, genDeps(&out, g), t.TempDir(), tc.args...); err != nil {
				t.Fatal(err)
			}
			for _, w := range tc.want {
				if !strings.Contains(out.String(), w) {
					t.Errorf("missing %q:\n%s", w, out.String())
				}
			}
			for _, n := range tc.not {
				if strings.Contains(out.String(), n) {
					t.Errorf("has %q:\n%s", n, out.String())
				}
			}
			noKeyMaterial(t, out.String())
		})
	}
}

func TestWalletNewMnemonicFDReachesTheDeriver(t *testing.T) {
	var out bytes.Buffer
	g := &genFake{}
	if err := runGen(t, genDeps(&out, g), t.TempDir(), "wallet", "new", "m", "--mnemonic-in-fd", fdWith(t, strings.ToUpper(strings.Replace(genWords, " ", "  ", 1))+"\n")); err != nil {
		t.Fatal(err)
	}
	// Normalised by the use case (lower case, single spaces) before deriving.
	if g.lastPhrase != genWords {
		t.Errorf("the deriver got %q", g.lastPhrase)
	}
}

func TestWalletNewRefusesBadFlagsBeforeAnything(t *testing.T) {
	fd := fdWith(t, "x")
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"both mnemonic sources":    {[]string{"--mnemonic", "--mnemonic-in-fd", fd}, "exclusive"},
		"account without mnemonic": {[]string{"--account", "1"}, "--mnemonic"},
		"index with stake only":    {[]string{"--stake", "--index", "1"}, "--mnemonic"},
		"account out of range":     {[]string{"--mnemonic", "--account", "2147483648"}, "0 to 2147483647"},
		"negative descriptor":      {[]string{"--mnemonic-in-fd", "-4"}, "file descriptor"},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			g := &genFake{}
			dir := t.TempDir()
			err := runGen(t, genDeps(&out, g), dir, append([]string{"wallet", "new", "w"}, tc.args...)...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if g.calls != 0 {
				t.Error("something was generated")
			}
			if ents, _ := os.ReadDir(dir); len(ents) != 0 {
				t.Errorf("the workspace was touched: %v", ents)
			}
		})
	}
}

// ADR 0008: the needs are stated before the store opens or anything is read.
func TestWalletNewStatesItsNeedsFirst(t *testing.T) {
	var out bytes.Buffer
	g := &genFake{}
	dir := t.TempDir()
	err := runGen(t, genDeps(&out, g, CapMnemonics), dir, "wallet", "new", "w", "--mnemonic")
	if err == nil || !strings.Contains(err.Error(), "mnemonic-generation: removed by the test") {
		t.Fatalf("err = %v", err)
	}
	err = runGen(t, genDeps(&out, g, CapStakeKeys), dir, "wallet", "new", "w", "--stake")
	if err == nil || !strings.Contains(err.Error(), "stake-keygen") {
		t.Fatalf("err = %v", err)
	}
	if g.calls != 0 {
		t.Error("generated before the needs were checked")
	}
}
