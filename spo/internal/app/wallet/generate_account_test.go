package wallet

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

const (
	payPubHex  = "a1a2a3a4a5a6a7a8a9a0b1b2b3b4b5b6b7b8b9b0c1c2c3c4c5c6c7c8c9c0d1d2"
	stkPubHex  = "b1b2b3b4b5b6b7b8b9b0c1c2c3c4c5c6c7c8c9c0d1d2d3d4d5d6d7d8d9d0e1e2"
	paySeedHex = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
	stkSeedHex = "99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa"
	// Words that must never appear in a result, error or log. They are valid
	// BIP-39 words; the fake generator makes a phrase of them.
	phraseWord = "zebra"
)

var fakePhrase = strings.TrimSpace(strings.Repeat(phraseWord+" ", 24))

func genEnv(typ, desc, key string) string {
	return fmt.Sprintf("{\n    \"type\": %q,\n    \"description\": %q,\n    \"cborHex\": \"5820%s\"\n}\n", typ, desc, key)
}

type genFakes struct {
	payCalls, stakeCalls, deriveCalls, phraseCalls int
	derived                                        struct {
		phrase       string
		account, idx uint32
	}
}

func (g *genFakes) GeneratePayment(context.Context) (ports.KeyPair, error) {
	g.payCalls++
	return ports.KeyPair{VKey: []byte(genEnv("PaymentVerificationKeyShelley_ed25519", "Payment Verification Key", payPubHex)),
		SKey: secret.Take([]byte(genEnv("PaymentSigningKeyShelley_ed25519", "Payment Signing Key", paySeedHex)))}, nil
}
func (g *genFakes) GenerateStake(context.Context) (ports.KeyPair, error) {
	g.stakeCalls++
	return ports.KeyPair{VKey: []byte(genEnv("StakeVerificationKeyShelley_ed25519", "Stake Verification Key", stkPubHex)),
		SKey: secret.Take([]byte(genEnv("StakeSigningKeyShelley_ed25519", "Stake Signing Key", stkSeedHex)))}, nil
}
func (g *genFakes) GenerateMnemonic(context.Context) (*secret.Buffer, error) {
	g.phraseCalls++
	return secret.Take([]byte(fakePhrase)), nil
}
func (g *genFakes) DeriveWallet(_ context.Context, m *secret.Buffer, account, index uint32) (ports.WalletKeys, error) {
	g.deriveCalls++
	m.Use(func(b []byte) error { g.derived.phrase = string(b); return nil })
	g.derived.account, g.derived.idx = account, index
	if g.derived.phrase != fakePhrase && g.derived.phrase != strings.ToLower(fakePhrase) {
		if strings.Contains(g.derived.phrase, "bad") {
			return ports.WalletKeys{}, ports.ErrInvalidMnemonic
		}
	}
	p, _ := g.GeneratePayment(nil)
	s, _ := g.GenerateStake(nil)
	g.payCalls, g.stakeCalls = 0, 0
	return ports.WalletKeys{Payment: p, Stake: s}, nil
}

type fakeAddrs struct{}

func (fakeAddrs) BuildAddress(n uint8, p txbuild.KeyHash, s *txbuild.KeyHash) (chain.Address, error) {
	if s == nil {
		return chain.Address(fmt.Sprintf("addr_fake_ent_%d_%x", n, p[:2])), nil
	}
	return chain.Address(fmt.Sprintf("addr_fake_base_%d_%x_%x", n, p[:2], s[:2])), nil
}
func (fakeAddrs) BuildStakeAddress(n uint8, s txbuild.KeyHash) (chain.StakeAddress, error) {
	return chain.StakeAddress(fmt.Sprintf("stake_fake_%d_%x", n, s[:2])), nil
}

func newGenDir(t *testing.T) (ports.NamedStore, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := plainstore.OpenTestnet(dir)
	if err != nil {
		t.Fatal(err)
	}
	return st, dir
}

func dirFiles(t *testing.T, dir string) []string {
	t.Helper()
	es, _ := os.ReadDir(dir)
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

func slurp(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func assertModes(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, n := range names {
		st, err := os.Stat(filepath.Join(dir, n))
		if err != nil || st.Mode().Perm() != 0o400 {
			t.Errorf("%s: mode %v err %v, want 0400", n, st.Mode().Perm(), err)
		}
	}
}

// noKeyMaterial fails when a formatted value or error holds key hex or a
// mnemonic word.
func noKeyMaterial(t *testing.T, what string, v any, err error) {
	t.Helper()
	text := fmt.Sprintf("%v %+v %#v %v", v, v, v, err)
	for _, s := range []string{paySeedHex, stkSeedHex, phraseWord, "Signing Key"} {
		if strings.Contains(text, s) {
			t.Fatalf("%s holds %q: %s", what, s, text)
		}
	}
}

func paymentUC(t *testing.T) (GeneratePaymentAccount, *genFakes, string) {
	st, dir := newGenDir(t)
	g := &genFakes{}
	return GeneratePaymentAccount{Store: st, KeyGen: g, Addresses: fakeAddrs{}, NetworkID: ports.NetworkTestnet}, g, dir
}

// spec: SPO-02-EXT-001, SPO-02-EXT-004, SPO-Pfiles-OUT-001, SPO-Pfiles-OUT-002, SPO-Pfiles-INV-003, SPO-Pfiles-SEC-001
func TestPaymentAccountWritesKeysAndEnterpriseAddress(t *testing.T) {
	uc, _, dir := paymentUC(t)
	res, err := uc.Run(context.Background(), GeneratePaymentRequest{Name: "w"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(dirFiles(t, dir), " "); got != "w.addr w.skey w.vkey" {
		t.Fatalf("files: %s", got)
	}
	assertModes(t, dir, "w.addr", "w.skey", "w.vkey")
	if !strings.HasPrefix(slurp(t, dir, "w.addr"), "addr_fake_ent_0_") || !!strings.HasSuffix(slurp(t, dir, "w.addr"), "\n") {
		t.Fatalf("addr file %q", slurp(t, dir, "w.addr"))
	}
	if slurp(t, dir, "w.addr") != string(res.Address) {
		t.Fatal("result and file disagree")
	}
	// spec: SPO-02-OUT-003, SPO-02-SEC-001
	// Decision: upstream prints the plaintext signing key; fixed, the result
	// holds the verification key and the address only.
	noKeyMaterial(t, "result", res, nil)
}

// spec: SPO-02-IF-002
func TestPaymentAccountNameForms(t *testing.T) {
	for _, in := range []string{"w", "w.addr", "./w.addr"} {
		uc, _, dir := paymentUC(t)
		if _, err := uc.Run(context.Background(), GeneratePaymentRequest{Name: in}); err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got := strings.Join(dirFiles(t, dir), " "); got != "w.addr w.skey w.vkey" {
			t.Fatalf("%s: files %s", in, got)
		}
	}
	uc, _, _ := paymentUC(t)
	if _, err := uc.Run(context.Background(), GeneratePaymentRequest{Name: "sub/w"}); err == nil {
		t.Fatal("a directory part was accepted")
	}
}

// spec: SPO-02-PRE-001
//
// Decision (quirk): upstream exits 2 when any of the four files exists, before
// creating anything. The port does the same and also generates no key.
func TestPaymentAccountRefusesToOverwrite(t *testing.T) {
	for _, existing := range []string{"w.vkey", "w.skey", "w.hwsfile", "w.addr"} {
		uc, g, dir := paymentUC(t)
		os.WriteFile(filepath.Join(dir, existing), []byte("x"), 0o400)
		_, err := uc.Run(context.Background(), GeneratePaymentRequest{Name: "w"})
		if !errors.Is(err, ErrAccountExists) || g.payCalls != 0 || len(dirFiles(t, dir)) != 1 {
			t.Fatalf("%s: err %v calls %d files %v", existing, err, g.payCalls, dirFiles(t, dir))
		}
	}
}

// spec: SPO-02-PRE-002
//
// Decision (quirk): upstream deletes the files on SIGINT between generation
// and the end of the write; the port writes nothing until everything is
// ready and commits all or none, so there is nothing to clean up. A failure
// after generation (here the address builder) leaves no file.
func TestPaymentAccountFailureLeavesNothing(t *testing.T) {
	uc, _, dir := paymentUC(t)
	uc.Addresses = failingAddrs{}
	_, err := uc.Run(context.Background(), GeneratePaymentRequest{Name: "w"})
	if err == nil || len(dirFiles(t, dir)) != 0 {
		t.Fatalf("err %v files %v", err, dirFiles(t, dir))
	}
}

type failingAddrs struct{ fakeAddrs }

func (failingAddrs) BuildAddress(uint8, txbuild.KeyHash, *txbuild.KeyHash) (chain.Address, error) {
	return "", errors.New("no address")
}

// Hardware holders are refused up front; the hardware ids of 02 (EXT-003,
// OUT-002, IF-003) are waived until the hardware signer adapter exists.
func TestPaymentAccountHardwareRefusedUpFront(t *testing.T) {
	uc, g, dir := paymentUC(t)
	_, err := uc.Run(context.Background(), GeneratePaymentRequest{Name: "w", Place: custody.PlaceHardware})
	var ue *custody.UnsupportedError
	if !errors.As(err, &ue) || g.payCalls != 0 || len(dirFiles(t, dir)) != 0 {
		t.Fatalf("err %v", err)
	}
}

func walletUC(t *testing.T) (GenerateWalletAccount, *genFakes, string) {
	st, dir := newGenDir(t)
	g := &genFakes{}
	return GenerateWalletAccount{Store: st, Payment: g, Stake: g, Mnemonics: g, Deriver: g, Addresses: fakeAddrs{}, NetworkID: ports.NetworkMainnet}, g, dir
}

// spec: SPO-03a-EXT-001, SPO-03a-EXT-004, SPO-03a-EXT-005, SPO-03a-OUT-004, SPO-03a-IF-003, SPO-Pfiles-OUT-001, SPO-Pfiles-OUT-002, SPO-Pfiles-INV-003, SPO-Pfiles-IN-003
func TestRandomWalletWritesEightArtefacts(t *testing.T) {
	uc, g, dir := walletUC(t)
	res, err := uc.Run(context.Background(), GenerateWalletRequest{Name: "owner", Source: WalletKeysRandom})
	if err != nil {
		t.Fatal(err)
	}
	want := "owner.payment.addr owner.payment.skey owner.payment.vkey owner.staking.addr owner.staking.skey owner.staking.vkey"
	if got := strings.Join(dirFiles(t, dir), " "); got != want {
		t.Fatalf("files: %s", got)
	}
	assertModes(t, dir, dirFiles(t, dir)...)
	if !strings.HasPrefix(slurp(t, dir, "owner.payment.addr"), "addr_fake_base_1_") || !strings.HasPrefix(slurp(t, dir, "owner.staking.addr"), "stake_fake_1_") {
		t.Fatal("address files")
	}
	if g.deriveCalls != 0 || res.MnemonicStored {
		t.Fatal("random keys must not derive or store a mnemonic")
	}
	// spec: SPO-03a-SEC-001
	// Decision: upstream prints the plaintext signing keys; fixed, never in a result.
	noKeyMaterial(t, "result", res, nil)
}

// spec: SPO-03a-IF-003
//
// Decision (quirk): upstream strips only `.addr` and a leading `./`, so
// `owner.payment` yields `owner.payment.payment.*`. The port keeps that.
func TestWalletNameOnlyLosesAddrAndDotSlash(t *testing.T) {
	uc, _, dir := walletUC(t)
	if _, err := uc.Run(context.Background(), GenerateWalletRequest{Name: "./owner.payment.addr", Source: WalletKeysRandom}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "owner.payment.payment.vkey")); err != nil {
		t.Fatalf("files %v", dirFiles(t, dir))
	}
}

// spec: SPO-03a-PRE-001
//
// Decision (quirk): upstream exits 2 when any of nine names exists, `.staking.cert`
// included, before generating; same here, and nothing is generated.
func TestWalletRefusesToOverwrite(t *testing.T) {
	names := []string{"owner.payment.vkey", "owner.payment.skey", "owner.payment.hwsfile", "owner.payment.addr",
		"owner.staking.vkey", "owner.staking.skey", "owner.staking.hwsfile", "owner.staking.addr", "owner.staking.cert"}
	for _, existing := range names {
		uc, g, dir := walletUC(t)
		os.WriteFile(filepath.Join(dir, existing), []byte("x"), 0o400)
		_, err := uc.Run(context.Background(), GenerateWalletRequest{Name: "owner", Source: WalletKeysRandom})
		if !errors.Is(err, ErrAccountExists) || g.payCalls+g.stakeCalls != 0 || len(dirFiles(t, dir)) != 1 {
			t.Fatalf("%s: err %v files %v", existing, err, dirFiles(t, dir))
		}
	}
}

// spec: SPO-03a-PRE-002, SPO-03a-PRE-001
func TestWalletRefusesWhenMnemonicsFileExists(t *testing.T) {
	uc, g, dir := walletUC(t)
	os.WriteFile(filepath.Join(dir, "owner.payment.mnemonics"), []byte("x"), 0o400)
	_, err := uc.Run(context.Background(), GenerateWalletRequest{Name: "owner", Source: WalletKeysMnemonic})
	if !errors.Is(err, ErrMnemonicsExist) || g.deriveCalls+g.phraseCalls != 0 || len(dirFiles(t, dir)) != 1 {
		t.Fatalf("err %v", err)
	}
	// The mnemonics file only matters for a derived wallet.
	if _, err := uc.Run(context.Background(), GenerateWalletRequest{Name: "owner", Source: WalletKeysRandom}); err != nil {
		t.Fatalf("a random wallet was refused: %v", err)
	}
}

// spec: SPO-03a-EXT-003, SPO-03a-INV-001, SPO-03a-OUT-002, SPO-03a-OUT-003, SPO-03a-OUT-004, SPO-Pfiles-OUT-005, SPO-Pfiles-SEC-001
func TestFreshMnemonicWalletStoresThePhraseAndReturnsNone(t *testing.T) {
	uc, g, dir := walletUC(t)
	res, err := uc.Run(context.Background(), GenerateWalletRequest{Name: "owner", Source: WalletKeysMnemonic, Account: 2, Index: 5})
	if err != nil {
		t.Fatal(err)
	}
	if g.phraseCalls != 1 || g.derived.account != 2 || g.derived.idx != 5 {
		t.Fatalf("derivation: %+v", g.derived)
	}
	if got := slurp(t, dir, "owner.payment.mnemonics"); got != fakePhrase+"\n" {
		t.Fatalf("mnemonics file is not the phrase and a newline (len %d)", len(got))
	}
	if got := strings.Join(dirFiles(t, dir), " "); !strings.Contains(got, "owner.payment.mnemonics") || len(dirFiles(t, dir)) != 7 {
		t.Fatalf("files %s", got)
	}
	assertModes(t, dir, dirFiles(t, dir)...)
	if !res.MnemonicStored {
		t.Fatal("MnemonicStored")
	}
	// spec: SPO-03a-SEC-002, SPO-Pfiles-SEC-003, SPO-03a-SEC-003
	// Decision: upstream prints the 24 words and passes given words on the
	// cardano-signer command line; fixed: the phrase enters and leaves as a
	// *secret.Buffer, is stored under PaymentMnemonics and is shown only by
	// the audited export use case. The file is written at 0400 from the
	// start (no umask window).
	noKeyMaterial(t, "result", res, nil)
}

// spec: SPO-03a-IF-004
//
// Decisions: given words are lowercased and runs of spaces squeezed before
// counting, as upstream does; the count must be 24 and nothing is written
// otherwise. Upstream validates acc and idx for every key type and then
// ignores them for the others; the port refuses a non-zero account, index or
// a mnemonic with random keys instead of ignoring them silently.
func TestGivenMnemonicIsNormalisedAndOptionsValidated(t *testing.T) {
	uc, g, dir := walletUC(t)
	messy := secret.Take([]byte("  " + strings.ToUpper(strings.Repeat(phraseWord+"  ", 24))))
	defer messy.Destroy()
	if _, err := uc.Run(context.Background(), GenerateWalletRequest{Name: "w", Source: WalletKeysMnemonic, Mnemonic: messy}); err != nil {
		t.Fatal(err)
	}
	if g.phraseCalls != 0 || g.derived.phrase != fakePhrase {
		t.Fatal("the given phrase was not normalised or a fresh one was made")
	}
	if slurp(t, dir, "w.payment.mnemonics") != fakePhrase+"\n" {
		t.Fatal("stored phrase")
	}

	uc2, _, dir2 := walletUC(t)
	short := secret.Take([]byte("one two three"))
	defer short.Destroy()
	_, err := uc2.Run(context.Background(), GenerateWalletRequest{Name: "w", Source: WalletKeysMnemonic, Mnemonic: short})
	if !errors.Is(err, custody.ErrMnemonicWords) || len(dirFiles(t, dir2)) != 0 || strings.Contains(err.Error(), "three") {
		t.Fatalf("err %v", err)
	}
	for _, req := range []GenerateWalletRequest{
		{Name: "w", Source: WalletKeysMnemonic, Account: MaxDerivationIndex + 1},
		{Name: "w", Source: WalletKeysMnemonic, Index: 1 << 31},
	} {
		if _, err := uc2.Run(context.Background(), req); !errors.Is(err, ErrDerivationRange) {
			t.Fatalf("range: %v", err)
		}
	}
	if _, err := uc2.Run(context.Background(), GenerateWalletRequest{Name: "w", Source: WalletKeysMnemonic, Account: MaxDerivationIndex, Index: MaxDerivationIndex}); err != nil {
		t.Fatalf("the largest allowed numbers were refused: %v", err)
	}
	uc3, _, _ := walletUC(t)
	for _, req := range []GenerateWalletRequest{
		{Name: "w", Source: WalletKeysRandom, Account: 1},
		{Name: "w", Source: WalletKeysRandom, Index: 1},
		{Name: "w", Source: WalletKeysRandom, Mnemonic: short},
	} {
		if _, err := uc3.Run(context.Background(), req); !errors.Is(err, ErrOptionNotUsed) {
			t.Fatalf("%+v: %v", req.Source, err)
		}
	}
}

// A phrase the deriver rejects writes nothing and the error holds no word.
func TestBadMnemonicWritesNothing(t *testing.T) {
	uc, _, dir := walletUC(t)
	bad := secret.Take([]byte(strings.Repeat("bad ", 24)))
	defer bad.Destroy()
	_, err := uc.Run(context.Background(), GenerateWalletRequest{Name: "w", Source: WalletKeysMnemonic, Mnemonic: bad})
	if !errors.Is(err, ports.ErrInvalidMnemonic) || len(dirFiles(t, dir)) != 0 {
		t.Fatalf("err %v", err)
	}
	noKeyMaterial(t, "error", nil, err)
}

// The caller's buffer is not consumed: it stays usable and the caller
// destroys it.
func TestGivenMnemonicBufferStaysTheCallers(t *testing.T) {
	uc, _, _ := walletUC(t)
	m := secret.Take([]byte(fakePhrase))
	defer m.Destroy()
	if _, err := uc.Run(context.Background(), GenerateWalletRequest{Name: "w", Source: WalletKeysMnemonic, Mnemonic: m}); err != nil {
		t.Fatal(err)
	}
	if m.Len() != len(fakePhrase) {
		t.Fatal("the use case destroyed the caller's buffer")
	}
}

// Hardware, hybrid and remote wallets are refused up front. The hardware ids
// of 03a (EXT-002, OUT-001, IF-005's hardware rows, PRE-... ) are waived until
// the hardware signer adapter exists.
func TestWalletHardwareRefusedUpFront(t *testing.T) {
	uc, g, dir := walletUC(t)
	_, err := uc.Run(context.Background(), GenerateWalletRequest{Name: "w", Source: WalletKeysRandom, Place: custody.PlaceHardware})
	var ue *custody.UnsupportedError
	if !errors.As(err, &ue) || g.payCalls != 0 || len(dirFiles(t, dir)) != 0 {
		t.Fatalf("err %v", err)
	}
}

func TestWalletNotConfigured(t *testing.T) {
	st, _ := newGenDir(t)
	uc := GenerateWalletAccount{Store: st, Addresses: fakeAddrs{}}
	for _, src := range []WalletKeySource{WalletKeysRandom, WalletKeysMnemonic} {
		if _, err := uc.Run(context.Background(), GenerateWalletRequest{Name: "w", Source: src}); !errors.Is(err, ErrNotConfigured) {
			t.Fatalf("%s: %v", src, err)
		}
	}
}
