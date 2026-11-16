package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/sqlitestore"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// secretHex reads a stored signing key back through the vault and returns
// its cborHex, to look for in the output and in the sealed file.
func secretHex(t *testing.T, dir string, ref ports.Ref) string {
	t.Helper()
	st, err := sqlitestore.Open(filepath.Join(dir, cli.WorkspaceFile), secret.Take([]byte(testPass)))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	buf, err := st.Open(context.Background(), ref)
	if err != nil {
		t.Fatalf("%v: %v", ref, err)
	}
	defer buf.Destroy()
	var h string
	buf.Use(func(b []byte) error {
		if m := regexp.MustCompile(`"cborHex"\s*:\s*"([0-9a-f]+)"`).FindSubmatch(b); m != nil {
			h = string(m[1])
		}
		return nil
	})
	if len(h) < 64 {
		t.Fatalf("no key in %v", ref)
	}
	return h
}

// The whole pool key chain through commands, on a sealed workspace: cold,
// VRF and KES keys, then the operational certificate, offline.
func TestPoolKeyChainThroughCommands(t *testing.T) {
	dir := copyWorkspace(t)
	genesis := writeGenesis(t)
	var all strings.Builder
	step := func(args ...string) string {
		t.Helper()
		out, err := withPass(t, dir, testPass, args...)
		all.WriteString(out)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		return out
	}
	out := step("pool", "keys", "generate", poolName)
	m := regexp.MustCompile(`Pool id \(hex\)\s+([0-9a-f]{56})\nPool id \(bech32\) (pool1\S+)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no pool id:\n%s", out)
	}
	id, err := chain.ParsePoolBech32(m[2])
	if err != nil || hex.EncodeToString(id[:]) != m[1] {
		t.Fatalf("the two forms of the pool id disagree: %v\n%s", err, out)
	}
	step("pool", "vrf", "generate", poolName)
	step("pool", "kes", "generate", poolName)
	out = step("pool", "opcert", "issue", poolName, "--offline", "--shelley-genesis", genesis)
	if !strings.Contains(out, "Issued operational certificate "+poolName+".node-000.opcert with counter 0") {
		t.Fatal(out)
	}
	if _, err := withPass(t, dir, testPass, "pool", "keys", "generate", poolName); err == nil {
		t.Error("cold keys were generated over existing ones")
	}
	step("store", "verify")

	needles := map[string]string{
		"pool name":       poolName,
		"cold signing":    secretHex(t, dir, ports.Ref{Name: poolName, Kind: ports.NodeSKey}),
		"VRF signing":     secretHex(t, dir, ports.Ref{Name: poolName, Kind: ports.VrfSKey}),
		"KES signing":     secretHex(t, dir, ports.Ref{Name: poolName, Kind: ports.KesSKey, Num: 0}),
		"envelope marker": "cborHex",
	}
	raw, err := os.ReadFile(filepath.Join(dir, cli.WorkspaceFile))
	if err != nil {
		t.Fatal(err)
	}
	for what, n := range needles {
		if bytes.Contains(raw, []byte(n)) {
			t.Errorf("workspace.spo contains the %s", what)
		}
		if what != "pool name" && what != "envelope marker" {
			notLeaked(t, all.String(), n)
		}
	}
	notLeaked(t, all.String(), testPass, "SigningKey")
}

const abandonArt = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

// cardano-signer's enterprise address of the phrase at 1852H/1815H/0H/0/0 on
// mainnet (internal/adapters/native/software_keys_test.go).
const abandonMainnetEnterprise = "addr1vyqt0pru382hy9vjlsxv3ye02z50sfvt8xunscg5pgden7czra7te"

func TestWalletNewThroughCommands(t *testing.T) {
	dir := copyWorkspace(t)
	var all strings.Builder
	step := func(term *fakeTerm, args ...string) string {
		t.Helper()
		pf, pfd := fdIn(t, testPass+"\n")
		defer pf.Close()
		out, err := exec(t, term, append([]string{"-C", dir, "--passphrase-fd", pfd}, args...)...)
		all.WriteString(out)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		return out
	}
	addrRE := func(label string) *regexp.Regexp { return regexp.MustCompile(`(?m)^` + label + `\s+(\S+)$`) }

	out := step(nil, "wallet", "new", "w")
	wAddr := addrRE("Address").FindStringSubmatch(out)
	if wAddr == nil || !strings.HasPrefix(wAddr[1], "addr_test1v") {
		t.Fatalf("enterprise address:\n%s", out)
	}
	out = step(nil, "wallet", "new", "s", "--stake")
	sBase, sStake := addrRE("Payment address").FindStringSubmatch(out), addrRE("Stake address").FindStringSubmatch(out)
	if sBase == nil || sStake == nil || !strings.HasPrefix(sBase[1], "addr_test1q") || !strings.HasPrefix(sStake[1], "stake_test1u") {
		t.Fatalf("base and stake addresses:\n%s", out)
	}

	// The public test phrase on a descriptor: account 0 index 0 is the
	// recorded vector, on the testnet network.
	pf, pfd := fdIn(t, abandonArt+"\n")
	defer pf.Close()
	out = step(nil, "wallet", "new", "m", "--mnemonic-in-fd", pfd)
	mBase, mStake := addrRE("Payment address").FindStringSubmatch(out), addrRE("Stake address").FindStringSubmatch(out)
	if mBase == nil || mStake == nil {
		t.Fatalf("addresses:\n%s", out)
	}
	_, mainPayload, err := chain.Bech32Decode(abandonMainnetEnterprise)
	if err != nil || mainPayload[0] != 0x61 {
		t.Fatalf("the vector: %v", err)
	}
	hrp, basePayload, err := chain.Bech32Decode(mBase[1])
	if err != nil || hrp != "addr_test" || basePayload[0] != 0x00 || !bytes.Equal(basePayload[1:29], mainPayload[1:]) {
		t.Fatalf("base address %s is not the vector's payment credential on testnet (%v)", mBase[1], err)
	}
	if !strings.HasPrefix(mStake[1], "stake_test1u") {
		t.Errorf("stake address %s", mStake[1])
	}
	// The same phrase and path again is refused: the wallet exists.
	pf2, pfd2 := fdIn(t, abandonArt+"\n")
	defer pf2.Close()
	if _, err := exec(t, nil, "-C", dir, "--passphrase-fd", func() string { f, fd := fdIn(t, testPass+"\n"); _ = f; return fd }(),
		"wallet", "new", "m", "--mnemonic-in-fd", pfd2); err == nil {
		t.Error("an existing wallet was overwritten")
	}

	// A generated phrase is stored and not shown.
	out = step(nil, "wallet", "new", "g", "--mnemonic", "--account", "3", "--index", "4")
	if !strings.Contains(out, "stored sealed") || !strings.Contains(out, "not shown") {
		t.Errorf("no note about the phrase:\n%s", out)
	}
	if n := len(regexp.MustCompile(`\b[a-z]{3,8}\b`).FindAllString(out, -1)); n > 80 {
		t.Errorf("output looks like it holds a phrase (%d words):\n%s", n, out)
	}

	out = step(nil, "capabilities")
	for _, want := range []string{"cold-keygen", "payment-keygen", "stake-keygen", "mnemonic-generation", "wallet-derivation", "address-building"} {
		if !strings.Contains(out, want) {
			t.Errorf("capabilities lack %s:\n%s", want, out)
		}
	}

	// The wiring still carries a payment: w sends the least to s's base address.
	transfer := filepath.Join(t.TempDir(), "offlineTransfer.json")
	writeTransferFile(t, transfer, wAddr[1])
	out = step(nil, "wallet", "send", "w", sBase[1], "MIN", "--yes", "--transfer-file", transfer, "--shelley-genesis", writeGenesis(t))
	if !regexp.MustCompile(`Queued transaction [0-9a-f]{64} in `).MatchString(out) {
		t.Fatalf("nothing queued:\n%s", out)
	}
	if b, _ := os.ReadFile(transfer); !strings.Contains(string(b), `"transactions"`) {
		t.Error("the transaction is not in the transfer file")
	}

	notLeaked(t, all.String(), testPass, "abandon", "SigningKey", "cborHex")
	raw, err := os.ReadFile(filepath.Join(dir, cli.WorkspaceFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"abandon", wAddr[1], sBase[1], mBase[1], "SigningKey", "cborHex"} {
		if bytes.Contains(raw, []byte(n)) {
			t.Errorf("workspace.spo contains %q", n)
		}
	}
}
