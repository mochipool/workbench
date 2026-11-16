package native

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/go-bip39"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

type env3 struct{ Type, Description, CborHex string }

func parse(t *testing.T, b []byte) env3 {
	t.Helper()
	var e struct {
		Type        string `json:"type"`
		Description string `json:"description"`
		CborHex     string `json:"cborHex"`
	}
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatal(err)
	}
	return env3(e)
}

func skeyBytes(t *testing.T, s *secret.Buffer) []byte {
	t.Helper()
	var out []byte
	if err := s.Use(func(b []byte) error { out = append([]byte(nil), b...); return nil }); err != nil {
		t.Fatal(err)
	}
	return out
}

// The envelope written straight into guarded memory has the bytes the shared
// envelope() helper renders.
func TestSecretEnvelopeEqualsEnvelope(t *testing.T) {
	key := bytes.Repeat([]byte{0xab}, 32)
	want, err := envelope(bursa.KeyFile{Type: "T", Description: "D x", CborHex: "5820" + hex.EncodeToString(key)})
	if err != nil {
		t.Fatal(err)
	}
	sb, err := secretEnvelope("T", "D x", key)
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Destroy()
	if got := skeyBytes(t, sb); !bytes.Equal(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

// spec: SPO-04a-EXT-001, SPO-02-EXT-001, SPO-03a-EXT-001, SPO-03a-EXT-004
func TestRandomKeysAreWellFormed(t *testing.T) {
	ctx := context.Background()
	k := SoftwareKeys{}
	cases := []struct {
		name         string
		gen          func(context.Context) (ports.KeyPair, error)
		vType, sType string
	}{
		{"cold", k.GenerateCold, coldVType, coldSType},
		{"payment", k.GeneratePayment, payVType, paySType},
		{"stake", k.GenerateStake, stkVType, stkSType},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, err := c.gen(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer a.SKey.Destroy()
			b, _ := c.gen(ctx)
			defer b.SKey.Destroy()
			v, s := parse(t, a.VKey), parse(t, skeyBytes(t, a.SKey))
			if v.Type != c.vType || s.Type != c.sType || !strings.HasPrefix(v.CborHex, "5820") || len(v.CborHex) != 68 || len(s.CborHex) != 68 {
				t.Fatalf("envelopes: %+v %+v", v, s)
			}
			seed, _ := hex.DecodeString(s.CborHex[4:])
			pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
			if hex.EncodeToString(pub) != v.CborHex[4:] {
				t.Fatal("verification key is not the public key of the signing key")
			}
			if bytes.Equal(a.VKey, b.VKey) {
				t.Fatal("two generations gave the same key")
			}
		})
	}
}

// spec: SPO-03a-EXT-003
func TestGenerateMnemonic(t *testing.T) {
	k := SoftwareKeys{}
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		m, err := k.GenerateMnemonic(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		phrase := string(skeyBytes(t, m))
		m.Destroy()
		if len(strings.Fields(phrase)) != 24 || strings.Contains(phrase, "  ") || strings.HasSuffix(phrase, "\n") {
			t.Fatalf("shape: %d words", len(strings.Fields(phrase)))
		}
		if !bip39.IsMnemonicValid(phrase) {
			t.Fatal("checksum invalid")
		}
		if seen[phrase] {
			t.Fatal("repeated phrase")
		}
		seen[phrase] = true
	}
}

// The phrase and the paths are the ones cardano-signer 1.35.0 was run with;
// the expected values are its output (the parity test repeats the check
// against the live tool).
const testPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

func TestDeriveWalletRecordedVectors(t *testing.T) {
	m := secret.Take([]byte(testPhrase))
	defer m.Destroy()
	keys, err := SoftwareKeys{}.DeriveWallet(context.Background(), m, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Payment.SKey.Destroy()
	defer keys.Stake.SKey.Destroy()
	// cardano-signer keygen --path 1852H/1815H/0H/0/0: enterprise address
	// addr1vyqt0pru382hy9vjlsxv3ye02z50sfvt8xunscg5pgden7czra7te.
	v := parse(t, keys.Payment.VKey)
	raw, _ := hex.DecodeString(v.CborHex[4:])
	addr, err := Ledger{}.BuildAddress(ports.NetworkMainnet, txbuild.HashKey(raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "addr1vyqt0pru382hy9vjlsxv3ye02z50sfvt8xunscg5pgden7czra7te" {
		t.Fatalf("payment 0/0 address = %s", addr)
	}
	s := parse(t, skeyBytes(t, keys.Payment.SKey))
	if s.Type != "PaymentExtendedSigningKeyShelley_ed25519_bip32" || s.Description != "Payment Signing Key" || !strings.HasPrefix(s.CborHex, "5880") || len(s.CborHex) != 260 {
		t.Fatalf("payment skey envelope: %s %s %d", s.Type, s.Description, len(s.CborHex))
	}
	if v.Type != payVType || v.Description != payVDesc {
		t.Fatalf("payment vkey envelope: %+v", v)
	}

	// account 1, index 3: stake1u85043y8j8hwdpcesppe9csnx82gzxx5nkzc2lqfkmlywqqkfasql
	keys2, err := SoftwareKeys{}.DeriveWallet(context.Background(), m, 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer keys2.Payment.SKey.Destroy()
	defer keys2.Stake.SKey.Destroy()
	sv := parse(t, keys2.Stake.VKey)
	sraw, _ := hex.DecodeString(sv.CborHex[4:])
	reward, err := Ledger{}.BuildStakeAddress(ports.NetworkMainnet, txbuild.HashKey(sraw))
	if err != nil {
		t.Fatal(err)
	}
	if reward != "stake1u85043y8j8hwdpcesppe9csnx82gzxx5nkzc2lqfkmlywqqkfasql" {
		t.Fatalf("stake 1/3 address = %s", reward)
	}
	if sv.Type != stkVType || sv.Description != stkVDesc {
		t.Fatalf("stake vkey envelope: %+v", sv)
	}
}

func TestDeriveWalletRefusesABadPhraseWithoutEchoingIt(t *testing.T) {
	bad := strings.Replace(testPhrase, " art", " zoo", 1) // valid words, wrong checksum
	m := secret.Take([]byte(bad))
	defer m.Destroy()
	_, err := SoftwareKeys{}.DeriveWallet(context.Background(), m, 0, 0)
	if !errors.Is(err, ports.ErrInvalidMnemonic) || strings.Contains(err.Error(), "abandon") {
		t.Fatalf("err = %v", err)
	}
}

func TestBuildAddressKinds(t *testing.T) {
	var h, s txbuild.KeyHash
	for i := range h {
		h[i], s[i] = byte(i), byte(100+i)
	}
	ent, _ := Ledger{}.BuildAddress(ports.NetworkTestnet, h, nil)
	base, _ := Ledger{}.BuildAddress(ports.NetworkMainnet, h, &s)
	rew, _ := Ledger{}.BuildStakeAddress(ports.NetworkTestnet, s)
	for addr, prefix := range map[string]string{string(ent): "addr_test1v", string(base): "addr1q", string(rew): "stake_test1u"} {
		if !strings.HasPrefix(addr, prefix) {
			t.Errorf("%s lacks prefix %s", addr, prefix)
		}
	}
	info, err := Ledger{}.InspectAddress(chain.Address(base))
	if err != nil || info.Kind != ports.AddrBase || *info.PaymentKeyHash != h || *info.StakeKeyHash != s {
		t.Fatalf("base round trip: %+v %v", info, err)
	}
	if _, err := (Ledger{}).BuildAddress(7, h, nil); err == nil {
		t.Fatal("an unknown network id was accepted")
	}
}
