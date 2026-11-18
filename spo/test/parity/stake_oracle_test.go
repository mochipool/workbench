package parity

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports/porttest"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

func (e env) fileKeyHash(t *testing.T, path string) [28]byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	env, err := pool.ParseEnvelope(b)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := env.Key32()
	if err != nil {
		t.Fatal(err)
	}
	return txbuild.HashKey(raw)
}

type certCase struct {
	name string
	spec stake.Spec
	// cli builds the certificate with cardano-cli into out.
	cli func(e env, t *testing.T, dir, out string)
}

// stakeCertCases lists every certificate kind and every vote-delegation
// target form, with the cardano-cli command that makes the same file.
func (e env) stakeCertCases(t *testing.T, keys keyset) []certCase {
	p := func(n string) string { return filepath.Join(keys.dir, n) }
	stakeHash := e.fileKeyHash(t, p("s.vkey"))
	var poolID chain.PoolID
	for i := range poolID {
		poolID[i] = byte(0xa0 + i)
	}
	poolHex := hex.EncodeToString(poolID[:])
	e.cli(t, lits("node", "key-gen", "--cold-verification-key-file", p("c.vkey"), "--cold-signing-key-file", p("c.skey"), "--operational-certificate-issue-counter-file", p("c.counter"))...)
	coldID, _ := chain.PoolIDOf(rawKey(t, p("c.vkey")))
	e.cli(t, lits("governance", "drep", "key-gen", "--verification-key-file", p("d.vkey"), "--signing-key-file", p("d.skey"))...)
	drepHash := e.fileKeyHash(t, p("d.vkey"))
	var h28 [28]byte
	for i := range h28 {
		h28[i] = byte(i * 7)
	}
	h28hex := hex.EncodeToString(h28[:])
	vote := func(flags ...string) func(env, *testing.T, string, string) {
		return func(e env, t *testing.T, dir, out string) {
			e.cli(t, lits(append([]string{"stake-address", "vote-delegation-certificate", "--stake-verification-key-file", p("s.vkey"), "--out-file", out}, flags...)...)...)
		}
	}
	reg := func(sub string, deposit uint64) func(env, *testing.T, string, string) {
		return func(e env, t *testing.T, dir, out string) {
			e.cli(t, lits("stake-address", sub, "--stake-verification-key-file", p("s.vkey"), "--key-reg-deposit-amt", strconv.FormatUint(deposit, 10), "--out-file", out)...)
		}
	}
	k := stake.KeyHash(stakeHash)
	return []certCase{
		{"registration", stake.Spec{Kind: stake.CertRegistration, Stake: k, Deposit: 2_000_000}, reg("registration-certificate", 2_000_000)},
		{"registration with another deposit", stake.Spec{Kind: stake.CertRegistration, Stake: k, Deposit: 400_000_000_000}, reg("registration-certificate", 400_000_000_000)},
		{"deregistration", stake.Spec{Kind: stake.CertDeregistration, Stake: k, Deposit: 2_000_000}, reg("deregistration-certificate", 2_000_000)},
		{"delegation to a pool id", stake.Spec{Kind: stake.CertPoolDelegation, Stake: k, Pool: poolID}, func(e env, t *testing.T, dir, out string) {
			e.cli(t, lits("stake-address", "stake-delegation-certificate", "--stake-verification-key-file", p("s.vkey"), "--stake-pool-id", poolHex, "--out-file", out)...)
		}},
		{"delegation to a pool id in bech32", stake.Spec{Kind: stake.CertPoolDelegation, Stake: k, Pool: poolID}, func(e env, t *testing.T, dir, out string) {
			e.cli(t, lits("stake-address", "stake-delegation-certificate", "--stake-verification-key-file", p("s.vkey"), "--stake-pool-id", poolID.Bech32(), "--out-file", out)...)
		}},
		{"delegation to a pool by its cold key", stake.Spec{Kind: stake.CertPoolDelegation, Stake: k, Pool: coldID}, func(e env, t *testing.T, dir, out string) {
			e.cli(t, lits("stake-address", "stake-delegation-certificate", "--stake-verification-key-file", p("s.vkey"), "--cold-verification-key-file", p("c.vkey"), "--out-file", out)...)
		}},
		{"vote delegation to a DRep key hash", stake.Spec{Kind: stake.CertVoteDelegation, Stake: k, DRep: stake.DRep{Kind: stake.DRepKey, Hash: h28}}, vote("--drep-key-hash", h28hex)},
		{"vote delegation to a DRep script hash", stake.Spec{Kind: stake.CertVoteDelegation, Stake: k, DRep: stake.DRep{Kind: stake.DRepScript, Hash: h28}}, vote("--drep-script-hash", h28hex)},
		{"vote delegation to a DRep key file", stake.Spec{Kind: stake.CertVoteDelegation, Stake: k, DRep: stake.DRep{Kind: stake.DRepKey, Hash: drepHash}}, vote("--drep-verification-key-file", p("d.vkey"))},
		{"vote delegation to always-abstain", stake.Spec{Kind: stake.CertVoteDelegation, Stake: k, DRep: stake.DRep{Kind: stake.DRepAbstain}}, vote("--always-abstain")},
		{"vote delegation to always-no-confidence", stake.Spec{Kind: stake.CertVoteDelegation, Stake: k, DRep: stake.DRep{Kind: stake.DRepNoConfidence}}, vote("--always-no-confidence")},
	}
}

func rawKey(t *testing.T, path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	env, err := pool.ParseEnvelope(b)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := env.Key32()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Every certificate kind is byte-equal to the file cardano-cli writes for the
// same key and deposit, text envelope included (type, description, cborHex,
// indentation, trailing newline), and reads back as the same certificate.
//
// spec: SPO-Pfiles-OUT-006, SPO-Pfiles-OUT-007, SPO-Pfiles-OUT-008, SPO-Pfiles-OUT-009,
// spec: SPO-03b-EXT-002, SPO-05b-EXT-001, SPO-05b-INV-001, SPO-08a-EXT-002, SPO-22a-EXT-001, SPO-22a-EXT-002,
// spec: SPO-22a-EXT-004, SPO-22a-EXT-005, SPO-06-IN-002, SPO-08b-IN-002, SPO-22b-IN-002
func TestStakeCertificatesMatchCardanoCLI(t *testing.T) {
	e := setup(t)
	keys := e.newKeys(t, false)
	led := native.Ledger{}
	for _, tc := range e.stakeCertCases(t, keys) {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(keys.dir, "x.cert")
			tc.cli(e, t, keys.dir, out)
			want, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			c, err := led.BuildCertificate(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			if string(c.Envelope) != string(want) {
				t.Fatalf("certificate differs\n  cardano-cli: %q\n  go:          %q", want, c.Envelope)
			}
			back, err := led.DecodeCertificate(want)
			if err != nil || back.Spec != tc.spec {
				t.Fatalf("cardano-cli's file reads back as %+v (%v), want %+v", back.Spec, err, tc.spec)
			}
		})
	}
	// The registration and deregistration of 03b and 08a name the stake
	// address, not the key file; the same bytes.
	for _, sub := range []string{"registration-certificate", "deregistration-certificate"} {
		sa := strings.TrimSpace(e.cli(t, lits("stake-address", "build", "--testnet-magic", "2", "--stake-verification-key-file", filepath.Join(keys.dir, "s.vkey"))...))
		out := filepath.Join(keys.dir, "y.cert")
		e.cli(t, lits("stake-address", sub, "--stake-address", sa, "--key-reg-deposit-amt", "2000000", "--out-file", out)...)
		want, _ := os.ReadFile(out)
		kind := stake.CertRegistration
		if sub == "deregistration-certificate" {
			kind = stake.CertDeregistration
		}
		info, err := led.InspectAddress(chain.Address(sa))
		if err != nil || info.StakeKeyHash == nil {
			t.Fatalf("%s: %+v %v", sa, info, err)
		}
		c, err := led.BuildCertificate(stake.Spec{Kind: kind, Stake: stake.KeyHash(*info.StakeKeyHash), Deposit: 2_000_000})
		if err != nil || string(c.Envelope) != string(want) {
			t.Errorf("%s from the stake address differs: %v\n%q\n%q", sub, err, want, c.Envelope)
		}
	}
}

type bodyCase struct {
	name        string
	certs       []stake.Certificate
	withdrawals []txbuild.Withdrawal
	certFiles   []string // cardano-cli --certificate-file paths
}

// Transaction bodies that carry certificates and withdrawals are byte-equal to
// `transaction build-raw`, with the same id, the minimum fee of
// `calculate-min-fee` at two witnesses, the witnesses of the payment and the
// stake key and the assembled transaction.
//
// spec: SPO-Ptx-EXT-001, SPO-Ptx-EXT-002, SPO-Ptx-EXT-004, SPO-Ptx-INV-006, SPO-Ptx-INV-007, SPO-Ptx-EXT-006,
// spec: SPO-03b-INV-002, SPO-06-INV-002, SPO-08b-INV-003, SPO-22b-INV-001, SPO-01claimRewards-INV-001, SPO-01claimRewards-INV-011
func TestStakeTransactionsMatchCardanoCLI(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	params := testParams(t)
	led := native.Ledger{}
	keys := e.newKeys(t, false)
	// The vault is a directory of its own: it holds the payment key `w` and, as
	// <name>.staking.*, the stake key of the wallet `s`. In keys.dir the same stake key
	// is the verification key `s`, and one key under two names would be two wallets
	// holding one identity (ADR 0010).
	vdir := t.TempDir()
	for _, n := range []string{"w.skey", "w.vkey"} {
		b, err := os.ReadFile(filepath.Join(keys.dir, n))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(vdir, n), b, 0o400); err != nil {
			t.Fatal(err)
		}
	}
	store, err := plainstore.OpenTestnet(vdir)
	if err != nil {
		t.Fatal(err)
	}
	signer := native.VaultSigner{Vault: store.Anchor()}
	p := func(n string) string { return filepath.Join(keys.dir, n) }
	// The vault reads the stake key as <name>.staking.skey.
	skeyRaw, _ := os.ReadFile(p("s.skey"))
	if err := os.WriteFile(filepath.Join(vdir, "w.staking.skey"), skeyRaw, 0o400); err != nil {
		t.Fatal(err)
	}
	vkeyRaw, _ := os.ReadFile(p("s.vkey")) // the verification key beside it (found by identity)
	if err := os.WriteFile(filepath.Join(vdir, "w.staking.vkey"), vkeyRaw, 0o400); err != nil {
		t.Fatal(err)
	}
	payKey := porttest.Key(t, store, custody.RolePayment, "w")
	stakeKey := porttest.Key(t, store, custody.RoleStake, "w")
	stakeAddr := chain.StakeAddress(strings.TrimSpace(e.cli(t, lits("stake-address", "build", "--testnet-magic", "2", "--stake-verification-key-file", p("s.vkey"))...)))
	stakeHash := stake.KeyHash(e.fileKeyHash(t, p("s.vkey")))

	certs := map[string]stake.Certificate{}
	files := map[string]string{}
	for _, tc := range e.stakeCertCases(t, keys) {
		switch tc.name {
		case "registration", "deregistration", "delegation to a pool id", "vote delegation to a DRep key hash", "vote delegation to always-abstain":
		default:
			continue
		}
		out := p(strings.ReplaceAll(tc.name, " ", "-") + ".cert")
		tc.cli(e, t, keys.dir, out)
		c, err := led.BuildCertificate(tc.spec)
		if err != nil {
			t.Fatal(err)
		}
		certs[tc.name], files[tc.name] = c, out
	}
	one := func(n string) bodyCase {
		return bodyCase{name: n, certs: []stake.Certificate{certs[n]}, certFiles: []string{files[n]}}
	}
	cases := []bodyCase{
		one("registration"), one("deregistration"), one("delegation to a pool id"),
		one("vote delegation to a DRep key hash"), one("vote delegation to always-abstain"),
		{name: "withdrawal", withdrawals: []txbuild.Withdrawal{{Reward: stakeAddr, Credential: stakeHash, Amount: 5_123_456}}},
		{name: "registration, vote delegation and withdrawal", certs: []stake.Certificate{certs["registration"], certs["vote delegation to always-abstain"]},
			certFiles:   []string{files["registration"], files["vote delegation to always-abstain"]},
			withdrawals: []txbuild.Withdrawal{{Reward: stakeAddr, Credential: stakeHash, Amount: 7}}},
	}
	h1 := mustTxID(t, "6b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c")
	h2 := mustTxID(t, "0b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c")
	inputs := []chain.Utxo{{TxID: h1, Index: 0, Lovelace: 60_000_000}, {TxID: h2, Index: 3, Lovelace: 40_000_000}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			outs := []txbuild.Output{{Address: keys.base, Lovelace: 97_000_000}}
			spec := txbuild.BodySpec{Inputs: inputs, Outputs: outs, Fee: 200_000, TTL: 123456, Certificates: tc.certs, Withdrawals: tc.withdrawals}
			args := []string{"transaction", "build-raw"}
			for _, in := range inputs {
				args = append(args, "--tx-in", fmt.Sprintf("%s#%d", in.TxID, in.Index))
			}
			args = append(args, "--tx-out", textOut(outs[0]), "--invalid-hereafter", "123456", "--fee", "200000", "--out-file", p("b.txbody"))
			for _, f := range tc.certFiles {
				args = append(args, "--certificate-file", f)
			}
			for _, w := range tc.withdrawals {
				args = append(args, "--withdrawal", fmt.Sprintf("%s+%d", w.Reward, w.Amount))
			}
			e.cli(t, lits(args...)...)
			body, err := led.BuildBody(spec)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := hex.EncodeToString(body.CBOR), cborHexOf(t, p("b.txbody")); got != want {
				t.Fatalf("body differs\n  cardano-cli: %s\n  go:          %s", want, got)
			}
			if id := strings.TrimSpace(e.cli(t, lits("transaction", "txid", "--tx-body-file", p("b.txbody"), "--output-text")...)); id != body.ID.String() {
				t.Errorf("txid %s, cardano-cli %s", body.ID, id)
			}
			out := e.cli(t, lits("transaction", "calculate-min-fee", "--tx-body-file", p("b.txbody"), "--protocol-params-file", lightParameters,
				"--witness-count", "2", "--reference-script-size", "0", "--output-text")...)
			wantFee, _ := strconv.ParseUint(strings.Fields(out)[0], 10, 64)
			if gotFee, err := led.EstimateFee(params, body, stake.StakeWitnesses); err != nil || uint64(gotFee) != wantFee {
				t.Errorf("fee at two witnesses: go %d (%v), cardano-cli %d", gotFee, err, wantFee)
			}

			// Witnesses: payment and stake.
			wPay, err := signer.Witness(ctx, payKey, body)
			if err != nil {
				t.Fatal(err)
			}
			wStake, err := signer.Witness(ctx, stakeKey, body)
			if err != nil {
				t.Fatal(err)
			}
			for n, k := range map[string][]byte{"pay.witness": keys.skeyBytes, "stake.witness": skeyRaw} {
				e.cli(t, append(lits("transaction", "witness", "--tx-body-file", p("b.txbody"), "--out-file", p(n), "--signing-key-file"),
					execx.SecretIn(secret.Take(append([]byte(nil), k...))))...)
			}
			for n, w := range map[string]txbuild.Witness{"pay.witness": wPay, "stake.witness": wStake} {
				if got, want := "825820"+hex.EncodeToString(w.VKey[:])+"5840"+hex.EncodeToString(w.Signature[:]), cborHexOf(t, p(n)); got != want {
					t.Fatalf("%s differs\n  cardano-cli: %s\n  go:          %s", n, want, got)
				}
			}
			e.cli(t, lits("transaction", "assemble", "--tx-body-file", p("b.txbody"), "--witness-file", p("pay.witness"), "--witness-file", p("stake.witness"), "--out-file", p("a.tx"))...)
			signed, err := led.Assemble(body, []txbuild.Witness{wPay, wStake})
			if err != nil {
				t.Fatal(err)
			}
			if got, want := hex.EncodeToString(signed.CBOR), cborHexOf(t, p("a.tx")); got != want {
				t.Fatalf("assembled transaction differs\n  cardano-cli: %s\n  go:          %s", want, got)
			}
			e.cli(t, append(lits("transaction", "sign", "--tx-body-file", p("b.txbody"), "--out-file", p("s.tx"), "--signing-key-file"),
				execx.SecretIn(secret.Take(append([]byte(nil), keys.skeyBytes...))), execx.Lit("--signing-key-file"), execx.SecretIn(secret.Take(append([]byte(nil), skeyRaw...))))...)
			if got, want := hex.EncodeToString(signed.CBOR), cborHexOf(t, p("s.tx")); got != want {
				t.Errorf("signed transaction differs from `transaction sign` with both keys\n  cardano-cli: %s\n  go:          %s", want, got)
			}
			if n, err := led.EstimateSize(body, 2); err != nil || n != len(signed.CBOR) {
				t.Errorf("estimated size %d (%v), signed size %d", n, err, len(signed.CBOR))
			}
		})
	}
}
