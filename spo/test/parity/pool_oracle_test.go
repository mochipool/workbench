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
	"github.com/mochipool/workbench/spo/test/plainstore"
)

// poolKit holds the keys of a pool made by cardano-cli: the cold and VRF
// keys and three stake keys, in a directory the vault reads as a store.
type poolKit struct {
	dir string
	e   env
}

func (e env) newPoolKit(t *testing.T) poolKit {
	dir := t.TempDir()
	p := func(n string) string { return filepath.Join(dir, n) }
	e.cli(t, lits("node", "key-gen", "--cold-verification-key-file", p("pp.node.vkey"), "--cold-signing-key-file", p("pp.node.skey"),
		"--operational-certificate-issue-counter-file", p("pp.node.counter"))...)
	e.cli(t, lits("node", "key-gen-VRF", "--verification-key-file", p("pp.vrf.vkey"), "--signing-key-file", p("pp.vrf.skey"))...)
	for _, n := range []string{"a", "b", "c"} {
		e.cli(t, lits("stake-address", "key-gen", "--verification-key-file", p(n+".staking.vkey"), "--signing-key-file", p(n+".staking.skey"))...)
	}
	e.cli(t, lits("address", "key-gen", "--verification-key-file", p("pay.vkey"), "--signing-key-file", p("pay.skey"))...)
	return poolKit{dir: dir, e: e}
}

func (k poolKit) p(n string) string { return filepath.Join(k.dir, n) }

// poolCase is one registration certificate, as the descriptor says it.
type poolCase struct {
	name          string
	pledge, cost  string
	margin        string
	owners        []string // key names: a, b, c
	reward        string
	relays        []pool.DescriptorRelay
	meta          bool
	mainnet       bool
	wantRefusedGo bool
}

func (k poolKit) specOf(t *testing.T, c poolCase) (pool.RegistrationSpec, []string) {
	t.Helper()
	cold := rawKey(t, k.p("pp.node.vkey"))
	id, _ := chain.PoolIDOf(cold)
	spec := pool.RegistrationSpec{Operator: id, VrfKeyHash: pool.VrfHash(rawKey(t, k.p("pp.vrf.vkey")))}
	var err error
	if spec.Pledge, err = pool.ParseLovelace(c.pledge); err != nil {
		t.Fatal(err)
	}
	if spec.Cost, err = pool.ParseLovelace(c.cost); err != nil {
		t.Fatal(err)
	}
	if spec.Margin, err = pool.ParseMargin(c.margin); err != nil {
		t.Fatal(err)
	}
	spec.RewardAccount = stake.KeyHash(txbuild.HashKey(rawKey(t, k.p(c.reward+".staking.vkey"))))
	if c.mainnet {
		spec.NetworkID = 1
	}
	args := []string{"stake-pool", "registration-certificate", "--cold-verification-key-file", k.p("pp.node.vkey"),
		"--vrf-verification-key-file", k.p("pp.vrf.vkey"), "--pool-pledge", c.pledge, "--pool-cost", c.cost, "--pool-margin", c.margin,
		"--pool-reward-account-verification-key-file", k.p(c.reward + ".staking.vkey")}
	for _, o := range c.owners {
		spec.Owners = append(spec.Owners, stake.KeyHash(txbuild.HashKey(rawKey(t, k.p(o+".staking.vkey")))))
		args = append(args, "--pool-owner-stake-verification-key-file", k.p(o+".staking.vkey"))
	}
	for _, r := range c.relays {
		rel, err := pool.ParseRelay(r)
		if err != nil {
			t.Fatal(err)
		}
		spec.Relays = append(spec.Relays, rel)
		switch rel.Kind {
		case pool.RelayIPv4:
			args = append(args, "--pool-relay-ipv4", r.Entry, "--pool-relay-port", r.Port)
		case pool.RelayIPv6:
			args = append(args, "--pool-relay-ipv6", r.Entry, "--pool-relay-port", r.Port)
		case pool.RelayDNS:
			args = append(args, "--single-host-pool-relay", r.Entry, "--pool-relay-port", r.Port)
		case pool.RelaySRV:
			args = append(args, "--multi-host-pool-relay", r.Entry)
		}
	}
	if c.meta {
		doc := pool.Metadata{Name: "Pool Name", Description: "A pool for the oracle", Ticker: "ORCL", Homepage: "https://example.org"}.Render()
		if err := os.WriteFile(k.p("meta.json"), doc, 0o600); err != nil {
			t.Fatal(err)
		}
		hashHex := strings.TrimSpace(k.e.cli(t, lits("stake-pool", "metadata-hash", "--pool-metadata-file", k.p("meta.json"))...))
		h, err := native.Ledger{}.MetadataHash(doc)
		if err != nil || hex.EncodeToString(h[:]) != hashHex {
			t.Fatalf("metadata hash: go %x (%v), cardano-cli %s", h, err, hashHex)
		}
		spec.MetaURL, spec.MetaHash = "https://example.org/pool.metadata.json", h
		args = append(args, "--metadata-url", spec.MetaURL, "--metadata-hash", hashHex)
	}
	net := []string{"--testnet-magic", "2"}
	if c.mainnet {
		net = []string{"--mainnet"}
	}
	return spec, append(append(args, net...), "--out-file")
}

// The pool registration and retirement certificates are byte-equal to
// cardano-cli's, text envelope included, for one owner and three, every relay
// type and a mix, with and without metadata, margins as upstream passes them,
// pledge and cost edge values, and a reward account that is an owner or not.
// The metadata hash and the pool id forms equal cardano-cli's too.
//
// spec: SPO-05a-EXT-001, SPO-05a-EXT-002, SPO-05a-EXT-004, SPO-05a-EXT-005, SPO-05a-OUT-008, SPO-05a-PRE-005, SPO-05a-PRE-007, SPO-05a-INV-002,
// spec: SPO-07a-EXT-001, SPO-Pfiles-OUT-018, SPO-Pfiles-OUT-019, SPO-Pfiles-OUT-020
func TestPoolCertificatesMatchCardanoCLI(t *testing.T) {
	e := setup(t)
	k := e.newPoolKit(t)
	ip4 := pool.DescriptorRelay{Type: "IPv4", Entry: "203.0.113.7", Port: "3001"}
	ip6 := pool.DescriptorRelay{Type: "ip6", Entry: "2001:db8::1", Port: "6000"}
	dns := pool.DescriptorRelay{Type: "DNS", Entry: "relay.example.org", Port: "3001"}
	srv := pool.DescriptorRelay{Type: "multisrv", Entry: "_cardano._tcp.example.org"}
	cases := []poolCase{
		{name: "one owner, one relay", pledge: "100000000000", cost: "340000000", margin: "0.10", owners: []string{"a"}, reward: "a", relays: []pool.DescriptorRelay{ip4}, meta: true},
		{name: "three owners, unsorted", pledge: "1", cost: "170000000", margin: "0.05", owners: []string{"c", "a", "b"}, reward: "b", relays: []pool.DescriptorRelay{dns}, meta: true},
		{name: "reward account is not an owner", pledge: "0", cost: "340000000", margin: "0", owners: []string{"a", "b"}, reward: "c", relays: []pool.DescriptorRelay{ip4}},
		{name: "IPv6 relay", pledge: "500000000", cost: "340000000", margin: "0.01", owners: []string{"a"}, reward: "a", relays: []pool.DescriptorRelay{ip6}, meta: true},
		{name: "DNS relay", pledge: "500000000", cost: "340000000", margin: "1", owners: []string{"a"}, reward: "a", relays: []pool.DescriptorRelay{dns}},
		{name: "SRV relay", pledge: "500000000", cost: "340000000", margin: "1.00", owners: []string{"a"}, reward: "a", relays: []pool.DescriptorRelay{srv}, meta: true},
		{name: "a mix of relays", pledge: "500000000", cost: "340000000", margin: "0.333333", owners: []string{"a", "b", "c"}, reward: "c", relays: []pool.DescriptorRelay{ip4, dns, ip6, srv}, meta: true},
		{name: "no relays, no metadata", pledge: "500000000", cost: "340000000", margin: "0.5", owners: []string{"a"}, reward: "a"},
		{name: "margin with many digits", pledge: "500000000", cost: "340000000", margin: "0.123456789", owners: []string{"a"}, reward: "a", relays: []pool.DescriptorRelay{ip4}},
		{name: "mainnet reward account", pledge: "500000000", cost: "340000000", margin: "0.02", owners: []string{"a"}, reward: "a", relays: []pool.DescriptorRelay{ip4}, mainnet: true, meta: true},
		{name: "large pledge and cost", pledge: "18446744073709551615", cost: "4294967296", margin: "0.99", owners: []string{"a"}, reward: "a", relays: []pool.DescriptorRelay{ip4}},
		{name: "duplicate owner", pledge: "1", cost: "340000000", margin: "0.2", owners: []string{"a", "b", "a"}, reward: "a", relays: []pool.DescriptorRelay{ip4}},
	}
	led := native.Ledger{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec, args := k.specOf(t, c)
			out := k.p(strings.ReplaceAll(c.name, " ", "_") + ".cert")
			e.cli(t, lits(append(args, out)...)...)
			got, err := led.BuildPoolRegistration(spec)
			if err != nil {
				t.Fatal(err)
			}
			want, _ := os.ReadFile(out)
			if string(got.Envelope) != string(want) {
				t.Fatalf("certificate differs\n  cardano-cli: %s\n  go:          %s", want, got.Envelope)
			}
			back, err := led.DecodePoolCertificate(want)
			if err != nil || string(back.CBOR) != string(got.CBOR) {
				t.Errorf("the certificate file does not read back: %v", err)
			}
		})
	}

	// Adjacent IPv4 and IPv6 relays: cardano-cli refuses, so does the port.
	{
		_, args := k.specOf(t, poolCase{pledge: "1", cost: "340000000", margin: "0.1", owners: []string{"a"}, reward: "a", relays: []pool.DescriptorRelay{ip4}})
		args = append(args[:len(args)-3:len(args)-3], "--pool-relay-ipv6", "2001:db8::1", "--pool-relay-port", "2", "--testnet-magic", "2", "--out-file", k.p("adj.cert"))
		_, cliErr := execx.OS{}.Run(context.Background(), execx.Cmd{Path: e.cliPath(t), Args: execx.Lits(append([]string{"conway"}, args...)...)})
		if cliErr == nil {
			t.Errorf("cardano-cli accepted adjacent IPv4 and IPv6 relays")
		}
		if err := pool.CheckRelays(([]pool.Relay{{Kind: pool.RelayIPv4}, {Kind: pool.RelayIPv6}})); err == nil {
			t.Errorf("the port accepted adjacent IPv4 and IPv6 relays")
		}
	}

	// The pool id in both forms.
	cold := rawKey(t, k.p("pp.node.vkey"))
	id, _ := chain.PoolIDOf(cold)
	if got, want := hex.EncodeToString(id[:]), strings.TrimSpace(e.cli(t, lits("stake-pool", "id", "--cold-verification-key-file", k.p("pp.node.vkey"), "--output-hex")...)); got != want {
		t.Errorf("pool id hex %s, cardano-cli %s", got, want)
	}
	if got, want := id.Bech32(), strings.TrimSpace(e.cli(t, lits("stake-pool", "id", "--cold-verification-key-file", k.p("pp.node.vkey"), "--output-bech32")...)); got != want {
		t.Errorf("pool id bech32 %s, cardano-cli %s", got, want)
	}

	// The retirement certificate.
	for _, epoch := range []uint64{1, 300, 4294967296} {
		out := k.p(fmt.Sprintf("retire-%d.cert", epoch))
		e.cli(t, lits("stake-pool", "deregistration-certificate", "--cold-verification-key-file", k.p("pp.node.vkey"), "--epoch", strconv.FormatUint(epoch, 10), "--out-file", out)...)
		got, err := led.BuildPoolRetirement(pool.RetirementSpec{Pool: id, Epoch: epoch})
		if err != nil {
			t.Fatal(err)
		}
		want, _ := os.ReadFile(out)
		if string(got.Envelope) != string(want) {
			t.Errorf("retirement at epoch %d differs\n  cardano-cli: %s\n  go:          %s", epoch, want, got.Envelope)
		}
		if back, err := led.DecodePoolCertificate(want); err != nil || back.Retirement == nil || back.Retirement.Epoch != epoch {
			t.Errorf("the retirement file does not read back: %v", err)
		}
	}

	// Metadata cardano-cli refuses, the port refuses too.
	for name, doc := range map[string]string{
		"not json":                 "{",
		"no ticker":                `{"name":"n","description":"d","homepage":"https://x"}`,
		"over 512 bytes":           `{"name":"n","description":"` + strings.Repeat("d", 600) + `","ticker":"TICK","homepage":"https://x"}`,
		"description not a string": `{"name":"n","description":3,"ticker":"TICK","homepage":"https://x"}`,
	} {
		if err := os.WriteFile(k.p("bad.json"), []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		_, cliErr := execx.OS{}.Run(context.Background(), execx.Cmd{Path: e.cliPath(t), Args: execx.Lits("conway", "stake-pool", "metadata-hash", "--pool-metadata-file", k.p("bad.json"))})
		_, goErr := led.MetadataHash([]byte(doc))
		if (cliErr != nil) != (goErr != nil) {
			t.Errorf("metadata %s: cardano-cli error %v, go error %v", name, cliErr, goErr)
		}
	}
}

func (e env) cliPath(t *testing.T) string {
	tool, err := e.tc.Tool(context.Background(), "cardano-cli")
	if err != nil {
		t.Fatal(err)
	}
	return tool.Path
}

// A body that carries the pool certificates is byte-equal to `build-raw`; the
// fee at the witness counts of the spec (2 + owners for a registration, 2 for
// a retirement) equals `calculate-min-fee`; the cold, payment and owner
// witnesses and the assembled transaction equal cardano-cli's.
//
// spec: SPO-05c-INV-004, SPO-05c-INV-005, SPO-05c-INV-007, SPO-05c-EXT-003, SPO-05c-EXT-004, SPO-05c-EXT-006, SPO-05c-EXT-007,
// spec: SPO-07b-INV-001, SPO-07b-EXT-002, SPO-Ptx-EXT-001, SPO-Ptx-EXT-002, SPO-Ptx-EXT-004
func TestPoolTransactionsMatchCardanoCLI(t *testing.T) {
	e := setup(t)
	k := e.newPoolKit(t)
	ctx := context.Background()
	params := testParams(t)
	led := native.Ledger{}
	store, err := plainstore.OpenTestnet(k.dir)
	if err != nil {
		t.Fatal(err)
	}
	signer := native.VaultSigner{Vault: store}
	// The vault reads the payment key as <name>.skey and the cold key as <pool>.node.skey.
	payAddr := chain.Address(strings.TrimSpace(e.cli(t, lits("address", "build", "--testnet-magic", "2", "--payment-verification-key-file", k.p("pay.vkey"))...)))
	cold := rawKey(t, k.p("pp.node.vkey"))
	id, _ := chain.PoolIDOf(cold)

	reg := poolCase{pledge: "500000000", cost: "340000000", margin: "0.05", owners: []string{"c", "a", "b"}, reward: "b",
		relays: []pool.DescriptorRelay{{Type: "ip", Entry: "203.0.113.7", Port: "3001"}, {Type: "dns", Entry: "r.example.org", Port: "3001"}}, meta: true}
	spec, args := k.specOf(t, reg)
	e.cli(t, lits(append(args, k.p("reg.cert"))...)...)
	regCert, err := led.BuildPoolRegistration(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range []string{"a", "b", "c"} {
		e.cli(t, lits("stake-address", "stake-delegation-certificate", "--stake-verification-key-file", k.p(o+".staking.vkey"), "--stake-pool-id", hex.EncodeToString(id[:]), "--out-file", k.p(o+".deleg.cert"))...)
	}
	e.cli(t, lits("stake-pool", "deregistration-certificate", "--cold-verification-key-file", k.p("pp.node.vkey"), "--epoch", "123", "--out-file", k.p("dereg.cert"))...)
	dereg, _ := led.BuildPoolRetirement(pool.RetirementSpec{Pool: id, Epoch: 123})

	deleg := func(o string) stake.Certificate {
		raw, _ := os.ReadFile(k.p(o + ".deleg.cert"))
		c, err := led.DecodeCertificate(raw)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	type txc struct {
		name      string
		certs     []stake.Certificate
		files     []string
		witnesses uint
		keys      []string // witness slots in order
	}
	cases := []txc{
		{name: "first registration", certs: []stake.Certificate{regCert.Attachment(500_000_000), deleg("c"), deleg("a"), deleg("b")},
			files: []string{k.p("reg.cert"), k.p("c.deleg.cert"), k.p("a.deleg.cert"), k.p("b.deleg.cert")}, witnesses: 2 + 3, keys: []string{"cold", "pay", "c", "a", "b"}},
		{name: "re-registration", certs: []stake.Certificate{regCert.Attachment(0), deleg("c"), deleg("a"), deleg("b")},
			files: []string{k.p("reg.cert"), k.p("c.deleg.cert"), k.p("a.deleg.cert"), k.p("b.deleg.cert")}, witnesses: 2 + 3, keys: []string{"cold", "pay", "c", "a", "b"}},
		{name: "registration certificate only", certs: []stake.Certificate{regCert.Attachment(0)}, files: []string{k.p("reg.cert")}, witnesses: 2 + 3, keys: []string{"cold", "pay", "c", "a", "b"}},
		{name: "retirement", certs: []stake.Certificate{dereg.Attachment(0)}, files: []string{k.p("dereg.cert")}, witnesses: 2, keys: []string{"cold", "pay"}},
	}
	h1 := mustTxID(t, "6b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c")
	inputs := []chain.Utxo{{TxID: h1, Index: 0, Lovelace: 700_000_000}}
	keyRef := func(s string) (custody.KeyRef, string, [28]byte) {
		switch s {
		case "cold":
			return custody.KeyRef{Role: custody.RolePoolCold, Holder: custody.HolderVault, Owner: "pp"}, k.p("pp.node.skey"), id
		case "pay":
			return custody.KeyRef{Role: custody.RolePayment, Holder: custody.HolderVault, Owner: "pay"}, k.p("pay.skey"), txbuild.HashKey(rawKey(t, k.p("pay.vkey")))
		}
		return custody.KeyRef{Role: custody.RoleStake, Holder: custody.HolderVault, Owner: s}, k.p(s + ".staking.skey"), txbuild.HashKey(rawKey(t, k.p(s+".staking.vkey")))
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			outs := []txbuild.Output{{Address: payAddr, Lovelace: 100_000_000}}
			bs := txbuild.BodySpec{Inputs: inputs, Outputs: outs, Fee: 200_000, TTL: 123456, Certificates: tc.certs}
			args := []string{"transaction", "build-raw", "--tx-in", fmt.Sprintf("%s#0", h1), "--tx-out", textOut(outs[0]), "--invalid-hereafter", "123456",
				"--fee", "200000", "--out-file", k.p("b.txbody")}
			for _, f := range tc.files {
				args = append(args, "--certificate-file", f)
			}
			e.cli(t, lits(args...)...)
			body, err := led.BuildBody(bs)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := hex.EncodeToString(body.CBOR), cborHexOf(t, k.p("b.txbody")); got != want {
				t.Fatalf("body differs\n  cardano-cli: %s\n  go:          %s", want, got)
			}
			out := e.cli(t, lits("transaction", "calculate-min-fee", "--tx-body-file", k.p("b.txbody"), "--protocol-params-file", lightParameters,
				"--witness-count", strconv.Itoa(int(tc.witnesses)), "--reference-script-size", "0", "--output-text")...)
			wantFee, _ := strconv.ParseUint(strings.Fields(out)[0], 10, 64)
			if gotFee, err := led.EstimateFee(params, body, tc.witnesses); err != nil || uint64(gotFee) != wantFee {
				t.Errorf("fee at %d witnesses: go %d (%v), cardano-cli %d", tc.witnesses, gotFee, err, wantFee)
			}
			var ws []txbuild.Witness
			var files []string
			for i, s := range tc.keys {
				ref, skeyFile, hash := keyRef(s)
				w, err := signer.Witness(ctx, ref, body)
				if err != nil {
					t.Fatal(err)
				}
				if err := txbuild.VerifyWitness(body, w, hash); err != nil {
					t.Fatalf("%s: %v", s, err)
				}
				raw, _ := os.ReadFile(skeyFile)
				wf := k.p(fmt.Sprintf("w%d.witness", i))
				e.cli(t, append(lits("transaction", "witness", "--tx-body-file", k.p("b.txbody"), "--out-file", wf, "--signing-key-file"),
					execx.SecretIn(secret.Take(append([]byte(nil), raw...))))...)
				if got, want := "5820"+hex.EncodeToString(w.VKey[:])+"5840"+hex.EncodeToString(w.Signature[:]), strings.TrimPrefix(cborHexOf(t, wf), "82"); got != want {
					t.Fatalf("witness %s differs\n  cardano-cli: %s\n  go:          %s", s, want, got)
				}
				if env, _ := os.ReadFile(wf); string(pool.WitnessEnvelope(w)) != string(env) {
					t.Errorf("witness envelope %s differs\n  cardano-cli: %s\n  go:          %s", s, env, pool.WitnessEnvelope(w))
				}
				if parsed, err := pool.ParseWitnessEnvelope(env2(t, wf)); err != nil || parsed != w {
					t.Errorf("witness %s does not parse back: %v", s, err)
				}
				ws, files = append(ws, w), append(files, wf)
			}
			aargs := []string{"transaction", "assemble", "--tx-body-file", k.p("b.txbody")}
			for _, f := range files {
				aargs = append(aargs, "--witness-file", f)
			}
			e.cli(t, lits(append(aargs, "--out-file", k.p("a.tx"))...)...)
			signed, err := led.Assemble(body, ws)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := hex.EncodeToString(signed.CBOR), cborHexOf(t, k.p("a.tx")); got != want {
				t.Fatalf("assembled transaction differs (witness set order)\n  cardano-cli: %s\n  go:          %s", want, got)
			}
			if n, err := led.EstimateSize(body, tc.witnesses); err != nil || n != len(signed.CBOR) {
				t.Errorf("estimated size %d (%v), signed size %d", n, err, len(signed.CBOR))
			}
			if env, _ := os.ReadFile(k.p("b.txbody")); string(pool.TxEnvelope(body.CBOR)) != string(env) {
				t.Errorf("body envelope differs\n  cardano-cli: %s\n  go:          %s", env, pool.TxEnvelope(body.CBOR))
			}
		})
	}
}

func env2(t *testing.T, path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
