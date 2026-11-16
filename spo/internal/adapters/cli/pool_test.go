package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/poolops"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/ports"
)

type poolParams struct{}

func (poolParams) Source() chain.Source { return "fake params" }
func (poolParams) ProtocolParameters(context.Context) (chain.ProtocolParameters, error) {
	return chain.ProtocolParameters{TxFeePerByte: 44, TxFeeFixed: 155381, CoinsPerUTxOByte: 4310, StakeAddressDeposit: 2_000_000,
		StakePoolDeposit: 500_000_000, MinPoolCost: 170_000_000, PoolRetireMaxEpoch: 18, MaxTxSize: 16384, MaxValueSize: 5000, ProtocolMajor: 10}, nil
}

// poolFix is an upstream-layout workspace whose Env has the pool capabilities;
// a test removes some with absent, and counts how often the wiring ran.
type poolFix struct {
	*sendFixture
	absent map[Cap]string
	wired  int
}

func newPoolFix(t *testing.T) *poolFix {
	t.Helper()
	f := &poolFix{sendFixture: newSendFixture(t), absent: map[Cap]string{}}
	f.deps.Wire = func(st ports.Store, o WireOptions) (*Env, error) {
		f.wired++
		led := native.Ledger{}
		soft := native.SoftwareKeys{}
		env := &Env{Mode: o.Mode, NetworkID: ports.NetworkTestnet, Clock: cliClock{},
			AddressInspector: led, MinOutputCalculator: led, FeeEstimator: led, TxBodyBuilder: led, TxAssembler: led,
			Addresses: led, Certs: led, CertDecoder: led, PaymentKeys: soft, StakeKeys: soft, ColdKeys: soft, VrfKeys: native.KeyGen{},
			PoolCerts: led, PoolCertDecoder: led, MetadataHasher: led, TxIDs: led,
			Genesis: cliGenesis{}, Tip: cliTip{}, Params: poolParams{}, Utxos: fakeUtxos{}, Queue: f.queue}
		var v ports.Vault
		if st != nil {
			v = st.(ports.Vault)
		}
		env.Signers = native.Signers{Vault: v}
		env.Absent(CapSubmit, "offline mode has no transaction submitter; queue to a transfer file instead")
		env.Absent(CapPools, "the offline transfer file holds no pool registration state")
		for c, why := range f.absent {
			switch c {
			case CapPoolCerts:
				env.PoolCerts = nil
			case CapPoolCertDecode:
				env.PoolCertDecoder = nil
			case CapTxID:
				env.TxIDs = nil
			case CapMetaHash:
				env.MetadataHasher = nil
			}
			env.Absent(c, why)
		}
		return env, nil
	}
	return f
}

func (f *poolFix) cmd(t *testing.T, lines []string, args ...string) (string, error) {
	t.Helper()
	f.out.Reset()
	err := f.run(t, &scriptTerm{t: t, lines: lines}, args...)
	return f.out.String(), err
}

func (f *poolFix) must(t *testing.T, args ...string) string {
	t.Helper()
	out, err := f.cmd(t, nil, args...)
	if err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return out
}

const goodDescriptor = "--owner w --reward w --pledge 100000000 --cost 300000000 --margin 0.03 --relay DNS:relay.example.org:3001 " +
	"--meta-name Quartz --meta-description Test --meta-ticker QRTZ --meta-homepage https://example.org --meta-url https://example.org/p.json"

// pool p with its keys, wallet w and a descriptor.
func (f *poolFix) pool(t *testing.T, extra string) {
	t.Helper()
	f.must(t, "wallet", "new", "w", "--stake")
	f.must(t, "pool", "keys", "generate", "p")
	f.must(t, "pool", "vrf", "generate", "p")
	f.must(t, append([]string{"pool", "descriptor", "new", "p"}, strings.Fields(goodDescriptor+" "+extra)...)...)
}

// put replaces a file of the workspace (the descriptor is read-only on disk).
func (f *poolFix) put(t *testing.T, name, content string) {
	t.Helper()
	p := filepath.Join(f.dir, name)
	os.Remove(p)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *poolFix) file(name string) string {
	b, _ := os.ReadFile(filepath.Join(f.dir, name))
	return string(b)
}

// --yes does not exist for the commands that commit a deposit or retire a
// pool: it is refused with the reason before the environment is even built.
func TestPoolRegisterAndRetireRefuseYes(t *testing.T) {
	for _, args := range [][]string{{"pool", "register", "p", "w.payment", "--yes"}, {"pool", "retire", "p", "w.payment", "--yes"}} {
		f := newPoolFix(t)
		out, err := f.cmd(t, nil, args...)
		if err == nil || !strings.Contains(err.Error(), "--yes is not accepted") || !strings.Contains(err.Error(), "SPO-Ptx-PR-004") {
			t.Errorf("%v: %v\n%s", args, err, out)
		}
		if f.wired != 0 || len(f.queue.got) != 0 {
			t.Errorf("%v: the environment was built (%d) or a transaction queued", args, f.wired)
		}
	}
}

// ADR 0008: the needs are checked before the workspace is opened or a
// question asked, and one error lists each with its reason.
func TestPoolCommandsRequireTheirCapabilitiesFirst(t *testing.T) {
	cases := []struct {
		args   []string
		absent map[Cap]string
		want   []string
	}{
		{[]string{"pool", "cert", "generate", "p"}, map[Cap]string{CapPoolCerts: "no pool certificate builder", CapMetaHash: "no hasher"},
			[]string{"pool-certificate-building: no pool certificate builder", "metadata-hash: no hasher"}},
		{[]string{"pool", "register", "p", "w.payment"}, map[Cap]string{CapTxID: "no id calculator", CapPoolCertDecode: "no decoder"},
			[]string{"tx-id: no id calculator", "pool-certificate-decoding: no decoder"}},
		{[]string{"pool", "retire", "p", "w.payment"}, map[Cap]string{CapPoolCertDecode: "no decoder"}, []string{"pool-certificate-decoding: no decoder"}},
		{[]string{"pool", "retire-cert", "p"}, map[Cap]string{CapPoolCerts: "no builder"}, []string{"pool-certificate-building: no builder"}},
		{[]string{"pool", "witness", "import", "p", "x.witness"}, map[Cap]string{CapTxID: "no id calculator"}, []string{"tx-id: no id calculator"}},
		{[]string{"pool", "status", "p"}, nil, []string{"pool-state: the offline transfer file holds no pool registration state"}},
	}
	for _, c := range cases {
		f := newPoolFix(t)
		f.absent = c.absent
		f.wired = 0
		d := f.deps
		d.Terminal = failTerm{t}
		root := NewRoot(d)
		root.SetArgs(append([]string{"--upstream-layout", "-C", f.dir}, c.args...))
		err := root.ExecuteContext(context.Background())
		if err == nil || !strings.Contains(err.Error(), "cannot run here") {
			t.Fatalf("%v: %v", c.args, err)
		}
		for _, w := range c.want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%v: no %q in %v", c.args, w, err)
			}
		}
	}
}

func TestPoolDescriptorNewShowSet(t *testing.T) {
	f := newPoolFix(t)
	out := f.must(t, "pool", "descriptor", "new", "p", "--owner", "a", "--owner", "b:external", "--relay", "IP6:2001:db8::1:3001", "--relay", "SRV:_cardano._tcp.example.org")
	mustContain(t, out, "Stored p.pool.json", "Still placeholders", "poolRewards", "poolMetaTicker", "Template defaults, check them: poolPledge, poolCost, poolMargin")
	show := f.must(t, "pool", "descriptor", "show", "p")
	mustContain(t, show, `"poolName": "p"`, `"ownerName": "b"`, `"ownerWitness": "external"`, `"relayType": "IP6"`, `"relayEntry": "2001:db8::1"`,
		`"relayType": "SRV"`, `"---": "DO NOT EDIT OR DELETE BELOW THIS LINE"`)
	// The order is the upstream template's.
	last := -1
	for _, k := range operatorFields {
		i := strings.Index(show, `"`+k+`"`)
		if i < last {
			t.Errorf("%s is out of order in:\n%s", k, show)
		}
		last = i
	}
	if _, err := f.cmd(t, nil, "pool", "descriptor", "new", "p"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("an existing descriptor was overwritten: %v", err)
	}
	for _, bad := range []string{"poolPledge=-1", "poolMargin=1.5", "poolMetaTicker=AB", "poolMetaTicker=A-B-C", "poolMetaUrl=ftp://x", "poolRelays=DNS:host", "poolRelays=IP:999.1.1.1:3001",
		"poolOwner=a,a", "poolID=abc", "regProtectionKey=x", "poolName=q", "nope"} {
		before := f.file("p.pool.json")
		if _, err := f.cmd(t, nil, "pool", "descriptor", "set", "p", bad); err == nil {
			t.Errorf("%s was accepted", bad)
		}
		if f.file("p.pool.json") != before {
			t.Errorf("%s changed the descriptor", bad)
		}
	}
	out = f.must(t, "pool", "descriptor", "set", "p", "poolPledge=5", "poolMetaName=A <b> & \"c\"", "poolExtendedMetaUrl=https://example.org/ext.json")
	mustContain(t, out, "Updated p.pool.json")
	mustContain(t, f.file("p.pool.json"), `"poolPledge": "5"`, `"poolMetaName": "A <b> & \"c\""`)
	// A key the template lacks goes before the marker line.
	if d := f.file("p.pool.json"); strings.Index(d, "poolExtendedMetaUrl") > strings.Index(d, `"---"`) {
		t.Errorf("poolExtendedMetaUrl is after the marker:\n%s", d)
	}
}

func TestPoolDescriptorShowHidesTheProtectionKeyAndSetRefusesAnOpenCollection(t *testing.T) {
	f := newPoolFix(t)
	f.pool(t, "")
	d := f.file("p.pool.json")
	secretKey := "the-protection-key-0123456789"
	f.put(t, "p.pool.json", strings.Replace(d, "\n}", ",\n  \"regProtectionKey\": \""+secretKey+"\"\n}", 1))
	out := f.must(t, "pool", "descriptor", "show", "p")
	if strings.Contains(out, secretKey) || strings.Contains(out, `"regProtectionKey":`) {
		t.Errorf("show printed the protection key:\n%s", out)
	}
	mustContain(t, out, `"poolName": "p"`)
	f.put(t, "p.pool.json", strings.Replace(f.file("p.pool.json"), "\n}", ",\n  \"regWitness\": {\"id\": 5}\n}", 1))
	if _, err := f.cmd(t, nil, "pool", "descriptor", "set", "p", "poolPledge=7"); err == nil || !strings.Contains(err.Error(), "witness collection is open") {
		t.Errorf("set with an open collection: %v", err)
	}
}

// The two answers of 05a are flags, both off by default; the refusal names
// the flag and writes nothing.
func TestPoolCertGenerateFlagsMapToChoices(t *testing.T) {
	f := newPoolFix(t)
	f.pool(t, "")
	f.must(t, "pool", "descriptor", "set", "p", "poolCost=100")

	_, err := f.cmd(t, nil, "pool", "cert", "generate", "p")
	if err == nil || !strings.Contains(err.Error(), "--raise-cost") || !strings.Contains(err.Error(), "170000000") {
		t.Fatalf("cost below the minimum: %v", err)
	}
	if f.file("p.pool.cert") != "" || strings.Contains(f.file("p.pool.json"), "poolID") {
		t.Error("a refused generation wrote something")
	}
	out := f.must(t, "pool", "cert", "generate", "p", "--raise-cost")
	mustContain(t, out, "Generated the registration certificate of pool p", "Corrected        poolCost", "Pool id (bech32) pool1", "spo pool metadata show p")
	mustContain(t, f.file("p.pool.json"), `"poolCost": "170000000"`)
	if f.file("p.pool.cert") == "" {
		t.Error("no certificate")
	}
	if strings.Contains(out, "regProtectionKey") {
		t.Error("the output mentions the protection key")
	}

	// A ticker with disallowed characters can only come from a hand-edited
	// descriptor; the refusal names --accept-ticker.
	g := newPoolFix(t)
	g.pool(t, "")
	g.put(t, "p.pool.json", strings.Replace(g.file("p.pool.json"), `"QRTZ"`, `"QR-Z"`, 1))
	if _, err := g.cmd(t, nil, "pool", "cert", "generate", "p"); err == nil || !strings.Contains(err.Error(), "--accept-ticker") || !strings.Contains(err.Error(), "QR_Z") {
		t.Fatalf("ticker: %v", err)
	}
	out = g.must(t, "pool", "cert", "generate", "p", "--accept-ticker")
	mustContain(t, out, "Corrected        poolMetaTicker")
}

func TestPoolCertGenerateRefusesPlaceholders(t *testing.T) {
	f := newPoolFix(t)
	f.must(t, "wallet", "new", "w", "--stake")
	f.must(t, "pool", "keys", "generate", "p")
	f.must(t, "pool", "vrf", "generate", "p")
	f.must(t, "pool", "descriptor", "new", "p", "--owner", "w", "--reward", "w")
	_, err := f.cmd(t, nil, "pool", "cert", "generate", "p")
	if err == nil || !strings.Contains(err.Error(), "CHANGE-ME") || !strings.Contains(err.Error(), "poolMetaTicker") {
		t.Fatalf("placeholders: %v", err)
	}
}

// The protection key comes from a descriptor and never from argv.
func TestPoolCertGenerateHasNoProtectionKeyFlagOtherThanAnFD(t *testing.T) {
	f := newPoolFix(t)
	f.pool(t, "")
	if _, err := f.cmd(t, nil, "pool", "cert", "generate", "p", "--protection-key", "abc"); err == nil || !strings.Contains(err.Error(), "unknown flag") {
		t.Fatalf("a protection key on argv: %v", err)
	}
}

// The pool summary shows what the descriptor says and who holds each
// signature, and never a key or the protection key.
func TestPoolSummaryShowsThePoolAndNoKeyMaterial(t *testing.T) {
	f := newPoolFix(t)
	f.pool(t, "")
	f.must(t, "pool", "descriptor", "set", "p", "poolOwner=w,second:external")
	protection := "protection-key-never-printed-777"
	f.put(t, "p.pool.json", strings.Replace(f.file("p.pool.json"), "\n}", ",\n  \"regProtectionKey\": \""+protection+"\"\n}", 1))

	var buf bytes.Buffer
	st, err := f.deps.OpenUpstream(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	var id chain.TxID
	id[0] = 0xcd
	sum := ports.TxSummary{Kind: "pool registration", Stage: "submit", Account: "p", Pool: "pool1abc", Pledge: 100_000_000, Deposit: 500_000_000, Fee: 190_000, TTL: 999,
		Source: "w.payment", TxID: id, Route: "queue", Unchecked: []string{"the registration type comes from the descriptor"}}
	printPoolSummary(context.Background(), &buf, st, native.Ledger{}, sum)
	out := buf.String()
	mustContain(t, out, "first registration", "pool id      pool1abc", "pledge       100.000000 ADA", "cost         300.000000 ADA", "margin       0.03", "reward acct  w",
		"owner        w (local)", "owner        second (external)", "relay        DNS relay.example.org:3001", "metadata     https://example.org/p.json", "deposit      500.000000 ADA",
		"fee          0.190000 ADA", "valid until  slot 999", "tx id        cd", "p.node ", "this workspace", "w.payment", "second.staking", "signs elsewhere (external)", "NOT CHECKED")
	for _, bad := range []string{protection, "SigningKey", "cborHex", "VerificationKey", genSKeyHex} {
		if strings.Contains(out, bad) {
			t.Errorf("the summary holds %q:\n%s", bad, out)
		}
	}
	// The re-registration and the retirement are named as such.
	buf.Reset()
	printPoolSummary(context.Background(), &buf, st, nil, ports.TxSummary{Kind: "pool re-registration", Account: "p", Pool: "pool1abc", Stage: "body"})
	mustContain(t, buf.String(), "re-registration", "before the witnesses are collected")
	buf.Reset()
	printPoolSummary(context.Background(), &buf, st, nil, ports.TxSummary{Kind: "pool retirement", Account: "p", Pool: "pool1abc", Stage: "submit", Source: "w.payment"})
	mustContain(t, buf.String(), "retirement certificate only", "deposit moves", "p.node")
	if strings.Contains(buf.String(), "pledge") {
		t.Error("a retirement shows a pledge")
	}
}

// With --allow-pending an open collection is a success that names each open
// slot, its holder and the transfer files; without it the same state is an
// error, because the transaction was not sent.
func TestRegisterReportsTheSlotsItWaitsFor(t *testing.T) {
	f := newPoolFix(t)
	f.pool(t, "")
	f.must(t, "pool", "descriptor", "set", "p", "poolOwner=w,second:external")
	st, err := f.deps.OpenUpstream(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	a := newApp(f.deps)
	s := &session{Store: st}
	res := poolops.RegisterResult{CollectionID: 77, Type: pool.PoolRegistration, Missing: []string{"second.staking"}, TransferFiles: []string{"p_second_77"}}

	f.out.Reset()
	if err := a.reportRegister(context.Background(), s, &Env{TxIDs: native.Ledger{}}, WireOptions{}, []string{"p", "w.payment"}, res, true); err != nil {
		t.Fatal(err)
	}
	mustContain(t, f.out.String(), "Witness collection 77", "waiting for 1 signature(s)", "open slot  second.staking", "stake", "signs elsewhere (external)",
		"wrote      p_second_77.witness", "spo pool witness import p <file>")
	if strings.Contains(f.out.String(), "Queued") || strings.Contains(f.out.String(), "Submitted") {
		t.Error("a waiting registration claims to be sent")
	}
	f.out.Reset()
	err = a.reportRegister(context.Background(), s, &Env{TxIDs: native.Ledger{}}, WireOptions{}, []string{"p", "w.payment"}, res, false)
	if err == nil || !strings.Contains(err.Error(), "--allow-pending") {
		t.Fatalf("waiting without --allow-pending: %v", err)
	}
}

func TestRegisterHintsAndTypeFlag(t *testing.T) {
	f := &poolFlags{}
	for err, want := range map[error]string{
		poolops.ErrSingleSource:     "--single-source",
		poolops.ErrNoChainReader:    "--allow-unverified",
		pool.ErrChooseType:          "--type REG",
		poolops.ErrMetadataMismatch: "pool metadata show",
		poolops.ErrNoDescriptor:     "descriptor new",
	} {
		if got := f.hint(err); got == nil || !strings.Contains(got.Error(), want) {
			t.Errorf("%v: %v", err, got)
		}
	}
	// A flag already given is not suggested again.
	g := &poolFlags{singleSource: true, allowUnverified: true}
	if got := g.hint(poolops.ErrSingleSource); strings.Contains(got.Error(), "pass --single-source") {
		t.Errorf("suggested a flag that was given: %v", got)
	}
	for in, want := range map[string]pool.RegistrationType{"": "", "reg": pool.PoolRegistration, "REREG": pool.PoolReRegistration} {
		if got, err := parseRegType(in); err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	if _, err := parseRegType("update"); err == nil {
		t.Error("an unknown type was accepted")
	}
}
