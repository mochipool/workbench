package cli

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/adapters/transferfile"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

type chainPool struct {
	info   chain.Reading[chain.PoolInfo]
	update chain.Reading[chain.PoolUpdate]
	asked  int
}

func (*chainPool) Source() chain.Source { return "fake koios" }
func (c *chainPool) PoolInfo(context.Context, chain.PoolID) (chain.Reading[chain.PoolInfo], error) {
	c.asked++
	return c.info, nil
}
func (c *chainPool) LatestPoolUpdate(context.Context, chain.PoolID) (chain.Reading[chain.PoolUpdate], error) {
	return c.update, nil
}

// secondChain is a second provider that states the same pool, so the import
// corroborates (ADR 0006); the tests that exercise the single source set
// their own.
type secondChain struct{ c *chainPool }

func (secondChain) Source() chain.Source { return "fake blockfrost" }
func (s secondChain) PoolInfo(context.Context, chain.PoolID) (chain.Reading[chain.PoolInfo], error) {
	return s.c.info, nil
}

type metaFetch struct{ body []byte }

func (m metaFetch) Fetch(context.Context, string) ([]byte, error) { return m.body, nil }

type depositParams struct{}

func (depositParams) Source() chain.Source { return "fake params" }
func (depositParams) ProtocolParameters(context.Context) (chain.ProtocolParameters, error) {
	return chain.ProtocolParameters{StakeAddressDeposit: 2_000_000}, nil
}

// keyed is a synthetic pool whose keys we hold: the recorded preview pool with
// its identity, VRF hash, owners and counter replaced (hand-written, as in the
// use case's tests), and the key files of it in a directory.
type keyed struct {
	chain       *chainPool
	meta        []byte
	poolID      chain.PoolID
	stakeAddr   string
	keys        map[string]*ports.Secret
	dir         string
	coldCBORHex string
}

func newKeyed(t *testing.T, rewardsOurs bool) *keyed {
	t.Helper()
	k := &keyed{dir: t.TempDir(), keys: map[string]*ports.Secret{}}
	ctx := context.Background()
	gen := native.SoftwareKeys{}
	c, _ := gen.GenerateCold(ctx)
	v, _ := native.KeyGen{}.GenerateVRF(ctx)
	p, _ := gen.GeneratePayment(ctx)
	s, _ := gen.GenerateStake(ctx)
	k.keys["cold"], k.keys["vrf"], k.keys["pay"], k.keys["stk"] = c.SKey, v.SKey, p.SKey, s.SKey
	t.Cleanup(func() {
		for _, x := range k.keys {
			x.Destroy()
		}
	})
	for name, sec := range k.keys {
		var b []byte
		_ = sec.Use(func(x []byte) error { b = append([]byte(nil), x...); return nil })
		if err := os.WriteFile(filepath.Join(k.dir, name+".skey"), b, 0o400); err != nil {
			t.Fatal(err)
		}
		if name == "cold" {
			var env struct{ CBORHex string }
			_ = json.Unmarshal(b, &env)
			k.coldCBORHex = env.CBORHex
		}
	}
	raw := func(env []byte) []byte {
		e, err := pool.ParseEnvelope(env)
		if err != nil {
			t.Fatal(err)
		}
		r, err := e.Key32()
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	k.poolID, _ = chain.PoolIDOf(raw(c.VKey))
	vh := pool.VrfHash(raw(v.VKey))
	sa, err := native.Ledger{}.BuildStakeAddress(ports.NetworkTestnet, txbuild.HashKey(raw(s.VKey)))
	if err != nil {
		t.Fatal(err)
	}
	k.stakeAddr = string(sa)

	var rows []json.RawMessage
	read := func(p string) []byte {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if err := json.Unmarshal(read("../koios/testdata/pool_info_registered.json"), &rows); err != nil {
		t.Fatal(err)
	}
	info, err := chain.ParsePoolInfo(rows[0])
	if err != nil {
		t.Fatal(err)
	}
	info.IDHex, info.IDBech, info.VRFKeyHash = hex.EncodeToString(k.poolID[:]), k.poolID.Bech32(), hex.EncodeToString(vh[:])
	info.Owners, info.RewardAddr = []string{"stake_test1other"}, "stake_test1other"
	if rewardsOurs {
		info.Owners, info.RewardAddr = []string{"stake_test1other", k.stakeAddr}, k.stakeAddr
	}
	info.OpCertCounter = chain.Value(uint64(17))
	var upd []struct {
		Time  uint64 `json:"block_time"`
		Epoch uint64 `json:"active_epoch_no"`
	}
	if err := json.Unmarshal(read("../koios/testdata/pool_updates_registered.json"), &upd); err != nil {
		t.Fatal(err)
	}
	k.chain = &chainPool{info: chain.Value(info), update: chain.Value(chain.PoolUpdate{BlockTime: upd[0].Time, ActiveEpoch: upd[0].Epoch})}
	k.meta = read("../../app/workspace/testdata/pool_metadata_apex_preview.json")
	return k
}

func (k *keyed) path(name string) string { return filepath.Join(k.dir, name+".skey") }

// withPoolImport wires what the composition root wires for the import: the
// chain readers (a nil chain is offline mode, with the reason), the fetcher, the
// derivers, builders and a sink.
func withPoolImport(f *sendFixture, k *keyed, fetch ports.MetadataFetcher) {
	old := f.deps.Wire
	f.deps.Wire = func(st ports.Store, o WireOptions) (*Env, error) {
		env, err := old(st, o)
		if err != nil {
			return nil, err
		}
		led := native.Ledger{}
		env.VKeyEnvelopes, env.VrfVKeys, env.Addresses, env.Certs, env.MetadataHasher = native.VKeyDeriver{}, native.VRFDeriver{}, led, led, led
		env.Params = depositParams{}
		env.Sinks = func(dir string) (ports.FileSink, error) { return transferfile.DirSink{Dir: dir}, nil }
		if k != nil {
			env.PoolInfos, env.PoolUpdates, env.Metadata = k.chain, k.chain, fetch
			env.PoolInfoCross = secondChain{k.chain}
		} else {
			const why = "offline mode cannot read a pool from the chain"
			env.Absent(CapPoolInfo, why)
			env.Absent(CapPoolUpdates, why)
			env.Absent(CapMetaFetch, "offline mode makes no network request")
		}
		return env, nil
	}
}

func listing(t *testing.T, dir string) string { return strings.Join(dirNames(t, dir), ",") }

// spec: SPO-0x-PRE-001, SPO-0x-MODE-001
// Needs come first: offline, a pool id cannot be read, and the refusal lists
// every missing capability with its reason, before any question or write.
func TestPoolImportNeedsAreCheckedBeforeAnyPrompt(t *testing.T) {
	f := newSendFixture(t)
	withPoolImport(f, nil, nil)
	before := listing(t, f.dir)
	term := &scriptTerm{t: t}
	err := f.run(t, term, "pool", "import", "--yes", "mypool", "pool1a7h89sr6ymj9g2a9tm6e6dddghl64tp39pj78f6cah5ewgd4px0")
	if err == nil {
		t.Fatal("offline import by pool id")
	}
	for _, want := range []string{"pool-info", "pool-updates", "metadata-fetch", "offline mode cannot read a pool"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
	if term.asked != 0 || listing(t, f.dir) != before {
		t.Errorf("asked %d, workspace changed", term.asked)
	}
	// An account with a stake key needs the deposit: stated up front.
	g := newSendFixture(t)
	withPoolImport(g, nil, nil)
	old := g.deps.Wire
	g.deps.Wire = func(st ports.Store, o WireOptions) (*Env, error) {
		env, err := old(st, o)
		env.Params = nil
		env.Absent(CapParams, "no parameters here")
		return env, err
	}
	info := writeFile(t, g.dir, "info.json", `{}`)
	err = g.run(t, &scriptTerm{t: t}, "pool", "import", "--yes", "mypool", info, "--account", "a:p.skey:s.skey")
	if err == nil || !strings.Contains(err.Error(), "protocol-parameters") {
		t.Errorf("deposit need: %v", err)
	}
	// Malformed flags are refused before the workspace is opened.
	for _, a := range []string{"x", "x:", ":p", "a:b:c:d"} {
		if err := g.run(t, &scriptTerm{t: t}, "pool", "import", "--yes", "mypool", info, "--account", a); err == nil || !strings.Contains(err.Error(), "--account") {
			t.Errorf("--account %q: %v", a, err)
		}
	}
	if err := g.run(t, &scriptTerm{t: t}, "pool", "import", "--yes", "...", info); err == nil || !strings.Contains(err.Error(), "letter or digit") {
		t.Errorf("empty name: %v", err)
	}
}

// spec: SPO-0x-IF-001, SPO-0x-OUT-007, SPO-0x-OUT-008, SPO-0x-OUT-009, SPO-0x-OUT-010, SPO-0x-OUT-011, SPO-0x-OUT-012, SPO-0x-SEC-004
// The flags reach the use case: every file the spec lists is written, the
// counter is one above the chain's, and no key material appears in the output.
func TestPoolImportFlagsWriteTheKeysAndShowNoKeyMaterial(t *testing.T) {
	k := newKeyed(t, true)
	f := newSendFixture(t)
	withPoolImport(f, k, metaFetch{body: k.meta})
	term := &scriptTerm{t: t}
	if err := f.run(t, term, "pool", "import", "--yes", "mypool.pool.json", k.poolID.Bech32(),
		"--cold", k.path("cold"), "--vrf", k.path("vrf"), "--account", "owner:"+k.path("pay")+":"+k.path("stk")); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	out := f.out.String()
	mustContain(t, out, "Imported pool "+k.poolID.Bech32()+" as mypool", "counter file holds 18", "account owner: an owner and the rewards account", "delegation certificate", "Next: spo pool kes generate mypool")
	if term.asked != 0 {
		t.Errorf("a rewards account was found and every key given, yet %d question(s) were asked", term.asked)
	}
	for _, name := range []string{"mypool.pool.json", "mypool.node.skey", "mypool.node.vkey", "mypool.node.counter", "mypool.vrf.skey", "mypool.vrf.vkey",
		"owner.payment.skey", "owner.payment.addr", "owner.staking.skey", "owner.staking.addr", "owner.staking.cert", "owner.deleg.cert"} {
		if _, err := os.Stat(filepath.Join(f.dir, name)); err != nil {
			t.Errorf("missing %s: %v", name, err)
		}
	}
	for what, sec := range k.keys {
		_ = sec.Use(func(b []byte) error {
			var env struct{ CBORHex string }
			if json.Unmarshal(b, &env) == nil && env.CBORHex != "" && strings.Contains(out, env.CBORHex) {
				t.Errorf("the %s key's content is in the output", what)
			}
			return nil
		})
	}
	// The pool exists now: importing it again is refused (the descriptor is never replaced).
	if err := f.run(t, &scriptTerm{t: t}, "pool", "import", "--yes", "mypool", k.poolID.Bech32(), "--continue"); err == nil || !strings.Contains(err.Error(), "descriptor") {
		t.Errorf("a second import: %v", err)
	}
}

// --dry-run checks everything and writes nothing.
func TestPoolImportDryRunWritesNothing(t *testing.T) {
	k := newKeyed(t, true)
	f := newSendFixture(t)
	withPoolImport(f, k, metaFetch{body: k.meta})
	before := listing(t, f.dir)
	if err := f.run(t, &scriptTerm{t: t}, "pool", "import", "--yes", "mypool", k.poolID.Bech32(), "--dry-run",
		"--cold", k.path("cold"), "--vrf", k.path("vrf"), "--account", "owner:"+k.path("pay")+":"+k.path("stk")); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	mustContain(t, f.out.String(), "Dry run: nothing was written", "the counter file (next number 18)", "account owner: an owner and the rewards account", `"poolName"`)
	if after := listing(t, f.dir); after != before {
		t.Errorf("a dry run changed the workspace:\n%s\n%s", before, after)
	}
	// A key that is not the pool's is refused by a dry run just as by a real one.
	other := newKeyed(t, true)
	if err := f.run(t, &scriptTerm{t: t}, "pool", "import", "--yes", "mypool", k.poolID.Bech32(), "--dry-run", "--cold", other.path("cold")); err == nil || !strings.Contains(err.Error(), "does not belong") {
		t.Errorf("another pool's cold key: %v", err)
	}
}

// spec: SPO-0x-PR-007
// No account is the rewards account: the question has the spec's words and the
// default is Yes (an empty answer goes back to add one); No imports without it.
func TestPoolImportAsksForARewardsAccount(t *testing.T) {
	k := newKeyed(t, true)
	fixture := func() (*sendFixture, *recTerm) {
		f := newSendFixture(t)
		withPoolImport(f, k, metaFetch{body: k.meta})
		return f, &recTerm{}
	}
	// Yes by default, then the account is asked for as PR-005 and PR-006 say.
	f, term := fixture()
	term.lines = []string{"", "owner_andor_rewards", k.path("pay"), k.path("stk"), ""}
	if err := f.runT(t, term, "pool", "import", "--yes", "mypool", k.poolID.Bech32(), "--cold", k.path("cold"), "--vrf", k.path("vrf")); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	if !strings.Contains(term.asked[0], "Currently there is no rewards account included, do you wanna go back and add a payment/staking keypair for the rewards account? [Y/n]") {
		t.Errorf("question: %q", term.asked[0])
	}
	mustContain(t, f.out.String(), "account owner_andor_rewards: an owner and the rewards account")
	if _, err := os.Stat(filepath.Join(f.dir, "owner_andor_rewards.staking.skey")); err != nil {
		t.Error(err)
	}
	// No: imported without a rewards account, and the notice says so.
	f, term = fixture()
	term.lines = []string{"n"}
	if err := f.runT(t, term, "pool", "import", "--yes", "mypool", k.poolID.Bech32()); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	mustContain(t, f.out.String(), "no imported account is the pool's rewards account")
	// No terminal and flags given: nothing is asked, the import goes ahead.
	f, term = fixture()
	if err := f.runT(t, term, "pool", "import", "--yes", "mypool", k.poolID.Bech32(), "--cold", k.path("cold")); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
}

// spec: SPO-0x-PR-003, SPO-0x-PR-004, SPO-0x-PR-005, SPO-0x-PR-006
// With no key flag and a terminal the paths are asked for: a failed attempt
// asks again, a blank skips or ends.
func TestPoolImportAsksForKeyPaths(t *testing.T) {
	k := newKeyed(t, true)
	f := newSendFixture(t)
	withPoolImport(f, k, metaFetch{body: k.meta})
	term := &recTerm{lines: []string{filepath.Join(k.dir, "missing.skey"), k.path("cold"), k.path("vrf"), "owner", k.path("pay"), k.path("stk"), ""}}
	if err := f.runT(t, term, "pool", "import", "--yes", "mypool", k.poolID.Bech32()); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	mustContain(t, f.out.String(), "missing.skey", "cannot be opened", "as mypool", "account owner: an owner and the rewards account")
	if !strings.Contains(term.asked[0], "node.skey (blank to skip)") || !strings.Contains(term.asked[1], "node.skey") || !strings.Contains(term.asked[2], "vrf.skey (blank to skip)") {
		t.Errorf("prompts %q", term.asked)
	}
	for _, n := range []string{"mypool.node.skey", "mypool.vrf.skey", "owner.staking.skey"} {
		if _, err := os.Stat(filepath.Join(f.dir, n)); err != nil {
			t.Errorf("missing %s", n)
		}
	}
	// Blank answers skip everything: the pool is imported with a descriptor only.
	g := newSendFixture(t)
	withPoolImport(g, k, metaFetch{body: k.meta})
	if err := g.runT(t, &recTerm{lines: []string{"", "", "", "n"}}, "pool", "import", "--yes", "plain", k.poolID.Bech32()); err != nil {
		t.Fatalf("%v\n%s", err, g.out.String())
	}
	if _, err := os.Stat(filepath.Join(g.dir, "plain.node.skey")); err == nil {
		t.Error("a blank answer imported a key")
	}
}

// The published metadata does not hash to the registered hash: both hashes are
// shown and the default answer is No.
func TestPoolImportMetadataMismatchAsksWithBothHashes(t *testing.T) {
	k := newKeyed(t, true)
	changed := append(append([]byte(nil), k.meta...), '\n')
	info, _ := k.chain.info.Get()
	h, _ := native.Ledger{}.MetadataHash(changed)
	args := []string{"pool", "import", "--yes", "mypool", k.poolID.Bech32(), "--vrf", k.path("vrf")}

	f := newSendFixture(t)
	withPoolImport(f, k, metaFetch{body: changed})
	before := listing(t, f.dir)
	if err := f.runT(t, &recTerm{lines: []string{""}}, args...); err == nil || !strings.Contains(err.Error(), "declined") {
		t.Fatalf("default answer: %v", err)
	}
	mustContain(t, f.out.String(), "registered hash  "+strings.ToLower(info.MetaHash), "published hash   "+hex.EncodeToString(h[:]))
	if listing(t, f.dir) != before {
		t.Error("a declined import wrote something")
	}
	// Yes goes ahead with the published metadata.
	g := newSendFixture(t)
	withPoolImport(g, k, metaFetch{body: changed})
	term := &recTerm{lines: []string{"y", "n"}}
	if err := g.runT(t, term, args...); err != nil {
		t.Fatalf("%v\n%s", err, g.out.String())
	}
	if !strings.Contains(term.asked[0], "Import the pool with the published metadata anyway? [y/N]") {
		t.Errorf("question %q", term.asked[0])
	}
	// No terminal: refused with the flag that answers it; the flag goes ahead.
	e := newSendFixture(t)
	withPoolImport(e, k, metaFetch{body: changed})
	if err := e.run(t, &scriptTerm{t: t}, args...); err == nil || !strings.Contains(err.Error(), "--accept-metadata-mismatch") {
		t.Fatalf("no terminal: %v", err)
	}
	if err := e.run(t, &scriptTerm{t: t}, append(args, "--accept-metadata-mismatch")...); err != nil {
		t.Fatalf("%v\n%s", err, e.out.String())
	}
}

// Key files are read in place into protected memory: a link or an oversized
// file is refused, a loose mode is noted, and nothing is echoed.
func TestPoolImportKeyFileHandling(t *testing.T) {
	k := newKeyed(t, true)
	f := newSendFixture(t)
	withPoolImport(f, k, metaFetch{body: k.meta})
	link := filepath.Join(k.dir, "link.skey")
	if err := os.Symlink(k.path("cold"), link); err != nil {
		t.Fatal(err)
	}
	if err := f.run(t, &scriptTerm{t: t}, "pool", "import", "--yes", "mypool", k.poolID.Bech32(), "--cold", link); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("a link: %v", err)
	}
	big := writeFile(t, k.dir, "big.skey", strings.Repeat("x", maxKeyFile+1))
	if err := f.run(t, &scriptTerm{t: t}, "pool", "import", "--yes", "mypool", k.poolID.Bech32(), "--cold", big); err == nil || !strings.Contains(err.Error(), "larger than a key") {
		t.Errorf("an oversized file: %v", err)
	}
	// The import has to be given a signing key envelope: a verification key is refused.
	notKey := writeFile(t, k.dir, "vk.skey", `{"type":"StakePoolVerificationKey_ed25519","description":"","cborHex":"5820`+strings.Repeat("00", 32)+`"}`)
	if err := f.run(t, &scriptTerm{t: t}, "pool", "import", "--yes", "mypool", k.poolID.Bech32(), "--cold", notKey); err == nil || !strings.Contains(err.Error(), "signing key") {
		t.Errorf("a verification key: %v", err)
	}
	if err := os.Chmod(k.path("cold"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.out.Reset()
	if err := f.run(t, &scriptTerm{t: t}, "pool", "import", "--yes", "mypool", k.poolID.Bech32(), "--cold", k.path("cold")); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	mustContain(t, f.out.String(), "readable by others")
	if strings.Contains(f.out.String(), k.coldCBORHex) {
		t.Error("the key is in the output")
	}
}

// export-info writes the public registration data; the file written is an info
// file that an offline import reads (no chain, no fetch).
func TestPoolExportInfoThenOfflineImport(t *testing.T) {
	k := newKeyed(t, true)
	f := newSendFixture(t)
	withPoolImport(f, k, metaFetch{body: k.meta})
	file := filepath.Join(t.TempDir(), "pool.info.json")
	if err := f.run(t, &scriptTerm{t: t}, "pool", "export-info", k.poolID.Bech32(), file); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	mustContain(t, f.out.String(), "Wrote the registration data of pool "+k.poolID.Bech32(), "public data")
	b, err := os.ReadFile(file)
	if err != nil || !bytes.Contains(b, []byte(k.poolID.Bech32())) {
		t.Fatalf("%v %s", err, b)
	}
	// It is never written over a file.
	if err := f.run(t, &scriptTerm{t: t}, "pool", "export-info", k.poolID.Bech32(), file); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("existing file: %v", err)
	}
	// --attach needs the transfer file's attacher, which no chain-reading mode has: listed up front.
	if err := f.run(t, &scriptTerm{t: t}, "pool", "export-info", k.poolID.Bech32(), filepath.Join(t.TempDir(), "x.json"), "--attach"); err == nil || !strings.Contains(err.Error(), "transfer-attach") {
		t.Errorf("--attach: %v", err)
	}
	// The offline machine imports from the file with no chain reader at all.
	g := newSendFixture(t)
	withPoolImport(g, nil, nil)
	calls := k.chain.asked
	if err := g.run(t, &scriptTerm{t: t}, "pool", "import", "--yes", "mypool", file, "--cold", k.path("cold"), "--account", "owner:"+k.path("pay")+":"+k.path("stk")); err != nil {
		t.Fatalf("%v\n%s", err, g.out.String())
	}
	if k.chain.asked != calls {
		t.Error("the import from a file asked the chain")
	}
	mustContain(t, g.out.String(), "Imported pool", "counter file holds 18")
	// Offline, export is refused with the reasons.
	if err := g.run(t, &scriptTerm{t: t}, "pool", "export-info", k.poolID.Bech32(), filepath.Join(t.TempDir(), "y.json")); err == nil || !strings.Contains(err.Error(), "pool-info") {
		t.Errorf("offline export: %v", err)
	}
	// Not a pool id: refused before anything.
	if err := f.run(t, &scriptTerm{t: t}, "pool", "export-info", "nope", filepath.Join(t.TempDir(), "z.json")); err == nil {
		t.Error("a bad pool id was accepted")
	}
}

// recTerm is a terminal that records its prompts and answers from a script.
type recTerm struct {
	lines []string
	asked []string
}

func (r *recTerm) ReadSecret(context.Context, string) (*secret.Buffer, error) {
	return nil, ErrNoTerminal
}
func (r *recTerm) ReadLine(_ context.Context, prompt string) (string, error) {
	r.asked = append(r.asked, prompt)
	if len(r.lines) == 0 {
		return "", ErrNoTerminal
	}
	l := r.lines[0]
	r.lines = r.lines[1:]
	return l, nil
}

func (f *sendFixture) runT(t *testing.T, term Terminal, args ...string) error {
	t.Helper()
	return f.run(t, term, args...)
}

// The import shows the registration data (reward address, owners, margin,
// cost, pledge, relays) and asks before anything is written (default No);
// strings a provider chose are made safe to print; a single source needs
// --single-source and is recorded (ADR 0006, F3 and F4).
//
// spec: SPO-0x-SEC-003 (ADR 0006)
func TestPoolImportConfirmsTheDataAndRecordsASingleSource(t *testing.T) {
	k := newKeyed(t, true)
	info, _ := k.chain.info.Get()
	info.RewardAddr = "stake_test1\x1b[2Jevil‮"
	k.chain.info = chain.Value(info)
	newFix := func(cross bool) (*sendFixture, *recAuditor) {
		f := newSendFixture(t)
		rec := &recAuditor{}
		f.deps = rec.deps(f.deps)
		withPoolImport(f, k, metaFetch{body: k.meta})
		if !cross {
			old := f.deps.Wire
			f.deps.Wire = func(st ports.Store, o WireOptions) (*Env, error) {
				env, err := old(st, o)
				env.PoolInfoCross = nil
				return env, err
			}
		}
		return f, rec
	}

	// Declined at the prompt (the default): nothing written, nothing recorded,
	// and the hostile text is shown as escapes.
	f, rec := newFix(true)
	err := f.runT(t, &recTerm{lines: []string{"", "", "", "n", ""}}, "pool", "import", "mypool", k.poolID.Bech32())
	if err == nil || !strings.Contains(err.Error(), "not confirmed") {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	out := f.out.String()
	mustContain(t, out, "reward address", "owner", "margin", "cost", "pledge", `\u{1b}`, `\u{202e}`)
	if strings.Contains(out, "\x1b") || strings.Contains(out, "‮") {
		t.Errorf("an active character was printed: %q", out)
	}
	if _, err := os.Stat(filepath.Join(f.dir, "mypool.pool.json")); err == nil {
		t.Error("written without confirmation")
	}
	rec.singles(t, 0)

	// One provider: refused without the flag; with it, recorded and warned.
	g, rec2 := newFix(false)
	err = g.runT(t, &recTerm{}, "pool", "import", "--yes", "mypool", k.poolID.Bech32())
	if err == nil || !strings.Contains(err.Error(), "--single-source") {
		t.Fatalf("%v", err)
	}
	rec2.singles(t, 0)
	g.out.Reset()
	if err := g.runT(t, &recTerm{}, "pool", "import", "--yes", "--single-source", "mypool", k.poolID.Bech32()); err != nil {
		t.Fatalf("%v\n%s", err, g.out.String())
	}
	if ev := rec2.singles(t, 1)[0]; ev.Command != "spo pool import" || ev.Source != "fake koios" {
		t.Errorf("record %+v", ev)
	}
	mustContain(t, g.out.String(), "WARNING", "ONE source (fake koios)")
}
