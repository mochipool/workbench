// Package world wires real use cases to the real native ledger adapter, the
// real file store and, when asked, the real hwcli adapter over a fake
// cardano-hw-cli, with a fake chain. It is for end-to-end tests of the use
// cases (test/hardware, app/poll): nothing in the binary imports it.
package world

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/hwcli"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

// Chain is a fake chain: the UTxOs of some addresses, parameters, a tip, and
// the transactions that were submitted.
type Chain struct {
	Funds     map[chain.Address][]chain.Utxo
	Params    chain.ProtocolParameters
	Slot      uint64
	Submitted [][]byte
	Ledger    native.Ledger
}

func (c *Chain) Source() chain.Source { return "fake chain" }
func (c *Chain) Tip(context.Context) (chain.Tip, error) {
	return chain.Tip{Slot: c.Slot, Epoch: c.Slot / 432000}, nil
}
func (c *Chain) ProtocolParameters(context.Context) (chain.ProtocolParameters, error) {
	return c.Params, nil
}
func (c *Chain) Utxos(_ context.Context, a chain.Address) ([]chain.Utxo, error) {
	return append([]chain.Utxo(nil), c.Funds[a]...), nil
}
func (c *Chain) Submit(_ context.Context, signed []byte) (chain.TxID, error) {
	c.Submitted = append(c.Submitted, append([]byte(nil), signed...))
	return c.Ledger.TransactionID(signed)
}

// Confirmer records the summaries it was shown and answers Yes.
type Confirmer struct {
	Seen []ports.TxSummary
	No   bool
}

func (c *Confirmer) Confirm(_ context.Context, s ports.TxSummary) (bool, error) {
	c.Seen = append(c.Seen, s)
	return !c.No, nil
}

// LegacyInputs wraps the native body builder and writes the inputs as a plain
// array, not the tag-258 set: valid CBOR in a form the fake hardware tool
// canonicalises, so the canonical body has another id than the one first built.
type LegacyInputs struct{ native.Ledger }

func (l LegacyInputs) BuildBody(s txbuild.BodySpec) (txbuild.TxBody, error) {
	b, err := l.Ledger.BuildBody(s)
	if err != nil {
		return b, err
	}
	i := bytes.Index(b.CBOR, []byte{0x00, 0xd9, 0x01, 0x02})
	if i < 0 || i > 3 {
		return b, fmt.Errorf("the built body has no tagged input set")
	}
	cbor := append(append([]byte(nil), b.CBOR[:i+1]...), b.CBOR[i+4:]...)
	id, err := l.Ledger.TransactionID(cbor)
	if err != nil {
		return b, err
	}
	return txbuild.TxBody{CBOR: cbor, ID: id}, nil
}

// World is one workspace with a fake chain.
type World struct {
	T       *testing.T
	Dir     string
	Store   *plainstore.Store
	Chain   *Chain
	Ledger  native.Ledger
	Conf    *Confirmer
	HW      *HW
	Bodies  ports.TxBodyBuilder
	Network uint8
}

// New makes an empty workspace.
func New(t *testing.T) *World {
	t.Helper()
	dir := t.TempDir()
	st, err := plainstore.OpenTestnet(dir)
	if err != nil {
		t.Fatal(err)
	}
	led := native.Ledger{}
	return &World{T: t, Dir: dir, Store: st, Ledger: led, Conf: &Confirmer{}, Bodies: led, Network: ports.NetworkTestnet,
		Chain: &Chain{Funds: map[chain.Address][]chain.Utxo{}, Slot: 1000, Ledger: led, Params: chain.ProtocolParameters{
			TxFeePerByte: 44, TxFeeFixed: 155381, CoinsPerUTxOByte: 4310, StakeAddressDeposit: 2_000_000, DRepDeposit: 500_000_000,
			MaxTxSize: 16384, MaxValueSize: 5000, ProtocolMajor: 11}}}
}

// Fund gives an address one UTxO.
func (w *World) Fund(addr chain.Address, lovelace chain.Lovelace) {
	var id chain.TxID
	id[0], id[1] = byte(len(w.Chain.Funds)+1), 0xaa
	w.Chain.Funds[addr] = append(w.Chain.Funds[addr], chain.Utxo{TxID: id, Index: 0, Lovelace: lovelace})
}

// Signers is the directory: vault keys to the vault signer, hardware keys to
// the hardware signer when one is set up.
func (w *World) Signers() ports.SignerDirectory {
	d := native.Signers{Vault: w.Store.Anchor()}
	if w.HW != nil {
		d.Hardware = w.HW.Lazy
	}
	return d
}

// Pipeline is the shared transaction pipeline over this world. Canonicalizer is
// wired only with a hardware tool, as the binary will wire it.
func (w *World) Pipeline() txflow.Pipeline {
	p := txflow.Pipeline{Signers: w.Signers(), Min: w.Ledger, Fees: w.Ledger, Bodies: w.Bodies, Assembler: w.Ledger,
		Confirmer: w.Conf, Submitter: w.Chain}
	if w.HW != nil {
		p.Canonicalizer = w.HW.Lazy
	}
	return p
}

// Canonicalizer is the hardware canonicalizer, nil without a tool. A nil
// interface is returned, not a typed nil.
func (w *World) Canonicalizer() ports.HardwareCanonicalizer {
	if w.HW == nil {
		return nil
	}
	return w.HW.Lazy
}

// Exporter is the hardware key exporter, nil without a tool.
func (w *World) Exporter() ports.HardwareKeyExporter {
	if w.HW == nil {
		return nil
	}
	return w.HW.Lazy
}

// ---- the fake hardware tool ----------------------------------------------

var (
	fakeOnce sync.Once
	fakePath string
	fakeErr  error
)

func moduleRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

func buildFake(t *testing.T) string {
	t.Helper()
	fakeOnce.Do(func() {
		dir, err := os.MkdirTemp("", "fakehw-world-")
		if err != nil {
			fakeErr = err
			return
		}
		fakePath = filepath.Join(dir, "cardano-hw-cli")
		goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
		_, err = execx.OS{}.Run(context.Background(), execx.Cmd{Path: goBin, Dir: moduleRoot(), Env: os.Environ(),
			Args: execx.Lits("build", "-o", fakePath, "./test/hardware/fakehw")})
		if err != nil {
			fakeErr = fmt.Errorf("build the fake hardware tool: %v", err)
		}
	})
	if fakeErr != nil {
		t.Skipf("%v", fakeErr)
	}
	return fakePath
}

type stubToolchain struct{ path string }

func (s stubToolchain) Tool(_ context.Context, n ports.ToolName) (ports.Tool, error) {
	return ports.Tool{Name: n, Path: s.path, Version: "1.20.0"}, nil
}

// HW is a hardware wallet: the real hwcli adapter over the fake tool.
type HW struct {
	Lazy    *hwcli.Lazy
	logPath string
	cfgPath string
	cfg     map[string]any
	hwcfg   hwcli.Config
}

// Seed is the seed of the fake device; the key of a path is derived from it.
const Seed = "fakehw-world-seed"

// UseHardware connects a fake device of a vendor with an app version ("Ledger"
// "8.0.8", "Trezor" "2.7.2", "Keystone" "1.7.7"), and makes the hardware
// signer, canonicalizer and exporter of the world.
func (w *World) UseHardware(vendor, app string) *HW {
	t := w.T
	t.Helper()
	bin := buildFake(t)
	dir := t.TempDir()
	h := &HW{logPath: filepath.Join(dir, "calls.log"), cfgPath: filepath.Join(dir, "fake.json")}
	h.cfg = map[string]any{"vendor": vendor, "app": app, "toolVersion": "1.20.0", "device": "ok", "action": "ok", "seed": Seed, "log": h.logPath}
	h.write()
	tmp := filepath.Join(dir, "tmp")
	if err := os.Mkdir(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := hwcli.Config{
		Toolchain: stubToolchain{bin}, Runner: execx.OS{}, Files: hwcli.StoreFiles{Store: w.Store.Anchor()},
		TxID: w.Ledger.TransactionID, PolicyID: w.Ledger.PolicyID, Network: hwcli.Network{Magic: 2},
		Timeout: 3 * time.Second, Poll: 20 * time.Millisecond, Attempt: 2 * time.Second, TempRoot: tmp,
		Env: []string{"FAKEHW_CONFIG=" + h.cfgPath},
	}
	h.hwcfg = cfg
	h.Lazy = hwcli.NewLazy(context.Background(), cfg)
	w.HW = h
	return h
}

// NewSession gives the world a new hardware session over the same device and
// configuration, as the next command would open: a device unplugged since the
// last session is found out when the plan asks for the signer's profile.
func (w *World) NewSession() {
	w.HW.Lazy = hwcli.NewLazy(context.Background(), w.HW.hwcfg)
}

func (h *HW) write() {
	b, _ := json.Marshal(h.cfg)
	if err := os.WriteFile(h.cfgPath, b, 0o600); err != nil {
		panic(err)
	}
}

// Calls are the argument vectors the fake tool logged.
func (h *HW) Calls() [][]string {
	raw, _ := os.ReadFile(h.logPath)
	var out [][]string
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var a []string
		if l != "" && json.Unmarshal([]byte(l), &a) == nil {
			out = append(out, a)
		}
	}
	return out
}

// Count is the number of logged calls that start with the words.
func (h *HW) Count(words ...string) int {
	n := 0
	for _, c := range h.Calls() {
		if len(c) >= len(words) && strings.Join(c[:len(words)], " ") == strings.Join(words, " ") {
			n++
		}
	}
	return n
}

// Last returns the last logged call that starts with the words.
func (h *HW) Last(words ...string) []string {
	var last []string
	for _, c := range h.Calls() {
		if len(c) >= len(words) && strings.Join(c[:len(words)], " ") == strings.Join(words, " ") {
			last = c
		}
	}
	return last
}

// Prompts is the number of logged calls that make the device prompt: everything
// but the version probe, which does not.
func (h *HW) Prompts() int {
	n := 0
	for _, c := range h.Calls() {
		if len(c) >= 2 && c[0] == "device" && c[1] == "version" {
			continue
		}
		n++
	}
	return n
}

// Set changes one setting of the fake tool: "action" (ok, error, rejected,
// disconnect, warning) or "device" (ok, nodevice, ...), for the next calls.
func (h *HW) Set(key string, value any) {
	h.cfg[key] = value
	h.write()
}
