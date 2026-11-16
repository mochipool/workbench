package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/adapters/fsstore"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/wallet"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// bech32 encodes data under hrp (BIP 173), enough to make a test address.
func bech32(hrp string, data []byte) string {
	const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	var five []byte
	acc, bits := 0, 0
	for _, b := range data {
		acc = acc<<8 | int(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			five = append(five, byte(acc>>bits&31))
		}
	}
	if bits > 0 {
		five = append(five, byte(acc<<(5-bits)&31))
	}
	polymod := func(v []byte) uint32 {
		gen := []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
		chk := uint32(1)
		for _, x := range v {
			top := chk >> 25
			chk = chk&0x1ffffff<<5 ^ uint32(x)
			for i := 0; i < 5; i++ {
				if top>>i&1 == 1 {
					chk ^= gen[i]
				}
			}
		}
		return chk
	}
	var exp []byte
	for _, c := range hrp {
		exp = append(exp, byte(c>>5))
	}
	exp = append(exp, 0)
	for _, c := range hrp {
		exp = append(exp, byte(c&31))
	}
	pm := polymod(append(append(exp, five...), 0, 0, 0, 0, 0, 0)) ^ 1
	out := hrp + "1"
	for _, x := range five {
		out += string(charset[x])
	}
	for i := 0; i < 6; i++ {
		out += string(charset[pm>>(5*(5-i))&31])
	}
	return out
}

// testnetAddr is the enterprise testnet address of an Ed25519 seed.
func testnetAddr(seed []byte) string {
	vk := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	h, _ := blake2b.New(28, nil)
	h.Write(vk)
	return bech32("addr_test", append([]byte{0x60}, h.Sum(nil)...))
}

type fakeUtxos struct{ addr string }

func (fakeUtxos) Source() chain.Source { return "fake utxos" }
func (f fakeUtxos) Utxos(_ context.Context, a chain.Address) ([]chain.Utxo, error) {
	var id chain.TxID
	id[0] = 0xab
	return []chain.Utxo{{TxID: id, Index: 1, Lovelace: 50_000_000}}, nil
}

type fakeParams struct{}

func (fakeParams) Source() chain.Source { return "fake params" }
func (fakeParams) ProtocolParameters(context.Context) (chain.ProtocolParameters, error) {
	return chain.ProtocolParameters{TxFeePerByte: 44, TxFeeFixed: 155381, CoinsPerUTxOByte: 4310,
		MaxTxSize: 16384, MaxValueSize: 5000, ProtocolMajor: 10}, nil
}

type recQueue struct{ got []ports.QueuedTx }

func (q *recQueue) Enqueue(_ context.Context, t ports.QueuedTx) error {
	q.got = append(q.got, t)
	return nil
}

// scriptTerm answers prompts from a script and fails the test if asked for a
// secret, or for a line when it has none.
type scriptTerm struct {
	t     *testing.T
	lines []string
	asked int
}

func (s *scriptTerm) ReadSecret(context.Context, string) (*secret.Buffer, error) {
	s.t.Helper()
	s.t.Error("the terminal was asked for a secret")
	return nil, ErrNoTerminal
}
func (s *scriptTerm) ReadLine(context.Context, string) (string, error) {
	s.asked++
	if len(s.lines) == 0 {
		return "", ErrNoTerminal
	}
	l := s.lines[0]
	s.lines = s.lines[1:]
	return l, nil
}

// sendFixture is an upstream-layout workspace with wallet w (a key and an
// address) and a Wire that returns a full offline environment around a
// recording queue.
type sendFixture struct {
	dir   string
	queue *recQueue
	out   bytes.Buffer
	deps  Deps
	seed  []byte
}

func newSendFixture(t *testing.T) *sendFixture {
	t.Helper()
	f := &sendFixture{dir: t.TempDir(), queue: &recQueue{}}
	f.seed = make([]byte, 32)
	for i := range f.seed {
		f.seed[i] = byte(i + 1)
	}
	os.WriteFile(filepath.Join(f.dir, "w.addr"), []byte(testnetAddr(f.seed)+"\n"), 0o600)
	os.WriteFile(filepath.Join(f.dir, "w.skey"), []byte(`{"type":"PaymentSigningKeyShelley_ed25519","description":"","cborHex":"5820`+hex.EncodeToString(f.seed)+`"}`), 0o400)
	cfgs := map[string]WorkspaceConfig{f.dir: {Network: "preview", Mode: ModeOffline}}
	f.deps = Deps{
		Out: &f.out, Err: &f.out, Config: memConfig(cfgs),
		OpenUpstream: func(dir string) (ports.Store, error) { return fsstore.Open(dir) },
		Wire: func(st ports.Store, o WireOptions) (*Env, error) {
			led := native.Ledger{}
			env := &Env{Mode: o.Mode, NetworkID: ports.NetworkTestnet, Clock: cliClock{},
				AddressInspector: led, MinOutputCalculator: led, FeeEstimator: led, TxBodyBuilder: led, TxAssembler: led,
				Genesis: cliGenesis{}, Tip: cliTip{}, Params: fakeParams{}, Utxos: fakeUtxos{}, Queue: f.queue}
			var v ports.Vault
			if st != nil {
				v = st.(ports.Vault)
			}
			env.Signers = native.Signers{Vault: v}
			env.Absent(CapSubmit, "offline mode has no transaction submitter; queue to a transfer file instead")
			return env, nil
		},
	}
	return f
}

func (f *sendFixture) run(t *testing.T, term Terminal, args ...string) error {
	t.Helper()
	d := f.deps
	d.Terminal = term
	root := NewRoot(d)
	root.SetArgs(append([]string{"--upstream-layout", "-C", f.dir}, args...))
	return root.ExecuteContext(context.Background())
}

const sendTo = "addr_test1vql6v54azljgm6npwncg248rd3r0e7dsr9mvjd7xp30hc4g995pn0"

// ADR 0008: the default answer is No. A decline signs, submits and queues
// nothing; the summary was shown first.
func TestSendDeclinedByDefaultQueuesNothing(t *testing.T) {
	for _, answer := range []string{"", "n", "no", "maybe"} {
		f := newSendFixture(t)
		term := &scriptTerm{t: t, lines: []string{answer}}
		err := f.run(t, term, "wallet", "send", "w", sendTo, "ALL")
		if !errors.Is(err, wallet.ErrDeclined) {
			t.Fatalf("answer %q: %v", answer, err)
		}
		if len(f.queue.got) != 0 {
			t.Errorf("answer %q: a transaction was queued", answer)
		}
		if term.asked != 1 {
			t.Errorf("asked %d times", term.asked)
		}
		out := f.out.String()
		for _, want := range []string{"Payment", "from         w", sendTo, "fee", "valid until", "tx id", "route        queue", "[y/N]"} {
			// [y/N] is the prompt, shown by the terminal, not Out.
			if want != "[y/N]" && !strings.Contains(out, want) {
				t.Errorf("answer %q: summary lacks %q:\n%s", answer, want, out)
			}
		}
	}
	// With no terminal and no --yes the command refuses; it does not guess.
	f := newSendFixture(t)
	err := f.run(t, &scriptTerm{t: t}, "wallet", "send", "w", sendTo, "ALL")
	if err == nil || !strings.Contains(err.Error(), "--yes") || len(f.queue.got) != 0 {
		t.Errorf("no terminal: %v", err)
	}
}

func TestSendYesQueuesAndSummaryHasNoKeyMaterial(t *testing.T) {
	f := newSendFixture(t)
	term := &scriptTerm{t: t}
	if err := f.run(t, term, "wallet", "send", "w", sendTo, "12000000", "--yes", "--message", "thanks"); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	if term.asked != 0 {
		t.Error("--yes still asked")
	}
	if len(f.queue.got) != 1 {
		t.Fatalf("queued %d", len(f.queue.got))
	}
	out := f.out.String()
	id := f.queue.got[0].Tx.ID.String()
	for _, want := range []string{"Payment", "to           " + sendTo, "12000000 lovelace", "change", "message      thanks", "tx id        " + id, "Queued transaction " + id} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	for _, bad := range []string{hex.EncodeToString(f.seed), "PaymentSigningKey", "cborHex", "skey"} {
		if strings.Contains(out, bad) {
			t.Errorf("output holds key material %q:\n%s", bad, out)
		}
	}
}
