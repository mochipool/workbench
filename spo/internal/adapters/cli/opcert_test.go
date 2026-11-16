package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/fsstore"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/ports"
)

type cliIssuer struct{}

func (cliIssuer) Profile() custody.Profile {
	return custody.NewProfile("fake").Allow(custody.RolePoolCold, custody.OpIssueOpCert)
}
func (cliIssuer) IssueOpCert(context.Context, custody.Key[custody.PoolCold], ports.OpCertRequest) ([]byte, error) {
	return []byte("opcert\n"), nil
}

type cliDir struct{}

func (cliDir) SignerFor(custody.KeyRef) (ports.Signer, error) { return cliIssuer{}, nil }

type cliTip struct{}

func (cliTip) Source() chain.Source                   { return "fake" }
func (cliTip) Tip(context.Context) (chain.Tip, error) { return chain.Tip{Slot: 129600 * 5}, nil }

type cliGenesis struct{}

func (cliGenesis) Genesis(context.Context) (chain.Genesis, error) {
	return chain.Genesis{SlotLength: time.Second, SlotsPerKESPeriod: 129600, MaxKESEvolutions: 62}, nil
}

type cliCounters struct{}

func (cliCounters) Source() chain.Source { return "fake" }
func (cliCounters) OpCertCounter(context.Context, chain.PoolID) (chain.Reading[uint64], error) {
	return chain.Unknown[uint64]("offline"), nil
}

type cliClock struct{}

func (cliClock) Now() time.Time { return time.Unix(1_800_000_000, 0) }

func opcertDeps(out *bytes.Buffer) Deps {
	return Deps{
		Out: out, Err: out,
		OpenStore: func(dir string, _ bool) (ports.Store, error) { return fsstore.Open(dir) },
		OfflineOpCert: func(ports.Store, OfflineOptions) (OpCertWiring, error) {
			return OpCertWiring{Signers: cliDir{}, Tip: cliTip{}, Genesis: cliGenesis{}, Counters: cliCounters{}, Clock: cliClock{}}, nil
		},
	}
}

func runWith(t *testing.T, d Deps, out *bytes.Buffer, args ...string) error {
	t.Helper()
	root := NewRoot(d)
	root.SetArgs(args)
	return root.ExecuteContext(context.Background())
}

// spec: SPO-04d-IF-001, SPO-04d-IF-002
//
// Decisions: the pool is the one required argument (IF-001); the counter is
// the explicit flag --counter (IF-002) and is a number or the command is
// refused by the parser. Online checking is not wired yet (MODE-001 waived
// until the node adapter exists), so without --offline the command refuses
// before it touches the workspace.
func TestOpcertIssueArguments(t *testing.T) {
	var out bytes.Buffer
	d := opcertDeps(&out)
	dir := t.TempDir()
	for _, args := range [][]string{
		{"-C", dir, "pool", "opcert", "issue"},
		{"-C", dir, "pool", "opcert", "issue", "p", "--offline"},                   // no genesis
		{"-C", dir, "pool", "opcert", "issue", "p", "--shelley-genesis", "g.json"}, // not offline
		{"-C", dir, "pool", "opcert", "issue", "p", "--offline", "--shelley-genesis", "g", "--counter", "x"},
	} {
		if err := runWith(t, d, &out, args...); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
	err := runWith(t, d, &out, "-C", dir, "pool", "opcert", "issue", "p", "--shelley-genesis", "g.json")
	if err == nil || !strings.Contains(err.Error(), "not wired yet") {
		t.Errorf("online: %v", err)
	}
}

// spec: SPO-04d-SEC-001, SPO-04d-OUT-003
func TestOpcertIssueOfflineAndNewCounter(t *testing.T) {
	var out bytes.Buffer
	d := opcertDeps(&out)
	dir := t.TempDir()
	w := func(n, c string) { os.WriteFile(filepath.Join(dir, n), []byte(c), 0o400) }
	w("p.node.vkey", `{"type":"StakePoolVerificationKey_ed25519","cborHex":"5820`+strings.Repeat("11", 32)+`"}`)
	w("p.node.skey", "x")
	w("p.kes.counter", "000\n")
	w("p.kes.counter-next", "000\n")
	w("p.kes-000.vkey", `{"type":"KesVerificationKey_ed25519_kes_2^6","cborHex":"5820`+strings.Repeat("22", 32)+`"}`)

	// No counter file: refused, then created by the new-counter command.
	args := []string{"-C", dir, "pool", "opcert", "issue", "p", "--offline", "--shelley-genesis", "g.json"}
	if err := runWith(t, d, &out, args...); err == nil {
		t.Fatal("issued without a counter")
	}
	if err := runWith(t, d, &out, "-C", dir, "pool", "opcert", "new-counter", "p"); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runWith(t, d, &out, args...); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "counter 0 for KES period 5") || !strings.Contains(out.String(), "not checked against the chain") {
		t.Errorf("output:\n%s", out.String())
	}
	// spec: SPO-04d-SEC-001
	// The report shows the certificate's name, counters and expiry only.
	if strings.Contains(out.String(), "skey") || strings.Contains(out.String(), "5820") {
		t.Errorf("key material in the report:\n%s", out.String())
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "p.kes.counter-next")); string(b) != "001\n" {
		t.Errorf("counter-next %q", b)
	}
}
