package parity

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/fsstore"
	"github.com/mochipool/workbench/spo/internal/adapters/genesisfile"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/adapters/offline"
	"github.com/mochipool/workbench/spo/internal/adapters/systemclock"
	"github.com/mochipool/workbench/spo/internal/app/poolops"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// previewGenesis is the Shelley genesis file of the preview network from the
// pinned release set. The check derivation sets the variable from the
// workbench manifest.
func previewGenesis(t *testing.T) string {
	t.Helper()
	p := os.Getenv("SPO_PARITY_SHELLEY_GENESIS_PREVIEW")
	if p == "" {
		t.Skip("set SPO_PARITY_SHELLEY_GENESIS_PREVIEW to run the opcert parity tests")
	}
	return p
}

func (e env) cardanoCLI(t *testing.T, args ...string) []byte {
	t.Helper()
	cli, err := e.tc.Tool(context.Background(), ports.CardanoCLI)
	if err != nil {
		t.Fatal(err)
	}
	as := make([]execx.Arg, len(args))
	for i, a := range args {
		as[i] = execx.Lit(a)
	}
	res, err := execx.OS{}.Run(context.Background(), execx.Cmd{Path: cli.Path, Args: as})
	if err != nil {
		t.Fatalf("cardano-cli %v: %v\n%s", args[:3], err, res.Stderr)
	}
	return res.Stdout
}

func copyDir(t *testing.T, from, to string) {
	t.Helper()
	// cp -a keeps the file modes, which parity compares.
	if out, err := exec.Command("cp", "-a", from+"/.", to).CombinedOutput(); err != nil {
		t.Fatalf("cp: %v\n%s", err, out)
	}
}

func readFile(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mode(t *testing.T, dir, name string) os.FileMode {
	t.Helper()
	st, err := os.Stat(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return st.Mode().Perm()
}

var expireRE = regexp.MustCompile(`"expireKESdate": "([^"]*)"`)

func issueUseCase(t *testing.T, dir, genesis string) poolops.IssueOperationalCertificate {
	t.Helper()
	store, err := fsstore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	clock := systemclock.Clock{}
	g := genesisfile.Shelley{Path: genesis}
	return poolops.IssueOperationalCertificate{
		Store: store, Signers: native.Signers{Vault: store},
		Tip: offline.Tip{Clock: clock, Genesis: g}, Genesis: g,
		Counters: offline.Counters{}, Clock: clock, AllowUnverified: true,
	}
}

// Operational certificate issue: upstream 04d (offline role, no counter
// argument) against IssueOperationalCertificate. Ed25519 is deterministic, so
// the certificate must be byte-equal.
//
// spec: SPO-04d-IF-001, SPO-04d-IN-001, SPO-04d-IN-002, SPO-04d-IN-003, SPO-04d-IN-004, SPO-04d-IN-005,
// spec: SPO-04d-OUT-001, SPO-04d-OUT-002, SPO-04d-OUT-003, SPO-04d-OUT-004, SPO-04d-INV-001, SPO-04d-INV-002,
// spec: SPO-04d-INV-003, SPO-04d-INV-005, SPO-04d-EXT-002, SPO-04d-EXT-003, SPO-04d-MODE-005, SPO-04d-PRE-003,
// spec: SPO-04d-PRE-004, SPO-Pfiles-OUT-011, SPO-Pfiles-OUT-014, SPO-Pfiles-OUT-015, SPO-Cchain-INV-008
func TestOpCertIssue(t *testing.T) {
	e := setup(t)
	genesis := previewGenesis(t)
	ctx := context.Background()

	var upDir, portDir string
	var upExpire, portExpire string
	for attempt := 0; ; attempt++ {
		upDir = e.upstreamWorkspace(t)
		for _, a := range [][]string{{"04a_genNodeKeys.sh", "mypool", "cli"}, {"04c_genKESKeys.sh", "mypool", "cli"}} {
			if code := e.upstream(t, upDir, append([]string{"exec"}, a...)...); code != 0 {
				t.Fatalf("upstream %s exited %d", a[0], code)
			}
		}
		// Copy the state before 04d, so both sides issue from the same files.
		portDir = t.TempDir()
		copyDir(t, upDir, portDir)

		// Before the issue, a second issue-ready pool: refused by both when no
		// KES key waits is covered after the first issue below.
		if code := e.upstream(t, upDir, "exec", "04d_genNodeOpCert.sh", "mypool"); code != 0 {
			t.Fatalf("upstream 04d exited %d", code)
		}
		res, err := issueUseCase(t, portDir, genesis).Run(ctx, "mypool", poolops.IssueOptions{})
		if err != nil {
			t.Fatalf("port: %v", err)
		}
		if res.Verified {
			t.Error("an offline issue reported itself verified")
		}
		upExpire, portExpire = readFile(t, upDir, "mypool.kes-expire.json"), readFile(t, portDir, "mypool.kes-expire.json")
		period := func(s string) string { return regexp.MustCompile(`"currentKESperiod": "(\d+)"`).FindString(s) }
		if period(upExpire) == period(portExpire) {
			break
		}
		if attempt > 0 {
			t.Fatalf("the KES period differs twice: %s vs %s", period(upExpire), period(portExpire))
		}
		t.Log("a KES period boundary fell between the two runs; retrying once")
	}

	// Certificate, counter and next-counter: byte-equal.
	for _, name := range []string{"mypool.node-000.opcert", "mypool.node.counter", "mypool.kes.counter-next", "mypool.kes.counter"} {
		if up, port := readFile(t, upDir, name), readFile(t, portDir, name); up != port {
			t.Errorf("%s differs\n  upstream: %q\n  port:     %q", name, up, port)
		}
	}
	// kes-expire.json: equal except the date, which is compared by time.
	strip := func(s string) string { return expireRE.ReplaceAllString(s, `"expireKESdate": "<date>"`) }
	if strip(upExpire) != strip(portExpire) {
		t.Errorf("kes-expire.json differs\n  upstream: %q\n  port:     %q", upExpire, portExpire)
	}
	parse := func(s string) time.Time {
		m := expireRE.FindStringSubmatch(s)
		if m == nil {
			t.Fatalf("no expireKESdate in %q", s)
		}
		// Upstream's text is `date`'s default in the oracle's locale. Both
		// sides run in this process's time zone.
		d, err := time.ParseInLocation(pool.ExpireDateLayout, m[1], time.Local)
		if err != nil {
			t.Fatalf("expireKESdate %q: %v", m[1], err)
		}
		return d
	}
	if delta := parse(portExpire).Sub(parse(upExpire)); delta < -time.Minute || delta > time.Minute {
		t.Errorf("expireKESdate differs by %v: %q vs %q", delta, upExpire, portExpire)
	}
	// File set and modes (0400 for every artefact).
	for _, name := range []string{"mypool.node-000.opcert", "mypool.node.counter", "mypool.kes.counter-next", "mypool.kes-expire.json"} {
		if mode(t, upDir, name) != mode(t, portDir, name) {
			t.Errorf("%s: mode %v vs %v", name, mode(t, upDir, name), mode(t, portDir, name))
		}
	}
	diff(t, "artefacts after issue", snapshotWithout(t, upDir, "mypool", "kes-expire.json"), snapshotWithout(t, portDir, "mypool", "kes-expire.json"))

	// A second issue is refused by both: the KES counters now differ.
	if code := e.upstream(t, upDir, "exec", "04d_genNodeOpCert.sh", "mypool"); code != 2 {
		t.Errorf("upstream second 04d exited %d, want 2", code)
	}
	if _, err := issueUseCase(t, portDir, genesis).Run(ctx, "mypool", poolops.IssueOptions{}); err == nil {
		t.Error("port second issue accepted")
	}
	diff(t, "artefacts after refused issue", snapshotWithout(t, upDir, "mypool", "kes-expire.json"), snapshotWithout(t, portDir, "mypool", "kes-expire.json"))
}

// snapshotWithout is snapshot minus one suffix.
func snapshotWithout(t *testing.T, dir, prefix, suffix string) state {
	s := snapshot(t, dir, prefix)
	delete(s, prefix+"."+suffix)
	return s
}

// The native certificate is the one cardano-cli issues for the same inputs,
// over counters and periods that need every CBOR integer width; cardano-cli
// parses it; and the issue counter envelope is the one `node new-counter`
// and `node issue-op-cert` write (the description aside, see below).
//
// spec: SPO-04d-EXT-001, SPO-04d-EXT-003, SPO-04d-OUT-002, SPO-04d-OUT-005, SPO-Pfiles-OUT-011, SPO-Pfiles-OUT-014
func TestOpCertMatchesCardanoCLI(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	dir := t.TempDir()
	p := func(n string) string { return filepath.Join(dir, n) }

	// A cold key pair and a KES verification key, made by cardano-cli.
	e.cardanoCLI(t, "latest", "node", "key-gen", "--cold-verification-key-file", p("mypool.node.vkey"),
		"--cold-signing-key-file", p("mypool.node.skey"), "--operational-certificate-issue-counter-file", p("seed.counter"))
	e.cardanoCLI(t, "latest", "node", "key-gen-KES", "--verification-key-file", p("kes.vkey"), "--signing-key-file", p("kes.skey"))

	store, err := fsstore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	signer := native.VaultSigner{Vault: store}
	cold, _ := pool.ParseEnvelope([]byte(readFile(t, dir, "mypool.node.vkey")))
	coldRaw, _ := cold.Key32()
	kesEnv, _ := pool.ParseEnvelope([]byte(readFile(t, dir, "kes.vkey")))
	kesRaw, _ := kesEnv.Key32()
	key, _ := coldKeyRef("mypool")

	for _, counter := range []uint64{0, 23, 24, 255, 256, 300, 65536, 70000, 1 << 32} {
		for _, period := range []uint64{0, 23, 24, 988, 65535, 70000} {
			name := fmt.Sprintf("c%d-p%d", counter, period)
			e.cardanoCLI(t, "latest", "node", "new-counter", "--cold-verification-key-file", p("mypool.node.vkey"),
				"--counter-value", fmt.Sprint(counter), "--operational-certificate-issue-counter-file", p(name+".counter"))
			// new-counter writes an empty description (upstream patches it, 04d EXT-001).
			created := readFile(t, dir, name+".counter")
			var vk [32]byte
			copy(vk[:], coldRaw)
			ours := pool.IssueCounter{Next: counter, ColdVKey: vk}.Envelope()
			ce, _ := pool.ParseEnvelope([]byte(created))
			oe, _ := pool.ParseEnvelope(ours)
			if ce.Type != oe.Type || ce.CborHex != oe.CborHex || ce.Description != "" {
				t.Fatalf("new-counter %d differs:\n  cardano-cli: %+v\n  port:        %+v", counter, ce, oe)
			}

			e.cardanoCLI(t, "latest", "node", "issue-op-cert", "--kes-verification-key-file", p("kes.vkey"),
				"--cold-signing-key-file", p("mypool.node.skey"), "--operational-certificate-issue-counter-file", p(name+".counter"),
				"--kes-period", fmt.Sprint(period), "--out-file", p(name+".opcert"))

			got, err := signer.IssueOpCert(ctx, key, ports.OpCertRequest{KesVKey: kesRaw, Counter: counter, KesPeriod: period})
			if err != nil {
				t.Fatal(err)
			}
			if want := readFile(t, dir, name+".opcert"); string(got) != want {
				t.Fatalf("opcert for counter %d, period %d differs\n  cardano-cli: %q\n  native:      %q", counter, period, want, got)
			}
			// After issuing, cardano-cli's counter file is what the port writes.
			if want := readFile(t, dir, name+".counter"); want != string(pool.IssueCounter{Next: counter + 1, ColdVKey: vk}.Envelope()) {
				t.Fatalf("counter after issue differs:\n  cardano-cli: %q\n  port: %q", want, pool.IssueCounter{Next: counter + 1, ColdVKey: vk}.Envelope())
			}
		}
	}

	// cardano-cli parses the native certificate.
	out, err := signer.IssueOpCert(ctx, key, ports.OpCertRequest{KesVKey: kesRaw, Counter: 7, KesPeriod: 988})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p("native.opcert"), out, 0o600); err != nil {
		t.Fatal(err)
	}
	decoded := string(e.cardanoCLI(t, "latest", "text-view", "decode-cbor", "--in-file", p("native.opcert")))
	for _, want := range []string{"list(2)", "list(4)", "int(7)", "int(988)", "bytes(64)"} {
		if !strings.Contains(decoded, want) {
			t.Errorf("decode-cbor lacks %q:\n%s", want, decoded)
		}
	}
	// The pool id of the cold key is the one cardano-cli computes.
	id, err := chain.PoolIDOf(coldRaw)
	if err != nil {
		t.Fatal(err)
	}
	hexID := strings.TrimSpace(string(e.cardanoCLI(t, "latest", "stake-pool", "id", "--cold-verification-key-file", p("mypool.node.vkey"), "--output-hex")))
	if hex.EncodeToString(id[:]) != hexID {
		t.Errorf("pool id %x, cardano-cli %s", id, hexID)
	}
}

func coldKeyRef(owner string) (custody.Key[custody.PoolCold], error) {
	return custody.As[custody.PoolCold](custody.KeyRef{Role: custody.RolePoolCold, Holder: custody.HolderVault, Owner: owner})
}
