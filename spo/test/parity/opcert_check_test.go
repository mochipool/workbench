package parity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/fsstore"
	"github.com/mochipool/workbench/spo/internal/adapters/genesisfile"
	"github.com/mochipool/workbench/spo/internal/adapters/koios"
	"github.com/mochipool/workbench/spo/internal/app/query"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
)

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func stripANSI(s string) string { return ansiRE.ReplaceAllString(s, "") }

// poolAnswers is what the stand-in Koios says about each pool: a counter, a
// pool that made no block (null), or a pool it does not know (an empty array).
type poolAnswers struct {
	mu sync.Mutex
	m  map[string]*uint64 // pool id bech32 -> counter; a nil counter is null
	// absent pools are unknown to Koios
}

func (p *poolAnswers) set(id string, counter *uint64, known bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.m == nil {
		p.m = map[string]*uint64{}
	}
	if !known {
		delete(p.m, id)
		return
	}
	p.m[id] = counter
}

// koiosFromTheClock answers /tip with the slot of now on the genesis, and
// /pool_info from the table.
func koiosFromTheClock(t *testing.T, k *koiosServer, genesis string, answers *poolAnswers) {
	t.Helper()
	g, err := genesisfile.Shelley{Path: genesis}.Genesis(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	k.custom = func(w http.ResponseWriter, r *http.Request, body []byte) bool {
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/v1/tip":
			now := time.Now()
			slot := uint64(now.Sub(g.SystemStart) / g.SlotLength)
			fmt.Fprintf(w, `[{"hash":"%064x","epoch_no":%d,"era":"Conway","abs_slot":%d,"epoch_slot":%d,"block_height":1,"block_no":1,"block_time":%d}]`,
				1, slot/g.EpochLength, slot, slot%g.EpochLength, now.Unix())
			return true
		case r.Method == "POST" && r.URL.Path == "/api/v1/pool_info":
			var rq struct {
				IDs []string `json:"_pool_bech32_ids"`
			}
			if err := json.Unmarshal(body, &rq); err != nil || len(rq.IDs) != 1 {
				http.Error(w, "bad request", 400)
				return true
			}
			answers.mu.Lock()
			c, known := answers.m[rq.IDs[0]]
			answers.mu.Unlock()
			if !known {
				io.WriteString(w, "[]")
				return true
			}
			counter := "null"
			if c != nil {
				counter = fmt.Sprint(*c)
			}
			fmt.Fprintf(w, `[{"pool_id_bech32":%q,"op_cert_counter":%s,"pool_status":"registered","meta_json":{"name":"Test Pool","ticker":"TST"}}]`, rq.IDs[0], counter)
			return true
		}
		return false
	}
}

func u64(v uint64) *uint64 { return &v }

// generatePool makes the keys, a KES key and an opcert with the counter, with the
// upstream scripts in an offline workspace.
func (e env) generatePool(t *testing.T, dir, name string, counter uint64) {
	t.Helper()
	for _, a := range [][]string{{"04a_genNodeKeys.sh", name, "cli"}, {"04c_genKESKeys.sh", name, "cli"}, {"04d_genNodeOpCert.sh", name, fmt.Sprint(counter)}} {
		if code, out := e.upstreamOut(t, dir, append([]string{"exec"}, a...)...); code != 0 {
			t.Fatalf("upstream %v exited %d\n%s", a, code, out)
		}
	}
}

// copyPoolFiles copies the pool's files into another workspace.
func copyPoolFiles(t *testing.T, from, to, name string) {
	t.Helper()
	ms, _ := filepath.Glob(filepath.Join(from, name+".*"))
	for _, m := range ms {
		b, err := os.ReadFile(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(to, filepath.Base(m)), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// writePoolIDFile derives the pool id from the cold verification key and stores
// it as `<name>.pool.id-bech`, which 05a does in a real workspace.
func writePoolIDFile(t *testing.T, dir, name string) {
	t.Helper()
	env, err := pool.ParseEnvelope([]byte(readFile(t, dir, name+".node.vkey")))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := env.Key32()
	if err != nil {
		t.Fatal(err)
	}
	id, err := chain.PoolIDOf(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".pool.id-bech"), []byte(id.Bech32()+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// verdictOf reads the counter verdict out of the upstream text, since the exit
// status carries none (SPO-04e-INV-004).
func verdictOf(out string) string {
	t := stripANSI(out)
	m := regexp.MustCompile(`OpCertCounter Check - [A-Za-z ]+: (OK|FALSE)`).FindStringSubmatch(t)
	if m == nil {
		return ""
	}
	return m[1]
}

// 04e: offline mode is refused by upstream (exit 1) and by the use case with no
// chain reader. In light mode the verdict of the use case matches the text of the
// script for every combination of the counter on disk, the counter on chain and the
// check; the exit status is 0 for every one of them, FALSE included
// (SPO-04e-INV-004), which is why the port returns the verdict as data. The one
// deliberate divergence is a pool Koios does not know: upstream reads the empty
// answer as no block yet and prints OK with exit 0; the port reports Unknown.
//
// spec: SPO-04e-PRE-001, SPO-04e-MODE-001, SPO-04e-MODE-005, SPO-04e-IF-001, SPO-04e-IF-004, SPO-04e-IN-001, SPO-04e-IN-002,
// spec: SPO-04e-INV-001, SPO-04e-INV-002, SPO-04e-INV-003, SPO-04e-INV-004, SPO-04e-OUT-001, SPO-04e-OUT-002, SPO-04e-OUT-003,
// spec: SPO-04e-MODE-003, SPO-04e-MODE-004, SPO-04e-EXT-001, SPO-04e-EXT-002, SPO-04e-PRE-003
func TestCheckOpCertMatchesUpstream(t *testing.T) {
	e := setup(t)
	genesis := previewGenesis(t)
	ctx := context.Background()

	off := e.upstreamWorkspace(t)
	e.generatePool(t, off, "p0", 0)
	e.generatePool(t, off, "p3", 3)
	for _, n := range []string{"p0", "p3"} {
		writePoolIDFile(t, off, n)
	}

	// Offline: refused by upstream with both subjects, and by the use case.
	for _, args := range [][]string{{"p0", "current"}, {"p0", "next"}, {"p0.node-000.opcert", "current"}, {"p0"}} {
		code, out := e.upstreamOut(t, off, append([]string{"-y", "exec", "04e_checkNodeOpCert.sh"}, args...)...)
		if code != 1 || !strings.Contains(stripANSI(out), "ONLINE or LIGHT") && !strings.Contains(stripANSI(out), "online or light") {
			t.Errorf("upstream offline 04e %v exited %d:\n%s", args, code, stripANSI(out))
		}
	}
	if _, err := (query.CheckOpCert{}).Run(ctx, query.OpCertCheck{OpCert: []byte("x"), Check: query.CheckCurrent}); err == nil || !strings.Contains(err.Error(), "not the offline mode") {
		t.Errorf("port offline: %v", err)
	}

	// Light: one workspace per pool sharing the same stand-in Koios.
	answers := &poolAnswers{}
	k := newReplay(t, loadExchanges(t, filepath.Join(airgapFx, "exchanges.json")), time.Now().UTC().Format(time.RFC1123Z))
	koiosFromTheClock(t, k, genesis, answers)
	light := e.lightWorkspace(t, k)
	for _, n := range []string{"p0", "p3"} {
		copyPoolFiles(t, off, light, n)
	}

	client, err := koios.New(koios.Config{BaseURL: k.KoiosAPI(), Network: "preview"})
	if err != nil {
		t.Fatal(err)
	}
	store, err := fsstore.Open(light)
	if err != nil {
		t.Fatal(err)
	}
	uc := query.CheckOpCert{Store: store, Tip: client, Genesis: genesisfile.Shelley{Path: genesis}, Counters: client}

	poolID := func(name string) string { return strings.TrimSpace(readFile(t, light, name+".pool.id-bech")) }
	type chainState struct {
		name  string
		onCh  *uint64
		known bool
	}
	states := []chainState{{"none", nil, true}, {"2", u64(2), true}, {"3", u64(3), true}, {"4", u64(4), true}}
	for _, pn := range []struct {
		pool   string
		onDisk uint64
	}{{"p0", 0}, {"p3", 3}} {
		for _, st := range states {
			for _, chk := range []query.CounterCheck{query.CheckCurrent, query.CheckNext} {
				name := fmt.Sprintf("%s on disk %d, chain %s, %s", pn.pool, pn.onDisk, st.name, chk)
				answers.set(poolID(pn.pool), st.onCh, st.known)
				code, out := e.upstreamOut(t, light, "-y", "exec", "04e_checkNodeOpCert.sh", pn.pool, string(chk))
				if code != 0 {
					t.Errorf("%s: upstream exited %d, want 0 for every completed check:\n%s", name, code, stripANSI(out))
					continue
				}
				up := verdictOf(out)
				v, err := uc.Run(ctx, query.OpCertCheck{Pool: pn.pool, Check: chk})
				if err != nil {
					t.Errorf("%s: port: %v", name, err)
					continue
				}
				if v.OnDisk != pn.onDisk {
					t.Errorf("%s: the port read counter %d from the file", name, v.OnDisk)
				}
				want := map[query.Status]string{query.StatusOK: "OK", query.StatusFalse: "FALSE"}[v.Counter]
				if up != want {
					t.Errorf("%s: upstream says %q, the port %s (%v)", name, up, v.Counter, v.Reasons)
				}
				if v.KES != query.StatusOK || !v.Window.InRange {
					t.Errorf("%s: the certificate is fresh, but the KES window says %+v", name, v.Window)
				}
			}
		}
	}

	// A pool Koios does not know (an empty answer). Upstream: "OK, no block yet", exit 0, for a
	// counter-0 certificate on `current`. The port: Unknown, not "no block yet".
	id := poolID("p0")
	answers.set(id, nil, false)
	code, out := e.upstreamOut(t, light, "-y", "exec", "04e_checkNodeOpCert.sh", "p0", "current")
	if code != 0 || verdictOf(out) != "OK" || !strings.Contains(stripANSI(out), "no block generated yet") {
		t.Errorf("upstream on an unknown pool: exit %d\n%s", code, stripANSI(out))
	}
	v, err := uc.Run(ctx, query.OpCertCheck{Pool: "p0", Check: query.CheckCurrent})
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != query.StatusUnknown || v.Counter != query.StatusUnknown || !v.OnChain.IsUnknown() || v.NoBlockYet || v.NextRequired != nil {
		t.Errorf("the port on an unknown pool must say Unknown, not no-block-yet: %+v", v)
	}
	if !strings.Contains(v.OnChain.Why(), "does not know") {
		t.Errorf("reason: %q", v.OnChain.Why())
	}

	// The pool-id subject. Upstream prints the next counter; an unknown pool is exit 1 ("could not
	// query"); the port reports the same facts, with Unknown for the unknown pool.
	q := query.QueryOpCertCounter{Store: store, Counters: client}
	answers.set(id, u64(7), true)
	code, out = e.upstreamOut(t, light, "-y", "exec", "04e_checkNodeOpCert.sh", id)
	rep, err := q.Run(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := rep.Counter.Get(); code != 0 || c != 7 || rep.Next == nil || *rep.Next != 8 || !strings.Contains(stripANSI(out), "8") {
		t.Errorf("pool-id mode with counter 7: exit %d, port %+v\n%s", code, rep, stripANSI(out))
	}
	answers.set(id, nil, true)
	code, out = e.upstreamOut(t, light, "-y", "exec", "04e_checkNodeOpCert.sh", id)
	rep, _ = q.Run(ctx, "p0")
	if !rep.Counter.IsNone() || rep.Next == nil || *rep.Next != 0 || code != 0 || !strings.Contains(stripANSI(out), "not made a block yet") && !strings.Contains(stripANSI(out), "not generated") {
		t.Errorf("pool-id mode with no block: exit %d, port %+v\n%s", code, rep, stripANSI(out))
	}
	answers.set(id, nil, false)
	code, _ = e.upstreamOut(t, light, "-y", "exec", "04e_checkNodeOpCert.sh", id)
	rep, err = q.Run(ctx, id)
	if err != nil || code != 1 || !rep.Counter.IsUnknown() || rep.Next != nil {
		t.Errorf("pool-id mode with an unknown pool: exit %d, port %+v %v", code, rep, err)
	}
}

// The unknown-pool divergence against the real Koios preview service: a freshly
// generated pool is on no chain, Koios answers an empty array, upstream reads
// it as "no block generated yet" and exits 0, and the port reports Unknown. Only
// public data is read and only the new pool's id is sent. Runs with
// SPO_PARITY_NETWORK=1 and network access.
//
// spec: SPO-04e-MODE-004, SPO-04e-INV-001, SPO-04e-INV-004, SPO-04e-EXT-002
func TestCheckOpCertUnknownPoolAgainstLiveKoios(t *testing.T) {
	if os.Getenv("SPO_PARITY_NETWORK") == "" {
		t.Skip("set SPO_PARITY_NETWORK=1 to ask the real Koios preview service")
	}
	e := setup(t)
	genesis := previewGenesis(t)
	ctx := context.Background()
	off := e.upstreamWorkspace(t)
	e.generatePool(t, off, "fresh", 0)
	writePoolIDFile(t, off, "fresh")

	light := t.TempDir()
	if code := e.upstream(t, light, "init", "--network", "preview", "--role", "light", "--airgapped", "--pool", "mypool"); code != 0 {
		t.Fatalf("workbench init exited %d", code)
	}
	copyPoolFiles(t, off, light, "fresh")
	code, out := e.upstreamOut(t, light, "-y", "exec", "04e_checkNodeOpCert.sh", "fresh", "current")
	if code != 0 || verdictOf(out) != "OK" || !strings.Contains(stripANSI(out), "no block generated yet") {
		t.Fatalf("upstream against the live service: exit %d\n%s", code, stripANSI(out))
	}
	client, err := koios.New(koios.Config{BaseURL: "https://preview.koios.rest/api/v1", Network: "preview"})
	if err != nil {
		t.Fatal(err)
	}
	store, err := fsstore.Open(light)
	if err != nil {
		t.Fatal(err)
	}
	v, err := (query.CheckOpCert{Store: store, Tip: client, Genesis: genesisfile.Shelley{Path: genesis}, Counters: client}).Run(ctx, query.OpCertCheck{Pool: "fresh", Check: query.CheckCurrent})
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != query.StatusUnknown || v.NoBlockYet || !v.OnChain.IsUnknown() {
		t.Errorf("the port on a pool the live service does not know: %+v", v)
	}
	t.Logf("live Koios: upstream OK (no block yet), exit 0; port %s: %s", v.Status, v.OnChain.Why())
}
