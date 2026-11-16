package poolops

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
)

// edit sets or (v == nil) deletes a field of the stored descriptor. The key
// order of the file is not kept: use it for the checks that do not look at it.
func (r *prig) edit(key string, v any) {
	r.t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(r.read("mypool.pool.json")), &m); err != nil {
		r.t.Fatal(err)
	}
	if v == nil {
		delete(m, key)
	} else {
		m[key] = v
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	r.write("mypool.pool.json", b)
}

// spec: SPO-05a-OUT-001, SPO-05a-OUT-008, SPO-05a-OUT-011, SPO-05a-EXT-002, SPO-05a-EXT-004, SPO-05a-EXT-005, SPO-05a-IF-001,
// spec: SPO-05a-IN-005, SPO-05a-SEC-003, SPO-Pfiles-OUT-017, SPO-Pfiles-OUT-018, SPO-Pfiles-OUT-019, SPO-Pfiles-OUT-021, SPO-05a-MODE-001
func TestGenerateWritesTheArtefacts(t *testing.T) {
	r := newPoolRig(t)
	g, err := r.generate()
	if err != nil {
		t.Fatal(err)
	}
	idHex := hex.EncodeToString(r.poolID[:])
	if g.PoolIDHex != idHex || g.PoolIDBech != r.poolID.Bech32() {
		t.Errorf("ids %s %s", g.PoolIDHex, g.PoolIDBech)
	}
	if r.read("mypool.pool.id") != idHex+"\n" || r.read("mypool.pool.id-bech") != r.poolID.Bech32()+"\n" {
		t.Error("id files")
	}
	meta := r.read("mypool.metadata.json")
	if meta != "{\n  \"name\": \"My Pool\",\n  \"description\": \"A pool for tests\",\n  \"ticker\": \"MYPL\",\n  \"homepage\": \"https://example.org\"\n}\n" {
		t.Errorf("metadata %q", meta)
	}
	h, _ := r.led.MetadataHash([]byte(meta))
	if g.MetaHash != hex.EncodeToString(h[:]) {
		t.Error("metadata hash")
	}
	if r.read("mypool.pool.cert") != string(g.Certificate.Envelope) {
		t.Error("certificate file")
	}
	// The certificate says what the descriptor says: the cold, VRF, reward and owner keys.
	spec := g.Certificate.Registration
	if spec == nil || spec.Operator != r.poolID || spec.Pledge != 100_000_000_000 || spec.Cost != 340_000_000 || spec.Margin != (chain.Rational{Num: 1, Den: 10}) ||
		spec.RewardAccount != stake.KeyHash(r.hashOf("alice.staking.vkey")) || len(spec.Owners) != 2 || spec.MetaHash != h ||
		spec.MetaURL != "https://example.org/mypool.metadata.json" || len(spec.Relays) != 1 || spec.Relays[0].Kind != pool.RelayDNS {
		t.Errorf("%+v", spec)
	}
	d := r.descriptor()
	for k, v := range map[string]string{"poolID": idHex, "poolIDbech": g.PoolIDBech, "poolMetaHash": g.MetaHash, "regCertFile": "mypool.pool.cert",
		"regCertCreated": "Mon, 16 Nov 2026 12:00:00 +0000"} {
		if d.Text(k) != v {
			t.Errorf("%s = %q", k, d.Text(k))
		}
	}
	if d.Has("regProtectionKey") {
		t.Error("no protection key was given")
	}
	// The modes: the descriptor locked, the published metadata readable by all.
	for n, want := range map[string]os.FileMode{"mypool.pool.json": 0o400, "mypool.pool.cert": 0o400, "mypool.pool.id": 0o400, "mypool.metadata.json": 0o444} {
		if fi, _ := os.Stat(r.path(n)); fi.Mode().Perm() != want {
			t.Errorf("%s mode %v, want %v", n, fi.Mode().Perm(), want)
		}
	}
	// The owner entry that had no ownerWitness gets "local"; no signing key was read (it needs none).
	for _, o := range []string{"alice", "bob"} {
		r.remove(o + ".staking.skey")
	}
	r.remove("mypool.node.skey")
	if _, err := r.generate(); err != nil {
		t.Errorf("generation needs verification keys only: %v", err)
	}
}

// spec: SPO-05a-IF-001, SPO-05a-IF-002, SPO-05a-OUT-012, SPO-05a-SEC-001, SPO-05c-SEC-002
func TestProtectionKeyIsRecordedAndNeverReturned(t *testing.T) {
	r := newPoolRig(t)
	uc := GeneratePoolCertificate{Store: r.store, Params: r.chain, Certs: r.led, Hasher: r.led, Clock: r.clock}
	g, err := uc.Run(context.Background(), GenerateRequest{Pool: "./mypool.pool.json", ProtectionKey: "s3cr3t-protection-key"})
	if err != nil {
		t.Fatal(err)
	}
	if r.descriptor().Text("regProtectionKey") != "s3cr3t-protection-key" {
		t.Error("the key is recorded for 05c and the offline entry")
	}
	if fmt := strings.Join(append(g.Decisions, g.Warnings...), "\n"); strings.Contains(fmt, "s3cr3t") || strings.Contains(strings.ToLower(fmt), "protection key") == false {
		t.Errorf("decisions must name H6 and never repeat the key: %s", fmt)
	}
	if got := strings.Join([]string{g.PoolIDHex, g.PoolIDBech, g.MetaHash}, ""); strings.Contains(got, "s3cr3t") {
		t.Error("the result holds the key")
	}
	if _, err := uc.Run(context.Background(), GenerateRequest{Pool: "dir/mypool"}); !errors.Is(err, ErrBadPoolName) {
		t.Errorf("a directory part: %v", err)
	}
	if _, err := uc.Run(context.Background(), GenerateRequest{Pool: ""}); !errors.Is(err, ErrBadPoolName) {
		t.Errorf("an empty name: %v", err)
	}
}

// spec: SPO-05a-IF-003, SPO-05a-PRE-002, SPO-05a-PRE-003, SPO-05a-PRE-013, SPO-05a-PRE-004, SPO-05a-PRE-005, SPO-05a-PRE-006,
// spec: SPO-05a-PRE-007, SPO-05a-PRE-008, SPO-05a-PRE-009, SPO-05a-PRE-010, SPO-05a-PRE-012, SPO-05a-IN-001, SPO-05a-INV-001,
// spec: SPO-05a-EXT-003, SPO-05a-IN-006
func TestGenerationRefusalsWriteNothing(t *testing.T) {
	cases := []struct {
		name string
		do   func(r *prig)
		opt  func(*GeneratePoolCertificate)
		want error
	}{
		{"no descriptor", func(r *prig) { r.remove("mypool.pool.json") }, nil, ErrNoDescriptor},
		{"another pool's name", func(r *prig) { r.edit("poolName", "other") }, nil, pool.ErrNameMismatch},
		{"a required field is missing", func(r *prig) { r.edit("poolMetaName", nil) }, nil, pool.ErrMissingField},
		{"no cold verification key", func(r *prig) { r.remove("mypool.node.vkey") }, nil, ErrMissingFile},
		{"no VRF verification key", func(r *prig) { r.remove("mypool.vrf.vkey") }, nil, ErrMissingFile},
		{"no reward account key", func(r *prig) { r.remove("alice.staking.vkey") }, nil, ErrMissingFile},
		{"no owner key", func(r *prig) { r.remove("bob.staking.vkey") }, nil, ErrMissingFile},
		{"cost below the minimum", func(r *prig) { r.edit("poolCost", "1") }, nil, pool.ErrCostBelowMinimum},
		{"margin out of range", func(r *prig) { r.edit("poolMargin", "1.5") }, nil, pool.ErrBadMargin},
		{"relay without a port", func(r *prig) { r.edit("poolRelays", []map[string]string{{"relayType": "ip", "relayEntry": "1.2.3.4"}}) }, nil, pool.ErrBadRelay},
		{"relay of an unknown type", func(r *prig) {
			r.edit("poolRelays", []map[string]string{{"relayType": "tor", "relayEntry": "x", "relayPort": "1"}})
		}, nil, pool.ErrBadRelay},
		{"name too long", func(r *prig) { r.edit("poolMetaName", strings.Repeat("n", 51)) }, nil, pool.ErrMetadataLimit},
		{"ticker needs correcting", func(r *prig) { r.edit("poolMetaTicker", "A-B-C") }, nil, pool.ErrTickerCorrection},
		{"metadata over 512 bytes", func(r *prig) {
			r.edit("poolMetaName", strings.Repeat("n", 50))
			r.edit("poolMetaDescription", strings.Repeat("é", 255))
		}, nil, pool.ErrMetadataLimit},
		{"duplicate owner", func(r *prig) {
			r.edit("poolOwner", []map[string]string{{"ownerName": "alice"}, {"ownerName": "alice"}})
		}, nil, ErrDuplicateOwner},
		{"Incentivized Testnet keys", func(r *prig) {
			r.write("mypool.itn.skey", []byte("x"))
			r.write("mypool.itn.vkey", []byte("y"))
		}, nil, ErrITNUnsupported},
		{"protocol version 12 needs a BLS key", func(r *prig) { r.chain.params.ProtocolMajor = 12 }, nil, ErrBLSRequired},
		{"no minPoolCost in the parameters", func(r *prig) { r.chain.params.MinPoolCost = 0 }, nil, ErrParameterMissing},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newPoolRig(t)
			c.do(r)
			before := r.snapshot()
			_, err := r.generate(c.opt)
			if !isErr(err, c.want) {
				t.Fatalf("%v, want %v", err, c.want)
			}
			r.nothingChanged(before, "a refused generation")
		})
	}
}

// spec: SPO-05a-PR-001, SPO-05a-PR-002, SPO-05a-OUT-002, SPO-05a-IN-006
func TestCorrectionsAreAcceptedOnRequest(t *testing.T) {
	r := newPoolRig(t)
	r.edit("poolCost", "1")
	r.edit("poolMetaTicker", "ab-cd")
	g, err := r.generate(func(uc *GeneratePoolCertificate) { uc.Choices = pool.Choices{RaiseCost: true, AcceptTicker: true} })
	if err != nil {
		t.Fatal(err)
	}
	d := r.descriptor()
	if d.Text("poolCost") != "170000000" || d.Text("poolMetaTicker") != "ab_cd" || len(g.Corrections) != 2 {
		t.Errorf("%s %s %v", d.Text("poolCost"), d.Text("poolMetaTicker"), g.Corrections)
	}
	if g.Certificate.Registration.Cost != 170_000_000 || !strings.Contains(r.read("mypool.metadata.json"), `"ticker": "ab_cd"`) {
		t.Error("the corrected values go into the certificate and the metadata")
	}
}

// spec: SPO-05a-OUT-004, SPO-05a-OUT-005, SPO-05a-IN-002
func TestLegacyOwnerAndMissingWitnessAreNormalised(t *testing.T) {
	r := newPoolRig(t)
	r.edit("poolOwner", "alice")
	if _, err := r.generate(); err != nil {
		t.Fatal(err)
	}
	o, legacy, err := r.descriptor().Owners()
	if err != nil || legacy || len(o) != 1 || o[0].Name != "alice" || o[0].Witness != "local" {
		t.Errorf("%+v %v %v", o, legacy, err)
	}
}

// spec: SPO-05a-OUT-013
func TestRerunKeepsTheRegistrationRecord(t *testing.T) {
	r := newPoolRig(t)
	r.mustGenerate()
	r.edit("regEpoch", "5")
	r.edit("regSubmitted", "before")
	r.edit("regWitness", map[string]any{"id": 9})
	if _, err := r.generate(); err != nil {
		t.Fatal(err)
	}
	d := r.descriptor()
	if d.Text("regEpoch") != "5" || d.Text("regSubmitted") != "before" || !d.Has("regWitness") {
		t.Errorf("a re-run lost the record:\n%s", d.Render())
	}
}

// spec: SPO-05a-INV-003, SPO-05a-IN-003, SPO-05a-IN-004, SPO-05a-OUT-003, SPO-05a-OUT-006, SPO-05a-PRE-011, SPO-05a-OUT-007
func TestExtendedMetadata(t *testing.T) {
	r := newPoolRig(t)
	r.edit("poolExtendedMetaUrl", "https://example.org/extended.json")
	before := r.snapshot()
	// No additional metadata: a dummy is written, the run stops, nothing else is written.
	_, err := r.generate()
	if !errors.Is(err, ErrAdditionalMetadataCreated) {
		t.Fatalf("%v", err)
	}
	if !r.exists("mypool.additional-metadata.json") || r.exists("mypool.pool.cert") || r.exists("mypool.metadata.json") || r.exists("mypool.pool.id") {
		t.Error("only the dummy is written")
	}
	if !strings.Contains(r.read("mypool.additional-metadata.json"), hex.EncodeToString(r.poolID[:])) {
		t.Error("the dummy names the pool")
	}
	_ = before
	// Invalid additional metadata is refused and nothing more is written.
	r.write("mypool.additional-metadata.json", []byte("{"))
	snap := r.snapshot()
	if _, err := r.generate(); err == nil {
		t.Fatal("invalid JSON accepted")
	}
	r.nothingChanged(snap, "a refused generation")
	// With a valid one: the extended file, and the metadata carries the URL.
	r.write("mypool.additional-metadata.json", []byte(`{"info": {"location": "Earth"}}`))
	if _, err := r.generate(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.read("mypool.metadata.json"), "\"homepage\": \"https://example.org\",\n  \"extended\": \"https://example.org/extended.json\"\n}") {
		t.Errorf("%s", r.read("mypool.metadata.json"))
	}
	if r.read("mypool.extended-metadata.json") != "{\n  \"info\": {\n    \"location\": \"Earth\"\n  }\n}\n" {
		t.Errorf("%q", r.read("mypool.extended-metadata.json"))
	}
	if fi, _ := os.Stat(r.path("mypool.extended-metadata.json")); fi.Mode().Perm() != 0o444 {
		t.Error("the extended metadata is readable by all")
	}
	// A URL of 65 to 128 characters silently means no extended metadata; the result warns.
	r2 := newPoolRig(t)
	r2.edit("poolExtendedMetaUrl", "https://example.org/"+strings.Repeat("e", 60))
	g, err := r2.generate()
	if err != nil || len(g.Warnings) == 0 || r2.exists("mypool.extended-metadata.json") {
		t.Errorf("%v %v", err, g.Warnings)
	}
}

// spec: SPO-05a-PRE-012
func TestMetadataSizeLimitIsExact(t *testing.T) {
	size := func(j, k int) int {
		return len(pool.Metadata{Name: "My Pool", Description: strings.Repeat("é", j), Ticker: "MYPL", Homepage: "https://" + strings.Repeat("h", k)}.Render())
	}
	// Description characters are two bytes each: find a pair of lengths that
	// gives exactly 512 bytes, and the next one up (513).
	var j, k int
	found := false
	for j = 0; j <= 255 && !found; j++ {
		for k = 0; k <= 120 && !found; k++ {
			found = size(j, k) == 512
		}
	}
	j, k = j-1, k-1
	if !found || size(j, k+1) != 513 {
		t.Fatalf("fixture: %v %d %d", found, j, k)
	}
	for kk, ok := range map[int]bool{k: true, k + 1: false} {
		r := newPoolRig(t)
		r.edit("poolMetaDescription", strings.Repeat("é", j))
		r.edit("poolMetaHomepage", "https://"+strings.Repeat("h", kk))
		before := r.snapshot()
		_, err := r.generate()
		if ok != (err == nil) {
			t.Errorf("%d bytes: %v", size(j, kk), err)
		}
		if !ok {
			if !errors.Is(err, pool.ErrMetadataLimit) {
				t.Errorf("%v", err)
			}
			r.nothingChanged(before, "a refused generation")
		}
	}
}
