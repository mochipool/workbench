package registry

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
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/assets"
	dassets "github.com/mochipool/workbench/spo/internal/domain/assets"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/tokenmeta"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

type fakeTip struct{}

func (fakeTip) Source() chain.Source                   { return "fake" }
func (fakeTip) Tip(context.Context) (chain.Tip, error) { return chain.Tip{Slot: 1000}, nil }

type fakeLogos map[string][]byte

func (f fakeLogos) ReadLogoFile(path string) ([]byte, error) {
	b, ok := f[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return b, nil
}

var png = append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{7}, 60)...)

type world struct {
	t     *testing.T
	dir   string
	store *plainstore.Store
	clock fixedClock
	logos fakeLogos
}

func newWorld(t *testing.T) *world {
	t.Helper()
	dir := t.TempDir()
	st, err := plainstore.OpenTestnet(dir)
	if err != nil {
		t.Fatal(err)
	}
	return &world{t: t, dir: dir, store: st, logos: fakeLogos{},
		clock: fixedClock{time.Date(2026, 11, 16, 9, 51, 2, 0, time.FixedZone("", 3600))}}
}

func (w *world) policy(name string, lifetime uint64) assets.PolicyGenerated {
	w.t.Helper()
	g, err := assets.GeneratePolicy{Store: w.store, KeyGen: native.SoftwareKeys{}, Policies: native.Ledger{}, Tip: fakeTip{}}.
		Run(context.Background(), assets.GeneratePolicyRequest{Name: name, Lifetime: lifetime})
	if err != nil {
		w.t.Fatal(err)
	}
	return g
}

func (w *world) gen() GenerateTokenMetadata {
	return GenerateTokenMetadata{Store: w.store, Signers: native.RegistrySigners{Vault: w.store}, Clock: w.clock, Logos: w.logos}
}

func (w *world) read(ref ports.Ref) ([]byte, bool) {
	w.t.Helper()
	var b []byte
	var ok bool
	if err := w.store.View(context.Background(), func(r ports.Reader) error {
		v, err := r.Get(ref)
		if errors.Is(err, ports.ErrNotFound) {
			return nil
		}
		b, ok = v, err == nil
		return err
	}); err != nil {
		w.t.Fatal(err)
	}
	return b, ok
}

func (w *world) record(name string) dassets.Record {
	w.t.Helper()
	b, ok := w.read(ports.Ref{Name: name, Kind: ports.AssetFile})
	if !ok {
		w.t.Fatalf("no record %s", name)
	}
	r, err := dassets.ParseRecord(b)
	if err != nil {
		w.t.Fatal(err)
	}
	return r
}

// edit sets string keys of the record, as the operator does by hand.
func (w *world) edit(name string, kv map[string]string) {
	w.t.Helper()
	r := w.record(name)
	for k, v := range kv {
		r.Set(k, v)
	}
	if err := w.store.Update(context.Background(), func(wr ports.Writer) error {
		return wr.Put(ports.Ref{Name: name, Kind: ports.AssetFile}, r.Marshal())
	}); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) fill(name string) {
	w.edit(name, map[string]string{"metaName": "My Token", "metaDescription": "A token for tests", "metaTicker": "MYT",
		"metaUrl": "https://example.org", "metaDecimals": "6"})
}

// spec: SPO-12a-IF-001, SPO-12a-IF-002, SPO-12a-IN-003, SPO-12a-IN-004, SPO-12a-OUT-001
func TestFirstRunCreatesTheRecordAndStops(t *testing.T) {
	w := newWorld(t)
	g := w.policy("tok", 5000)
	res, err := w.gen().Run(context.Background(), GenerateRequest{Asset: "tok.MYTOKEN.asset"}) // a trailing .asset is dropped
	if err != nil {
		t.Fatal(err)
	}
	if !res.Created || res.Sequence != 0 || res.File != (ports.Ref{}) {
		t.Fatalf("result: %+v", res)
	}
	rec := w.record("tok.MYTOKEN")
	want := []string{"metaName", "metaDescription", "metaDecimals", "metaTicker", "metaUrl", "metaLogoPNG", "---", "===",
		"minted", "name", "hexname", "bechName", "policyID", "policyValidBeforeSlot", "subject", "sequenceNumber", "lastUpdate", "lastAction"}
	if got := rec.Keys(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("keys\n got %v\nwant %v", got, want)
	}
	for k, v := range map[string]string{"metaName": "MYTOKEN", "metaDecimals": "", "minted": "0", "name": "MYTOKEN", "hexname": "",
		"policyID": g.PolicyID, "policyValidBeforeSlot": "6000", "sequenceNumber": "0", "lastAction": "created Asset-File",
		"subject": g.PolicyID + hex.EncodeToString([]byte("MYTOKEN"))} {
		if rec.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, rec.Get(k), v)
		}
	}
	if _, ok := w.read(ports.Ref{Name: res.Subject, Kind: ports.TokenRegistration}); ok {
		t.Error("the first run wrote a submission file")
	}
	// A {hex} name keeps its hex in hexname and reads hex-<hex> in the store.
	r2, err := w.gen().Run(context.Background(), GenerateRequest{Asset: "tok.{00010203}"})
	if err != nil || !r2.Created {
		t.Fatalf("%v %+v", err, r2)
	}
	if h := w.record("tok.hex-00010203").Get("hexname"); h != "00010203" {
		t.Errorf("hexname %q", h)
	}
	// The name rules of SPO-11a-IF-003 (SPO-12a-IF-002) and the argument shape (SPO-12a-IF-001).
	for _, a := range []string{"tok", "tok.my token", "tok.{zz}", "tok." + strings.Repeat("a", 33), "tok.{" + strings.Repeat("00", 33) + "}", "a.b.c", ".x"} {
		if _, err := w.gen().Run(context.Background(), GenerateRequest{Asset: a}); err == nil {
			t.Errorf("%q accepted", a)
		}
	}
}

func TestFirstRunUnlimitedPolicy(t *testing.T) {
	w := newWorld(t)
	w.policy("free", 0)
	if _, err := w.gen().Run(context.Background(), GenerateRequest{Asset: "free.COIN"}); err != nil {
		t.Fatal(err)
	}
	if v := w.record("free.COIN").Get("policyValidBeforeSlot"); v != "unlimited" {
		t.Errorf("policyValidBeforeSlot %q", v)
	}
	// A readable name is cut to 50 characters (SPO-12a-OUT-001); a 32-byte name is under it, so
	// only the hex form of a binary name can approach it: 64 hex digits are cut.
	if _, err := w.gen().Run(context.Background(), GenerateRequest{Asset: "free.{" + strings.Repeat("ff", 32) + "}"}); err != nil {
		t.Fatal(err)
	}
	if n := len(w.record("free.hex-" + strings.Repeat("ff", 32)).Get("metaName")); n != 50 {
		t.Errorf("metaName is %d characters", n)
	}
}

// spec: SPO-12a-OUT-002, SPO-12a-OUT-003, SPO-12a-OUT-004, SPO-12a-INV-001, SPO-12a-INV-002, SPO-12a-SEC-001, SPO-12a-SEC-002
// spec: SPO-12a-EXT-001, SPO-12a-EXT-002, SPO-12a-EXT-003, SPO-12a-EXT-004
func TestGenerateSignsStoresAndCountsUp(t *testing.T) {
	w := newWorld(t)
	g := w.policy("tok", 5000)
	if _, err := w.gen().Run(context.Background(), GenerateRequest{Asset: "tok.MYTOKEN"}); err != nil {
		t.Fatal(err)
	}
	w.fill("tok.MYTOKEN")
	w.logos["logo.png"] = png
	w.edit("tok.MYTOKEN", map[string]string{"metaLogoPNG": "logo.png"})
	before := w.record("tok.MYTOKEN")

	res, err := w.gen().Run(context.Background(), GenerateRequest{Asset: "tok.MYTOKEN"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Created || res.Sequence != 1 || res.Subject != before.Get("subject") {
		t.Fatalf("result %+v", res)
	}
	b, ok := w.read(res.File)
	if !ok || res.File.Name != res.Subject {
		t.Fatalf("submission file %v %v", res.File, ok)
	}
	e, err := tokenmeta.ParseEntry(b)
	if err != nil {
		t.Fatal(err)
	}
	v := e.Verify()
	if !v.OK || !v.PolicyChecked || !v.PolicyIDMatches || len(e.Props) != 6 {
		t.Fatalf("entry: %+v", v)
	}
	for p, a := range e.Props {
		if a.Sequence != 1 {
			t.Errorf("%s: sequence %d", p, a.Sequence)
		}
	}
	if d := e.Props[tokenmeta.PropDecimals]; d.Value.Number() != 6 {
		t.Errorf("decimals %v", d.Value)
	}
	if !bytes.Equal(e.Props[tokenmeta.PropLogo].Value.Bytes(), png) {
		t.Error("the logo is not the file's")
	}
	rec := w.record("tok.MYTOKEN")
	if rec.Get("sequenceNumber") != "1" || rec.Get("lastAction") != "created Token-Registry-JSON" ||
		rec.Get("lastUpdate") != "Mon, 16 Nov 2026 09:51:02 +0100" {
		t.Errorf("record %q %q %q", rec.Get("sequenceNumber"), rec.Get("lastAction"), rec.Get("lastUpdate"))
	}
	if rec.Get("policyID") != g.PolicyID {
		t.Error("a key of the record changed")
	}
	// No secret in the submission: not the policy key's seed.
	skey, _ := os.ReadFile(filepath.Join(w.dir, "tok.policy.skey"))
	var seed string
	if i := strings.Index(string(skey), `"cborHex": "5820`); i >= 0 {
		seed = string(skey)[i+len(`"cborHex": "5820`) : i+len(`"cborHex": "5820`)+64]
	}
	if seed == "" || strings.Contains(string(b), seed) {
		t.Errorf("the submission carries the signing key (seed found: %v)", seed != "")
	}

	// A second run counts up by one and replaces the file (SPO-12a-INV-002, SPO-12a-OUT-004).
	res2, err := w.gen().Run(context.Background(), GenerateRequest{Asset: "tok.MYTOKEN"})
	if err != nil || res2.Sequence != 2 {
		t.Fatalf("%v %+v", err, res2)
	}
	b2, _ := w.read(res2.File)
	e2, err := tokenmeta.ParseEntry(b2)
	if err != nil || !e2.Verify().OK {
		t.Fatalf("second entry: %v", err)
	}
	if s, _ := e2.Sequence(); s != 2 || w.record("tok.MYTOKEN").Get("sequenceNumber") != "2" {
		t.Errorf("sequence %d", s)
	}
}

// spec: SPO-12a-OUT-002
// A record made by 11a has no metaDecimals; 12a adds "0" and so registers 0 decimals
// (upstream quirk, reproduced). The record is rewritten only when the run succeeds.
func TestNormaliseAddsDecimalsZeroAndKeepsExistingKeys(t *testing.T) {
	w := newWorld(t)
	w.policy("tok", 0)
	if _, err := w.gen().Run(context.Background(), GenerateRequest{Asset: "tok.A"}); err != nil {
		t.Fatal(err)
	}
	// Rebuild the record as 11a writes it: no metaDecimals, a custom key kept.
	r := w.record("tok.A")
	skel, _ := dassets.ParseRecord(nil)
	for _, k := range r.Keys() {
		if k != "metaDecimals" {
			skel.Set(k, r.Get(k))
		}
	}
	skel.Set("custom", "kept")
	skel.Set("metaName", "Alpha")
	skel.Set("metaDescription", "desc")
	if err := w.store.Update(context.Background(), func(wr ports.Writer) error {
		return wr.Put(ports.Ref{Name: "tok.A", Kind: ports.AssetFile}, skel.Marshal())
	}); err != nil {
		t.Fatal(err)
	}
	res, err := w.gen().Run(context.Background(), GenerateRequest{Asset: "tok.A"})
	if err != nil {
		t.Fatal(err)
	}
	rec := w.record("tok.A")
	if rec.Get("metaDecimals") != "0" || rec.Get("custom") != "kept" || rec.Get("metaName") != "Alpha" {
		t.Errorf("record: decimals %q custom %q", rec.Get("metaDecimals"), rec.Get("custom"))
	}
	if d, ok := res.Entry.Props[tokenmeta.PropDecimals]; !ok || d.Value.Number() != 0 {
		t.Error("0 decimals were not registered")
	}
	// Existing keys win: lastUpdate of the first run was not refreshed by the skeleton before the change.
	if rec.Get("policyValidBeforeSlot") != "unlimited" {
		t.Errorf("policyValidBeforeSlot %q", rec.Get("policyValidBeforeSlot"))
	}
}

// spec: SPO-12a-PRE-001, SPO-12a-PRE-002, SPO-12a-PRE-003, SPO-12a-PRE-004, SPO-12a-PRE-005, SPO-12a-PRE-006, SPO-12a-OUT-002
// An invalid field is refused and leaves the record exactly as it was: upstream locks it first
// (a decision of the port notes), here nothing is written.
func TestInvalidFieldRefusedRecordUntouched(t *testing.T) {
	w := newWorld(t)
	w.policy("tok", 0)
	if _, err := w.gen().Run(context.Background(), GenerateRequest{Asset: "tok.A"}); err != nil {
		t.Fatal(err)
	}
	w.fill("tok.A")
	ref := ports.Ref{Name: "tok.A", Kind: ports.AssetFile}
	cases := []struct {
		name string
		kv   map[string]string
	}{
		{"empty name", map[string]string{"metaName": ""}},
		{"long name", map[string]string{"metaName": strings.Repeat("n", 51)}},
		{"empty description", map[string]string{"metaDescription": ""}},
		{"short ticker", map[string]string{"metaTicker": "A"}},
		{"url without https", map[string]string{"metaUrl": "http://x"}},
		{"url with https inside", map[string]string{"metaUrl": "see https://x"}},
		{"decimals text", map[string]string{"metaDecimals": "six"}},
		{"decimals 300", map[string]string{"metaDecimals": "300"}},
		{"decimals 20", map[string]string{"metaDecimals": "20"}},
		{"missing logo file", map[string]string{"metaLogoPNG": "nothere.png"}},
	}
	w.logos["gif.png"] = []byte("GIF89a")
	cases = append(cases, struct {
		name string
		kv   map[string]string
	}{"logo not png", map[string]string{"metaLogoPNG": "gif.png"}})
	for _, c := range cases {
		w.fill("tok.A")
		w.edit("tok.A", c.kv)
		before, _ := w.read(ref)
		if _, err := w.gen().Run(context.Background(), GenerateRequest{Asset: "tok.A"}); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
		if after, _ := w.read(ref); !bytes.Equal(before, after) {
			t.Errorf("%s: the record changed", c.name)
		}
	}
	// A logo is read through the reader.
	w.fill("tok.A")
	w.edit("tok.A", map[string]string{"metaLogoPNG": "ok.png"})
	g := w.gen()
	g.Logos = nil
	if _, err := g.Run(context.Background(), GenerateRequest{Asset: "tok.A"}); !errors.Is(err, ErrNoLogoSource) {
		t.Errorf("no reader: %v", err)
	}
}

// spec: SPO-12a-IN-002
func TestPolicyFilesAndHardwareRefusal(t *testing.T) {
	w := newWorld(t)
	// Nothing of the policy.
	if _, err := w.gen().Run(context.Background(), GenerateRequest{Asset: "none.A"}); !errors.Is(err, ErrPolicyFiles) {
		t.Errorf("no policy: %v", err)
	}
	w.policy("tok", 0)
	if _, err := w.gen().Run(context.Background(), GenerateRequest{Asset: "tok.A"}); err != nil {
		t.Fatal(err)
	}
	w.fill("tok.A")
	// A hardware signing file: refused before the signing key is looked at, and nothing is written.
	if err := w.store.Update(context.Background(), func(wr ports.Writer) error {
		return wr.Put(ports.Ref{Name: "tok", Kind: ports.PolicyHwsFile}, []byte("{}\n"))
	}); err != nil {
		t.Fatal(err)
	}
	before, _ := w.read(ports.Ref{Name: "tok.A", Kind: ports.AssetFile})
	_, err := w.gen().Run(context.Background(), GenerateRequest{Asset: "tok.A"})
	if err == nil || !strings.Contains(err.Error(), "hardware") {
		t.Fatalf("hardware policy: %v", err)
	}
	if after, _ := w.read(ports.Ref{Name: "tok.A", Kind: ports.AssetFile}); !bytes.Equal(before, after) {
		t.Error("the record changed")
	}
	// A directory that has a registry signer for hardware would be planned, not refused blind: a
	// profile without the operation is refused by the plan.
	if _, err := (GenerateTokenMetadata{Store: w.store, Signers: native.NewSignatureSigners(w.store), Clock: w.clock}).
		Run(context.Background(), GenerateRequest{Asset: "tok.A"}); err == nil {
		t.Error("a directory without the registry capability signed")
	}
	// Without the key (and no hardware file): refused.
	w2 := newWorld(t)
	w2.policy("tok", 0)
	_ = os.Remove(filepath.Join(w2.dir, "tok.policy.skey"))
	if _, err := w2.gen().Run(context.Background(), GenerateRequest{Asset: "tok.A"}); !errors.Is(err, ErrPolicyFiles) {
		t.Errorf("no key: %v", err)
	}
}

// spec: SPO-12a-INV-001
// The subject is the record's, never recomputed, and the sequence number is read as a decimal
// number: shell arithmetic would take `010` as octal and a word as 0 (upstream quirks, refused).
func TestSubjectAndSequenceAreTheRecords(t *testing.T) {
	w := newWorld(t)
	w.policy("tok", 0)
	if _, err := w.gen().Run(context.Background(), GenerateRequest{Asset: "tok.A"}); err != nil {
		t.Fatal(err)
	}
	w.fill("tok.A")
	for _, bad := range []string{"abc", "", "-1", "1.5", "0x10"} {
		w.edit("tok.A", map[string]string{"sequenceNumber": bad})
		if _, err := w.gen().Run(context.Background(), GenerateRequest{Asset: "tok.A"}); !errors.Is(err, ErrBadSequence) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	w.edit("tok.A", map[string]string{"sequenceNumber": "010"})
	res, err := w.gen().Run(context.Background(), GenerateRequest{Asset: "tok.A"})
	if err != nil || res.Sequence != 11 {
		t.Errorf("010 is decimal ten: %v %+v", err, res)
	}
	// A subject of another policy cannot be signed with this policy's script.
	w.edit("tok.A", map[string]string{"subject": strings.Repeat("ab", 28) + "41"})
	if _, err := w.gen().Run(context.Background(), GenerateRequest{Asset: "tok.A"}); err == nil {
		t.Error("another policy's subject was signed")
	}
	w.edit("tok.A", map[string]string{"subject": "zz"})
	if _, err := w.gen().Run(context.Background(), GenerateRequest{Asset: "tok.A"}); err == nil {
		t.Error("a bad subject was signed")
	}
}

// A signer that attests with another key (a self-consistent signature) is
// refused: the attestation must come from the policy's key.
//
// spec: SPO-Xidentity-SEC-001
func TestAttestationFromAnotherKeyIsRefused(t *testing.T) {
	w := newWorld(t)
	w.policy("tok", 5000)
	if _, err := w.gen().Run(context.Background(), GenerateRequest{Asset: "tok.MYTOKEN"}); err != nil {
		t.Fatal(err)
	}
	w.fill("tok.MYTOKEN")
	uc := w.gen()
	uc.Signers = impostorDir{}
	if _, err := uc.Run(context.Background(), GenerateRequest{Asset: "tok.MYTOKEN"}); !errors.Is(err, tokenmeta.ErrSigner) || !strings.Contains(err.Error(), custody.ErrMessageKey.Error()) {
		t.Errorf("%v", err)
	}
	if w.record("tok.MYTOKEN").Get("sequenceNumber") != "0" {
		t.Error("the record was counted up")
	}
}

type impostorDir struct{}

func (impostorDir) SignerFor(custody.KeyRef) (ports.Signer, error) { return impostor{}, nil }

// Connected implements ports.SignerDirectory.
func (d impostorDir) Connected(k custody.KeyRef) ([]ports.ConnectedSigner, error) {
	return ports.ConnectedVia(d, k)
}

type impostor struct{}

func (impostor) Profile() custody.Profile {
	return custody.NewProfile("impostor").Allow(custody.RolePolicy, custody.OpSignRegistryEntry)
}

func (impostor) SignRegistryMessages(_ context.Context, _ custody.Key[custody.Policy], msgs [][32]byte) ([]ports.RegistryAttestation, error) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	out := make([]ports.RegistryAttestation, len(msgs))
	for i, m := range msgs {
		copy(out[i].PublicKey[:], pub)
		copy(out[i].Signature[:], ed25519.Sign(priv, m[:]))
	}
	return out, nil
}
