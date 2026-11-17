package poolkey

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

const phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

// The Calidus id of the public phrase at 1852H/1815H/0H/0/0, from cardano-signer.
const phraseID = "calidus15yqt0pru382hy9vjlsxv3ye02z50sfvt8xunscg5pgden7czfjdjq"

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

type fixedTip struct{ slot uint64 }

func (fixedTip) Source() chain.Source { return "test" }
func (f fixedTip) Tip(context.Context) (chain.Tip, error) {
	return chain.Tip{Slot: f.slot}, nil
}

type rig struct {
	dir   string
	store *plainstore.Store
	clock fixedClock
}

func newRig(t *testing.T) rig {
	t.Helper()
	dir := t.TempDir()
	st, err := plainstore.OpenTestnet(dir)
	if err != nil {
		t.Fatal(err)
	}
	return rig{dir, st, fixedClock{time.Date(2026, 11, 16, 12, 34, 56, 0, time.Local)}}
}

func (r rig) keyUC() GenerateCalidusKey {
	return GenerateCalidusKey{Store: r.store, Deriver: native.SoftwareKeys{}, Mnemonics: native.SoftwareKeys{}}
}

func (r rig) regUC() GenerateCalidusRegistration {
	return GenerateCalidusRegistration{Store: r.store, Signers: native.NewSignatureSigners(r.store), Clock: r.clock}
}

func (r rig) files(t *testing.T) []string {
	t.Helper()
	es, err := os.ReadDir(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

func (r rig) mode(t *testing.T, name string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(filepath.Join(r.dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func (r rig) put(t *testing.T, ref ports.Ref, b []byte) {
	t.Helper()
	err := r.store.Update(context.Background(), func(w ports.Writer) error {
		if ref.Kind.Secret() {
			return w.PutSecret(ref, secret.Take(append([]byte(nil), b...)))
		}
		return w.Put(ref, b)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (r rig) coldKey(t *testing.T, pool string) {
	t.Helper()
	pair, err := native.SoftwareKeys{}.GenerateCold(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer pair.SKey.Destroy()
	r.put(t, ports.Ref{Name: pool, Kind: ports.NodeVKey}, pair.VKey)
	if err := r.store.Update(context.Background(), func(w ports.Writer) error {
		return w.PutSecret(ports.Ref{Name: pool, Kind: ports.NodeSKey}, pair.SKey)
	}); err != nil {
		t.Fatal(err)
	}
}

// A Calidus key from the public phrase: the four artefacts, locked at 0400,
// the id of cardano-signer, and no secret in the result.
//
// spec: SPO-15-IF-002, SPO-15-EXT-001, SPO-15-OUT-001, SPO-15-INV-001, SPO-15-INV-004, SPO-15-SEC-001, SPO-15-SEC-003, SPO-Pfiles-OUT-036
func TestGenerateCalidusKeyFromMnemonic(t *testing.T) {
	r := newRig(t)
	m := secret.Take([]byte("  " + strings.ToUpper(phrase[:20]) + phrase[20:] + "\n"))
	defer m.Destroy()
	res, err := r.keyUC().Run(context.Background(), GenerateCalidusKeyRequest{Name: "./cal", Mnemonic: m})
	if err != nil {
		t.Fatal(err)
	}
	if res.Name != "cal" || res.ID != phraseID || !res.MnemonicStored {
		t.Errorf("result %+v", res)
	}
	got := r.files(t)
	want := []string{"cal.calidus.id", "cal.calidus.mnemonics", "cal.calidus.skey", "cal.calidus.vkey"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("files %v", got)
	}
	for _, f := range got {
		if r.mode(t, f) != 0o400 {
			t.Errorf("%s mode %v", f, r.mode(t, f))
		}
	}
	if b, _ := os.ReadFile(filepath.Join(r.dir, "cal.calidus.id")); string(b) != phraseID+"\n" {
		t.Errorf("id file %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(r.dir, "cal.calidus.mnemonics")); string(b) != phrase+"\n" {
		t.Error("the mnemonics file is not the normalised phrase and a newline")
	}
	// Nothing secret in the result, however it is formatted.
	if s := fmt.Sprintf("%+v %#v", res, res); strings.Contains(s, "abandon") || strings.Contains(s, "SigningKey") {
		t.Error("the result carries a secret")
	}
}

// Without a phrase a fresh 24-word mnemonic is generated, stored and not
// returned; a phrase of another length is refused before anything is written.
//
// spec: SPO-15-EXT-002, SPO-15-EXT-001, SPO-15-SEC-001
func TestGenerateCalidusKeyFreshAndBadPhrase(t *testing.T) {
	r := newRig(t)
	res, err := r.keyUC().Run(context.Background(), GenerateCalidusKeyRequest{Name: "fresh"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(r.dir, "fresh.calidus.mnemonics"))
	if n := len(strings.Fields(string(b))); n != 24 {
		t.Errorf("%d words", n)
	}
	if strings.Contains(fmt.Sprintf("%+v", res), strings.Fields(string(b))[0]+" "+strings.Fields(string(b))[1]) {
		t.Error("the result carries the phrase")
	}
	short := secret.Take([]byte("abandon abandon"))
	defer short.Destroy()
	n := len(r.files(t))
	if _, err := r.keyUC().Run(context.Background(), GenerateCalidusKeyRequest{Name: "short", Mnemonic: short}); !errors.Is(err, custody.ErrMnemonicWords) {
		t.Errorf("short phrase: %v", err)
	}
	if len(r.files(t)) != n {
		t.Error("a refused phrase left files")
	}
}

// An existing key is refused whichever artefact is there, and nothing changes;
// a hardware or remote holder is refused up front (upstream suspends `new hw`).
//
// spec: SPO-15-PRE-001, SPO-15-PRE-002
func TestGenerateCalidusKeyRefusals(t *testing.T) {
	r := newRig(t)
	if _, err := r.keyUC().Run(context.Background(), GenerateCalidusKeyRequest{Name: "k"}); err != nil {
		t.Fatal(err)
	}
	before := r.files(t)
	if _, err := r.keyUC().Run(context.Background(), GenerateCalidusKeyRequest{Name: "k"}); !errors.Is(err, ErrExists) {
		t.Errorf("second run: %v", err)
	}
	// An orphan hardware file is enough.
	r.put(t, ports.Ref{Name: "h", Kind: ports.CalidusHwsFile}, []byte("{}"))
	if _, err := r.keyUC().Run(context.Background(), GenerateCalidusKeyRequest{Name: "h"}); !errors.Is(err, ErrExists) {
		t.Errorf("hwsfile: %v", err)
	}
	if got := r.files(t); len(got) != len(before)+1 {
		t.Errorf("files changed: %v", got)
	}
	var ue *custody.UnsupportedError
	if _, err := r.keyUC().Run(context.Background(), GenerateCalidusKeyRequest{Name: "hw", Place: custody.PlaceHardware}); !errors.Is(err, ErrHardwareCalidusSuspended) {
		t.Errorf("hardware holder: %v", err)
	}
	if _, err := r.keyUC().Run(context.Background(), GenerateCalidusKeyRequest{Name: "rm", Place: "remote"}); !errors.As(err, &ue) {
		t.Errorf("remote holder: %v", err)
	}
	if _, err := r.keyUC().Run(context.Background(), GenerateCalidusKeyRequest{Name: "../x"}); !errors.Is(err, ErrBadName) {
		t.Errorf("bad name: %v", err)
	}
	if _, err := r.keyUC().Run(context.Background(), GenerateCalidusKeyRequest{Name: "r", Account: 1 << 31}); !errors.Is(err, ErrDerivationRange) {
		t.Errorf("range: %v", err)
	}
	if got := r.files(t); len(got) != len(before)+1 {
		t.Errorf("refusals wrote files: %v", got)
	}
}

// The registration: signed by the pool cold key through the vault signer, the
// file named from the pool and the local time, mode default, the metadata
// verifying with the pool's key; the nonce is the mainnet slot of the clock
// unless given or taken from the tip; the key files are untouched.
//
// spec: SPO-15-IN-002, SPO-15-EXT-003, SPO-15-OUT-002, SPO-15-IF-003, SPO-15-IF-004, SPO-15-MODE-001, SPO-15-MODE-002, SPO-15-INV-004, SPO-15-INV-005, SPO-15-OUT-004, SPO-15-SEC-004, SPO-Pfiles-OUT-036
func TestGenerateCalidusRegistration(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	m := secret.Take([]byte(phrase))
	defer m.Destroy()
	if _, err := r.keyUC().Run(ctx, GenerateCalidusKeyRequest{Name: "cal", Mnemonic: m}); err != nil {
		t.Fatal(err)
	}
	r.coldKey(t, "mypool")
	before, _ := os.ReadFile(filepath.Join(r.dir, "mypool.node.skey"))

	res, err := r.regUC().Run(ctx, CalidusRegistrationRequest{Calidus: "./cal.calidus.vkey", Pool: "mypool.node.skey"})
	if err != nil {
		t.Fatal(err)
	}
	wantName := "mypool_261116123456.calidus-registration.json"
	if res.Ref.Name+".calidus-registration.json" != wantName {
		t.Errorf("name %s", res.Ref.Name)
	}
	if r.mode(t, wantName) != 0o644 {
		t.Errorf("mode %v", r.mode(t, wantName))
	}
	file, _ := os.ReadFile(filepath.Join(r.dir, wantName))
	if string(file) != string(res.JSON) || !strings.HasPrefix(string(file), "{\n  \"867\": {") {
		t.Errorf("file %q", file[:40])
	}
	reg, err := cose.VerifyCip88(res.CBOR)
	if err != nil {
		t.Fatal(err)
	}
	if reg.Nonce != cose.MainnetSlotAt(r.clock.Now()) || res.Nonce != reg.Nonce {
		t.Errorf("nonce %d, want the mainnet slot of the clock %d", reg.Nonce, cose.MainnetSlotAt(r.clock.Now()))
	}
	if res.CalidusID != phraseID || fmt.Sprintf("%x", res.CalidusPub) != "63c5d69570349e4233a0575811464f0e8a3fd329abe76e9bdc3d3f1b95982179" {
		t.Errorf("calidus %s %x", res.CalidusID, res.CalidusPub)
	}
	if !strings.HasPrefix(res.PoolBech, "pool1") {
		t.Errorf("pool %s", res.PoolBech)
	}
	if after, _ := os.ReadFile(filepath.Join(r.dir, "mypool.node.skey")); string(after) != string(before) {
		t.Error("the cold key file changed")
	}
	// The JSON of the stored file is the signer's, indented: same keys, in order.
	if !strings.Contains(string(file), "\"4\": "+fmt.Sprint(reg.Nonce)) {
		t.Error("the nonce is not in the file")
	}

	// A given nonce wins; the tip is the default when wired; a second run in
	// the same second is refused (SPO-15-PRE-005) and writes nothing.
	later := r.regUC()
	later.Clock = fixedClock{r.clock.t.Add(time.Minute)}
	later.Tip = fixedTip{4242}
	res2, err := later.Run(ctx, CalidusRegistrationRequest{Calidus: "cal", Pool: "mypool"})
	if err != nil || res2.Nonce != 4242 {
		t.Fatalf("tip nonce: %v %d", err, res2.Nonce)
	}
	res3, err := later.Run(ctx, CalidusRegistrationRequest{Calidus: "cal", Pool: "mypool", Nonce: 99})
	if !errors.Is(err, ErrExists) {
		t.Fatalf("same second: %v %+v", err, res3)
	}
	later.Clock = fixedClock{r.clock.t.Add(2 * time.Minute)}
	res3, err = later.Run(ctx, CalidusRegistrationRequest{Calidus: "cal", Pool: "mypool", Nonce: 99})
	if err != nil || res3.Nonce != 99 {
		t.Fatalf("given nonce: %v %d", err, res3.Nonce)
	}
}

// The checks before anything is signed: missing Calidus key, missing cold key,
// no pool id; a failing signer is an error and leaves no file; the existing
// file refusal.
//
// spec: SPO-15-PRE-004, SPO-15-PRE-005, SPO-15-INV-003, SPO-15-EXT-003, SPO-15-OUT-002
func TestGenerateCalidusRegistrationRefusals(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if _, err := r.regUC().Run(ctx, CalidusRegistrationRequest{Calidus: "none", Pool: "p"}); !errors.Is(err, ErrMissingFile) {
		t.Errorf("no calidus key: %v", err)
	}
	m := secret.Take([]byte(phrase))
	defer m.Destroy()
	if _, err := r.keyUC().Run(ctx, GenerateCalidusKeyRequest{Name: "cal", Mnemonic: m}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.regUC().Run(ctx, CalidusRegistrationRequest{Calidus: "cal", Pool: "p"}); !errors.Is(err, ErrNoColdSigner) {
		t.Errorf("no cold key: %v", err)
	}
	// A cold signing key with no verification key and no id file: no pool id.
	r.put(t, ports.Ref{Name: "q", Kind: ports.NodeSKey}, []byte(`{"type":"StakePoolSigningKey_ed25519","description":"","cborHex":"5820`+strings.Repeat("11", 32)+`"}`))
	if _, err := r.regUC().Run(ctx, CalidusRegistrationRequest{Calidus: "cal", Pool: "q"}); !errors.Is(err, ErrNoPoolID) {
		t.Errorf("no pool id: %v", err)
	}
	// The id files come before the verification key (first match wins); a
	// wrong id file makes the signer refuse, not sign for another pool.
	r.coldKey(t, "p")
	other := chain.PoolID{1, 2, 3}
	bech, _ := chain.Bech32Encode("pool", other[:])
	r.put(t, ports.Ref{Name: "p", Kind: ports.PoolIDBechFile}, []byte(bech+"\n"))
	n := len(r.files(t))
	if _, err := r.regUC().Run(ctx, CalidusRegistrationRequest{Calidus: "cal", Pool: "p"}); err == nil || !strings.Contains(err.Error(), "not the pool's key") {
		t.Errorf("a stale pool id file: %v", err)
	}
	if len(r.files(t)) != n {
		t.Error("a refused signature left a file")
	}
	// A signer that fails: an error, no file (upstream exits 0 and writes none).
	uc := r.regUC()
	uc.Signers = failingDir{}
	if _, err := uc.Run(ctx, CalidusRegistrationRequest{Calidus: "cal", Pool: "q"}); err == nil {
		t.Error("signer failure was not an error")
	}
}

type failingDir struct{}

func (failingDir) SignerFor(custody.KeyRef) (ports.Signer, error) { return failingSigner{}, nil }

// Connected implements ports.SignerDirectory.
func (d failingDir) Connected(k custody.KeyRef) ([]ports.ConnectedSigner, error) {
	return ports.ConnectedVia(d, k)
}

type failingSigner struct{}

func (failingSigner) Profile() custody.Profile {
	return custody.NewProfile("failing").Allow(custody.RolePoolCold, custody.OpSignCip88)
}
func (failingSigner) SignCip88(context.Context, custody.Key[custody.PoolCold], cose.Cip88) (ports.Registration, error) {
	return ports.Registration{}, errors.New("device gone")
}

// A hardware cold key takes precedence over a software one and is refused up
// front, as is a remote holder: no registration is built, nothing is written.
//
// spec: SPO-15-INV-002
func TestRegistrationHardwareColdKeyRefusedUpFront(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	m := secret.Take([]byte(phrase))
	defer m.Destroy()
	if _, err := r.keyUC().Run(ctx, GenerateCalidusKeyRequest{Name: "cal", Mnemonic: m}); err != nil {
		t.Fatal(err)
	}
	r.coldKey(t, "p")
	r.put(t, ports.Ref{Name: "p", Kind: ports.NodeHwsFile}, []byte("{}"))
	// The hardware file wins beside a key file (SPO-15-INV-002) and, with no device
	// signer, is refused by the plan. (The old "remote holder" case is gone: a
	// holder can no longer be named in a request.)
	n := len(r.files(t))
	var ue *custody.UnsupportedError
	if _, err := r.regUC().Run(ctx, CalidusRegistrationRequest{Calidus: "cal", Pool: "p"}); !errors.As(err, &ue) {
		t.Errorf("hwsfile beside skey: %v", err)
	}
	if len(r.files(t)) != n {
		t.Error("a refused plan wrote a file")
	}
}

type recReader struct {
	got     []ports.CalidusFilter
	entries []ports.CalidusEntry
	err     error
}

func (*recReader) Source() chain.Source { return "test" }
func (r *recReader) CalidusKeys(_ context.Context, f ports.CalidusFilter) ([]ports.CalidusEntry, error) {
	r.got = append(r.got, f)
	return r.entries, r.err
}

// The subject is classified in upstream's order and the provider is asked with
// the matching filter; the first match wins.
//
// spec: SPO-15-IF-005
func TestQueryCalidusClassifiesSubjects(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	m := secret.Take([]byte(phrase))
	defer m.Destroy()
	if _, err := r.keyUC().Run(ctx, GenerateCalidusKeyRequest{Name: "cal", Mnemonic: m}); err != nil {
		t.Fatal(err)
	}
	r.coldKey(t, "pl")
	r.put(t, ports.Ref{Name: "ph", Kind: ports.PoolIDFile}, []byte(strings.Repeat("ab", 28)+"\n"))
	pub := "63c5d69570349e4233a0575811464f0e8a3fd329abe76e9bdc3d3f1b95982179"
	nodeV, _ := os.ReadFile(filepath.Join(r.dir, "pl.node.vkey"))
	nodePub, _ := cose.VKeyFromEnvelope(nodeV)
	h := cose.Blake2b224(nodePub[:])
	wantPool, _ := chain.Bech32Encode("pool", h[:])
	poolBech, _ := chain.Bech32Encode("pool", make([]byte, 28))
	hexPool, _ := chain.Bech32Encode("pool", []byte(strings.Repeat("\xab", 28)))
	// A stored name that is also valid hex wins as a file, as upstream's order has it.
	r.put(t, ports.Ref{Name: strings.Repeat("c", 64), Kind: ports.CalidusID}, []byte(phraseID+"\n"))

	for _, c := range []struct {
		subject string
		want    ports.CalidusFilter
	}{
		{phraseID, ports.CalidusFilter{IDBech: phraseID}},
		{"cal", ports.CalidusFilter{IDBech: phraseID}}, // cal.calidus.id before cal.calidus.vkey
		{strings.ToUpper(pub), ports.CalidusFilter{PubKeyHex: pub}},
		{strings.Repeat("c", 64), ports.CalidusFilter{IDBech: phraseID}},
		{poolBech, ports.CalidusFilter{PoolBech: poolBech}},
		{"ph", ports.CalidusFilter{PoolBech: hexPool}},
		{"pl", ports.CalidusFilter{PoolBech: wantPool}},
		{"ALL", ports.CalidusFilter{}},
		{"./cal", ports.CalidusFilter{IDBech: phraseID}},
	} {
		rd := &recReader{}
		if _, err := (QueryCalidus{Store: r.store, Reader: rd}).Run(ctx, c.subject); err != nil {
			t.Errorf("%q: %v", c.subject, err)
			continue
		}
		if len(rd.got) != 1 || rd.got[0] != c.want {
			t.Errorf("%q asked %+v, want %+v", c.subject, rd.got, c.want)
		}
	}
	// A vkey-only name uses the key's public key.
	r.put(t, ports.Ref{Name: "vonly", Kind: ports.CalidusVKey}, []byte(`{"type":"x","description":"","cborHex":"5820`+pub+`"}`))
	rd := &recReader{}
	if _, err := (QueryCalidus{Store: r.store, Reader: rd}).Run(ctx, "vonly"); err != nil || rd.got[0].PubKeyHex != pub {
		t.Errorf("vkey subject: %v %+v", err, rd.got)
	}
	// Invalid forms.
	for _, bad := range []string{"nothing-stored", "calidus1" + strings.Repeat("q", 53), "pool1" + strings.Repeat("q", 51), strings.Repeat("z", 64), ""} {
		rd := &recReader{}
		if _, err := (QueryCalidus{Store: r.store, Reader: rd}).Run(ctx, bad); !errors.Is(err, ErrBadSubject) || len(rd.got) != 0 {
			t.Errorf("%q: %v (asked %d)", bad, err, len(rd.got))
		}
	}
}

// Offline mode has no reader and refuses; the provider's failure is an error;
// no entry is an empty answer; the entries are passed on oldest first with the
// count of distinct Calidus ids.
//
// spec: SPO-15-PRE-006, SPO-15-PRE-007, SPO-15-OUT-005, SPO-15-MODE-002
func TestQueryCalidusResults(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if _, err := (QueryCalidus{Store: r.store}).Run(ctx, "all"); !errors.Is(err, ErrNoReader) {
		t.Errorf("offline: %v", err)
	}
	rd := &recReader{err: errors.New("koios 503")}
	if _, err := (QueryCalidus{Store: r.store, Reader: rd}).Run(ctx, "all"); err == nil {
		t.Error("a provider failure was not an error")
	}
	rd = &recReader{}
	res, err := (QueryCalidus{Store: r.store, Reader: rd}).Run(ctx, "all")
	if err != nil || len(res.Entries) != 0 || res.UniqueIDs != 0 {
		t.Errorf("no entries: %v %+v", err, res)
	}
	rd.entries = []ports.CalidusEntry{
		{PoolBech: "pool1a", IDBech: "calidus1x", Nonce: 5, HasNonce: true, TxHash: "aa", BlockTime: time.Unix(100, 0)},
		{PoolBech: "pool1a", IDBech: "calidus1y", Nonce: 9, HasNonce: true, TxHash: "bb", BlockTime: time.Unix(200, 0)},
		{PoolBech: "pool1b", IDBech: "calidus1y", TxHash: "cc"},
	}
	res, err = (QueryCalidus{Store: r.store, Reader: rd}).Run(ctx, "all")
	if err != nil || len(res.Entries) != 3 || res.UniqueIDs != 2 || res.Entries[0].TxHash != "aa" {
		t.Errorf("entries: %v %+v", err, res)
	}
}

// A signer that answers with a valid registration signed by another cold key
// (and naming that key's pool) is refused: the pool id demanded decides.
//
// spec: SPO-Xidentity-SEC-003
func TestRegistrationFromAnotherColdKeyIsRefused(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	m := secret.Take([]byte(phrase))
	defer m.Destroy()
	if _, err := r.keyUC().Run(ctx, GenerateCalidusKeyRequest{Name: "cal", Mnemonic: m}); err != nil {
		t.Fatal(err)
	}
	r.coldKey(t, "p")
	n := len(r.files(t))
	uc := r.regUC()
	uc.Signers = impostorDir{}
	if _, err := uc.Run(ctx, CalidusRegistrationRequest{Calidus: "cal", Pool: "p"}); !errors.Is(err, custody.ErrMessageKey) || len(r.files(t)) != n {
		t.Errorf("%v, files %d, want %d", err, len(r.files(t)), n)
	}
}

type impostorDir struct{}

func (impostorDir) SignerFor(custody.KeyRef) (ports.Signer, error) { return impostorSigner{}, nil }

// Connected implements ports.SignerDirectory.
func (d impostorDir) Connected(k custody.KeyRef) ([]ports.ConnectedSigner, error) {
	return ports.ConnectedVia(d, k)
}

type impostorSigner struct{}

func (impostorSigner) Profile() custody.Profile {
	return custody.NewProfile("impostor").Allow(custody.RolePoolCold, custody.OpSignCip88)
}

// SignCip88 registers for the pool of a cold key of its own.
func (impostorSigner) SignCip88(_ context.Context, _ custody.Key[custody.PoolCold], reg cose.Cip88) (ports.Registration, error) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	reg.PoolID = cose.Blake2b224(pub)
	return ports.Registration{CBOR: reg.Metadata(pub, ed25519.Sign(priv, reg.ToBeSigned()))}, nil
}
