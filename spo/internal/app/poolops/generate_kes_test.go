package poolops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

const fakeSKey = `{"type":"KesSigningKey_ed25519_kes_2^6","description":"KES Signing Key","cborHex":"5902c0deadbeef"}`
const fakeVKey = `{"type":"KesVerificationKey_ed25519_kes_2^6","description":"KES Verification Key","cborHex":"5820aa"}`

type fakeKeyGen struct {
	calls int
	err   error
}

func (f *fakeKeyGen) GenerateKES(context.Context) (ports.KeyPair, error) {
	f.calls++
	if f.err != nil {
		return ports.KeyPair{}, f.err
	}
	return ports.KeyPair{VKey: []byte(fakeVKey), SKey: secret.Take([]byte(fakeSKey))}, nil
}

func setup(t *testing.T) (GenerateKesKey, *fakeKeyGen, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := plainstore.OpenTestnet(dir)
	if err != nil {
		t.Fatal(err)
	}
	kg := &fakeKeyGen{}
	return GenerateKesKey{Store: st, KeyGen: kg}, kg, dir
}

func read(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func files(t *testing.T, dir string) []string {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// spec: SPO-04c-OUT-001, SPO-04c-OUT-003, SPO-04c-OUT-004, SPO-04c-INV-001, SPO-04c-IN-001, SPO-04c-IN-002
func TestFirstKeyOfAFreshPool(t *testing.T) {
	uc, _, dir := setup(t)
	res, err := uc.Run(context.Background(), "mypool")
	if err != nil {
		t.Fatal(err)
	}
	if res.Number != 0 {
		t.Fatalf("number = %d", res.Number)
	}
	if read(t, dir, "mypool.kes.counter") != "000\n" || read(t, dir, "mypool.kes.counter-next") != "000\n" {
		t.Fatal("counters wrong")
	}
	if read(t, dir, "mypool.kes-000.skey") != fakeSKey || read(t, dir, "mypool.kes-000.vkey") != fakeVKey {
		t.Fatal("key files wrong")
	}
}

// spec: SPO-04c-PRE-001
//
// Upstream quirk decision (SPO-04c-OUT-001): upstream creates counter-next
// before it checks anything, so the file persists after a refusal. Fixed:
// a refusal writes nothing.
func TestRefusesWhileNewestKeyIsUnconsumed(t *testing.T) {
	uc, kg, dir := setup(t)
	if _, err := uc.Run(context.Background(), "mypool"); err != nil {
		t.Fatal(err)
	}
	before := files(t, dir)
	_, err := uc.Run(context.Background(), "mypool")
	if !errors.Is(err, pool.ErrKesKeyUnconsumed) {
		t.Fatalf("err = %v", err)
	}
	if kg.calls != 1 {
		t.Fatalf("a key was generated for a refused request (%d calls)", kg.calls)
	}
	if after := files(t, dir); strings.Join(after, ",") != strings.Join(before, ",") {
		t.Fatalf("refusal changed the workspace: %v -> %v", before, after)
	}
}

// spec: SPO-04c-OUT-003 (the 04d side, SPO-04d-OUT-003, advances next)
func TestNextKeyAfterAnOpCertConsumedTheLast(t *testing.T) {
	uc, _, dir := setup(t)
	uc.Run(context.Background(), "mypool")
	// What 04d does when it issues an opcert for key 0.
	os.Chmod(filepath.Join(dir, "mypool.kes.counter-next"), 0o600)
	os.WriteFile(filepath.Join(dir, "mypool.kes.counter-next"), []byte("001\n"), 0o400)
	res, err := uc.Run(context.Background(), "mypool")
	if err != nil || res.Number != 1 {
		t.Fatalf("number=%d err=%v", res.Number, err)
	}
	if read(t, dir, "mypool.kes.counter") != "001\n" {
		t.Fatal("current counter not advanced")
	}
}

// spec: SPO-04c-PRE-002
func TestRefusesToOverwriteExistingKeyFiles(t *testing.T) {
	for _, existing := range []string{"mypool.kes-000.vkey", "mypool.kes-000.skey"} {
		uc, kg, dir := setup(t)
		os.WriteFile(filepath.Join(dir, existing), []byte("old"), 0o400)
		_, err := uc.Run(context.Background(), "mypool")
		if !errors.Is(err, ErrKesKeyExists) {
			t.Fatalf("%s: err = %v", existing, err)
		}
		if kg.calls != 0 || read(t, dir, existing) != "old" {
			t.Fatalf("%s: existing key touched", existing)
		}
	}
}

// spec: SPO-04c-EXT-001
//
// Upstream quirk decision (SPO-04c-PRE-004): upstream can leave an orphaned
// .vkey. Fixed: a failed generation leaves the workspace unchanged.
func TestToolFailureLeavesNothingBehind(t *testing.T) {
	uc, kg, dir := setup(t)
	kg.err = errors.New("cardano-cli exited 1")
	if _, err := uc.Run(context.Background(), "mypool"); err == nil {
		t.Fatal("no error")
	}
	if got := files(t, dir); len(got) != 0 {
		t.Fatalf("orphans: %v", got)
	}
}

// spec: SPO-04c-SEC-001
//
// Upstream prints the signing key. Decision: fixed. The result carries the
// verification key only.
func TestResultHoldsNoSigningKey(t *testing.T) {
	uc, _, _ := setup(t)
	res, err := uc.Run(context.Background(), "mypool")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(res.VKey), "deadbeef") || strings.Contains(res.Pool, "deadbeef") {
		t.Fatal("signing key material in the result")
	}
}

func TestMalformedCounterIsAnError(t *testing.T) {
	uc, kg, dir := setup(t)
	os.WriteFile(filepath.Join(dir, "mypool.kes.counter"), []byte("0x1\n"), 0o400)
	if _, err := uc.Run(context.Background(), "mypool"); !errors.Is(err, pool.ErrBadCounter) {
		t.Fatalf("err = %v", err)
	}
	if kg.calls != 0 {
		t.Fatal("generated despite a malformed counter")
	}
}
