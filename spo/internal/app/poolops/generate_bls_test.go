package poolops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

type blsFakeGen struct {
	calls int
	err   error
}

func (g *blsFakeGen) GenerateBLS(context.Context) (ports.KeyPair, error) {
	g.calls++
	if g.err != nil {
		return ports.KeyPair{}, g.err
	}
	return ports.KeyPair{
		VKey: []byte(`{"type":"BlsVerificationKey_x","description":"BLS12-381 verification key","cborHex":"5860aa"}` + "\n"),
		SKey: secret.Take([]byte(`{"type":"BlsSigningKey_x","description":"BLS12-381 signing key","cborHex":"5820bb"}` + "\n")),
	}, nil
}

func blsSetup(t *testing.T) (GenerateBLSKeys, *blsFakeGen, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := plainstore.OpenTestnet(dir)
	if err != nil {
		t.Fatal(err)
	}
	g := &blsFakeGen{}
	return GenerateBLSKeys{Store: st, KeyGen: g}, g, dir
}

// The pair is written as `<pool>.bls.vkey` and `<pool>.bls.skey`, both locked
// at 0400, and the result carries the verification key only: the signing
// key is never handed back to be printed.
//
// spec: SPO-04f-IF-001, SPO-04f-OUT-001, SPO-04f-SEC-001, SPO-Pfiles-OUT-016
func TestGenerateBLSKeys(t *testing.T) {
	uc, g, dir := blsSetup(t)
	res, err := uc.Run(context.Background(), GenerateBLSKeysRequest{Pool: "mypool"})
	if err != nil || g.calls != 1 {
		t.Fatalf("%v (generated %d times)", err, g.calls)
	}
	for _, n := range []string{"mypool.bls.vkey", "mypool.bls.skey"} {
		st, err := os.Stat(filepath.Join(dir, n))
		if err != nil || st.Mode().Perm() != 0o400 {
			t.Errorf("%s: %v %v", n, st, err)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "mypool.bls.vkey")); string(b) != string(res.VKey) {
		t.Errorf("the stored verification key is not the one returned")
	}
	if strings.Contains(string(res.VKey), "BlsSigningKey") || res.Pool != "mypool" {
		t.Errorf("the result leaks the signing key: %+v", res)
	}
}

// Either file existing refuses before anything is generated, and a failing
// generator leaves nothing behind (no orphaned verification key, which the
// upstream script leaves and which then blocks the retry).
//
// spec: SPO-04f-PRE-001, SPO-04f-PRE-003
func TestGenerateBLSKeysRefusesAndIsAtomic(t *testing.T) {
	for _, existing := range []string{"p.bls.vkey", "p.bls.skey"} {
		uc, g, dir := blsSetup(t)
		if err := os.WriteFile(filepath.Join(dir, existing), []byte("x"), 0o400); err != nil {
			t.Fatal(err)
		}
		if _, err := uc.Run(context.Background(), GenerateBLSKeysRequest{Pool: "p"}); !errors.Is(err, ErrBLSKeyExists) || g.calls != 0 {
			t.Errorf("%s: %v (generated %d times)", existing, err, g.calls)
		}
	}
	uc, g, dir := blsSetup(t)
	g.err = errors.New("no entropy")
	if _, err := uc.Run(context.Background(), GenerateBLSKeysRequest{Pool: "p"}); err == nil {
		t.Fatal("a generator failure was swallowed")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("files left behind: %v", entries)
	}
	if _, err := uc.Run(context.Background(), GenerateBLSKeysRequest{Pool: "p", Place: custody.PlaceHardware}); !errors.Is(err, ErrBLSHolder) {
		t.Errorf("a hardware holder: %v", err)
	}
}
