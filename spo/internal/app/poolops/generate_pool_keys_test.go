package poolops

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

// A fake key's signing key hex; no result, error or formatted value may
// contain it.
const coldSeedHex = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
const coldPubHex = "a1a2a3a4a5a6a7a8a9a0b1b2b3b4b5b6b7b8b9b0c1c2c3c4c5c6c7c8c9c0d1d2"

func fakeEnv(typ, desc, hexKey string) string {
	return fmt.Sprintf("{\n    \"type\": %q,\n    \"description\": %q,\n    \"cborHex\": \"5820%s\"\n}\n", typ, desc, hexKey)
}

type fakeColdGen struct {
	calls int
	err   error
}

func (f *fakeColdGen) GenerateCold(context.Context) (ports.KeyPair, error) {
	f.calls++
	if f.err != nil {
		return ports.KeyPair{}, f.err
	}
	return ports.KeyPair{
		VKey: []byte(fakeEnv("StakePoolVerificationKey_ed25519", "Stake Pool Operator Verification Key", coldPubHex)),
		SKey: secret.Take([]byte(fakeEnv("StakePoolSigningKey_ed25519", "Stake Pool Operator Signing Key", coldSeedHex))),
	}, nil
}

type fakeVrfGen struct{ calls int }

func (f *fakeVrfGen) GenerateVRF(context.Context) (ports.KeyPair, error) {
	f.calls++
	return ports.KeyPair{
		VKey: []byte(fakeEnv("VrfVerificationKey_PraosVRF", "VRF Verification Key", coldPubHex)),
		SKey: secret.Take([]byte(fakeEnv("VrfSigningKey_PraosVRF", "VRF Signing Key", coldSeedHex))),
	}, nil
}

func newDir(t *testing.T) (ports.Store, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := plainstore.OpenTestnet(dir)
	if err != nil {
		t.Fatal(err)
	}
	return st, dir
}

func modeOf(t *testing.T, dir, name string) os.FileMode {
	t.Helper()
	st, err := os.Stat(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

// noSecret fails when a value formatted the ways a log would holds key material.
func noSecret(t *testing.T, what string, v any, err error) {
	t.Helper()
	text := fmt.Sprintf("%v %+v %#v %v", v, v, v, err)
	for _, s := range []string{coldSeedHex, "Signing Key"} {
		if strings.Contains(text, s) {
			t.Fatalf("%s holds %q: %s", what, s, text)
		}
	}
}

// spec: SPO-04a-EXT-001, SPO-04a-OUT-001, SPO-Pfiles-OUT-010, SPO-Pfiles-OUT-011, SPO-Pfiles-INV-003, SPO-Pfiles-SEC-001
func TestColdKeysWriteThreeArtefactsAndACounterAtZero(t *testing.T) {
	st, dir := newDir(t)
	kg := &fakeColdGen{}
	res, err := GenerateColdKeys{Store: st, KeyGen: kg}.Run(context.Background(), GenerateColdKeysRequest{Pool: "mypool"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"mypool.node.vkey", "mypool.node.skey", "mypool.node.counter"} {
		if m := modeOf(t, dir, f); m != 0o400 {
			t.Errorf("%s mode %v, want 0400", f, m)
		}
	}
	counter, err := pool.ParseIssueCounter([]byte(read(t, dir, "mypool.node.counter")))
	if err != nil || counter.Next != 0 || hex.EncodeToString(counter.ColdVKey[:]) != coldPubHex {
		t.Fatalf("counter = %+v, %v", counter, err)
	}
	if !strings.Contains(read(t, dir, "mypool.node.counter"), "Next certificate issue number: 0") {
		t.Fatal("counter description")
	}
	if read(t, dir, "mypool.node.skey") != fakeEnv("StakePoolSigningKey_ed25519", "Stake Pool Operator Signing Key", coldSeedHex) {
		t.Fatal("signing key not stored as given")
	}
	pid, _ := chain.PoolIDOf(counter.ColdVKey[:])
	if res.PoolID != pid {
		t.Fatal("pool id")
	}
	// spec: SPO-04a-SEC-001
	// Decision: upstream prints the plaintext cold signing key; fixed, the
	// result carries only the verification key and the pool id.
	noSecret(t, "result", res, nil)
}

// spec: SPO-04a-PRE-001
//
// Decision (quirk): upstream checks the four names before anything else and
// exits 2; the port checks inside the transaction too, writes nothing and
// generates no key on a refusal. The hardware signing file counts.
func TestColdKeysRefuseToOverwrite(t *testing.T) {
	for _, existing := range []string{"mypool.node.vkey", "mypool.node.skey", "mypool.node.hwsfile", "mypool.node.counter"} {
		t.Run(existing, func(t *testing.T) {
			st, dir := newDir(t)
			if err := os.WriteFile(filepath.Join(dir, existing), []byte("x"), 0o400); err != nil {
				t.Fatal(err)
			}
			kg := &fakeColdGen{}
			_, err := GenerateColdKeys{Store: st, KeyGen: kg}.Run(context.Background(), GenerateColdKeysRequest{Pool: "mypool"})
			if !errors.Is(err, ErrColdKeyExists) {
				t.Fatalf("err = %v", err)
			}
			if kg.calls != 0 || len(files(t, dir)) != 1 {
				t.Fatalf("a refusal must cost nothing: %d calls, files %v", kg.calls, files(t, dir))
			}
		})
	}
}

// spec: SPO-04a-SEC-004
//
// Decision (quirk): upstream's plaintext signing key sits on disk with
// cardano-cli's mode until the lock; the store writes each file under a
// temporary name already at 0400 and renames it into place, so there is no
// window. A failure to generate leaves nothing at all.
func TestColdKeyGenerationFailureLeavesNothing(t *testing.T) {
	st, dir := newDir(t)
	boom := errors.New("entropy source failed")
	_, err := GenerateColdKeys{Store: st, KeyGen: &fakeColdGen{err: boom}}.Run(context.Background(), GenerateColdKeysRequest{Pool: "mypool"})
	if !errors.Is(err, boom) || len(files(t, dir)) != 0 {
		t.Fatalf("err %v, files %v", err, files(t, dir))
	}
}

// Hardware cold keys are refused before a key is generated or a file is
// written: the plan has no signer for them. The hardware waivers of 04a name
// this: SPO-04a-EXT-003 and friends wait for the hardware signer adapter.
func TestColdKeysHardwareHolderRefusedUpFront(t *testing.T) {
	st, dir := newDir(t)
	kg := &fakeColdGen{}
	for _, h := range []custody.Placement{custody.PlaceHardware, "remote"} {
		_, err := GenerateColdKeys{Store: st, KeyGen: kg}.Run(context.Background(), GenerateColdKeysRequest{Pool: "mypool", Place: h})
		var ue *custody.UnsupportedError
		if !errors.As(err, &ue) {
			t.Fatalf("holder %s: err = %v", h, err)
		}
	}
	if kg.calls != 0 || len(files(t, dir)) != 0 {
		t.Fatal("something happened before the refusal")
	}
}

// spec: SPO-04b-EXT-001, SPO-04b-OUT-001, SPO-Pfiles-OUT-012, SPO-Pfiles-INV-003, SPO-Pfiles-SEC-001
func TestVrfKeysWriteTwoArtefacts(t *testing.T) {
	st, dir := newDir(t)
	res, err := GenerateVrfKeys{Store: st, KeyGen: &fakeVrfGen{}}.Run(context.Background(), GenerateVrfKeysRequest{Pool: "mypool"})
	if err != nil {
		t.Fatal(err)
	}
	if got := files(t, dir); len(got) != 2 {
		t.Fatalf("files %v", got)
	}
	for _, f := range []string{"mypool.vrf.vkey", "mypool.vrf.skey"} {
		if m := modeOf(t, dir, f); m != 0o400 {
			t.Errorf("%s mode %v", f, m)
		}
	}
	// spec: SPO-04b-SEC-001
	// Decision: upstream prints the plaintext VRF signing key; fixed, the
	// result carries the verification key only.
	noSecret(t, "result", res, nil)
}

// spec: SPO-04b-PRE-001
//
// Decision (quirk): upstream refuses when either file exists; so does the
// port, and a refusal writes nothing and generates nothing.
func TestVrfKeysRefuseToOverwrite(t *testing.T) {
	for _, existing := range []string{"mypool.vrf.vkey", "mypool.vrf.skey"} {
		st, dir := newDir(t)
		os.WriteFile(filepath.Join(dir, existing), []byte("x"), 0o400)
		kg := &fakeVrfGen{}
		_, err := GenerateVrfKeys{Store: st, KeyGen: kg}.Run(context.Background(), GenerateVrfKeysRequest{Pool: "mypool"})
		if !errors.Is(err, ErrVrfKeyExists) || kg.calls != 0 || len(files(t, dir)) != 1 {
			t.Fatalf("%s: err %v calls %d files %v", existing, err, kg.calls, files(t, dir))
		}
	}
}

func TestVrfKeysHardwareHolderRefusedUpFront(t *testing.T) {
	st, dir := newDir(t)
	kg := &fakeVrfGen{}
	_, err := GenerateVrfKeys{Store: st, KeyGen: kg}.Run(context.Background(), GenerateVrfKeysRequest{Pool: "mypool", Place: custody.PlaceHardware})
	var ue *custody.UnsupportedError
	if !errors.As(err, &ue) || kg.calls != 0 || len(files(t, dir)) != 0 {
		t.Fatalf("err %v", err)
	}
}
