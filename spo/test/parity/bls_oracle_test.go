package parity

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/fsstore"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/poolops"
	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// The BLS key files of the native generator have the shape of those of the
// pinned cardano-cli: `cardano-cli dijkstra node key-gen-BLS` is the oracle
// of upstream's testnet-only 04f (the script itself is not in the mainnet
// tree the workbench wraps, and the pinned cli has no command that consumes a
// BLS key, so the shape is what can be compared): type string (the cli's
// typo included), description, the CBOR header and length of both keys, and
// the text layout. The signing key is read here only to measure it.
//
// spec: SPO-04f-EXT-001, SPO-Pfiles-OUT-016
func TestNativeBLSKeysHaveTheShapeOfCardanoCLIs(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	cli, err := e.tc.Tool(ctx, ports.CardanoCLI)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	v, s := filepath.Join(dir, "t.vkey"), filepath.Join(dir, "t.skey")
	res, err := execx.OS{}.Run(ctx, execx.Cmd{Path: cli.Path, Args: execx.Lits("dijkstra", "node", "key-gen-BLS",
		"--verification-key-file", v, "--signing-key-file", s)})
	if err != nil {
		t.Skipf("the pinned cardano-cli cannot generate BLS keys: %v\n%s", err, res.Stderr)
	}
	theirV, err := os.ReadFile(v)
	if err != nil {
		t.Fatal(err)
	}
	theirS, err := os.ReadFile(s)
	if err != nil {
		t.Fatal(err)
	}

	pair, err := native.KeyGen{}.GenerateBLS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer pair.SKey.Destroy()
	var oursS []byte
	pair.SKey.Use(func(b []byte) error { oursS = append([]byte(nil), b...); return nil })

	// The layout, with the key bytes blanked: byte-equal.
	blank := regexp.MustCompile(`"cborHex": "[0-9a-f]+"`)
	for _, c := range []struct {
		name         string
		ours, theirs []byte
	}{{"verification key", pair.VKey, theirV}, {"signing key", oursS, theirS}} {
		a, b := blank.ReplaceAll(c.ours, []byte(`"cborHex": "-"`)), blank.ReplaceAll(c.theirs, []byte(`"cborHex": "-"`))
		if string(a) != string(b) {
			t.Errorf("%s layout differs:\nnative: %s\ncli:    %s", c.name, a, b)
		}
		var x, y envelope
		if err := json.Unmarshal(c.ours, &x); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(c.theirs, &y); err != nil {
			t.Fatal(err)
		}
		if len(x.CborHex) != len(y.CborHex) || x.CborHex[:4] != y.CborHex[:4] {
			t.Errorf("%s: native cborHex %d chars from %s, cli %d chars from %s", c.name, len(x.CborHex), x.CborHex[:4], len(y.CborHex), y.CborHex[:4])
		}
	}
}

// The upstream 04f script, run through the workbench (the testnet tree), writes
// both files at 0400 and refuses (exit 2) when either exists; the port
// writes the same names and modes, with the same envelope layout, and refuses
// the same way. Output is discarded: the script prints the signing key
// (SPO-04f-SEC-001).
//
// spec: SPO-04f-PRE-001, SPO-04f-OUT-001, SPO-04f-EXT-001, SPO-Pfiles-OUT-016
func TestBLSKeyScriptAgainstThePort(t *testing.T) {
	e := setup(t)
	up := e.upstreamWorkspace(t)
	if code := e.upstream(t, up, "exec", "04f_genBLSKeys.sh", "mypool", "cli"); code != 0 {
		t.Skipf("upstream 04f exited %d (the pinned cardano-cli cannot generate BLS keys?)", code)
	}
	for _, n := range []string{"mypool.bls.vkey", "mypool.bls.skey"} {
		st, err := os.Stat(filepath.Join(up, n))
		if err != nil || st.Mode().Perm() != 0o400 {
			t.Fatalf("upstream %s: %v %v", n, st, err)
		}
	}
	if code := e.upstream(t, up, "exec", "04f_genBLSKeys.sh", "mypool", "cli"); code != 2 {
		t.Errorf("upstream with the files present exited %d, want 2", code)
	}
	// The port, in a fresh workspace.
	dir := t.TempDir()
	st, err := fsstore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	uc := poolops.GenerateBLSKeys{Store: st, KeyGen: native.KeyGen{}}
	if _, err := uc.Run(context.Background(), poolops.GenerateBLSKeysRequest{Pool: "mypool"}); err != nil {
		t.Fatal(err)
	}
	if _, err := uc.Run(context.Background(), poolops.GenerateBLSKeysRequest{Pool: "mypool"}); !errors.Is(err, poolops.ErrBLSKeyExists) {
		t.Errorf("port with the files present: %v", err)
	}
	blank := regexp.MustCompile(`"cborHex": "[0-9a-f]+"`)
	for _, n := range []string{"mypool.bls.vkey", "mypool.bls.skey"} {
		pst, err := os.Stat(filepath.Join(dir, n))
		if err != nil || pst.Mode().Perm() != 0o400 {
			t.Fatalf("port %s: %v %v", n, pst, err)
		}
		a, _ := os.ReadFile(filepath.Join(up, n))
		b, _ := os.ReadFile(filepath.Join(dir, n))
		if x, y := blank.ReplaceAll(a, nil), blank.ReplaceAll(b, nil); string(x) != string(y) {
			t.Errorf("%s: layout differs: upstream %q, port %q", n, x, y)
		}
	}
}
