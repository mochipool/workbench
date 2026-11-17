package parity

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/catalyst"
	"github.com/mochipool/workbench/spo/internal/app/poolkey"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

// Script-level parity of 15_calidusPoolKey.sh and 09a_catalystVote.sh against
// poolkey and catalyst, in two workspaces: the artefacts are byte-equal where
// they are deterministic. What is not: a fresh mnemonic (compared by shape and
// by deriving upstream's phrase natively), the file names (the clock of the
// script, taken from its output name and given to the port), the nonce of
// `genmeta` without an argument (the clock of the machine: compared within a
// few seconds) and the slot of the Catalyst nonce (read back from upstream's
// file and given to the port as the tip).

// keyShape is a deterministic snapshot of the files of one name: mode and
// content, except signing keys, whose content is compared (never printed) by
// cipSameBytes.
func keyShape(t *testing.T, dir, prefix string, deterministic bool) state {
	t.Helper()
	out := state{}
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range es {
		name := en.Name()
		if !strings.HasPrefix(name, prefix+".") {
			continue
		}
		info, _ := en.Info()
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		desc := "mode=" + info.Mode().Perm().String() + " "
		switch {
		case strings.HasSuffix(name, ".skey") && deterministic:
			desc += "secret len=" + itoa(len(raw))
		case deterministic:
			desc += "content=" + string(raw)
		case strings.HasSuffix(name, ".mnemonics"):
			desc += "words=" + itoa(len(strings.Fields(string(raw)))) + " newline=" + itoa(strings.Count(string(raw), "\n"))
		case strings.HasSuffix(name, ".id"), strings.HasSuffix(name, ".pkey"):
			desc += "text prefix=" + string(raw[:6]) + " len=" + itoa(len(raw)) + " newline=" + itoa(strings.Count(string(raw), "\n"))
		default:
			var envl struct{ Type, Description, CborHex string }
			if jsonUnmarshal(raw, &envl) == nil && envl.Type != "" {
				desc += "envelope=" + envl.Type + " description=" + envl.Description + " cborHexLen=" + itoa(len(envl.CborHex)) + " bytes=" + itoa(len(raw))
			} else {
				desc += "other len=" + itoa(len(raw))
			}
		}
		out[name] = desc
	}
	return out
}

func cipSameBytes(t *testing.T, a, b string, names ...string) {
	t.Helper()
	for _, n := range names {
		x, y := readFile(t, a, n), readFile(t, b, n)
		if x != y {
			if strings.HasSuffix(n, ".skey") || strings.HasSuffix(n, ".mnemonics") {
				t.Errorf("%s differs (not shown)", n)
			} else {
				t.Errorf("%s differs\n  upstream: %q\n  port:     %q", n, x, y)
			}
		}
	}
}

func copyFilesTo(t *testing.T, from, to string, names ...string) {
	t.Helper()
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(from, n))
		if err != nil {
			t.Fatal(err)
		}
		info, _ := os.Stat(filepath.Join(from, n))
		if err := os.WriteFile(filepath.Join(to, n), b, 0o600); err != nil {
			t.Fatal(err)
		}
		os.Chmod(filepath.Join(to, n), info.Mode().Perm())
	}
}

func (e env) up(t *testing.T, dir string, args ...string) int {
	t.Helper()
	return e.upstream(t, dir, append([]string{"-y", "exec"}, args...)...)
}

// `new cli` with the public phrase: the four artefacts are byte-equal, signing
// key and mnemonics file included (not printed); a name that exists is
// refused by both and nothing changes; `new hw` is refused by both (upstream
// suspends it).
//
// spec: SPO-15-EXT-001, SPO-15-INV-001, SPO-15-OUT-001, SPO-15-PRE-001, SPO-15-PRE-002, SPO-15-IF-002, SPO-Pfiles-OUT-036
func TestCalidusKeyScriptParity(t *testing.T) {
	e := setup(t)
	e.needSigner(t)
	upDir := e.upstreamWorkspace(t)
	st, portDir := openStore(t)
	if code := e.up(t, upDir, "15_calidusPoolKey.sh", "new", "cli", "cal", publicPhrase); code != 0 {
		t.Fatalf("upstream new exited %d", code)
	}
	m := secret.Take([]byte(publicPhrase))
	defer m.Destroy()
	kg := native.SoftwareKeys{}
	if _, err := (poolkey.GenerateCalidusKey{Store: st, Deriver: kg, Mnemonics: kg}).Run(context.Background(), poolkey.GenerateCalidusKeyRequest{Name: "cal", Mnemonic: m}); err != nil {
		t.Fatal(err)
	}
	up := keyShape(t, upDir, "cal", true)
	if len(up) != 4 {
		t.Fatalf("upstream artefacts: %v", up)
	}
	diff(t, "15 new cli", up, keyShape(t, portDir, "cal", true))
	cipSameBytes(t, upDir, portDir, "cal.calidus.skey", "cal.calidus.vkey", "cal.calidus.mnemonics", "cal.calidus.id")

	// Refusals.
	if code := e.up(t, upDir, "15_calidusPoolKey.sh", "new", "cli", "cal", publicPhrase); code == 0 {
		t.Error("upstream overwrote an existing key")
	}
	if _, err := (poolkey.GenerateCalidusKey{Store: st, Deriver: kg, Mnemonics: kg}).Run(context.Background(), poolkey.GenerateCalidusKeyRequest{Name: "cal", Mnemonic: m}); !errors.Is(err, poolkey.ErrExists) {
		t.Errorf("port overwrote: %v", err)
	}
	diff(t, "after refused new", up, keyShape(t, upDir, "cal", true))
	if code := e.up(t, upDir, "15_calidusPoolKey.sh", "new", "hw", "hwk"); code == 0 {
		t.Error("upstream `new hw` succeeded")
	}
	if len(keyShape(t, upDir, "hwk", false)) != 0 {
		t.Error("upstream `new hw` left files")
	}
	if _, err := (poolkey.GenerateCalidusKey{Store: st, Deriver: kg}).Run(context.Background(), poolkey.GenerateCalidusKeyRequest{Name: "hwk", Place: "hardware", Mnemonic: m}); err == nil {
		t.Error("port made a hardware Calidus key")
	}
	// A mnemonic of another length: refused by both.
	short := secret.Take([]byte("abandon abandon art"))
	defer short.Destroy()
	if code := e.up(t, upDir, "15_calidusPoolKey.sh", "new", "cli", "short", "abandon abandon art"); code == 0 {
		t.Error("upstream accepted a short phrase")
	}
	if _, err := (poolkey.GenerateCalidusKey{Store: st, Deriver: kg}).Run(context.Background(), poolkey.GenerateCalidusKeyRequest{Name: "short", Mnemonic: short}); err == nil {
		t.Error("port accepted a short phrase")
	}
	if len(keyShape(t, upDir, "short", false)) != 0 || len(keyShape(t, portDir, "short", false)) != 0 {
		t.Error("a refused phrase left files")
	}
}

// Without a phrase upstream generates one: the shapes agree and the key the
// port derives from upstream's phrase is upstream's.
//
// spec: SPO-15-EXT-002, SPO-15-SEC-003
func TestCalidusFreshKeyScriptParity(t *testing.T) {
	e := setup(t)
	e.needSigner(t)
	upDir := e.upstreamWorkspace(t)
	st, portDir := openStore(t)
	if code := e.up(t, upDir, "15_calidusPoolKey.sh", "new", "cli", "fresh"); code != 0 {
		t.Fatalf("upstream exited %d", code)
	}
	kg := native.SoftwareKeys{}
	if _, err := (poolkey.GenerateCalidusKey{Store: st, Deriver: kg, Mnemonics: kg}).Run(context.Background(), poolkey.GenerateCalidusKeyRequest{Name: "fresh"}); err != nil {
		t.Fatal(err)
	}
	diff(t, "15 new cli, fresh phrase", keyShape(t, upDir, "fresh", false), keyShape(t, portDir, "fresh", false))
	words := secret.Take([]byte(strings.TrimSpace(readFile(t, upDir, "fresh.calidus.mnemonics"))))
	defer words.Destroy()
	pair, err := kg.DeriveCalidus(context.Background(), words, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer pair.SKey.Destroy()
	if string(pair.VKey) != readFile(t, upDir, "fresh.calidus.vkey") {
		t.Error("the native derivation of upstream's phrase gives another verification key")
	}
	pub, _ := cose.VKeyFromEnvelope(pair.VKey)
	if id, _ := cose.CalidusID(pub[:]); id+"\n" != readFile(t, upDir, "fresh.calidus.id") {
		t.Error("the Calidus id differs")
	}
}

func fileTime(t *testing.T, name, suffix string) time.Time {
	t.Helper()
	ts := strings.TrimSuffix(name[strings.LastIndex(name, "_")+1:], suffix)
	tm, err := time.ParseInLocation("060102150405", ts, time.Local)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return tm
}

func globOne(t *testing.T, dir, pattern string) string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil || len(m) != 1 {
		t.Fatalf("%s: %v %v", pattern, m, err)
	}
	return filepath.Base(m[0])
}

type fakeClock struct{ t time.Time }

func (c fakeClock) Now() time.Time { return c.t }

type sourceTip struct{ slot uint64 }

func (sourceTip) Source() chain.Source { return "upstream's slot" }
func (s sourceTip) Tip(context.Context) (chain.Tip, error) {
	return chain.Tip{Slot: s.slot}, nil
}

// The upstream cold key, Calidus key and pool in an upstream workspace and a
// copy of their files in a port workspace.
func (e env) poolWorkspaces(t *testing.T) (upDir, portDir string, st *plainstore.Store) {
	t.Helper()
	upDir = e.upstreamWorkspace(t)
	for _, run := range [][]string{{"04a_genNodeKeys.sh", "mypool", "cli"}, {"15_calidusPoolKey.sh", "new", "cli", "cal", publicPhrase}} {
		if code := e.up(t, upDir, run...); code != 0 {
			t.Fatalf("upstream %v exited %d", run, code)
		}
	}
	st, portDir = openStore(t)
	copyFilesTo(t, upDir, portDir, "mypool.node.skey", "mypool.node.vkey", "cal.calidus.vkey", "cal.calidus.skey", "cal.calidus.id", "cal.calidus.mnemonics")
	return
}

// `genmeta` with a software cold key and a nonce: the registration file is
// byte-equal, name included (the port is given the clock of the script's
// file name); without a nonce the file is equal except the nonce, which both
// take from the machine clock (cardano-signer's mainnet slot); an existing
// file, a missing Calidus key and a missing cold key are refused by both.
//
// spec: SPO-15-EXT-003, SPO-15-OUT-002, SPO-15-IF-003, SPO-15-IF-004, SPO-15-PRE-004, SPO-15-PRE-005, SPO-15-INV-005, SPO-15-INV-006, SPO-15-OUT-003, SPO-15-MODE-002, SPO-15-OUT-004
func TestCalidusRegistrationScriptParity(t *testing.T) {
	e := setup(t)
	e.needSigner(t)
	upDir, portDir, st := e.poolWorkspaces(t)
	ctx := context.Background()
	uc := func(now time.Time) poolkey.GenerateCalidusRegistration {
		return poolkey.GenerateCalidusRegistration{Store: st, Signers: native.NewSignatureSigners(st), Clock: fakeClock{now}}
	}

	// With a nonce, and the names as upstream normalises them.
	if code := e.up(t, upDir, "15_calidusPoolKey.sh", "genmeta", "./cal.calidus.vkey", "mypool.node.skey", "777"); code != 0 {
		t.Fatalf("upstream genmeta exited %d", code)
	}
	name := globOne(t, upDir, "mypool_*.calidus-registration.json")
	now := fileTime(t, name, ".calidus-registration.json")
	res, err := uc(now).Run(ctx, poolkey.CalidusRegistrationRequest{Calidus: "./cal.calidus.vkey", Pool: "mypool.node.skey", Nonce: 777})
	if err != nil {
		t.Fatal(err)
	}
	if res.Ref.Name+".calidus-registration.json" != name {
		t.Errorf("file name %s, upstream %s", res.Ref.Name, name)
	}
	diff(t, "15 genmeta", state{name: "mode=" + mode(t, upDir, name).String() + " content=" + readFile(t, upDir, name)},
		state{name: "mode=" + mode(t, portDir, name).String() + " content=" + readFile(t, portDir, name)})

	// Without a nonce: the same file but for the nonce.
	time.Sleep(1100 * time.Millisecond)
	if code := e.up(t, upDir, "15_calidusPoolKey.sh", "genmeta", "cal", "mypool"); code != 0 {
		t.Fatalf("upstream genmeta exited %d", code)
	}
	var upName string
	es, _ := os.ReadDir(upDir)
	for _, en := range es {
		if strings.HasSuffix(en.Name(), ".calidus-registration.json") && en.Name() != name {
			upName = en.Name()
		}
	}
	now2 := fileTime(t, upName, ".calidus-registration.json")
	res2, err := uc(now2).Run(ctx, poolkey.CalidusRegistrationRequest{Calidus: "cal", Pool: "mypool"})
	if err != nil {
		t.Fatal(err)
	}
	if res2.Ref.Name+".calidus-registration.json" != upName {
		t.Errorf("file name %s, upstream %s", res2.Ref.Name, upName)
	}
	upNonce := nonceOf(t, readFile(t, upDir, upName))
	if d := int64(upNonce) - int64(res2.Nonce); d < -3 || d > 3 {
		t.Errorf("nonce %d, upstream %d", res2.Nonce, upNonce)
	}
	// Same layout, pool id, Calidus key, cold key and protected header; only the
	// nonce and what covers it (payload hash, signature) differ.
	if a, b := withoutNonce(t, readFile(t, upDir, upName)), withoutNonce(t, readFile(t, portDir, upName)); a != b {
		t.Errorf("registration differs beyond the nonce\n  upstream: %s\n  port:     %s", a, b)
	}
	if got := readFile(t, portDir, upName); !strings.HasSuffix(got, "\n") || strings.Count(got, "\n") != strings.Count(readFile(t, upDir, upName), "\n") {
		t.Error("the files differ in layout")
	}

	// Refusals shared with upstream.
	if code := e.up(t, upDir, "15_calidusPoolKey.sh", "genmeta", "nokey", "mypool", "5"); code == 0 {
		t.Error("upstream signed with a missing Calidus key")
	}
	if _, err := uc(now2.Add(time.Hour)).Run(ctx, poolkey.CalidusRegistrationRequest{Calidus: "nokey", Pool: "mypool", Nonce: 5}); !errors.Is(err, poolkey.ErrMissingFile) {
		t.Errorf("port, missing Calidus key: %v", err)
	}
	if code := e.up(t, upDir, "15_calidusPoolKey.sh", "genmeta", "cal", "nopool", "5"); code == 0 {
		t.Error("upstream signed with a missing cold key")
	}
	if _, err := uc(now2.Add(time.Hour)).Run(ctx, poolkey.CalidusRegistrationRequest{Calidus: "cal", Pool: "nopool", Nonce: 5}); !errors.Is(err, poolkey.ErrNoColdSigner) {
		t.Errorf("port, missing cold key: %v", err)
	}
	if code := e.up(t, upDir, "15_calidusPoolKey.sh", "genmeta", "cal", "mypool", "0"); code == 0 {
		t.Error("upstream accepted nonce 0")
	}
	if code := e.up(t, upDir, "15_calidusPoolKey.sh", "genmeta", "cal", "mypool", "12x"); code == 0 {
		t.Error("upstream accepted a non-numeric nonce")
	}
	if _, err := uc(now2).Run(ctx, poolkey.CalidusRegistrationRequest{Calidus: "cal", Pool: "mypool"}); !errors.Is(err, poolkey.ErrExists) {
		t.Errorf("port, existing file: %v", err)
	}
}

func nonceOf(t *testing.T, file string) uint64 {
	t.Helper()
	var doc struct {
		N867 struct {
			P struct {
				Nonce uint64 `json:"4"`
			} `json:"1"`
		} `json:"867"`
	}
	if err := jsonUnmarshal([]byte(file), &doc); err != nil {
		t.Fatal(err)
	}
	return doc.N867.P.Nonce
}

// withoutNonce blanks the nonce, the payload hash and the signature of a
// registration file and returns the rest, re-marshalled.
func withoutNonce(t *testing.T, file string) string {
	t.Helper()
	var doc map[string]any
	if err := jsonUnmarshal([]byte(file), &doc); err != nil {
		t.Fatal(err)
	}
	top := doc["867"].(map[string]any)
	top["1"].(map[string]any)["4"] = 0
	w := top["2"].([]any)[0].(map[string]any)["2"].([]any)
	w[2], w[3] = "x", "x"
	out, _ := json.Marshal(doc)
	return string(out)
}

// `new cli` of the voting key with the public phrase: the four artefacts are
// byte-equal; a fresh phrase agrees in shape and derivation; existing keys are
// refused by both.
//
// spec: SPO-09a-EXT-001, SPO-09a-OUT-001, SPO-09a-OUT-002, SPO-09a-OUT-003, SPO-09a-PRE-001, SPO-09a-PRE-002, SPO-09a-IF-002, SPO-09a-INV-001, SPO-Pfiles-OUT-035
func TestVotingKeyScriptParity(t *testing.T) {
	e := setup(t)
	e.needSigner(t)
	ctx := context.Background()
	upDir := e.upstreamWorkspace(t)
	st, portDir := openStore(t)
	kg := native.SoftwareKeys{}
	uc := catalyst.GenerateVotingKey{Store: st, Deriver: kg, Mnemonics: kg}
	if code := e.up(t, upDir, "09a_catalystVote.sh", "new", "cli", "vote", publicPhrase); code != 0 {
		t.Fatalf("upstream exited %d", code)
	}
	m := secret.Take([]byte(publicPhrase))
	defer m.Destroy()
	if _, err := uc.Run(ctx, catalyst.GenerateVotingKeyRequest{Name: "vote", Mnemonic: m}); err != nil {
		t.Fatal(err)
	}
	up := keyShape(t, upDir, "vote", true)
	if len(up) != 4 {
		t.Fatalf("upstream artefacts: %v", up)
	}
	diff(t, "09a new cli", up, keyShape(t, portDir, "vote", true))
	cipSameBytes(t, upDir, portDir, "vote.voting.skey", "vote.voting.vkey", "vote.voting.pkey", "vote.voting.mnemonics")

	if code := e.up(t, upDir, "09a_catalystVote.sh", "new", "cli", "vote", publicPhrase); code == 0 {
		t.Error("upstream overwrote a voting key")
	}
	if _, err := uc.Run(ctx, catalyst.GenerateVotingKeyRequest{Name: "vote", Mnemonic: m}); !errors.Is(err, catalyst.ErrExists) {
		t.Errorf("port: %v", err)
	}
	if code := e.up(t, upDir, "09a_catalystVote.sh", "new", "cli", "short", "abandon art"); code == 0 {
		t.Error("upstream accepted a short phrase")
	}

	// A fresh phrase.
	if code := e.up(t, upDir, "09a_catalystVote.sh", "new", "cli", "fresh"); code != 0 {
		t.Fatalf("upstream fresh exited %d", code)
	}
	if _, err := uc.Run(ctx, catalyst.GenerateVotingKeyRequest{Name: "fresh"}); err != nil {
		t.Fatal(err)
	}
	diff(t, "09a new cli, fresh", keyShape(t, upDir, "fresh", false), keyShape(t, portDir, "fresh", false))
	words := secret.Take([]byte(strings.TrimSpace(readFile(t, upDir, "fresh.voting.mnemonics"))))
	defer words.Destroy()
	pair, pkey, err := kg.DeriveVoting(ctx, words, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer pair.SKey.Destroy()
	if string(pair.VKey) != readFile(t, upDir, "fresh.voting.vkey") || pkey+"\n" != readFile(t, upDir, "fresh.voting.pkey") {
		t.Error("the native derivation of upstream's phrase gives another key")
	}
}

// `genmeta`: the registration of a key-file stake key for a stored voting key
// (single, weight 1) and for a delegation to a stored and a hex key with
// weights is byte-equal to the file the script wrote, given the slot the script
// used as the tip (read back from its file) and its clock; the unknown key, the
// stake address as rewards and a bad weight are refused by both.
//
// spec: SPO-09a-EXT-003, SPO-09a-OUT-005, SPO-09a-OUT-006, SPO-09a-INV-003, SPO-09a-IF-003, SPO-09a-IF-006, SPO-09a-IN-002, SPO-09a-IN-004, SPO-09a-PRE-003, SPO-09a-PRE-004, SPO-09a-PRE-005, SPO-09a-MODE-001
func TestCatalystRegistrationScriptParity(t *testing.T) {
	e := setup(t)
	e.needSigner(t)
	ctx := context.Background()
	upDir := e.upstreamWorkspace(t)
	for _, run := range [][]string{{"03a_genStakingPaymentAddr.sh", "w", "cli"}, {"09a_catalystVote.sh", "new", "cli", "vote", publicPhrase}} {
		if code := e.up(t, upDir, run...); code != 0 {
			t.Fatalf("upstream %v exited %d", run, code)
		}
	}
	st, portDir := openStore(t)
	copyFilesTo(t, upDir, portDir, "w.staking.skey", "w.staking.vkey", "w.payment.addr", "w.staking.addr", "vote.voting.pkey", "vote.voting.vkey")
	hexKey := strings.Repeat("ab", 32)

	for _, c := range []struct {
		name  string
		deleg string
	}{{"single", "vote"}, {"weighted", "vote 3|" + hexKey + " 1"}} {
		t.Run(c.name, func(t *testing.T) {
			before := globAll(t, upDir, "w_*.vote-registration.cbor")
			// Different seconds, so the script does not refuse an existing file.
			time.Sleep(1100 * time.Millisecond)
			if code := e.up(t, upDir, "09a_catalystVote.sh", "genmeta", c.deleg, "w", "w.payment"); code != 0 {
				t.Fatalf("upstream genmeta exited %d", code)
			}
			name := newest(t, upDir, "w_*.vote-registration.cbor", before)
			upCBOR := readFile(t, upDir, name)
			reg, err := cose.VerifyCip36([]byte(upCBOR))
			if err != nil {
				t.Fatalf("the script's registration does not verify: %v", err)
			}
			deleg, err := catalyst.ParseDelegation(c.deleg)
			if err != nil {
				t.Fatal(err)
			}
			uc := catalyst.GenerateRegistration{Store: st, Signers: native.NewSignatureSigners(st),
				Clock: fakeClock{fileTime(t, name, ".vote-registration.cbor")}, Tip: sourceTip{reg.Nonce}, NetworkID: ports.NetworkTestnet}
			res, err := uc.Run(ctx, catalyst.RegistrationRequest{Delegation: deleg, Stake: "w", Rewards: "w.payment"})
			if err != nil {
				t.Fatal(err)
			}
			if res.Ref.Name+".vote-registration.cbor" != name {
				t.Errorf("file name %s, upstream %s", res.Ref.Name, name)
			}
			diff(t, "09a genmeta", state{name: "mode=" + mode(t, upDir, name).String() + " content=" + hex.EncodeToString([]byte(upCBOR))},
				state{name: "mode=" + mode(t, portDir, name).String() + " content=" + hex.EncodeToString([]byte(readFile(t, portDir, name)))})
		})
	}

	// Refusals.
	stakeAddr := strings.TrimSpace(readFile(t, upDir, "w.staking.addr"))
	for _, c := range []struct {
		name, deleg, stake, rewards string
		want                        error
	}{
		{"unknown key", "nobody", "w", "w.payment", catalyst.ErrBadVotingKey},
		{"bad weight", "vote x", "w", "w.payment", catalyst.ErrBadDelegation},
		{"no stake key", "vote", "nostake", "w.payment", catalyst.ErrNoStakeSigner},
		{"stake address as rewards", "vote", "w", stakeAddr, catalyst.ErrBadRewards},
	} {
		time.Sleep(1100 * time.Millisecond)
		if code := e.up(t, upDir, "09a_catalystVote.sh", "genmeta", c.deleg, c.stake, c.rewards); code == 0 {
			t.Errorf("%s: upstream succeeded", c.name)
		}
		deleg, perr := catalyst.ParseDelegation(c.deleg)
		var err error
		if perr == nil {
			uc := catalyst.GenerateRegistration{Store: st, Signers: native.NewSignatureSigners(st), Clock: fakeClock{time.Now()}, Tip: sourceTip{1}, NetworkID: ports.NetworkTestnet}
			_, err = uc.Run(ctx, catalyst.RegistrationRequest{Delegation: deleg, Stake: c.stake, Rewards: c.rewards})
		} else {
			err = perr
		}
		if !errors.Is(err, c.want) {
			t.Errorf("%s: port %v, want %v", c.name, err, c.want)
		}
	}
}

func globAll(t *testing.T, dir, pattern string) map[string]bool {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(dir, pattern))
	out := map[string]bool{}
	for _, f := range m {
		out[filepath.Base(f)] = true
	}
	return out
}

func newest(t *testing.T, dir, pattern string, before map[string]bool) string {
	t.Helper()
	for n := range globAll(t, dir, pattern) {
		if !before[n] {
			return n
		}
	}
	t.Fatalf("no new file matching %s", pattern)
	return ""
}

// `qrcode` needs catalyst-toolbox, which is not in the pinned toolchain; the
// script refuses without it, and the port has no QR code: the artefact is
// secret (SPO-Pfiles-SEC-001) and its PIN encryption is the tool's, not
// specified by the spec nor checkable here.
func TestCatalystQrCodeScriptRefusesWithoutTool(t *testing.T) {
	e := setup(t)
	upDir := e.upstreamWorkspace(t)
	if code := e.up(t, upDir, "09a_catalystVote.sh", "qrcode", "nokey", "1234"); code == 0 {
		t.Error("upstream qrcode worked without catalyst-toolbox")
	}
}
