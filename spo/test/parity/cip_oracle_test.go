package parity

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/porttest"
)

// cardano-signer as the oracle of the message and registration signing
// (CIP-8, CIP-36, CIP-88) and of the Calidus and voting key derivation. Every
// test starts with needSigner. The test keys come from the public test phrase
// or are random and thrown away with the temporary directory; the secret key
// files are handed to the tool through SecretIn pipes where it takes a path.

// signer runs cardano-signer and returns its standard output.
func (e env) signer(t *testing.T, args ...execx.Arg) string {
	t.Helper()
	tool, err := e.tc.Tool(context.Background(), ports.CardanoSigner)
	if err != nil {
		t.Fatal(err)
	}
	res, err := execx.OS{}.Run(context.Background(), execx.Cmd{Path: tool.Path, Args: args})
	if err != nil {
		t.Fatalf("cardano-signer %s: %v\n%s", firstWord(args), err, res.Stderr)
	}
	return strings.TrimSpace(string(res.Stdout))
}

func firstWord(args []execx.Arg) string { return "" }

// signerFails runs cardano-signer and reports whether it exited non-zero.
func (e env) signerFails(t *testing.T, args ...execx.Arg) bool {
	t.Helper()
	tool, err := e.tc.Tool(context.Background(), ports.CardanoSigner)
	if err != nil {
		t.Fatal(err)
	}
	_, err = execx.OS{}.Run(context.Background(), execx.Cmd{Path: tool.Path, Args: args})
	return err != nil
}

func sk(b []byte) execx.Arg { return execx.SecretIn(secret.Take(append([]byte(nil), b...))) }

// signerKeys derives a key with cardano-signer's keygen from the public phrase
// and returns the signing key envelope, never the tool's output.
func (e env) signerKey(t *testing.T, path string, extra ...string) (skey []byte, vkeyHex string) {
	t.Helper()
	dir := t.TempDir()
	args := append(lits("keygen", "--path", path, "--mnemonics", publicPhrase), lits(extra...)...)
	args = append(args, lits("--out-skey", filepath.Join(dir, "k.skey"), "--out-vkey", filepath.Join(dir, "k.vkey"))...)
	e.signer(t, args...)
	skey, err := os.ReadFile(filepath.Join(dir, "k.skey"))
	if err != nil {
		t.Fatal(err)
	}
	vk, _ := os.ReadFile(filepath.Join(dir, "k.vkey"))
	var env struct{ CborHex string }
	json.Unmarshal(vk, &env)
	return skey, env.CborHex[4:]
}

func putSecret(t *testing.T, st ports.Store, name string, kind ports.Kind, b []byte) {
	t.Helper()
	err := st.Update(context.Background(), func(w ports.Writer) error {
		return w.PutSecret(ports.Ref{Name: name, Kind: kind}, secret.Take(append([]byte(nil), b...)))
	})
	if err != nil {
		t.Fatal(err)
	}
}

func addrBytes(t *testing.T, bech string) []byte {
	t.Helper()
	_, b, err := chain.Bech32Decode(bech)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// buildAddress makes an address with cardano-cli from verification key hex.
func (e env) buildAddress(t *testing.T, payVKeyHex, stakeVKeyHex string) (base, enterprise, reward string) {
	t.Helper()
	dir := t.TempDir()
	write := func(name, typ, hexKey string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(`{"type":"`+typ+`","description":"","cborHex":"5820`+hexKey+`"}`), 0o600)
		return p
	}
	pv := write("p.vkey", "PaymentVerificationKeyShelley_ed25519", payVKeyHex)
	sv := write("s.vkey", "StakeVerificationKeyShelley_ed25519", stakeVKeyHex)
	base = e.latest(t, lits("address", "build", "--payment-verification-key-file", pv, "--stake-verification-key-file", sv, "--testnet-magic", "2")...)
	enterprise = e.latest(t, lits("address", "build", "--payment-verification-key-file", pv, "--testnet-magic", "2")...)
	reward = e.latest(t, lits("stake-address", "build", "--stake-verification-key-file", sv, "--testnet-magic", "2")...)
	return
}

// CIP-8: the COSE_Sign1 and COSE_Key of a signature made natively are
// byte-equal to cardano-signer's for payment and stake keys, extended and
// normal, with and without the hashed flag, and each verifies with the
// other's verifier.
//
// spec: SPO-Pfiles-OUT-036
func TestCip8SignMatchesCardanoSigner(t *testing.T) {
	e := setup(t)
	e.needSigner(t)
	ctx := context.Background()
	st, _ := openStore(t)
	payS, payV := e.signerKey(t, "payment")
	stkS, stkV := e.signerKey(t, "stake")
	putSecret(t, st, "ext", ports.AddrSKey, payS)
	putSecret(t, st, "ext", ports.StakingSKey, stkS)
	// Normal (non-extended) keys from the native generators.
	sw := native.SoftwareKeys{}
	np, err := sw.GeneratePayment(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ns, err := sw.GenerateStake(ctx)
	if err != nil {
		t.Fatal(err)
	}
	nPayBytes, nStkBytes := secretBytes(t, np.SKey), secretBytes(t, ns.SKey)
	putSecret(t, st, "norm", ports.AddrSKey, nPayBytes)
	putSecret(t, st, "norm", ports.StakingSKey, nStkBytes)
	vkHex := func(env []byte) string {
		var x struct{ CborHex string }
		json.Unmarshal(env, &x)
		return x.CborHex[4:]
	}
	var sg ports.Signer = native.VaultSignatures{VaultSigner: native.VaultSigner{Vault: st}}
	ms := sg.(ports.MessageSigner)

	type kc struct {
		name, owner string
		role        custody.Role
		skey        []byte
		addr        func(base, ent, rew string) string
	}
	for _, set := range []struct {
		name       string
		pay, stake string
		sk         func(role custody.Role) []byte
		owner      string
	}{
		{"extended", payV, stkV, func(r custody.Role) []byte {
			if r == custody.RolePayment {
				return payS
			}
			return stkS
		}, "ext"},
		{"normal", vkHex(np.VKey), vkHex(ns.VKey), func(r custody.Role) []byte {
			if r == custody.RolePayment {
				return nPayBytes
			}
			return nStkBytes
		}, "norm"},
	} {
		base, ent, rew := e.buildAddress(t, set.pay, set.stake)
		cases := []struct {
			name string
			role custody.Role
			addr string
		}{{"payment/base", custody.RolePayment, base}, {"payment/enterprise", custody.RolePayment, ent},
			{"stake/reward", custody.RoleStake, rew}, {"stake/base", custody.RoleStake, base}}
		for _, c := range cases {
			for _, hashed := range []bool{false, true} {
				for _, data := range []struct{ flag, val string }{{"--data", "hello cardano"}, {"--data-hex", "00ff10"}} {
					t.Run(set.name+" "+c.name+map[bool]string{false: "", true: " hashed"}[hashed]+" "+data.flag, func(t *testing.T) {
						args := lits("sign", "--cip8", "--testnet", data.flag, data.val, "--address", c.addr, "--secret-key")
						args = append(args, sk(set.sk(c.role)))
						if hashed {
							args = append(args, execx.Lit("--hashed"))
						}
						out := strings.Fields(e.signer(t, args...))
						if len(out) != 2 {
							t.Fatalf("tool output: %v", len(out))
						}
						payload := []byte(data.val)
						if data.flag == "--data-hex" {
							payload, _ = hex.DecodeString(data.val)
						}
						got, err := ms.SignMessage(ctx, ports.MessageRequest{
							Key:     porttest.Key(t, st, c.role, set.owner),
							Address: addrBytes(t, c.addr), Payload: payload, Hashed: hashed})
						if err != nil {
							t.Fatal(err)
						}
						if hex.EncodeToString(got.Sign1) != out[0] {
							t.Errorf("COSE_Sign1 differs\n  tool: %s\n  go:   %s", out[0], hex.EncodeToString(got.Sign1))
						}
						if hex.EncodeToString(got.Key) != out[1] {
							t.Errorf("COSE_Key differs\n  tool: %s\n  go:   %s", out[1], hex.EncodeToString(got.Key))
						}
						// Both directions of verification.
						if _, err := cose.VerifyCip8(mustHex(t, out[0]), mustHex(t, out[1]), nil, true); err != nil {
							t.Errorf("go verifies the tool's message: %v", err)
						}
						v := e.signer(t, lits("verify", "--cip8", "--cose-sign1", hex.EncodeToString(got.Sign1), "--cose-key", hex.EncodeToString(got.Key), "--address", c.addr, "--testnet")...)
						if !strings.Contains(v, "true") {
							t.Errorf("the tool does not verify the Go message: %q", v)
						}
					})
				}
			}
		}
	}
	// A key that does not belong to the address is refused by both.
	_, _, rew := e.buildAddress(t, payV, stkV)
	_, err = ms.SignMessage(ctx, ports.MessageRequest{Key: porttest.Key(t, st, custody.RolePayment, "ext"),
		Address: addrBytes(t, rew), Payload: []byte("x")})
	if err == nil {
		t.Error("a payment key signed for a stake address")
	}
	if !e.signerFails(t, append(lits("sign", "--cip8", "--testnet", "--data", "x", "--address", rew, "--secret-key"), sk(payS))...) {
		t.Error("the tool signed for a stake address with a payment key")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func secretBytes(t *testing.T, s *secret.Buffer) []byte {
	t.Helper()
	var out []byte
	if err := s.Use(func(b []byte) error { out = append([]byte(nil), b...); return nil }); err != nil {
		t.Fatal(err)
	}
	return out
}

// CIP-36: the registration metadata of a stake key (extended and normal), for
// a single voting key and for a delegation with weights, with the Catalyst
// and another purpose, is byte-equal to cardano-signer's `--out-cbor` file
// and `--json` output; the tool's file verifies natively.
//
// spec: SPO-09a-EXT-003, SPO-09a-OUT-006
func TestCip36MatchesCardanoSigner(t *testing.T) {
	e := setup(t)
	e.needSigner(t)
	ctx := context.Background()
	st, _ := openStore(t)
	sw := native.SoftwareKeys{}
	stkS, stkV := e.signerKey(t, "stake")
	_, payV := e.signerKey(t, "payment")
	ns, err := sw.GenerateStake(ctx)
	if err != nil {
		t.Fatal(err)
	}
	nsBytes := secretBytes(t, ns.SKey)
	putSecret(t, st, "ext", ports.StakingSKey, stkS)
	putSecret(t, st, "norm", ports.StakingSKey, nsBytes)
	normV := func() string {
		var x struct{ CborHex string }
		json.Unmarshal(ns.VKey, &x)
		return x.CborHex[4:]
	}()
	m := secret.Take([]byte(publicPhrase))
	defer m.Destroy()
	var votes []string
	for i := uint32(0); i < 3; i++ {
		pair, bech, err := sw.DeriveVoting(ctx, m, 0, i)
		if err != nil {
			t.Fatal(err)
		}
		pair.SKey.Destroy()
		votes = append(votes, bech)
	}
	var sg ports.Signer = native.VaultSignatures{VaultSigner: native.VaultSigner{Vault: st}}
	c36 := sg.(ports.Cip36Signer)

	for _, set := range []struct {
		name, owner, stakeV string
		skey                []byte
	}{{"extended", "ext", stkV, stkS}, {"normal", "norm", normV, nsBytes}} {
		base, _, _ := e.buildAddress(t, payV, set.stakeV)
		for _, tc := range []struct {
			name    string
			votes   []string
			weights []uint64
			nonce   uint64
			purpose uint64
		}{
			{"single", votes[:1], []uint64{1}, 12345, 0},
			{"two weighted", votes[:2], []uint64{3, 1}, 98765432, 0},
			{"three, purpose 1", votes, []uint64{5, 1, 2}, 1 << 33, 1},
			{"same key twice", []string{votes[0], votes[0]}, []uint64{1, 2}, 7, 0},
		} {
			t.Run(set.name+" "+tc.name, func(t *testing.T) {
				dir := t.TempDir()
				cbor := filepath.Join(dir, "r.cbor")
				args := lits("sign", "--cip36", "--testnet", "--payment-address", base, "--nonce", itoa(int(tc.nonce)), "--vote-purpose", itoa(int(tc.purpose)), "--out-cbor", cbor, "--json")
				for i, v := range tc.votes {
					args = append(args, execx.Lit("--vote-public-key"), execx.Lit(v))
					if len(tc.votes) > 1 {
						args = append(args, execx.Lit("--vote-weight"), execx.Lit(itoa(int(tc.weights[i]))))
					}
				}
				args = append(args, execx.Lit("--secret-key"), sk(set.skey))
				toolJSON := e.signer(t, args...)
				toolCBOR, err := os.ReadFile(cbor)
				if err != nil {
					t.Fatal(err)
				}
				reg := cose.Cip36{Nonce: tc.nonce, Purpose: tc.purpose, Address: addrBytes(t, base)}
				copy(reg.StakePub[:], mustHex(t, set.stakeV))
				for i, v := range tc.votes {
					_, pub, err := chain.Bech32Decode(v)
					if err != nil {
						t.Fatal(err)
					}
					d := cose.Delegation{Weight: tc.weights[i]}
					copy(d.VotePub[:], pub)
					reg.Delegations = append(reg.Delegations, d)
				}
				got, err := c36.SignCip36(ctx, mustStake(t, porttest.Key(t, st, custody.RoleStake, set.owner)), reg)
				if err != nil {
					t.Fatal(err)
				}
				if string(got.CBOR) != string(toolCBOR) {
					t.Errorf("metadata CBOR differs\n  tool: %x\n  go:   %x", toolCBOR, got.CBOR)
				}
				if got.JSON != toolJSON {
					t.Errorf("metadata JSON differs\n  tool: %s\n  go:   %s", toolJSON, got.JSON)
				}
				if _, err := cose.VerifyCip36(toolCBOR); err != nil {
					t.Errorf("go does not verify the tool's registration: %v", err)
				}
			})
		}
	}
	// Refusals the two share: the total weight zero and a stake address as rewards.
	base, _, rew := e.buildAddress(t, payV, stkV)
	if !e.signerFails(t, append(lits("sign", "--cip36", "--testnet", "--payment-address", base, "--nonce", "1", "--vote-public-key", votes[0], "--vote-weight", "0", "--secret-key"), sk(stkS))...) {
		t.Error("the tool accepted a zero total weight")
	}
	if !e.signerFails(t, append(lits("sign", "--cip36", "--testnet", "--payment-address", rew, "--nonce", "1", "--vote-public-key", votes[0], "--secret-key"), sk(stkS))...) {
		t.Error("the tool accepted a reward address as the rewards address")
	}
	zero := cose.Cip36{Delegations: []cose.Delegation{{Weight: 0}}, Address: addrBytes(t, base)}
	if zero.Validate() == nil {
		t.Error("a zero total weight validates")
	}
	zero.Delegations[0].Weight, zero.Address = 1, addrBytes(t, rew)
	if zero.Validate() == nil {
		t.Error("a reward address validates")
	}
}

func mustStake(t *testing.T, ref custody.KeyRef) custody.Key[custody.Stake] {
	t.Helper()
	k, err := custody.As[custody.Stake](ref)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustCold(t *testing.T, ref custody.KeyRef) custody.Key[custody.PoolCold] {
	t.Helper()
	k, err := custody.As[custody.PoolCold](ref)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// CIP-88 version 2: the Calidus registration of a pool cold key (extended and
// normal) is byte-equal to cardano-signer's `--out-cbor` file, its `--json`
// output and its `payloadCbor` and `payloadHash`, and the tool's `verify
// --cip88` accepts the Go output.
//
// spec: SPO-15-EXT-003, SPO-15-INV-005, SPO-15-INV-006, SPO-15-OUT-003, SPO-15-INV-004
func TestCip88MatchesCardanoSigner(t *testing.T) {
	e := setup(t)
	e.needSigner(t)
	ctx := context.Background()
	st, _ := openStore(t)
	sw := native.SoftwareKeys{}
	poolS, poolV := e.signerKey(t, "pool")
	cold, err := sw.GenerateCold(ctx)
	if err != nil {
		t.Fatal(err)
	}
	coldBytes := secretBytes(t, cold.SKey)
	putSecret(t, st, "ext", ports.NodeSKey, poolS)
	putSecret(t, st, "norm", ports.NodeSKey, coldBytes)
	coldV := func() string {
		var x struct{ CborHex string }
		json.Unmarshal(cold.VKey, &x)
		return x.CborHex[4:]
	}()
	calS, calV := e.signerKey(t, "calidus")
	_ = calS
	var sg ports.Signer = native.VaultSignatures{VaultSigner: native.VaultSigner{Vault: st}}
	c88 := sg.(ports.Cip88Signer)

	for _, set := range []struct {
		name, owner, vkey string
		skey              []byte
	}{{"extended", "ext", poolV, poolS}, {"normal", "norm", coldV, coldBytes}} {
		for _, nonce := range []uint64{777, 203266041, 1 << 40} {
			t.Run(set.name+" nonce "+itoa(int(nonce)), func(t *testing.T) {
				dir := t.TempDir()
				cbor := filepath.Join(dir, "r.cbor")
				calFile := filepath.Join(dir, "cal.vkey")
				os.WriteFile(calFile, []byte(`{"type":"PaymentVerificationKeyShelley_ed25519","description":"","cborHex":"5820`+calV+`"}`), 0o600)
				args := append(lits("sign", "--cip88", "--calidus-public-key", calFile, "--nonce", itoa(int(nonce)), "--out-cbor", cbor, "--json-extended", "--secret-key"), sk(set.skey))
				var ext struct {
					PoolIDHex     string `json:"poolIdHex"`
					CalidusIDBech string `json:"calidusIdBech"`
					PayloadCbor   string `json:"payloadCbor"`
					PayloadHash   string `json:"payloadHash"`
					Output        struct {
						JSON json.RawMessage `json:"json"`
					} `json:"output"`
				}
				if err := json.Unmarshal([]byte(e.signer(t, args...)), &ext); err != nil {
					t.Fatal(err)
				}
				toolCBOR, _ := os.ReadFile(cbor)
				reg := cose.Cip88{Nonce: nonce}
				copy(reg.CalidusPub[:], mustHex(t, calV))
				pid := cose.Blake2b224(mustHex(t, set.vkey))
				reg.PoolID = pid
				if hex.EncodeToString(pid[:]) != ext.PoolIDHex {
					t.Fatalf("pool id %x, tool %s", pid, ext.PoolIDHex)
				}
				if hex.EncodeToString(reg.Payload()) != ext.PayloadCbor {
					t.Errorf("payload differs\n  tool: %s\n  go:   %x", ext.PayloadCbor, reg.Payload())
				}
				ph := reg.PayloadHash()
				if hex.EncodeToString(ph[:]) != ext.PayloadHash {
					t.Errorf("payload hash differs")
				}
				if id, _ := cose.CalidusID(reg.CalidusPub[:]); id != ext.CalidusIDBech {
					t.Errorf("calidus id %s, tool %s", id, ext.CalidusIDBech)
				}
				got, err := c88.SignCip88(ctx, mustCold(t, porttest.Key(t, st, custody.RolePoolCold, set.owner)), reg)
				if err != nil {
					t.Fatal(err)
				}
				if string(got.CBOR) != string(toolCBOR) {
					t.Errorf("metadata CBOR differs\n  tool: %x\n  go:   %x", toolCBOR, got.CBOR)
				}
				var a, b bytesJSON
				a, b = bytesJSON(ext.Output.JSON), bytesJSON(got.JSON)
				if a.compact() != b.compact() {
					t.Errorf("metadata JSON differs\n  tool: %s\n  go:   %s", a.compact(), got.JSON)
				}
				if got.JSON != a.compact() {
					t.Errorf("Go JSON is not byte-equal to the tool's compact form\n  tool: %s\n  go:   %s", a.compact(), got.JSON)
				}
				if _, err := cose.VerifyCip88(toolCBOR); err != nil {
					t.Errorf("go does not verify the tool's registration: %v", err)
				}
				for name, args := range map[string][]string{
					"--data-hex": {"--data-hex", hex.EncodeToString(got.CBOR)},
					"--data":     {"--data", got.JSON},
				} {
					v := e.signer(t, lits(append([]string{"verify", "--cip88"}, args...)...)...)
					if !strings.Contains(v, "true") {
						t.Errorf("the tool does not verify the Go registration (%s): %q", name, v)
					}
				}
			})
		}
	}
	// The wrong cold key is refused before signing.
	reg := cose.Cip88{Nonce: 1}
	reg.PoolID = cose.Blake2b224(mustHex(t, poolV))
	if _, err := c88.SignCip88(ctx, mustCold(t, porttest.Key(t, st, custody.RolePoolCold, "norm")), reg); err == nil {
		t.Error("a cold key signed for another pool's id")
	}
}

type bytesJSON []byte

// compact removes the whitespace outside strings.
func (b bytesJSON) compact() string {
	var out []byte
	in := false
	for _, c := range b {
		switch {
		case c == '"':
			in = !in
			out = append(out, c)
		case !in && (c == ' ' || c == '\n' || c == '\t'):
		default:
			out = append(out, c)
		}
	}
	return string(out)
}

// Calidus and voting keys derived natively equal cardano-signer's keygen for
// the public test phrase: the signing and verification key files byte for
// byte, the Calidus id, the `cvote_vk` text; the calidus alias is the path
// 1852H/1815H/0H/0/0.
//
// spec: SPO-15-EXT-001, SPO-15-INV-001, SPO-15-OUT-001, SPO-09a-EXT-001, SPO-09a-OUT-001, SPO-09a-OUT-002
func TestCalidusAndVotingKeysMatchCardanoSigner(t *testing.T) {
	e := setup(t)
	e.needSigner(t)
	ctx := context.Background()
	sw := native.SoftwareKeys{}
	m := secret.Take([]byte(publicPhrase))
	defer m.Destroy()

	// Calidus: the alias, and explicit paths for other accounts and indexes.
	for _, ai := range []struct{ a, i uint32 }{{0, 0}, {2, 5}} {
		dir := t.TempDir()
		args := lits("keygen", "--mnemonics", publicPhrase, "--json-extended", "--out-skey", filepath.Join(dir, "k.skey"), "--out-vkey", filepath.Join(dir, "k.vkey"))
		if ai.a == 0 && ai.i == 0 {
			args = append(args, lits("--path", "calidus")...)
		} else {
			args = append(args, lits("--path", "1852H/1815H/"+itoa(int(ai.a))+"H/0/"+itoa(int(ai.i)))...)
		}
		var ext struct {
			CalidusIDBech string `json:"calidusIdBech"`
			PublicKey     string `json:"publicKey"`
		}
		if err := json.Unmarshal([]byte(e.signer(t, args...)), &ext); err != nil {
			t.Fatal(err)
		}
		pair, err := sw.DeriveCalidus(ctx, m, ai.a, ai.i)
		if err != nil {
			t.Fatal(err)
		}
		toolV, _ := os.ReadFile(filepath.Join(dir, "k.vkey"))
		toolS, _ := os.ReadFile(filepath.Join(dir, "k.skey"))
		if ai.a == 0 && ai.i == 0 {
			if string(pair.VKey) != string(toolV) {
				t.Errorf("calidus vkey differs\n  tool: %s\n  go:   %s", toolV, pair.VKey)
			}
			if string(secretBytes(t, pair.SKey)) != string(toolS) {
				t.Errorf("calidus skey file differs (not shown)")
			}
		} else {
			// An explicit path has the payment descriptions; the key itself is the same.
			var gv struct{ CborHex string }
			json.Unmarshal(pair.VKey, &gv)
			if gv.CborHex[4:] != ext.PublicKey {
				t.Errorf("calidus %d/%d public key differs", ai.a, ai.i)
			}
		}
		id, err := cose.CalidusID(mustHex(t, ext.PublicKey))
		if err != nil || (ai.a == 0 && ai.i == 0 && id != ext.CalidusIDBech) {
			t.Errorf("calidus id %s (%v), tool %s", id, err, ext.CalidusIDBech)
		}
		pair.SKey.Destroy()
	}

	// Voting key: `--cip36` is 1694H/1815H/0H/0/0 and ignores --path (observed:
	// with --path 1694H/1815H/3H/0/7 --cip36 the tool still gives the 0/0 key); other
	// accounts and indexes are compared by public key through a plain --path.
	for _, ai := range []struct{ a, i uint32 }{{0, 0}, {3, 7}} {
		dir := t.TempDir()
		args := lits("keygen", "--mnemonics", publicPhrase, "--json-extended", "--out-skey", filepath.Join(dir, "k.skey"), "--out-vkey", filepath.Join(dir, "k.vkey"))
		if ai.a == 0 && ai.i == 0 {
			args = append(args, lits("--cip36")...)
		} else {
			args = append(args, lits("--path", "1694H/1815H/"+itoa(int(ai.a))+"H/0/"+itoa(int(ai.i)))...)
		}
		var ext struct {
			PublicKey     string `json:"publicKey"`
			PublicKeyBech string `json:"publicKeyBech"`
		}
		if err := json.Unmarshal([]byte(e.signer(t, args...)), &ext); err != nil {
			t.Fatal(err)
		}
		pair, bech, err := sw.DeriveVoting(ctx, m, ai.a, ai.i)
		if err != nil {
			t.Fatal(err)
		}
		toolV, _ := os.ReadFile(filepath.Join(dir, "k.vkey"))
		toolS, _ := os.ReadFile(filepath.Join(dir, "k.skey"))
		if ai.a == 0 && ai.i == 0 {
			if bech != ext.PublicKeyBech {
				t.Errorf("voting cvote_vk %s, tool %s", bech, ext.PublicKeyBech)
			}
			if string(pair.VKey) != string(toolV) {
				t.Errorf("voting vkey differs\n  tool: %s\n  go:   %s", toolV, pair.VKey)
			}
			if string(secretBytes(t, pair.SKey)) != string(toolS) {
				t.Errorf("voting skey file differs (not shown)")
			}
		} else {
			_, pub, _ := chain.Bech32Decode(bech)
			if hex.EncodeToString(pub) != ext.PublicKey {
				t.Errorf("voting %d/%d public key differs", ai.a, ai.i)
			}
		}
		pair.SKey.Destroy()
	}
}
