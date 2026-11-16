package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/fsstore"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/catalyst"
	domcat "github.com/mochipool/workbench/spo/internal/domain/catalyst"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

const (
	testPhrase  = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
	calidusOfIt = "calidus15yqt0pru382hy9vjlsxv3ye02z50sfvt8xunscg5pgden7czfjdjq"
)

// recDeriver records the path it was asked for and derives for real.
type recDeriver struct {
	native.SoftwareKeys
	calls [][2]uint32
}

func (r *recDeriver) DeriveCalidus(ctx context.Context, m *ports.Secret, a, i uint32) (ports.KeyPair, error) {
	r.calls = append(r.calls, [2]uint32{a, i})
	return r.SoftwareKeys.DeriveCalidus(ctx, m, a, i)
}

func (r *recDeriver) DeriveVoting(ctx context.Context, m *ports.Secret, a, i uint32) (ports.KeyPair, string, error) {
	r.calls = append(r.calls, [2]uint32{a, i})
	return r.SoftwareKeys.DeriveVoting(ctx, m, a, i)
}

type fakeCalidusReader struct{ f ports.CalidusFilter }

func (*fakeCalidusReader) Source() chain.Source { return "fake registrations" }
func (r *fakeCalidusReader) CalidusKeys(_ context.Context, f ports.CalidusFilter) ([]ports.CalidusEntry, error) {
	r.f = f
	return []ports.CalidusEntry{{PoolBech: "pool1abc", IDBech: calidusOfIt, PubKeyHex: strings.Repeat("ab", 32), Nonce: 9, HasNonce: true,
		Epoch: 5, HasEpoch: true, TxHash: strings.Repeat("cd", 32), BlockTime: time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)}}, nil
}

// withRegistrations gives the fixture the capabilities of the Calidus and
// Catalyst commands, with a recording deriver.
func withRegistrations(f *stakeFix, d *recDeriver, reader ports.CalidusKeyReader) {
	old := f.deps.Wire
	f.deps.Wire = func(st ports.Store, o WireOptions) (*Env, error) {
		env, err := old(st, o)
		if err != nil {
			return nil, err
		}
		var v ports.Vault
		if st != nil {
			v = st.(ports.Vault)
		}
		soft := native.SoftwareKeys{}
		env.CalidusKeys, env.VotingKeys, env.Mnemonics, env.ColdKeys = d, d, soft, soft
		env.SignatureSigner = native.VaultSignatures{VaultSigner: native.VaultSigner{Vault: v}}
		env.Signers = native.NewSignatureSigners(v)
		env.MetadataFiles, env.MsgEncrypter, env.CalidusReader = fsstore.MetadataFiles{}, native.CIP83{}, reader
		env.Absent(CapCalidusRead, "no provider reads Calidus keys")
		return env, nil
	}
}

// noTip takes the current-slot reader away, as in an offline mode without genesis.
func noTip(f *stakeFix) {
	old := f.deps.Wire
	f.deps.Wire = func(st ports.Store, o WireOptions) (*Env, error) {
		env, err := old(st, o)
		if env != nil {
			env.Tip = nil
			env.Absent(CapTip, "no genesis")
		}
		return env, err
	}
}

func (f *stakeFix) mustRun(t *testing.T, args ...string) string {
	t.Helper()
	f.out.Reset()
	if err := f.run(t, &scriptTerm{t: t}, args...); err != nil {
		t.Fatalf("%v: %v\n%s", args, err, f.out.String())
	}
	return f.out.String()
}

// What a command needs is stated before anything is asked or changed.
func TestCalidusAndCatalystStateTheirNeedsFirst(t *testing.T) {
	f := newStakeFix(t) // none of the new capabilities
	for _, tc := range [][]string{
		{"pool", "calidus", "new", "c"},
		{"pool", "calidus", "register-metadata", "c", "p"},
		{"pool", "calidus", "status", "c"},
		{"catalyst", "key", "new", "v"},
		{"catalyst", "register", "s", "s.payment", "--vote-key", "v"},
	} {
		term := &scriptTerm{t: t}
		err := f.run(t, term, tc...)
		if err == nil || !strings.Contains(err.Error(), "this command cannot run here; it needs:") {
			t.Errorf("%v: %v", tc, err)
		}
		if term.asked != 0 {
			t.Errorf("%v asked a question", tc)
		}
	}
	// The reasons are named.
	err := f.run(t, &scriptTerm{t: t}, "pool", "calidus", "register-metadata", "c", "p")
	if !strings.Contains(err.Error(), "registration-signing") {
		t.Errorf("%v", err)
	}
	// Without --mnemonic-in-fd a phrase is generated: that needs the generator too.
	g := newStakeFix(t)
	withRegistrations(g, &recDeriver{}, nil)
	old := g.deps.Wire
	g.deps.Wire = func(st ports.Store, o WireOptions) (*Env, error) {
		env, err := old(st, o)
		env.Mnemonics = nil
		return env, err
	}
	if err := g.run(t, &scriptTerm{t: t}, "pool", "calidus", "new", "c"); err == nil || !strings.Contains(err.Error(), "mnemonic-generation") {
		t.Errorf("a fresh phrase needs the generator: %v", err)
	}
	if g.has("c.calidus.vkey") {
		t.Error("a key was written")
	}
}

func TestCalidusNewAndCatalystKeyNewMapTheirFlags(t *testing.T) {
	f := newStakeFix(t)
	d := &recDeriver{}
	withRegistrations(f, d, nil)

	fd := pipeFD(t, testPhrase+"\n")
	out := f.mustRun(t, "pool", "calidus", "new", "c", "--mnemonic-in-fd", itoaFD(fd), "--account", "2", "--index", "3")
	mustContain(t, out, "Generated the Calidus key c.", "Calidus id   calidus1", "spo pool calidus register-metadata c <pool>")
	if len(d.calls) != 1 || d.calls[0] != [2]uint32{2, 3} {
		t.Errorf("path %v", d.calls)
	}
	if strings.Contains(out, "abandon") || strings.Contains(out, "cborHex") || strings.Contains(out, "recovery phrase was generated") {
		t.Errorf("key material or a false notice in:\n%s", out)
	}
	for _, n := range []string{"c.calidus.vkey", "c.calidus.skey", "c.calidus.mnemonics", "c.calidus.id"} {
		if !f.has(n) {
			t.Errorf("%s missing", n)
		}
	}
	// No phrase given: generated and stored, not shown.
	out = f.mustRun(t, "pool", "calidus", "new", "fresh")
	mustContain(t, out, "stored sealed in the workspace")
	if strings.Count(out, " ") > 0 && regexpWords(out) {
		t.Errorf("a phrase may have been printed:\n%s", out)
	}
	// Derivation numbers past the range, and a phrase on the passphrase descriptor.
	if err := f.run(t, &scriptTerm{t: t}, "pool", "calidus", "new", "x", "--account", "2147483648"); err == nil {
		t.Error("an account past the range")
	}
	if err := f.run(t, &scriptTerm{t: t}, "--passphrase-fd", "7", "pool", "calidus", "new", "x", "--mnemonic-in-fd", "7"); err == nil || !strings.Contains(err.Error(), "same descriptor") {
		t.Errorf("same descriptor: %v", err)
	}

	d.calls = nil
	fd = pipeFD(t, testPhrase+"\n")
	out = f.mustRun(t, "catalyst", "key", "new", "v", "--mnemonic-in-fd", itoaFD(fd), "--index", "1")
	mustContain(t, out, "Generated the voting key v.", "public key   cvote_vk1", "--vote-key v")
	if len(d.calls) != 1 || d.calls[0] != [2]uint32{0, 1} || strings.Contains(out, "abandon") {
		t.Errorf("%v\n%s", d.calls, out)
	}
	if !f.has("v.voting.pkey") || !f.has("v.voting.skey") {
		t.Error("voting key files")
	}
}

// regexpWords is true when the text has a run of twelve lower-case words.
func regexpWords(s string) bool {
	n := 0
	for _, w := range strings.Fields(s) {
		if len(w) >= 3 && len(w) <= 8 && strings.ToLower(w) == w && strings.Trim(w, "abcdefghijklmnopqrstuvwxyz") == "" {
			n++
			if n >= 12 {
				return true
			}
		} else {
			n = 0
		}
	}
	return false
}

func TestCalidusRegisterMetadata(t *testing.T) {
	f := newStakeFix(t)
	withRegistrations(f, &recDeriver{}, nil)
	noTip(f)
	f.mustRun(t, "pool", "keys", "generate", "p")
	fd := pipeFD(t, testPhrase+"\n")
	f.mustRun(t, "pool", "calidus", "new", "c", "--mnemonic-in-fd", itoaFD(fd))

	// A zero nonce is not the default; no slot source on a testnet needs --nonce.
	if err := f.run(t, &scriptTerm{t: t}, "pool", "calidus", "register-metadata", "c", "p", "--nonce", "0"); err == nil || !strings.Contains(err.Error(), "greater than zero") {
		t.Errorf("zero nonce: %v", err)
	}
	if err := f.run(t, &scriptTerm{t: t}, "pool", "calidus", "register-metadata", "c", "p"); err == nil || !strings.Contains(err.Error(), "give --nonce") {
		t.Errorf("no slot source: %v", err)
	}
	out := f.mustRun(t, "pool", "calidus", "register-metadata", "c", "p", "--nonce", "77")
	mustContain(t, out, "Calidus id   "+calidusOfIt, "nonce        77", "pool id      pool1", ".calidus-registration.json",
		"spo wallet send <payer> <payer> MIN --metadata-record p_")
	if strings.Contains(out, "skey") || strings.Contains(out, "cborHex") {
		t.Errorf("key material:\n%s", out)
	}

	// A pool whose cold key is on a hardware wallet is refused up front: no file.
	f.mustRun(t, "pool", "keys", "generate", "h")
	if err := os.WriteFile(filepath.Join(f.dir, "h.node.hwsfile"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := regList(t, f.dir)
	err := f.run(t, &scriptTerm{t: t}, "pool", "calidus", "register-metadata", "c", "h", "--nonce", "5")
	if err == nil || !errors.Is(err, ports.ErrNoHardwareSigner) && !strings.Contains(err.Error(), "hardware") {
		t.Errorf("a hardware cold key: %v", err)
	}
	if after := regList(t, f.dir); len(after) != len(before) {
		t.Errorf("a registration was written: %v -> %v", before, after)
	}
}

func regList(t *testing.T, dir string) []string {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(dir, "*registration*"))
	return m
}

func TestCalidusStatus(t *testing.T) {
	f := newStakeFix(t)
	r := &fakeCalidusReader{}
	withRegistrations(f, &recDeriver{}, r)
	old := f.deps.Wire
	f.deps.Wire = func(st ports.Store, o WireOptions) (*Env, error) { // the reader is there
		env, err := old(st, o)
		env.CalidusReader = r
		return env, err
	}
	out := f.mustRun(t, "pool", "calidus", "status", calidusOfIt)
	mustContain(t, out, "1 registration(s), 1 Calidus key(s) [fake registrations]", "pool pool1abc", "calidus id  "+calidusOfIt,
		"nonce       9", "epoch       5", "2026-11-16T09:00:00Z")
	if r.f.IDBech != calidusOfIt {
		t.Errorf("filter %+v", r.f)
	}
}

func TestVoteKeyFlagsBecomeADelegation(t *testing.T) {
	got, err := delegationWords([]string{"v", "w:3", "cvote_vk1abc:10"})
	if err != nil || got != "v|w 3|cvote_vk1abc 10" {
		t.Fatalf("%q %v", got, err)
	}
	words, err := catalyst.ParseDelegation(got)
	if err != nil || len(words) != 3 || words[0].Weight != 1 || words[1].Weight != 3 || words[2].Weight != 10 {
		t.Errorf("%+v %v", words, err)
	}
	for _, bad := range [][]string{nil, {""}, {"a|b"}, {"a b"}, {"a:"}, {":3"}} {
		if _, err := delegationWords(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	if _, err := catalyst.ParseDelegation("v x"); err == nil {
		t.Error("a weight that is not a number")
	}
}

func TestCatalystRegisterFlagsReachTheUseCase(t *testing.T) {
	f := newStakeFix(t)
	withRegistrations(f, &recDeriver{}, nil)
	noTip(f)
	f.newWallet(t)
	fd := pipeFD(t, testPhrase+"\n")
	f.mustRun(t, "catalyst", "key", "new", "v", "--mnemonic-in-fd", itoaFD(fd))
	if err := f.run(t, &scriptTerm{t: t}, "catalyst", "register", "s", "s.payment", "--vote-key", "v"); err == nil || !strings.Contains(err.Error(), "--nonce") {
		t.Errorf("no slot source: %v", err)
	}
	out := f.mustRun(t, "catalyst", "register", "s", "s.payment", "--vote-key", "v:4", "--nonce", "9", "--purpose", "0")
	mustContain(t, out, "nonce        9", "weight 4", "rewards to   addr_test1", ".vote-registration.cbor", "spo wallet send <payer> <payer> MIN --metadata-record s_")
	if strings.Contains(out, "skey") || strings.Contains(out, "cborHex") {
		t.Errorf("key material:\n%s", out)
	}
	// A rewards address of another network is the use case's refusal.
	if err := f.run(t, &scriptTerm{t: t}, "catalyst", "register", "s", "addr1vyqt0pru382hy9vjlsxv3ye02z50sfvt8xunscg5pgden7czra7te", "--vote-key", "v", "--nonce", "9"); !errors.Is(err, catalyst.ErrBadRewards) {
		t.Errorf("another network: %v", err)
	}
}

// --metadata-record reads the registration through the workspace; the name must
// carry its extension, and a record the workspace lacks is the reader's refusal.
func TestMetadataRecordReadsThroughTheWorkspace(t *testing.T) {
	f := newStakeFix(t)
	withRegistrations(f, &recDeriver{}, nil)
	f.newWallet(t)
	fd := pipeFD(t, testPhrase+"\n")
	f.mustRun(t, "catalyst", "key", "new", "v", "--mnemonic-in-fd", itoaFD(fd))
	out := f.mustRun(t, "catalyst", "register", "s", "s.payment", "--vote-key", "v", "--nonce", "9")
	i := strings.Index(out, "stored as")
	name := strings.Fields(out[i:])[2]

	out = f.mustRun(t, "wallet", "send", "w", sendTo, "2000000", "--metadata-record", name, "--yes")
	mustContain(t, out, "Queued transaction")
	if len(f.queue.got) != 1 || !bytes.Contains(f.queue.got[0].Tx.CBOR, []byte{0x19, 0xef, 0x64}) { // label 61284
		t.Errorf("the registration is not in the transaction")
	}
	for _, name := range []string{"s_1", "s_1.vote.cbor", "nope.vote-registration.cbor"} {
		if err := f.run(t, &scriptTerm{t: t}, "wallet", "send", "w", sendTo, "2000000", "--metadata-record", name, "--yes"); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// The same flag on the other transaction commands.
	for _, args := range [][]string{
		{"wallet", "claim-rewards", "s", "s.payment", "--metadata-record", name, "--yes"},
		{"stake", "register", "s", "s.payment", "--metadata-record", name, "--yes", "--allow-unverified"},
	} {
		if err := f.run(t, &scriptTerm{t: t}, args...); err != nil && strings.Contains(err.Error(), "unknown flag") {
			t.Errorf("%v: %v", args, err)
		}
	}
}

// The recordFiles reader only serves the names it was given.
func TestRecordFilesServeOnlyNamedRecords(t *testing.T) {
	dir := t.TempDir()
	st, _ := fsstore.Open(dir)
	ref := ports.Ref{Name: "s_1", Kind: ports.VoteRegistration}
	if err := st.Update(context.Background(), func(w ports.Writer) error { return w.Put(ref, []byte{0xa0}) }); err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(dir, "plain.json")
	os.WriteFile(disk, []byte(`{}`), 0o600)
	r, err := newRecordFiles(st, []string{"s_1.vote-registration.cbor"}, fsstore.MetadataFiles{})
	if err != nil {
		t.Fatal(err)
	}
	if b, err := r.ReadMetadataFile("s_1.vote-registration.cbor"); err != nil || len(b) != 1 {
		t.Errorf("%v %v", b, err)
	}
	if b, err := r.ReadMetadataFile(disk); err != nil || string(b) != "{}" {
		t.Errorf("a plain file: %v %s", err, b)
	}
	if _, err := r.ReadMetadataFile("other.vote-registration.cbor"); err == nil {
		t.Error("a record that was not named is served from the store or the disk")
	}
	if _, err := newRecordFiles(st, []string{"s_1"}, nil); err == nil {
		t.Error("a name without its extension")
	}
}

// claim-rewards takes the extras like the other certificate commands.
func TestClaimRewardsTakesTheExtras(t *testing.T) {
	f := newStakeFix(t)
	withExtras(f.sendFixture)
	old := f.deps.Wire
	f.deps.Wire = func(st ports.Store, o WireOptions) (*Env, error) {
		env, err := old(st, o)
		if env != nil {
			env.MetadataFiles = fsstore.MetadataFiles{}
		}
		return env, err
	}
	f.newWallet(t)
	f.rewards = &fakeRewards{name: "fake rewards", r: registered(7_000_000)}
	meta := writeFile(t, t.TempDir(), "m.json", `{"721":{"name":"claim-demo"}}`)
	if err := f.run(t, &scriptTerm{t: t}, "wallet", "claim-rewards", "s", "s.payment", "--yes", "--metadata-file", meta, "--message", "thanks"); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	f.queued(t, 1)
	if !bytes.Contains(f.queue.got[0].Tx.CBOR, []byte("claim-demo")) || !bytes.Contains(f.queue.got[0].Tx.CBOR, []byte("thanks")) {
		t.Error("the metadata file or the message is not in the claim")
	}
	// The payment filters are not a claim's flags.
	if err := f.run(t, &scriptTerm{t: t}, "wallet", "claim-rewards", "s", "s.payment", "--utxo-limit", "2"); err == nil || !strings.Contains(err.Error(), "unknown flag") {
		t.Errorf("%v", err)
	}
}

type fakeQR struct{ png int }

func (fakeQR) VotingKeyQRPayload(context.Context, string, domcat.PIN) ([]byte, error) {
	return []byte("payload"), nil
}
func (q *fakeQR) WritePNG(string, []byte) error { q.png++; return nil }
func (*fakeQR) Terminal([]byte) (string, error) { return "██DRAWING██\n", nil }

// The key-equivalent QR code is drawn in the terminal only when the operator
// asks (--show) and standard output is a terminal; by default only the PNG is
// written. A piped or redirected output never gets the drawing. The warning
// names scrollback, terminal logs and screen sharing and says the PNG and the
// drawing are key-equivalent under a four-digit PIN.
//
// spec: SPO-09a-OUT-007, SPO-09a-SEC-002
func TestCatalystQRCodeIsDrawnOnlyOnRequestAndOnATerminal(t *testing.T) {
	f := newStakeFix(t)
	d := &recDeriver{}
	withRegistrations(f, d, nil)
	qr := &fakeQR{}
	old := f.deps.Wire
	f.deps.Wire = func(st ports.Store, o WireOptions) (*Env, error) {
		env, err := old(st, o)
		if env != nil {
			env.VotingQR, env.QRCodes = qr, qr
		}
		return env, err
	}
	fd := pipeFD(t, testPhrase+"\n")
	f.mustRun(t, "catalyst", "key", "new", "v", "--mnemonic-in-fd", itoaFD(fd))
	run := func(tty bool, extra ...string) string {
		t.Helper()
		defer func(o func(io.Writer) bool) { stdoutIsTerminal = o }(stdoutIsTerminal)
		stdoutIsTerminal = func(io.Writer) bool { return tty }
		pin := pipeFD(t, "4821\n")
		return f.mustRun(t, append([]string{"catalyst", "key", "qrcode", "v", "--pin-fd", itoaFD(pin), "--out", "x.png"}, extra...)...)
	}
	for name, tc := range map[string]struct {
		tty   bool
		extra []string
		draws bool
	}{"default on a terminal": {true, nil, false}, "--show on a pipe": {false, []string{"--show"}, false}, "default on a pipe": {false, nil, false}, "--show on a terminal": {true, []string{"--show"}, true}} {
		out := run(tc.tty, tc.extra...)
		if got := strings.Contains(out, "DRAWING"); got != tc.draws {
			t.Errorf("%s: drawn = %v\n%s", name, got, out)
		}
		mustContain(t, out, "key-equivalent", "four-digit PIN")
	}
	out := run(true, "--show")
	mustContain(t, out, "scrollback", "terminal log", "shared screen")
	if strings.Contains(out, "4821") {
		t.Error("the PIN was printed")
	}
	if qr.png != 5 {
		t.Errorf("PNGs written: %d", qr.png)
	}
}
