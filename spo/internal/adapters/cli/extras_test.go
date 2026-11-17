package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/adapters/upstreamdir"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/txparam"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ---- flag to extras mapping ----

func parseFlags(t *testing.T, kind extraKind, msgs []string, args ...string) (*extraFlags, error) {
	t.Helper()
	cmd := &cobra.Command{Use: "x"}
	var f extraFlags
	m := msgs
	f.add(cmd, &m, kind)
	if err := cmd.ParseFlags(args); err != nil {
		return nil, err
	}
	return &f, f.parse()
}

const (
	txA = "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11"
	txB = "bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22"
	pol = "cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33"
)

func TestExtraFlagsBecomeTheDomainsExtras(t *testing.T) {
	f, err := parseFlags(t, extraSend, []string{"hello"}, "--metadata-file", "a.json", "--metadata-file", "B.CBOR",
		"--utxo-limit", "3", "--only-utxo-with-asset", pol, "--only-utxo-with-asset", pol+"746f6b", "--skip-utxo-with-asset", pol,
		"--input", txA+"#0", "--input", txB+"#7", "--encrypt-messages")
	if err != nil {
		t.Fatal(err)
	}
	ex := f.ex
	if ex == nil {
		t.Fatal("no extras")
	}
	if len(ex.MetadataFiles) != 2 || ex.MetadataFiles[0] != (txparam.MetadataFile{Path: "a.json", Format: txparam.FileJSON}) ||
		ex.MetadataFiles[1] != (txparam.MetadataFile{Path: "B.CBOR", Format: txparam.FileCBOR}) {
		t.Errorf("files: %+v", ex.MetadataFiles)
	}
	if ex.UtxoLimit != 3 || len(ex.Only) != 2 || !ex.Only[1].HasName || string(ex.Only[1].Name) != "tok" || len(ex.Skip) != 1 {
		t.Errorf("filters: %+v", ex)
	}
	if len(ex.Inputs) != 2 || ex.Inputs[1].Index != 7 || ex.Inputs[0].TxID.String() != txA {
		t.Errorf("inputs: %+v", ex.Inputs)
	}
	// The message lines are the command's own flag: the mode is kept with a
	// message and dropped without one.
	if ex.Encryption != "basic" || len(ex.Messages) != 0 {
		t.Errorf("encryption %q messages %v", ex.Encryption, ex.Messages)
	}
	if ex.HasPassphrase() {
		t.Error("a passphrase came out of a flag")
	}
	f, err = parseFlags(t, extraSend, nil, "--encrypt-messages")
	if err != nil || f.ex != nil {
		t.Errorf("--encrypt-messages with no message has an effect: %v %v", f.ex, err)
	}
	f, err = parseFlags(t, extraSend, []string{"only a message"})
	if err != nil || f.ex != nil {
		t.Errorf("a message alone needs no extras: %v %v", f.ex, err)
	}
	if got := f.needs(); len(got) != 0 {
		t.Errorf("needs %v", got)
	}
	f, _ = parseFlags(t, extraSend, []string{"m"}, "--metadata-file", "a.json", "--encrypt-messages")
	if n := f.needs(); len(n) != 2 || n[0] != Need(CapMetaFiles) || n[1] != Need(CapMsgEncrypt) {
		t.Errorf("needs %v", n)
	}
}

// The domain's refusals are the ones the command gives; nothing is
// re-implemented here.
func TestExtraFlagRefusalsAreTheDomainsOwn(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want error
	}{
		{[]string{"--metadata-file", "notes.txt"}, txparam.ErrBadMetadataFile},
		{[]string{"--metadata-file", "x:y.json"}, txparam.ErrUnknownKey},
		{[]string{"--utxo-limit", "0"}, txparam.ErrBadUtxoLimit},
		{[]string{"--utxo-limit", "many"}, txparam.ErrBadUtxoLimit},
		{[]string{"--input", "nothex#1"}, txparam.ErrBadUtxoRef},
		{[]string{"--input", txA}, nil},
		{[]string{"--only-utxo-with-asset", "abcd"}, txparam.ErrBadAssetFilter},
		{[]string{"--skip-utxo-with-asset", pol + "|" + pol}, nil},
	} {
		_, err := parseFlags(t, extraSend, nil, tc.args...)
		switch {
		case tc.want != nil && !errors.Is(err, tc.want):
			t.Errorf("%v: %v, want %v", tc.args, err, tc.want)
		case tc.want == nil && tc.args[0] != "--input" && err == nil:
			t.Errorf("%v: accepted", tc.args)
		}
	}
	// A flag a command does not offer is not there at all.
	if _, err := parseFlags(t, extraCert, nil, "--utxo-limit", "2"); err == nil || !strings.Contains(err.Error(), "unknown flag") {
		t.Errorf("a certificate command with --utxo-limit: %v", err)
	}
	if _, err := parseFlags(t, extraMint, nil, "--only-utxo-with-asset", pol); err == nil {
		t.Error("mint accepts the asset filters")
	}
	if f, err := parseFlags(t, extraMint, nil, "--input", txA+"#1"); err != nil || f.ex == nil || len(f.ex.Inputs) != 1 {
		t.Errorf("mint --input: %v", err)
	}
	if _, err := parseFlags(t, extraAssets, nil, "--lovelace", "007"); !errors.Is(err, txparam.ErrBadLovelaces) {
		t.Errorf("--lovelace 007: %v", err)
	}
	if f, err := parseFlags(t, extraAssets, nil, "--lovelace", "3000000", "--keep-policy", pol); err != nil || f.ex.Lovelaces != 3_000_000 || len(f.ex.KeepPolicies) != 1 {
		t.Errorf("--lovelace: %v", err)
	}
}

// ---- through the commands ----

// secretTerm answers secret prompts from a list and records what it was asked.
type secretTerm struct {
	secrets []string
	lines   []string
	asked   []string
}

func (s *secretTerm) ReadSecret(_ context.Context, p string) (*secret.Buffer, error) {
	s.asked = append(s.asked, p)
	if len(s.secrets) == 0 {
		return nil, ErrNoTerminal
	}
	v := s.secrets[0]
	s.secrets = s.secrets[1:]
	return secret.Take([]byte(v)), nil
}
func (s *secretTerm) ReadLine(_ context.Context, p string) (string, error) {
	s.asked = append(s.asked, p)
	if len(s.lines) == 0 {
		return "", ErrNoTerminal
	}
	l := s.lines[0]
	s.lines = s.lines[1:]
	return l, nil
}

// withExtras gives the fixture's Wire the local capabilities of the extras.
func withExtras(f *sendFixture) {
	old := f.deps.Wire
	f.deps.Wire = func(st ports.Store, o WireOptions) (*Env, error) {
		env, err := old(st, o)
		if err != nil {
			return nil, err
		}
		env.MetadataFiles, env.MsgEncrypter = upstreamdir.MetadataFiles{}, native.CIP83{}
		env.PolicyIDs, env.PaymentKeys = native.Ledger{}, native.SoftwareKeys{}
		return env, nil
	}
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// pipeFD returns a descriptor that holds text, kept open for the test.
func pipeFD(t *testing.T, text string) int {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.WriteString(text)
	w.Close()
	t.Cleanup(func() { r.Close() })
	return int(r.Fd())
}

func TestSendWithMetadataFileAndEncryptedMessage(t *testing.T) {
	f := newSendFixture(t)
	withExtras(f)
	meta := writeFile(t, t.TempDir(), "m.json", `{"721":{"name":"demo-nft"}}`)
	const pass = "s3cret-message-passphrase"
	args := []string{"wallet", "send", "w", sendTo, "12000000", "--yes", "--message", "hello world", "--metadata-file", meta,
		"--encrypt-messages", "--message-passphrase-fd", itoaFD(pipeFD(t, pass+"\n"))}
	term := &secretTerm{}
	if err := f.run(t, term, args...); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	if len(term.asked) != 0 {
		t.Errorf("a descriptor was given and the terminal was asked: %v", term.asked)
	}
	if len(f.queue.got) != 1 {
		t.Fatalf("queued %d", len(f.queue.got))
	}
	tx := f.queue.got[0].Tx.CBOR
	if !bytes.Contains(tx, []byte("demo-nft")) {
		t.Error("the metadata file is not in the transaction")
	}
	if bytes.Contains(tx, []byte("hello world")) || !bytes.Contains(tx, []byte("basic")) {
		t.Error("the message was not encrypted")
	}
	// The passphrase is in no argument, no output and no queue entry.
	for _, a := range args {
		if strings.Contains(a, pass) {
			t.Errorf("the passphrase is in argv: %q", a)
		}
	}
	for _, where := range []string{f.out.String(), string(tx), f.queue.got[0].Description} {
		if strings.Contains(where, pass) {
			t.Errorf("the passphrase leaked:\n%s", where)
		}
	}
}

func TestEncryptedMessagePassphraseFromTheTerminalIsAskedTwiceWithoutEcho(t *testing.T) {
	f := newSendFixture(t)
	withExtras(f)
	const pass = "typed-passphrase-1"
	term := &secretTerm{secrets: []string{pass, pass}}
	if err := f.run(t, term, "wallet", "send", "w", sendTo, "12000000", "--yes", "--message", "hi", "--encrypt-messages"); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	if len(term.asked) != 2 || !strings.Contains(term.asked[0], "Message passphrase") || !strings.Contains(term.asked[1], "Repeat") {
		t.Errorf("prompts: %q", term.asked)
	}
	if strings.Contains(f.out.String(), pass) || bytes.Contains(f.queue.got[0].Tx.CBOR, []byte("hi\x00")) {
		t.Error("the passphrase or the clear message leaked")
	}
	// Two entries that differ queue nothing.
	f = newSendFixture(t)
	withExtras(f)
	term = &secretTerm{secrets: []string{pass, pass + "x"}}
	if err := f.run(t, term, "wallet", "send", "w", sendTo, "12000000", "--yes", "--message", "hi", "--encrypt-messages"); err == nil || len(f.queue.got) != 0 {
		t.Errorf("mismatch: %v", err)
	}
	// No terminal and no descriptor: the way out is named, nothing is queued.
	f = newSendFixture(t)
	withExtras(f)
	err := f.run(t, &secretTerm{}, "wallet", "send", "w", sendTo, "12000000", "--yes", "--message", "hi", "--encrypt-messages")
	if err == nil || !strings.Contains(err.Error(), "--message-passphrase-fd") || len(f.queue.got) != 0 {
		t.Errorf("no terminal: %v", err)
	}
}

// A refusal of the domain happens before the workspace is opened and before
// any prompt.
func TestExtraRefusalHappensBeforeAnyPrompt(t *testing.T) {
	f := newSendFixture(t)
	withExtras(f)
	err := f.run(t, failTerm{t}, "wallet", "send", "w", sendTo, "12000000", "--metadata-file", "notes.txt", "--encrypt-messages", "--message", "x")
	if !errors.Is(err, txparam.ErrBadMetadataFile) {
		t.Errorf("%v", err)
	}
	err = f.run(t, &scriptTerm{t: t}, "wallet", "send", "w", sendTo, "12000000", "--yes", "--metadata-file", filepath.Join(t.TempDir(), "absent.json"))
	if err == nil || !strings.Contains(err.Error(), "does not exist") || len(f.queue.got) != 0 {
		t.Errorf("a missing metadata file: %v", err)
	}
	long := strings.Repeat("x", 65)
	err = f.run(t, &scriptTerm{t: t}, "wallet", "send", "w", sendTo, "12000000", "--yes", "--message", long)
	if err == nil || len(f.queue.got) != 0 {
		t.Errorf("a message over 64 bytes: %v", err)
	}
	// The capability is named when the Env has none.
	f2 := newSendFixture(t)
	err = f2.run(t, failTerm{t}, "wallet", "send", "w", sendTo, "12000000", "--metadata-file", "m.json")
	if err == nil || !strings.Contains(err.Error(), "metadata-file") {
		t.Errorf("no reader: %v", err)
	}
}

// The certificate commands take the extras too.
func TestStakeRegisterCarriesMetadataFile(t *testing.T) {
	f := newStakeFix(t)
	withExtras(f.sendFixture)
	old := f.deps.Wire
	f.deps.Wire = func(st ports.Store, o WireOptions) (*Env, error) {
		env, err := old(st, o)
		if env != nil {
			env.MetadataFiles = upstreamdir.MetadataFiles{}
		}
		return env, err
	}
	f.newWallet(t)
	f.rewards = &fakeRewards{name: "fake rewards", r: chainUnknown()}
	meta := writeFile(t, t.TempDir(), "m.json", `{"721":{"name":"cert-demo"}}`)
	if err := f.run(t, &scriptTerm{t: t}, "stake", "register", "s", "s.payment", "--yes", "--allow-unverified", "--metadata-file", meta); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	f.queued(t, 1)
	if !bytes.Contains(f.queue.got[0].Tx.CBOR, []byte("cert-demo")) {
		t.Error("the metadata file is not in the stake registration")
	}
	// The payment filters are not a certificate command's.
	err := f.run(t, &scriptTerm{t: t}, "stake", "register", "s", "s.payment", "--utxo-limit", "2")
	if err == nil || !strings.Contains(err.Error(), "unknown flag") {
		t.Errorf("%v", err)
	}
}

func itoaFD(fd int) string { return strconv.Itoa(fd) }

func chainUnknown() chain.Reading[chain.RewardAccount] {
	return chain.Unknown[chain.RewardAccount]("not in the file")
}
