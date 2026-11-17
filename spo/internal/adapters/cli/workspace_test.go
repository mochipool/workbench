package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/exportdir"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/adapters/upstreamdir"
	"github.com/mochipool/workbench/spo/internal/domain/keyfile"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

// fsSealed stands in for the sealed workspace: an upstream-layout directory
// behind the SealedStore interface. Only what the workspace commands use is
// implemented; the rest of the interface is the nil embedded one.
type fsSealed struct {
	SealedStore
	st *plainstore.Store
}

func (f *fsSealed) View(ctx context.Context, fn func(ports.Reader) error) error {
	return f.st.View(ctx, fn)
}
func (f *fsSealed) Update(ctx context.Context, fn func(ports.Writer) error) error {
	return f.st.Update(ctx, fn)
}
func (f *fsSealed) Open(ctx context.Context, r ports.Ref) (*secret.Buffer, error) {
	return f.st.Open(ctx, r)
}
func (f *fsSealed) List(ctx context.Context) (ports.SourceListing, error) { return f.st.List(ctx) }
func (f *fsSealed) Close() error                                          { return nil }
func (f *fsSealed) Notices() []string                                     { return nil }

// auditRec records what the export tells the auditor, and what was already in
// the destination when it did.
type auditRec struct {
	reason string
	events []ports.AuditEvent
	// seenFiles is the number of files in dest at the time of each record.
	dest      string
	seenFiles []int
	fail      error
}

func (a *auditRec) Record(_ context.Context, e ports.AuditEvent) error {
	a.events = append(a.events, e)
	ents, _ := os.ReadDir(a.dest)
	a.seenFiles = append(a.seenFiles, len(ents))
	return a.fail
}

type wsFix struct {
	t      *testing.T
	ws     string // the "sealed" workspace
	sealed *fsSealed
	src    string // the upstream directory to import
	out    bytes.Buffer
	audit  *auditRec
	deps   Deps
	seed   []byte
	gpg    bool // the Env has a (fake) gpg
}

// fakeCrypt is both gpg ports without gpg: the "ciphertext" has the packet
// structure of gpg's symmetric message (a session key packet and an
// integrity-protected data packet, which the export destination checks) around
// the key text, bound to the exact password.
type fakeCrypt struct{}

// cryptPad is the session key packet (version 4, AES-256, S2K 3, SHA-512, a
// salt, count 255) and the header of the data packet (tag 18, a four-octet
// length), then the data packet's version octet 1.
func cryptHead(n int) string {
	n++ // the version octet
	return "\xc3\x0d\x04\x09\x03\x0a\x01\x02\x03\x04\x05\x06\x07\x08\xff" + "\xd2\xff" +
		string([]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}) + "\x01"
}

const cryptPadLen = 15 + 6 + 1

func (fakeCrypt) Encrypt(_ context.Context, cbor, pass *ports.Secret) ([]byte, error) {
	var out []byte
	err := cbor.Use(func(c []byte) error {
		return pass.Use(func(p []byte) error {
			body := string(p) + "\x00" + string(c)
			out = []byte(hex.EncodeToString([]byte(cryptHead(len(body)) + body)))
			return nil
		})
	})
	return out, err
}

func (fakeCrypt) Decrypt(_ context.Context, encrHex []byte, pass *ports.Secret) (*ports.Secret, error) {
	raw, err := hex.DecodeString(string(encrHex))
	if err != nil || len(raw) < cryptPadLen || !strings.HasPrefix(string(raw), "\xc3\x0d\x04\x09\x03") {
		return nil, ports.ErrMalformedCiphertext
	}
	pw, cbor, ok := strings.Cut(string(raw[cryptPadLen:]), "\x00")
	if !ok {
		return nil, ports.ErrMalformedCiphertext
	}
	good := false
	_ = pass.Use(func(p []byte) error { good = string(p) == pw; return nil })
	if !good {
		return nil, ports.ErrWrongPassphrase
	}
	return secret.Take([]byte(cbor)), nil
}

func skeyText(seed []byte) string {
	return `{"type":"PaymentSigningKeyShelley_ed25519","description":"","cborHex":"5820` + hex.EncodeToString(seed) + `"}`
}

func vkeyText(seed []byte) string {
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	return `{"type":"PaymentVerificationKeyShelley_ed25519","description":"","cborHex":"5820` + hex.EncodeToString(pub) + `"}`
}

func newWsFix(t *testing.T) *wsFix {
	t.Helper()
	f := &wsFix{t: t, ws: t.TempDir(), src: t.TempDir(), audit: &auditRec{}}
	f.seed = make([]byte, 32)
	for i := range f.seed {
		f.seed[i] = byte(i + 9)
	}
	os.WriteFile(filepath.Join(f.ws, WorkspaceFile), []byte("sealed"), 0o600)
	ws, err := plainstore.OpenTestnet(f.ws)
	if err != nil {
		t.Fatal(err)
	}
	f.sealed = &fsSealed{st: ws}
	f.deps = Deps{
		Out: &f.out, Err: &f.out,
		Config:             memConfig(map[string]WorkspaceConfig{f.ws: {Network: "preview", Mode: ModeOffline}}),
		Sealed:             SealedOps{Open: func(string, *secret.Buffer, OpenOptions) (SealedStore, error) { return f.sealed, nil }},
		OpenUpstreamSource: func(dir string) (UpstreamSource, error) { return upstreamdir.Open(dir) },
		OpenExportDir:      func(dir string) (ports.Store, error) { return exportdir.Open(dir) },
		WorkspaceAuditor: func(_ string, _ ports.Store, reason string) ports.WorkspaceAuditor {
			f.audit.reason = reason
			return f.audit
		},
		Wire: func(st ports.Store, o WireOptions) (*Env, error) {
			led := native.Ledger{}
			env := &Env{Mode: o.Mode, NetworkID: ports.NetworkTestnet, AddressInspector: led, VKeyDeriver: native.VKeyDeriver{}}
			if f.gpg {
				env.KeyEncryptor, env.KeyDecryptor = fakeCrypt{}, fakeCrypt{}
			}
			return env, nil
		},
	}
	return f
}

// wallet writes a wallet of the upstream layout into dir.
func (f *wsFix) wallet(dir, name string, vkeyOf []byte) {
	f.t.Helper()
	os.WriteFile(filepath.Join(dir, name+".addr"), []byte(testnetAddr(f.seed)+"\n"), 0o600)
	os.WriteFile(filepath.Join(dir, name+".skey"), []byte(skeyText(f.seed)), 0o400)
	os.WriteFile(filepath.Join(dir, name+".vkey"), []byte(vkeyText(vkeyOf)), 0o600)
}

func (f *wsFix) run(term Terminal, args ...string) error {
	f.t.Helper()
	d := f.deps
	d.Terminal = term
	root := NewRoot(d)
	root.SetArgs(append([]string{"-C", f.ws, "--passphrase-fd", itoaFD(pipeFD(f.t, "workspace passphrase\n"))}, args...))
	return root.ExecuteContext(context.Background())
}

// The report is a table of owner, artefact, status and reason; a failed owner
// is not imported and the exit status says so; no key material is printed.
func TestImportReportHasNoSecretsAndFailsOnAFailedOwner(t *testing.T) {
	f := newWsFix(t)
	f.wallet(f.src, "good", f.seed)
	other := make([]byte, 32)
	other[0] = 1
	f.wallet(f.src, "bad", other) // a verification key that is not the signing key's
	os.WriteFile(filepath.Join(f.src, "notes.txt"), []byte("hello"), 0o600)

	err := f.run(&scriptTerm{t: t}, "workspace", "import", f.src)
	out := f.out.String()
	if err == nil || !strings.Contains(err.Error(), "1 owner(s) were not imported") {
		t.Fatalf("exit: %v\n%s", err, out)
	}
	mustContain(t, out, "OWNER", "ARTEFACT", "STATUS", "REASON", "good", "good.addr.skey", "done", "bad", "failed", "notes.txt", "ignored", "1 owner(s) of 2 imported")
	for _, bad := range []string{hex.EncodeToString(f.seed), "cborHex", "SigningKey", "5820"} {
		if strings.Contains(out, bad) {
			t.Errorf("the report holds %q:\n%s", bad, out)
		}
	}
	// Nothing of the failed owner is in the workspace; the good one is.
	if _, err := os.Stat(filepath.Join(f.ws, "bad.skey")); err == nil {
		t.Error("a failed owner was written")
	}
	if _, err := os.Stat(filepath.Join(f.ws, "good.skey")); err != nil {
		t.Errorf("the good owner was not written: %v", err)
	}
	// The source was only read.
	if b, _ := os.ReadFile(filepath.Join(f.src, "good.skey")); string(b) != skeyText(f.seed) {
		t.Error("the source changed")
	}
	// There is no --upstream-layout here (this Deps wires no plain workspace).
	if NewRoot(f.deps).PersistentFlags().Lookup("upstream-layout") != nil {
		t.Error("the flag exists although no plain workspace is wired")
	}
	err = f.run(&scriptTerm{t: t}, "workspace", "import", f.src, "--owner", "nobody")
	if err == nil || !strings.Contains(err.Error(), "nobody") {
		t.Errorf("an unknown owner: %v", err)
	}
}

// There is no way to export a signing key in clear: no flag, no confirmation
// word. A password is the only way out, and it is required.
//
// spec: SPO-Xcustody-INV-001, SPO-Xcustody-IF-001
func TestExportNeedsAPasswordAndHasNoPlaintextOption(t *testing.T) {
	f := newWsFix(t)
	f.wallet(f.ws, "w", f.seed)
	target := filepath.Join(t.TempDir(), "out")
	f.audit.dest = target
	err := f.run(&scriptTerm{t: t}, "workspace", "export", target)
	if err == nil || !strings.Contains(err.Error(), "password-fd") {
		t.Fatalf("%v", err)
	}
	for _, flag := range []string{"--plaintext", "--yes"} {
		if err := f.run(&scriptTerm{t: t}, "workspace", "export", target, flag, "--password-fd", "9"); err == nil || !strings.Contains(err.Error(), "unknown flag") {
			t.Errorf("%s: %v", flag, err)
		}
	}
	if _, serr := os.Stat(target); serr == nil || len(f.audit.events) != 0 {
		t.Errorf("a refused export created %s or recorded %v", target, f.audit.events)
	}
	// --password-fd without gpg: the need is named, nothing is written.
	err = f.run(&scriptTerm{t: t}, "workspace", "export", target, "--password-fd", itoaFD(pipeFD(t, "Str0ng-Password!-And-Long\n")))
	if err == nil || !strings.Contains(err.Error(), "key-encryption") {
		t.Errorf("no gpg: %v", err)
	}
	if _, serr := os.Stat(target); serr == nil {
		t.Error("an export without gpg created the directory")
	}
}

// The export records first, writes the signing key encrypted and nothing
// secret in clear, and does not print key material.
//
// spec: SPO-Xcustody-INV-001, SPO-Xcustody-OUT-003, SPO-Pfiles-SEC-001
func TestExportRecordsFirstAndWritesTheKeyEncryptedOnly(t *testing.T) {
	f := newWsFix(t)
	f.gpg = true
	f.wallet(f.ws, "w", f.seed)
	os.WriteFile(filepath.Join(f.ws, "w.payment.mnemonics"), []byte("abandon abandon"), 0o400)
	target := filepath.Join(t.TempDir(), "out")
	f.audit.dest = target
	pw := "Str0ng-Password!-And-Long"
	if err := f.run(&scriptTerm{t: t}, "workspace", "export", target, "--password-fd", itoaFD(pipeFD(t, pw+"\n")), "--reason", "moving to the upstream scripts"); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	if len(f.audit.events) != 1 || f.audit.seenFiles[0] != 0 {
		t.Errorf("events %v, files present at the record: %v", f.audit.events, f.audit.seenFiles)
	}
	ev := f.audit.events[0]
	if ev.Operation != "export-workspace" || ev.PlaintextKeys != 0 || ev.Acknowledged || !ev.Protected || ev.ProtectedKeys != 1 {
		t.Errorf("event %+v", ev)
	}
	if f.audit.reason != "moving to the upstream scripts" {
		t.Errorf("reason %q", f.audit.reason)
	}
	got, err := os.ReadFile(filepath.Join(target, "w.skey"))
	if err != nil || !strings.Contains(string(got), "encrHex") || strings.Contains(string(got), hex.EncodeToString(f.seed)) {
		t.Errorf("the exported key is not in the encrypted form: %v\n%s", err, got)
	}
	if _, err := os.Stat(filepath.Join(target, "w.payment.mnemonics")); err == nil {
		t.Error("a mnemonic file was written")
	}
	out := f.out.String()
	mustContain(t, out, "w.addr.skey", "encrypted", "1 owner(s) of 1 exported")
	if strings.Contains(out, hex.EncodeToString(f.seed)) || strings.Contains(out, "cborHex") || strings.Contains(out, "PLAINTEXT") {
		t.Errorf("the report shows the key or a plaintext claim:\n%s", out)
	}
	if err := f.run(&scriptTerm{t: t}, "workspace", "export", target, "--password-fd", itoaFD(pipeFD(t, pw+"\n"))); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Errorf("a non-empty directory: %v", err)
	}
}

// The export password must be at least 20 characters besides upstream's rule:
// a password that passes upstream's strength rule alone is refused, and the
// refusal names --generate-password.
//
// spec: SPO-Xcustody-PRE-003
func TestExportRefusesAShortPassword(t *testing.T) {
	f := newWsFix(t)
	f.gpg = true
	f.wallet(f.ws, "w", f.seed)
	target := filepath.Join(t.TempDir(), "out")
	f.audit.dest = target
	err := f.run(&scriptTerm{t: t}, "workspace", "export", target, "--password-fd", itoaFD(pipeFD(t, "Password1!\n")))
	if err == nil || !strings.Contains(err.Error(), "20 characters") || !strings.Contains(err.Error(), "--generate-password") {
		t.Fatalf("%v", err)
	}
	if _, serr := os.Stat(filepath.Join(target, "w.skey")); serr == nil || len(f.audit.events) != 0 {
		t.Errorf("a refused export wrote a key or recorded %v", f.audit.events)
	}
}

// --generate-password draws a 160-bit password that meets both rules, uses it,
// and delivers it once: on a descriptor with --password-out-fd, or on a
// terminal. A pipe with no descriptor is refused before anything happens, and
// --password-fd is exclusive with it.
//
// spec: SPO-Xcustody-IF-003
func TestExportGeneratePassword(t *testing.T) {
	f := newWsFix(t)
	f.gpg = true
	f.wallet(f.ws, "w", f.seed)
	base := t.TempDir()
	// Refusals first: nothing is written or recorded.
	for name, args := range map[string][]string{
		"both":              {"--generate-password", "--password-fd", "9"},
		"out-fd alone":      {"--password-out-fd", "9", "--password-fd", "9"},
		"a pipe, no out fd": {"--generate-password"},
		"neither":           {},
	} {
		if err := f.run(&scriptTerm{t: t}, append([]string{"workspace", "export", filepath.Join(base, "r"), "--reason", "x"}, args...)...); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, serr := os.Stat(filepath.Join(base, "r")); serr == nil || len(f.audit.events) != 0 {
		t.Errorf("a refusal created the directory or recorded %v", f.audit.events)
	}
	// To a descriptor.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	target := filepath.Join(base, "out")
	f.audit.dest = target
	if err := f.run(&scriptTerm{t: t}, "workspace", "export", target, "--generate-password", "--password-out-fd", itoaFD(int(w.Fd()))); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	w.Close()
	raw, _ := io.ReadAll(r)
	pw := strings.TrimSuffix(string(raw), "\n")
	if len(pw) < 20 || !keyfile.IsStrongPassword([]byte(pw)) || !keyfile.IsLongExportPassword([]byte(pw)) || strings.ContainsAny(pw, "\\ \n") {
		t.Fatalf("the generated password %d characters does not meet the rules", len(pw))
	}
	if strings.Contains(f.out.String(), pw) {
		t.Error("the password was printed although a descriptor was given")
	}
	mustContain(t, f.out.String(), "not memory-hard", "transport form")
	got, err := os.ReadFile(filepath.Join(target, "w.skey"))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := keyfile.ParseEncrypted(got)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (fakeCrypt{}).Decrypt(context.Background(), enc.EncrHex, secret.Take([]byte(pw))); err != nil {
		t.Errorf("the key was not encrypted with the generated password: %v", err)
	}
	// On a terminal: shown once in the output.
	defer func(o func(io.Writer) bool) { stdoutIsTerminal = o }(stdoutIsTerminal)
	stdoutIsTerminal = func(io.Writer) bool { return true }
	target2 := filepath.Join(base, "out2")
	f.audit.dest = target2
	if err := f.run(&scriptTerm{t: t}, "workspace", "export", target2, "--generate-password"); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	shown := regexp.MustCompile(`(?m)^  (\S+)$`).FindStringSubmatch(f.out.String())
	if shown == nil || !keyfile.IsLongExportPassword([]byte(shown[1])) || shown[1] == pw {
		t.Errorf("no fresh password on the terminal:\n%s", f.out.String())
	}
}

// A record that cannot be made stops the export before a key is written.
func TestExportStopsWhenTheAuditRecordFails(t *testing.T) {
	f := newWsFix(t)
	f.gpg = true
	f.wallet(f.ws, "w", f.seed)
	target := filepath.Join(t.TempDir(), "out")
	f.audit.dest = target
	f.audit.fail = errors.New("disk full")
	err := f.run(&scriptTerm{t: t}, "workspace", "export", target, "--password-fd", itoaFD(pipeFD(t, "Str0ng-Password!-And-Long\n")))
	if err == nil {
		t.Fatal("exported without a record")
	}
	if _, serr := os.Stat(filepath.Join(target, "w.skey")); serr == nil {
		t.Error("a key was written although the record failed")
	}
	if _, serr := os.Stat(target); serr == nil {
		t.Error("the empty directory was left behind")
	}
}

// key protect and key unprotect no longer exist: a signing key in the sealed
// workspace is protected already, and none is ever written in clear.
//
// spec: SPO-Xcustody-INV-001
func TestKeyHasOnlyConvert(t *testing.T) {
	f := newWsFix(t)
	key, _, err := NewRoot(f.deps).Find([]string{"key"})
	if err != nil || key.Name() != "key" {
		t.Fatalf("%v", err)
	}
	var names []string
	for _, c := range key.Commands() {
		names = append(names, c.Name())
	}
	if len(names) != 1 || names[0] != "convert" {
		t.Errorf("key subcommands: %v", names)
	}
}

// key convert turns a kept encrypted key into a sealed one, asks for nothing
// on a terminal when the password comes on a descriptor, and never prints the
// key. A wrong password changes nothing.
//
// spec: SPO-Xcustody-IF-002, SPO-Xcustody-PR-001, SPO-Xcustody-OUT-001, SPO-Xcustody-OUT-002
func TestKeyConvertMakesASealedKey(t *testing.T) {
	f := newWsFix(t)
	f.gpg = true
	os.WriteFile(filepath.Join(f.ws, "w.vkey"), []byte(vkeyText(f.seed)), 0o600)
	pw := "Str0ng-Password!-And-Long"
	cbor := "5820" + hex.EncodeToString(f.seed)
	encr, err := fakeCrypt{}.Encrypt(context.Background(), secret.Take([]byte(cbor)), secret.Take([]byte(pw)))
	if err != nil {
		t.Fatal(err)
	}
	kept := filepath.Join(f.ws, "w.upstream-encrypted.skey")
	os.WriteFile(kept, keyfile.EncryptedEnvelope("PaymentSigningKeyShelley_ed25519", "Payment Signing Key", encr), 0o400)
	if err := f.run(&scriptTerm{t: t}, "key", "convert", "w", "--password-fd", itoaFD(pipeFD(t, "Wrong-Password1!\n"))); err == nil {
		t.Fatal("a wrong password converted the key")
	}
	if _, err := os.Stat(kept); err != nil {
		t.Fatal("the kept record went although the password was wrong")
	}
	if err := f.run(&scriptTerm{t: t}, "key", "convert", "w.skey", "--password-fd", itoaFD(pipeFD(t, pw+"\n"))); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	if _, err := os.Stat(kept); err == nil {
		t.Error("the kept record is still there")
	}
	got, err := os.ReadFile(filepath.Join(f.ws, "w.skey"))
	if err != nil || !strings.Contains(string(got), cbor) {
		t.Errorf("the sealed key: %v\n%s", err, got)
	}
	if out := f.out.String(); strings.Contains(out, cbor) || strings.Contains(out, hex.EncodeToString(f.seed)) {
		t.Errorf("the output shows the key:\n%s", out)
	}
}
