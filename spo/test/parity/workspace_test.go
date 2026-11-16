package parity

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/fsstore"
	"github.com/mochipool/workbench/spo/internal/adapters/gpg"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/poolops"
	"github.com/mochipool/workbench/spo/internal/app/workspace"
	"github.com/mochipool/workbench/spo/internal/domain/keyfile"
	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// wsTTY runs one upstream script on a pseudo terminal made by script(1) and
// types the given lines, one every 400 ms: the prompts of 01_protectKey and
// of every signing script read the terminal (`read -s`, `read < tty`), so a
// pipe does not reach them. Output is discarded, as everywhere: these scripts
// print plaintext keys. A run that outlasts timeout is killed and reported as
// timed out.
func (e env) wsTTY(t *testing.T, timeout time.Duration, dir string, lines []string, args ...string) (code int, timedOut bool) {
	t.Helper()
	sc, err := exec.LookPath("script")
	if err != nil {
		t.Skip("script(1) is needed to type into the prompts of the upstream scripts")
	}
	words := append([]string{e.workbench, "-C", dir, "exec"}, args...)
	for i, w := range words {
		words[i] = "'" + strings.ReplaceAll(w, "'", `'\''`) + "'"
	}
	cmd := exec.Command(sc, "-qefc", strings.Join(words, " "), "/dev/null")
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "LC_ALL=C", "ENV_DECRYPT_PASSWORD=")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(900 * time.Millisecond)
		for _, l := range lines {
			select {
			case <-stop:
				return
			case <-time.After(400 * time.Millisecond):
			}
			if _, err := io.WriteString(in, l+"\n"); err != nil {
				return
			}
		}
	}()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var werr error
	select {
	case werr = <-done:
	case <-time.After(timeout):
		timedOut = true
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		werr = <-done
	}
	close(stop)
	wg.Wait()
	in.Close()
	var ee *exec.ExitError
	if errors.As(werr, &ee) {
		return ee.ExitCode(), timedOut
	}
	if werr != nil {
		t.Fatalf("script: %v", werr)
	}
	return 0, timedOut
}

func (e env) wsGPG() gpg.GPG { return gpg.GPG{Tools: e.tc, Runner: execx.OS{}} }

func wsSec(s string) *ports.Secret { return secret.Take([]byte(s)) }

// wsDeriver derives ed25519 verification keys from 32-byte seed signing keys;
// the consistency check of an import needs a ports.VerificationKeyDeriver,
// which native does not implement yet.
type wsDeriver struct{}

func (wsDeriver) DeriveVerificationKey(_ context.Context, env *ports.Secret) ([]byte, error) {
	var out []byte
	err := env.Use(func(d []byte) error {
		span, err := keyfile.CborHexSpan(d)
		if err != nil {
			return err
		}
		raw, err := hex.DecodeString(string(span))
		if err != nil || len(raw) != 34 || raw[0] != 0x58 || raw[1] != 0x20 {
			return ports.ErrKeyTypeUnsupported
		}
		out = []byte(ed25519.NewKeyFromSeed(raw[2:]).Public().(ed25519.PublicKey))
		return nil
	})
	return out, err
}

// wsRecorder wraps a store and records which kinds were written with Put and
// which with PutSecret.
type wsRecorder struct {
	ports.Store
	mu      sync.Mutex
	puts    []ports.Ref
	secrets []ports.Ref
}

type wsWriter struct {
	ports.Writer
	r *wsRecorder
}

func (w wsWriter) Put(ref ports.Ref, d []byte) error {
	w.r.mu.Lock()
	w.r.puts = append(w.r.puts, ref)
	w.r.mu.Unlock()
	return w.Writer.Put(ref, d)
}

func (w wsWriter) PutSecret(ref ports.Ref, s *secret.Buffer) error {
	w.r.mu.Lock()
	w.r.secrets = append(w.r.secrets, ref)
	w.r.mu.Unlock()
	return w.Writer.PutSecret(ref, s)
}

func (r *wsRecorder) Update(ctx context.Context, fn func(ports.Writer) error) error {
	return r.Store.Update(ctx, func(w ports.Writer) error { return fn(wsWriter{w, r}) })
}

type wsAudit struct{ events []ports.AuditEvent }

func (a *wsAudit) Record(_ context.Context, e ports.AuditEvent) error {
	a.events = append(a.events, e)
	return nil
}

func wsPlainCbor(t *testing.T, b []byte) string {
	t.Helper()
	span, err := keyfile.CborHexSpan(b)
	if err != nil {
		t.Fatalf("not a plain signing key: %v", err)
	}
	return string(span)
}

// Key encryption interoperates with upstream's own 01_protectKey, both ways,
// with the pinned gpg and the pinned scripts, including passwords that
// upstream's `read` without -r mangles and one with a trailing space. It pins
// the mangling rule: upstream encrypts with the password after the backslash
// is consumed, never with the keystrokes.
//
// spec: SPO-Ckey-EXT-001, SPO-Ckey-EXT-002, SPO-Ckey-OUT-001, SPO-Ckey-OUT-002, SPO-Ckey-INV-003, SPO-Ckey-INV-001, SPO-Ckey-SEC-001
// spec: SPO-Cui-IF-003, SPO-Cui-SEC-001, SPO-01protectKey-OUT-001, SPO-01protectKey-OUT-002, SPO-01protectKey-PR-001, SPO-01protectKey-PR-002, SPO-01protectKey-PR-004, SPO-01protectKey-PR-005, SPO-01protectKey-PR-006
// spec: SPO-01protectKey-EXT-001, SPO-01protectKey-EXT-002, SPO-01protectKey-PRE-003, SPO-01protectKey-PRE-004
func TestKeyProtectionInteroperatesWithUpstreamGpg(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	g := e.wsGPG()
	cases := []struct{ name, typed, stored string }{
		{"backslash", `Abc\def-12345`, "Abcdef-12345"},
		{"trailing-space", "Trail space-1A ", "Trail space-1A "},
		{"plain", "Plain-Passw0rd!", "Plain-Passw0rd!"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := e.upstreamWorkspace(t)
			store, _ := fsstore.Open(dir)

			// Upstream encrypts; Go decrypts to the identical cborHex.
			up := "up" + c.name
			if code := e.upstream(t, dir, "exec", "02_genPaymentAddrOnly.sh", up, "cli"); code != 0 {
				t.Fatalf("02 exited %d", code)
			}
			orig := readFile(t, dir, up+".skey")
			cbor := wsPlainCbor(t, []byte(orig))
			if code, to := e.wsTTY(t, 60*time.Second, dir, []string{"y", c.typed, c.typed, "n", "y"}, "01_protectKey.sh", "enc", up+".skey"); code != 0 || to {
				t.Fatalf("upstream 01_protectKey enc exited %d (timed out: %v)", code, to)
			}
			encFile := readFile(t, dir, up+".skey")
			info, err := keyfile.Classify([]byte(encFile))
			if err != nil || info.Form != keyfile.FormEncrypted {
				t.Fatalf("upstream's output is not an encrypted envelope: %v %v", info.Form, err)
			}
			if mode(t, dir, up+".skey") != 0o400 {
				t.Errorf("mode %v, want 0400 (SPO-01protectKey-OUT-001)", mode(t, dir, up+".skey"))
			}
			enc, err := keyfile.ParseEncrypted([]byte(encFile))
			if err != nil {
				t.Fatal(err)
			}
			// the envelope is rendered exactly as upstream's jq prints it
			if string(keyfile.EncryptedEnvelope(enc.Type, keyfile.PlainDescription(enc.Description), enc.EncrHex)) != encFile {
				t.Errorf("the envelope format differs from upstream's:\n%s", encFile)
			}
			// the mangling rule, against the real script: the stored form opens it
			plain, err := g.Decrypt(ctx, enc.EncrHex, wsSec(c.stored))
			if err != nil {
				t.Fatalf("decrypting with the password as upstream stored it: %v", err)
			}
			plain.Use(func(b []byte) error {
				if string(b) != cbor {
					t.Error("decrypted cborHex differs from the original")
				}
				return nil
			})
			if c.typed != c.stored {
				if _, err := g.Decrypt(ctx, enc.EncrHex, wsSec(c.typed)); !errors.Is(err, ports.ErrWrongPassphrase) {
					t.Errorf("the keystrokes with a backslash opened upstream's key (%v): upstream's rule is not as pinned", err)
				}
			}
			// the use case opens it from the keystrokes, by candidates
			un := workspace.UnprotectKey{Store: store, Vault: store, Decryptor: g, Auditor: &wsAudit{}}
			if err := un.Run(ctx, ports.Ref{Name: up, Kind: ports.AddrSKey}, wsSec(c.typed), true); err != nil {
				t.Fatalf("UnprotectKey: %v", err)
			}
			if wsPlainCbor(t, []byte(readFile(t, dir, up+".skey"))) != cbor {
				t.Error("UnprotectKey wrote a different key")
			}

			// Go encrypts; upstream decrypts.
			goKey := "go" + c.name
			if code := e.upstream(t, dir, "exec", "02_genPaymentAddrOnly.sh", goKey, "cli"); code != 0 {
				t.Fatalf("02 exited %d", code)
			}
			orig2 := readFile(t, dir, goKey+".skey")
			prot := workspace.ProtectKey{Store: store, Vault: store, Encryptor: g, Decryptor: g}
			if err := prot.Run(ctx, ports.Ref{Name: goKey, Kind: ports.AddrSKey}, wsSec(c.typed)); err != nil {
				t.Fatalf("ProtectKey: %v", err)
			}
			if mode(t, dir, goKey+".skey") != 0o400 {
				t.Errorf("ProtectKey left mode %v", mode(t, dir, goKey+".skey"))
			}
			// upstream's `enc` refuses a file that is already encrypted, and reads ours
			if code, _ := e.wsTTY(t, 60*time.Second, dir, []string{"y"}, "01_protectKey.sh", "enc", goKey+".skey"); code == 0 {
				t.Error("upstream 01_protectKey enc accepted a file the port had encrypted")
			}
			if code, to := e.wsTTY(t, 60*time.Second, dir, []string{"y", c.typed, "y"}, "01_protectKey.sh", "dec", goKey+".skey"); code != 0 || to {
				t.Fatalf("upstream 01_protectKey dec of the port's envelope exited %d (timed out: %v)", code, to)
			}
			after := readFile(t, dir, goKey+".skey")
			if wsPlainCbor(t, []byte(after)) != wsPlainCbor(t, []byte(orig2)) {
				t.Error("upstream decrypted the port's envelope to a different key")
			}
			// upstream's dec writes the jq formatting: two-space indent
			p, n, _ := keyfile.ParsePlain([]byte(after))
			want := keyfile.AppendPlainEnvelope(nil, p.Type, p.Description, []byte(wsPlainCbor(t, []byte(after))), n, "  ")
			if string(want) != after {
				t.Errorf("upstream's decrypted file is not in the jq format the port writes:\n%s", after)
			}
			// a wrong password: upstream dec exits 1 without retry
			if err := prot.Run(ctx, ports.Ref{Name: goKey, Kind: ports.AddrSKey}, wsSec(c.typed)); err != nil {
				t.Fatal(err)
			}
			if code, to := e.wsTTY(t, 60*time.Second, dir, []string{"y", "Wrong-Passw0rd!x"}, "01_protectKey.sh", "dec", goKey+".skey"); code != 1 || to {
				t.Errorf("upstream dec with a wrong password exited %d (timed out: %v), want 1", code, to)
			}
		})
	}
}

// listFiles returns the regular files of a directory with their modes.
func wsFiles(t *testing.T, dir string) map[string]os.FileMode {
	t.Helper()
	out := map[string]os.FileMode{}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range ents {
		if en.Type().IsRegular() {
			info, _ := en.Info()
			out[en.Name()] = info.Mode().Perm()
		}
	}
	return out
}

// A realistic workspace made by the real scripts (04a, 04b, 04c, 04d offline,
// 02, 03a, and one key encrypted by 01_protectKey) is imported into a second
// store: every artefact is there, counters are equal, secrets went through
// PutSecret, and the imported store works with the existing use cases. The
// export of the import is the original directory, byte for byte.
//
// spec: SPO-Pfiles-OUT-001, SPO-Pfiles-OUT-002, SPO-Pfiles-OUT-003, SPO-Pfiles-OUT-010, SPO-Pfiles-OUT-011, SPO-Pfiles-OUT-012, SPO-Pfiles-OUT-013, SPO-Pfiles-OUT-014, SPO-Pfiles-OUT-015
// spec: SPO-Pfiles-INV-003, SPO-Pfiles-SEC-001, SPO-Pfiles-SEC-002, SPO-Pfiles-IN-003, SPO-Ckey-EXT-002, SPO-Ckey-OUT-002, SPO-Cui-IF-003, SPO-Ckey-IN-001
func TestImportRealWorkspaceAndRoundTrip(t *testing.T) {
	e := setup(t)
	genesis := previewGenesis(t)
	ctx := context.Background()
	dir := e.upstreamWorkspace(t)
	for _, a := range [][]string{
		{"04a_genNodeKeys.sh", "mypool", "cli"}, {"04b_genVRFKeys.sh", "mypool", "cli"}, {"04c_genKESKeys.sh", "mypool", "cli"},
		{"04d_genNodeOpCert.sh", "mypool"}, {"02_genPaymentAddrOnly.sh", "pay", "cli"}, {"03a_genStakingPaymentAddr.sh", "w", "cli"},
	} {
		if code := e.upstream(t, dir, append([]string{"exec"}, a...)...); code != 0 {
			t.Fatalf("upstream %s exited %d", a[0], code)
		}
	}
	// one key encrypted by upstream, with a backslash in its password
	const typed = `Abc\def-12345`
	plainNode := readFile(t, dir, "mypool.node.skey")
	if code, to := e.wsTTY(t, 60*time.Second, dir, []string{"y", typed, typed, "n", "y"}, "01_protectKey.sh", "enc", "mypool.node.skey"); code != 0 || to {
		t.Fatalf("upstream 01_protectKey enc exited %d (timed out: %v)", code, to)
	}
	if info, _ := keyfile.Classify([]byte(readFile(t, dir, "mypool.node.skey"))); info.Form != keyfile.FormEncrypted {
		t.Fatal("the cold key is not encrypted")
	}
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("an operator's note\n"), 0o644)
	srcBefore := wsFiles(t, dir)

	src, err := fsstore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	dstDir := t.TempDir()
	dstFS, _ := fsstore.Open(dstDir)
	dst := &wsRecorder{Store: dstFS}
	led := native.Ledger{}
	imp := workspace.ImportWorkspace{Source: src, SourceVault: src, Lister: src, Dest: dst, Decryptor: e.wsGPG(), Deriver: wsDeriver{}, Addresses: led}

	// no password: the pool with the encrypted key is refused, the wallets are imported
	rep, err := imp.Run(ctx, workspace.ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Failed() != 1 {
		t.Fatalf("without a password exactly the pool must fail: %+v", rep)
	}
	for f := range wsFiles(t, dstDir) {
		if strings.HasPrefix(f, "mypool.") {
			t.Errorf("%s imported from a failed owner", f)
		}
	}
	// with the keystrokes of the password: everything
	dstDir = t.TempDir()
	dstFS, _ = fsstore.Open(dstDir)
	dst = &wsRecorder{Store: dstFS}
	imp.Dest = dst
	pw := wsSec(typed)
	rep, err = imp.Run(ctx, workspace.ImportOptions{Password: pw})
	if err != nil || rep.Failed() != 0 {
		t.Fatalf("%v %+v", err, rep)
	}
	// the workbench's own files and the operator's note are reported, never imported
	unknown := map[string]bool{}
	for _, u := range rep.Unknown {
		unknown[u.File] = true
	}
	for _, f := range []string{"notes.txt", "common.inc", "workbench.toml"} {
		if !unknown[f] {
			t.Errorf("%s is not reported as unknown: %+v", f, rep.Unknown)
		}
	}
	// the source is untouched
	for f, m := range wsFiles(t, dir) {
		if srcBefore[f] != m {
			t.Errorf("source file %s changed mode", f)
		}
	}
	if len(wsFiles(t, dir)) != len(srcBefore) {
		t.Error("the source directory changed")
	}

	// every artefact is present with the same content; counters are equal
	dstFiles := wsFiles(t, dstDir)
	var names []string
	for f := range srcBefore {
		if _, ok := fsstore.RefOf(f); ok {
			names = append(names, f)
		}
	}
	sort.Strings(names)
	for _, f := range names {
		if _, ok := dstFiles[f]; !ok {
			t.Errorf("%s was not imported", f)
		}
	}
	if len(dstFiles) != len(names) {
		t.Errorf("imported %d files, source has %d artefacts", len(dstFiles), len(names))
	}
	for _, f := range []string{"mypool.node.counter", "mypool.kes.counter", "mypool.kes.counter-next", "mypool.node-000.opcert"} {
		if readFile(t, dir, f) != readFile(t, dstDir, f) {
			t.Errorf("%s differs after import", f)
		}
	}
	// every secret went through PutSecret, nothing secret through Put
	for _, r := range dst.puts {
		if r.Kind.Secret() {
			t.Errorf("%v was written with Put", r)
		}
	}
	nsec := 0
	for _, f := range names {
		if r, ok := fsstore.RefOf(f); ok && r.Kind.Secret() {
			nsec++
		}
	}
	if len(dst.secrets) != nsec || nsec < 6 {
		t.Errorf("%d secret writes for %d secret artefacts", len(dst.secrets), nsec)
	}
	// the decrypted cold key is the original plain file
	if got := readFile(t, dstDir, "mypool.node.skey"); got != plainNode {
		t.Errorf("imported cold key differs from the key before encryption:\n%q\n%q", got, plainNode)
	}

	// round trip: export to a fresh directory in plaintext, compare byte for byte
	outDir := t.TempDir()
	outFS, _ := fsstore.Open(outDir)
	exp := workspace.ExportWorkspace{Source: dstFS, SourceVault: dstFS, Lister: dstFS, Dest: outFS, Auditor: &wsAudit{}}
	erep, err := exp.Run(ctx, workspace.ExportOptions{PlaintextAcknowledged: true})
	if err != nil || erep.Failed() != 0 {
		t.Fatalf("%v %+v", err, erep)
	}
	outFiles := wsFiles(t, outDir)
	if len(outFiles) != len(names) {
		t.Errorf("exported %d files, want %d", len(outFiles), len(names))
	}
	for _, f := range names {
		if outFiles[f] != srcBefore[f] {
			t.Errorf("%s: mode %v, original %v", f, outFiles[f], srcBefore[f])
		}
		want := readFile(t, dir, f)
		if f == "mypool.node.skey" {
			want = plainNode // the original was encrypted; its plain form is the comparison
		}
		if got := readFile(t, outDir, f); got != want {
			t.Errorf("%s differs after the round trip", f)
		}
	}

	// the imported store works: GenerateKesKey, then IssueOperationalCertificate offline
	gen := poolops.GenerateKesKey{Store: dstFS, KeyGen: native.KeyGen{}}
	if r, err := gen.Run(ctx, "mypool"); err != nil || r.Number != 1 {
		t.Fatalf("GenerateKesKey on the imported store: %+v %v", r, err)
	}
	if _, err := issueUseCase(t, dstDir, genesis).Run(ctx, "mypool", poolops.IssueOptions{}); err != nil {
		t.Fatalf("IssueOperationalCertificate on the imported store: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dstDir, "mypool.node-001.opcert")); err != nil {
		t.Error("no opcert was issued on the imported store")
	}
}

// H8: an encrypted envelope that is damaged is refused at once by the port,
// without starting gpg. Upstream asks for the password again and again
// (SPO-Ckey-PRE-010); the test types a few wrong passwords and records that
// it does not give up.
//
// spec: SPO-Ckey-PRE-003, SPO-Ckey-PRE-006, SPO-Ckey-PRE-010, SPO-Ckey-PR-003, SPO-Ckey-PR-001
func TestMalformedEncryptedKeyFailsFastWhereUpstreamLoops(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	dir := e.upstreamWorkspace(t)
	for _, a := range [][]string{{"04a_genNodeKeys.sh", "mypool", "cli"}, {"04c_genKESKeys.sh", "mypool", "cli"}} {
		if code := e.upstream(t, dir, append([]string{"exec"}, a...)...); code != 0 {
			t.Fatalf("upstream %s exited %d", a[0], code)
		}
	}
	bad := []byte(`{"type":"StakePoolSigningKey_ed25519","description":"Encrypted Stake Pool Operator Signing Key","encrHex":"not-hex-at-all"}`)
	os.Chmod(filepath.Join(dir, "mypool.node.skey"), 0o600)
	if err := os.WriteFile(filepath.Join(dir, "mypool.node.skey"), bad, 0o400); err != nil {
		t.Fatal(err)
	}

	// the port: no gpg process, a typed error in the report
	src, _ := fsstore.Open(dir)
	dstDir := t.TempDir()
	dst, _ := fsstore.Open(dstDir)
	spawned := 0
	g := gpg.GPG{Tools: e.tc, Runner: execx.OS{Observe: func(execx.Spawn) { spawned++ }}}
	imp := workspace.ImportWorkspace{Source: src, SourceVault: src, Lister: src, Dest: dst, Decryptor: g}
	rep, err := imp.Run(ctx, workspace.ImportOptions{Owners: []string{"mypool"}, Password: wsSec("Str0ng-Passw0rd!")})
	if err != nil || rep.Failed() != 1 {
		t.Fatalf("%v %+v", err, rep)
	}
	if spawned != 0 {
		t.Errorf("gpg was started %d times for a damaged envelope", spawned)
	}
	if n := len(wsFiles(t, dstDir)); n != 0 {
		t.Errorf("%d files imported from a failed owner", n)
	}
	damaged := false
	for _, a := range rep.Owners[0].Artefacts {
		if a.Status == workspace.StatusFailed && strings.Contains(a.Reason, "damaged") {
			damaged = true
		}
	}
	if !damaged {
		t.Errorf("the report does not say the file is damaged: %+v", rep.Owners[0].Artefacts)
	}

	// upstream (04d reads the cold key with read_skeyFILE): type wrong strong
	// passwords; it keeps asking. A timeout is the loop.
	pws := []string{"Wrong-Passw0rd!1", "Wrong-Passw0rd!2", "Wrong-Passw0rd!3", "Wrong-Passw0rd!4"}
	code, timedOut := e.wsTTY(t, 20*time.Second, dir, pws, "04d_genNodeOpCert.sh", "mypool")
	if timedOut {
		t.Log("upstream 04d did not exit after four wrong passwords: it loops on the prompt (SPO-Ckey-PRE-010), as the spec says")
	} else {
		t.Errorf("upstream 04d exited %d after a damaged encrypted key and wrong passwords; the spec says it asks again until an empty answer", code)
	}
}
