package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/fsstore"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// fsSealed stands in for the sealed workspace: an upstream-layout directory
// behind the SealedStore interface. Only what the workspace commands use is
// implemented; the rest of the interface is the nil embedded one.
type fsSealed struct {
	SealedStore
	st *fsstore.Store
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
	ws, err := fsstore.Open(f.ws)
	if err != nil {
		t.Fatal(err)
	}
	f.sealed = &fsSealed{st: ws}
	f.deps = Deps{
		Out: &f.out, Err: &f.out,
		Config:       memConfig(map[string]WorkspaceConfig{f.ws: {Network: "preview", Mode: ModeOffline}}),
		Sealed:       SealedOps{Open: func(string, *secret.Buffer, OpenOptions) (SealedStore, error) { return f.sealed, nil }},
		OpenUpstream: func(dir string) (ports.Store, error) { return fsstore.Open(dir) },
		OpenUpstreamSource: func(dir string) (UpstreamSource, error) {
			s, err := fsstore.Open(dir)
			if err != nil {
				return nil, err
			}
			return roSource{s}, nil
		},
		WorkspaceAuditor: func(_ string, _ ports.Store, reason string) ports.WorkspaceAuditor {
			f.audit.reason = reason
			return f.audit
		},
		RefOfFile: fsstore.RefOf,
		Wire: func(st ports.Store, o WireOptions) (*Env, error) {
			led := native.Ledger{}
			return &Env{Mode: o.Mode, NetworkID: ports.NetworkTestnet, AddressInspector: led, VKeyDeriver: native.VKeyDeriver{}}, nil
		},
	}
	return f
}

type roSource struct{ *fsstore.Store }

func (roSource) Update(context.Context, func(ports.Writer) error) error {
	return errors.New("read-only")
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
	// A plain-layout directory cannot be an import target.
	err = f.run(&scriptTerm{t: t}, "--upstream-layout", "workspace", "import", f.src)
	if err == nil {
		t.Error("import with --upstream-layout")
	}
	err = f.run(&scriptTerm{t: t}, "workspace", "import", f.src, "--owner", "nobody")
	if err == nil || !strings.Contains(err.Error(), "nobody") {
		t.Errorf("an unknown owner: %v", err)
	}
}

func TestExportNeedsAProtectionChoice(t *testing.T) {
	f := newWsFix(t)
	f.wallet(f.ws, "w", f.seed)
	target := filepath.Join(t.TempDir(), "out")
	f.audit.dest = target
	err := f.run(&scriptTerm{t: t}, "workspace", "export", target)
	if err == nil || !strings.Contains(err.Error(), "--password-fd") || !strings.Contains(err.Error(), "--plaintext") {
		t.Fatalf("%v", err)
	}
	if err := f.run(&scriptTerm{t: t}, "workspace", "export", target, "--plaintext", "--password-fd", "9"); err == nil || !strings.Contains(err.Error(), "choose one") {
		t.Errorf("both choices: %v", err)
	}
	if _, serr := os.Stat(target); serr == nil || len(f.audit.events) != 0 {
		t.Errorf("a refused export created %s or recorded %v", target, f.audit.events)
	}
	// --password-fd without gpg: the need is named, nothing is written.
	err = f.run(&scriptTerm{t: t}, "workspace", "export", target, "--password-fd", itoaFD(pipeFD(t, "Str0ng-Password!\n")))
	if err == nil || !strings.Contains(err.Error(), "key-encryption") {
		t.Errorf("no gpg: %v", err)
	}
	if _, serr := os.Stat(target); serr == nil {
		t.Error("an export without gpg created the directory")
	}
}

func TestExportPlaintextRecordsFirstAndNeedsTheTypedWord(t *testing.T) {
	f := newWsFix(t)
	f.wallet(f.ws, "w", f.seed)
	target := filepath.Join(t.TempDir(), "out")
	f.audit.dest = target

	// Anything but the word declines; nothing is created or recorded.
	for _, answer := range []string{"", "y", "yes", "PLAINTEXT"} {
		err := f.run(&scriptTerm{t: t, lines: []string{answer}}, "workspace", "export", target, "--plaintext")
		if err == nil || !strings.Contains(err.Error(), "declined") {
			t.Fatalf("answer %q: %v", answer, err)
		}
	}
	if err := f.run(&scriptTerm{t: t}, "workspace", "export", target, "--plaintext"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Errorf("no terminal: %v", err)
	}
	if _, serr := os.Stat(target); serr == nil || len(f.audit.events) != 0 {
		t.Fatalf("a declined export created %s or recorded %v", target, f.audit.events)
	}

	term := &scriptTerm{t: t, lines: []string{"plaintext"}}
	if err := f.run(term, "workspace", "export", target, "--plaintext", "--reason", "moving to the upstream scripts"); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	if term.asked != 1 {
		t.Errorf("asked %d times", term.asked)
	}
	// The audit record came before anything was written, and carries the reason.
	if len(f.audit.events) != 1 || f.audit.seenFiles[0] != 0 {
		t.Errorf("events %v, files present at the record: %v", f.audit.events, f.audit.seenFiles)
	}
	ev := f.audit.events[0]
	if ev.Operation != "export-workspace" || ev.PlaintextKeys != 1 || !ev.Acknowledged || ev.Protected {
		t.Errorf("event %+v", ev)
	}
	if f.audit.reason != "moving to the upstream scripts" {
		t.Errorf("reason %q", f.audit.reason)
	}
	got, err := os.ReadFile(filepath.Join(target, "w.skey"))
	if err != nil || string(got) != skeyText(f.seed) {
		t.Errorf("the exported key: %v", err)
	}
	out := f.out.String()
	mustContain(t, out, "w.addr.skey", "PLAINTEXT", "in CLEAR", "1 owner(s) of 1 exported")
	if strings.Contains(out, hex.EncodeToString(f.seed)) || strings.Contains(out, "cborHex") {
		t.Errorf("the report shows the key:\n%s", out)
	}

	// --yes types the word; the directory is no longer empty, so --overwrite.
	if err := f.run(&scriptTerm{t: t}, "workspace", "export", target, "--plaintext", "--yes"); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Errorf("a non-empty directory: %v", err)
	}
	f.audit.events, f.audit.seenFiles = nil, nil
	if err := f.run(&scriptTerm{t: t}, "workspace", "export", target, "--plaintext", "--yes", "--overwrite"); err != nil || len(f.audit.events) != 1 {
		t.Errorf("--overwrite --yes: %v %v", err, f.audit.events)
	}
}

// A record that cannot be made stops the export before a key is written.
func TestExportStopsWhenTheAuditRecordFails(t *testing.T) {
	f := newWsFix(t)
	f.wallet(f.ws, "w", f.seed)
	target := filepath.Join(t.TempDir(), "out")
	f.audit.dest = target
	f.audit.fail = errors.New("disk full")
	err := f.run(&scriptTerm{t: t}, "workspace", "export", target, "--plaintext", "--yes")
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

func TestKeyProtectOnTheSealedWorkspaceGivesTheUseCasesExplanation(t *testing.T) {
	f := newWsFix(t)
	for _, c := range []string{"protect", "unprotect"} {
		err := f.run(&scriptTerm{t: t}, "key", c, "w.skey")
		if err == nil || !strings.Contains(err.Error(), "sealed store are always protected") || !strings.Contains(err.Error(), "--upstream-layout") {
			t.Errorf("%s: %v", c, err)
		}
	}
}
