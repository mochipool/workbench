package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/fsstore"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// fakeSealed is a SealedStore over a plain directory, enough for commands
// that only use the store and the vault.
type fakeSealed struct {
	*fsstore.Store
	tokens map[string][]byte // the upstream file layout has no place for a provider token
}

// tokenWriter keeps provider tokens in memory and passes everything else on.
type tokenWriter struct {
	ports.Writer
	tokens map[string][]byte
}

func (w tokenWriter) PutSecret(r ports.Ref, s *secret.Buffer) error {
	if r.Kind != ports.ProviderToken {
		return w.Writer.PutSecret(r, s)
	}
	return s.Use(func(b []byte) error { w.tokens[r.Name] = append([]byte(nil), b...); return nil })
}

func (w tokenWriter) Delete(r ports.Ref) error {
	if r.Kind != ports.ProviderToken {
		return w.Writer.Delete(r)
	}
	delete(w.tokens, r.Name)
	return nil
}

func (w tokenWriter) Exists(r ports.Ref) (bool, error) {
	if r.Kind != ports.ProviderToken {
		return w.Writer.Exists(r)
	}
	_, ok := w.tokens[r.Name]
	return ok, nil
}

func (f fakeSealed) Update(ctx context.Context, fn func(ports.Writer) error) error {
	return f.Store.Update(ctx, func(w ports.Writer) error { return fn(tokenWriter{w, f.tokens}) })
}

type tokenReader struct {
	ports.Reader
	tokens map[string][]byte
}

func (r tokenReader) Exists(ref ports.Ref) (bool, error) {
	if ref.Kind != ports.ProviderToken {
		return r.Reader.Exists(ref)
	}
	_, ok := r.tokens[ref.Name]
	return ok, nil
}

func (f fakeSealed) View(ctx context.Context, fn func(ports.Reader) error) error {
	return f.Store.View(ctx, func(r ports.Reader) error { return fn(tokenReader{r, f.tokens}) })
}

func (f fakeSealed) Open(ctx context.Context, r ports.Ref) (*secret.Buffer, error) {
	if r.Kind != ports.ProviderToken {
		return f.Store.Open(ctx, r)
	}
	b, ok := f.tokens[r.Name]
	if !ok {
		return nil, ports.ErrNotFound
	}
	return secret.Take(append([]byte(nil), b...)), nil
}

func (fakeSealed) VerifyDetailed(context.Context) (VerifyReport, error) { return VerifyReport{}, nil }
func (fakeSealed) BackupWithHead(context.Context, string) (Head, error) { return Head{}, nil }
func (fakeSealed) Slots(context.Context) ([]Slot, error)                { return nil, nil }
func (fakeSealed) Notices() []string                                    { return nil }
func (fakeSealed) Head() Head                                           { return Head{} }
func (fakeSealed) Close() error                                         { return nil }
func (fakeSealed) ChangePassphraseRekey(context.Context, *secret.Buffer) (*secret.Buffer, error) {
	return nil, nil
}
func (fakeSealed) RekeyKeepPassphrase(context.Context, *secret.Buffer) (*secret.Buffer, error) {
	return nil, nil
}

type passTerm struct{}

func (passTerm) ReadSecret(context.Context, string) (*secret.Buffer, error) {
	return secret.Take([]byte("a passphrase")), nil
}
func (passTerm) ReadLine(context.Context, string) (string, error) { return "", ErrNoTerminal }

func tokenFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "tok")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(content)
	f.Seek(0, 0)
	t.Cleanup(func() { f.Close() })
	return strconv.Itoa(int(f.Fd()))
}

// The token commands and the light-mode loading. The token reaches the wiring
// and never the output.
func TestProviderTokenStoreAndUse(t *testing.T) {
	const tok = "eyJ.token-value-xyz"

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, WorkspaceFile), nil, 0o600)
	seedPool(t, dir)
	fs, err := fsstore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	tokens := map[string][]byte{}
	cfgs := map[string]WorkspaceConfig{dir: {Network: "preview", Mode: ModeLight, Koios: &KoiosConfig{}}}
	var out bytes.Buffer
	w := &wired{}
	d := opcertDeps(&out, cfgs, w)
	d.Terminal = passTerm{}
	d.Sealed = SealedOps{Open: func(string, *secret.Buffer, OpenOptions) (SealedStore, error) { return fakeSealed{fs, tokens}, nil }}
	run := func(args ...string) error {
		root := NewRoot(d)
		root.SetArgs(args)
		return root.ExecuteContext(context.Background())
	}

	if err := run("-C", dir, "provider", "token", "set", "koios", "--token-fd", tokenFile(t, tok+"\n")); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), tok) {
		t.Errorf("token printed:\n%s", out.String())
	}
	if err := run("-C", dir, "provider", "token", "set", "koios", "--token-fd", tokenFile(t, "\n")); err == nil {
		t.Error("empty token accepted")
	}
	if err := run("-C", dir, "provider", "token", "set", "other"); err == nil {
		t.Error("unknown provider accepted")
	}

	// New counter then issue in light mode: the wiring receives the token.
	if err := run("-C", dir, "pool", "opcert", "new-counter", "p"); err != nil {
		t.Fatal(err)
	}
	var seen string
	d.Wire = func(s ports.Store, o WireOptions) (*Env, error) {
		if o.Token != nil {
			o.Token.Use(func(b []byte) error { seen = string(b); return nil })
		}
		return w.wire(s, o)
	}
	if err := run("-C", dir, "pool", "opcert", "issue", "p"); err != nil {
		t.Fatal(err)
	}
	if seen != tok {
		t.Errorf("wiring saw token %q", seen)
	}
	if strings.Contains(out.String(), tok) {
		t.Errorf("token printed:\n%s", out.String())
	}

	if err := run("-C", dir, "provider", "token", "clear", "koios"); err != nil {
		t.Fatal(err)
	}
	if err := run("-C", dir, "provider", "token", "clear", "koios"); err != nil {
		t.Errorf("second clear: %v", err)
	}
}
