package ports

import (
	"io/fs"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"
	"testing"
)

// The constructors that set a transport kind are called only by the transport
// adapters (and tests, and the test rig's pipes): wiring cannot label a
// network as a file (SPO-Xparty-INV-024). The adapters are the file bag, the
// tailcat adapter and the mailbox client. Each entry is one package directory,
// matched exactly: a subdirectory (tailcat/stream, a package under the mailbox
// client) is another package and must be added by name if it ever needs to call.
var transportCallerAllowList = []string{
	"internal/ports/",
	"internal/adapters/filebag/",
	"internal/adapters/tailcat/",
	"internal/adapters/mailbox/",
	"test/multiparty/partyrig/",
}

var transportConstructors = []string{"ports.FileTransport(", "ports.NetworkTransport(", "ports.FileReceived(", "ports.NetworkReceived("}

// offenders lists the non-test Go files under root, outside the allow-list,
// that call one of the constructors.
func offenders(t *testing.T, root string, allowed []string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		// the package directory, exactly: a subpackage of an allowed package is
		// another package and is not admitted
		for _, a := range allowed {
			if pathpkg.Dir(rel) == strings.TrimSuffix(a, "/") {
				return nil
			}
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, n := range transportConstructors {
			if strings.Contains(string(b), n) {
				out = append(out, rel+" calls "+n)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// spec: SPO-Xparty-INV-024
func TestTransportKindConstructorsAreOnlyCalledByAdapters(t *testing.T) {
	for _, o := range offenders(t, filepath.Join("..", ".."), transportCallerAllowList) {
		t.Errorf("%s: only the transport adapters make a transport or a received envelope", o)
	}
}

// The allow-list names the mailbox client and still fails for a call from any
// other package, the mailbox's neighbours included.
//
// spec: SPO-Xparty-INV-024
func TestTransportCallerAllowListStillBites(t *testing.T) {
	root := t.TempDir()
	write := func(rel, src string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	call := "package x\nvar _ = ports.NetworkTransport(nil)\n"
	write("internal/adapters/mailbox/client.go", call)                                       // allowed
	write("internal/adapters/mailboxstore/store.go", call)                                   // a neighbour: not allowed
	write("internal/adapters/mailboxx/x.go", call)                                           // a prefix lookalike: not allowed
	write("internal/adapters/mailbox/sub/x.go", call)                                        // a subpackage of an allowed package: not allowed
	write("internal/adapters/filebag/sub/x.go", call)                                        // likewise
	write("internal/adapters/tailcat/stream/x.go", call)                                     // likewise
	write("test/multiparty/partyrig/deeper/x.go", call)                                      // likewise
	write("internal/app/relay/session.go", call)                                             // not allowed
	write("internal/adapters/cli/wiring.go", "package x\nvar _ = ports.FileReceived(nil)\n") // not allowed
	write("internal/adapters/other/x_test.go", call)                                         // tests are skipped
	got := offenders(t, root, transportCallerAllowList)
	want := map[string]bool{
		"internal/adapters/mailboxstore/store.go calls ports.NetworkTransport(": true,
		"internal/adapters/mailboxx/x.go calls ports.NetworkTransport(":         true,
		"internal/app/relay/session.go calls ports.NetworkTransport(":           true,
		"internal/adapters/mailbox/sub/x.go calls ports.NetworkTransport(":      true,
		"internal/adapters/filebag/sub/x.go calls ports.NetworkTransport(":      true,
		"internal/adapters/tailcat/stream/x.go calls ports.NetworkTransport(":   true,
		"test/multiparty/partyrig/deeper/x.go calls ports.NetworkTransport(":    true,
		"internal/adapters/cli/wiring.go calls ports.FileReceived(":             true,
	}
	if len(got) != len(want) {
		t.Fatalf("offenders = %v", got)
	}
	for _, g := range got {
		if !want[g] {
			t.Fatalf("unexpected offender %q in %v", g, got)
		}
	}
}
