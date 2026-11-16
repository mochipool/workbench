package ports

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The constructors that set a transport kind are called only by the transport
// adapters (and tests, and the test rig's pipes): wiring cannot label a
// network as a file (SPO-Xparty-INV-024).
//
// spec: SPO-Xparty-INV-024
func TestTransportKindConstructorsAreOnlyCalledByAdapters(t *testing.T) {
	root := filepath.Join("..", "..")
	allowed := []string{"internal/ports/", "internal/adapters/filebag/", "internal/adapters/tailcat/", "test/multiparty/partyrig/"}
	names := []string{"ports.FileTransport(", "ports.NetworkTransport(", "ports.FileReceived(", "ports.NetworkReceived("}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		for _, a := range allowed {
			if strings.HasPrefix(rel, a) {
				return nil
			}
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, n := range names {
			if strings.Contains(string(b), n) {
				t.Errorf("%s calls %s: only the transport adapters make a transport or a received envelope", rel, n)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
