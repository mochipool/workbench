package mailbox_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The package imports the standard library, the canonical CBOR helper, the
// party types and Blake2b, and nothing that does I/O.
//
// spec: SPO-Xmailbox-INV-001
func TestPackageIsPure(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	allowedModule := map[string]bool{
		"github.com/mochipool/workbench/spo/internal/domain/identity": true,
		"github.com/mochipool/workbench/spo/internal/domain/party":    true,
		"golang.org/x/crypto/blake2b":                                 true,
	}
	forbidden := []string{"os", "net", "io/fs", "io/ioutil", "syscall", "unsafe", "math/rand", "crypto/rand", "os/exec", "plugin", "log"}
	seen := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		seen++
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			for _, bad := range forbidden {
				if p == bad || strings.HasPrefix(p, bad+"/") && bad != "io/fs" {
					t.Errorf("%s imports %s", f, p)
				}
			}
			if strings.Contains(strings.SplitN(p, "/", 2)[0], ".") && !allowedModule[p] {
				t.Errorf("%s imports %s, which is not on the list", f, p)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no source files")
	}
}
