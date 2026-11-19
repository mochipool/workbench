package relaybind_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The package imports the standard library, the COSE domain (for Blake2b and
// the Sig_structure), the party types and the canonical CBOR helper, and
// nothing that does I/O. In particular it has no age, no envelope adapter and
// no mailbox domain: the relay binary links it (archtest checks its whole
// import closure).
//
// spec: SPO-Xrelaybind-INV-001
func TestPackageIsPure(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	allowedModule := map[string]bool{
		"github.com/mochipool/workbench/spo/internal/domain/cose":     true,
		"github.com/mochipool/workbench/spo/internal/domain/identity": true,
		"github.com/mochipool/workbench/spo/internal/domain/party":    true,
		"golang.org/x/crypto/blake2b":                                 true,
	}
	forbidden := []string{"os", "net", "io/fs", "io/ioutil", "syscall", "unsafe", "math/rand", "crypto/rand", "os/exec", "plugin", "log", "time/tzdata"}
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
