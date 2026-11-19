package mailbox_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
)

// The bounds of the version 2 frames are the bounds of the statements they
// carry: this package does not import relaybind, so a test pins the two sets of
// constants together.
//
// spec: SPO-Xmailbox-PRE-027, SPO-Xmailbox-INV-028
func TestV2BoundsAreTheStatementBounds(t *testing.T) {
	if mailbox.MaxSign1Bytes != relaybind.MaxSign1Bytes || mailbox.MaxCOSEKeyBytes != relaybind.MaxKeyBytes ||
		mailbox.WalletKeySize != relaybind.KeyHashSize || int64(mailbox.MaxTime) != relaybind.MaxTime {
		t.Fatalf("sign1 %d/%d, key %d/%d, wallet key %d/%d, time %d/%d",
			mailbox.MaxSign1Bytes, relaybind.MaxSign1Bytes, mailbox.MaxCOSEKeyBytes, relaybind.MaxKeyBytes,
			mailbox.WalletKeySize, relaybind.KeyHashSize, int64(mailbox.MaxTime), relaybind.MaxTime)
	}
	if mailbox.MaxSign1Bytes != 512 || mailbox.MaxCOSEKeyBytes != 128 || mailbox.MaxSenders != 64 || mailbox.WalletKeySize != 28 {
		t.Error("the numbers of the ADR")
	}
	// A relaybind.KeyHash converts to a WalletKey and back with no copy loop.
	k := relaybind.KeyHash(wk(5))
	if mailbox.WalletKey(k) != wk(5) {
		t.Error("the key types differ")
	}
	// The relay session's numbers (ADR 0014 decision 5) are named here.
	if mailbox.MaxRevokesPerConn != 8 || mailbox.UnauthBudget != 5*time.Second || mailbox.MaxUnauthConnections != 16 ||
		mailbox.MaxNewBindingsPerHour != 60 || mailbox.NewBindingBurst != 10 || mailbox.MaxBoundDevices != 4096 ||
		mailbox.MaxDevicesPerKey != 8 || mailbox.BindingIdleDrop != 30*24*time.Hour {
		t.Error("the session limits")
	}
	if mailbox.StrangerEntries != 16 || mailbox.StrangerBytes != 1<<20 {
		t.Error("the stranger allowance")
	}
	if mailbox.MaxHeaderFrame != 4096 {
		t.Errorf("the header bound moved to %d; the largest Auth needs 2726", mailbox.MaxHeaderFrame)
	}
	if mailbox.Version1 != 1 || mailbox.Version2 != 2 {
		t.Error("versions")
	}
}

// The package still imports nothing of the binding domain: the frames carry the
// statements as bounded byte strings, and the pure glue that verifies them is
// the caller's.
//
// spec: SPO-Xmailbox-INV-028
func TestMailboxDoesNotImportRelaybind(t *testing.T) {
	files, _ := filepath.Glob("*.go")
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
			if strings.Contains(p, "relaybind") || strings.Contains(p, "/domain/cose") {
				t.Errorf("%s imports %s", f, p)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no source files")
	}
}
