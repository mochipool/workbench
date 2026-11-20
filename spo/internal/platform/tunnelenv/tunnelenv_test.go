package tunnelenv

import (
	"bytes"
	"io"
	"log"
	"strings"
	"testing"
)

// Any variable of the debug prefix refuses the start and is named; its value is
// never shown. Other variables, and one that only resembles the prefix, pass.
//
// spec: SPO-Xmailbox-SEC-085
func TestADebugVariableOfTheTunnelLibraryRefusesTheStart(t *testing.T) {
	saved := environ
	t.Cleanup(func() { environ = saved })
	environ = func() []string {
		return []string{"HOME=/home/op", "TS_DEBUG_ADDR=1", "TS_DEBUG_USE_DERP_HTTP=secretvalue", "XTS_DEBUG_ADDR=1", "TS_DEBUGX=1"}
	}
	err := Check()
	if err == nil {
		t.Fatal("a start with TS_DEBUG_ADDR set")
	}
	for _, w := range []string{"TS_DEBUG_ADDR", "TS_DEBUG_USE_DERP_HTTP", "unset"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("%q does not name %s", err, w)
		}
	}
	for _, not := range []string{"secretvalue", "XTS_DEBUG_ADDR", "TS_DEBUGX"} {
		if strings.Contains(err.Error(), not) {
			t.Errorf("%q names %s", err, not)
		}
	}
	if Prepare() == nil {
		t.Fatal("Prepare passed")
	}
	environ = func() []string { return []string{"HOME=/home/op", "TS_DEBUGX=1", "TSDEBUG_ADDR=1"} }
	if err := Check(); err != nil {
		t.Fatal(err)
	}
}

// After a start, the global log package writes nowhere: a line the tunnel
// library prints with log.Printf (as it does for TS_DEBUG_ADDR) never reaches
// the standard error.
//
// spec: SPO-Xmailbox-SEC-085
func TestAStartDiscardsTheGlobalLog(t *testing.T) {
	saved, savedW := environ, log.Writer()
	t.Cleanup(func() { environ = saved; log.SetOutput(savedW) })
	environ = func() []string { return nil }
	var buf bytes.Buffer
	log.SetOutput(&buf)
	if err := Prepare(); err != nil {
		t.Fatal(err)
	}
	log.Printf("tailcat address: %s", "tcSECRET")
	if buf.Len() != 0 || log.Writer() != io.Discard {
		t.Fatalf("the global log still writes: %q", buf.String())
	}
}
