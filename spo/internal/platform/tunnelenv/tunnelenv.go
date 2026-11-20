// Package tunnelenv guards a process that starts a tailcat tunnel against the
// tunnel library's debug knobs (SPO-Xmailbox-SEC-085). The library reads
// environment variables of the form TS_DEBUG_* at its start: TS_DEBUG_ADDR makes
// it print the tunnel address, which holds the pre-shared key, to the standard
// error through the global log package, and TS_DEBUG_USE_DERP_HTTP turns TLS to
// the DERP server off. Neither has a place in spo or spo-relay, so a start with
// any variable of that prefix is refused, and the global log output, which the
// library writes to past every filtered logger, is discarded.
//
// It imports the standard library only, so the tunnel adapters and the commands
// can share it.
package tunnelenv

import (
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
)

// Prefix is the prefix of the tunnel library's debug variables.
const Prefix = "TS_DEBUG_"

// environ is the process environment (a test's seam).
var environ = os.Environ

// Check refuses a tunnel start when any environment variable of the debug
// prefix is set, naming them (their names only; a value is never shown). Every
// variable of the prefix is refused, not a list: a knob added to the library
// later is refused too.
func Check() error {
	var names []string
	for _, kv := range environ() {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, Prefix) {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)
	return fmt.Errorf("the environment sets %s: a tunnel debug setting (%s*) can print the tunnel's pre-shared key or turn TLS to the DERP server off; unset it and start again (no tunnel was started)", strings.Join(names, ", "), Prefix)
}

// QuietGlobalLog sends the global log package's output nowhere. The tunnel
// library writes some lines with log.Printf directly, past the logger a caller
// gives it; none of them is needed, and a future one could carry a secret.
func QuietGlobalLog() {
	log.SetOutput(io.Discard)
}

// Prepare is what every tunnel start runs first: Check, then QuietGlobalLog.
func Prepare() error {
	if err := Check(); err != nil {
		return err
	}
	QuietGlobalLog()
	return nil
}
