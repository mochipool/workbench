package stream

import (
	"context"
	"io"
	"log"
	"strings"
	"testing"
)

// A relay's listener and a device's dialer refuse to start when the
// environment sets a debug variable of the tunnel library (TS_DEBUG_ADDR would
// print the address, with the pre-shared key, to the standard error), before
// any key is read or the network is touched; the error names the variable.
//
// spec: SPO-Xmailbox-SEC-085
func TestATunnelDebugVariableRefusesTheRelayAndTheDialer(t *testing.T) {
	for _, name := range []string{"TS_DEBUG_ADDR", "TS_DEBUG_USE_DERP_HTTP", "TS_DEBUG_SOMETHING_NEW"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "1")
			read := 0
			reader := func(func([]byte) error) error { read++; return nil }
			_, err := Listen(context.Background(), ListenerConfig{NodeKey: reader, PSK: reader})
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("Listen: %v", err)
			}
			_, err = NewDialer(DialerConfig{Address: reader, NodeKey: reader})
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("NewDialer: %v", err)
			}
			if read != 0 {
				t.Fatalf("a key or the address was read %d times before the refusal", read)
			}
		})
	}
}

// An all-zero node key is an error, not a panic inside the tunnel library.
func TestAZeroNodeKeyIsRefusedNotAPanic(t *testing.T) {
	var zero, psk [KeyLen]byte
	psk[0] = 1
	if _, err := Listen(context.Background(), ListenerConfig{NodeKey: KeyBytes(zero), PSK: KeyBytes(psk)}); err == nil || !strings.Contains(err.Error(), "all zero") {
		t.Fatalf("Listen: %v", err)
	}
	if _, err := PublicKey(KeyBytes(zero)); err == nil {
		t.Fatal("PublicKey of the zero key")
	}
}

// A start discards the global log: the tunnel library's own log.Printf lines
// never reach the standard error.
//
// spec: SPO-Xmailbox-SEC-085
func TestATunnelStartDiscardsTheGlobalLog(t *testing.T) {
	saved := log.Writer()
	t.Cleanup(func() { log.SetOutput(saved) })
	log.SetOutput(&strings.Builder{})
	_, _ = NewDialer(DialerConfig{}) // refused for its config, after the guard ran
	if log.Writer() != io.Discard {
		t.Fatal("the global log was not discarded")
	}
}
