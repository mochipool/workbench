package main

import (
	"bytes"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/relayhost"
	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// The tailcat listener gets everything of the tunnel spec, its log included:
// the adapter's lines (a failed rebuild, a stuck teardown) reach the operator
// log through the spec's Logf, which relayhost makes safe (review finding L4).
//
// spec: SPO-Xmailbox-OUT-113
func TestTheListenerGetsTheSpecAndItsLog(t *testing.T) {
	var lines []string
	stuck := 0
	spec := relayhost.TunnelSpec{
		NodeKey:         func(use func([]byte) error) error { return use(make([]byte, 32)) },
		PSK:             func(use func([]byte) error) error { return use(make([]byte, 32)) },
		Allowed:         []party.NodeKey{{1}},
		Port:            7400,
		DERPMapURL:      "https://derp.example/map.json",
		OnTeardownStuck: func(error) { stuck++ },
		Logf:            func(f string, _ ...any) { lines = append(lines, f) },
	}
	c := listenerConfig(spec)
	if c.Port != 7400 || c.DERPMapURL != spec.DERPMapURL || len(c.Allowed) != 1 || c.Allowed[0] != spec.Allowed[0] || c.NodeKey == nil || c.PSK == nil {
		t.Fatalf("listener config %+v", c)
	}
	if c.Logf == nil || c.OnTeardownStuck == nil {
		t.Fatal("the listener has no log or no stuck hook")
	}
	c.Logf("tailcat stream: rebuilding the tunnel server (try %d of %d): %v", 1, 3, "x")
	c.OnTeardownStuck(nil)
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "tailcat stream:") || stuck != 1 {
		t.Fatalf("the log got %q, the hook %d", lines, stuck)
	}
	var log bytes.Buffer
	d := deps(&log)
	if d.Log != &log || d.LoadConfig == nil || d.LoadKey == nil || d.CreateKey == nil || d.PublicKey == nil || d.OpenMailbox == nil ||
		d.OpenRegistry == nil || d.Listen == nil || d.Rand == nil {
		t.Fatalf("deps are incomplete: %+v", d)
	}
}

// The signals: SIGHUP reloads, SIGINT and SIGTERM stop.
func TestTheSignals(t *testing.T) {
	raw := make(chan os.Signal, 3)
	sig := signals(raw)
	raw <- syscall.SIGHUP
	raw <- syscall.SIGTERM
	raw <- syscall.SIGINT
	for _, want := range []relayhost.Signal{relayhost.SignalReload, relayhost.SignalStop, relayhost.SignalStop} {
		select {
		case got := <-sig:
			if got != want {
				t.Fatalf("got %v, want %v", got, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("no signal")
		}
	}
	close(raw)
}
