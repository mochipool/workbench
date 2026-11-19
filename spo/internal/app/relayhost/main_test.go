package relayhost_test

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/relayhost"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

type run struct {
	code           int
	stdout, stderr string
}

func (h *host) main(sig chan relayhost.Signal, args ...string) run {
	h.t.Helper()
	var out, errb bytes.Buffer
	code := relayhost.Main(args, &out, &errb, sig, h.deps())
	return run{code, out.String(), errb.String()}
}

// The command line: usage errors are 2; a bad file is 1; init-key creates the key
// once and prints the node key; check-config validates without starting and
// prints the node key when there is one; serve without a key names init-key.
//
// spec: SPO-Xmailbox-IF-023, SPO-Xmailbox-OUT-103, SPO-Xmailbox-OUT-101
func TestTheCommandLine(t *testing.T) {
	h := newHost(t)
	a := newDevice(h.net, "alice", 1)
	conf := h.write(h.text([]*fakenet.Node{a.node}))
	for _, args := range [][]string{nil, {"serve"}, {"start", "--config", conf}, {"serve", "--config"}, {"check-config", "--config", conf, "extra"},
		{"init-key", "--config", conf, "--print-address"}} {
		if r := h.main(nil, args...); r.code != relayhost.ExitUsage || !strings.Contains(r.stderr, "usage") && !strings.Contains(r.stderr, "flag") {
			t.Errorf("%q: %+v, want the usage status 2", args, r)
		}
	}
	if r := h.main(nil, "help"); r.code != 0 || !strings.Contains(r.stdout, "init-key") {
		t.Errorf("help: %+v", r)
	}
	if r := h.main(nil, "check-config", "--config", conf+".missing"); r.code != relayhost.ExitFail {
		t.Errorf("a missing file: %+v", r)
	}
	bad := h.write(h.text(nil))
	if r := h.main(nil, "check-config", "--config", bad); r.code != relayhost.ExitFail || !strings.Contains(r.stderr, "[[device]]") {
		t.Errorf("a file with no device: %+v", r)
	}
	over := h.write(h.text([]*fakenet.Node{a.node}) + "[limits]\nconnections = 65\n")
	if r := h.main(nil, "check-config", "--config", over); r.code != relayhost.ExitFail || !strings.Contains(r.stderr, "connections") {
		t.Errorf("a limit above the table: %+v", r)
	}
	conf = h.write(h.text([]*fakenet.Node{a.node}))
	if r := h.main(nil, "check-config", "--config", conf); r.code != 0 || !strings.Contains(r.stdout, "init-key") || strings.Contains(r.stdout, "relay node key") {
		t.Errorf("check-config before the key: %+v", r)
	}
	if r := h.main(nil, "serve", "--config", conf); r.code != relayhost.ExitFail || !strings.Contains(r.stderr, "init-key") {
		t.Errorf("serve with no key: %+v", r)
	}
	if h.listened != 0 {
		t.Fatal("check-config or a refused serve opened the tunnel")
	}
	want := "relay node key " + hexKey(h.relay.Key)
	r := h.main(nil, "init-key", "--config", conf)
	if r.code != 0 || !strings.Contains(r.stdout, want) {
		t.Fatalf("init-key: %+v", r)
	}
	if r := h.main(nil, "init-key", "--config", conf); r.code != relayhost.ExitFail || !strings.Contains(r.stderr, "exists") {
		t.Errorf("a second init-key: %+v", r)
	}
	if r := h.main(nil, "check-config", "--config", conf); r.code != 0 || !strings.Contains(r.stdout, want) || !strings.Contains(r.stdout, "valid") {
		t.Errorf("check-config with the key: %+v", r)
	}
	if _, err := os.Stat(h.dir + "/state/mailbox"); err == nil {
		t.Error("check-config created a store")
	}
	if err := os.Chmod(h.dir+"/key/relay.key", 0o644); err != nil {
		t.Fatal(err)
	}
	if r := h.main(nil, "check-config", "--config", conf); r.code != relayhost.ExitFail {
		t.Errorf("check-config with a readable key: %+v", r)
	}
	os.Chmod(h.dir+"/key/relay.key", 0o600)
}

// serve: prints the node key and, only on request, the address with a warning;
// SIGHUP reloads the device list or refuses another change; SIGTERM stops with
// 0; a stuck teardown is 3 and says "tunnel did not stop".
//
// spec: SPO-Xmailbox-OUT-101, SPO-Xmailbox-OUT-102, SPO-Xmailbox-OUT-103
func TestServe(t *testing.T) {
	h := newHost(t)
	a, b := newDevice(h.net, "alice", 1), newDevice(h.net, "bob", 2)
	conf := h.write(h.text([]*fakenet.Node{a.node}))
	if r := h.main(nil, "init-key", "--config", conf); r.code != 0 {
		t.Fatal(r)
	}
	serve := func(sig chan relayhost.Signal, args ...string) chan run {
		out := make(chan run, 1)
		go func() { out <- h.main(sig, append([]string{"serve", "--config", conf}, args...)...) }()
		return out
	}
	waitTunnel := func() *fakeTunnel {
		for range 200 {
			h.mu.Lock()
			tun := h.tun
			h.mu.Unlock()
			if tun != nil && !tun.closed.Load() {
				return tun
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("the relay did not start")
		return nil
	}
	sig := make(chan relayhost.Signal)
	done := serve(sig)
	tun := waitTunnel()
	// a reload with another device list
	h.write(h.text([]*fakenet.Node{a.node, b.node}))
	sig <- relayhost.SignalReload
	for i := 0; len(tun.sets()) == 0; i++ {
		if i > 200 {
			t.Fatal("the reload was not applied")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// a reload with another port is refused
	h.write(h.text([]*fakenet.Node{b.node}, "port = 7400"))
	sig <- relayhost.SignalReload
	sig <- relayhost.SignalStop
	r := <-done
	if r.code != 0 || !strings.Contains(r.stdout, "relay node key "+hexKey(h.relay.Key)) || !strings.Contains(r.stdout, "stopped") {
		t.Fatalf("serve: %+v", r)
	}
	if strings.Contains(r.stdout, "holding-the-psk") || strings.Contains(r.stderr, "holding-the-psk") {
		t.Fatalf("the address was printed unasked: %+v", r)
	}
	if !strings.Contains(r.stdout, "now admits 2 device") || !strings.Contains(r.stderr, "reload refused") {
		t.Fatalf("the reloads: %+v", r)
	}
	if s := tun.sets(); len(s) != 1 || len(s[0]) != 2 {
		t.Fatalf("the tunnel lists %x", s)
	}

	h.tun = nil
	conf = h.write(h.text([]*fakenet.Node{a.node}))
	sig = make(chan relayhost.Signal)
	done = serve(sig, "--print-address")
	tun = waitTunnel()
	tun.closeErr = relayhost.ErrTeardownStuck
	sig <- relayhost.SignalStop
	r = <-done
	if r.code != relayhost.ExitStuck || !strings.Contains(r.stderr, "tunnel did not stop") || strings.Contains(r.stdout, "stopped") {
		t.Fatalf("a stuck teardown: %+v", r)
	}
	if !strings.Contains(r.stdout, "address tailcat-fake-address-holding-the-psk") || !strings.Contains(r.stderr, "pre-shared key") {
		t.Fatalf("--print-address: %+v", r)
	}
}
