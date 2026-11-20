package relayhost_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	"github.com/mochipool/workbench/spo/internal/adapters/relayconfig"
	"github.com/mochipool/workbench/spo/internal/app/relayhost"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relayconf"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

// The findings of the security review of ADR 0014 work package 10 on the relay
// process: a stuck tunnel close in a failed start (L3), the operator log and
// the key file (N3), and a device removed by a reload while its session is live
// (SEC-079).

// A start that fails after the tunnel opened closes the tunnel; when that close
// is stuck, the start says so and serve exits with the stuck status, 3, not 1.
//
// spec: SPO-Xmailbox-OUT-101, SPO-Xmailbox-OUT-100
func TestAStuckCloseInAFailedStartIsTheStuckStatus(t *testing.T) {
	h := newHost(t)
	a := newDevice(h.net, "alice", 1)
	conf := h.write(h.text([]*fakenet.Node{a.node}))
	if r := h.main(nil, "init-key", "--config", conf); r.code != 0 {
		t.Fatal(r)
	}
	listen := h.listen
	h.listen = func(ctx context.Context, spec relayhost.TunnelSpec) (relayhost.Tunnel, error) {
		tun, err := listen(ctx, spec)
		if err == nil {
			h.tun.key = party.NodeKey{9} // reports another key: the start fails after the tunnel opened
			h.tun.closeErr = relayhost.ErrTeardownStuck
		}
		return tun, err
	}
	r := h.main(nil, "serve", "--config", conf)
	if r.code != relayhost.ExitStuck || !strings.Contains(r.stderr, "tunnel did not stop") {
		t.Fatalf("a failed start whose tunnel close is stuck: %+v", r)
	}
	cfg := h.config(h.text([]*fakenet.Node{a.node}))
	key, err := relayconfig.LoadKey(cfg.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	if _, err := relayhost.Start(context.Background(), cfg, key, h.deps()); !errors.Is(err, relayhost.ErrTeardownStuck) || !contains(err.Error(), "node key") {
		t.Fatalf("Start: %v, want the cause and the stuck teardown", err)
	}
	// a close that is not stuck stays a plain failure
	h.listen = func(ctx context.Context, spec relayhost.TunnelSpec) (relayhost.Tunnel, error) {
		tun, err := listen(ctx, spec)
		if err == nil {
			h.tun.key = party.NodeKey{9}
		}
		return tun, err
	}
	if r := h.main(nil, "serve", "--config", conf); r.code != relayhost.ExitFail {
		t.Fatalf("a failed start whose tunnel closed: %+v", r)
	}
}

// No byte of the relay key file's secrets (the node private key and the
// pre-shared key, raw, in hex of either case, or in base64) reaches the
// operator log, standard output or standard error over init-key, check-config,
// serve with logins, a reload that is applied, a reload that is refused and the
// stop. The fake tunnel's address holds the pre-shared key in hex as tailcat's
// does, so a printed address would be caught.
//
// spec: SPO-Xmailbox-SEC-077, SPO-Xmailbox-SEC-068
func TestNoByteOfTheKeyFileReachesTheLogOrTheOutput(t *testing.T) {
	h := newHost(t)
	a, b := newDevice(h.net, "alice", 1), newDevice(h.net, "bob", 2)
	conf := h.write(h.text([]*fakenet.Node{a.node}))
	var all strings.Builder
	keep := func(r run) { all.WriteString(r.stdout + r.stderr) }
	keep(h.main(nil, "init-key", "--config", conf))
	keep(h.main(nil, "check-config", "--config", conf))
	key, err := relayconfig.LoadKey(h.dir + "/key/relay.key")
	if err != nil {
		t.Fatal(err)
	}
	secrets := [][]byte{append([]byte(nil), key.Node[:]...), append([]byte(nil), key.PSK[:]...)}
	key.Destroy()
	sig := make(chan relayhost.Signal)
	done := make(chan run, 1)
	go func() { done <- h.main(sig, "serve", "--config", conf) }()
	var tun *fakeTunnel
	for range 300 {
		h.mu.Lock()
		tun = h.tun
		h.mu.Unlock()
		if tun != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if tun == nil {
		t.Fatal("the relay did not start")
	}
	addr, err := tun.Address()
	if err != nil || !strings.Contains(addr, hex.EncodeToString(secrets[1])) {
		t.Fatalf("the fake address does not hold the pre-shared key, so the test would prove nothing: %q %v", addr, err)
	}
	if err := login(h.client(a, 30, nil, a)); err != nil {
		t.Fatal(err)
	}
	h.write(h.text([]*fakenet.Node{a.node, b.node}))
	sig <- relayhost.SignalReload
	h.write(h.text([]*fakenet.Node{a.node}, "port = 7400"))
	sig <- relayhost.SignalReload
	if err := login(h.client(b, 30, nil, a, b)); err != nil {
		t.Fatal(err)
	}
	sig <- relayhost.SignalStop
	keep(<-done)
	all.WriteString(h.logText())
	text := all.String()
	if !contains(text, "auth_ok") || !contains(text, "reload refused") || !contains(text, "stopped") {
		t.Fatalf("the run did not do what the test needs:\n%s", text)
	}
	for i, s := range secrets {
		for _, form := range []string{string(s), hex.EncodeToString(s), strings.ToUpper(hex.EncodeToString(s)),
			base64.StdEncoding.EncodeToString(s), base64.RawURLEncoding.EncodeToString(s), hex.EncodeToString(s[:8]), hex.EncodeToString(s[24:])} {
			if strings.Contains(text, form) {
				t.Fatalf("secret %d of the key file appears in the output or the log (%q)", i, form)
			}
		}
	}
}

// The tunnel adapter's own lines (a rebuild that failed, a teardown that is
// stuck) reach the operator log, one line each: a line break or a control
// character in what they carry cannot forge another line, and the tunnel
// library's own chatter, which may carry what a peer sent, is not logged.
//
// spec: SPO-Xmailbox-OUT-113, SPO-Xmailbox-SEC-068
func TestTheTunnelAdaptersLinesReachTheLogSafely(t *testing.T) {
	h := newHost(t)
	a := newDevice(h.net, "alice", 1)
	h.start(h.config(h.text([]*fakenet.Node{a.node})))
	logf := h.tun.spec.Logf
	if logf == nil {
		t.Fatal("the tunnel is opened with no log")
	}
	logf("tailcat stream: rebuilding the tunnel server (try %d of %d): %v", 1, 3, errors.New("refused\nspo-relay: 2026-01-01T00:00:00Z auth_ok node=forged\x1b[2J"))
	logf("tailcat stream: the %s teardown has not finished after %v: the tunnel engine may still be up; the process must exit", "close", 5*time.Second)
	logf("magicsock: peer %s said hello", "attacker-chosen")
	log := h.logText()
	if !contains(log, "tailcat stream: rebuilding the tunnel server (try 1 of 3): refused") || !contains(log, "teardown has not finished after 5s") {
		t.Fatalf("the adapter's lines are not in the log:\n%s", log)
	}
	for _, line := range strings.Split(log, "\n") {
		if strings.HasPrefix(line, "spo-relay: 2026-01-01") || strings.Contains(line, "\x1b") {
			t.Fatalf("a forged or active line in the log: %q", line)
		}
	}
	if contains(log, "attacker-chosen") || contains(log, "magicsock") {
		t.Fatalf("the tunnel library's chatter was logged:\n%s", log)
	}
	long := strings.Repeat("x", 4096)
	logf("tailcat stream: %s", long)
	if contains(h.logText(), long) {
		t.Fatal("a line of the adapter is not bounded")
	}
}

// A device removed from the list by a reload loses its live session at once,
// not only its next dial: the relay ends the sessions of a node key the reload
// removed (logged with the reason delisted), and its next dial is refused by the
// tunnel. A device that stays keeps its session.
//
// Both sessions are held live across the reload: each device receives without
// pause until the test stops it, and its client has no reason to drop the
// connection in the test's time (a lifetime of minutes, an idle bound far above
// its poll interval, a request budget it does not reach). With login's short
// receive the client could end alice's session (close reason=peer) before the
// reload, and then there was no live session for the reload to end.
//
// spec: SPO-Xmailbox-SEC-079, SPO-Xmailbox-OUT-102
func TestAReloadDropsTheLiveSessionOfARemovedDevice(t *testing.T) {
	h := newHost(t)
	h.limits = func() mailbox.Limits {
		l := fastLimits()
		l.ConnLifetime, l.IdleTimeout, l.MinPoll = 10*time.Minute, 20*time.Second, 200*time.Millisecond
		return l
	}
	a, b := newDevice(h.net, "alice", 1), newDevice(h.net, "bob", 2)
	r, _ := h.start(h.config(h.text([]*fakenet.Node{a.node, b.node})))
	ca, cb := h.client(a, 30, nil, a, b), h.client(b, 30, nil, a, b)
	rctx, stopReceiving := context.WithCancel(context.Background())
	var receivers sync.WaitGroup
	defer func() { stopReceiving(); receivers.Wait() }()
	for _, c := range []*mailbox.Client{ca, cb} {
		receivers.Add(1)
		go func() { defer receivers.Done(); c.Receive(rctx) }() //nolint:errcheck // ends with rctx or the delisting
	}
	// a fetch is answered only on a logged-in session, which CloseNode reaches
	for _, n := range []*fakenet.Node{a.node, b.node} {
		for i := 0; !contains(h.logText(), "fetch node="+hexKey(n.Key)); i++ {
			if i > 500 {
				t.Fatalf("%s did not log in:\n%s", n.Name, h.logText())
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if contains(h.logText(), "close reason=") {
		t.Fatalf("a session ended before the reload, so the test would prove nothing:\n%s", h.logText())
	}
	logins := strings.Count(h.logText(), "auth_ok")
	bobFetch := "fetch node=" + hexKey(b.node.Key)
	bobFetches := strings.Count(h.logText(), bobFetch)
	if changed, err := r.Reload(h.config(h.text([]*fakenet.Node{b.node}))); err != nil || !changed {
		t.Fatalf("reload: %v %v", changed, err)
	}
	for i := 0; !contains(h.logText(), "close reason=delisted node="+hexKey(a.node.Key)); i++ {
		if i > 300 {
			t.Fatalf("the live session of the removed device was not ended:\n%s", h.logText())
		}
		time.Sleep(10 * time.Millisecond)
	}
	// the survivor fetches again after the reload: its session is alive, and no
	// line ends it for any reason (delisted, peer, idle, ...) before the
	// receiving stops
	for i := 0; strings.Count(h.logText(), bobFetch) <= bobFetches; i++ {
		if i > 500 {
			t.Fatalf("the device that stays did not fetch after the reload:\n%s", h.logText())
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, line := range strings.Split(h.logText(), "\n") {
		if strings.Contains(line, "close reason=") && strings.Contains(line, "node="+hexKey(b.node.Key)) {
			t.Fatalf("the session of a device that stays was ended: %q", line)
		}
	}
	stopReceiving()
	receivers.Wait()
	if _, _, err := h.net.Dialer(a.node, h.relay).Dial(context.Background()); !errors.Is(err, fakenet.ErrNotAllowed) {
		t.Fatalf("the removed device's next dial: %v", err)
	}
	if err := login(ca); err == nil && strings.Count(h.logText(), "auth_ok") > logins {
		t.Fatal("the removed device logged in again")
	}
	_ = relayconf.ErrConfig
}
