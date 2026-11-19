package stream

import (
	"bufio"
	"context"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func fdCount(t *testing.T) int {
	t.Helper()
	es, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("no /proc/self/fd: %v", err)
	}
	return len(es)
}

// settled polls until get() is at most limit, for up to d, and returns the last
// value.
func settled(d time.Duration, limit int, get func() int) int {
	end := time.Now().Add(d)
	for {
		runtime.GC()
		if v := get(); v <= limit || time.Now().After(end) {
			return v
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Many sequential connections, closed on both sides, leave no goroutine, no
// descriptor and no record behind.
//
// spec: SPO-Xmailbox-INV-023
func TestManySequentialConnectionsLeakNothing(t *testing.T) {
	reg := relayRegion(t)
	n := newNode(t)
	l := startListener(t, reg, n.pub)
	d := dialerFor(t, l, n)

	one := func() {
		c, s, _, _ := connect(t, l, d)
		c.Write([]byte("a"))
		s.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(s, make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		s.Write([]byte("b"))
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		c.Close()
		s.Close()
	}
	for range 3 { // warm up: the tunnel, DERP and netstack start what they keep
		one()
	}
	baseG := settled(10*time.Second, 0, func() int { return runtime.NumGoroutine() })
	baseF := fdCount(t)
	const rounds = 40
	for range rounds {
		one()
	}
	g := settled(30*time.Second, baseG+2, func() int { return runtime.NumGoroutine() })
	f := settled(30*time.Second, baseF+2, func() int { return fdCount(t) })
	t.Logf("goroutines %d before, %d after %d connections; descriptors %d before, %d after", baseG, g, rounds, baseF, f)
	if g > baseG+2 {
		buf := make([]byte, 1<<18)
		t.Errorf("goroutines grew from %d to %d over %d connections:\n%s", baseG, g, rounds, buf[:runtime.Stack(buf, true)])
	}
	if f > baseF+2 {
		t.Errorf("descriptors grew from %d to %d over %d connections", baseF, f, rounds)
	}
	l.mu.Lock()
	live := len(l.live)
	l.mu.Unlock()
	d.mu.Lock()
	dlive := len(d.live)
	d.mu.Unlock()
	if live != 0 || dlive != 0 {
		t.Fatalf("records left: %d keys on the listener, %d streams on the dialer", live, dlive)
	}
}

// A listener and a dialer that are closed leave no goroutine and no descriptor of
// their own behind.
//
// spec: SPO-Xmailbox-INV-023
func TestTeardownLeavesNothing(t *testing.T) {
	reg := relayRegion(t)
	// one round to let the shared test infrastructure and the runtime settle
	warm := newNode(t)
	lw := startListener(t, reg, warm.pub)
	connect(t, lw, dialerFor(t, lw, warm))
	baseG := settled(5*time.Second, 0, func() int { return runtime.NumGoroutine() })
	baseF := fdCount(t)

	for range 3 {
		nkey, _ := RandomKey()
		psk, _ := RandomKey()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		l, err := Listen(ctx, ListenerConfig{NodeKey: KeyBytes(nkey), PSK: KeyBytes(psk), Allowed: nil, Region: reg, Logf: quietLogf, DrainTimeout: testDrain})
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		l.Close()
		select {
		case <-l.Done():
		case <-time.After(20 * time.Second):
			t.Fatal("teardown did not finish")
		}
	}
	g := settled(30*time.Second, baseG+2, func() int { return runtime.NumGoroutine() })
	f := settled(30*time.Second, baseF+2, func() int { return fdCount(t) })
	t.Logf("goroutines %d before, %d after three listeners were started and closed; descriptors %d before, %d after", baseG, g, baseF, f)
	if g > baseG+2 || f > baseF+2 {
		buf := make([]byte, 1<<18)
		t.Errorf("a closed listener leaves goroutines (%d -> %d) or descriptors (%d -> %d):\n%s", baseG, g, baseF, f, buf[:runtime.Stack(buf, true)])
	}
}

// ---- sockets ----

type osSocket struct {
	local string
	port  int
	state string
	inode string
}

// procSockets lists the sockets of one /proc/self/net table.
func procSockets(t *testing.T, name string) []osSocket {
	t.Helper()
	f, err := os.Open("/proc/self/net/" + name)
	if err != nil {
		if strings.HasSuffix(name, "6") {
			return nil // a host without IPv6 has no such table
		}
		t.Skipf("no /proc/self/net/%s: %v", name, err)
	}
	defer f.Close()
	var out []osSocket
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 10 {
			continue
		}
		var port int
		if i := strings.LastIndex(fs[1], ":"); i >= 0 {
			for _, c := range fs[1][i+1:] {
				port = port*16 + hexVal(byte(c))
			}
		}
		out = append(out, osSocket{local: fs[1], port: port, state: fs[3], inode: fs[9]})
	}
	return out
}

func hexVal(b byte) int {
	switch {
	case b >= '0' && b <= '9':
		return int(b - '0')
	case b >= 'A' && b <= 'F':
		return int(b-'A') + 10
	case b >= 'a' && b <= 'f':
		return int(b-'a') + 10
	}
	return 0
}

func newSockets(before, after []osSocket) []osSocket {
	seen := map[string]bool{}
	for _, s := range before {
		seen[s.inode] = true
	}
	var out []osSocket
	for _, s := range after {
		if !seen[s.inode] {
			out = append(out, s)
		}
	}
	return out
}

func allSockets(t *testing.T) (tcp, udp []osSocket) {
	t.Helper()
	tcp = append(procSockets(t, "tcp"), procSockets(t, "tcp6")...)
	udp = append(procSockets(t, "udp"), procSockets(t, "udp6")...)
	return tcp, udp
}

// Neither side opens a TCP socket that listens, and the served port is not an
// operating-system port: it exists only inside the tunnel. Each side does bind
// ONE UDP socket per address family on an operating-system port (tailcat's
// WireGuard engine, magicsock, ListenPort 0): this test records what it is and
// that nothing else is.
//
// spec: SPO-Xmailbox-SEC-034
func TestOSSockets(t *testing.T) {
	reg := relayRegion(t) // the in-process DERP and STUN servers open their own sockets first
	tcp0, udp0 := allSockets(t)

	n := newNode(t)
	l := startListener(t, reg, n.pub)
	tcp1, udp1 := allSockets(t)
	ntcp, nudp := newSockets(tcp0, tcp1), newSockets(udp0, udp1)
	for _, s := range ntcp {
		t.Logf("relay side, new TCP socket: %+v", s)
		if s.state == "0A" {
			t.Errorf("the relay side listens on an operating-system TCP socket: %+v", s)
		}
		if s.port == int(DefaultPort) {
			t.Errorf("a TCP socket uses the served port: %+v", s)
		}
	}
	for _, s := range nudp {
		t.Logf("relay side, new UDP socket: %+v", s)
	}
	if len(nudp) == 0 {
		t.Error("the relay side bound no UDP socket: tailcat changed, and the claim in the package comment is out of date")
	}
	relayUDP := len(nudp)

	d := dialerFor(t, l, n)
	connect(t, l, d)
	tcp2, udp2 := allSockets(t)
	for _, s := range newSockets(tcp1, tcp2) {
		t.Logf("client side, new TCP socket: %+v", s)
		if s.state == "0A" {
			t.Errorf("the client side listens on an operating-system TCP socket: %+v", s)
		}
		if s.port == int(DefaultPort) {
			t.Errorf("a TCP socket uses the served port: %+v", s)
		}
	}
	cudp := newSockets(udp1, udp2)
	for _, s := range cudp {
		t.Logf("client side, new UDP socket: %+v", s)
	}
	if len(cudp) == 0 || len(cudp) > relayUDP {
		t.Errorf("the client side bound %d UDP sockets, the relay side %d", len(cudp), relayUDP)
	}
	// opening many streams opens no further socket of either kind
	for range 5 {
		c, s, _, _ := connect(t, l, d)
		c.Close()
		s.Close()
	}
	tcp3, udp3 := allSockets(t)
	for _, s := range newSockets(tcp2, tcp3) {
		if s.state == "0A" || s.port == int(DefaultPort) {
			t.Errorf("a stream opened a socket: %+v", s)
		}
	}
	if got := len(newSockets(udp2, udp3)); got != 0 {
		t.Errorf("five streams opened %d UDP sockets", got)
	}
}
