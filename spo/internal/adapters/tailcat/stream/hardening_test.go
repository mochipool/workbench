package stream

// Tests of the findings of the security review of this package (F1 to F5, F8):
// teardown racing a first dial, a forged "meowed" acknowledgment, the teardown
// that cannot finish with many endpoints, refused connections that linger, the
// close that resets, and Accept returning a closed stream. Each test is the
// reviewer's scenario. Every blocking operation runs with an assertion on its
// bound, never with the test binary's timeout as the only kill.

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"tailscale.com/derp/derphttp"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/netmon"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/nettype"
	"tailscale.com/util/eventbus"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"

	tc "github.com/tailscale/tailcat"
)

// ---- helpers ----

// within runs fn and fails the test when it has not returned d + 2 s later.
func within[T any](t *testing.T, d time.Duration, what string, fn func() T) T {
	t.Helper()
	ch := make(chan T, 1)
	go func() { ch <- fn() }()
	select {
	case v := <-ch:
		return v
	case <-time.After(d + 2*time.Second):
		t.Fatalf("%s did not return within %v (+2 s)", what, d)
		panic("unreachable")
	}
}

// readErr reads one byte from s under a deadline and returns the error; it
// fails the test if the read outlives the deadline by 2 s.
func readErr(t *testing.T, s relayport.Stream, d time.Duration) error {
	t.Helper()
	s.SetReadDeadline(time.Now().Add(d))
	return within(t, d, "Read", func() error { _, err := s.Read(make([]byte, 1)); return err })
}

func waitClosed(t *testing.T, ch <-chan struct{}, d time.Duration, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(d):
		t.Fatalf("%s did not finish within %v", what, d)
	}
}

type derpRelay struct {
	reg *tailcfg.DERPRegion
	srv *derpserver.Server
}

// startDERP is integration.RunDERPAndSTUN with the DERP server handed back, so
// that a test can ask whether a node key is connected.
func startDERP(t *testing.T) derpRelay {
	t.Helper()
	d := derpserver.New(key.NewNode(), quietLogf)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpsrv := httptest.NewUnstartedServer(derpserver.AddWebSocketSupport(d, derpserver.Handler(d)))
	httpsrv.Listener.Close()
	httpsrv.Listener = ln
	httpsrv.Config.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	httpsrv.StartTLS()
	stunAddr, stunCleanup := stuntest.ServeWithPacketListener(t, nettype.Std{})
	reg := &tailcfg.DERPRegion{RegionID: 1, RegionCode: "test", Nodes: []*tailcfg.DERPNode{{
		Name: "t1", RegionID: 1, HostName: "127.0.0.1", IPv4: "127.0.0.1", IPv6: "none",
		STUNPort: stunAddr.Port, DERPPort: ln.Addr().(*net.TCPAddr).Port, InsecureForTests: true, STUNTestIP: "127.0.0.1",
	}}}
	t.Cleanup(func() {
		httpsrv.CloseClientConnections()
		httpsrv.Close()
		d.Close()
		stunCleanup()
		ln.Close()
	})
	return derpRelay{reg: reg, srv: d}
}

// listenCfg starts a listener with chosen keys and configuration changes, and
// closes it, bounded, at the end of the test.
func listenCfg(t *testing.T, reg *tailcfg.DERPRegion, nk, psk [32]byte, mod func(*ListenerConfig), allowed ...party.NodeKey) *Listener {
	t.Helper()
	cfg := ListenerConfig{NodeKey: KeyBytes(nk), PSK: KeyBytes(psk), Allowed: allowed, Region: reg, Logf: quietLogf, DrainTimeout: testDrain}
	if mod != nil {
		mod(&cfg)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	l, err := Listen(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		l.Close()
		select {
		case <-l.Done():
		case <-time.After(20 * time.Second):
			t.Error("the listener's teardown did not finish within 20 s of Close")
		}
	})
	return l
}

func randKeys(t *testing.T) (nk, psk [32]byte) {
	t.Helper()
	var err error
	if nk, err = RandomKey(); err != nil {
		t.Fatal(err)
	}
	if psk, err = RandomKey(); err != nil {
		t.Fatal(err)
	}
	return nk, psk
}

// dialerCfg builds a dialer for l as node n with configuration changes.
func dialerCfg(t *testing.T, l *Listener, n node, mod func(*DialerConfig)) *Dialer {
	t.Helper()
	addr, err := l.Address()
	if err != nil {
		t.Fatal(err)
	}
	cfg := DialerConfig{Address: SecretBytes([]byte(addr)), NodeKey: n.secret(), ExpectServerKey: l.NodeKey(), Logf: quietLogf, DialTimeout: 15 * time.Second, DrainTimeout: testDrain}
	if mod != nil {
		mod(&cfg)
	}
	d, err := NewDialer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		d.Close()
		select {
		case <-d.Done():
		case <-time.After(20 * time.Second):
			t.Error("the dialer's teardown did not finish within 20 s of Close")
		}
	})
	return d
}

// tcpEndpoints counts the endpoints registered in the netstack of a tailcat
// server: what the library's teardown has to abort one by one.
func tcpEndpoints(t *testing.T, ts *tc.Server) int {
	t.Helper()
	lb := reflect.ValueOf(ts).Elem().FieldByName("lb")
	if !lb.IsValid() || lb.IsNil() {
		t.Fatal("tailcat.Server has no lb: the library changed")
	}
	ns := lb.Elem().FieldByName("ns")
	if !ns.IsValid() || ns.IsNil() {
		t.Fatal("tailcat locoBackend has no ns: the library changed")
	}
	ipf := ns.Elem().FieldByName("ipstack")
	if !ipf.IsValid() {
		t.Fatal("netstack.Impl has no ipstack: the library changed")
	}
	st := reflect.NewAt(ipf.Type(), unsafe.Pointer(ipf.UnsafeAddr())).Elem().Interface().(*stack.Stack)
	return len(st.RegisteredEndpoints())
}

func settledInt(d time.Duration, limit int, get func() int) int {
	end := time.Now().Add(d)
	for {
		if v := get(); v <= limit || time.Now().After(end) {
			return v
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// ---- F1: Close racing a first Dial ----

// Close runs after Dial took the client and before it started it. Nothing may
// be left running after Done: no engine, no UDP socket, no goroutine, and the
// device is not connected to the DERP relay. A later Dial fails.
//
// spec: SPO-Xmailbox-INV-025
func TestCloseRacingTheFirstDialStartsNothing(t *testing.T) {
	t.Run("BeforeTheCancelCheck", func(t *testing.T) { raceCloseAgainstDial(t, false) })
	// Close lands after the dial passed its check: the engine is built by the
	// library's first use of the client, and only the teardown waiting for the
	// dial closes it.
	t.Run("AfterTheCancelCheck", func(t *testing.T) { raceCloseAgainstDial(t, true) })
}

func raceCloseAgainstDial(t *testing.T, afterCheck bool) {
	dr := startDERP(t)
	warm := newNode(t)
	lw := listenFresh(t, dr.reg, nil, warm.pub)
	connect(t, lw, dialerCfg(t, lw, warm, nil))
	n := newNode(t)
	l := listenFresh(t, dr.reg, nil, n.pub)
	baseG := settled(3*time.Second, 0, func() int { return runtime.NumGoroutine() })
	_, udp0 := allSockets(t)
	d := dialerCfg(t, l, n, nil)

	taken, gate := make(chan struct{}), make(chan struct{})
	var once sync.Once
	hook := func(*tc.Client) {
		once.Do(func() {
			close(taken)
			<-gate
		})
	}
	if afterCheck {
		d.beforeDial = hook
	} else {
		d.afterTake = hook
	}
	dialErr := make(chan error, 1)
	go func() {
		s, _, err := d.Dial(context.Background())
		if err == nil {
			s.Close()
		}
		dialErr <- err
	}()
	waitClosed(t, taken, 5*time.Second, "the first Dial reaching the seam")
	d.Close()
	time.Sleep(100 * time.Millisecond)
	close(gate)
	var err error
	select {
	case err = <-dialErr:
	case <-time.After(2 * time.Second):
		t.Errorf("a Dial that Close raced is still running 2 s after Close")
		err = <-dialErr
	}
	if !errors.Is(err, ErrDialerClosed) {
		t.Errorf("the raced Dial = %v, want ErrDialerClosed", err)
	}
	waitClosed(t, d.Done(), 10*time.Second, "the dialer's teardown")
	_, udp1 := allSockets(t)
	if ns := newSockets(udp0, udp1); len(ns) != 0 {
		t.Errorf("%d UDP sockets are open after Done: an engine was started after Close and nothing closes it: %+v", len(ns), ns)
	}
	if g := settled(10*time.Second, baseG+2, func() int { return runtime.NumGoroutine() }); g > baseG+2 {
		t.Errorf("goroutines %d after Done, %d before the dialer: an engine is still running", g, baseG)
	}
	if dr.srv.IsClientConnectedForTest(nodePublic(n.pub)) {
		t.Error("the device is still connected to the DERP relay after logout")
	}
	if _, _, err := d.Dial(context.Background()); !errors.Is(err, ErrDialerClosed) {
		t.Errorf("Dial after Close = %v, want ErrDialerClosed", err)
	}
}

func listenFresh(t *testing.T, reg *tailcfg.DERPRegion, mod func(*ListenerConfig), allowed ...party.NodeKey) *Listener {
	t.Helper()
	nk, psk := randKeys(t)
	return listenCfg(t, reg, nk, psk, mod, allowed...)
}

// Close cancels a Dial that is stalled: it returns at once, not after the dial
// budget.
//
// spec: SPO-Xmailbox-INV-025
func TestCloseCancelsAStalledDial(t *testing.T) {
	reg := relayRegion(t)
	l := startListener(t, reg, newNode(t).pub) // the dialer's key is not listed: nobody answers
	d := dialerFor(t, l, newNode(t))
	res := make(chan error, 1)
	go func() {
		s, _, err := d.Dial(context.Background())
		if err == nil {
			s.Close()
		}
		res <- err
	}()
	time.Sleep(1500 * time.Millisecond) // the engine is up and pinging
	start := time.Now()
	d.Close()
	select {
	case err := <-res:
		if took := time.Since(start); took > 200*time.Millisecond {
			t.Errorf("Dial returned %v after Close, want under 200 ms", took)
		}
		if !errors.Is(err, ErrDialerClosed) {
			t.Errorf("the cancelled Dial = %v, want ErrDialerClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a stalled Dial is still blocked 2 s after Close")
	}
	waitClosed(t, d.Done(), 10*time.Second, "the dialer's teardown")
}

// A dialer that dialed, and is closed, leaves nothing: no goroutine, no socket,
// and the relay's DERP server sees the device gone.
//
// spec: SPO-Xmailbox-INV-025
func TestDialerTeardownLeavesNothing(t *testing.T) {
	dr := startDERP(t)
	warm := newNode(t)
	lw := listenFresh(t, dr.reg, nil, warm.pub)
	connect(t, lw, dialerCfg(t, lw, warm, nil))
	n := newNode(t)
	l := listenFresh(t, dr.reg, nil, n.pub)
	baseG := settled(3*time.Second, 0, func() int { return runtime.NumGoroutine() })
	_, udp0 := allSockets(t)
	d := dialerCfg(t, l, n, nil)
	c, s, _, _ := connect(t, l, d)
	if err := roundTrip(c, s); err != nil {
		t.Fatal(err)
	}
	if !dr.srv.IsClientConnectedForTest(nodePublic(n.pub)) {
		t.Fatal("the dialer is not connected to the DERP relay while it works")
	}
	c.Close()
	s.Close()
	if err := d.CloseWithin(10 * time.Second); err != nil {
		t.Fatal(err)
	}
	_, udp1 := allSockets(t)
	if ns := newSockets(udp0, udp1); len(ns) != 0 {
		t.Errorf("%d UDP sockets open after Done: %+v", len(ns), ns)
	}
	if g := settled(10*time.Second, baseG+2, func() int { return runtime.NumGoroutine() }); g > baseG+2 {
		t.Errorf("goroutines %d after Done, %d before the dialer", g, baseG)
	}
	if got := settledInt(5*time.Second, 0, func() int {
		if dr.srv.IsClientConnectedForTest(nodePublic(n.pub)) {
			return 1
		}
		return 0
	}); got != 0 {
		t.Error("the DERP relay still reports the device as connected after Done")
	}
}

// ---- F2: a forged acknowledgment, a restart between the ack and the dial ----

// A third DERP client that knows only the party's public node key sends the
// "meowed" acknowledgment every 20 ms while the relay is down. The library
// believes it is registered; the relay comes back with the same keys and
// knows nobody. The dialer must recover within a bounded number of attempts.
//
// spec: SPO-Xmailbox-INV-026
func TestForgedAckWedgeIsRecovered(t *testing.T) {
	dr := startDERP(t)
	n := newNode(t)
	nk, psk := randKeys(t)
	l1 := listenCfg(t, dr.reg, nk, psk, nil, n.pub)
	d := dialerCfg(t, l1, n, func(c *DialerConfig) { c.DialTimeout = 3 * time.Second; c.MinRebuildInterval = 50 * time.Millisecond })
	l1.Close()
	waitClosed(t, l1.Done(), 10*time.Second, "the first relay's teardown")

	mon, err := netmon.New(eventbus.New(), quietLogf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mon.Close() })
	atk := derphttp.NewRegionClient(key.NewNode(), quietLogf, mon, func() *tailcfg.DERPRegion { return dr.reg })
	cctx, ccancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer ccancel()
	if err := atk.Connect(cctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { atk.Close() })
	stop, stopped := make(chan struct{}), make(chan struct{})
	var stopOnce sync.Once
	stopAttack := func() { stopOnce.Do(func() { close(stop) }); <-stopped }
	go func() {
		defer close(stopped)
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
				atk.Send(nodePublic(n.pub), tc.EncodeMeowed())
			}
		}
	}()
	t.Cleanup(stopAttack)

	// the caller's own deadline, shorter than the dialer's budget, ends the dial:
	// the tunnel must be replaced then too
	ctx1, c1 := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	if s, _, err := d.Dial(ctx1); err == nil {
		s.Close()
		t.Fatal("a Dial succeeded with the relay down")
	}
	c1()
	stopAttack()

	l2 := listenCfg(t, dr.reg, nk, psk, nil, n.pub)
	_ = l2
	var last error
	for attempt := 1; attempt <= 3; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		s, _, err := d.Dial(ctx)
		cancel()
		if err == nil {
			s.Close()
			if attempt != 1 {
				t.Errorf("recovered only at attempt %d: the tunnel that the caller's deadline ended was not replaced at once", attempt)
			}
			return
		}
		last = err
	}
	t.Fatalf("the dialer never recovered from a forged acknowledgment in 3 attempts with the relay back: %v", last)
}

// The same wedge without an attacker: the relay restarts between the first
// acknowledgment and the first successful TCP dial.
//
// spec: SPO-Xmailbox-INV-026
func TestRelayRestartBetweenTheAckAndTheFirstDial(t *testing.T) {
	reg := relayRegion(t)
	n := newNode(t)
	nk, psk := randKeys(t)
	l1 := listenCfg(t, reg, nk, psk, nil, n.pub)
	d := dialerCfg(t, l1, n, func(c *DialerConfig) { c.DialTimeout = 3 * time.Second; c.MinRebuildInterval = 50 * time.Millisecond })
	var once sync.Once
	d.afterTake = func(c *tc.Client) {
		once.Do(func() {
			pctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := c.Ping(pctx); err != nil { // the relay acknowledges: registered with l1
				t.Errorf("Ping: %v", err)
			}
			l1.Close()
			waitClosed(t, l1.Done(), 10*time.Second, "the first relay's teardown")
			listenCfg(t, reg, nk, psk, nil, n.pub) // restarted, knows nobody
		})
	}
	var last error
	for attempt := 1; attempt <= 3; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		s, _, err := d.Dial(ctx)
		cancel()
		if err == nil {
			s.Close()
			t.Logf("recovered at attempt %d", attempt)
			return
		}
		last = err
	}
	t.Fatalf("a dialer whose relay restarted between the ack and the first dial never recovered in 3 attempts: %v", last)
}

// Rebuilds are bounded: one per failed dial and no more often than the
// interval, by an injected clock.
//
// spec: SPO-Xmailbox-INV-026
func TestRebuildsAreRateLimited(t *testing.T) {
	reg := relayRegion(t)
	l := startListener(t, reg, newNode(t).pub) // the dialer's key is not listed: every dial fails
	var mu sync.Mutex
	now := time.Unix(1_000_000, 0)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	d := dialerCfg(t, l, newNode(t), func(c *DialerConfig) {
		c.DialTimeout = 400 * time.Millisecond
		c.MinRebuildInterval = 30 * time.Second
		c.Now = clock
	})
	fail := func() {
		t.Helper()
		if s, _, err := d.Dial(context.Background()); err == nil {
			s.Close()
			t.Fatal("a Dial to a relay that does not list the key succeeded")
		}
	}
	fail()
	if got := d.rebuilds.Load(); got != 1 {
		t.Fatalf("after the first failed dial rebuilds = %d, want 1", got)
	}
	fail()
	if got := d.rebuilds.Load(); got != 1 {
		t.Fatalf("a second failed dial within the interval rebuilt again: rebuilds = %d, want 1", got)
	}
	mu.Lock()
	now = now.Add(31 * time.Second)
	mu.Unlock()
	fail()
	if got := d.rebuilds.Load(); got != 2 {
		t.Fatalf("after the interval rebuilds = %d, want 2", got)
	}
}

// ---- F3: teardown with many endpoints, caps, a stuck teardown ----

// acceptAll accepts streams until the listener closes and keeps them open.
type acceptAll struct {
	mu sync.Mutex
	ss []relayport.Stream
}

func (a *acceptAll) run(l *Listener) {
	go func() {
		for {
			s, _, err := l.Accept(context.Background())
			if err != nil {
				if errors.Is(err, relayport.ErrListenerClosed) {
					return
				}
				continue
			}
			a.mu.Lock()
			a.ss = append(a.ss, s)
			a.mu.Unlock()
		}
	}()
}

// isReset reports a dial that the listener answered with a reset: tailcat's
// netstack gives the error as text ("connection reset by peer"), not as an errno.
func isReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) || strings.Contains(err.Error(), "connection reset by peer")
}

// Connections that stay open do not stop the teardown: just under the cap
// they complete, and far over it the cap sheds the rest abortively, so the
// netstack never holds the number of endpoints at which tailcat's close
// deadlocks (more than about 512).
//
// A shed connection is reset as soon as the listener takes it from the netstack.
// The dialer's netstack usually reports the connection established before that
// reset arrives, but on a loaded machine the reset can be handled first, and the
// Dial itself then fails with "connection reset by peer". That is the listener
// doing what it must (over the cap, or with its backlog full), not a fault of
// the dialer: such a dial is counted, and the test checks that the listener did
// shed at least as many connections as there were reset dials. A retry would
// only be shed again.
//
// spec: SPO-Xmailbox-INV-027
func TestTeardownCompletesWithManyOpenConnections(t *testing.T) {
	for _, sz := range []struct {
		name string
		n    int
	}{{"UnderTheCap", 250}, {"OverTheCap", 600}} {
		t.Run(sz.name, func(t *testing.T) {
			reg := relayRegion(t)
			n := newNode(t)
			nk, psk := randKeys(t)
			l := listenCfg(t, reg, nk, psk, nil, n.pub)
			d := dialerCfg(t, l, n, func(c *DialerConfig) { c.MaxStreams = 1000 })
			var acc acceptAll
			acc.run(l)
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			var held []relayport.Stream
			resets := 0
			for i := 0; i < sz.n; i++ {
				s, _, err := d.Dial(ctx)
				if err != nil {
					if isReset(err) { // shed by the listener before the dial returned
						resets++
						continue
					}
					t.Fatalf("Dial %d: %v", i, err)
				}
				held = append(held, s)
			}
			// every connection the dialer made reaches the listener: accepted or shed
			st := l.Stats()
			for wait := time.Now().Add(20 * time.Second); st.Accepted+st.Shed < int64(sz.n) && time.Now().Before(wait); st = l.Stats() {
				time.Sleep(20 * time.Millisecond)
			}
			t.Logf("%d dialed: held %d, reset at dial %d; accepted %d, shed %d, endpoints %d", sz.n, len(held), resets, st.Accepted, st.Shed, tcpEndpoints(t, l.server()))
			if st.Accepted+st.Shed < int64(sz.n) {
				t.Fatalf("the listener saw %d connections of the %d dialled", st.Accepted+st.Shed, sz.n)
			}
			if int64(resets) > st.Shed {
				t.Fatalf("%d dials were reset but the listener shed only %d: a reset that is not a shed", resets, st.Shed)
			}
			// the teardown below must face many open connections, or it proves nothing
			if floor := int64(min(sz.n, DefaultListenerMaxStreams) / 2); st.Accepted < floor {
				t.Fatalf("only %d connections are open at the listener, fewer than %d", st.Accepted, floor)
			}
			if sz.n > DefaultListenerMaxStreams && st.Accepted > int64(DefaultListenerMaxStreams) {
				t.Errorf("accepted %d streams, the cap is %d", st.Accepted, DefaultListenerMaxStreams)
			}
			if sz.n > DefaultListenerMaxStreams && st.Shed < int64(sz.n-DefaultListenerMaxStreams) {
				t.Errorf("shed %d connections of %d over the cap", st.Shed, sz.n-DefaultListenerMaxStreams)
			}
			if err := l.CloseWithin(30 * time.Second); err != nil {
				t.Fatalf("the teardown with %d open connections: %v", sz.n, err)
			}
			for _, s := range held {
				s.Close()
			}
		})
	}
}

// The dialer caps its open streams.
//
// spec: SPO-Xmailbox-INV-027
func TestDialerStreamCap(t *testing.T) {
	reg := relayRegion(t)
	n := newNode(t)
	l := startListener(t, reg, n.pub)
	d := dialerCfg(t, l, n, func(c *DialerConfig) { c.MaxStreams = 2 })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var ss []relayport.Stream
	for i := 0; i < 2; i++ {
		s, _, err := d.Dial(ctx)
		if err != nil {
			t.Fatal(err)
		}
		ss = append(ss, s)
	}
	if s, _, err := d.Dial(ctx); !errors.Is(err, ErrTooManyStreams) {
		if err == nil {
			s.Close()
		}
		t.Fatalf("the third Dial with a cap of 2 = %v, want ErrTooManyStreams", err)
	}
	ss[0].Close()
	s, _, err := d.Dial(ctx)
	deadline := time.Now().Add(5 * time.Second) // the closing stream is released when it has drained
	for errors.Is(err, ErrTooManyStreams) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		s, _, err = d.Dial(ctx)
	}
	if err != nil {
		t.Fatalf("Dial after a stream was closed: %v", err)
	}
	s.Close()
}

// A teardown that does not finish is reported within the bound, as an error
// and as an event, and Done stays open: the caller (the relay process) can
// exit instead of waiting.
//
// spec: SPO-Xmailbox-INV-027
func TestStuckTeardownIsReportedWithinTheBound(t *testing.T) {
	reg := relayRegion(t)
	n := newNode(t)
	nk, psk := randKeys(t)
	events := make(chan error, 4)
	onStuck := func(err error) {
		select {
		case events <- err:
		default:
		}
	}
	release := make(chan struct{})
	l := listenCfg(t, reg, nk, psk, func(c *ListenerConfig) { c.TeardownTimeout = 300 * time.Millisecond; c.OnTeardownStuck = onStuck }, n.pub)
	l.testBeforeEngineClose = func() { <-release }
	d := dialerCfg(t, l, n, func(c *DialerConfig) { c.TeardownTimeout = 300 * time.Millisecond; c.OnTeardownStuck = onStuck })
	d.testBeforeEngineClose = func() { <-release }
	t.Cleanup(func() { close(release) }) // registered last, so it runs first: the cleanups above wait for Done
	connect(t, l, d)

	for name, closeWithin := range map[string]func(time.Duration) error{"listener": l.CloseWithin, "dialer": d.CloseWithin} {
		start := time.Now()
		err := within(t, 500*time.Millisecond, name+" CloseWithin", func() error { return closeWithin(500 * time.Millisecond) })
		if !errors.Is(err, ErrTeardownStuck) {
			t.Fatalf("%s: CloseWithin of a stuck teardown = %v, want ErrTeardownStuck", name, err)
		}
		if took := time.Since(start); took > 1500*time.Millisecond {
			t.Errorf("%s: CloseWithin took %v for a bound of 500 ms", name, took)
		}
		select {
		case e := <-events:
			if !errors.Is(e, ErrTeardownStuck) {
				t.Errorf("%s: the event carried %v", name, e)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: no teardown-stuck event within 2 s", name)
		}
	}
	select {
	case <-l.Done():
		t.Fatal("Done closed while the teardown is stuck")
	default:
	}
}

// ---- F4: refused connections, removal ----

// tcpLike is a connection with what the stack's endpoint offers: CloseWrite
// and SetLinger, recorded.
type tcpLike struct {
	net.Conn
	mu        sync.Mutex
	cw        bool
	closed    bool
	lingerSet bool
	linger    int
}

func newTCPLike(c net.Conn) *tcpLike { return &tcpLike{Conn: c} }

func (c *tcpLike) CloseWrite() error { c.mu.Lock(); c.cw = true; c.mu.Unlock(); return nil }
func (c *tcpLike) SetLinger(sec int) error {
	c.mu.Lock()
	c.lingerSet, c.linger = true, sec
	c.mu.Unlock()
	return nil
}
func (c *tcpLike) Close() error { c.mu.Lock(); c.closed = true; c.mu.Unlock(); return c.Conn.Close() }
func (c *tcpLike) state() (cw, closed, lingerSet bool, linger int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cw, c.closed, c.lingerSet, c.linger
}

// feedL is feed with a connection that records how it was closed.
func (r *unitRig) feedL(k party.NodeKey, known bool) (*tcpLike, net.Conn) {
	near, far := net.Pipe()
	lc := newTCPLike(near)
	if known {
		r.mu.Lock()
		r.keys[lc] = k
		r.mu.Unlock()
	}
	r.ln.conns <- lc
	return lc, far
}

func expectAborted(t *testing.T, lc *tcpLike, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, closed, _, _ := lc.state(); closed {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	_, closed, lingerSet, linger := lc.state()
	if !closed {
		t.Fatalf("%s: the connection was not closed", what)
	}
	if !lingerSet || linger != 0 {
		t.Fatalf("%s: closed gracefully (linger set %v, %d): a peer that keeps its end open leaves an endpoint behind for 60 s; want an abortive close (linger 0)", what, lingerSet, linger)
	}
}

// Refused, unidentified, over-the-cap and over-the-backlog connections are
// closed abortively: the endpoint is gone at once.
//
// spec: SPO-Xmailbox-SEC-035
func TestRefusedShedAndUnidentifiedConnectionsAreAborted(t *testing.T) {
	r := newUnitRigWith(t, 1, func(l *Listener) { l.maxStreams = 2 }, nk(1))
	bad, farBad := r.feedL(nk(9), true)
	defer farBad.Close()
	expectAborted(t, bad, "a key that is not listed")
	unk, farUnk := r.feedL(nk(1), false)
	defer farUnk.Close()
	expectAborted(t, unk, "a connection the tunnel names no key for")
	// one stream fills the backlog (1); the next is over the backlog
	ok1, far1 := r.feedL(nk(1), true)
	defer far1.Close()
	deadline := time.Now().Add(3 * time.Second)
	for len(r.l.backlog) < 1 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	over, farOver := r.feedL(nk(1), true)
	defer farOver.Close()
	expectAborted(t, over, "a connection over the backlog")
	if _, closed, _, _ := ok1.state(); closed {
		t.Fatal("the queued stream was closed")
	}
	// accept it, queue another (2 live), then a third is over the stream cap
	if _, _, err := acceptWithin(t, r.l, 3*time.Second); err != nil {
		t.Fatal(err)
	}
	ok2, far2 := r.feedL(nk(1), true)
	defer far2.Close()
	deadline = time.Now().Add(3 * time.Second)
	for len(r.l.backlog) < 1 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	capd, farCap := r.feedL(nk(1), true)
	defer farCap.Close()
	expectAborted(t, capd, "a connection over the stream cap")
	if _, closed, _, _ := ok2.state(); closed {
		t.Fatal("the second stream was closed")
	}
}

// The stream cap counts the streams waiting and handed out, and a stream that
// is closed frees its place.
//
// spec: SPO-Xmailbox-INV-027
func TestListenerStreamCapIsEnforced(t *testing.T) {
	r := newUnitRigWith(t, 8, func(l *Listener) { l.maxStreams = 3 }, nk(1))
	var fars []net.Conn
	var ncs []*tcpLike
	for range 3 {
		lc, far := r.feedL(nk(1), true)
		ncs = append(ncs, lc)
		fars = append(fars, far)
	}
	var held []relayport.Stream
	for range 3 {
		s, _, err := acceptWithin(t, r.l, 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, s)
	}
	over, farOver := r.feedL(nk(1), true)
	defer farOver.Close()
	expectAborted(t, over, "the fourth stream with a cap of 3")
	deadline := time.Now().Add(3 * time.Second)
	for r.l.Stats().Shed < 1 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if st := r.l.Stats(); st.Shed != 1 {
		t.Fatalf("stats %+v, want one shed", st)
	}
	relayport.Abort(held[0])
	// the place is free: the next one is accepted
	again, farAgain := r.feedL(nk(1), true)
	defer farAgain.Close()
	if _, _, err := acceptWithin(t, r.l, 3*time.Second); err != nil {
		t.Fatalf("a stream after one was closed: %v", err)
	}
	_ = again
	for _, f := range fars {
		f.Close()
	}
	_ = ncs
}

// The flood of the review: a removed key, still admitted by the tunnel, opens
// connections and keeps its end open. None lingers on the relay, and memory
// does not grow over three rounds.
//
// spec: SPO-Xmailbox-SEC-035
func TestRemovedKeyFloodLeavesNoEndpoints(t *testing.T) {
	reg := relayRegion(t)
	a, b := newNode(t), newNode(t)
	nk, psk := randKeys(t)
	l := listenCfg(t, reg, nk, psk, func(c *ListenerConfig) { c.KeepTunnelOnRemoval = true }, a.pub, b.pub)
	da := dialerCfg(t, l, a, func(c *DialerConfig) { c.MaxStreams = 1000 })
	connect(t, l, da) // the tunnel is up
	if err := l.SetAllowed([]party.NodeKey{b.pub}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	base := tcpEndpoints(t, l.server())
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var heap []uint64
	for round := 1; round <= 3; round++ {
		var held []relayport.Stream
		for i := 0; i < 300; i++ {
			s, _, err := da.Dial(ctx)
			if err != nil {
				t.Fatalf("round %d dial %d: %v", round, i, err)
			}
			held = append(held, s) // the peer keeps its end open
		}
		n := settledInt(3*time.Second, base+5, func() int { return tcpEndpoints(t, l.server()) })
		if n > base+5 {
			t.Fatalf("round %d: %d endpoints linger on the relay after 300 refused connections (baseline %d): each costs ~13 KiB for 60 s", round, n, base)
		}
		for _, s := range held {
			relayport.Abort(s)
		}
		runtime.GC()
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		heap = append(heap, ms.HeapInuse)
	}
	t.Logf("heap in use after each round: %v", heap)
	if heap[2] > heap[0]+24<<20 {
		t.Fatalf("memory grew from %d to %d bytes over three rounds", heap[0], heap[2])
	}
}

// Removal is real: SetAllowed rebuilds the tunnel with the same identity and
// the remaining keys. The removed key no longer forms a tunnel, the others
// recover through the dialer's rebuild, the address is unchanged and a key
// listed again connects.
//
// spec: SPO-Xmailbox-SEC-035
func TestRemovalRebuildsTheTunnel(t *testing.T) {
	reg := relayRegion(t)
	a, b := newNode(t), newNode(t)
	nk, psk := randKeys(t)
	l := listenCfg(t, reg, nk, psk, func(c *ListenerConfig) { c.RebuildGap = 50 * time.Millisecond }, a.pub, b.pub)
	mod := func(c *DialerConfig) { c.DialTimeout = 4 * time.Second; c.MinRebuildInterval = 50 * time.Millisecond }
	da, db := dialerCfg(t, l, a, mod), dialerCfg(t, l, b, mod)
	addr0, _ := l.Address()
	ca, sa, _, _ := connect(t, l, da)
	cb, sb, _, _ := connect(t, l, db)
	if err := roundTrip(cb, sb); err != nil {
		t.Fatal(err)
	}
	if err := l.SetAllowed([]party.NodeKey{b.pub}); err != nil {
		t.Fatal(err)
	}
	if err := readErr(t, sa, 5*time.Second); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the removed key's stream on the relay: %v", err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for l.Stats().Rebuilds < 1 && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}
	if got := l.Stats().Rebuilds; got != 1 {
		t.Fatalf("rebuilds = %d after removing a key, want 1", got)
	}
	if addr1, _ := l.Address(); addr1 != addr0 {
		t.Fatal("the rebuild changed the relay's address")
	}
	if err := readErr(t, ca, 5*time.Second); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the removed key's stream at the dialer: %v", err)
	}
	if err := readErr(t, cb, 5*time.Second); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the kept key's stream survived the tunnel rebuild: %v", err)
	}
	cb.Close()
	sb.Close()
	ca.Close()
	sa.Close()
	// the kept key recovers
	var recovered bool
	for attempt := 1; attempt <= 3 && !recovered; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		s, _, err := db.Dial(ctx)
		cancel()
		if err == nil {
			s.Close()
			recovered = true
		}
	}
	if !recovered {
		t.Fatal("the kept key did not recover after the rebuild in 3 attempts")
	}
	// the removed key does not form a tunnel
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	if s, _, err := da.Dial(ctx); err == nil {
		s.Close()
		t.Fatal("the removed key connected")
	}
	cancel()
	if st := l.Stats(); st.Refused != 0 {
		t.Fatalf("stats %+v: the removed key reached our accept, so the tunnel still admits it", st)
	}
	// listed again: it connects, and no rebuild was needed
	if err := l.SetAllowed([]party.NodeKey{a.pub, b.pub}); err != nil {
		t.Fatal(err)
	}
	recovered = false
	for attempt := 1; attempt <= 3 && !recovered; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		s, _, err := da.Dial(ctx)
		cancel()
		if err == nil {
			s.Close()
			recovered = true
		}
	}
	if !recovered {
		t.Fatal("a key listed again did not connect in 3 attempts")
	}
	if got := l.Stats().Rebuilds; got != 1 {
		t.Fatalf("adding a key rebuilt the tunnel: rebuilds = %d", got)
	}
}

// Abort on a real stream is a reset: the peer sees a connection error, not a
// clean end, and the relay's endpoint is gone at once.
//
// spec: SPO-Xmailbox-SEC-035
func TestAbortSendsAReset(t *testing.T) {
	reg := relayRegion(t)
	n := newNode(t)
	l := startListener(t, reg, n.pub)
	c, s, _, _ := connect(t, l, dialerFor(t, l, n))
	if err := roundTrip(c, s); err != nil {
		t.Fatal(err)
	}
	if got := tcpEndpoints(t, l.server()); got != 1 {
		t.Logf("endpoints before Abort: %d", got)
	}
	relayport.Abort(s)
	err := readErr(t, c, 5*time.Second)
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the peer of an aborted stream read %v, want a connection reset", err)
	}
	if got := settledInt(3*time.Second, 0, func() int { return tcpEndpoints(t, l.server()) }); got != 0 {
		t.Fatalf("%d endpoints are left on the relay after Abort", got)
	}
}

// Rebuilds are spaced by RebuildGap and merged: two removals in a row cause
// one rebuild at once and the second no earlier than the gap later.
//
// spec: SPO-Xmailbox-SEC-035
func TestListenerRebuildsAreSpacedByTheGap(t *testing.T) {
	reg := relayRegion(t)
	a, b, c := newNode(t), newNode(t), newNode(t)
	l := listenFresh(t, reg, func(cfg *ListenerConfig) { cfg.RebuildGap = 1500 * time.Millisecond }, a.pub, b.pub, c.pub)
	if err := l.SetAllowed([]party.NodeKey{b.pub, c.pub}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for l.Stats().Rebuilds < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if l.Stats().Rebuilds != 1 {
		t.Fatalf("rebuilds = %d, want 1", l.Stats().Rebuilds)
	}
	first := time.Now()
	if err := l.SetAllowed([]party.NodeKey{c.pub}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(600 * time.Millisecond)
	if got := l.Stats().Rebuilds; got != 1 {
		t.Fatalf("a second removal rebuilt the tunnel %v after the first: rebuilds = %d, want it to wait for the gap", time.Since(first), got)
	}
	for l.Stats().Rebuilds < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := l.Stats().Rebuilds; got != 2 {
		t.Fatalf("rebuilds = %d after the gap, want 2", got)
	}
}

// ---- F5: the lingering close ----

func newLingerStream(c net.Conn, d time.Duration, max int) *Stream {
	s := newStream(c, nil)
	s.ling = newLingerer(d, max)
	return s
}

// Close returns at once, sends FIN (CloseWrite) first, discards inbound data
// until the peer's end, and only then closes the connection.
//
// spec: SPO-Xmailbox-INV-022
func TestCloseLingersUntilThePeerEnds(t *testing.T) {
	near, far := net.Pipe()
	lc := newTCPLike(near)
	s := newLingerStream(lc, 5*time.Second, 4)
	start := time.Now()
	s.Close()
	if took := time.Since(start); took > 100*time.Millisecond {
		t.Fatalf("Close took %v", took)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cw, _, _, _ := lc.state(); cw {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	cw, closed, _, _ := lc.state()
	if !cw || closed {
		t.Fatalf("after Close: CloseWrite %v, closed %v; want CloseWrite called and the connection still open for the peer's data", cw, closed)
	}
	// the peer sends more than we read, then ends: all of it is discarded
	go func() { far.Write(make([]byte, 100)); far.Close() }()
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, closed, _, _ := lc.state(); closed {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the connection was not closed after the peer's end")
}

// The linger is bounded in time: a peer that never ends is cut off.
//
// spec: SPO-Xmailbox-INV-022
func TestLingerIsBoundedInTime(t *testing.T) {
	near, far := net.Pipe()
	defer far.Close()
	lc := newTCPLike(near)
	s := newLingerStream(lc, 150*time.Millisecond, 4)
	go func() { // endless data
		buf := make([]byte, 512)
		for {
			if _, err := far.Write(buf); err != nil {
				return
			}
		}
	}()
	s.Close()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, closed, _, _ := lc.state(); closed {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("a peer that sends for ever kept a closed stream open past its linger bound")
}

// The number of lingering closers is bounded: beyond it a stream is closed
// abortively.
//
// spec: SPO-Xmailbox-INV-022
func TestLingeringClosersAreBounded(t *testing.T) {
	var lcs []*tcpLike
	var fars []net.Conn
	lg := newLingerer(400*time.Millisecond, 2)
	for range 3 {
		near, far := net.Pipe()
		lc := newTCPLike(near)
		s := newStream(lc, nil)
		s.ling = lg
		lcs = append(lcs, lc)
		fars = append(fars, far)
		defer far.Close()
		s.Close()
		time.Sleep(30 * time.Millisecond)
	}
	for i, lc := range lcs[:2] {
		if cw, closed, _, _ := lc.state(); !cw || closed {
			t.Errorf("closer %d (within the bound): CloseWrite %v, closed %v; want it lingering", i, cw, closed)
		}
	}
	expectAborted(t, lcs[2], "the closer over the bound")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, c0, _, _ := lcs[0].state()
		_, c1, _, _ := lcs[1].state()
		if c0 && c1 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the lingering streams were not closed at the end of their linger")
}

// Abort resets at once, also a stream that is already lingering.
//
// spec: SPO-Xmailbox-INV-022
func TestAbortIsImmediateAndEndsALinger(t *testing.T) {
	near, far := net.Pipe()
	defer far.Close()
	lc := newTCPLike(near)
	s := newLingerStream(lc, 5*time.Second, 4)
	s.Close() // lingering
	time.Sleep(50 * time.Millisecond)
	s.Abort()
	expectAborted(t, lc, "an aborted lingering stream")
	if _, err := s.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write after Abort = %v, want net.ErrClosed", err)
	}
}

// ---- F8 ----

type accRes struct {
	s   relayport.Stream
	k   party.NodeKey
	err error
}

// Accept never returns a stream with a nil error once the listener is closed:
// the closed state is checked again after a stream was taken.
//
// spec: SPO-Xmailbox-IF-013
func TestAcceptNeverReturnsAStreamOfAClosedListener(t *testing.T) {
	for i := range 100 {
		r := newUnitRig(t, 4, nk(1))
		_, far := r.feedL(nk(1), true)
		deadline := time.Now().Add(3 * time.Second)
		for len(r.l.backlog) < 1 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		r.l.testAcceptRace = func() { r.l.Close() } // Close lands between the two selects
		res := within(t, time.Second, "Accept", func() accRes {
			s, k, err := r.l.Accept(context.Background())
			return accRes{s, k, err}
		})
		if res.err == nil {
			t.Fatalf("iteration %d: Accept returned a stream (%v) with a nil error after Close", i, res.s != nil)
		}
		if !errors.Is(res.err, relayport.ErrListenerClosed) {
			t.Fatalf("iteration %d: Accept = %v, want ErrListenerClosed", i, res.err)
		}
		far.Close()
	}
}

// The window of Close: the listener is marked closed and its streams have not
// been reset yet. A stream taken in that window is not handed out.
//
// spec: SPO-Xmailbox-IF-013
func TestAcceptNeverReturnsAStreamInTheWindowOfClose(t *testing.T) {
	for i := range 50 {
		r := newUnitRig(t, 4, nk(1))
		_, far := r.feedL(nk(1), true)
		deadline := time.Now().Add(3 * time.Second)
		for len(r.l.backlog) < 1 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		r.l.testAcceptRace = func() {
			r.l.mu.Lock()
			r.l.closed = true
			close(r.l.done)
			r.l.mu.Unlock()
		}
		res := within(t, time.Second, "Accept", func() accRes {
			s, k, err := r.l.Accept(context.Background())
			return accRes{s, k, err}
		})
		close(r.l.torn) // the hook closed the listener by hand: there is no teardown to wait for
		if res.err == nil {
			t.Fatalf("iteration %d: Accept returned a stream with a nil error while the listener was closing", i)
		}
		far.Close()
	}
}

// A dial that succeeds on a tunnel that was retired meanwhile does not hand
// out a stream that is about to die.
//
// spec: SPO-Xmailbox-INV-026
func TestStreamFromARetiredTunnelIsNotHandedOut(t *testing.T) {
	reg := relayRegion(t)
	n := newNode(t)
	l := startListener(t, reg, n.pub)
	d := dialerFor(t, l, n)
	first := d.tcc
	if !d.retire(first) {
		t.Fatal("an idle tunnel was not retired")
	}
	near, far := net.Pipe()
	defer far.Close()
	s, _, err := d.register(first, near)
	if err == nil {
		s.Close()
		t.Fatal("a stream of a retired tunnel was handed out")
	}
	far.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := far.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("the stream of the retired tunnel was not closed: %v", err)
	}
}

// A dial that succeeds on a tunnel that is replaced before the stream is
// registered does not fail: the stream is closed and the dial goes once more on
// the new tunnel, and what it returns works.
//
// spec: SPO-Xmailbox-INV-026
func TestDialOnATunnelRetiredMidDialIsRetried(t *testing.T) {
	reg := relayRegion(t)
	n := newNode(t)
	l := startListener(t, reg, n.pub)
	d := dialerCfg(t, l, n, func(c *DialerConfig) { c.MinRebuildInterval = 10 * time.Millisecond })
	var once sync.Once
	d.beforeRegister = func(tun *tunnel) {
		once.Do(func() {
			if !d.retire(tun) {
				t.Error("the tunnel could not be retired mid-dial")
			}
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, _, err := d.Dial(ctx)
	if err != nil {
		t.Fatalf("a Dial whose tunnel was replaced mid-dial = %v, want it to retry on the new tunnel", err)
	}
	defer c.Close()
	if got := d.rebuilds.Load(); got != 1 {
		t.Fatalf("rebuilds = %d, want 1", got)
	}
	// the relay accepted the reset connection of the first try, then ours
	var worked bool
	for range 2 {
		s, _, err := l.Accept(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if roundTripWithin(c, s, 3*time.Second) == nil {
			worked = true
			break
		}
	}
	if !worked {
		t.Fatal("the stream that Dial returned does not work")
	}
}

// The private key the dialer holds for its lifetime is cleared when the
// dialer is closed.
//
// spec: SPO-Xmailbox-INV-023
func TestDialerClearsItsNodeKeyOnClose(t *testing.T) {
	reg := relayRegion(t)
	n := newNode(t)
	l := startListener(t, reg, n.pub)
	d := dialerFor(t, l, n)
	d.mu.Lock()
	held := !d.priv.IsZero() && !d.tcc.c.Key.IsZero() && d.addr != "" && d.tcc.c.Server != ""
	tun := d.tcc
	d.mu.Unlock()
	if !held {
		t.Fatal("the dialer holds no key or address before Close: the test does not test anything")
	}
	if err := d.CloseWithin(10 * time.Second); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	zero := d.priv.IsZero()
	d.mu.Unlock()
	if !zero {
		t.Fatal("the dialer still holds the node private key after Close")
	}
	// the copies this package made for the tunnel library: the client's key (a
	// value it can clear once the engine is closed) and the address string
	// (dropped, not wiped: a Go string cannot be); the library's own copies are
	// out of reach (SPO-Xmailbox-SEC-083)
	if !tun.c.Key.IsZero() || tun.c.Server != "" || d.addr != "" {
		t.Fatal("the tunnel client's key or the relay address is still held after Close")
	}
}

// A dial that finishes after Close does not hand out its stream: the connection
// is reset and the dialer is closed.
//
// spec: SPO-Xmailbox-INV-025
func TestStreamOfADialFinishingAfterCloseIsNotHandedOut(t *testing.T) {
	reg := relayRegion(t)
	n := newNode(t)
	l := startListener(t, reg, n.pub)
	d := dialerFor(t, l, n)
	tun := d.tcc
	d.Close()
	near, far := net.Pipe()
	defer far.Close()
	s, _, err := d.register(tun, near)
	if s != nil || !errors.Is(err, ErrDialerClosed) {
		t.Fatalf("register after Close = %v, %v; want ErrDialerClosed and no stream", s, err)
	}
	far.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := far.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("the connection of the late dial was not closed: %v", err)
	}
}

// A stream that SetAllowed revoked while it waited in the backlog is not handed
// out by Accept.
//
// spec: SPO-Xmailbox-SEC-033
func TestAcceptSkipsAStreamRevokedWhileItWaited(t *testing.T) {
	r := newUnitRig(t, 4, nk(1), nk(2))
	_, far1 := r.feedL(nk(1), true)
	defer far1.Close()
	_, far2 := r.feedL(nk(2), true)
	defer far2.Close()
	deadline := time.Now().Add(3 * time.Second)
	for len(r.l.backlog) < 2 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if err := r.l.SetAllowed([]party.NodeKey{nk(2)}); err != nil { // key 1 is revoked while its stream waits
		t.Fatal(err)
	}
	s, k, err := acceptWithin(t, r.l, 3*time.Second)
	if err != nil || k != nk(2) {
		t.Fatalf("Accept = %x, %v; want the stream of key 2 and not the revoked one", k, err)
	}
	s.Close()
}

// After Close or Abort a deadline is refused, so that it cannot undo the
// deadline that unblocked a pending operation.
//
// spec: SPO-Xmailbox-INV-022
func TestDeadlineAfterCloseIsNotApplied(t *testing.T) {
	near, far := net.Pipe()
	defer far.Close()
	s := newStream(near, nil)
	s.Close()
	for name, err := range map[string]error{
		"SetDeadline":      s.SetDeadline(time.Now().Add(time.Hour)),
		"SetReadDeadline":  s.SetReadDeadline(time.Now().Add(time.Hour)),
		"SetWriteDeadline": s.SetWriteDeadline(time.Now().Add(time.Hour)),
	} {
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("%s after Close = %v, want net.ErrClosed", name, err)
		}
	}
}

var _ atomic.Int64
