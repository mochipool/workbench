package stream

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// nilAddrConn is a connection whose endpoint was reset before it was admitted:
// gonet's TCPConn.RemoteAddr (and LocalAddr) then return nil.
type nilAddrConn struct {
	net.Conn
	local, remote net.Addr
}

func (c nilAddrConn) LocalAddr() net.Addr  { return c.local }
func (c nilAddrConn) RemoteAddr() net.Addr { return c.remote }

// A connection reset between tailcat's accept and the peer lookup has no
// address; tailcat's PeerEnv dereferences it (tailcat_exec.go, PeerEnv:
// remote.String()), which crashed the relay process under the race detector in
// a rebuild test. Such a connection is unidentified and closed, never a panic.
//
// spec: SPO-Xmailbox-SEC-086
func TestAConnectionWithoutAnAddressIsUnidentified(t *testing.T) {
	env := func(local, remote net.Addr) []string {
		return []string{"TAILCAT_REMOTE_ADDR=" + remote.String(), "TAILCAT_LOCAL_ADDR=" + local.String()} // panics on nil, as tailcat does
	}
	peer := peerFunc(env, nil)
	addr := &net.TCPAddr{IP: net.IPv4(100, 64, 0, 1), Port: 1}
	for name, c := range map[string]net.Conn{
		"no remote": nilAddrConn{local: addr},
		"no local":  nilAddrConn{remote: addr},
		"neither":   nilAddrConn{},
	} {
		if _, ok := peer(c); ok {
			t.Errorf("%s: identified", name)
		}
	}
	// A panic inside the library's lookup is an unidentified connection too.
	if _, ok := peerFunc(func(net.Addr, net.Addr) []string { panic("library bug") }, nil)(nilAddrConn{local: addr, remote: addr}); ok {
		t.Error("a panicking lookup: identified")
	}
	key := "nodekey:" + "0102030405060708091011121314151617181920212223242526272829303132"
	got, ok := peerFunc(func(net.Addr, net.Addr) []string { return []string{"TAILCAT_PEER_KEY=" + key} }, nil)(nilAddrConn{local: addr, remote: addr})
	if !ok || got[0] != 1 || got[31] != 0x32 {
		t.Fatalf("a connection with addresses: %x %v", got, ok)
	}
}

// A panic of the library's lookup is counted on its own (PeerPanics, not
// Unidentified), the connection is closed unserved, and the first such panic
// of the process is logged once; the listener goes on.
//
// spec: SPO-Xmailbox-SEC-086
func TestAPeerLookupPanicIsCountedAndLoggedOnceAtTheRelay(t *testing.T) {
	peerPanicsTotal.Store(0)
	t.Cleanup(func() { peerPanicsTotal.Store(0) })
	var mu sync.Mutex
	var lines []string
	r := newUnitRigWith(t, 4, func(l *Listener) {
		l.logf = func(f string, a ...any) { mu.Lock(); lines = append(lines, f); mu.Unlock() }
		e := l.eng
		e.peerKey = peerFunc(func(net.Addr, net.Addr) []string { panic("library bug") }, e.notePanic)
	})
	addr := &net.TCPAddr{IP: net.IPv4(100, 64, 0, 1), Port: 1}
	var remotes []net.Conn
	for i := 0; i < 2; i++ {
		a, b := net.Pipe()
		remotes = append(remotes, b)
		r.ln.conns <- nilAddrConn{Conn: a, local: addr, remote: addr}
	}
	deadline := time.Now().Add(5 * time.Second)
	for r.l.Stats().PeerPanics < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if st := r.l.Stats(); st.PeerPanics != 2 || st.Unidentified != 0 || st.Accepted != 0 {
		t.Fatalf("stats = %+v", st)
	}
	for i, b := range remotes {
		b.SetReadDeadline(time.Now().Add(2 * time.Second))
		if n, err := b.Read(make([]byte, 1)); n != 0 || err == nil {
			t.Fatalf("connection %d is open", i)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(lines) != 1 || !strings.Contains(lines[0], "panicked") || peerPanicsTotal.Load() != 2 {
		t.Fatalf("log lines %q, process count %d", lines, peerPanicsTotal.Load())
	}
}
