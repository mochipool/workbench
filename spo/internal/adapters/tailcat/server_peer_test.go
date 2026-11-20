package tailcat

import (
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// nilAddrConn is a connection whose endpoint was reset before the peer lookup:
// gonet's TCPConn.RemoteAddr (and LocalAddr) then return nil.
type nilAddrConn struct {
	net.Conn
	local, remote net.Addr
}

func (c nilAddrConn) LocalAddr() net.Addr  { return c.local }
func (c nilAddrConn) RemoteAddr() net.Addr { return c.remote }

// chanListener hands out the connections sent on it, then fails once closed.
type chanListener struct {
	conns chan net.Conn
	once  sync.Once
	done  chan struct{}
}

func newChanListener() *chanListener {
	return &chanListener{conns: make(chan net.Conn, 4), done: make(chan struct{})}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *chanListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *chanListener) Addr() net.Addr { return &net.TCPAddr{} }

// tailcatEnv behaves as tailcat's Server.PeerEnv (tailcat_exec.go): it calls
// String on both addresses, so a nil one panics.
func tailcatEnv(local, remote net.Addr) []string {
	return []string{"TAILCAT_REMOTE_ADDR=" + remote.String(), "TAILCAT_LOCAL_ADDR=" + local.String()}
}

// A connection reset between tailcat's accept and the peer lookup has no
// address, and tailcat's PeerEnv dereferences it. The server's accept loop
// must count such a connection as accepted and refused, close it, and keep
// running: a panic there ends `party serve`, a process that holds keys.
//
// spec: SPO-Xparty-SEC-004
func TestAConnectionWithoutAnAddressIsRefusedAtTheServer(t *testing.T) {
	s := testServer(t, ServerConfig{})
	ln := newChanListener()
	s.ln = ln
	// As tailcat: the addresses are formatted first (a nil one panics), then
	// the peer key is named (key1).
	s.peerKey = peerFunc(func(local, remote net.Addr) []string {
		return append(tailcatEnv(local, remote), "TAILCAT_PEER_KEY=nodekey:"+"0100000000000000000000000000000000000000000000000000000000000000")
	}, nil)
	s.wg.Add(1)
	go s.acceptLoop()

	addr := &net.TCPAddr{IP: net.IPv4(100, 64, 0, 1), Port: 1}
	var remotes []net.Conn
	for _, mk := range []func(net.Conn) net.Conn{
		func(c net.Conn) net.Conn { return nilAddrConn{Conn: c, local: addr} },
		func(c net.Conn) net.Conn { return nilAddrConn{Conn: c, remote: addr} },
		func(c net.Conn) net.Conn { return nilAddrConn{Conn: c} },
	} {
		a, b := net.Pipe()
		remotes = append(remotes, b)
		ln.conns <- mk(a)
	}
	deadline := time.Now().Add(5 * time.Second)
	for s.Stats().Refused < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if st := s.Stats(); st.Accepted != 3 || st.Refused != 3 || st.Frames != 0 {
		t.Fatalf("stats = %+v", st)
	}
	for i, b := range remotes {
		b.SetReadDeadline(time.Now().Add(2 * time.Second))
		if n, err := b.Read(make([]byte, 1)); n != 0 || err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("connection %d: read %d bytes, err %v: not closed", i, n, err)
		}
	}
	// The accept loop is still running: a connection with addresses, whose key
	// tailcat names, is served.
	a, b := net.Pipe()
	defer b.Close()
	ln.conns <- nilAddrConn{Conn: a, local: addr, remote: addr}
	go WriteFrame(b, []byte("still serving"))
	if got := recvOne(t, s); string(got) != "still serving" {
		t.Fatalf("got %q", got)
	}
}

// Whatever else the library dereferences, a panic in the peer lookup is
// contained: the connection is unidentified, never a crash.
//
// spec: SPO-Xparty-SEC-004
func TestAPanicInThePeerLookupIsUnidentified(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv4(100, 64, 0, 1), Port: 1}
	peer := peerFunc(func(net.Addr, net.Addr) []string { panic("library bug") }, nil)
	if _, ok := peer(nilAddrConn{local: addr, remote: addr}); ok {
		t.Fatal("identified")
	}
	// A connection without an address never reaches the library at all; the
	// recover is the second line, not the first.
	calls := 0
	counted := peerFunc(func(l, r net.Addr) []string { calls++; return tailcatEnv(l, r) }, nil)
	for _, c := range []net.Conn{nilAddrConn{local: addr}, nilAddrConn{remote: addr}, nilAddrConn{}} {
		if _, ok := counted(c); ok {
			t.Fatal("a connection without an address was identified")
		}
	}
	if calls != 0 {
		t.Fatalf("PeerEnv was called %d time(s) for a connection without an address", calls)
	}
	got, ok := peerFunc(func(net.Addr, net.Addr) []string {
		return []string{"TAILCAT_PEER_KEY=nodekey:" + "0102030405060708091011121314151617181920212223242526272829303132"}
	}, nil)(nilAddrConn{local: addr, remote: addr})
	if !ok || got[0] != 1 || got[31] != 0x32 {
		t.Fatalf("a connection with addresses: %x %v", got, ok)
	}
}

// The server owns its node key and pre-shared key (ServerConfig): Close
// destroys them, whether they were given or generated, and whether or not the
// server was started.
//
// spec: SPO-Xparty-SEC-005
func TestServerCloseDestroysItsKeys(t *testing.T) {
	base := secret.Budget().Live
	s, err := NewServer(ServerConfig{Allowed: []party.NodeKey{key1}, Admit: admitAll}) // both generated
	if err != nil {
		t.Fatal(err)
	}
	if got := secret.Budget().Live; got != base+2 {
		t.Fatalf("live buffers %d, want %d", got, base+2)
	}
	s.Close()
	s.Close() // twice is fine
	if got := secret.Budget().Live; got != base {
		t.Fatalf("Close left %d locked buffer(s) alive", got-base)
	}
	nk, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	psk, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	s, err = NewServer(ServerConfig{NodeKey: nk, PSK: psk, Allowed: []party.NodeKey{key1}, Admit: admitAll})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if got := secret.Budget().Live; got != base {
		t.Fatalf("Close left %d given buffer(s) alive", got-base)
	}
}

// NewServer takes the buffers over at the call: when it fails it destroys
// them, and any key it generated before the failure.
//
// spec: SPO-Xparty-SEC-005
func TestFailedNewServerDestroysTheKeys(t *testing.T) {
	short := func() *secret.Buffer {
		b, err := secret.TryNew(16)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	full := func() *secret.Buffer {
		b, err := NewKey()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for name, mk := range map[string]func() ServerConfig{
		"short psk, generated node key": func() ServerConfig {
			return ServerConfig{PSK: short(), Allowed: []party.NodeKey{key1}, Admit: admitAll}
		},
		"short node key, generated psk": func() ServerConfig {
			return ServerConfig{NodeKey: short(), Allowed: []party.NodeKey{key1}, Admit: admitAll}
		},
		"empty allow-list": func() ServerConfig { return ServerConfig{NodeKey: full(), PSK: full(), Admit: admitAll} },
		"no Admit":         func() ServerConfig { return ServerConfig{NodeKey: full(), PSK: full(), Allowed: []party.NodeKey{key1}} },
		"zero key listed": func() ServerConfig {
			return ServerConfig{NodeKey: full(), PSK: full(), Allowed: []party.NodeKey{{}}, Admit: admitAll}
		},
	} {
		base := secret.Budget().Live
		cfg := mk()
		if _, err := NewServer(cfg); err == nil {
			t.Fatalf("%s: built", name)
		}
		if got := secret.Budget().Live; got != base {
			t.Errorf("%s: %d locked buffer(s) left alive", name, got-base)
		}
	}
}
