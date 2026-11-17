package secretfd

import (
	"errors"
	"net"
	"testing"
)

// A TCP socket is a socket, but it sends the secret off the machine: only a
// Unix-domain socket is accepted.
//
// spec: SPO-Xcustody-OUT-005
func TestCheckRefusesANetworkSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener: %v", err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			defer c.Close()
			buf := make([]byte, 1)
			_, _ = c.Read(buf)
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	f, err := c.(*net.TCPConn).File()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := Check("recovery-key-fd", int(f.Fd())); !errors.Is(err, ErrNotAPipe) {
		t.Fatalf("a TCP socket was accepted: %v", err)
	}
	if err := Write("recovery-key-fd", int(f.Fd()), []byte("secret")); !errors.Is(err, ErrNotAPipe) {
		t.Fatalf("a secret was written to a TCP socket: %v", err)
	}
}
