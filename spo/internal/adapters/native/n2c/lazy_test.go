package n2c

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pcommon "github.com/blinklabs-io/gouroboros/protocol/common"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// A lazy client does not touch the socket until a read needs it, connects once,
// and closes cleanly whether or not it ever connected.
func TestLazyClientDialsOnFirstUseOnly(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.set("chain-point", pcommon.NewPoint(7, fill(1, 32)))
	n.set("epoch-no", 3)
	var dials atomic.Int32
	cfg := n.config()
	cfg.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}
	c, err := DialLazy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if c.Source() != "node socket preview" {
		t.Fatalf("source %q", c.Source())
	}
	time.Sleep(100 * time.Millisecond)
	if dials.Load() != 0 || n.Accepted() != 0 {
		t.Fatalf("a client that was not used connected: %d dials, %d accepted", dials.Load(), n.Accepted())
	}
	for i := 0; i < 3; i++ {
		if tip, err := c.Tip(context.Background()); err != nil || tip.Slot != 7 {
			t.Fatalf("tip %+v %v", tip, err)
		}
	}
	if dials.Load() != 1 {
		t.Fatalf("%d connections for one command", dials.Load())
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Tip(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("a closed lazy client: %v", err)
	}
	// Closing one that never connected is harmless.
	idle, err := DialLazy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := idle.Close(); err != nil || dials.Load() != 1 {
		t.Fatalf("close of an idle client: %v, dials %d", err, dials.Load())
	}
}

func TestLazyClientRefusesABadConfigurationAtOnce(t *testing.T) {
	if _, err := DialLazy(Config{Address: "/x", NetworkMagic: 0}); err == nil {
		t.Error("magic 0 accepted")
	}
	if _, err := DialLazy(Config{Address: "http://x", NetworkMagic: 2}); err == nil {
		t.Error("a bad scheme accepted")
	}
}

// An unreachable node is reported by every read as Unknown, with the address in
// the reason, and the connection is tried once: the second read does not wait
// again.
func TestLazyClientRemembersAFailedConnection(t *testing.T) {
	var dials atomic.Int32
	cfg := Config{Address: "/nonexistent/node.socket", NetworkMagic: 2, Network: "preview", Timeout: time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			dials.Add(1)
			var d net.Dialer
			return d.DialContext(ctx, network, address)
		}}
	c, err := DialLazy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sa := stakeAddr(t, false, false, fill(9, 28))
	for i := 0; i < 2; i++ {
		r, err := c.RewardAccount(context.Background(), sa)
		if err != nil || !r.IsUnknown() || r.IsNone() || !strings.Contains(r.Why(), "/nonexistent/node.socket") {
			t.Fatalf("reading %+v %v", r, err)
		}
	}
	if _, err := c.OpCertCounter(context.Background(), chain.PoolID(fill(1, 28))); err != nil {
		t.Fatal(err)
	}
	if dials.Load() != 1 {
		t.Fatalf("%d connection attempts", dials.Load())
	}
}

// A node that accepts the connection and never speaks is given the timeout, no
// more: the read is Unknown and returns.
func TestLazyClientBoundsAnUnresponsiveNode(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	c, err := DialLazy(Config{Address: "tcp://" + ln.Addr().String(), NetworkMagic: 2, Timeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	r, err := c.RewardAccount(context.Background(), stakeAddr(t, false, false, fill(9, 28)))
	if err != nil || !r.IsUnknown() {
		t.Fatalf("reading %+v %v", r, err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("took %v for a 500ms timeout", d)
	}
}
