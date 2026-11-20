package relayhost_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/relayconfig"
	"github.com/mochipool/workbench/spo/internal/app/relayhost"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

// The default lease of a host with directory stores: it has no end, and the
// stores' locks keep one writer.
//
// spec: SPO-Xmailbox-IF-031, SPO-Xmailbox-IF-034
func TestSingleHostLeaseContract(t *testing.T) {
	relayporttest.RunLease(t, func(t *testing.T) relayporttest.LeaseFixture {
		return relayporttest.LeaseFixture{Lease: relayhost.SingleHostLease(), Clock: relayporttest.NewManualClock(startTime)}
	})
}

// tracedLease is a lease whose Acquire is a step of the start and whose
// releases are counted.
type tracedLease struct {
	relayport.Lease
	h        *host
	releases atomic.Int32
}

func (l *tracedLease) Acquire(ctx context.Context) error {
	l.h.trace("lease")
	return l.Lease.Acquire(ctx)
}

func (l *tracedLease) Release(ctx context.Context) error {
	l.releases.Add(1)
	return l.Lease.Release(ctx)
}

// withStandLease gives the host a lease of an in-memory lease record, renewed
// every few milliseconds.
func withStandLease(h *host) (*relayporttest.LeaseStand, *tracedLease) {
	stand := relayporttest.NewLeaseStand(h.clock, relayporttest.DefaultLeaseTimes())
	tl := &tracedLease{Lease: stand.Lease("pod-a"), h: h}
	h.openLease = func(party.NodeKey, relayport.Clock) (relayport.Lease, error) { return tl, nil }
	h.renewEvery = 5 * time.Millisecond
	return stand, tl
}

// The start order of ADR 0015 decision 5: the lease, then the load (the
// stores, which are given the lease), then the tunnel. A planned stop releases
// the lease after the stores are closed.
//
// spec: SPO-Xmailbox-IF-034, SPO-Xmailbox-OUT-100
func TestStartOrderIsLeaseLoadTunnel(t *testing.T) {
	h := newHost(t)
	a := newDevice(h.net, "alice", 1)
	_, tl := withStandLease(h)
	_, end := h.start(h.config(h.text([]*fakenet.Node{a.node})))
	if got := h.steps(); !slices.Equal(got, []string{"lease", "mailbox", "registry", "tunnel"}) {
		t.Fatalf("the start ran %v", got)
	}
	h.mu.Lock()
	env := h.env
	h.mu.Unlock()
	if env.Lease != relayport.Lease(tl) || env.Clock == nil {
		t.Fatalf("the stores were not given the lease and the clock: %+v", env)
	}
	if err := end(); err != nil {
		t.Fatalf("a planned stop: %v", err)
	}
	if n := tl.releases.Load(); n != 1 {
		t.Fatalf("a planned stop released the lease %d times, want once", n)
	}
}

// A lease that is lost while serving ends Run with ErrAuthorityLost: the
// sessions end, the tunnel is closed, and the lease is not released (the
// process cannot tell whether the lease it holds is still the one it wrote).
//
// spec: SPO-Xmailbox-OUT-127, SPO-Xmailbox-OUT-101
func TestALostLeaseEndsTheRelay(t *testing.T) {
	h := newHost(t)
	a := newDevice(h.net, "alice", 1)
	stand, tl := withStandLease(h)
	_, end := h.start(h.config(h.text([]*fakenet.Node{a.node})))
	stand.Steal()
	for i := 0; !strings.Contains(h.logText(), "stopped reason=authority_lost"); i++ {
		if i > 500 {
			t.Fatalf("the relay did not stop on its own:\n%s", h.logText())
		}
		time.Sleep(10 * time.Millisecond)
	}
	errc := make(chan error, 1)
	go func() { errc <- end() }()
	var err error
	select {
	case err = <-errc:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not end")
	}
	if !errors.Is(err, relayhost.ErrAuthorityLost) || !errors.Is(err, relayport.ErrAuthorityLost) {
		t.Fatalf("Run = %v, want ErrAuthorityLost", err)
	}
	if !h.tun.closed.Load() {
		t.Fatal("the tunnel was not closed")
	}
	if n := tl.releases.Load(); n != 0 {
		t.Fatalf("a lost lease was released %d times", n)
	}
	if !strings.Contains(h.logText(), "authority_lost") {
		t.Fatalf("the log does not say so:\n%s", h.logText())
	}
}

// quietLease hides the lease's Lost channel: only a refused renewal tells the
// holder. loudLease renews without fault: only Lost tells it. The host reacts
// to each on its own.
type quietLease struct{ relayport.Lease }

func (quietLease) Lost() <-chan struct{} { return make(chan struct{}) }

type loudLease struct {
	relayport.Lease
	lost chan struct{}
}

func (l *loudLease) Renew(context.Context) error { return nil }
func (l *loudLease) Lost() <-chan struct{}       { return l.lost }

// Either signal of a lost lease ends the relay: a refused renewal, and Lost.
//
// spec: SPO-Xmailbox-OUT-127
func TestEitherSignalOfALostLeaseEndsTheRelay(t *testing.T) {
	for _, quiet := range []bool{true, false} {
		h := newHost(t)
		a := newDevice(h.net, "alice", 1)
		stand := relayporttest.NewLeaseStand(h.clock, relayporttest.DefaultLeaseTimes())
		var lease relayport.Lease
		var loud *loudLease
		if quiet {
			lease = quietLease{stand.Lease("pod-a")}
		} else {
			loud = &loudLease{Lease: stand.Lease("pod-a"), lost: make(chan struct{})}
			lease = loud
		}
		h.openLease = func(party.NodeKey, relayport.Clock) (relayport.Lease, error) { return lease, nil }
		h.renewEvery = 5 * time.Millisecond
		h.start(h.config(h.text([]*fakenet.Node{a.node})))
		if quiet {
			stand.Steal()
		} else {
			close(loud.lost)
		}
		for i := 0; !strings.Contains(h.logText(), "stopped reason=authority_lost"); i++ {
			if i > 500 {
				t.Fatalf("quiet=%v: the relay did not stop:\n%s", quiet, h.logText())
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// serve exits with the status of a lost authority, 4, and says why.
//
// spec: SPO-Xmailbox-OUT-101, SPO-Xmailbox-OUT-127
func TestServeExitsWithTheAuthorityStatus(t *testing.T) {
	if relayhost.ExitAuthority != 4 {
		t.Fatalf("ExitAuthority = %d", relayhost.ExitAuthority)
	}
	h := newHost(t)
	a := newDevice(h.net, "alice", 1)
	stand, _ := withStandLease(h)
	conf := h.write(h.text([]*fakenet.Node{a.node}))
	if r := h.main(nil, "init-key", "--config", conf); r.code != 0 {
		t.Fatal(r)
	}
	out := make(chan run, 1)
	go func() { out <- h.main(make(chan relayhost.Signal), "serve", "--config", conf) }()
	for i := 0; ; i++ {
		h.mu.Lock()
		up := h.tun != nil
		h.mu.Unlock()
		if up {
			break
		}
		if i > 500 {
			t.Fatal("the relay did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	stand.Steal()
	select {
	case r := <-out:
		if r.code != relayhost.ExitAuthority || !strings.Contains(r.stderr, "no longer the writer") || strings.Contains(r.stdout, "stopped") {
			t.Fatalf("serve after a lost lease: %+v", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not exit")
	}
}

// A start whose lease is lost before the tunnel starts is refused and starts no
// tunnel.
//
// spec: SPO-Xmailbox-IF-034
func TestALeaseLostDuringTheLoadStartsNoTunnel(t *testing.T) {
	h := newHost(t)
	a := newDevice(h.net, "alice", 1)
	stand, tl := withStandLease(h)
	h.renewEvery = time.Hour // only the stores' own check sees the theft
	cfg := h.config(h.text([]*fakenet.Node{a.node}))
	key, err := relayconfig.CreateKey(cfg.KeyFile, seeded{})
	if err != nil {
		t.Fatal(err)
	}
	d := h.deps()
	open := d.OpenRegistry
	d.OpenRegistry = func(spec relayhost.StoreSpec, c relayregistry.Config, env relayhost.StoreEnv) (relayport.Registry, []string, error) {
		stand.Steal()
		env.Lease.Renew(context.Background()) //nolint:errcheck // the store finds the theft
		return open(spec, c, env)
	}
	_, err = relayhost.Start(context.Background(), cfg, key, d)
	if !errors.Is(err, relayhost.ErrAuthorityLost) {
		t.Fatalf("Start = %v, want ErrAuthorityLost", err)
	}
	if h.listened != 0 {
		t.Fatal("a tunnel was started without the lease")
	}
	if n := tl.releases.Load(); n != 0 {
		t.Fatalf("a lost lease was released %d times", n)
	}
}

// refreshCounter is the registry with its refreshes counted.
type refreshCounter struct {
	relayport.Registry
	n atomic.Int32
}

func (r *refreshCounter) RefreshTombstones(ctx context.Context) (relayregistry.MergeResult, error) {
	r.n.Add(1)
	return r.Registry.RefreshTombstones(ctx)
}

// The tombstones are re-read on an interval for as long as the relay serves.
//
// spec: SPO-Xmailbox-OUT-126
func TestTombstonesAreReReadWhileServing(t *testing.T) {
	if relayhost.DefaultRenewEvery != 5*time.Second {
		t.Fatalf("DefaultRenewEvery = %v", relayhost.DefaultRenewEvery)
	}
	h := newHost(t)
	a := newDevice(h.net, "alice", 1)
	var rc *refreshCounter
	h.wrapRegistry = func(r relayport.Registry) relayport.Registry { rc = &refreshCounter{Registry: r}; return rc }
	h.refreshEvery = 5 * time.Millisecond
	_, end := h.start(h.config(h.text([]*fakenet.Node{a.node})))
	for i := 0; rc.n.Load() < 2; i++ {
		if i > 500 {
			t.Fatal("the tombstones were not re-read")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := end(); err != nil {
		t.Fatal(err)
	}
}
