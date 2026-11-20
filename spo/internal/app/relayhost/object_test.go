package relayhost_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/bindingstore"
	"github.com/mochipool/workbench/spo/internal/adapters/mailboxstore"
	"github.com/mochipool/workbench/spo/internal/adapters/relayconfig"
	"github.com/mochipool/workbench/spo/internal/app/relayhost"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relayconf"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

// objectText is a configuration of an object-store relay on this host: the key
// file, [store] kind = "s3" and the full region the object store requires.
func (h *host) objectText(devices []*fakenet.Node, extra ...string) string {
	s := "[relay]\nadmission = \"open\"\nkey_file = \"" + filepath.Join(h.dir, "key", "relay.key") + "\"\nsweep_seconds = 60\n" +
		"[store]\nkind = \"s3\"\nregion = \"eu-west-1\"\nregistry_bucket = \"acme-relay-registry\"\nworking_bucket = \"acme-relay-working\"\n" +
		"role_arn = \"arn:aws:iam::123456789012:role/spo-relay\"\nweb_identity_token_file = \"/var/run/secrets/eks.amazonaws.com/serviceaccount/token\"\n"
	for _, e := range extra {
		s += e + "\n"
	}
	s += "[derp_region]\nregion_id = 900\n[[derp_node]]\nname = \"a\"\nhost_name = \"derp.example.org\"\n"
	for _, d := range devices {
		s += "[[device]]\nlabel = \"" + d.Name + "\"\nnode_key = \"" + hexKey(d.Key) + "\"\n"
	}
	return s
}

// fakeObject is an OpenObjectStore over the directory stores of this host and
// the in-memory lease of tl, which records each step.
type fakeObject struct {
	h      *host
	tl     *tracedLease
	spec   relayhost.StoreSpec
	relay  party.NodeKey
	closes int
	// releasedFirst is how many releases the lease had when Close ran
	releasedFirst int32
	block         chan struct{} // when set, the mailbox open waits for its context
	fail          error
	onClose       func() // when set, runs in the mailbox store's Close
}

func (f *fakeObject) open(ctx context.Context, spec relayhost.StoreSpec, relay party.NodeKey, clock relayport.Clock) (*relayhost.ObjectStore, error) {
	f.h.trace("object")
	f.spec, f.relay = spec, relay
	if f.fail != nil {
		return nil, f.fail
	}
	dir := filepath.Join(f.h.dir, "state")
	return &relayhost.ObjectStore{
		Lease: f.tl,
		OpenMailbox: func(ctx context.Context, env relayhost.StoreEnv) (relayport.MailboxStore, []string, error) {
			f.h.trace("mailbox")
			if f.block != nil {
				close(f.block)
				<-ctx.Done()
				return nil, nil, ctx.Err()
			}
			s, notes, err := mailboxstore.Open(filepath.Join(dir, "mailbox"), env.Clock)
			if err != nil {
				return nil, nil, err
			}
			return &closeTraced{MailboxStore: s, h: f.h, hook: f.onClose}, notes, nil
		},
		OpenRegistry: func(ctx context.Context, cfg relayregistry.Config, env relayhost.StoreEnv) (relayport.Registry, []string, error) {
			f.h.trace("registry")
			if env.Lease != relayport.Lease(f.tl) {
				return nil, nil, errors.New("the registry is not given the lease")
			}
			s, notes, err := bindingstore.Open(filepath.Join(dir, "registry"), cfg, env.Clock)
			if err != nil {
				return nil, nil, err
			}
			return s, notes, nil
		},
		Close: func() { f.h.trace("store-close"); f.closes++; f.releasedFirst = f.tl.releases.Load() },
		Notes: []string{"self-test passed"},
	}, nil
}

type closeTraced struct {
	relayport.MailboxStore
	h    *host
	hook func()
}

func (c *closeTraced) Close() error {
	c.h.trace("mailbox-close")
	if c.hook != nil {
		c.hook()
	}
	return c.MailboxStore.Close()
}

// A panic in Run (here in the close of a store at a planned stop) is recovered
// on Run's goroutine: serve exits 1 with one line, and the lease, whose
// release comes after the close, is not released.
//
// spec: SPO-Xmailbox-OUT-101
func TestAPanicInRunExitsOne(t *testing.T) {
	h := newHost(t)
	stand := relayporttest.NewLeaseStand(h.clock, relayporttest.DefaultLeaseTimes())
	tl := &tracedLease{Lease: stand.Lease("pod-a"), h: h}
	f := &fakeObject{h: h, tl: tl, onClose: func() { panic("SECRET-VALUE in a close") }}
	alice := h.net.Node("alice")
	conf := h.write(h.objectText([]*fakenet.Node{alice}))
	h.key(h.config(h.objectText([]*fakenet.Node{alice})))
	d := h.deps()
	d.OpenObjectStore = f.open
	d.RenewEvery = 5 * time.Millisecond
	sig := make(chan relayhost.Signal, 1)
	var out, errs bytes.Buffer
	code := make(chan int, 1)
	go func() { code <- relayhost.Main([]string{"serve", "--config", conf}, &out, &errs, sig, d) }()
	for i := 0; !slices.Contains(h.steps(), "tunnel"); i++ {
		if i > 500 {
			t.Fatalf("the relay did not start: %v", h.steps())
		}
		time.Sleep(10 * time.Millisecond)
	}
	sig <- relayhost.SignalStop
	select {
	case c := <-code:
		if c != relayhost.ExitFail || strings.Contains(errs.String(), "SECRET") || !strings.Contains(errs.String(), "internal error") {
			t.Fatalf("exit %d\n%s%s", c, out.String(), errs.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not end")
	}
	if tl.releases.Load() != 0 {
		t.Fatalf("%d releases", tl.releases.Load())
	}
}

// A planned stop whose close of the stores outlasts the lease end sends no
// release (there is nothing left to release) and says so: the log line is
// "stopped lease=lapses reason=late", not "stopped".
//
// spec: SPO-Xmailbox-OUT-129, SPO-Xobjstore-IF-303
func TestAStopThatClosesPastTheLeaseEndSaysTheLeaseLapses(t *testing.T) {
	h := newHost(t)
	stand := relayporttest.NewLeaseStand(h.clock, relayporttest.DefaultLeaseTimes())
	tl := &tracedLease{Lease: stand.Lease("pod-a"), h: h}
	f := &fakeObject{h: h, tl: tl, onClose: func() { h.clock.Advance(time.Minute) }}
	alice := h.net.Node("alice")
	cfg := h.config(h.objectText([]*fakenet.Node{alice}))
	d := h.deps()
	d.OpenObjectStore = f.open
	d.RenewEvery = 5 * time.Millisecond
	r, err := relayhost.Start(context.Background(), cfg, h.key(cfg), d)
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	stop()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	log := h.logText()
	if !strings.Contains(log, "stopped lease=lapses reason=late") || strings.Contains(log, " stopped\n") || tl.releases.Load() != 0 {
		t.Fatalf("%d releases, log:\n%s", tl.releases.Load(), log)
	}
}

// An object-store relay starts in the order of ADR 0015 work package 10: the
// store (its clients and self-tests), the lease, the load (the mailbox, then
// the registry, both given the lease), then the tunnel; a planned stop closes
// the stores before it releases the lease and closes the store's clients last.
// The start logs the configuration's hash and the store.
//
// spec: SPO-Xobjstore-OUT-302, SPO-Xobjstore-IF-303
func TestAnObjectStoreRelayStartsAndStopsInOrder(t *testing.T) {
	h := newHost(t)
	stand := relayporttest.NewLeaseStand(h.clock, relayporttest.DefaultLeaseTimes())
	tl := &tracedLease{Lease: stand.Lease("pod-a"), h: h}
	f := &fakeObject{h: h, tl: tl}
	alice := h.net.Node("alice")
	cfg := h.config(h.objectText([]*fakenet.Node{alice}))
	d := h.deps()
	d.OpenObjectStore = f.open
	d.OpenMailbox, d.OpenRegistry = nil, nil // never used for an object store
	d.RenewEvery = 5 * time.Millisecond
	key := h.key(cfg)
	r, err := relayhost.Start(context.Background(), cfg, key, d)
	if err != nil {
		t.Fatal(err)
	}
	if got := h.steps(); !slices.Equal(got, []string{"object", "lease", "mailbox", "registry", "tunnel"}) {
		t.Fatalf("start order %v", got)
	}
	if f.spec.Kind != relayhost.StoreObject || f.spec.Object == nil || f.spec.Object.WorkingBucket != "acme-relay-working" || f.relay != h.relay.Key {
		t.Fatalf("the store was opened with %+v for %x", f.spec, f.relay)
	}
	log := h.logText()
	if !strings.Contains(log, "start config="+cfg.HashTag()+" store=s3 registry_bucket=acme-relay-registry working_bucket=acme-relay-working prefix=relays/"+hexKey(h.relay.Key)+"/") {
		t.Fatalf("the start line:\n%s", log)
	}
	if !strings.Contains(log, "self-test passed") {
		t.Fatalf("the store's notes are not logged:\n%s", log)
	}
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	stop()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	steps := h.steps()
	if tail := steps[len(steps)-2:]; !slices.Equal(tail, []string{"mailbox-close", "store-close"}) || tl.releases.Load() != 1 || f.closes != 1 || f.releasedFirst != 1 {
		t.Fatalf("stop: %v, %d releases, %d closes", steps, tl.releases.Load(), f.closes)
	}
}

// The keeper's renewals are bounded by the configured request timeout, not by
// the 10 s default.
//
// spec: SPO-Xobjstore-IF-303
func TestTheConfiguredRequestTimeoutBoundsTheRenewals(t *testing.T) {
	h := newHost(t)
	h.realClock = true
	stand := relayporttest.NewLeaseStand(relayporttest.NewManualClock(time.Now().Unix()), relayporttest.DefaultLeaseTimes())
	dl := &deadlineLease{Lease: stand.Lease("pod-a"), got: make(chan time.Duration, 64)}
	tl := &tracedLease{Lease: dl, h: h}
	f := &fakeObject{h: h, tl: tl}
	alice := h.net.Node("alice")
	cfg := h.config(h.objectText([]*fakenet.Node{alice}, "request_timeout_seconds = 2"))
	d := h.deps()
	d.OpenObjectStore = f.open
	d.RenewEvery = 5 * time.Millisecond
	r, err := relayhost.Start(context.Background(), cfg, h.key(cfg), d)
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	select {
	case left := <-dl.got:
		if left > 2*time.Second || left < time.Second {
			t.Fatalf("a renewal's deadline is %v away, want at most the configured 2 s", left)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no renewal")
	}
	stop()
	<-done
}

type deadlineLease struct {
	relayport.Lease
	got chan time.Duration
}

func (l *deadlineLease) Renew(ctx context.Context) error {
	if dl, ok := ctx.Deadline(); ok {
		select {
		case l.got <- time.Until(dl):
		default:
		}
	}
	return l.Lease.Renew(ctx)
}

// A store that does not open (a self-test that fails, an uninitialised store,
// no credentials) fails the start before the lease and the tunnel; a build
// without the object store refuses its configuration.
//
// spec: SPO-Xobjstore-OUT-302
func TestAnObjectStoreThatDoesNotOpenStartsNothing(t *testing.T) {
	h := newHost(t)
	stand := relayporttest.NewLeaseStand(h.clock, relayporttest.DefaultLeaseTimes())
	tl := &tracedLease{Lease: stand.Lease("pod-a"), h: h}
	why := errors.New("the store fails the self-test: a create with If-None-Match: * over an existing object answers 412")
	f := &fakeObject{h: h, tl: tl, fail: why}
	alice := h.net.Node("alice")
	cfg := h.config(h.objectText([]*fakenet.Node{alice}))
	d := h.deps()
	d.OpenObjectStore = f.open
	if _, err := relayhost.Start(context.Background(), cfg, h.key(cfg), d); !errors.Is(err, why) || !strings.Contains(err.Error(), "the object store") {
		t.Fatalf("%v", err)
	}
	if got := h.steps(); !slices.Equal(got, []string{"object"}) {
		t.Fatalf("steps %v", got)
	}
	d.OpenObjectStore = nil
	if _, err := relayhost.Start(context.Background(), cfg, h.key(cfg), d); err == nil || !strings.Contains(err.Error(), "object store") {
		t.Fatalf("a build without the object store: %v", err)
	}
}

// SIGTERM during the load of an object store is a planned stop: serve exits 0
// before serving, started no tunnel, and the lease is left to lapse because a
// request of the load may still land.
//
// spec: SPO-Xmailbox-OUT-132, SPO-Xobjstore-OUT-302
func TestSIGTERMDuringTheLoadIsAPlannedStop(t *testing.T) {
	h := newHost(t)
	stand := relayporttest.NewLeaseStand(h.clock, relayporttest.DefaultLeaseTimes())
	tl := &tracedLease{Lease: stand.Lease("pod-a"), h: h}
	f := &fakeObject{h: h, tl: tl, block: make(chan struct{})}
	alice := h.net.Node("alice")
	conf := h.write(h.objectText([]*fakenet.Node{alice}))
	cfg := h.config(h.objectText([]*fakenet.Node{alice}))
	h.key(cfg)
	d := h.deps()
	d.OpenObjectStore = f.open
	d.RenewEvery = 5 * time.Millisecond
	sig := make(chan relayhost.Signal, 1)
	var out, errs bytes.Buffer
	code := make(chan int, 1)
	go func() { code <- relayhost.Main([]string{"serve", "--config", conf}, &out, &errs, sig, d) }()
	select {
	case <-f.block:
	case <-time.After(10 * time.Second):
		t.Fatalf("the load did not start: %v\n%s", h.steps(), errs.String())
	}
	sig <- relayhost.SignalStop
	select {
	case c := <-code:
		if c != relayhost.ExitOK || !strings.Contains(out.String(), "stopped before serving") {
			t.Fatalf("exit %d\n%s%s", c, out.String(), errs.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop")
	}
	if slices.Contains(h.steps(), "tunnel") || tl.releases.Load() != 0 || !strings.Contains(h.logText(), "start_failed lease=lapses reason=load") {
		t.Fatalf("steps %v, %d releases\n%s", h.steps(), tl.releases.Load(), h.logText())
	}
}

// check-config of an object-store relay prints the store's kind, the two
// buckets, the prefix (the relay's node key) and the configuration's hash, and
// nothing of the web identity but that it is the source.
//
// spec: SPO-Xobjstore-OUT-301
func TestCheckConfigPrintsTheStoreAndTheHash(t *testing.T) {
	h := newHost(t)
	alice := h.net.Node("alice")
	text := h.objectText([]*fakenet.Node{alice})
	conf := h.write(text)
	cfg := h.config(text)
	var out, errs bytes.Buffer
	d := h.deps()
	if code := relayhost.Main([]string{"check-config", "--config", conf}, &out, &errs, nil, d); code != relayhost.ExitOK {
		t.Fatalf("exit %d %s", code, errs.String())
	}
	for _, want := range []string{"configuration hash " + cfg.HashTag(), "store s3: registry bucket acme-relay-registry, working bucket acme-relay-working",
		"prefix relays/<node key>/", "object lock compliance", "credentials: web identity", "DERP region pinned in full"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("no %q in:\n%s", want, out.String())
		}
	}
	h.key(cfg)
	out.Reset()
	if code := relayhost.Main([]string{"check-config", "--config", conf}, &out, &errs, nil, d); code != relayhost.ExitOK ||
		!strings.Contains(out.String(), "store prefix relays/"+hexKey(h.relay.Key)+"/") {
		t.Fatalf("with a key: %d\n%s", code, out.String())
	}
	if strings.Contains(out.String(), "eks.amazonaws.com") {
		t.Fatalf("the token file's path is printed:\n%s", out.String())
	}
}

// key loads or makes the relay key of cfg.
func (h *host) key(cfg *relayconf.Config) *relayconf.Key {
	h.t.Helper()
	k, err := relayconfig.LoadKey(cfg.KeyFile)
	if errors.Is(err, os.ErrNotExist) {
		k, err = relayconfig.CreateKey(cfg.KeyFile, seeded{})
	}
	if err != nil {
		h.t.Fatal(err)
	}
	return k
}
