package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objlease"
	"github.com/mochipool/workbench/spo/internal/adapters/objmailbox"
	"github.com/mochipool/workbench/spo/internal/adapters/objregistry"
	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/adapters/webidentity"
	"github.com/mochipool/workbench/spo/internal/app/relayhost"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relayconf"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/platform/stsweb"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// storeOptions are what a test changes in the object store's wiring: the
// lease's times (zero: objlease.DefaultTimes with the configured request
// timeout) and its tick.
type storeOptions struct {
	times objlease.Times
	tick  time.Duration
}

// ErrNotInitialised is a start on a store that holds neither a lease record nor
// a working-bucket marker of the identity: it was never initialised, and the
// relay does not initialise it by itself.
var ErrNotInitialised = errors.New("the store was never initialised for this relay")

// selfTestBound bounds the start-up self-test of one bucket: about a dozen
// requests, each also bounded by the request timeout.
const selfTestRequests = 16

// openObjectStore is relayhost.Deps.OpenObjectStore (ADR 0015 work package 10):
// the web identity provider (no static key), one client per bucket, the
// start-up self-test of each (working: versioning never enabled; registry:
// versioning, Object Lock and the deny of simple deletes; the retention part is
// init-store's and store verify's), the check that the identity was
// initialised, and the lease. The mailbox and the registry are opened by
// relayhost after the lease is held, with the lease.
func (o storeOptions) openObjectStore(ctx context.Context, spec relayhost.StoreSpec, relay party.NodeKey, clock relayport.Clock) (*relayhost.ObjectStore, error) {
	c := spec.Object
	if spec.Kind != relayhost.StoreObject || c == nil {
		return nil, errors.New("not an object store")
	}
	node := hex.EncodeToString(relay[:])
	prefix := "relays/" + node + "/"
	endpoint := c.Endpoint
	if endpoint == "" {
		var err error
		if endpoint, err = stsweb.RegionEndpoint("s3", c.Region); err != nil {
			return nil, err
		}
	}
	prov, err := webidentity.New(webidentity.Config{Region: c.Region, RoleARN: c.RoleARN, TokenFile: c.TokenFile,
		Endpoint: c.STSEndpoint, AllowLoopbackHTTP: c.LoopbackHTTP && c.STSEndpoint != ""})
	if err != nil {
		return nil, err
	}
	client := func(bucket string) (*s3client.Client, error) {
		return s3client.New(s3client.Config{Endpoint: endpoint, Region: c.Region, Bucket: bucket, PathStyle: c.PathStyle,
			Credentials: prov, AllowLoopbackHTTP: c.LoopbackHTTP})
	}
	reg, err := client(c.RegistryBucket)
	if err != nil {
		return nil, fmt.Errorf("the registry bucket: %w", err)
	}
	work, err := client(c.WorkingBucket)
	if err != nil {
		reg.Close()
		return nil, fmt.Errorf("the working bucket: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			reg.Close()
			work.Close()
		}
	}()
	mode := s3client.Compliance
	if c.LockMode == relayconf.LockGovernance {
		mode = s3client.Governance
	}
	for _, b := range []struct {
		name     string
		c        *s3client.Client
		registry bool
	}{{"working", work, false}, {"registry", reg, true}} {
		sctx, cancel := context.WithTimeout(ctx, selfTestRequests*c.RequestTimeout)
		err := s3client.SelfTest(sctx, b.c, s3client.SelfTestOptions{Prefix: prefix, Registry: b.registry, Mode: mode})
		cancel()
		if err != nil {
			return nil, fmt.Errorf("the %s bucket %s: %w", b.name, b.c.Bucket(), err)
		}
	}
	if err := initialised(ctx, work, node, c.RequestTimeout); err != nil {
		return nil, err
	}
	times := o.times
	if times == (objlease.Times{}) {
		times = objlease.DefaultTimes()
		times.RequestTimeout = c.RequestTimeout
	}
	lease, err := objlease.New(objlease.Config{Store: work, NodeKey: node, Clock: clock, Times: times, Tick: o.tick})
	if err != nil {
		return nil, err
	}
	ok = true
	return &relayhost.ObjectStore{
		Lease: lease,
		OpenMailbox: func(ctx context.Context, env relayhost.StoreEnv) (relayport.MailboxStore, []string, error) {
			s, notes, err := objmailbox.Open(ctx, objmailbox.Config{Client: work, NodeKey: node, Lease: env.Lease, Clock: env.Clock, RequestTimeout: c.RequestTimeout})
			if err != nil {
				return nil, nil, err
			}
			return s, notes, nil
		},
		OpenRegistry: func(ctx context.Context, cfg relayregistry.Config, env relayhost.StoreEnv) (relayport.Registry, []string, error) {
			s, notes, err := objregistry.Open(ctx, objregistry.Config{Registry: reg, Working: work, Lease: env.Lease, Clock: env.Clock,
				NodeKey: relay, Core: cfg, Mode: mode, RequestTimeout: c.RequestTimeout})
			if err != nil {
				return nil, nil, err
			}
			return s, notes, nil
		},
		Close: func() { reg.Close(); work.Close() },
		Notes: []string{fmt.Sprintf("self-test passed: working bucket %s, registry bucket %s (the retention checks are init-store's and store verify's)", work.Bucket(), reg.Bucket())},
	}, nil
}

// initialised refuses a store that holds neither the identity's lease record
// nor its working-bucket marker: init-store writes both, and the relay never
// writes either in their place (a lease object that is absent alone is lapsed,
// and the registry refuses a missing marker by itself). Each read is a GET
// bounded by the request timeout; a 404 of the object is ErrNotFound, told
// apart from a missing bucket (s3client, SPO-Xobjstore-PRE-004).
func initialised(ctx context.Context, work *s3client.Client, node string, timeout time.Duration) error {
	absent := 0
	for _, key := range []string{objlease.Key(node), "relays/" + node + "/marker"} {
		rctx, cancel := context.WithTimeout(ctx, timeout)
		_, err := work.Get(rctx, s3client.GetInput{Key: key, MaxBytes: 1024})
		cancel()
		switch {
		case errors.Is(err, s3client.ErrNotFound):
			absent++
		case err != nil:
			return fmt.Errorf("the working bucket %s: %w", work.Bucket(), err)
		}
	}
	if absent == 2 {
		return fmt.Errorf("%w (relays/%s/ holds no lease record and no marker): for a new relay, run once spo-relay init-store --config FILE; never for a relay that had a store", ErrNotInitialised, node)
	}
	return nil
}
