package relayport

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
)

// The bound on bodies a put may hold whole: 64 bodies of at most one envelope,
// 64 MiB for the whole store (ADR 0015 decision 2, m1).
//
// spec: SPO-Xmailbox-IF-001
func TestHeldBodiesAreBounded(t *testing.T) {
	n, b, env := MaxHeldBodies, MaxHeldBodyBytes, mailbox.MaxEnvelopeBytes
	if n != 64 || b != 64<<20 || b != n*env {
		t.Fatalf("held bodies %d, bytes %d", n, b)
	}
}

// The three store errors are distinct, and each is what a caller tests for.
//
// spec: SPO-Xmailbox-IF-032
func TestStoreErrorsAreDistinct(t *testing.T) {
	all := []error{ErrAuthorityLost, ErrOutcomeUnknown, ErrDeleteRefused, ErrRegistryClosed, ErrMailboxClosed}
	for i, a := range all {
		for j, b := range all {
			if i != j && errors.Is(a, b) {
				t.Fatalf("%v wraps %v", a, b)
			}
		}
	}
}

// The lease port and the refresher have exactly the methods the ADR names.
//
// spec: SPO-Xmailbox-IF-031, SPO-Xmailbox-IF-033, SPO-Xmailbox-IF-035
func TestLeaseAndRefresherPorts(t *testing.T) {
	if got := methodNames(reflect.TypeFor[Lease]()); !slices.Equal(got, []string{"Acquire", "Lost", "Release", "Renew", "Until"}) {
		t.Fatalf("Lease has %v", got)
	}
	if got := methodNames(reflect.TypeFor[TombstoneRefresher]()); !slices.Equal(got, []string{"RefreshTombstones"}) {
		t.Fatalf("TombstoneRefresher has %v", got)
	}
	if _, ok := reflect.TypeFor[Registry]().MethodByName("RefreshTombstones"); !ok {
		t.Fatal("Registry lacks RefreshTombstones")
	}
	if got := methodNames(reflect.TypeFor[RateSaver]()); !slices.Equal(got, []string{"SaveRates"}) {
		t.Fatalf("RateSaver has %v", got)
	}
	if _, ok := reflect.TypeFor[Registry]().MethodByName("SaveRates"); !ok {
		t.Fatal("Registry lacks SaveRates")
	}
	if TombstoneRefreshEvery != time.Minute {
		t.Fatalf("TombstoneRefreshEvery = %v", TombstoneRefreshEvery)
	}
}

// stub is a lease with a fixed state, for RequestContext.
type stub struct {
	until time.Time
	ok    bool
	lost  chan struct{}
}

func (s stub) Acquire(context.Context) error { return nil }
func (s stub) Renew(context.Context) error   { return nil }
func (s stub) Release(context.Context) error { return nil }
func (s stub) Until() (time.Time, bool)      { return s.until, s.ok }
func (s stub) Lost() <-chan struct{}         { return s.lost }

// RequestContext refuses a request when the lease is not held, is lost or has
// ended, and bounds it by the lease end otherwise.
//
// spec: SPO-Xmailbox-IF-031
func TestRequestContext(t *testing.T) {
	now := time.Unix(1800000000, 0)
	open := make(chan struct{})
	closed := make(chan struct{})
	close(closed)
	for name, l := range map[string]stub{
		"not held": {lost: open},
		"lost":     {until: now.Add(time.Minute), ok: true, lost: closed},
		"ended":    {until: now, ok: true, lost: open},
	} {
		if _, _, err := RequestContext(context.Background(), l, now, time.Second); !errors.Is(err, ErrAuthorityLost) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	ctx, cancel, err := RequestContext(context.Background(), stub{until: now.Add(2 * time.Second), ok: true, lost: open}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	if dl, _ := ctx.Deadline(); time.Until(dl) > 2*time.Second {
		t.Fatalf("not bounded by the lease end: %v", time.Until(dl))
	}
	ctx2, cancel2, err := RequestContext(context.Background(), stub{ok: true, lost: open}, now, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel2()
	if dl, ok := ctx2.Deadline(); !ok || time.Until(dl) > time.Second {
		t.Fatal("a lease without an end does not bound the request by max")
	}
}
