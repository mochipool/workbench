package relay_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

// The security review of the version 2 session found that a revoke that errors
// let any peer purge the queue of a device whose binding had lapsed (H1): the
// fallback asked the registry about the device the revoke names and purged it when
// the answer was "not bound", without asking whether the device had been served
// before the revoke or under the revoke's key. These tests are that finding, as
// negative tests over both registries, and the positive cases the fix must keep.

// registries runs f once over the in-memory registry and once over the durable one.
func registries(t *testing.T, f func(t *testing.T, durable bool)) {
	t.Helper()
	for _, tc := range []struct {
		name    string
		durable bool
	}{{"memory", false}, {"durable", true}} {
		t.Run(tc.name, func(t *testing.T) { f(t, tc.durable) })
	}
}

// lapsedRig is a rig in which bob's binding was short (an hour) and has lapsed,
// with one entry from alice still queued for him. Nothing has swept anything.
func lapsedRig(t *testing.T, durable bool, opts ...rigOpt) *rig {
	t.Helper()
	opts = append([]rigOpt{withoutBindings()}, opts...)
	if durable {
		opts = append(opts, withDurableRegistry())
	}
	r := newRig(t, opts...)
	r.b.stmt = r.b.wallet.BindingStatement(r.b.fp, startTime-60, startTime+3600, false)
	r.bindAll()
	a, _ := r.login(r.a)
	if pr := a.put(1, r.b.fp, envelope(100, 1)); pr.Status != mailbox.StatusStored {
		t.Fatalf("put to bob: status %d", pr.Status)
	}
	a.s.Close()
	r.clock.Advance(2 * time.Hour)
	if _, ok := r.bindingOf(r.b.fp); ok {
		t.Fatal("bob's binding has not lapsed")
	}
	if n := len(r.list(r.b.fp)); n != 1 {
		t.Fatalf("%d entries queued for bob, want 1", n)
	}
	return r
}

func oneRevokePerHour(c *relayregistry.Config) { c.RevokesPerHour, c.RevokeBurst = 1, 1 }

// spendNonInvalidating has carol's key revoke a device that is not bound: recorded,
// and it uses the relay-wide share of the non-invalidating revokes (the cap of one
// an hour, or the limited share of a table of two).
func spendNonInvalidating(t *testing.T, r *rig, rv *conn) {
	t.Helper()
	rr := rv.revoke(walletRevoke(r.c.wallet, 1, relayporttest.Device(1), false, r.clock.Now().Unix()))
	if rr.Status != mailbox.RevokeRecorded {
		t.Fatalf("the first non-invalidating revoke: status %d, want recorded", rr.Status)
	}
}

// requireMailKept requires that nothing was purged and that bob's queue is whole,
// and that a fresh binding of bob is served the old mail (ADR 0014 decision 5: a
// lapsed pair's stored mail stays until retention).
func requireMailKept(t *testing.T, r *rig) {
	t.Helper()
	if got := r.store.purgedMailboxes(); len(got) != 0 {
		t.Fatalf("purged %v; a revoke that invalidated nothing purged a queue", got)
	}
	if n := len(r.list(r.b.fp)); n != 1 {
		t.Fatalf("%d entries left for bob, want 1", n)
	}
	now := r.clock.Now().Unix()
	r.b.stmt = r.b.wallet.BindingStatement(r.b.fp, now-60, now+3600, false)
	b, _ := r.login(r.b)
	if it, _ := b.fetch(1, nil, 16, 0); len(it.Entries) != 1 {
		t.Fatalf("bob bound again got %d entries, want the 1 that was kept", len(it.Entries))
	}
}

// H1: the relay-wide cap on non-invalidating revokes is spent, and a pair revoke
// by carol's key names bob's device, whose binding has lapsed. The registry
// refuses it (ErrRevokeRate); the refusal touches no storage and no queue goes.
//
// spec: SPO-Xmailbox-SEC-069
func TestH1RevokeRateRefusalDoesNotPurgeALapsedDevice(t *testing.T) {
	registries(t, func(t *testing.T, durable bool) {
		r := lapsedRig(t, durable, withRegistryConfig(oneRevokePerHour))
		rv := r.revoker()
		spendNonInvalidating(t, r, rv)
		rr := rv.revoke(walletRevoke(r.c.wallet, 2, r.b.fp, false, r.clock.Now().Unix()))
		if rr.Status != mailbox.RevokeRefused {
			t.Fatalf("the pair revoke over the cap: status %d, want refused", rr.Status)
		}
		requireMailKept(t, r)
	})
}

// H1: the same with a full table of tombstones (the limited share is one entry).
//
// spec: SPO-Xmailbox-SEC-069
func TestH1FullTombstoneTableDoesNotPurgeALapsedDevice(t *testing.T) {
	registries(t, func(t *testing.T, durable bool) {
		r := lapsedRig(t, durable, withRegistryConfig(func(c *relayregistry.Config) { c.MaxTombstones = 2 }))
		rv := r.revoker()
		spendNonInvalidating(t, r, rv)
		rr := rv.revoke(walletRevoke(r.c.wallet, 2, r.b.fp, false, r.clock.Now().Unix()))
		if rr.Status != mailbox.RevokeRefused {
			t.Fatalf("the pair revoke into a full table: status %d, want refused", rr.Status)
		}
		requireMailKept(t, r)
	})
}

// H1: a revoke of "all" by a key that binds nothing here, refused for the rate,
// touches no queue.
//
// spec: SPO-Xmailbox-SEC-069
func TestH1AllScopeOfAnotherKeyPurgesNothing(t *testing.T) {
	registries(t, func(t *testing.T, durable bool) {
		r := lapsedRig(t, durable, withRegistryConfig(oneRevokePerHour))
		rv := r.revoker()
		spendNonInvalidating(t, r, rv)
		throwaway := relayporttest.NewWallet(9)
		rr := rv.revoke(walletRevoke(throwaway, 2, party.Fingerprint{}, true, r.clock.Now().Unix()))
		if rr.Status != mailbox.RevokeRefused {
			t.Fatalf("an all revoke over the cap: status %d, want refused", rr.Status)
		}
		requireMailKept(t, r)
	})
}

// H1: a device-signed revoke made with the attacker's own keys names the
// attacker's own fingerprint (the relay recomputes it from the keys in the frame),
// so bob's device is untouched, and nothing is purged for the attacker's device
// either: it was never served.
//
// spec: SPO-Xmailbox-SEC-069
func TestH1DeviceSignedRevokeOfAnAttackerPurgesNothing(t *testing.T) {
	registries(t, func(t *testing.T, durable bool) {
		r := lapsedRig(t, durable, withRegistryConfig(oneRevokePerHour))
		mallory := r.addPeer("mallory", relayporttest.NewWallet(9))
		rv := r.revoker()
		spendNonInvalidating(t, r, rv)
		rr := rv.revoke(deviceRevoke(t, mallory, 2, r.clock.Now().Unix()))
		if rr.Status != mailbox.RevokeRefused {
			t.Fatalf("a device revoke over the cap: status %d, want refused", rr.Status)
		}
		requireMailKept(t, r)
	})
}

// H1: a revoke that fails for a reason of storage (not a refusal) and names a
// device whose binding had already lapsed does not purge it either: the device was
// not served before the revoke, so the revoke took nothing away from it.
//
// spec: SPO-Xmailbox-SEC-069
func TestH1StorageErrorOnALapsedDeviceDoesNotPurgeIt(t *testing.T) {
	registries(t, func(t *testing.T, durable bool) {
		r := lapsedRig(t, durable)
		r.hreg.RevokeHook = func(res relayregistry.RevokeResult, err error) (relayregistry.RevokeResult, error) {
			return relayregistry.RevokeResult{}, errors.New("fsync failed")
		}
		rv := r.revoker()
		now := r.clock.Now().Unix()
		// by bob's own key, by carol's, and by bob's device alone
		rv.revoke(walletRevoke(r.b.wallet, 1, r.b.fp, false, now))
		rv.revoke(walletRevoke(r.c.wallet, 2, r.b.fp, false, now))
		rv.revoke(walletRevoke(r.b.wallet, 3, party.Fingerprint{}, true, now))
		rv.revoke(deviceRevoke(t, r.b, 4, now))
		// the tombstones these recorded stop an old binding, so bob is not bound again
		// here; his queue is whole
		if got := r.store.purgedMailboxes(); len(got) != 0 {
			t.Fatalf("purged %v after a storage error on a lapsed device", got)
		}
		if n := len(r.list(r.b.fp)); n != 1 {
			t.Fatalf("%d entries left for bob, want 1", n)
		}
	})
}

// H1: a device that was served under bob's key before the revoke and is "not
// served" after it, named by a revoke of carol's key (an old key of that device,
// say), is not purged: the revoke is not the key's that bound it.
//
// spec: SPO-Xmailbox-SEC-069
func TestH1DeviceBoundUnderAnotherKeyIsNotPurgedByAnOldKeysRevoke(t *testing.T) {
	registries(t, func(t *testing.T, durable bool) {
		var opts []rigOpt
		if durable {
			opts = append(opts, withDurableRegistry())
		}
		r := newRig(t, opts...)
		a, _ := r.login(r.a)
		if pr := a.put(1, r.b.fp, envelope(100, 1)); pr.Status != mailbox.StatusStored {
			t.Fatalf("put %d", pr.Status)
		}
		// the first Lookup (before the revoke) is true; every later one is "not bound"
		r.hreg.hideLookup(r.b.fp, 1)
		r.hreg.RevokeHook = func(res relayregistry.RevokeResult, err error) (relayregistry.RevokeResult, error) {
			return relayregistry.RevokeResult{}, errors.New("the answer was lost")
		}
		rv := r.revoker()
		// carol's key (the old one) names bob's device, bound under bob's key
		rv.revoke(walletRevoke(r.c.wallet, 1, r.b.fp, false, startTime))
		if got := r.store.purgedMailboxes(); len(got) != 0 {
			t.Fatalf("purged %v; the revoke's key is not the key that bound the device", got)
		}
		if n := len(r.list(r.b.fp)); n != 1 {
			t.Fatalf("%d entries left for bob, want 1", n)
		}
	})
}

// Obligation 14, positive: a revoke whose answer is lost still purges the device
// it invalidated (served before, not served after, under the revoke's own key).
//
// spec: SPO-Xmailbox-SEC-067, SPO-Xmailbox-SEC-069
func TestH1LostAnswerStillPurgesThePairItInvalidated(t *testing.T) {
	registries(t, func(t *testing.T, durable bool) {
		var opts []rigOpt
		if durable {
			opts = append(opts, withDurableRegistry())
		}
		r := newRig(t, opts...)
		b := r.parkedLongPoll(r.b)
		r.hreg.RevokeHook = func(res relayregistry.RevokeResult, err error) (relayregistry.RevokeResult, error) {
			return relayregistry.RevokeResult{}, errors.New("the answer was lost")
		}
		rv := r.revoker()
		rv.revoke(walletRevoke(r.b.wallet, 1, r.b.fp, false, startTime))
		if code := b.expectError(); code != mailbox.CodeBinding {
			t.Fatalf("code %d", code)
		}
		if got := r.store.purgedMailboxes(); len(got) != 1 || got[0] != r.b.fp {
			t.Fatalf("purged %v, want bob's only", got)
		}
	})
}

// Obligation 14, positive: a device-signed revoke by the device itself, whose
// answer is lost, purges that device. Its tombstone carries no wallet key, so the
// scope is what permits it.
//
// spec: SPO-Xmailbox-SEC-067, SPO-Xmailbox-SEC-069
func TestH1LostAnswerOfADeviceSignedRevokePurgesTheDevice(t *testing.T) {
	registries(t, func(t *testing.T, durable bool) {
		var opts []rigOpt
		if durable {
			opts = append(opts, withDurableRegistry())
		}
		r := newRig(t, opts...)
		b := r.parkedLongPoll(r.b)
		r.hreg.RevokeHook = func(res relayregistry.RevokeResult, err error) (relayregistry.RevokeResult, error) {
			return relayregistry.RevokeResult{}, errors.New("the answer was lost")
		}
		rv := r.revoker()
		rv.revoke(deviceRevoke(t, r.b, 1, startTime))
		if code := b.expectError(); code != mailbox.CodeBinding {
			t.Fatalf("code %d", code)
		}
		if got := r.store.purgedMailboxes(); len(got) != 1 || got[0] != r.b.fp {
			t.Fatalf("purged %v, want bob's only", got)
		}
	})
}

// Obligation 14, positive, scope all: bob's key has two devices; the revoke's
// not-before is between their `from` times, so it invalidates the older device and
// not the newer one. Whether the registry's partial result lists the older device
// or the answer is lost entirely, exactly the older device is purged and the newer
// one keeps its queue and its binding.
//
// spec: SPO-Xmailbox-SEC-067, SPO-Xmailbox-SEC-069
func TestH1AllScopeErrorPurgesExactlyTheInvalidatedDevices(t *testing.T) {
	for _, tc := range []struct {
		name string
		hook func(res relayregistry.RevokeResult, err error) (relayregistry.RevokeResult, error)
	}{
		{"partial result", func(res relayregistry.RevokeResult, err error) (relayregistry.RevokeResult, error) {
			return res, errors.New("fsync failed")
		}},
		{"lost answer", func(res relayregistry.RevokeResult, err error) (relayregistry.RevokeResult, error) {
			return relayregistry.RevokeResult{}, errors.New("the answer was lost")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registries(t, func(t *testing.T, durable bool) {
				var opts []rigOpt
				if durable {
					opts = append(opts, withDurableRegistry())
				}
				r := newRig(t, opts...)
				b2 := r.addPeer("bob-laptop", r.b.wallet)
				b2.stmt = r.b.wallet.BindingStatement(b2.fp, startTime-10, startTime+30*24*3600, false)
				r.bind(b2)
				a, _ := r.login(r.a)
				for i, to := range []party.Fingerprint{r.b.fp, b2.fp} {
					if pr := a.put(uint32(i+1), to, envelope(100, byte(i+1))); pr.Status != mailbox.StatusStored {
						t.Fatalf("put %d: status %d", i+1, pr.Status)
					}
				}
				r.hreg.RevokeHook = tc.hook
				rv := r.revoker()
				rv.revoke(walletRevoke(r.b.wallet, 1, party.Fingerprint{}, true, startTime-30))
				if got := r.store.purgedMailboxes(); len(got) != 1 || got[0] != r.b.fp {
					t.Fatalf("purged %v, want only the older device", got)
				}
				if n := len(r.list(b2.fp)); n != 1 {
					t.Fatalf("%d entries left for the newer device, want 1", n)
				}
				if _, ok := r.bindingOf(b2.fp); !ok {
					t.Fatal("the newer device is no longer bound")
				}
			})
		})
	}
}

// H1: a refusal that touched no storage, or a context that ended, purges nothing,
// even when the binding is in fact gone (here the real revoke ran and the hook
// replaces its answer with the refusal): each of the refusals separately.
//
// spec: SPO-Xmailbox-SEC-069
func TestH1RefusalsAndContextErrorsPurgeNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"revoke rate", relayregistry.ErrRevokeRate},
		{"tombstone table full", relayregistry.ErrTombstoneFull},
		{"unverified", relaybind.ErrUnverified},
		{"range", relaybind.ErrRange},
		{"context cancelled", context.Canceled},
		{"context deadline", context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			r.hreg.RevokeHook = func(res relayregistry.RevokeResult, err error) (relayregistry.RevokeResult, error) {
				return relayregistry.RevokeResult{}, tc.err
			}
			rv := r.revoker()
			rr := rv.revoke(walletRevoke(r.b.wallet, 1, r.b.fp, false, startTime))
			if rr.Status != mailbox.RevokeRefused {
				t.Fatalf("status %d, want refused", rr.Status)
			}
			if got := r.store.purgedMailboxes(); len(got) != 0 {
				t.Fatalf("purged %v after %v", got, tc.err)
			}
		})
	}
}

// Obligation 14, positive: a partial result closes and purges what it lists even
// when the error is one of the refusals (the result is what was really done).
//
// spec: SPO-Xmailbox-SEC-067, SPO-Xmailbox-SEC-069
func TestH1ListedDevicesArePurgedWhateverTheError(t *testing.T) {
	for _, err := range []error{errors.New("fsync failed"), relayregistry.ErrRevokeRate, context.Canceled} {
		t.Run(err.Error(), func(t *testing.T) {
			r := newRig(t)
			r.hreg.RevokeHook = func(res relayregistry.RevokeResult, _ error) (relayregistry.RevokeResult, error) {
				return res, err
			}
			rv := r.revoker()
			rv.revoke(walletRevoke(r.b.wallet, 1, r.b.fp, false, startTime))
			got := r.store.purgedMailboxes()
			if !slices.Equal(got, []party.Fingerprint{r.b.fp}) {
				t.Fatalf("purged %v, want bob's only", got)
			}
		})
	}
}
