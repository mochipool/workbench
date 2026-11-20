package objregistry

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
	"github.com/mochipool/workbench/spo/test/s3stand"
)

// fixture: three bindings revoked by one tombstone of each scope, and one
// tombstone raised twice (three versions).
type revoked struct {
	w    *relayporttest.Wallet
	d    party.Fingerprint
	k    relayregistry.TombKey
	nb   int64
	from int64
}

func (e *env) revokeEachScope(r *Registry) []revoked {
	e.t.Helper()
	ctx := bg(e.t)
	var out []revoked
	now := e.clock.Now().Unix()
	for i, scope := range []relaybind.Scope{relaybind.ScopePair, relaybind.ScopeAll, relaybind.ScopeDevice} {
		w, d := relayporttest.NewWallet(byte(10+i)), relayporttest.Device(byte(10+i))
		if _, err := r.Register(ctx, w.Present(e.t, d, bFrom, bUntil, now)); err != nil {
			e.t.Fatal(err)
		}
		var rec relayregistry.RevokeRecord
		k := relayregistry.TombKey{Scope: scope}
		switch scope {
		case relaybind.ScopePair:
			rec, k.Key, k.Device = w.WalletRevoke(e.t, d, bFrom, now), w.Key, d
		case relaybind.ScopeAll:
			rec, k.Key = w.AllRevoke(e.t, bFrom, now), w.Key
		default:
			rec, k.Device = relayporttest.DeviceRevoke(e.t, d, bFrom), d
		}
		res, err := r.Revoke(ctx, rec)
		if err != nil || !res.Recorded || len(res.Invalidated) != 1 {
			e.t.Fatalf("revoke of scope %d: %+v, %v", scope, res, err)
		}
		out = append(out, revoked{w: w, d: d, k: k, nb: bFrom, from: bFrom})
	}
	// two raises of the pair tombstone: three locked versions of one name
	for _, nb := range []int64{bFrom + 100, bFrom + 200} {
		if _, err := r.Revoke(ctx, out[0].w.WalletRevoke(e.t, out[0].d, nb, now)); err != nil {
			e.t.Fatal(err)
		}
		out[0].nb = nb
	}
	if n := len(e.tombVersions(out[0].k)); n != 3 {
		e.t.Fatalf("the pair tombstone has %d versions, want 3", n)
	}
	return out
}

func valueOf(ts relaybind.Tombstones, s relaybind.Scope) int64 {
	switch s {
	case relaybind.ScopePair:
		return ts.Pair
	case relaybind.ScopeAll:
		return ts.All
	}
	return ts.Device
}

// enforced asserts that r holds every tombstone at its value and refuses the
// revoked binding when it is presented again.
func (e *env) enforced(r *Registry, rs []revoked) {
	e.t.Helper()
	ctx := bg(e.t)
	for _, x := range rs {
		key := x.w.Key
		ts, err := r.Tombstones(ctx, key, x.d)
		if err != nil {
			e.t.Fatal(err)
		}
		if got := valueOf(ts, x.k.Scope); got != x.nb {
			e.t.Errorf("scope %d: not-before %d, want %d", x.k.Scope, got, x.nb)
		}
		_, err = r.Register(ctx, x.w.Present(e.t, x.d, x.from, bUntil, e.clock.Now().Unix()))
		if !errors.Is(err, relaybind.ErrRevoked) {
			e.t.Errorf("scope %d: the revoked binding presented again: %v, want ErrRevoked", x.k.Scope, err)
		}
		if _, ok, _ := r.Lookup(ctx, x.d); ok {
			e.t.Errorf("scope %d: a revoked device is served", x.k.Scope)
		}
	}
}

// A foreign principal (or the store's operator) puts a delete marker over
// every tombstone: a plain listing shows none, the load still enforces them
// all, and a later raise is still recorded (create-only over the marker).
//
// spec: SPO-Xobjstore-PRE-802, SPO-Xobjstore-SEC-801
func TestADeleteMarkerOverEveryTombstoneHidesNothing(t *testing.T) {
	e := newEnv(t, nil)
	r := e.initStore(testCfg(nil))
	rs := e.revokeEachScope(r)
	r.Close()
	for _, x := range rs {
		e.srv.AdminDeleteMarker(regBucket, tombKey(testPrefix, x.k))
		if _, live := e.srv.Current(regBucket, tombKey(testPrefix, x.k)); live {
			t.Fatal("setup: the delete marker does not hide the current version")
		}
	}
	r2 := e.mustOpen(testCfg(nil))
	e.enforced(r2, rs)
	if n := r2.Versions(); n != 5 {
		t.Errorf("%d versions loaded, want 5 (delete markers are not versions)", n)
	}
	x := rs[1]
	res, err := r2.Revoke(bg(t), x.w.AllRevoke(t, x.nb+50, e.clock.Now().Unix()))
	if err != nil || !res.Recorded || !res.Raised {
		t.Fatalf("a raise over a delete marker: %+v, %v", res, err)
	}
	e.noForbiddenRequests()
}

// The operator writes a lower not-before on top of a raised tombstone: the
// load takes the highest across versions, and a refresh of a live writer
// lowers nothing; the writer's next raise is conditional on the new version
// and is recorded.
//
// spec: SPO-Xobjstore-PRE-802, SPO-Xobjstore-OUT-804
func TestALowerVersionOnTopLowersNothing(t *testing.T) {
	e := newEnv(t, nil)
	r := e.initStore(testCfg(nil))
	rs := e.revokeEachScope(r)
	x := rs[0]
	e.srv.AdminPutVersion(regBucket, tombKey(testPrefix, x.k), encodeTomb(bFrom-1000))
	res, err := r.RefreshTombstones(bg(t))
	if err != nil || res.Raised != 0 {
		t.Fatalf("a refresh that finds a lower version: %+v, %v", res, err)
	}
	e.enforced(r, rs)
	r.Close()
	r2 := e.mustOpen(testCfg(nil))
	e.enforced(r2, rs)
	if rv, err := r2.Revoke(bg(t), x.w.WalletRevoke(t, x.d, x.nb+1, e.clock.Now().Unix())); err != nil || !rv.Recorded {
		t.Fatalf("a raise over the operator's lower version: %+v, %v", rv, err)
	}
}

// An older version of a binding is restored as current (a copy, the way S3
// restores): the load verifies it again; it is served only as what it is
// (the older binding), the device's current binding replaces it, and the
// writer's next write is conditional on the restored version, not a conflict.
//
// spec: SPO-Xobjstore-OUT-803
func TestAnOlderBindingVersionRestoredIsOnlyThatBinding(t *testing.T) {
	e := newEnv(t, nil)
	r := e.initStore(testCfg(nil))
	ctx := bg(t)
	w, d := relayporttest.NewWallet(1), relayporttest.Device(1)
	now := e.clock.Now().Unix()
	if _, err := r.Register(ctx, w.Present(t, d, bFrom, bUntil, now)); err != nil {
		t.Fatal(err)
	}
	newer := w.Present(t, d, bFrom+30, bUntil, now)
	if _, err := r.Register(ctx, newer); err != nil {
		t.Fatal(err)
	}
	key := bindingKey(testPrefix, d)
	vs := e.srv.Versions(regBucket, key)
	if len(vs) != 2 {
		t.Fatalf("%d binding versions", len(vs))
	}
	if _, err := e.srv.AdminRestoreVersion(regBucket, key, vs[0].ID); err != nil {
		t.Fatal(err)
	}
	r.Close()
	r2 := e.mustOpen(testCfg(nil))
	got, ok, _ := r2.Lookup(ctx, d)
	if !ok || got.Binding.From != bFrom {
		t.Fatalf("after the restore: %+v, %v", got, ok)
	}
	res, err := r2.Register(ctx, w.Present(t, d, bFrom+30, bUntil, now))
	if err != nil || res.Outcome != relayregistry.Replaced {
		t.Fatalf("the current binding over the restored one: %+v, %v", res, err)
	}
}

// A binding object restored after its revoke (the operator copies its old
// version back over the delete marker): the load checks it against the
// tombstones, drops it, deletes it again and never serves it.
//
// spec: SPO-Xobjstore-OUT-803, SPO-Xobjstore-PRE-802
func TestABindingRestoredAfterItsRevokeIsDroppedAtLoad(t *testing.T) {
	e := newEnv(t, nil)
	r := e.initStore(testCfg(nil))
	rs := e.revokeEachScope(r)
	r.Close()
	for _, x := range rs {
		key := bindingKey(testPrefix, x.d)
		vs := e.srv.Versions(regBucket, key)
		if len(vs) < 2 || !vs[len(vs)-1].DeleteMarker {
			t.Fatalf("setup: the revoke did not delete the binding: %+v", vs)
		}
		if _, err := e.srv.AdminRestoreVersion(regBucket, key, vs[0].ID); err != nil {
			t.Fatal(err)
		}
	}
	r2, notes, err := e.open(testCfg(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(notes, "\n"), "dropped 3 binding(s) revoked by a tombstone") {
		t.Errorf("notes: %q", notes)
	}
	e.enforced(r2, rs)
	for _, x := range rs {
		if _, live := e.srv.Current(regBucket, bindingKey(testPrefix, x.d)); live {
			t.Errorf("the restored binding of %x is still current in the store", x.d[:2])
		}
	}
}

// A prefix emptied in one bucket, or a marker removed while the identity has
// state, refuses the start; a store with nothing of the identity is new and
// refused without InitIdentity; a marker that names another identity refuses;
// a delete marker over the registry marker hides nothing.
//
// spec: SPO-Xobjstore-PRE-801, SPO-Xobjstore-IF-803
func TestAnEmptiedPrefixOrAMissingMarkerRefusesTheStart(t *testing.T) {
	t.Run("new store", func(t *testing.T) {
		e := newEnv(t, nil)
		_, _, err := e.open(testCfg(nil))
		wantErr(t, err, ErrStoreNew)
		if len(e.srv.UnconditionalPuts()) != 0 || e.putsAfter(0) != 0 {
			t.Fatal("an ordinary start wrote something to a new store")
		}
	})
	t.Run("the working bucket emptied", func(t *testing.T) {
		e := newEnv(t, nil)
		e.initStore(testCfg(nil)).Close()
		for _, k := range []string{testPrefix + markerPath, testPrefix + ratesPath} {
			if err := e.srv.AdminRollback(workBucket, k, ""); err != nil {
				t.Fatal(err)
			}
		}
		_, _, err := e.open(testCfg(nil))
		wantErr(t, err, ErrStoreEmptied)
		_, _, err = e.open(testCfg(nil), func(o *options) { o.init = true })
		if err != nil {
			t.Fatalf("init-store over an emptied working bucket whose registry is new: %v", err)
		}
	})
	t.Run("the registry bucket emptied", func(t *testing.T) {
		e := newEnv(t, nil)
		r := e.initStore(testCfg(nil))
		e.revokeEachScope(r)
		r.Close()
		// governance-like: an operator able to remove locked versions empties it
		e.srv.Do(func() { e.reg.IgnoreRetention = true })
		for _, k := range e.keysUnder(regBucket, testPrefix) {
			if err := e.srv.AdminRollback(regBucket, k, ""); err != nil {
				t.Fatal(err)
			}
		}
		_, _, err := e.open(testCfg(nil))
		wantErr(t, err, ErrStoreEmptied)
		_, _, err = e.open(testCfg(nil), func(o *options) { o.init = true })
		wantErr(t, err, ErrStoreEmptied) // the working bucket still holds the rates: not new
	})
	t.Run("state without a marker", func(t *testing.T) {
		e := newEnv(t, nil)
		k := relayregistry.TombKey{Scope: relaybind.ScopeDevice, Device: relayporttest.Device(9)}
		e.srv.AdminPutVersion(regBucket, tombKey(testPrefix, k), encodeTomb(bFrom))
		_, _, err := e.open(testCfg(nil))
		wantErr(t, err, ErrStoreEmptied)
		_, _, err = e.open(testCfg(nil), func(o *options) { o.init = true })
		wantErr(t, err, ErrStoreEmptied)
		if _, ok := e.srv.Current(regBucket, testPrefix+markerPath); ok {
			t.Fatal("InitIdentity wrote a marker over a prefix that holds state")
		}
	})
	t.Run("another identity's marker", func(t *testing.T) {
		e := newEnv(t, nil)
		e.initStore(testCfg(nil)).Close()
		other := testNode
		other[0] ^= 1
		e.srv.AdminPutVersion(workBucket, testPrefix+markerPath, encodeMarker(other))
		_, _, err := e.open(testCfg(nil))
		wantErr(t, err, ErrStoreEmptied)
	})
	t.Run("a delete marker over the registry marker", func(t *testing.T) {
		e := newEnv(t, nil)
		e.initStore(testCfg(nil)).Close()
		e.srv.AdminDeleteMarker(regBucket, testPrefix+markerPath)
		if _, _, err := e.open(testCfg(nil)); err != nil {
			t.Fatalf("a delete marker over the marker refused the start: %v", err)
		}
	})
}

// The working bucket's rate object rolled back, deleted or damaged gives no
// token a restart without stored state would not (the burst), and a deleted
// or damaged one gives none at all; a later SaveRates is conditional on the
// object the load found.
//
// spec: SPO-Xobjstore-OUT-802
func TestARolledBackWorkingBucketGivesNoExtraTokens(t *testing.T) {
	e := newEnv(t, nil)
	r := e.initStore(testCfg(nil))
	ctx := bg(t)
	full, _ := e.srv.Current(workBucket, testPrefix+ratesPath)
	now := e.clock.Now().Unix()
	for i := byte(0); i < 10; i++ {
		if _, err := r.Register(ctx, relayporttest.NewWallet(100+i).Present(t, relayporttest.Device(100+i), bFrom, bUntil, now)); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.SaveRates(ctx); err != nil {
		t.Fatal(err)
	}
	r.Close()
	tokens := func() int {
		t.Helper()
		r, _, err := e.open(testCfg(nil))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		s, _ := r.Stats(ctx)
		return s.NewTokens
	}
	if n := tokens(); n != 0 {
		t.Fatalf("after spending the burst and a restart: %d tokens", n)
	}
	e.srv.AdminPutVersion(workBucket, testPrefix+ratesPath, full) // rolled back to the init's full buckets
	if n := tokens(); n > relayregistry.DefaultConfig().NewBindingBurst {
		t.Fatalf("a rolled-back rate object gave %d tokens, more than the burst", n)
	}
	for name, body := range map[string][]byte{
		"deleted": nil,
		"damaged": append([]byte{full[0] ^ 0xff}, full[1:]...),
		"too big": append(bytes.Clone(full), make([]byte, 100)...),
		"out of range": encodeRates(relayregistry.RateSnapshot{NewBindings: relayregistry.RateState{Units: 1 << 40, At: now},
			Revokes: relayregistry.RateState{Units: 0, At: now}}),
	} {
		if body == nil {
			if err := e.srv.AdminRollback(workBucket, testPrefix+ratesPath, ""); err != nil {
				t.Fatal(err)
			}
		} else {
			e.srv.AdminPutVersion(workBucket, testPrefix+ratesPath, body)
		}
		if n := tokens(); n != 0 {
			t.Errorf("%s rate object: %d tokens, want 0 (empty buckets)", name, n)
		}
		r := e.mustOpen(testCfg(nil))
		if err := r.SaveRates(ctx); err != nil {
			t.Errorf("SaveRates over a %s rate object: %v", name, err)
		}
		r.Close()
	}
}

// A stale listing at load (it misses the latest version of a name) refuses
// the start instead of loading the lower value; at a refresh it lowers
// nothing and is not adopted, so the next raise is not a conflict. A listing
// whose IsLatest lies fails the refresh and leaves memory as it was.
//
// spec: SPO-Xobjstore-PRE-803, SPO-Xobjstore-OUT-804
func TestAStaleOrLyingListingNeverLowersANotBefore(t *testing.T) {
	e := newEnv(t, nil)
	r := e.initStore(testCfg(nil))
	ctx := bg(t)
	rs := e.revokeEachScope(r)
	x := rs[0]
	e.srv.Snapshot() // the state with the pair tombstone at bFrom + 200
	rv, err := r.Revoke(ctx, x.w.WalletRevoke(t, x.d, x.nb+50, e.clock.Now().Unix()))
	if err != nil || !rv.Raised {
		t.Fatalf("%+v, %v", rv, err)
	}
	rs[0].nb = x.nb + 50

	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStaleList, Op: s3stand.OpListVersions})
	if res, err := r.RefreshTombstones(ctx); err != nil || res.Raised != 0 {
		t.Fatalf("a refresh over a stale listing: %+v, %v", res, err)
	}
	e.enforced(r, rs)
	if rv, err := r.Revoke(ctx, x.w.WalletRevoke(t, x.d, rs[0].nb+1, e.clock.Now().Unix())); err != nil || !rv.Raised {
		t.Fatalf("a raise after a stale refresh: %+v, %v", rv, err)
	}
	rs[0].nb++
	e.srv.ClearFaults()
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultLieIsLatest, Op: s3stand.OpListVersions})
	if _, err := r.RefreshTombstones(ctx); err == nil {
		t.Fatal("a refresh over a lying listing succeeded")
	}
	e.enforced(r, rs)
	r.Close()

	e.srv.ClearFaults()
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStaleList, Op: s3stand.OpListVersions})
	_, _, err = e.open(testCfg(nil))
	wantErr(t, err, ErrStaleListing)
	e.srv.ClearFaults()
	e.enforced(e.mustOpen(testCfg(nil)), rs)
}
