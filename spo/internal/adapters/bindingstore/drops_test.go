//go:build unix

package bindingstore

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

// isTombName reports whether a name in a registry directory is a tombstone's.
func isTombName(name string) bool {
	return strings.HasPrefix(name, "p-") || strings.HasPrefix(name, "a-") || strings.HasPrefix(name, "d-")
}

// A revoke at a table that is at its bound with expired tombstones makes room by
// dropping them. When those drops fail, the revoke must still record its
// tombstone (in the headroom) and delete the binding it invalidates: a failed
// drop is held back, never a reason to leave a revoked binding live (ADR 0015
// decision 3, "The registry core"). Before the change, execute stopped at the
// first failed drop, before the tombstone and before the binding's delete.
//
// spec: SPO-Xmailbox-SEC-087, SPO-Xmailbox-PRE-040, SPO-Xmailbox-PRE-049, SPO-Xmailbox-OUT-079
func TestFailedDropDoesNotLeaveTheRevokedBindingLive(t *testing.T) {
	clock := relayporttest.NewManualClock(t0)
	s, _, err := openWithSeams(t, newDir(t), clock, func(c *relayregistry.Config) { c.MaxBoundDevices = 2; c.MaxTombstones = 4 }, realSeams())
	if err != nil {
		t.Fatal(err)
	}
	// four tombstones to the bound: two of nothing (the limited share) and two
	// that invalidate a binding each
	for i := byte(0); i < 2; i++ {
		if _, err := s.Revoke(t.Context(), relayporttest.NewWallet(50+i).WalletRevoke(t, relayporttest.Device(50+i), bFrom-10, t0)); err != nil {
			t.Fatal(err)
		}
	}
	for i := byte(0); i < 2; i++ {
		w, d := relayporttest.NewWallet(70+i), relayporttest.Device(70+i)
		if _, err := s.Register(t.Context(), w.Present(t, d, bFrom, bUntil, t0)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Revoke(t.Context(), w.WalletRevoke(t, d, bFrom, t0)); err != nil {
			t.Fatal(err)
		}
	}
	// every one of them expires
	clock.Advance(time.Duration(relaybind.MaxLifetimeSeconds+relaybind.SkewSeconds+10) * time.Second)
	now := clock.Now().Unix()
	w, d := relayporttest.NewWallet(90), relayporttest.Device(90)
	if _, err := s.Register(t.Context(), w.Present(t, d, now-60, now-60+86400, now)); err != nil {
		t.Fatal(err)
	}
	attempts := 0
	s.sm.unlinkat = func(fd int, name string, fl int) error {
		if isTombName(name) {
			attempts++
			return unix.EIO
		}
		return unix.Unlinkat(fd, name, fl)
	}
	res, err := s.Revoke(t.Context(), w.WalletRevoke(t, d, now-60, now))
	if err != nil {
		t.Fatalf("a revoke whose room-making drops failed: %v", err)
	}
	if len(res.Invalidated) != 1 || res.Invalidated[0].Device != d || !res.Recorded || res.TombstoneUnrecorded {
		t.Fatalf("result = %+v, want the binding invalidated and the tombstone recorded in the headroom", res)
	}
	if _, ok, _ := s.Lookup(t.Context(), d); ok {
		t.Fatal("the revoked binding is still served after its drops failed")
	}
	if ts, _ := s.Tombstones(t.Context(), w.Key, d); ts.Pair != now-60 {
		t.Fatalf("the tombstone was not recorded: %+v", ts)
	}
	if attempts != 4 {
		t.Fatalf("%d drops were tried, want each of the 4 once", attempts)
	}
	// the drops are held back: a second revoke does not try them again
	w2, d2 := relayporttest.NewWallet(91), relayporttest.Device(91)
	if _, err := s.Register(t.Context(), w2.Present(t, d2, now-60, now-60+86400, now)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Revoke(t.Context(), w2.WalletRevoke(t, d2, now-60, now)); err != nil {
		t.Fatal(err)
	}
	if attempts != 4 {
		t.Fatalf("held drops were tried again within the hour: %d attempts", attempts)
	}
	if _, ok, _ := s.Lookup(t.Context(), d2); ok {
		t.Fatal("the second revoked binding is still served")
	}
}
