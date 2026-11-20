//go:build unix

package bindingstore

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

// A tombstone whose rename happened and whose directory sync then failed is
// not known to be durable: the revoke is not `recorded` (the client sends it
// again), memory enforces it, and the next sweep syncs it and confirms it.
//
// spec: SPO-Xmailbox-INV-044, SPO-Xmailbox-OUT-128
func TestATombstoneWhoseSyncFailedIsNotRecorded(t *testing.T) {
	boom := errors.New("injected: the directory sync failed")
	sm := realSeams()
	armed := false
	sm.hook = func(step string) error {
		if armed && step == stepDirSynced {
			armed = false
			return boom
		}
		return nil
	}
	s, _, err := openWithSeams(t, newDir(t), relayporttest.NewManualClock(t0), nil, sm)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register(t.Context(), wal1.Present(t, dev1, bFrom, bUntil, t0)); err != nil {
		t.Fatal(err)
	}
	armed = true
	res, err := s.Revoke(t.Context(), wal1.WalletRevoke(t, dev1, bFrom, t0))
	if !errors.Is(err, boom) {
		t.Fatalf("Revoke: %v, want the sync failure", err)
	}
	if res.Recorded {
		t.Fatalf("a tombstone whose durability is not confirmed is reported recorded: %+v", res)
	}
	if !errors.Is(err, relayport.ErrOutcomeUnknown) || !res.Unconfirmed || len(res.Invalidated) != 1 {
		t.Fatalf("the result: %+v, %v", res, err)
	}
	if _, ok, _ := s.Lookup(t.Context(), dev1); ok {
		t.Fatal("the unconfirmed tombstone is not enforced")
	}
	// the client's re-sent revoke writes it again and is recorded
	res, err = s.Revoke(t.Context(), wal1.WalletRevoke(t, dev1, bFrom, t0))
	if err != nil || !res.Recorded {
		t.Fatalf("the re-sent revoke: %+v, %v", res, err)
	}
	if st, _ := s.Stats(t.Context()); st.Unconfirmed != 0 {
		t.Fatalf("%d unconfirmed after the re-sent revoke", st.Unconfirmed)
	}
	// a second one is confirmed by the sweep's sync
	if _, err := s.Register(t.Context(), wal2.Present(t, dev2, bFrom, bUntil, t0)); err != nil {
		t.Fatal(err)
	}
	armed = true
	if _, err := s.Revoke(t.Context(), wal2.WalletRevoke(t, dev2, bFrom, t0)); !errors.Is(err, boom) {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := s.Sweep(t.Context()); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.Stats(t.Context()); st.Unconfirmed != 0 {
		t.Fatalf("%d unconfirmed after the sweep", st.Unconfirmed)
	}
}

// A room-making drop that failed with an error that is not a refusal is held
// back for a minute, not an hour: an I/O error is not a retention. A refusal
// is still held for the hour.
//
// spec: SPO-Xmailbox-OUT-124
func TestAFailedDropIsHeldForAMinute(t *testing.T) {
	for _, c := range []struct {
		cause error
		want  int // attempts in all after a second revoke 61 s later
	}{{unix.EIO, 8}, {fmt.Errorf("%w: injected", relayport.ErrDeleteRefused), 4}} {
		t.Run(c.cause.Error(), func(t *testing.T) {
			clock := relayporttest.NewManualClock(t0)
			s, _, err := openWithSeams(t, newDir(t), clock, func(c *relayregistry.Config) { c.MaxBoundDevices = 2; c.MaxTombstones = 4 }, realSeams())
			if err != nil {
				t.Fatal(err)
			}
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
			clock.Advance(time.Duration(relaybind.MaxLifetimeSeconds+relaybind.SkewSeconds+10) * time.Second)
			attempts := 0
			s.sm.unlinkat = func(fd int, name string, fl int) error {
				if isTombName(name) {
					attempts++
					return c.cause
				}
				return unix.Unlinkat(fd, name, fl)
			}
			revokeOne := func(n byte) {
				t.Helper()
				now := clock.Now().Unix()
				w, d := relayporttest.NewWallet(n), relayporttest.Device(n)
				if _, err := s.Register(t.Context(), w.Present(t, d, now-60, now-60+86400, now)); err != nil {
					t.Fatal(err)
				}
				if _, err := s.Revoke(t.Context(), w.WalletRevoke(t, d, now-60, now)); err != nil {
					t.Fatal(err)
				}
			}
			revokeOne(90)
			if attempts != 4 {
				t.Fatalf("%d drops tried, want 4", attempts)
			}
			if relayregistry.HoldErrorSeconds != 60 {
				t.Fatalf("HoldErrorSeconds = %d", relayregistry.HoldErrorSeconds)
			}
			clock.Advance(time.Duration(relayregistry.HoldErrorSeconds+1) * time.Second)
			revokeOne(91)
			if attempts != c.want {
				t.Fatalf("61 s after the failure the drops were tried %d times in all, want %d", attempts, c.want)
			}
		})
	}
}
