//go:build unix

package bindingstore

import (
	"crypto/sha256"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

// The cases of the registry review (ADR 0014 work package 5): what Open does with
// a directory whose policy, bounds or clock changed, and what a failed delete
// leaves behind.

// devN is a fingerprint for the n-th record of a crowd: the registry names a
// binding by the fingerprint in its file name and payload, and nothing relates it
// to keys.
func devN(n int) party.Fingerprint {
	var f party.Fingerprint
	f[0], f[1], f[2] = byte(n), byte(n>>8), 0x5a
	return f
}

func recordFile(t testing.TB, w *relayporttest.Wallet, d party.Fingerprint, from, until, lastAuth, now int64) []byte {
	t.Helper()
	p := w.Present(t, d, from, until, now)
	return encodeRecord(relayregistry.Record{LastAuth: lastAuth, Sign1: p.Sign1(), COSEKey: p.COSEKey()})
}

func dirEntries(t testing.TB, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

func containsNote(notes []string, sub string) bool {
	for _, n := range notes {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}

// Tightening the maximum lifetime and restarting drops the longer bindings with
// a note, like an expiry. It does not quarantine them (they are not damaged),
// and with more than the quarantine's 256 files Open does not refuse.
//
// spec: SPO-Xmailbox-OUT-080
func TestTightenedLifetimeDropsInsteadOfQuarantining(t *testing.T) {
	dir := prep(t)
	const n = 300
	for i := 0; i < n; i++ {
		writeFile(t, bpath(dir, devN(i)), recordFile(t, wal1, devN(i), bFrom, bUntil, t0, t0), 0o600)
	}
	s, notes := openAt(t, dir, relayporttest.NewManualClock(t0), func(c *relayregistry.Config) { c.Policy.MaxLifetime = 30 * 86400 })
	if q := dirEntries(t, filepath.Join(dir, quarantineDir)); len(q) != 0 {
		t.Fatalf("%d bindings were quarantined for a lifetime over the policy; they are not damaged", len(q))
	}
	if b := dirEntries(t, filepath.Join(dir, bindingsDir)); len(b) != 0 {
		t.Fatalf("%d files left in the bindings directory", len(b))
	}
	if st, _ := s.Stats(t.Context()); st.Bindings != 0 {
		t.Fatalf("stats = %+v", st)
	}
	if !containsNote(notes, "lifetime") {
		t.Fatalf("no note about the lifetime policy: %q", notes)
	}
	if len(notes) > 4 {
		t.Fatalf("%d notes for one cause; they are summarised", len(notes))
	}
	// a binding within the policy stays
	s.Close()
	dir2 := prep(t)
	writeFile(t, bpath(dir2, dev1), recordFile(t, wal1, dev1, bFrom, bFrom+30*86400, t0, t0), 0o600)
	s2, notes2 := openAt(t, dir2, relayporttest.NewManualClock(t0), func(c *relayregistry.Config) { c.Policy.MaxLifetime = 30 * 86400 })
	if _, ok, _ := s2.Lookup(t.Context(), dev1); !ok || len(notes2) != 0 {
		t.Fatalf("a binding of exactly the policy's lifetime: found %v, notes %q", ok, notes2)
	}
}

// A clock stepped back at start by more than the skew (a board with no battery
// clock) does not quarantine the recent bindings as not yet valid: they are kept
// on disk, not served until the clock reaches them, and Open says the clock
// looks wrong.
//
// spec: SPO-Xmailbox-OUT-080, SPO-Xmailbox-SEC-060
func TestClockSteppedBackKeepsBindings(t *testing.T) {
	dir := newDir(t)
	clock := relayporttest.NewManualClock(t0)
	s, _ := openAt(t, dir, clock, nil)
	if _, err := s.Register(t.Context(), wal1.Present(t, dev1, bFrom, bUntil, t0)); err != nil {
		t.Fatal(err)
	}
	s.Close()
	const back = 10000
	behind := relayporttest.NewManualClock(t0 - back)
	s2, notes := openAt(t, dir, behind, nil)
	if q := dirEntries(t, filepath.Join(dir, quarantineDir)); len(q) != 0 {
		t.Fatalf("a binding was quarantined for a time reason: %v", q)
	}
	if _, err := os.Lstat(bpath(dir, dev1)); err != nil {
		t.Fatalf("the binding file is gone: %v", err)
	}
	if _, ok, _ := s2.Lookup(t.Context(), dev1); ok {
		t.Fatal("a binding that is not valid yet by the clock is served")
	}
	if !containsNote(notes, "clock appears to be behind") {
		t.Fatalf("no note about the clock: %q", notes)
	}
	if !containsNote(notes, "not valid yet") {
		t.Fatalf("no summary note about the bindings that wait: %q", notes)
	}
	behind.Advance(back * time.Second)
	if _, ok, _ := s2.Lookup(t.Context(), dev1); !ok {
		t.Fatal("the binding is not served once the clock reaches it")
	}
	// a clock within the skew of the last authentication is quiet
	s2.Close()
	_, notes3 := openAt(t, dir, relayporttest.NewManualClock(t0), nil)
	if len(notes3) != 0 {
		t.Fatalf("notes at a right clock: %q", notes3)
	}
}

// Lowering max_bound_devices or the tombstone bound below what is stored does not
// make Open refuse: the scan is bounded by the ceilings, everything valid is
// loaded, and the normal eviction rules apply at the next registration.
//
// spec: SPO-Xmailbox-PRE-052
func TestLoweredBoundsStillOpen(t *testing.T) {
	dir := prep(t)
	const n = 25
	for i := 0; i < n; i++ {
		writeFile(t, bpath(dir, devN(i)), recordFile(t, wal1, devN(i), bFrom, bUntil, t0, t0), 0o600)
		writeFile(t, filepath.Join(dir, tombstonesDir, "d-"+deviceName(devN(1000+i))), encodeTomb(bFrom-5), 0o600)
	}
	s, notes := openAt(t, dir, relayporttest.NewManualClock(t0), func(c *relayregistry.Config) { c.MaxBoundDevices = 1; c.MaxTombstones = 2 })
	st, _ := s.Stats(t.Context())
	if st.Bindings != n || st.Tombstones != n {
		t.Fatalf("stats = %+v, want all %d bindings and %d tombstones loaded", st, n, n)
	}
	if !containsNote(notes, "more than max_bound_devices") || !containsNote(notes, "more than the configured bound") {
		t.Fatalf("notes = %q", notes)
	}
	res, err := s.Register(t.Context(), wal2.Present(t, dev2, bFrom, bUntil, t0))
	if err != nil {
		t.Fatalf("Register above the lowered cap: %v", err)
	}
	if len(res.Evicted) != n {
		t.Fatalf("evicted %d, want the %d that stood above the cap", len(res.Evicted), n)
	}
	if st, _ := s.Stats(t.Context()); st.Bindings != 1 {
		t.Fatalf("stats = %+v", st)
	}
}

type fileSnap struct {
	mode fs.FileMode
	size int64
	sum  [32]byte
	link string
}

// snapshot records the names, modes, sizes and contents of a tree, without
// following links and without opening anything that is not a regular file.
func snapshot(t testing.TB, dir string) map[string]fileSnap {
	t.Helper()
	out := map[string]fileSnap{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		s := fileSnap{mode: fi.Mode(), size: fi.Size()}
		switch {
		case fi.Mode().IsRegular() && fi.Size() <= 1<<20: // never read a big file whole
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			s.sum = sha256.Sum256(b)
		case fi.Mode()&fs.ModeSymlink != 0:
			s.link, _ = os.Readlink(p)
		}
		out[rel] = s
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// diffSnap says what differs between two snapshots, or "".
func diffSnap(before, after map[string]fileSnap) string {
	var d []string
	for k, b := range before {
		a, ok := after[k]
		switch {
		case !ok:
			d = append(d, "removed "+k)
		case a != b:
			d = append(d, "changed "+k)
		}
	}
	for k := range after {
		if _, ok := before[k]; !ok {
			d = append(d, "added "+k)
		}
	}
	return strings.Join(d, ", ")
}

// An Open that is refused has changed nothing it found: the cleanups (temporary
// files, quarantine moves, rewrites) come after every check.
//
// spec: SPO-Xmailbox-SEC-061
func TestRefusedOpenLeavesTheDirectoryAlone(t *testing.T) {
	dir := prep(t)
	// things a successful Open would clean up ...
	writeFile(t, filepath.Join(dir, tombstonesDir, tmpPrefix+"0123456789abcdef"), []byte("half"), 0o600)
	writeFile(t, filepath.Join(dir, bindingsDir, tmpPrefix+"fedcba9876543210"), []byte("half"), 0o600)
	writeFile(t, bpath(dir, dev1), []byte("junk"), 0o600) // quarantined by a successful Open
	writeFile(t, bpath(dir, dev2), recordFile(t, wal1, dev2, bFrom, bFrom+86400, t0-100000000, t0), 0o600)
	// ... and what makes the Open refuse
	if err := unix.Mkfifo(bpath(dir, devN(7)), 0o600); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, dir)
	refuseOpen(t, dir, realSeams(), nil, "not a regular file")
	if d := diffSnap(before, snapshot(t, dir)); d != "" {
		t.Fatalf("a refused Open changed the directory: %s", d)
	}
}

// A failed delete does not lose what was done. The tombstone was written, so the
// binding is invalidated: no reader serves it though its file is still there, the
// result tells the caller (who closes its sessions and drops its mail), and the
// error comes with it. A sweep, or the client's re-sent revoke, removes the file.
//
// spec: SPO-Xmailbox-OUT-076, SPO-Xmailbox-OUT-077, SPO-Xmailbox-OUT-081
func TestFailedUnlinkKeepsTheResultAndServesNothing(t *testing.T) {
	setup := func(t *testing.T) (*Store, string) {
		dir := newDir(t)
		s, _, err := openWithSeams(t, dir, relayporttest.NewManualClock(t0), nil, realSeams())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Register(t.Context(), wal1.Present(t, dev1, bFrom, bUntil, t0)); err != nil {
			t.Fatal(err)
		}
		if err := s.SetExpectedSenders(t.Context(), dev1, nil); err != nil {
			t.Fatal(err)
		}
		s.sm.unlinkat = func(int, string, int) error { return unix.EIO }
		res, err := s.Revoke(t.Context(), wal1.WalletRevoke(t, dev1, bFrom, t0))
		if !errors.Is(err, unix.EIO) {
			t.Fatalf("Revoke: %v", err)
		}
		if !res.Recorded || len(res.Invalidated) != 1 || res.Invalidated[0].Device != dev1 {
			t.Fatalf("the result of the revoke was lost with the error: %+v", res)
		}
		if _, ok, _ := s.Lookup(t.Context(), dev1); ok {
			t.Fatal("Lookup serves a binding that a stored tombstone invalidates")
		}
		if devs, _ := s.Devices(t.Context(), wal1.Key); len(devs) != 0 {
			t.Fatalf("Devices lists it: %v", devs)
		}
		if got, _ := s.ExpectedSenders(t.Context(), dev1); len(got) != 0 {
			t.Fatalf("ExpectedSenders serves it: %v", got)
		}
		if ts, _ := s.Tombstones(t.Context(), wal1.Key, dev1); ts.Pair != bFrom {
			t.Fatal("the tombstone, which was written, is not in memory")
		}
		if _, err := os.Lstat(bpath(dir, dev1)); err != nil {
			t.Fatalf("the file should still be there: %v", err)
		}
		s.sm.unlinkat = unix.Unlinkat
		return s, dir
	}
	t.Run("a re-sent revoke finishes it", func(t *testing.T) {
		s, dir := setup(t)
		res, err := s.Revoke(t.Context(), wal1.WalletRevoke(t, dev1, bFrom, t0))
		if err != nil || res.Raised || len(res.Invalidated) != 1 {
			t.Fatalf("retry = %+v, %v", res, err)
		}
		if _, err := os.Lstat(bpath(dir, dev1)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("the file survived the retry")
		}
	})
	t.Run("a sweep finishes it", func(t *testing.T) {
		s, dir := setup(t)
		sw, err := s.Sweep(t.Context())
		if err != nil || len(sw.Invalidated) != 1 {
			t.Fatalf("sweep = %+v, %v", sw, err)
		}
		if _, err := os.Lstat(bpath(dir, dev1)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("the file survived the sweep")
		}
	})
}

// A registration that evicts a binding and then fails to write the newcomer does
// not lose the eviction: the session purges the queue of what was evicted.
//
// spec: SPO-Xmailbox-OUT-077
func TestFailedRegisterReturnsTheEvictions(t *testing.T) {
	boom := errors.New("injected")
	sm := realSeams()
	fail := false
	sm.hook = func(step string) error {
		if fail && step == stepTmpCreated {
			return boom
		}
		return nil
	}
	s, _, err := openWithSeams(t, newDir(t), relayporttest.NewManualClock(t0), func(c *relayregistry.Config) { c.MaxBoundDevices = 1 }, sm)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register(t.Context(), wal1.Present(t, dev1, bFrom, bUntil, t0)); err != nil {
		t.Fatal(err)
	}
	fail = true
	res, err := s.Register(t.Context(), wal2.Present(t, dev2, bFrom, bUntil, t0))
	if !errors.Is(err, boom) {
		t.Fatalf("Register: %v", err)
	}
	if len(res.Evicted) != 1 || res.Evicted[0].Device != dev1 {
		t.Fatalf("the eviction was lost with the error: %+v", res)
	}
	if _, ok, _ := s.Lookup(t.Context(), dev1); ok {
		t.Fatal("the evicted binding is still served")
	}
}

// An all revoke deletes one binding and fails to delete the other: the result
// names both (neither is served any more), so the session closes both.
//
// spec: SPO-Xmailbox-OUT-077
func TestPartialRevokeReturnsWhatWasApplied(t *testing.T) {
	dir := newDir(t)
	s, _, err := openWithSeams(t, dir, relayporttest.NewManualClock(t0), nil, realSeams())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []party.Fingerprint{dev1, dev2} {
		if _, err := s.Register(t.Context(), wal1.Present(t, d, bFrom, bUntil, t0)); err != nil {
			t.Fatal(err)
		}
	}
	s.sm.unlinkat = func(fd int, name string, fl int) error {
		if name == deviceName(dev2) {
			return unix.EIO
		}
		return unix.Unlinkat(fd, name, fl)
	}
	res, err := s.Revoke(t.Context(), wal1.AllRevoke(t, bFrom, t0))
	if !errors.Is(err, unix.EIO) {
		t.Fatalf("Revoke: %v", err)
	}
	if len(res.Invalidated) != 2 {
		t.Fatalf("result names %d devices, want both: %+v", len(res.Invalidated), res)
	}
	for _, d := range []party.Fingerprint{dev1, dev2} {
		if _, ok, _ := s.Lookup(t.Context(), d); ok {
			t.Fatalf("device %x is still served", d[:2])
		}
	}
	if _, err := os.Lstat(bpath(dir, dev1)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("device 1's file was not deleted")
	}
	if _, err := os.Lstat(bpath(dir, dev2)); err != nil {
		t.Fatal("device 2's file is gone though its unlink failed")
	}
}
