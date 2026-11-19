//go:build unix

package bindingstore

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

var (
	wal1 = relayporttest.NewWallet(1)
	wal2 = relayporttest.NewWallet(2)
	dev1 = relayporttest.Device(1)
	dev2 = relayporttest.Device(2)
)

// prep makes a directory with the layout and nothing in it, closed.
func prep(t testing.TB) string {
	t.Helper()
	dir := newDir(t)
	s, _, err := Open(dir, testCfg(nil), relayporttest.NewManualClock(t0))
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	return dir
}

func goodRecordFile(t testing.TB, w *relayporttest.Wallet, d party.Fingerprint) []byte {
	t.Helper()
	p := w.Present(t, d, bFrom, bUntil, t0)
	return encodeRecord(relayregistry.Record{LastAuth: t0, Sign1: p.Sign1(), COSEKey: p.COSEKey()})
}

func writeFile(t testing.TB, p string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(p, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func bpath(dir string, d party.Fingerprint) string {
	return filepath.Join(dir, bindingsDir, deviceName(d))
}

func refuseOpen(t *testing.T, dir string, sm seams, mod func(*relayregistry.Config), substr string) {
	t.Helper()
	before := snapshot(t, dir)
	defer func() {
		t.Helper()
		if d := diffSnap(before, snapshot(t, dir)); d != "" {
			t.Errorf("a refused Open changed the directory: %s", d)
		}
	}()
	done := make(chan error, 1)
	go func() {
		s, _, err := openWith(dir, testCfg(mod), relayporttest.NewManualClock(t0), sm)
		if err == nil {
			s.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("Open accepted the directory (want an error containing %q)", substr)
		}
		if !errors.Is(err, relayport.ErrRegistryCorrupt) {
			t.Fatalf("error %v does not wrap ErrRegistryCorrupt", err)
		}
		if !strings.Contains(err.Error(), substr) {
			t.Fatalf("error %q does not contain %q", err, substr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Open blocked (it opened something it should not have)")
	}
}

// armedSeams returns seams whose uid is wrong from the moment step is reached
// ("" for from the start).
func armedSeams(step string) seams {
	sm := realSeams()
	armed := step == ""
	sm.euid = func() int {
		if armed {
			return os.Geteuid() + 1
		}
		return os.Geteuid()
	}
	sm.hook = func(s string) error {
		if s == step {
			armed = true
		}
		return nil
	}
	return sm
}

// spec: SPO-Xmailbox-SEC-052
func TestHostileDirectories(t *testing.T) {
	type tc struct {
		name   string
		setup  func(t *testing.T, dir string)
		seams  seams
		mod    func(*relayregistry.Config)
		expect string
	}
	fifo := func(t *testing.T, p string) {
		if err := unix.Mkfifo(p, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := func(t *testing.T, p string) {
		if err := os.Symlink("/etc/passwd", p); err != nil {
			t.Fatal(err)
		}
	}
	real := realSeams()
	// the ceilings on the number of names, made small so that a test needs few files
	smallNames := realSeams()
	smallNames.maxBindNames, smallNames.maxTombNames = 18, 20
	// a small file that claims to be huge: the size comes from the injected fstat
	claims := realSeams()
	claims.fstat = func(fd int, st *unix.Stat_t) error {
		err := unix.Fstat(fd, st)
		st.Size = 1 << 40
		return err
	}
	cases := []tc{
		{"binding is a symbolic link", func(t *testing.T, d string) { link(t, bpath(d, dev1)) }, real, nil, "not a regular file"},
		{"binding is a FIFO", func(t *testing.T, d string) { fifo(t, bpath(d, dev1)) }, real, nil, "not a regular file"},
		{"binding is a directory", func(t *testing.T, d string) { os.Mkdir(bpath(d, dev1), 0o700) }, real, nil, "not a regular file"},
		{"tombstone is a symbolic link", func(t *testing.T, d string) {
			link(t, filepath.Join(d, tombstonesDir, "d-"+deviceName(dev1)))
		}, real, nil, "not a regular file"},
		{"tombstone is a FIFO", func(t *testing.T, d string) { fifo(t, filepath.Join(d, tombstonesDir, "d-"+deviceName(dev1))) }, real, nil, "not a regular file"},
		{"bindings directory is a link", func(t *testing.T, d string) {
			os.RemoveAll(filepath.Join(d, bindingsDir))
			os.Symlink(t.TempDir(), filepath.Join(d, bindingsDir))
		}, real, nil, "not part of a registry"},
		{"tombstones directory is a file", func(t *testing.T, d string) {
			os.RemoveAll(filepath.Join(d, tombstonesDir))
			writeFile(t, filepath.Join(d, tombstonesDir), []byte("x"), 0o600)
		}, real, nil, "not part of a registry"},
		{"quarantine directory is a link", func(t *testing.T, d string) {
			os.RemoveAll(filepath.Join(d, quarantineDir))
			os.Symlink(t.TempDir(), filepath.Join(d, quarantineDir))
		}, real, nil, "not part of a registry"},
		{"junk file at the top", func(t *testing.T, d string) { writeFile(t, filepath.Join(d, "notes.txt"), []byte("x"), 0o600) }, real, nil, "not part of a registry"},
		{"directory of another name at the top", func(t *testing.T, d string) { os.Mkdir(filepath.Join(d, "mailbox"), 0o700) }, real, nil, "not part of a registry"},
		{"lock file is a directory", func(t *testing.T, d string) {
			os.Remove(filepath.Join(d, lockName))
			os.Mkdir(filepath.Join(d, lockName), 0o700)
		}, real, nil, "not part of a registry"},
		{"cleanups come after the refusal", func(t *testing.T, d string) {
			writeFile(t, filepath.Join(d, tombstonesDir, tmpPrefix+"0123456789abcdef"), []byte("half"), 0o600)
			writeFile(t, filepath.Join(d, bindingsDir, "README"), []byte("x"), 0o600)
		}, real, nil, "not the name of a binding"},
		{"junk name in bindings", func(t *testing.T, d string) {
			writeFile(t, filepath.Join(d, bindingsDir, "README"), []byte("x"), 0o600)
		}, real, nil, "not the name of a binding"},
		{"upper-case device name", func(t *testing.T, d string) {
			writeFile(t, filepath.Join(d, bindingsDir, strings.ToUpper(deviceName(dev1))), []byte("x"), 0o600)
		}, real, nil, "not the name of a binding"},
		{"short device name", func(t *testing.T, d string) {
			writeFile(t, filepath.Join(d, bindingsDir, deviceName(dev1)[:39]), []byte("x"), 0o600)
		}, real, nil, "not the name of a binding"},
		{"junk name in tombstones", func(t *testing.T, d string) {
			writeFile(t, filepath.Join(d, tombstonesDir, "x-1"), encodeTomb(5), 0o600)
		}, real, nil, "not the name of a tombstone"},
		{"junk name in quarantine", func(t *testing.T, d string) {
			writeFile(t, filepath.Join(d, quarantineDir, "junk"), []byte("x"), 0o600)
		}, real, nil, "not the name of a quarantined"},
		{"binding over its size bound", func(t *testing.T, d string) {
			writeFile(t, bpath(d, dev1), make([]byte, maxRecordBytes+1), 0o600)
		}, real, nil, "bytes"},
		{"binding that claims a terabyte", func(t *testing.T, d string) { writeFile(t, bpath(d, dev1), []byte("x"), 0o600) }, claims, nil, "bytes"},
		{"tombstone of the wrong size", func(t *testing.T, d string) {
			writeFile(t, filepath.Join(d, tombstonesDir, "d-"+deviceName(dev1)), append(encodeTomb(5), 0), 0o600)
		}, real, nil, "bytes"},
		{"tombstone with a bad magic", func(t *testing.T, d string) {
			b := encodeTomb(5)
			b[0] ^= 1
			writeFile(t, filepath.Join(d, tombstonesDir, "d-"+deviceName(dev1)), b, 0o600)
		}, real, nil, "not a tombstone record"},
		{"tombstone not-before out of range", func(t *testing.T, d string) {
			b := encodeTomb(5)
			b[len(tombMagic)] = 0xff
			writeFile(t, filepath.Join(d, tombstonesDir, "d-"+deviceName(dev1)), b, 0o600)
		}, real, nil, "out of range"},
		{"root owned by someone else", func(t *testing.T, d string) {}, armedSeams(""), nil, "not owned by the user"},
		{"directory owned by someone else", func(t *testing.T, d string) {}, armedSeams(stepScanDirs), nil, "not owned by the user"},
		{"binding owned by someone else", func(t *testing.T, d string) {
			writeFile(t, bpath(d, dev1), goodRecordFile(t, wal1, dev1), 0o600)
		}, armedSeams(stepScanBindings), nil, "not owned by the user"},
		{"tombstone owned by someone else", func(t *testing.T, d string) {
			writeFile(t, filepath.Join(d, tombstonesDir, "d-"+deviceName(dev1)), encodeTomb(5), 0o600)
		}, armedSeams(stepScanTombstones), nil, "not owned by the user"},
		{"temporary file owned by someone else", func(t *testing.T, d string) {
			writeFile(t, filepath.Join(d, bindingsDir, tmpPrefix+"0123456789abcdef"), []byte("x"), 0o600)
		}, armedSeams(stepScanBindings), nil, "not owned by the user"},
		{"root writable by its group", func(t *testing.T, d string) { os.Chmod(d, 0o770) }, real, nil, "writable by its group or by everyone"},
		{"root writable by others", func(t *testing.T, d string) { os.Chmod(d, 0o702) }, real, nil, "writable by its group or by everyone"},
		{"bindings directory is group readable", func(t *testing.T, d string) { os.Chmod(filepath.Join(d, bindingsDir), 0o750) }, real, nil, "has mode"},
		{"tombstones directory is world readable", func(t *testing.T, d string) { os.Chmod(filepath.Join(d, tombstonesDir), 0o705) }, real, nil, "has mode"},
		{"binding file is group readable", func(t *testing.T, d string) {
			writeFile(t, bpath(d, dev1), goodRecordFile(t, wal1, dev1), 0o640)
		}, real, nil, "has mode"},
		{"binding file is world readable", func(t *testing.T, d string) {
			writeFile(t, bpath(d, dev1), goodRecordFile(t, wal1, dev1), 0o604)
		}, real, nil, "has mode"},
		{"tombstone file is world readable", func(t *testing.T, d string) {
			writeFile(t, filepath.Join(d, tombstonesDir, "d-"+deviceName(dev1)), encodeTomb(5), 0o644)
		}, real, nil, "has mode"},
		{"too many names in bindings", func(t *testing.T, d string) {
			for i := 0; i < 19; i++ {
				writeFile(t, bpath(d, relayporttest.Device(byte(i))), nil, 0o600)
			}
		}, smallNames, nil, "more than 18 names"},
		{"too many names in tombstones", func(t *testing.T, d string) {
			for i := 0; i < 21; i++ {
				writeFile(t, filepath.Join(d, tombstonesDir, "d-"+deviceName(relayporttest.Device(byte(i)))), encodeTomb(5), 0o600)
			}
		}, smallNames, nil, "more than 20 names"},
		{"quarantine is full", func(t *testing.T, d string) {
			for i := 0; i < maxQuarantine+1; i++ {
				writeFile(t, filepath.Join(d, quarantineDir, fmt.Sprintf("%040x-%016x", i, i)), []byte("x"), 0o600)
			}
		}, real, nil, "more than"},
		{"temporary file that is a link", func(t *testing.T, d string) { link(t, filepath.Join(d, bindingsDir, tmpPrefix+"0123456789abcdef")) }, real, nil, "not a regular file"},
		{"lock file is a link", func(t *testing.T, d string) {
			os.Remove(filepath.Join(d, lockName))
			link(t, filepath.Join(d, lockName))
		}, real, nil, "not part of a registry"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := prep(t)
			c.setup(t, dir)
			refuseOpen(t, dir, c.seams, c.mod, c.expect)
		})
	}
}

// A binding that fails verification at load is quarantined: moved out of the
// directory the registry reads, kept for the operator, never loaded, with a note
// returned from Open. The registry still opens.
//
// spec: SPO-Xmailbox-OUT-075, SPO-Xmailbox-SEC-053
func TestStoredBindingsAreVerifiedAtLoad(t *testing.T) {
	good := func(t *testing.T) []byte { return goodRecordFile(t, wal1, dev1) }
	mut := func(f func(r *storedRecord)) func(t *testing.T) []byte {
		return func(t *testing.T) []byte {
			st, err := decodeRecord(good(t))
			if err != nil {
				t.Fatal(err)
			}
			f(&st)
			return encodeRecord(relayregistry.Record{LastAuth: st.lastAuth, Senders: st.senders, Sign1: st.sign1, COSEKey: st.coseKey})
		}
	}
	cases := []struct {
		name string
		file func(t *testing.T) []byte
		as   party.Fingerprint
		want string
	}{
		{"signature altered", mut(func(r *storedRecord) { r.sign1[len(r.sign1)-1] ^= 1 }), dev1, "signature"},
		{"payload altered", mut(func(r *storedRecord) { r.sign1[len(r.sign1)-70] ^= 1 }), dev1, "relaybind"},
		{"another wallet's key", mut(func(r *storedRecord) { r.coseKey = wal2.COSEKey() }), dev1, "signature"},
		{"truncated file", func(t *testing.T) []byte { b := good(t); return b[:len(b)-10] }, dev1, "truncated"},
		{"garbage", func(t *testing.T) []byte { return []byte(strings.Repeat("junk", 30)) }, dev1, "magic"},
		{"empty", func(t *testing.T) []byte { return nil }, dev1, "magic"},
		{"bytes after the record", func(t *testing.T) []byte { return append(good(t), 1, 2, 3) }, dev1, "after the record"},
		{"another device's name", good, dev2, "another device"},
		{"sign1 that is not strict COSE", mut(func(r *storedRecord) { r.sign1 = []byte{0x84, 0, 0, 0, 0} }), dev1, "relaybind"},
		{"cose key that is not a key", mut(func(r *storedRecord) { r.coseKey = []byte{1, 2, 3} }), dev1, "relaybind"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := prep(t)
			writeFile(t, bpath(dir, c.as), c.file(t), 0o600)
			s, notes := openAt(t, dir, relayporttest.NewManualClock(t0), nil)
			if len(notes) != 1 || !strings.Contains(notes[0], "quarantined") || !strings.Contains(notes[0], deviceName(c.as)) {
				t.Fatalf("notes = %q, want one note saying the binding was quarantined", notes)
			}
			if !strings.Contains(notes[0], c.want) {
				t.Fatalf("note %q does not give the reason (%q)", notes[0], c.want)
			}
			if _, ok, _ := s.Lookup(t.Context(), c.as); ok {
				t.Fatal("a binding that failed verification was loaded")
			}
			if st, _ := s.Stats(t.Context()); st.Bindings != 0 {
				t.Fatalf("stats = %+v", st)
			}
			if _, err := os.Lstat(bpath(dir, c.as)); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("the quarantined file is still where the registry reads: %v", err)
			}
			q, _ := os.ReadDir(filepath.Join(dir, quarantineDir))
			if len(q) != 1 || !quarRE.MatchString(q[0].Name()) || !strings.HasPrefix(q[0].Name(), deviceName(c.as)) {
				t.Fatalf("quarantine = %v", q)
			}
			// the next start is quiet
			s.Close()
			_, notes2 := openAt(t, dir, relayporttest.NewManualClock(t0), nil)
			if len(notes2) != 0 {
				t.Fatalf("notes at the second start: %v", notes2)
			}
		})
	}
	t.Run("a refused load does not drop a good neighbour", func(t *testing.T) {
		dir := prep(t)
		writeFile(t, bpath(dir, dev1), good(t), 0o600)
		writeFile(t, bpath(dir, dev2), []byte("junk"), 0o600)
		s, notes := openAt(t, dir, relayporttest.NewManualClock(t0), nil)
		if len(notes) != 1 {
			t.Fatalf("notes = %q", notes)
		}
		if _, ok, _ := s.Lookup(t.Context(), dev1); !ok {
			t.Fatal("the good binding was not loaded")
		}
	})
}

// The "invalidated by a tombstone" case is the partial rollback that SEC-063 says
// is handled: an old binding file next to a newer tombstone does not come back.
//
// spec: SPO-Xmailbox-SEC-054, SPO-Xmailbox-SEC-063
func TestLoadDropsWhatTheRulesDrop(t *testing.T) {
	clock := relayporttest.NewManualClock(t0)
	t.Run("expired", func(t *testing.T) {
		dir := prep(t)
		w := wal1
		p := w.Present(t, dev1, bFrom, t0+3600, t0)
		writeFile(t, bpath(dir, dev1), encodeRecord(relayregistry.Record{LastAuth: t0, Sign1: p.Sign1(), COSEKey: p.COSEKey()}), 0o600)
		clock.Advance(3601 * time.Second)
		s, notes := openAt(t, dir, clock, nil)
		if _, ok, _ := s.Lookup(t.Context(), dev1); ok || len(notes) != 1 || !strings.Contains(notes[0], "expired") {
			t.Fatalf("notes = %q", notes)
		}
		if _, err := os.Lstat(bpath(dir, dev1)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("the expired file was left")
		}
		if q, _ := os.ReadDir(filepath.Join(dir, quarantineDir)); len(q) != 0 {
			t.Fatal("an expired binding was quarantined; it is not damaged")
		}
	})
	t.Run("invalidated by a tombstone", func(t *testing.T) {
		dir := prep(t)
		writeFile(t, bpath(dir, dev1), goodRecordFile(t, wal1, dev1), 0o600)
		writeFile(t, filepath.Join(dir, tombstonesDir, "d-"+deviceName(dev1)), encodeTomb(bFrom), 0o600)
		s, notes := openAt(t, dir, relayporttest.NewManualClock(t0), nil)
		if _, ok, _ := s.Lookup(t.Context(), dev1); ok || len(notes) != 1 || !strings.Contains(notes[0], "revoked by a tombstone") {
			t.Fatalf("notes = %q", notes)
		}
		if _, err := os.Lstat(bpath(dir, dev1)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("the invalidated file was left")
		}
	})
	t.Run("a tombstone older than the binding keeps it", func(t *testing.T) {
		dir := prep(t)
		writeFile(t, bpath(dir, dev1), goodRecordFile(t, wal1, dev1), 0o600)
		writeFile(t, filepath.Join(dir, tombstonesDir, "d-"+deviceName(dev1)), encodeTomb(bFrom-1), 0o600)
		s, notes := openAt(t, dir, relayporttest.NewManualClock(t0), nil)
		if _, ok, _ := s.Lookup(t.Context(), dev1); !ok || len(notes) != 0 {
			t.Fatalf("notes = %q", notes)
		}
	})
	t.Run("a key that is not on the allow-list", func(t *testing.T) {
		dir := prep(t)
		writeFile(t, bpath(dir, dev1), goodRecordFile(t, wal1, dev1), 0o600)
		s, notes := openAt(t, dir, relayporttest.NewManualClock(t0), func(c *relayregistry.Config) {
			c.Restricted, c.Allowed = true, []relaybind.KeyHash{wal2.Key}
		})
		if _, ok, _ := s.Lookup(t.Context(), dev1); ok || len(notes) != 1 || !strings.Contains(notes[0], "allow-list") {
			t.Fatalf("notes = %q", notes)
		}
	})
	t.Run("a last authentication in the future is clamped", func(t *testing.T) {
		dir := prep(t)
		p := wal1.Present(t, dev1, bFrom, bUntil, t0)
		writeFile(t, bpath(dir, dev1), encodeRecord(relayregistry.Record{LastAuth: t0 + 1000000, Sign1: p.Sign1(), COSEKey: p.COSEKey()}), 0o600)
		s, _ := openAt(t, dir, relayporttest.NewManualClock(t0), nil)
		if e, ok, _ := s.Lookup(t.Context(), dev1); !ok || e.LastAuth != t0 {
			t.Fatalf("entry = %+v, %v; a stored time after relay time must not keep a binding from ever being evicted", e, ok)
		}
	})
	t.Run("a sender list that is not canonical is dropped", func(t *testing.T) {
		dir := prep(t)
		p := wal1.Present(t, dev1, bFrom, bUntil, t0)
		writeFile(t, bpath(dir, dev1), encodeRecord(relayregistry.Record{LastAuth: t0, Sign1: p.Sign1(), COSEKey: p.COSEKey(),
			Senders: []mailbox.WalletKey{{2}, {1}}}), 0o600)
		s, notes := openAt(t, dir, relayporttest.NewManualClock(t0), nil)
		if _, ok, _ := s.Lookup(t.Context(), dev1); !ok || len(notes) != 1 || !strings.Contains(notes[0], "expected-sender list dropped") {
			t.Fatalf("notes = %q", notes)
		}
		if got, _ := s.ExpectedSenders(t.Context(), dev1); len(got) != 0 {
			t.Fatalf("a bad list was kept: %v", got)
		}
		// the file is rewritten, so the next start is quiet and the list is empty
		s.Close()
		_, notes2 := openAt(t, dir, relayporttest.NewManualClock(t0), nil)
		if len(notes2) != 0 {
			t.Fatalf("second start: %q", notes2)
		}
	})
	t.Run("an expired tombstone is kept at load and dropped by a sweep", func(t *testing.T) {
		dir := prep(t)
		name := filepath.Join(dir, tombstonesDir, "d-"+deviceName(dev1))
		writeFile(t, name, encodeTomb(t0-relaybind.MaxLifetimeSeconds-relaybind.SkewSeconds-1), 0o600)
		s, notes := openAt(t, dir, relayporttest.NewManualClock(t0), nil)
		if st, _ := s.Stats(t.Context()); st.Tombstones != 1 || len(notes) != 0 {
			t.Fatalf("stats %+v notes %q: the load must not drop a tombstone on the start-up clock alone", st, notes)
		}
		if _, err := os.Lstat(name); err != nil {
			t.Fatalf("the tombstone file was removed at load: %v", err)
		}
		sw, err := s.Sweep(t.Context())
		if err != nil || sw.Tombstones != 1 {
			t.Fatalf("sweep = %+v, %v", sw, err)
		}
		if _, err := os.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("the sweep left the file")
		}
	})
	t.Run("leftovers of a crash", func(t *testing.T) {
		dir := prep(t)
		for _, d := range []string{bindingsDir, tombstonesDir} {
			writeFile(t, filepath.Join(dir, d, tmpPrefix+"0123456789abcdef"), []byte("half"), 0o600)
		}
		_, notes := openAt(t, dir, relayporttest.NewManualClock(t0), nil)
		if len(notes) != 2 || !strings.Contains(notes[0]+notes[1], "temporary") {
			t.Fatalf("notes = %q", notes)
		}
		for _, d := range []string{bindingsDir, tombstonesDir} {
			if es, _ := os.ReadDir(filepath.Join(dir, d)); len(es) != 0 {
				t.Fatalf("%s still holds %v", d, es)
			}
		}
	})
}

// The cases that quarantine cannot take: a full quarantine fails closed.
//
// spec: SPO-Xmailbox-SEC-053
func TestQuarantineIsBounded(t *testing.T) {
	dir := prep(t)
	for i := 0; i < maxQuarantine; i++ {
		writeFile(t, filepath.Join(dir, quarantineDir, fmt.Sprintf("%040x-%016x", i, i)), []byte("x"), 0o600)
	}
	writeFile(t, bpath(dir, dev1), []byte("junk"), 0o600)
	refuseOpen(t, dir, realSeams(), nil, "quarantine")
	if _, err := os.Lstat(bpath(dir, dev1)); err != nil {
		t.Fatal("a binding that could not be quarantined was removed")
	}
}

type snap struct{ step, dir string }

func copyTree(t testing.TB, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// recorder returns seams that snapshot the directory after every step.
func recorder(t testing.TB, dir string, log *[]snap) seams {
	sm := realSeams()
	sm.hook = func(step string) error {
		d := filepath.Join(t.TempDir(), "s")
		copyTree(t, dir, d)
		*log = append(*log, snap{step, d})
		return nil
	}
	return sm
}

func hasTmp(dir string) bool {
	found := false
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && strings.HasPrefix(d.Name(), tmpPrefix) {
			found = true
		}
		return nil
	})
	return found
}

func stepsOf(log []snap) []string {
	var s []string
	for _, x := range log {
		s = append(s, x.step)
	}
	return s
}

var putSteps = []string{stepTmpCreated, stepBodyWritten, stepBodySynced, stepRenamed, stepDirSynced}

// A crash at any step of a write leaves a registry that opens and holds either
// the old state or the new one, never a mix, and no temporary file.
//
// spec: SPO-Xmailbox-SEC-055
func TestCrashAtEveryStepOfABindingWrite(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(fmt.Sprintf("replace=%v", replace), func(t *testing.T) {
			dir := newDir(t)
			clock := relayporttest.NewManualClock(t0)
			var log []snap
			started := false
			sm := recorder(t, dir, &log)
			inner := sm.hook
			sm.hook = func(step string) error {
				if !started {
					return nil
				}
				return inner(step)
			}
			s, _, err := openWithSeams(t, dir, clock, nil, sm)
			if err != nil {
				t.Fatal(err)
			}
			if replace {
				if _, err := s.Register(t.Context(), wal1.Present(t, dev1, bFrom, bUntil, t0)); err != nil {
					t.Fatal(err)
				}
			}
			started = true
			if _, err := s.Register(t.Context(), wal1.Present(t, dev1, bFrom, bUntil+10, t0)); err != nil {
				t.Fatal(err)
			}
			if got := stepsOf(log); !slices.Equal(got, putSteps) {
				t.Fatalf("steps = %v, want %v", got, putSteps)
			}
			for _, sn := range log {
				before := slices.Index(putSteps, sn.step) < slices.Index(putSteps, stepRenamed)
				leftover := hasTmp(sn.dir)
				if leftover != before { // the temporary file exists from its creation to the rename
					t.Errorf("%s: temporary file present = %v", sn.step, leftover)
				}
				r, notes := openAt(t, sn.dir, relayporttest.NewManualClock(t0), nil)
				e, ok, _ := r.Lookup(t.Context(), dev1)
				switch {
				case before && replace:
					if !ok || e.Binding.Until != bUntil {
						t.Errorf("%s: the old binding is not intact: %+v %v", sn.step, e, ok)
					}
				case before:
					if ok {
						t.Errorf("%s: a binding appeared before the rename", sn.step)
					}
				default:
					if !ok || e.Binding.Until != bUntil+10 {
						t.Errorf("%s: the new binding is not there: %+v %v", sn.step, e, ok)
					}
				}
				if leftover && (len(notes) != 1 || !strings.Contains(notes[0], "temporary")) {
					t.Errorf("%s: notes = %q", sn.step, notes)
				}
				if hasTmp(sn.dir) {
					t.Errorf("%s: Open left a temporary file", sn.step)
				}
				r.Close()
			}
		})
	}
}

// spec: SPO-Xmailbox-SEC-055
func TestCrashAtEveryStepOfATombstoneWrite(t *testing.T) {
	for _, raise := range []bool{false, true} {
		t.Run(fmt.Sprintf("raise=%v", raise), func(t *testing.T) {
			dir := newDir(t)
			var log []snap
			started := false
			sm := recorder(t, dir, &log)
			inner := sm.hook
			sm.hook = func(step string) error {
				if !started {
					return nil
				}
				return inner(step)
			}
			s, _, err := openWithSeams(t, dir, relayporttest.NewManualClock(t0), nil, sm)
			if err != nil {
				t.Fatal(err)
			}
			if raise {
				if _, err := s.Revoke(t.Context(), relayporttest.DeviceRevoke(t, dev1, bFrom-50)); err != nil {
					t.Fatal(err)
				}
			}
			started = true
			if _, err := s.Revoke(t.Context(), relayporttest.DeviceRevoke(t, dev1, bFrom-40)); err != nil {
				t.Fatal(err)
			}
			if got := stepsOf(log); !slices.Equal(got, putSteps) {
				t.Fatalf("steps = %v, want %v", got, putSteps)
			}
			for _, sn := range log {
				before := slices.Index(putSteps, sn.step) < slices.Index(putSteps, stepRenamed)
				r, _ := openAt(t, sn.dir, relayporttest.NewManualClock(t0), nil)
				ts, _ := r.Tombstones(t.Context(), wal1.Key, dev1)
				want := bFrom - 40
				if before {
					want = relaybind.NoTombstone
					if raise {
						want = bFrom - 50
					}
				}
				if ts.Device != want {
					t.Errorf("%s: tombstone = %d, want %d", sn.step, ts.Device, want)
				}
				r.Close()
			}
		})
	}
}

// A crash between the tombstone and the deletion of the binding it invalidates
// leaves a binding that the next load drops: the registry never serves a binding
// that a stored tombstone invalidates.
//
// spec: SPO-Xmailbox-SEC-056
func TestCrashBetweenTombstoneAndDeletion(t *testing.T) {
	dir := newDir(t)
	var log []snap
	started := false
	sm := recorder(t, dir, &log)
	inner := sm.hook
	sm.hook = func(step string) error {
		if !started {
			return nil
		}
		return inner(step)
	}
	s, _, err := openWithSeams(t, dir, relayporttest.NewManualClock(t0), nil, sm)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register(t.Context(), wal1.Present(t, dev1, bFrom, bUntil, t0)); err != nil {
		t.Fatal(err)
	}
	started = true
	res, err := s.Revoke(t.Context(), wal1.WalletRevoke(t, dev1, bFrom, t0))
	if err != nil || len(res.Invalidated) != 1 {
		t.Fatalf("revoke: %+v, %v", res, err)
	}
	want := append(append([]string{}, putSteps...), stepUnlinked, stepUnlinkSynced)
	if got := stepsOf(log); !slices.Equal(got, want) {
		t.Fatalf("steps = %v, want %v", got, want)
	}
	for i, sn := range log {
		r, notes := openAt(t, sn.dir, relayporttest.NewManualClock(t0), nil)
		_, bound, _ := r.Lookup(t.Context(), dev1)
		ts, _ := r.Tombstones(t.Context(), wal1.Key, dev1)
		tombWritten := i >= slices.Index(want, stepRenamed)
		_, statErr := os.Lstat(bpath(sn.dir, dev1))
		if !tombWritten {
			if !bound || ts.Pair != relaybind.NoTombstone || statErr != nil {
				t.Errorf("%s: before the tombstone is stored the binding must be intact (bound %v, tombstone %d)", sn.step, bound, ts.Pair)
			}
			r.Close()
			continue
		}
		if bound {
			t.Errorf("%s: the registry serves a binding that a stored tombstone invalidates", sn.step)
		}
		if ts.Pair != bFrom {
			t.Errorf("%s: tombstone = %d", sn.step, ts.Pair)
		}
		if statErr == nil {
			t.Errorf("%s: Open did not clear the invalidated binding", sn.step)
		}
		fileLeft := i < slices.Index(want, stepUnlinked)
		if fileLeft && (len(notes) != 1 || !strings.Contains(notes[0], "revoked by a tombstone")) {
			t.Errorf("%s: notes = %q", sn.step, notes)
		}
		r.Close()
	}
}

// spec: SPO-Xmailbox-SEC-055
func TestCrashAtEveryStepOfADeletion(t *testing.T) {
	dir := newDir(t)
	var log []snap
	started := false
	sm := recorder(t, dir, &log)
	inner := sm.hook
	sm.hook = func(step string) error {
		if !started {
			return nil
		}
		return inner(step)
	}
	s, _, err := openWithSeams(t, dir, relayporttest.NewManualClock(t0), nil, sm)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register(t.Context(), wal1.Present(t, dev1, bFrom, t0+3600, t0)); err != nil {
		t.Fatal(err)
	}
	s.clock.(*relayporttest.ManualClock).Advance(3601 * time.Second)
	started = true
	if sw, err := s.Sweep(t.Context()); err != nil || len(sw.Expired) != 1 {
		t.Fatalf("sweep: %+v, %v", sw, err)
	}
	if got := stepsOf(log); !slices.Equal(got, []string{stepUnlinked, stepUnlinkSynced}) {
		t.Fatalf("steps = %v", got)
	}
	// the binding is expired in every snapshot; what matters is that each opens
	for _, sn := range log {
		r, _ := openAt(t, sn.dir, relayporttest.NewManualClock(t0+3601), nil)
		if _, ok, _ := r.Lookup(t.Context(), dev1); ok {
			t.Errorf("%s: an expired binding is served", sn.step)
		}
		r.Close()
	}
}

// A failure before the rename leaves the old state and no temporary file; a
// failure after it leaves the memory following the directory, with the error
// returned.
//
// spec: SPO-Xmailbox-SEC-057
func TestFailureOfEveryStep(t *testing.T) {
	boom := errors.New("injected")
	for _, step := range putSteps {
		t.Run(step, func(t *testing.T) {
			dir := newDir(t)
			fail := false
			sm := realSeams()
			sm.hook = func(s string) error {
				if fail && s == step {
					return boom
				}
				return nil
			}
			s, _, err := openWithSeams(t, dir, relayporttest.NewManualClock(t0), nil, sm)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Register(t.Context(), wal1.Present(t, dev1, bFrom, bUntil, t0)); err != nil {
				t.Fatal(err)
			}
			fail = true
			_, err = s.Register(t.Context(), wal1.Present(t, dev1, bFrom, bUntil+10, t0))
			if !errors.Is(err, boom) {
				t.Fatalf("Register: %v, want the injected error", err)
			}
			e, ok, _ := s.Lookup(t.Context(), dev1)
			renamed := slices.Index(putSteps, step) >= slices.Index(putSteps, stepRenamed)
			switch {
			case renamed && (!ok || e.Binding.Until != bUntil+10):
				t.Fatalf("after the rename the memory must follow the directory: %+v", e)
			case !renamed && (!ok || e.Binding.Until != bUntil):
				t.Fatalf("a failure before the rename changed the binding: %+v", e)
			}
			if !renamed && hasTmp(dir) {
				t.Fatal("a temporary file was left")
			}
			fail = false
			if _, err := s.Register(t.Context(), wal1.Present(t, dev1, bFrom, bUntil+20, t0)); err != nil {
				t.Fatalf("the registry is not usable after a failure: %v", err)
			}
			if e, _, _ := s.Lookup(t.Context(), dev1); e.Binding.Until != bUntil+20 {
				t.Fatal("the next write did not take")
			}
		})
	}
}

// The syncs are where durability needs them: the file before the rename, the
// directory after it, the directory after an unlink.
//
// spec: SPO-Xmailbox-SEC-058
func TestSyncOrder(t *testing.T) {
	var log []string
	sm := realSeams()
	sm.hook = func(step string) error { log = append(log, step); return nil }
	sm.sync = func(fd int) error { log = append(log, "sync"); return unix.Fsync(fd) }
	dir := newDir(t)
	clock := relayporttest.NewManualClock(t0)
	s, _, err := openWithSeams(t, dir, clock, nil, sm)
	if err != nil {
		t.Fatal(err)
	}
	log = nil
	if _, err := s.Register(t.Context(), wal1.Present(t, dev1, bFrom, bUntil, t0)); err != nil {
		t.Fatal(err)
	}
	want := []string{stepTmpCreated, stepBodyWritten, "sync", stepBodySynced, stepRenamed, "sync", stepDirSynced}
	if !slices.Equal(log, want) {
		t.Fatalf("a binding write:\n got %v\nwant %v", log, want)
	}
	log = nil
	if _, err := s.Revoke(t.Context(), relayporttest.DeviceRevoke(t, dev2, bFrom)); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(log, want) {
		t.Fatalf("a tombstone write:\n got %v\nwant %v", log, want)
	}
	log = nil
	if _, err := s.Revoke(t.Context(), relayporttest.DeviceRevoke(t, dev1, bFrom)); err != nil {
		t.Fatal(err)
	}
	want2 := append(append([]string{}, want...), stepUnlinked, "sync", stepUnlinkSynced)
	if !slices.Equal(log, want2) {
		t.Fatalf("a revoke that deletes:\n got %v\nwant %v", log, want2)
	}
}

// A re-authentication younger than the granularity writes nothing.
//
// spec: SPO-Xmailbox-OUT-074
func TestGranularityWritesNothing(t *testing.T) {
	var log []string
	sm := realSeams()
	sm.hook = func(step string) error { log = append(log, step); return nil }
	clock := relayporttest.NewManualClock(t0)
	s, _, err := openWithSeams(t, newDir(t), clock, nil, sm)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register(t.Context(), wal1.Present(t, dev1, bFrom, bUntil, t0)); err != nil {
		t.Fatal(err)
	}
	log = nil
	clock.Advance(time.Duration(relayregistry.PersistGranularity-1) * time.Second)
	if _, err := s.Register(t.Context(), wal1.Present(t, dev1, bFrom, bUntil, t0)); err != nil || len(log) != 0 {
		t.Fatalf("a re-authentication wrote: %v, %v", log, err)
	}
	clock.Advance(time.Second)
	if _, err := s.Register(t.Context(), wal1.Present(t, dev1, bFrom, bUntil, t0)); err != nil || !slices.Equal(log, putSteps) {
		t.Fatalf("a re-authentication at the granularity: %v, %v", log, err)
	}
}

// Refusing an oversize file costs no allocation proportional to its claimed size:
// the size is read from the descriptor before the file is read.
//
// spec: SPO-Xmailbox-SEC-059
func TestOversizeFileIsNotRead(t *testing.T) {
	dir := prep(t)
	writeFile(t, bpath(dir, dev1), []byte("small"), 0o600) // 5 bytes on disk
	sm := realSeams()
	sm.fstat = func(fd int, st *unix.Stat_t) error { // ... that claims a terabyte
		err := unix.Fstat(fd, st)
		st.Size = 1 << 40
		return err
	}
	runtime.GC()
	var a, b runtime.MemStats
	runtime.ReadMemStats(&a)
	_, _, err := openWith(dir, testCfg(nil), relayporttest.NewManualClock(t0), sm)
	runtime.ReadMemStats(&b)
	if !errors.Is(err, relayport.ErrRegistryCorrupt) {
		t.Fatalf("Open: %v", err)
	}
	if d := b.TotalAlloc - a.TotalAlloc; d > 1<<20 {
		t.Fatalf("refusing the file allocated %d bytes", d)
	}
}

// Operations racing Close never touch a closed descriptor.
//
// spec: SPO-Xmailbox-SEC-047
func TestCloseWaitsForWriters(t *testing.T) {
	dir := newDir(t)
	clock := relayporttest.NewManualClock(t0)
	s, _, err := openWithSeams(t, dir, clock, nil, realSeams())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				w := relayporttest.NewWallet(byte(30 + j%5))
				p, err := w.TryPresent(relayporttest.Device(byte(j%5)), bFrom, bUntil, t0, false)
				if err != nil {
					t.Error(err)
					return
				}
				s.Register(t.Context(), p)
				s.Revoke(t.Context(), relayporttest.DeviceRevoke(t, relayporttest.Device(byte(j%5)), bFrom))
			}
		}()
	}
	wg.Add(1)
	go func() { defer wg.Done(); time.Sleep(2 * time.Millisecond); s.Close() }()
	wg.Wait()
	if _, _, err := s.Lookup(t.Context(), dev1); !errors.Is(err, relayport.ErrRegistryClosed) {
		t.Fatalf("Lookup after Close: %v", err)
	}
	// what was written is complete: the directory opens
	r, _ := openAt(t, dir, clock, nil)
	_ = r
}
