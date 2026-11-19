//go:build unix

package bindingstore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

const t0 = relayporttest.RegT0

// the binding of the tests: valid from t0 - 60 for 90 days
const (
	bFrom  = t0 - 60
	bUntil = bFrom + 90*86400
)

func newDir(t testing.TB) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "reg")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func testCfg(mod func(*relayregistry.Config)) relayregistry.Config {
	cfg := relayregistry.DefaultConfig()
	cfg.Evictable = func(party.Fingerprint) bool { return true }
	if mod != nil {
		mod(&cfg)
	}
	return cfg
}

func openAt(t testing.TB, dir string, clock relayport.Clock, mod func(*relayregistry.Config)) (*Store, []string) {
	t.Helper()
	s, notes, err := Open(dir, testCfg(mod), clock)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s, notes
}

func openWithSeams(t testing.TB, dir string, clock relayport.Clock, mod func(*relayregistry.Config), sm seams) (*Store, []string, error) {
	t.Helper()
	s, notes, err := openWith(dir, testCfg(mod), clock, sm)
	if err == nil {
		t.Cleanup(func() { s.Close() })
	}
	return s, notes, err
}

// spec: SPO-Xmailbox-IF-014, SPO-Xmailbox-OUT-058, SPO-Xmailbox-OUT-059, SPO-Xmailbox-OUT-060
// spec: SPO-Xmailbox-OUT-061, SPO-Xmailbox-OUT-062, SPO-Xmailbox-OUT-063, SPO-Xmailbox-OUT-064
// spec: SPO-Xmailbox-OUT-069, SPO-Xmailbox-OUT-070, SPO-Xmailbox-OUT-071, SPO-Xmailbox-OUT-072
// spec: SPO-Xmailbox-OUT-073, SPO-Xmailbox-OUT-074, SPO-Xmailbox-PRE-032, SPO-Xmailbox-PRE-033
// spec: SPO-Xmailbox-PRE-034, SPO-Xmailbox-PRE-035, SPO-Xmailbox-PRE-036, SPO-Xmailbox-PRE-037
// spec: SPO-Xmailbox-PRE-038, SPO-Xmailbox-PRE-039, SPO-Xmailbox-PRE-040, SPO-Xmailbox-SEC-043
func TestRegistryContract(t *testing.T) {
	relayporttest.RunRegistry(t, func(t *testing.T, cfg relayregistry.Config, clock relayport.Clock) relayporttest.RegistryFixture {
		dir := newDir(t)
		s, _, err := Open(dir, cfg, clock)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		cur := s
		return relayporttest.RegistryFixture{
			Registry: s,
			Reopen: func(t *testing.T) relayport.Registry {
				cur.Close()
				n, _, err := Open(dir, cfg, clock)
				if err != nil {
					t.Fatalf("reopen: %v", err)
				}
				t.Cleanup(func() { n.Close() })
				cur = n
				return n
			},
		}
	})
}

// A new directory gets the layout and the modes of the ADR: directories 0700,
// files 0600, nothing else.
//
// spec: SPO-Xmailbox-SEC-048
func TestOpenCreatesTheLayout(t *testing.T) {
	dir := newDir(t)
	clock := relayporttest.NewManualClock(t0)
	s, notes := openAt(t, dir, clock, nil)
	if len(notes) != 0 {
		t.Fatalf("notes on a new directory: %v", notes)
	}
	want := map[string]os.FileMode{lockName: 0o600, bindingsDir: 0o700, tombstonesDir: 0o700, quarantineDir: 0o700}
	es, err := os.ReadDir(dir)
	if err != nil || len(es) != len(want) {
		t.Fatalf("directory = %v, %v", es, err)
	}
	for _, e := range es {
		fi, _ := e.Info()
		if m, ok := want[e.Name()]; !ok || fi.Mode().Perm() != m {
			t.Errorf("%s has mode %v", e.Name(), fi.Mode())
		}
	}
	// a binding file and a tombstone file are 0600 too
	w := relayporttest.NewWallet(1)
	if _, err := s.Register(t.Context(), w.Present(t, relayporttest.Device(1), bFrom, bUntil, t0)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Revoke(t.Context(), relayporttest.DeviceRevoke(t, relayporttest.Device(2), bFrom)); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		filepath.Join(dir, bindingsDir, deviceName(relayporttest.Device(1))),
		filepath.Join(dir, tombstonesDir, tombName(relayregistry.TombKey{Scope: relaybind.ScopeDevice, Device: relayporttest.Device(2)})),
	} {
		fi, err := os.Lstat(p)
		if err != nil || fi.Mode() != 0o600 {
			t.Errorf("%s: %v, %v", p, fi, err)
		}
	}
}

// One process owns the directory by an exclusive lock held until Close.
//
// spec: SPO-Xmailbox-SEC-049
func TestExclusiveLock(t *testing.T) {
	dir := newDir(t)
	clock := relayporttest.NewManualClock(t0)
	s, _ := openAt(t, dir, clock, nil)
	_, _, err := Open(dir, testCfg(nil), clock)
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("second Open: %v, want ErrLocked", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, _, err := Open(dir, testCfg(nil), clock)
	if err != nil {
		t.Fatalf("Open after Close: %v", err)
	}
	s2.Close()
}

// spec: SPO-Xmailbox-PRE-042
func TestOpenRefusesBadArguments(t *testing.T) {
	clock := relayporttest.NewManualClock(t0)
	if _, _, err := Open("relative/dir", testCfg(nil), clock); err == nil {
		t.Fatal("a relative directory was accepted")
	}
	if _, _, err := Open(newDir(t), testCfg(nil), nil); err == nil {
		t.Fatal("a nil clock was accepted")
	}
	bad := testCfg(func(c *relayregistry.Config) { c.MaxBoundDevices = 0 })
	if _, _, err := Open(newDir(t), bad, clock); !errors.Is(err, relayregistry.ErrConfig) {
		t.Fatalf("an invalid configuration: %v", err)
	}
	// a clock outside 1970 to 9999 is refused: the registry names nothing by it
	if _, _, err := Open(newDir(t), testCfg(nil), relayporttest.NewManualClock(-5)); err == nil {
		t.Fatal("a negative clock was accepted")
	}
	s2, _, err := Open(newDir(t), testCfg(nil), relayporttest.NewManualClock(t0))
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	s2.clock = relayporttest.NewManualClock(relaybind.MaxTime + 1)
	if _, _, err := s2.Lookup(t.Context(), relayporttest.Device(1)); err == nil {
		t.Fatal("a clock beyond the year 9999 was accepted")
	}
}

// No secret material is at rest: a binding and a tombstone are public
// statements, and the files hold nothing of the signing key or the wallet's
// seed.
//
// spec: SPO-Xmailbox-SEC-050
func TestNothingSecretAtRest(t *testing.T) {
	dir := newDir(t)
	s, _ := openAt(t, dir, relayporttest.NewManualClock(t0), nil)
	w := relayporttest.NewWallet(7)
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 7 + byte(i)*3
	}
	if _, err := s.Register(t.Context(), w.Present(t, relayporttest.Device(1), bFrom, bUntil, t0)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Revoke(t.Context(), w.WalletRevoke(t, relayporttest.Device(2), bFrom, t0)); err != nil {
		t.Fatal(err)
	}
	n := 0
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := os.ReadFile(p)
		n++
		if bytes.Contains(b, seed[:16]) {
			t.Errorf("%s holds the seed", p)
		}
		return nil
	})
	if n < 3 {
		t.Fatalf("saw %d files", n)
	}
}

// A binding file is 7 + 8 + 1 + 64*28 + 2 + 512 + 2 + 128 bytes at most; the
// largest real record fits.
//
// spec: SPO-Xmailbox-PRE-043
func TestRecordBounds(t *testing.T) {
	if maxRecordBytes != 2452 {
		t.Fatalf("maxRecordBytes = %d", maxRecordBytes)
	}
	big := relayregistry.Record{LastAuth: relaybind.MaxTime, Sign1: make([]byte, 512), COSEKey: make([]byte, 128)}
	for i := 0; i < mailbox.MaxSenders; i++ {
		big.Senders = append(big.Senders, mailbox.WalletKey{byte(i + 1)})
	}
	b := encodeRecord(big)
	if len(b) != maxRecordBytes {
		t.Fatalf("largest record = %d bytes", len(b))
	}
	if st, err := decodeRecord(b); err != nil || !st.sendersOK || len(st.senders) != 64 {
		t.Fatalf("decode largest: %+v, %v", st, err)
	}
	if _, err := decodeRecord(append(b, 0)); err == nil {
		t.Fatal("a record over its bound decoded")
	}
	for name, mod := range map[string]func([]byte) []byte{
		"bad magic":      func(b []byte) []byte { b[0] ^= 1; return b },
		"over MaxTime":   func(b []byte) []byte { b[7] = 0x7f; return b },
		"count over 64":  func(b []byte) []byte { b[15] = 65; return b },
		"truncated":      func(b []byte) []byte { return b[:len(b)-1] },
		"zero sign1 len": func(b []byte) []byte { b[16+64*28], b[16+64*28+1] = 0, 0; return b },
		"sign1 over 512": func(b []byte) []byte { b[16+64*28], b[16+64*28+1] = 2, 1; return b },
	} {
		if _, err := decodeRecord(mod(bytes.Clone(encodeRecord(big)))); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	// a list that is not strictly ascending is dropped, not an error
	unsorted := relayregistry.Record{Sign1: []byte{1}, COSEKey: []byte{1}, Senders: []mailbox.WalletKey{{2}, {1}}}
	if st, err := decodeRecord(encodeRecord(unsorted)); err != nil || st.sendersOK || st.senders != nil {
		t.Fatalf("unsorted list: %+v, %v", st, err)
	}
	// tombstone files
	if nb, err := decodeTomb(encodeTomb(12345)); err != nil || nb != 12345 {
		t.Fatalf("tombstone: %d, %v", nb, err)
	}
	for name, b := range map[string][]byte{
		"short": encodeTomb(1)[:14], "long": append(encodeTomb(1), 0), "magic": append([]byte("XPORT1\n"), make([]byte, 8)...),
		"range": append([]byte(tombMagic), 0xff, 0, 0, 0, 0, 0, 0, 0),
	} {
		if _, err := decodeTomb(b); err == nil {
			t.Errorf("tombstone %s decoded", name)
		}
	}
}

// Names are strict: lower-case hex of the exact length, one of three tombstone
// shapes.
//
// spec: SPO-Xmailbox-SEC-051
func TestNamesAreStrict(t *testing.T) {
	d := relayporttest.Device(3)
	k := relayporttest.NewWallet(1).Key
	good := deviceName(d)
	if got, err := parseDeviceName(good); err != nil || got != d {
		t.Fatalf("parse: %v, %v", got, err)
	}
	for _, bad := range []string{"", good[:39], good + "0", strings.ToUpper(good), "g" + good[1:], ".tmp-0123456789abcdef", good + "\n", " " + good} {
		if _, err := parseDeviceName(bad); err == nil {
			t.Errorf("device name %q accepted", bad)
		}
	}
	for _, tk := range []relayregistry.TombKey{
		{Scope: relaybind.ScopePair, Key: k, Device: d}, {Scope: relaybind.ScopeAll, Key: k}, {Scope: relaybind.ScopeDevice, Device: d},
	} {
		got, err := parseTombName(tombName(tk))
		if err != nil || got != tk {
			t.Errorf("round trip of %+v: %+v, %v", tk, got, err)
		}
	}
	kh := tombName(relayregistry.TombKey{Scope: relaybind.ScopeAll, Key: k})
	for _, bad := range []string{
		"", "x-" + kh[2:], "a-" + strings.ToUpper(kh[2:]), kh + "0", kh[:len(kh)-1], "p-" + kh[2:], "d-" + kh[2:],
		"p-" + kh[2:] + "-" + good[:39], "a-" + kh[2:] + "-" + good,
	} {
		if _, err := parseTombName(bad); err == nil {
			t.Errorf("tombstone name %q accepted", bad)
		}
	}
}

var _ = time.Second
var _ = unix.O_RDONLY
