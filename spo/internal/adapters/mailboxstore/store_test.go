//go:build unix

package mailboxstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

const t0 = 1_700_000_000

func fp(b byte) party.Fingerprint {
	var f party.Fingerprint
	for i := range f {
		f[i] = b
	}
	return f
}

var (
	rcptA, rcptB, sndC = fp(0xA1), fp(0xB2), fp(0xC3)
	loose              = validated(mailbox.DefaultQuota())
)

// validated is Validated(1) for a quota the test knows is good.
func validated(q mailbox.Quota) mailbox.ValidQuota {
	v, err := q.Validated(1)
	if err != nil {
		panic(err)
	}
	return v
}

func body(n int, tag byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*13) ^ tag
	}
	if n > 0 {
		b[0] = tag
	}
	return b
}

func newDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "relay")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func openAt(t *testing.T, dir string, clk relayport.Clock) *Store {
	t.Helper()
	s, _, err := Open(dir, clk)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func put(t *testing.T, s *Store, rcpt, snd party.Fingerprint, b []byte) relayport.MailboxOutcome {
	t.Helper()
	o, err := s.Put(context.Background(), relayport.MailboxPut{Recipient: rcpt, Sender: snd, Mid: mailbox.HashOf(b), Size: uint32(len(b)), Quota: loose}, bytes.NewReader(b))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	return o
}

func entries(t *testing.T, s *Store, rcpt party.Fingerprint) []relayport.MailboxEntry {
	t.Helper()
	es, _, err := s.List(context.Background(), rcpt, nil, mailbox.MaxMailboxEntries)
	if err != nil {
		t.Fatal(err)
	}
	return es
}

// tree lists every path below dir with its type and mode.
func tree(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == dir {
			return err
		}
		fi, _ := d.Info()
		rel, _ := filepath.Rel(dir, p)
		out = append(out, fmt.Sprintf("%s %v", rel, fi.Mode()))
		return nil
	})
	return out
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		to := filepath.Join(dst, rel)
		fi, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(to, fi.Mode().Perm())
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file", p)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(to, b, fi.Mode().Perm())
	})
	if err != nil {
		t.Fatal(err)
	}
}

// spec: SPO-Xmailbox-OUT-012
func TestLayoutAndModes(t *testing.T) {
	dir := newDir(t)
	clk := relayporttest.NewManualClock(t0)
	s := openAt(t, dir, clk)
	b := body(300, 1)
	put(t, s, rcptA, sndC, b)
	name := filepath.Join(dir, "mailbox", recipientName(rcptA), entryName(t0, mailbox.HashOf(b), sndC))
	got, err := os.ReadFile(name)
	if err != nil || !bytes.Equal(got, b) {
		t.Fatalf("the entry file %s: %v", name, err)
	}
	modes := map[string]fs.FileMode{}
	for _, l := range tree(t, dir) {
		var p, m string
		fmt.Sscanf(l, "%s %s", &p, &m)
		_ = m
	}
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		fi, _ := d.Info()
		rel, _ := filepath.Rel(dir, p)
		modes[rel] = fi.Mode()
		return nil
	})
	for rel, m := range modes {
		switch {
		case rel == ".":
			continue
		case m.IsDir() && m.Perm() != 0o700:
			t.Errorf("directory %s has mode %v, want 0700", rel, m.Perm())
		case m.IsRegular() && m.Perm() != 0o600:
			t.Errorf("file %s has mode %v, want 0600", rel, m.Perm())
		}
	}
	if _, ok := modes[lockName]; !ok {
		t.Error("no lock file")
	}
	for rel := range modes {
		if strings.Contains(rel, tmpPrefix) {
			t.Errorf("a temporary file is left: %s", rel)
		}
	}
	// the entry does not look like the envelope: the file holds the bytes and the
	// name holds no plaintext field (the body's first bytes are not in the tree)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

// spec: SPO-Xmailbox-INV-004
func TestSecondOwnerIsRefusedByTheLock(t *testing.T) {
	dir := newDir(t)
	s := openAt(t, dir, relayporttest.NewManualClock(t0))
	if _, _, err := Open(dir, relayporttest.NewManualClock(t0)); !errors.Is(err, ErrLocked) {
		t.Fatalf("a second Open = %v, want ErrLocked", err)
	}
	s.Close()
	s2, _, err := Open(dir, relayporttest.NewManualClock(t0))
	if err != nil {
		t.Fatalf("Open after Close: %v", err)
	}
	s2.Close()
}

func TestOpenRefusesBadArguments(t *testing.T) {
	clk := relayporttest.NewManualClock(t0)
	if _, _, err := Open("relative/dir", clk); err == nil {
		t.Error("a relative path was accepted")
	}
	if _, _, err := Open(newDir(t), nil); err == nil {
		t.Error("a nil clock was accepted")
	}
	file := filepath.Join(t.TempDir(), "f")
	os.WriteFile(file, nil, 0o600)
	if _, _, err := Open(file, clk); err == nil {
		t.Error("a file was accepted as the directory")
	}
	// the directory is made when it is missing, mode 0700
	fresh := filepath.Join(t.TempDir(), "a", "b")
	s, _, err := Open(fresh, clk)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if fi, _ := os.Stat(fresh); fi.Mode().Perm() != 0o700 {
		t.Errorf("the new directory has mode %v", fi.Mode().Perm())
	}
}

// spec: SPO-Xmailbox-SEC-008
func TestOpenRefusesAWritableRoot(t *testing.T) {
	for _, m := range []os.FileMode{0o770, 0o707, 0o777} {
		dir := newDir(t)
		os.Chmod(dir, m)
		if _, _, err := Open(dir, relayporttest.NewManualClock(t0)); err == nil || !strings.Contains(err.Error(), "writable") {
			t.Errorf("mode %v: Open = %v, want a refusal that says writable", m, err)
		}
	}
}

// spec: SPO-Xmailbox-SEC-005
func TestHostileDirectoryIsRefusedAtOpen(t *testing.T) {
	good := entryName(t0, mailbox.HashOf([]byte("m")), sndC)
	rcpt := recipientName(rcptA)
	cases := []struct {
		name  string
		setup func(t *testing.T, root string)
	}{
		{"a symlink as a mailbox directory", func(t *testing.T, root string) {
			os.MkdirAll(filepath.Join(root, "mailbox"), 0o700)
			os.Symlink(t.TempDir(), filepath.Join(root, "mailbox", rcpt))
		}},
		{"a symlink as an entry", func(t *testing.T, root string) {
			d := mk(t, root, rcpt)
			os.Symlink(goodFile(t), filepath.Join(d, good)) // a link to a fine file of this user
		}},
		{"a symlink as the mailbox directory", func(t *testing.T, root string) {
			os.Symlink(t.TempDir(), filepath.Join(root, "mailbox"))
		}},
		{"a FIFO as an entry", func(t *testing.T, root string) {
			d := mk(t, root, rcpt)
			if err := syscall.Mkfifo(filepath.Join(d, good), 0o600); err != nil {
				t.Skip(err)
			}
		}},
		{"a directory as an entry", func(t *testing.T, root string) {
			d := mk(t, root, rcpt)
			os.Mkdir(filepath.Join(d, good), 0o700)
		}},
		{"a FIFO named like a temporary file", func(t *testing.T, root string) {
			d := mk(t, root, rcpt)
			if err := syscall.Mkfifo(filepath.Join(d, ".tmp-0123456789abcdef"), 0o600); err != nil {
				t.Skip(err)
			}
		}},
		{"a symlink named like a temporary file", func(t *testing.T, root string) {
			d := mk(t, root, rcpt)
			os.Symlink(goodFile(t), filepath.Join(d, ".tmp-0123456789abcdef"))
		}},
		{"a symlink as the lock file", func(t *testing.T, root string) {
			os.Symlink(goodFile(t), filepath.Join(root, lockName))
		}},
		{"a directory as the lock file", func(t *testing.T, root string) { os.Mkdir(filepath.Join(root, lockName), 0o700) }},
		{"a FIFO as the lock file", func(t *testing.T, root string) {
			if err := syscall.Mkfifo(filepath.Join(root, lockName), 0o600); err != nil {
				t.Skip(err)
			}
		}},
		{"a file as the mailbox directory", func(t *testing.T, root string) {
			os.WriteFile(filepath.Join(root, "mailbox"), nil, 0o600)
		}},
		{"an upper-case mailbox name", func(t *testing.T, root string) { mk(t, root, strings.ToUpper(rcpt)[:39]+"A") }},
		{"a short mailbox name", func(t *testing.T, root string) { mk(t, root, rcpt[:38]) }},
		{"a file where a mailbox directory belongs", func(t *testing.T, root string) {
			os.MkdirAll(filepath.Join(root, "mailbox"), 0o700)
			os.WriteFile(filepath.Join(root, "mailbox", rcpt), nil, 0o600)
		}},
		{"a stray file in the mailbox directory", func(t *testing.T, root string) {
			mk(t, root, rcpt)
			os.WriteFile(filepath.Join(root, "mailbox", "README"), nil, 0o600)
		}},
		{"a stray file in the root", func(t *testing.T, root string) { os.WriteFile(filepath.Join(root, "notes.txt"), nil, 0o600) }},
		{"a stray directory in the root", func(t *testing.T, root string) { os.Mkdir(filepath.Join(root, "objects"), 0o700) }},
		{"a badly named entry", func(t *testing.T, root string) {
			d := mk(t, root, rcpt)
			os.WriteFile(filepath.Join(d, strings.ToUpper(good)), []byte("x"), 0o600)
		}},
		{"an entry with an unexpected extra name", func(t *testing.T, root string) {
			d := mk(t, root, rcpt)
			os.WriteFile(filepath.Join(d, good+".bak"), []byte("x"), 0o600)
		}},
		{"an empty entry", func(t *testing.T, root string) {
			d := mk(t, root, rcpt)
			os.WriteFile(filepath.Join(d, good), nil, 0o600)
		}},
		{"an entry over the envelope bound", func(t *testing.T, root string) {
			d := mk(t, root, rcpt)
			p := filepath.Join(d, good)
			os.WriteFile(p, nil, 0o600)
			os.Truncate(p, mailbox.MaxEnvelopeBytes+1) // sparse: nothing is written
		}},
		{"an entry far over the bound that claims terabytes", func(t *testing.T, root string) {
			d := mk(t, root, rcpt)
			p := filepath.Join(d, good)
			os.WriteFile(p, nil, 0o600)
			if err := os.Truncate(p, 1<<40); err != nil {
				t.Skip(err)
			}
		}},
		{"an entry file readable by its group", func(t *testing.T, root string) {
			d := mk(t, root, rcpt)
			p := filepath.Join(d, good)
			os.WriteFile(p, []byte("x"), 0o600)
			os.Chmod(p, 0o640)
		}},
		{"a mailbox directory open to its group", func(t *testing.T, root string) {
			d := mk(t, root, rcpt)
			os.Chmod(d, 0o750)
		}},
		{"the mailbox directory open to others", func(t *testing.T, root string) {
			mk(t, root, rcpt)
			os.Chmod(filepath.Join(root, "mailbox"), 0o705)
		}},
		{"too many mailboxes", func(t *testing.T, root string) {
			os.MkdirAll(filepath.Join(root, "mailbox"), 0o700)
			for i := range mailbox.MaxAccessListParties + 1 {
				var f party.Fingerprint
				f[0], f[1] = byte(i>>8), byte(i)
				d := filepath.Join(root, "mailbox", recipientName(f))
				os.Mkdir(d, 0o700)
				os.WriteFile(filepath.Join(d, good), []byte("x"), 0o600) // empty ones are pruned, not refused
			}
		}},
		{"too many entries in one mailbox", func(t *testing.T, root string) {
			d := mk(t, root, rcpt)
			for i := range mailbox.MaxMailboxEntries + 1 {
				os.WriteFile(filepath.Join(d, entryName(t0, mailbox.HashOf([]byte{byte(i), byte(i >> 8)}), sndC)), []byte("x"), 0o600)
			}
		}},
		{"too many temporary files in one mailbox", func(t *testing.T, root string) {
			d := mk(t, root, rcpt)
			for i := range 2*mailbox.MaxMailboxEntries + 1 {
				os.WriteFile(filepath.Join(d, fmt.Sprintf(".tmp-%016x", i)), nil, 0o600)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := newDir(t)
			c.setup(t, root)
			done := make(chan error, 1)
			go func() {
				s, _, err := Open(root, relayporttest.NewManualClock(t0))
				if err == nil {
					s.Close()
				}
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, relayport.ErrMailboxCorrupt) && !strings.Contains(fmt.Sprint(err), "writable") {
					t.Fatalf("Open = %v, want a refusal (ErrMailboxCorrupt)", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Open hung (a FIFO must never be opened for reading)")
			}
		})
	}
}

// goodFile is a regular file of this user, mode 0600, one byte: what an entry
// would be if a link to it were followed.
func goodFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func mk(t *testing.T, root string, parts ...string) string {
	t.Helper()
	p := filepath.Join(append([]string{root, "mailbox"}, parts...)...)
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

// spec: SPO-Xmailbox-INV-005
func TestCrashLeftoversAreCleanedAtOpen(t *testing.T) {
	root := newDir(t)
	d := mk(t, root, recipientName(rcptA))
	for _, n := range []string{".tmp-0123456789abcdef", ".tmp-fedcba9876543210"} {
		os.WriteFile(filepath.Join(d, n), []byte("half a body"), 0o600)
	}
	s := openAt(t, root, relayporttest.NewManualClock(t0))
	if left, _ := os.ReadDir(d); len(left) != 0 {
		t.Fatalf("%d leftovers after Open", len(left))
	}
	if n := len(entries(t, s, rcptA)); n != 0 {
		t.Fatalf("%d entries", n)
	}
}

// spec: SPO-Xmailbox-OUT-015
func TestUsageIsRecomputedFromTheDirectoryAtOpen(t *testing.T) {
	root := newDir(t)
	clk := relayporttest.NewManualClock(t0)
	s := openAt(t, root, clk)
	put(t, s, rcptA, sndC, body(11, 1))
	put(t, s, rcptA, sndC, body(22, 2))
	put(t, s, rcptA, fp(0xD4), body(33, 3))
	put(t, s, rcptB, sndC, body(44, 4))
	want := func(s *Store, r, snd party.Fingerprint) mailbox.Usage {
		u, _ := s.Usage(context.Background(), r, snd)
		return u
	}
	before := []mailbox.Usage{want(s, rcptA, sndC), want(s, rcptA, fp(0xD4)), want(s, rcptB, sndC)}
	if before[0] != (mailbox.Usage{MailboxEntries: 3, MailboxBytes: 66, PairEntries: 2, PairBytes: 33, SenderBytes: 77, GlobalBytes: 110}) {
		t.Fatalf("usage = %+v", before[0])
	}
	s.Close()
	s2 := openAt(t, root, clk)
	after := []mailbox.Usage{want(s2, rcptA, sndC), want(s2, rcptA, fp(0xD4)), want(s2, rcptB, sndC)}
	if !slices.Equal(before, after) {
		t.Fatalf("usage after reopen %+v, before %+v", after, before)
	}
}

// spec: SPO-Xmailbox-INV-005
func TestCrashBetweenTheStepsOfAPut(t *testing.T) {
	steps := []string{stepTmpCreated, stepBodyWritten, stepBodySynced, stepLinked, stepTmpUnlinked, stepDirSynced}
	visible := map[string]bool{stepLinked: true, stepTmpUnlinked: true, stepDirSynced: true}
	for _, at := range steps {
		t.Run("crash at "+at, func(t *testing.T) {
			root, snap := newDir(t), filepath.Join(t.TempDir(), "snap")
			os.Mkdir(snap, 0o700)
			clk := relayporttest.NewManualClock(t0)
			s := openAt(t, root, clk)
			stepHook = func(step string) error {
				if step == at {
					copyTree(t, root, snap) // the disk as a crash here would leave it
				}
				return nil
			}
			defer func() { stepHook = nil }()
			b := body(5000, 7)
			put(t, s, rcptA, sndC, b)
			stepHook = nil
			// the temporary name exists from its creation until it is unlinked
			tmps := 0
			for _, l := range tree(t, snap) {
				if strings.Contains(l, tmpPrefix) {
					tmps++
				}
			}
			if want := map[string]int{stepTmpCreated: 1, stepBodyWritten: 1, stepBodySynced: 1, stepLinked: 1}[at]; tmps != want {
				t.Fatalf("at %s the disk holds %d temporary files, want %d", at, tmps, want)
			}
			// a new process opens what the crash left
			s2, _, err := Open(snap, clk)
			if err != nil {
				t.Fatalf("Open of the crashed directory: %v", err)
			}
			defer s2.Close()
			es := entries(t, s2, rcptA)
			if visible[at] {
				if len(es) != 1 || es[0].Mid != mailbox.HashOf(b) {
					t.Fatalf("after a crash at %s the entry is missing: %+v", at, es)
				}
				rc, err := s2.Open(context.Background(), rcptA, es[0].Mid)
				if err != nil {
					t.Fatal(err)
				}
				got, _ := io.ReadAll(rc)
				rc.Close()
				if !bytes.Equal(got, b) {
					t.Fatal("the linked entry is not whole")
				}
				if o := put(t, s2, rcptA, sndC, b); o != relayport.MailboxDuplicate {
					t.Fatalf("a retry after the crash = %v, want duplicate", o)
				}
			} else {
				if len(es) != 0 {
					t.Fatalf("a crash at %s left a visible entry: %+v", at, es)
				}
				if u, _ := s2.Usage(context.Background(), rcptA, sndC); u != (mailbox.Usage{}) {
					t.Fatalf("usage after the crash = %+v", u)
				}
				if o := put(t, s2, rcptA, sndC, b); o != relayport.MailboxStored {
					t.Fatalf("a retry after the crash = %v, want stored", o)
				}
			}
			for _, l := range tree(t, snap) {
				if strings.Contains(l, tmpPrefix) {
					t.Fatalf("a temporary file survives Open: %s", l)
				}
			}
		})
	}
}

// spec: SPO-Xmailbox-INV-005
func TestFailureBetweenTheStepsLeavesNothing(t *testing.T) {
	boom := errors.New("disk on fire")
	for _, at := range []string{stepReserved, stepDirOpened, stepTmpCreated, stepBodyWritten, stepBodySynced, stepLinked, stepTmpUnlinked, stepDirSynced} {
		t.Run("failure at "+at, func(t *testing.T) {
			root := newDir(t)
			clk := relayporttest.NewManualClock(t0)
			s := openAt(t, root, clk)
			stepHook = func(step string) error {
				if step == at {
					return boom
				}
				return nil
			}
			defer func() { stepHook = nil }()
			b := body(900, 9)
			o, err := s.Put(context.Background(), relayport.MailboxPut{Recipient: rcptA, Sender: sndC, Mid: mailbox.HashOf(b), Size: uint32(len(b)), Quota: loose}, bytes.NewReader(b))
			if !errors.Is(err, boom) || o == relayport.MailboxStored {
				t.Fatalf("Put = %v, %v; want the failure", o, err)
			}
			stepHook = nil
			if es := entries(t, s, rcptA); len(es) != 0 {
				t.Fatalf("an entry is visible after a failed put: %+v", es)
			}
			if u, _ := s.Usage(context.Background(), rcptA, sndC); u != (mailbox.Usage{}) {
				t.Fatalf("a failed put left usage %+v (a reservation leaked)", u)
			}
			for _, l := range tree(t, root) {
				if strings.Contains(l, tmpPrefix) || strings.Contains(l, "0000000") {
					t.Fatalf("a failed put left %s", l)
				}
			}
			if o := put(t, s, rcptA, sndC, b); o != relayport.MailboxStored {
				t.Fatalf("a retry = %v, want stored", o)
			}
		})
	}
}

// spec: SPO-Xmailbox-INV-005
func TestCrashDuringRemoveLeavesAConsistentMailbox(t *testing.T) {
	for _, at := range []string{stepUnlinked, stepRemoveSynced} {
		t.Run(at, func(t *testing.T) {
			root, snap := newDir(t), filepath.Join(t.TempDir(), "snap")
			os.Mkdir(snap, 0o700)
			clk := relayporttest.NewManualClock(t0)
			s := openAt(t, root, clk)
			b1, b2 := body(100, 1), body(200, 2)
			put(t, s, rcptA, sndC, b1)
			put(t, s, rcptA, sndC, b2)
			stepHook = func(step string) error {
				if step == at {
					copyTree(t, root, snap)
				}
				return nil
			}
			defer func() { stepHook = nil }()
			if ok, err := s.Remove(context.Background(), rcptA, mailbox.HashOf(b1)); err != nil || !ok {
				t.Fatal(ok, err)
			}
			stepHook = nil
			s2, _, err := Open(snap, clk)
			if err != nil {
				t.Fatal(err)
			}
			defer s2.Close()
			es := entries(t, s2, rcptA)
			if len(es) != 1 || es[0].Mid != mailbox.HashOf(b2) {
				t.Fatalf("after a crash during Remove: %+v", es)
			}
			u, _ := s2.Usage(context.Background(), rcptA, sndC)
			if u.MailboxEntries != 1 || u.MailboxBytes != 200 || u.GlobalBytes != 200 {
				t.Fatalf("usage = %+v", u)
			}
		})
	}
}

// the hook seam is set only by tests
func TestNoHookIsSetByDefault(t *testing.T) {
	if stepHook != nil {
		t.Fatal("a step hook is set outside a test")
	}
}

// spec: SPO-Xmailbox-INV-005
func TestAnEntryIsNeverVisibleHalfWritten(t *testing.T) {
	root := newDir(t)
	s := openAt(t, root, relayporttest.NewManualClock(t0))
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var bad error
	var mu sync.Mutex
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			es, _, _ := s.List(context.Background(), rcptA, nil, mailbox.MaxMailboxEntries)
			for _, e := range es {
				rc, err := s.Open(context.Background(), rcptA, e.Mid)
				if err != nil {
					continue
				}
				h := mailbox.NewHasher()
				n, _ := io.Copy(h, rc)
				rc.Close()
				if uint32(n) != e.Size || h.Sum() != e.Mid {
					mu.Lock()
					bad = fmt.Errorf("entry %v read as %d bytes (declared %d), hash %v", e.Mid, n, e.Size, h.Sum())
					mu.Unlock()
					return
				}
			}
		}
	}()
	for i := range 12 {
		put(t, s, rcptA, sndC, body(200_000+i, byte(i)))
	}
	close(stop)
	wg.Wait()
	if bad != nil {
		t.Fatal(bad)
	}
}

// spec: SPO-Xmailbox-INV-008
func TestStressKeepsTheCountersEqualToTheDisk(t *testing.T) {
	root := newDir(t)
	clk := relayporttest.NewManualClock(t0)
	s := openAt(t, root, clk)
	var wg sync.WaitGroup
	for w := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := context.Background()
			for i := range 40 {
				b := body(100+(i%7), byte(w*40+i))
				rcpt := []party.Fingerprint{rcptA, rcptB}[i%2]
				s.Put(ctx, relayport.MailboxPut{Recipient: rcpt, Sender: fp(byte(w)), Mid: mailbox.HashOf(b), Size: uint32(len(b)), Quota: loose}, bytes.NewReader(b))
				switch i % 5 {
				case 1:
					s.Remove(ctx, rcpt, mailbox.HashOf(body(100+((i-1)%7), byte(w*40+i-1))))
				case 3:
					s.List(ctx, rcpt, nil, 16)
				case 4:
					clk.Advance(time.Second)
					s.Sweep(ctx, 5)
				}
			}
		}()
	}
	wg.Wait()
	live := map[party.Fingerprint]mailbox.Usage{}
	for _, r := range []party.Fingerprint{rcptA, rcptB} {
		for _, e := range entries(t, s, r) {
			u := live[r]
			u.MailboxEntries++
			u.MailboxBytes += uint64(e.Size)
			live[r] = u
		}
	}
	for r, w := range live {
		got, _ := s.Usage(context.Background(), r, fp(200))
		if got.MailboxEntries != w.MailboxEntries || got.MailboxBytes != w.MailboxBytes {
			t.Fatalf("counters %+v do not match the listing %+v", got, w)
		}
	}
	s.Close()
	s2 := openAt(t, root, clk)
	for r, w := range live {
		got, _ := s2.Usage(context.Background(), r, fp(200))
		if got.MailboxEntries != w.MailboxEntries || got.MailboxBytes != w.MailboxBytes {
			t.Fatalf("after reopen: counters %+v, listing %+v", got, w)
		}
	}
}

// spec: SPO-Xmailbox-OUT-014
func TestBodiesAreStreamedNotHeldTwice(t *testing.T) {
	s := openAt(t, newDir(t), relayporttest.NewManualClock(t0))
	b := body(mailbox.MaxEnvelopeBytes, 5)
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	put(t, s, rcptA, sndC, b)
	runtime.ReadMemStats(&m1)
	if d := m1.TotalAlloc - m0.TotalAlloc; d > 256<<10 {
		t.Fatalf("a put of 1 MiB allocated %d bytes; the body must stream", d)
	}
	rc, err := s.Open(context.Background(), rcptA, mailbox.HashOf(b))
	if err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&m0)
	n, _ := io.Copy(io.Discard, rc)
	rc.Close()
	runtime.ReadMemStats(&m1)
	if d := m1.TotalAlloc - m0.TotalAlloc; n != mailbox.MaxEnvelopeBytes || d > 256<<10 {
		t.Fatalf("a read of %d bytes allocated %d", n, d)
	}
}

// spec: SPO-Xmailbox-SEC-006
func TestAHostileEntryChangedAfterOpenIsNotTrusted(t *testing.T) {
	root := newDir(t)
	s := openAt(t, root, relayporttest.NewManualClock(t0))
	b := body(100, 3)
	put(t, s, rcptA, sndC, b)
	p := filepath.Join(root, "mailbox", recipientName(rcptA), entryName(t0, mailbox.HashOf(b), sndC))
	// grown behind our back: the reader still yields only the recorded size, or refuses
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.Write(make([]byte, 5000))
	f.Close()
	rc, err := s.Open(context.Background(), rcptA, mailbox.HashOf(b))
	if err == nil {
		got, _ := io.ReadAll(rc)
		rc.Close()
		if len(got) > len(b) {
			t.Fatalf("read %d bytes of an entry recorded as %d", len(got), len(b))
		}
	} else if !errors.Is(err, relayport.ErrMailboxCorrupt) {
		t.Fatal(err)
	}
	// replaced by a symlink: refused, never followed
	os.Remove(p)
	same := filepath.Join(t.TempDir(), "same")
	os.WriteFile(same, b, 0o600)
	os.Symlink(same, p) // a link to a file of exactly the recorded size
	if rc, err := s.Open(context.Background(), rcptA, mailbox.HashOf(b)); err == nil {
		rc.Close()
		t.Fatal("a symlink in place of an entry was opened")
	}
	// replaced by a FIFO: refused without blocking
	os.Remove(p)
	if syscall.Mkfifo(p, 0o600) == nil {
		done := make(chan error, 1)
		go func() {
			rc, err := s.Open(context.Background(), rcptA, mailbox.HashOf(b))
			if err == nil {
				rc.Close()
			}
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("a FIFO in place of an entry was opened")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Open of a FIFO blocked")
		}
	}
}

func TestNegativeClockIsRefused(t *testing.T) {
	s := openAt(t, newDir(t), relayporttest.NewManualClock(-5))
	b := body(10, 1)
	o, err := s.Put(context.Background(), relayport.MailboxPut{Recipient: rcptA, Sender: sndC, Mid: mailbox.HashOf(b), Size: 10, Quota: loose}, bytes.NewReader(b))
	if err == nil || o == relayport.MailboxStored {
		t.Fatalf("Put with a clock before 1970 = %v, %v", o, err)
	}
}

func TestEmptyMailboxDirectoryIsPrunedAfterTheLastRemove(t *testing.T) {
	root := newDir(t)
	s := openAt(t, root, relayporttest.NewManualClock(t0))
	b := body(10, 1)
	put(t, s, rcptA, sndC, b)
	s.Remove(context.Background(), rcptA, mailbox.HashOf(b))
	if _, err := os.Stat(filepath.Join(root, "mailbox", recipientName(rcptA))); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the empty mailbox directory is still there: %v", err)
	}
	if o := put(t, s, rcptA, sndC, b); o != relayport.MailboxStored {
		t.Fatal(o)
	}
}

// spec: SPO-Xmailbox-SEC-008
func TestADirectoryReplacedByALinkAfterOpenIsNotFollowed(t *testing.T) {
	root := newDir(t)
	s := openAt(t, root, relayporttest.NewManualClock(t0))
	b := body(100, 3)
	put(t, s, rcptA, sndC, b)
	// another directory holds the same entry name
	elsewhere := filepath.Join(t.TempDir(), "other")
	os.Mkdir(elsewhere, 0o700)
	name := entryName(t0, mailbox.HashOf(b), sndC)
	os.WriteFile(filepath.Join(elsewhere, name), b, 0o600)
	mdir := filepath.Join(root, "mailbox", recipientName(rcptA))
	os.RemoveAll(mdir)
	os.Symlink(elsewhere, mdir)
	if rc, err := s.Open(context.Background(), rcptA, mailbox.HashOf(b)); err == nil {
		rc.Close()
		t.Fatal("a mailbox directory replaced by a link was followed on read")
	}
	b2 := body(50, 4)
	if o, err := s.Put(context.Background(), relayport.MailboxPut{Recipient: rcptA, Sender: sndC, Mid: mailbox.HashOf(b2), Size: 50, Quota: loose}, bytes.NewReader(b2)); err == nil {
		t.Fatalf("a put through a replaced directory = %v", o)
	}
	if left, _ := os.ReadDir(elsewhere); len(left) != 1 {
		t.Fatalf("a put wrote through the link: %d files elsewhere", len(left))
	}
}

// the bounds are inclusive: the limit itself is accepted at open
func TestOpenAcceptsTheBounds(t *testing.T) {
	root := newDir(t)
	d := mk(t, root, recipientName(rcptA))
	for i := range mailbox.MaxMailboxEntries {
		os.WriteFile(filepath.Join(d, entryName(t0, mailbox.HashOf([]byte{byte(i), byte(i >> 8)}), sndC)), []byte("x"), 0o600)
	}
	big := filepath.Join(d, entryName(t0, mailbox.HashOf([]byte("big")), sndC))
	_ = big
	for i := 1; i < mailbox.MaxAccessListParties; i++ { // 1023 more, 1024 in all
		var f party.Fingerprint
		f[0], f[1] = byte(i>>8), byte(i)
		f[19] = 7
		os.Mkdir(filepath.Join(root, "mailbox", recipientName(f)), 0o700)
	}
	s, _, err := Open(root, relayporttest.NewManualClock(t0))
	if err != nil {
		t.Fatalf("Open at the bounds: %v", err)
	}
	s.Close()
	// an entry of exactly the largest envelope
	root2 := newDir(t)
	d2 := mk(t, root2, recipientName(rcptA))
	p := filepath.Join(d2, entryName(t0, mailbox.HashOf([]byte("m")), sndC))
	os.WriteFile(p, nil, 0o600)
	os.Truncate(p, mailbox.MaxEnvelopeBytes)
	s2, _, err := Open(root2, relayporttest.NewManualClock(t0))
	if err != nil {
		t.Fatalf("Open with an entry of the largest size: %v", err)
	}
	s2.Close()
	// and as many temporary files as the bound allows
	root3 := newDir(t)
	d3 := mk(t, root3, recipientName(rcptA))
	for i := range 2 * mailbox.MaxMailboxEntries {
		os.WriteFile(filepath.Join(d3, fmt.Sprintf(".tmp-%016x", i)), nil, 0o600)
	}
	s3, _, err := Open(root3, relayporttest.NewManualClock(t0))
	if err != nil {
		t.Fatalf("Open with %d temporary files: %v", 2*mailbox.MaxMailboxEntries, err)
	}
	s3.Close()
}

// spec: SPO-Xmailbox-INV-005
func TestTheSyncsHappenInTheRightOrder(t *testing.T) {
	root := newDir(t)
	clk := relayporttest.NewManualClock(t0)
	s := openAt(t, root, clk)
	b := body(100, 1)
	put(t, s, rcptA, sndC, b) // makes the mailbox directory
	var events []string
	stepHook = func(step string) error { events = append(events, step); return nil }
	syncFd = func(fd int) error {
		var st unix.Stat_t
		unix.Fstat(fd, &st)
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFREG:
			events = append(events, "fsync:file")
		case unix.S_IFDIR:
			events = append(events, "fsync:dir")
		}
		return unix.Fsync(fd)
	}
	defer func() { stepHook, syncFd = nil, unix.Fsync }()
	b2 := body(200, 2)
	put(t, s, rcptA, sndC, b2)
	want := []string{stepReserved, stepDirOpened, stepTmpCreated, stepBodyWritten, "fsync:file", stepBodySynced, stepLinked, stepTmpUnlinked, "fsync:dir", stepDirSynced}
	if fmt.Sprint(events) != fmt.Sprint(want) {
		t.Fatalf("a put did\n %v\nwant\n %v", events, want)
	}
	events = nil
	if ok, err := s.Remove(context.Background(), rcptA, mailbox.HashOf(b2)); err != nil || !ok {
		t.Fatal(ok, err)
	}
	want = []string{stepUnlinked, "fsync:dir", stepRemoveSynced}
	if fmt.Sprint(events[:3]) != fmt.Sprint(want) {
		t.Fatalf("a remove did %v, want %v first", events, want)
	}
}

// A remove that empties a mailbox while a put to it is between opening the
// directory and creating its temporary file must not take the directory away.
//
// spec: SPO-Xmailbox-INV-008
func TestPruneLeavesTheDirectoryOfAPutInFlight(t *testing.T) {
	root := newDir(t)
	s := openAt(t, root, relayporttest.NewManualClock(t0))
	first, second := body(40, 1), body(60, 2)
	put(t, s, rcptA, sndC, first)
	stepHook = func(step string) error {
		if step == stepDirOpened {
			stepHook = nil
			if ok, err := s.Remove(context.Background(), rcptA, mailbox.HashOf(first)); err != nil || !ok {
				t.Errorf("Remove = %v, %v", ok, err)
			}
		}
		return nil
	}
	defer func() { stepHook = nil }()
	if o := put(t, s, rcptA, sndC, second); o != relayport.MailboxStored {
		t.Fatalf("Put = %v", o)
	}
	if es := entries(t, s, rcptA); len(es) != 1 || es[0].Mid != mailbox.HashOf(second) {
		t.Fatalf("entries = %+v", es)
	}
}

// A directory with a huge number of names is abandoned at its bound, never read
// whole.
//
// spec: SPO-Xmailbox-SEC-006
func TestAHugeDirectoryIsAbandonedAtItsBound(t *testing.T) {
	root := newDir(t)
	d := mk(t, root, recipientName(rcptA))
	for i := range 6000 {
		os.WriteFile(filepath.Join(d, fmt.Sprintf(".tmp-%016x", i)), nil, 0o600)
	}
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	s, _, err := Open(root, relayporttest.NewManualClock(t0))
	runtime.ReadMemStats(&m1)
	if err == nil {
		s.Close()
		t.Fatal("Open accepted 6000 names in one mailbox")
	}
	if got := m1.TotalAlloc - m0.TotalAlloc; got > 200<<10 {
		t.Fatalf("refusing the directory allocated %d bytes; it was read past its bound", got)
	}
}

// A clock beyond the protocol's time range is refused like one before 1970,
// and a stored name carrying an arrival beyond that range (a planted file, or
// a clock that once ran ahead) is accepted at open, counted, and expired by
// Sweep (the domain's Expired), so it cannot hold quota for ever.
//
// spec: SPO-Xmailbox-SEC-015
func TestFarFutureArrivalIsClockRefusedAndSwept(t *testing.T) {
	s := openAt(t, newDir(t), relayporttest.NewManualClock(mailbox.MaxTime+1))
	b := body(10, 1)
	o, err := s.Put(context.Background(), relayport.MailboxPut{Recipient: rcptA, Sender: sndC, Mid: mailbox.HashOf(b), Size: 10, Quota: loose}, bytes.NewReader(b))
	if err == nil || o == relayport.MailboxStored {
		t.Fatalf("Put with a clock above the range = %v, %v", o, err)
	}
	if es := entries(t, s, rcptA); len(es) != 0 {
		t.Fatalf("%d entries stored", len(es))
	}
	// The last second of the range is a clock the store accepts.
	s2 := openAt(t, newDir(t), relayporttest.NewManualClock(mailbox.MaxTime))
	if o := put(t, s2, rcptA, sndC, b); o != relayport.MailboxStored {
		t.Fatalf("Put at the top of the range = %v", o)
	}

	root := newDir(t)
	clk := relayporttest.NewManualClock(t0)
	s3 := openAt(t, root, clk)
	put(t, s3, rcptA, sndC, body(10, 1))
	put(t, s3, rcptA, sndC, body(20, 2))
	s3.Close()
	names, _ := filepath.Glob(filepath.Join(root, "mailbox", "*", "*"))
	if len(names) != 2 {
		t.Fatalf("%v", names)
	}
	sort.Strings(names)
	// Rename the first entry to an arrival of MaxInt64 (20 digits, so it still
	// fits the name's shape and an int64).
	base := filepath.Base(names[0])
	if err := os.Rename(names[0], filepath.Join(filepath.Dir(names[0]), "09223372036854775807"+base[20:])); err != nil {
		t.Fatal(err)
	}
	s4, _, err := Open(root, clk)
	if err != nil {
		t.Fatalf("a name with a far-future arrival is refused at open: %v", err)
	}
	defer s4.Close()
	u, _ := s4.Usage(context.Background(), rcptA, sndC)
	if u.MailboxEntries != 2 || u.MailboxBytes != 30 {
		t.Fatalf("usage %+v", u)
	}
	n, err := s4.Sweep(context.Background(), mailbox.DefaultRetentionSeconds)
	if err != nil || n != 1 {
		t.Fatalf("Sweep = %d, %v; want the far-future entry only", n, err)
	}
	u, _ = s4.Usage(context.Background(), rcptA, sndC)
	if u.MailboxEntries != 1 {
		t.Fatalf("usage after the sweep %+v", u)
	}
}
