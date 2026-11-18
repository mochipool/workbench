//go:build unix

package mailboxstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

func putOf(rcpt, snd party.Fingerprint, b []byte) relayport.MailboxPut {
	return relayport.MailboxPut{Recipient: rcpt, Sender: snd, Mid: mailbox.HashOf(b), Size: uint32(len(b)), Quota: loose}
}

func listAllOf(t *testing.T, s *Store, rcpt party.Fingerprint) []relayport.MailboxEntry {
	t.Helper()
	return entries(t, s, rcpt)
}

// ---- M1: a put reads exactly the declared size ----

// blockAfter serves data and then blocks until its own deadline passes, as a
// stream with a read deadline does. reads counts the calls that reached the
// block.
type blockAfter struct {
	data    []byte
	wait    time.Duration
	blocked int
}

func (b *blockAfter) Read(p []byte) (int, error) {
	if len(b.data) == 0 {
		b.blocked++
		time.Sleep(b.wait)
		return 0, os.ErrDeadlineExceeded
	}
	n := copy(p, b.data)
	b.data = b.data[n:]
	return n, nil
}

// spec: SPO-Xmailbox-OUT-020
func TestPutLeavesTheNextFrameOnTheStream(t *testing.T) {
	s := openAt(t, newDir(t), relayporttest.NewManualClock(t0))
	b := body(100, 1)
	trailer := []byte("NEXT-FRAME-HEADER")
	r := bytes.NewReader(append(slices.Clone(b), trailer...))
	o, err := s.Put(context.Background(), putOf(rcptA, sndC, b), r)
	if err != nil || o != relayport.MailboxStored {
		t.Fatalf("Put from a stream with a following frame = %v, %v", o, err)
	}
	rest, _ := io.ReadAll(r)
	if !bytes.Equal(rest, trailer) {
		t.Fatalf("the stream holds %q after the put, want the untouched %q", rest, trailer)
	}
}

// spec: SPO-Xmailbox-OUT-020
func TestPutWithAnExactBodyDoesNotWaitForAnotherByte(t *testing.T) {
	s := openAt(t, newDir(t), relayporttest.NewManualClock(t0))
	b := body(100, 2)
	r := &blockAfter{data: slices.Clone(b), wait: 300 * time.Millisecond}
	o, err := s.Put(context.Background(), putOf(rcptA, sndC, b), r)
	if err != nil || o != relayport.MailboxStored || r.blocked != 0 {
		t.Fatalf("Put = %v, %v; the reader was read past the declared size %d times", o, err, r.blocked)
	}
}

// spec: SPO-Xmailbox-OUT-020, SPO-Xmailbox-PRE-017
func TestPutWhoseReaderBlocksReleasesItsReservationOnTheDeadline(t *testing.T) {
	s := openAt(t, newDir(t), relayporttest.NewManualClock(t0))
	b := body(100, 3)
	r := &blockAfter{data: slices.Clone(b[:40]), wait: 50 * time.Millisecond}
	o, err := s.Put(context.Background(), putOf(rcptA, sndC, b), r)
	if !errors.Is(err, os.ErrDeadlineExceeded) || o == relayport.MailboxStored {
		t.Fatalf("Put = %v, %v; want the deadline error", o, err)
	}
	if u, _ := s.Usage(context.Background(), rcptA, sndC); u != (mailbox.Usage{}) {
		t.Fatalf("the reservation leaked: %+v", u)
	}
	if o := put(t, s, rcptA, sndC, b); o != relayport.MailboxStored { // not Busy
		t.Fatalf("a retry = %v", o)
	}
}

// spec: SPO-Xmailbox-PRE-017
func TestPutWithAShortBodyIsAnUnexpectedEOF(t *testing.T) {
	s := openAt(t, newDir(t), relayporttest.NewManualClock(t0))
	b := body(100, 4)
	o, err := s.Put(context.Background(), putOf(rcptA, sndC, b), bytes.NewReader(b[:60]))
	if !errors.Is(err, io.ErrUnexpectedEOF) || !errors.Is(err, mailbox.ErrSize) || o == relayport.MailboxStored {
		t.Fatalf("Put of 60 of 100 bytes = %v, %v; want ErrUnexpectedEOF wrapping ErrSize", o, err)
	}
}

// ---- item 4: a revoked mailbox is not recreated by a put in flight ----

// spec: SPO-Xmailbox-INV-009
func TestRemoveMailboxCancelsAPutInFlight(t *testing.T) {
	for _, withEntries := range []bool{false, true} {
		t.Run(fmt.Sprintf("existing entries %v", withEntries), func(t *testing.T) {
			root := newDir(t)
			s := openAt(t, root, relayporttest.NewManualClock(t0))
			if withEntries {
				put(t, s, rcptA, sndC, body(30, 9))
			}
			stepHook = func(step string) error {
				if step == stepDirOpened {
					stepHook = nil
					if _, err := s.RemoveMailbox(context.Background(), rcptA); err != nil {
						t.Errorf("RemoveMailbox: %v", err)
					}
				}
				return nil
			}
			defer func() { stepHook = nil }()
			b := body(100, 5)
			o, err := s.Put(context.Background(), putOf(rcptA, sndC, b), bytes.NewReader(b))
			if !errors.Is(err, relayport.ErrMailboxRevoked) || o == relayport.MailboxStored {
				t.Fatalf("Put = %v, %v; want ErrMailboxRevoked", o, err)
			}
			if es := entries(t, s, rcptA); len(es) != 0 {
				t.Fatalf("a revoked mailbox lists %+v", es)
			}
			if u, _ := s.Usage(context.Background(), rcptA, sndC); u != (mailbox.Usage{}) {
				t.Fatalf("usage %+v after the revoked put (a reservation leaked)", u)
			}
			if _, err := os.Stat(filepath.Join(root, "mailbox", recipientName(rcptA))); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the mailbox directory was recreated: %v", err)
			}
			// a put after the revocation is a new put and is stored
			if o := put(t, s, rcptA, sndC, b); o != relayport.MailboxStored {
				t.Fatalf("a put after the revocation = %v", o)
			}
			if len(s.revoked) != 0 {
				t.Fatalf("revocation markers are kept with no put in flight: %v", s.revoked)
			}
		})
	}
}

// ---- item 5: operations racing Close ----

// spec: SPO-Xmailbox-INV-010
func TestAPutAfterCloseDoesNotUseAReusedDescriptor(t *testing.T) {
	root := newDir(t)
	s := openAt(t, root, relayporttest.NewManualClock(t0))
	decoy := t.TempDir()
	mboxFd := int(s.mbox.Fd())
	var held []int
	stepHook = func(step string) error {
		if step != stepReserved {
			return nil
		}
		stepHook = nil
		s.Close()
		for range 16 { // take the numbers the closed store gave back
			fd, err := unix.Open(decoy, unix.O_RDONLY|unix.O_DIRECTORY, 0)
			if err != nil {
				t.Error(err)
				return nil
			}
			held = append(held, fd)
			if fd == mboxFd {
				break
			}
		}
		return nil
	}
	defer func() {
		stepHook = nil
		for _, fd := range held {
			unix.Close(fd)
		}
	}()
	b := body(100, 6)
	_, err := s.Put(context.Background(), putOf(rcptA, sndC, b), bytes.NewReader(b))
	if !errors.Is(err, relayport.ErrMailboxClosed) {
		t.Fatalf("Put across Close = %v, want ErrMailboxClosed", err)
	}
	if left, _ := os.ReadDir(decoy); len(left) != 0 {
		t.Fatalf("a put wrote into a directory that reused the closed descriptor: %v", left)
	}
}

// spec: SPO-Xmailbox-INV-010
func TestCloseRacingOperationsIsSafe(t *testing.T) {
	for range 20 {
		root := newDir(t)
		clk := relayporttest.NewManualClock(t0)
		s := openAt(t, root, clk)
		first := body(50, 1)
		put(t, s, rcptA, sndC, first)
		var wg sync.WaitGroup
		okErr := func(err error) bool {
			return err == nil || errors.Is(err, relayport.ErrMailboxClosed) || errors.Is(err, relayport.ErrMailboxNotFound)
		}
		for w := range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx := context.Background()
				for i := range 20 {
					b := body(60+i, byte(w*20+i))
					if _, err := s.Put(ctx, putOf(rcptA, fp(byte(w)), b), bytes.NewReader(b)); !okErr(err) {
						t.Errorf("Put: %v", err)
					}
					if rc, err := s.Open(ctx, rcptA, mailbox.HashOf(first)); err == nil {
						io.Copy(io.Discard, rc)
						rc.Close()
					} else if !okErr(err) {
						t.Errorf("Open: %v", err)
					}
					if _, _, err := s.List(ctx, rcptA, nil, 8); !okErr(err) {
						t.Errorf("List: %v", err)
					}
					if _, err := s.Sweep(ctx, 5); !okErr(err) {
						t.Errorf("Sweep: %v", err)
					}
				}
			}()
		}
		time.Sleep(time.Millisecond)
		s.Close()
		wg.Wait()
		if _, err := s.Open(context.Background(), rcptA, mailbox.HashOf(first)); !errors.Is(err, relayport.ErrMailboxClosed) {
			t.Fatalf("Open after Close = %v", err)
		}
	}
}

// ---- item 6: open repairs what is recoverable ----

// spec: SPO-Xmailbox-OUT-023
func TestOpenKeepsTheEarliestOfTwoEntriesWithOneSenderAndMid(t *testing.T) {
	root := newDir(t)
	d := mk(t, root, recipientName(rcptA))
	mid := mailbox.HashOf([]byte("m"))
	early, late := entryName(t0, mid, sndC), entryName(t0+5, mid, sndC)
	os.WriteFile(filepath.Join(d, early), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(d, late), []byte("x"), 0o600)
	// another sender's entry with the same mid is not a duplicate
	other := entryName(t0+7, mid, fp(0xD4))
	os.WriteFile(filepath.Join(d, other), []byte("xy"), 0o600)
	s, notes, err := Open(root, relayporttest.NewManualClock(t0))
	if err != nil {
		t.Fatalf("Open = %v, want the duplicate repaired", err)
	}
	defer s.Close()
	if _, err := os.Stat(filepath.Join(d, late)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the later duplicate was kept: %v", err)
	}
	if _, err := os.Stat(filepath.Join(d, early)); err != nil {
		t.Fatalf("the earliest was removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(d, other)); err != nil {
		t.Fatalf("another sender's entry was removed: %v", err)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], late) {
		t.Fatalf("notes = %q, want one naming %s", notes, late)
	}
	if u, _ := s.Usage(context.Background(), rcptA, sndC); u.MailboxEntries != 2 || u.PairEntries != 1 || u.MailboxBytes != 3 {
		t.Fatalf("usage %+v counts the removed duplicate", u)
	}
}

// spec: SPO-Xmailbox-OUT-023
func TestOpenPrunesEmptyMailboxDirectories(t *testing.T) {
	root := newDir(t)
	os.MkdirAll(filepath.Join(root, "mailbox"), 0o700)
	for i := range mailbox.MaxAccessListParties + 5 { // more than a mailbox may hold, all empty
		var f party.Fingerprint
		f[0], f[1], f[19] = byte(i>>8), byte(i), 1
		os.Mkdir(filepath.Join(root, "mailbox", recipientName(f)), 0o700)
	}
	d := mk(t, root, recipientName(rcptA))
	os.WriteFile(filepath.Join(d, ".tmp-0123456789abcdef"), nil, 0o600) // only a crash leftover: also empty
	s, notes, err := Open(root, relayporttest.NewManualClock(t0))
	if err != nil {
		t.Fatalf("Open = %v, want the empty directories pruned", err)
	}
	defer s.Close()
	left, _ := os.ReadDir(filepath.Join(root, "mailbox"))
	if len(left) != 0 {
		t.Fatalf("%d empty mailbox directories are left", len(left))
	}
	if len(notes) != 1 || !strings.Contains(notes[0], fmt.Sprint(mailbox.MaxAccessListParties+6)) {
		t.Fatalf("notes = %q, want one counting the pruned directories", notes)
	}
}

// Over the bound with entries in them, the directories are still refused.
//
// spec: SPO-Xmailbox-SEC-005
func TestOpenStillRefusesTooManyNonEmptyMailboxes(t *testing.T) {
	root := newDir(t)
	os.MkdirAll(filepath.Join(root, "mailbox"), 0o700)
	for i := range mailbox.MaxAccessListParties + 1 {
		var f party.Fingerprint
		f[0], f[1], f[19] = byte(i>>8), byte(i), 1
		d := filepath.Join(root, "mailbox", recipientName(f))
		os.Mkdir(d, 0o700)
		os.WriteFile(filepath.Join(d, entryName(t0, mailbox.HashOf([]byte{1}), sndC)), []byte("x"), 0o600)
	}
	if _, _, err := Open(root, relayporttest.NewManualClock(t0)); !errors.Is(err, relayport.ErrMailboxCorrupt) {
		t.Fatalf("Open = %v, want ErrMailboxCorrupt", err)
	}
}

// spec: SPO-Xmailbox-SEC-006
func TestAHugeNumberOfMailboxDirectoriesIsAbandonedAtItsBound(t *testing.T) {
	root := newDir(t)
	os.MkdirAll(filepath.Join(root, "mailbox"), 0o700)
	for i := range maxRecipientNames + 1 {
		var f party.Fingerprint
		f[0], f[1], f[2], f[19] = byte(i>>16), byte(i>>8), byte(i), 2
		os.Mkdir(filepath.Join(root, "mailbox", recipientName(f)), 0o700)
	}
	if s, _, err := Open(root, relayporttest.NewManualClock(t0)); !errors.Is(err, relayport.ErrMailboxCorrupt) {
		if s != nil {
			s.Close()
		}
		t.Fatalf("Open = %v, want ErrMailboxCorrupt past %d directories", err, maxRecipientNames)
	}
}

// A rollback that cannot unlink is an error the caller sees, and the entry that
// stays on the disk is the one the store knows, so a retry is a duplicate and
// the counters match the disk.
//
// spec: SPO-Xmailbox-PRE-018
func TestAFailedRollbackIsSurfacedAndTheEntryAdopted(t *testing.T) {
	root := newDir(t)
	s := openAt(t, root, relayporttest.NewManualClock(t0))
	boom, stuck := errors.New("disk on fire"), errors.New("read-only file system")
	stepHook = func(step string) error {
		if step == stepLinked {
			return boom
		}
		return nil
	}
	unlinkat = func(dfd int, name string, flags int) error {
		if flags == 0 && !strings.HasPrefix(name, tmpPrefix) {
			return stuck // the rollback of the final name
		}
		return unix.Unlinkat(dfd, name, flags)
	}
	defer func() { stepHook, unlinkat = nil, unix.Unlinkat }()
	b := body(100, 7)
	o, err := s.Put(context.Background(), putOf(rcptA, sndC, b), bytes.NewReader(b))
	if !errors.Is(err, boom) || !errors.Is(err, stuck) || o == relayport.MailboxStored {
		t.Fatalf("Put = %v, %v; want both the step failure and the unlink failure", o, err)
	}
	stepHook, unlinkat = nil, unix.Unlinkat
	if es := listAllOf(t, s, rcptA); len(es) != 1 || es[0].Mid != mailbox.HashOf(b) {
		t.Fatalf("the entry left on the disk is not the store's: %+v", es)
	}
	if u, _ := s.Usage(context.Background(), rcptA, sndC); u.MailboxEntries != 1 || u.MailboxBytes != 100 {
		t.Fatalf("usage %+v does not match the disk", u)
	}
	if o := put(t, s, rcptA, sndC, b); o != relayport.MailboxDuplicate {
		t.Fatalf("a retry = %v, want duplicate", o)
	}
}

// ---- item 7: sweeps and revocations sync once per directory ----

// spec: SPO-Xmailbox-INV-011
func TestSweepSyncsOncePerMailboxDirectory(t *testing.T) {
	root := newDir(t)
	clk := relayporttest.NewManualClock(t0)
	s := openAt(t, root, clk)
	for i := range 6 {
		put(t, s, rcptA, sndC, body(20+i, byte(i)))
	}
	for i := range 3 {
		put(t, s, rcptB, sndC, body(20+i, byte(50+i)))
	}
	clk.Advance(1000 * time.Second)
	keep := body(30, 99)
	put(t, s, rcptA, sndC, keep)
	var dirSyncs, fileSyncs int
	syncFd = func(fd int) error {
		var st unix.Stat_t
		unix.Fstat(fd, &st)
		if st.Mode&unix.S_IFMT == unix.S_IFDIR {
			dirSyncs++
		} else {
			fileSyncs++
		}
		return unix.Fsync(fd)
	}
	defer func() { syncFd = unix.Fsync }()
	n, err := s.Sweep(context.Background(), 500) // A: 6 of 7 due, B: 3 of 3 due
	if err != nil || n != 9 {
		t.Fatalf("Sweep = %d, %v", n, err)
	}
	// A: one sync of its directory. B: one sync, then its emptied directory is
	// removed and the mailbox directory synced once.
	if dirSyncs != 3 || fileSyncs != 0 {
		t.Fatalf("Sweep of 9 entries in 2 directories did %d directory syncs and %d file syncs, want 3 and 0", dirSyncs, fileSyncs)
	}
	if es := entries(t, s, rcptA); len(es) != 1 || es[0].Mid != mailbox.HashOf(keep) {
		t.Fatalf("A lists %+v", es)
	}
}

// spec: SPO-Xmailbox-INV-011
func TestRemoveMailboxSyncsOncePerDirectory(t *testing.T) {
	s := openAt(t, newDir(t), relayporttest.NewManualClock(t0))
	for i := range 5 {
		put(t, s, rcptA, sndC, body(20+i, byte(i)))
	}
	var dirSyncs int
	syncFd = func(fd int) error {
		var st unix.Stat_t
		unix.Fstat(fd, &st)
		if st.Mode&unix.S_IFMT == unix.S_IFDIR {
			dirSyncs++
		}
		return unix.Fsync(fd)
	}
	defer func() { syncFd = unix.Fsync }()
	if n, err := s.RemoveMailbox(context.Background(), rcptA); err != nil || n != 5 {
		t.Fatalf("RemoveMailbox = %d, %v", n, err)
	}
	if dirSyncs != 2 { // the mailbox's directory once, the parent once for the removal
		t.Fatalf("RemoveMailbox of 5 entries did %d directory syncs, want 2", dirSyncs)
	}
}

// Between two mailboxes a sweep holds no lock, so a reader is not stalled for
// the whole sweep.
//
// spec: SPO-Xmailbox-INV-011
func TestSweepReleasesTheLockBetweenMailboxes(t *testing.T) {
	s := openAt(t, newDir(t), relayporttest.NewManualClock(t0))
	for i, r := range []party.Fingerprint{rcptA, rcptB, fp(0xE5)} {
		put(t, s, r, sndC, body(20, byte(i)))
	}
	s.clock.(*relayporttest.ManualClock).Advance(1000 * time.Second)
	reached := 0
	stepHook = func(step string) error {
		if step != stepRecipientDone {
			return nil
		}
		reached++
		done := make(chan struct{})
		go func() { s.Usage(context.Background(), rcptA, sndC); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("a sweep held the store's lock between two mailboxes")
		}
		return nil
	}
	defer func() { stepHook = nil }()
	if n, err := s.Sweep(context.Background(), 500); err != nil || n != 3 {
		t.Fatalf("Sweep = %d, %v", n, err)
	}
	if reached != 3 {
		t.Fatalf("the hook between mailboxes ran %d times, want 3", reached)
	}
}

// ---- item 8: the duplicate decision is per sender ----

// spec: SPO-Xmailbox-OUT-021
func TestASecondSenderPuttingTheSameBytesGetsItsOwnEntry(t *testing.T) {
	root := newDir(t)
	clk := relayporttest.NewManualClock(t0)
	s := openAt(t, root, clk)
	b := body(100, 8)
	if o := put(t, s, rcptA, sndC, b); o != relayport.MailboxStored {
		t.Fatal(o)
	}
	other := fp(0xD4)
	if o := put(t, s, rcptA, other, b); o != relayport.MailboxStored {
		t.Fatalf("the same bytes from another sender = %v, want stored (a duplicate answer would tell it the bytes exist)", o)
	}
	es := entries(t, s, rcptA)
	if len(es) != 1 || es[0].Sender != sndC {
		t.Fatalf("entries = %+v, want the one message, as its first copy", es)
	}
	if names, _ := filepath.Glob(filepath.Join(root, "mailbox", "*", "0*")); len(names) != 2 {
		t.Fatalf("%d copies on disk, want 2", len(names))
	}
	if u, _ := s.Usage(context.Background(), rcptA, other); u.PairEntries != 1 || u.PairBytes != 100 || u.SenderBytes != 100 || u.MailboxEntries != 2 {
		t.Fatalf("usage = %+v: the second sender is charged for its own entry only", u)
	}
	// the same sender again is a duplicate
	if o := put(t, s, rcptA, other, b); o != relayport.MailboxDuplicate {
		t.Fatalf("the same sender again = %v", o)
	}
	// the recipient's ack of the id removes both copies: they are one message
	if ok, err := s.Remove(context.Background(), rcptA, mailbox.HashOf(b)); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if es := entries(t, s, rcptA); len(es) != 0 {
		t.Fatalf("an ack left %+v", es)
	}
	if u, _ := s.Usage(context.Background(), rcptA, other); u != (mailbox.Usage{}) {
		t.Fatalf("usage after the ack = %+v", u)
	}
}

// spec: SPO-Xmailbox-OUT-021
func TestTwoSendersPuttingTheSameBytesAtOnceAreNotBusy(t *testing.T) {
	s := openAt(t, newDir(t), relayporttest.NewManualClock(t0))
	b := body(100, 9)
	gate := make(chan struct{})
	started := make(chan struct{})
	r := &gatedReader{r: bytes.NewReader(b), gate: gate, started: started}
	done := make(chan relayport.MailboxOutcome, 1)
	go func() {
		o, _ := s.Put(context.Background(), putOf(rcptA, sndC, b), r)
		done <- o
	}()
	<-started
	if o := put(t, s, rcptA, fp(0xD4), b); o != relayport.MailboxStored {
		t.Fatalf("a second sender while the first is in flight = %v, want stored (busy would tell it a put is under way)", o)
	}
	if o := put(t, s, rcptA, sndC, b); o != relayport.MailboxBusy {
		t.Fatalf("the same sender while its put is in flight = %v, want busy", o)
	}
	close(gate)
	if o := <-done; o != relayport.MailboxStored {
		t.Fatalf("the first put = %v", o)
	}
}

type gatedReader struct {
	r       io.Reader
	gate    chan struct{}
	started chan struct{}
	once    sync.Once
}

func (g *gatedReader) Read(p []byte) (int, error) {
	g.once.Do(func() { close(g.started); <-g.gate })
	return g.r.Read(p)
}

// ---- item 10: the owner checks ----

// spec: SPO-Xmailbox-SEC-017
func TestEveryOwnerCheckRefusesAnotherUser(t *testing.T) {
	build := func(t *testing.T) string {
		root := newDir(t)
		d := mk(t, root, recipientName(rcptA))
		os.WriteFile(filepath.Join(d, entryName(t0, mailbox.HashOf([]byte("m")), sndC)), []byte("x"), 0o600)
		os.WriteFile(filepath.Join(d, ".tmp-0123456789abcdef"), []byte("x"), 0o600)
		return root
	}
	real := os.Geteuid()
	defer func() { geteuid = os.Geteuid }()
	// count the checks of a good open
	calls := 0
	geteuid = func() int { calls++; return real }
	s, _, err := Open(build(t), relayporttest.NewManualClock(t0))
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	want := []string{"directory", "lock file", "\"mailbox\"", "is not owned", "is not owned", "is not owned"}
	if calls != len(want) {
		t.Fatalf("a fixture with a root, a lock file, mailbox/, one mailbox, one entry and one temporary file has %d owner checks, want %d", calls, len(want))
	}
	for k := 1; k <= calls; k++ {
		t.Run(fmt.Sprintf("check %d", k), func(t *testing.T) {
			n := 0
			geteuid = func() int {
				n++
				if n == k {
					return real + 1
				}
				return real
			}
			s, _, err := Open(build(t), relayporttest.NewManualClock(t0))
			if err == nil {
				s.Close()
				t.Fatal("Open accepted a file owned by someone else")
			}
			if !strings.Contains(err.Error(), "owned") && !errors.Is(err, relayport.ErrMailboxCorrupt) {
				t.Fatalf("Open = %v, want a refusal that names ownership", err)
			}
		})
	}
}

// ---- item 11: a clock that steps back does not reorder a mailbox ----

// spec: SPO-Xmailbox-OUT-022
func TestAClockStepBackDoesNotMakeAnEntryListEarlier(t *testing.T) {
	root := newDir(t)
	clk := relayporttest.NewManualClock(t0 + 100)
	s := openAt(t, root, clk)
	// the first entry has the larger id, the second (arriving later) the smaller
	b1, b2 := body(50, 1), body(60, 2)
	if h1, h2 := mailbox.HashOf(b1), mailbox.HashOf(b2); slices.Compare(h1[:], h2[:]) < 0 {
		b1, b2 = b2, b1
	}
	put(t, s, rcptA, sndC, b1)
	first := mailbox.HashOf(b1)
	clk.Advance(-90 * time.Second) // the clock steps back
	put(t, s, rcptA, sndC, b2)
	es := entries(t, s, rcptA)
	if len(es) != 2 || es[0].Mid != first || es[1].Mid != mailbox.HashOf(b2) {
		t.Fatalf("entries = %+v, want the arrival order", es)
	}
	if es[1].Arrival < es[0].Arrival {
		t.Fatalf("a later arrival is stamped %d, before the entry it followed (%d)", es[1].Arrival, es[0].Arrival)
	}
	// a client that has read the first entry and asks for what follows gets the second
	page, _, err := s.List(context.Background(), rcptA, &first, 8)
	if err != nil || len(page) != 1 || page[0].Mid != mailbox.HashOf(b2) {
		t.Fatalf("after the first entry: %+v, %v", page, err)
	}
	// the stamp is in the name, so the order survives a reopen
	s.Close()
	s2 := openAt(t, root, clk)
	if es := entries(t, s2, rcptA); len(es) != 2 || es[0].Mid != first || es[1].Arrival != t0+101 {
		t.Fatalf("after reopen: %+v", es)
	}
}

// Two entries that arrive in one second list in the order they were stored,
// whatever their ids, so a cursor never skips the later one.
//
// spec: SPO-Xmailbox-OUT-022
func TestEntriesOfOneSecondListInStoredOrder(t *testing.T) {
	s := openAt(t, newDir(t), relayporttest.NewManualClock(t0))
	var bodies [][]byte
	for i := range 12 {
		bodies = append(bodies, body(40+i, byte(i*17+1)))
	}
	for _, b := range bodies {
		put(t, s, rcptA, sndC, b)
	}
	es := entries(t, s, rcptA)
	for i, e := range es {
		if e.Mid != mailbox.HashOf(bodies[i]) {
			t.Fatalf("entry %d is not the %dth stored", i, i)
		}
	}
	// paging one at a time reaches all of them
	var got int
	var after *mailbox.Hash
	for range 20 {
		page, more, _ := s.List(context.Background(), rcptA, after, 1)
		got += len(page)
		if !more {
			break
		}
		a := page[0].Mid
		after = &a
	}
	if got != 12 {
		t.Fatalf("paging reached %d of 12", got)
	}
}

// A Close that comes between the body and the link stops the put: nothing is
// linked after the lock is released.
//
// spec: SPO-Xmailbox-INV-010
func TestACloseBetweenTheBodyAndTheLinkStopsThePut(t *testing.T) {
	root := newDir(t)
	s := openAt(t, root, relayporttest.NewManualClock(t0))
	stepHook = func(step string) error {
		if step == stepBodySynced {
			stepHook = nil
			s.Close()
		}
		return nil
	}
	defer func() { stepHook = nil }()
	b := body(100, 7)
	o, err := s.Put(context.Background(), putOf(rcptA, sndC, b), bytes.NewReader(b))
	if !errors.Is(err, relayport.ErrMailboxClosed) || o == relayport.MailboxStored {
		t.Fatalf("Put across Close = %v, %v; want ErrMailboxClosed", o, err)
	}
	for _, l := range tree(t, root) {
		if strings.Contains(l, "0000") || strings.Contains(l, tmpPrefix) {
			t.Fatalf("a put after Close left %s", l)
		}
	}
}

// An entry that arrived "from the far future" (a planted name, or a clock that
// once ran ahead) does not drag the arrival of new entries with it.
//
// spec: SPO-Xmailbox-OUT-022, SPO-Xmailbox-SEC-015
func TestTheClampIgnoresArrivalsBeyondTheRange(t *testing.T) {
	root := newDir(t)
	clk := relayporttest.NewManualClock(t0)
	s := openAt(t, root, clk)
	first := body(10, 1)
	put(t, s, rcptA, sndC, first)
	s.Close()
	names, _ := filepath.Glob(filepath.Join(root, "mailbox", "*", "*"))
	base := filepath.Base(names[0])
	os.Rename(names[0], filepath.Join(filepath.Dir(names[0]), "09223372036854775807"+base[20:]))
	s2 := openAt(t, root, clk)
	second := body(20, 2)
	put(t, s2, rcptA, sndC, second)
	for _, e := range entries(t, s2, rcptA) {
		if e.Mid == mailbox.HashOf(second) && e.Arrival != t0 {
			t.Fatalf("a new entry was stamped %d, want the clock %d: an entry beyond the range set it", e.Arrival, t0)
		}
	}
}
