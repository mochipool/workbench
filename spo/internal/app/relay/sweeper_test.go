package relay_test

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailboxstore"
	"github.com/mochipool/workbench/spo/internal/app/relay"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

type sweepRig struct {
	clock *relayporttest.ManualClock
	st    *mailboxstore.Store
	ev    *events
}

func newSweepRig(t *testing.T) *sweepRig {
	t.Helper()
	clock := relayporttest.NewManualClock(1_700_000_000)
	st, _, err := mailboxstore.Open(t.TempDir(), clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return &sweepRig{clock: clock, st: st, ev: &events{}}
}

// store puts one entry at the clock's present.
func (s *sweepRig) store(t *testing.T, rcpt party.Fingerprint, tag byte) {
	t.Helper()
	q, _ := mailbox.DefaultQuota().Validated(3)
	env := envelope(60, tag)
	out, err := s.st.Put(context.Background(), relayport.MailboxPut{Recipient: rcpt, Sender: party.Fingerprint{9}, Mid: mailbox.HashOf(env), Size: 60, Quota: q}, bytes.NewReader(env))
	if err != nil || out != relayport.MailboxStored {
		t.Fatalf("put: %v %v", out, err)
	}
}

func (s *sweepRig) count(t *testing.T, rcpt party.Fingerprint) int {
	es, _, err := s.st.List(context.Background(), rcpt, nil, mailbox.MaxMailboxEntries)
	if err != nil {
		t.Fatal(err)
	}
	return len(es)
}

// The sweep deletes exactly the entries whose age has reached the retention,
// measured from arrival, and says how many.
//
// spec: SPO-Xmailbox-OUT-030
func TestSweeperDeletesExactlyTheExpired(t *testing.T) {
	s := newSweepRig(t)
	rcpt := party.Fingerprint{1}
	s.store(t, rcpt, 1) // arrival T
	s.clock.Advance(50 * time.Second)
	s.store(t, rcpt, 2) // T+50
	s.clock.Advance(49 * time.Second)
	s.store(t, rcpt, 3) // T+99
	sw, err := relay.NewSweeper(s.st, s.clock, 100, s.ev.sink)
	if err != nil {
		t.Fatal(err)
	}
	s.clock.Advance(time.Second) // now T+100: the first is exactly at the retention
	n, err := sw.Sweep(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("swept %d, %v; want 1", n, err)
	}
	if got := s.count(t, rcpt); got != 2 {
		t.Fatalf("%d entries left, want 2", got)
	}
	s.clock.Advance(50 * time.Second) // T+150: the second is 100 old, the third 51
	if n, err := sw.Sweep(context.Background()); err != nil || n != 1 {
		t.Fatalf("swept %d, %v; want 1", n, err)
	}
	if n, _ := sw.Sweep(context.Background()); n != 0 {
		t.Fatalf("a sweep with nothing due removed %d", n)
	}
	ev := s.ev.of(relay.EventSweep)
	if len(ev) != 3 || ev[0].Count != 1 || ev[1].Count != 1 || ev[2].Count != 0 || ev[0].Time.Unix() != s.clock.Now().Unix()-50 {
		t.Fatalf("events %+v", ev)
	}
}

// The retention is refused at zero and never beyond 30 days.
//
// spec: SPO-Xmailbox-OUT-030
func TestSweeperRetentionIsClamped(t *testing.T) {
	s := newSweepRig(t)
	if _, err := relay.NewSweeper(s.st, s.clock, 0, nil); err == nil {
		t.Error("a retention of zero was accepted")
	}
	if _, err := relay.NewSweeper(nil, s.clock, 10, nil); err == nil {
		t.Error("no expirer was accepted")
	}
	if _, err := relay.NewSweeper(s.st, nil, 10, nil); err == nil {
		t.Error("no clock was accepted")
	}
	rcpt := party.Fingerprint{2}
	s.store(t, rcpt, 1)
	sw, err := relay.NewSweeper(s.st, s.clock, 100*24*3600, nil) // 100 days asked
	if err != nil {
		t.Fatal(err)
	}
	s.clock.Advance(29 * 24 * time.Hour)
	if n, _ := sw.Sweep(context.Background()); n != 0 {
		t.Fatal("an entry of 29 days was swept")
	}
	s.clock.Advance(24 * time.Hour)
	if n, _ := sw.Sweep(context.Background()); n != 1 {
		t.Fatal("an entry of 30 days survived a retention asked at 100")
	}
}

type recordingExpirer struct{ got []uint64 }

func (r *recordingExpirer) Sweep(_ context.Context, retention uint64) (int, error) {
	r.got = append(r.got, retention)
	return 0, nil
}

// The retention the expirer is given is the clamped one, whatever the expirer
// does with it.
//
// spec: SPO-Xmailbox-OUT-030
func TestSweeperPassesTheClampedRetention(t *testing.T) {
	rec := &recordingExpirer{}
	clock := relayporttest.NewManualClock(5)
	for _, tc := range []struct{ asked, want uint64 }{
		{1, 1}, {3600, 3600}, {mailbox.MaxRetentionSeconds, mailbox.MaxRetentionSeconds}, {mailbox.MaxRetentionSeconds + 1, mailbox.MaxRetentionSeconds}, {1 << 62, mailbox.MaxRetentionSeconds},
	} {
		sw, err := relay.NewSweeper(rec, clock, tc.asked, nil)
		if err != nil {
			t.Fatal(err)
		}
		sw.Sweep(context.Background())
		if got := rec.got[len(rec.got)-1]; got != tc.want {
			t.Errorf("asked %d: the expirer was given %d, want %d", tc.asked, got, tc.want)
		}
	}
}

// The sweeper takes the expirer capability and a clock and nothing else.
//
// spec: SPO-Xmailbox-OUT-030, SPO-Xmailbox-IF-005
func TestSweeperTakesOnlyTheExpirerAndAClock(t *testing.T) {
	ft := reflect.TypeOf(relay.NewSweeper)
	exp := ft.In(0)
	if exp.Kind() != reflect.Interface || exp.NumMethod() != 1 {
		t.Fatalf("the first parameter is %s", exp)
	}
	if _, ok := exp.MethodByName("Sweep"); !ok {
		t.Fatalf("the first parameter is %s", exp)
	}
	if ft.In(1) != reflect.TypeFor[relayport.Clock]() {
		t.Fatalf("the second parameter is %s", ft.In(1))
	}
}

type failingExpirer struct{ calls int }

func (f *failingExpirer) Sweep(context.Context, uint64) (int, error) {
	f.calls++
	return 0, errors.New("/secret/dir: disk gone")
}

// A failed sweep is returned and logged with no text of the error.
//
// spec: SPO-Xmailbox-OUT-030, SPO-Xmailbox-IF-006
func TestSweepFailureIsAnEventWithoutDetail(t *testing.T) {
	ev := &events{}
	clock := relayporttest.NewManualClock(5)
	sw, _ := relay.NewSweeper(&failingExpirer{}, clock, 10, ev.sink)
	if _, err := sw.Sweep(context.Background()); err == nil {
		t.Fatal("no error")
	}
	got := ev.of(relay.EventSweepErr)
	if len(got) != 1 || got[0].Reason != relay.ReasonStore {
		t.Fatalf("events %+v", ev.all())
	}
}

// Run sweeps on an interval and stops with its context, leaving no goroutine.
//
// spec: SPO-Xmailbox-OUT-030, SPO-Xmailbox-INV-013
func TestSweeperRunsOnAnIntervalAndStops(t *testing.T) {
	fakenet.CheckLeaks(t)
	s := newSweepRig(t)
	rcpt := party.Fingerprint{3}
	s.store(t, rcpt, 1)
	sw, _ := relay.NewSweeper(s.st, s.clock, 60, s.ev.sink)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	var runErr error
	wg.Add(1)
	go func() { defer wg.Done(); runErr = sw.Run(ctx, 10*time.Millisecond) }()
	s.clock.Advance(2 * time.Minute)
	eventually(t, "the entry to be swept", func() bool { return s.count(t, rcpt) == 0 })
	cancel()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not stop")
	}
	if !errors.Is(runErr, context.Canceled) {
		t.Fatalf("Run returned %v", runErr)
	}
	if err := sw.Run(context.Background(), 0); err == nil {
		t.Fatal("an interval of zero was accepted")
	}
}
