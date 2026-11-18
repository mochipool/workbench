package mailbox_test

import (
	"math"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
)

// spec: SPO-Xmailbox-OUT-010
func TestClampRetention(t *testing.T) {
	cases := []struct {
		in, want uint64
		bad      bool
	}{
		{0, 0, true},
		{1, 1, false},
		{mailbox.DefaultRetentionSeconds, mailbox.DefaultRetentionSeconds, false},
		{mailbox.MaxRetentionSeconds - 1, mailbox.MaxRetentionSeconds - 1, false},
		{mailbox.MaxRetentionSeconds, mailbox.MaxRetentionSeconds, false},
		{mailbox.MaxRetentionSeconds + 1, mailbox.MaxRetentionSeconds, false},
		{math.MaxUint64, mailbox.MaxRetentionSeconds, false},
	}
	for _, c := range cases {
		got, err := mailbox.ClampRetention(c.in)
		if (err != nil) != c.bad || got != c.want {
			t.Errorf("%d: %d, %v", c.in, got, err)
		}
	}
}

// An entry is expired once its age reaches the retention.
//
// spec: SPO-Xmailbox-OUT-010
func TestExpiredBoundary(t *testing.T) {
	const arrival, ret = 1000, 60
	cases := []struct {
		now  int64
		want bool
	}{
		{999, false}, {1000, false}, {1059, false}, {1060, true}, {1061, true}, {1 << 62, true},
	}
	for _, c := range cases {
		if got := mailbox.Expired(arrival, c.now, ret); got != c.want {
			t.Errorf("now %d: %v", c.now, got)
		}
	}
}

// spec: SPO-Xmailbox-OUT-010, SPO-Xmailbox-SEC-004
func TestExpiredEdgesAndOverflow(t *testing.T) {
	if !mailbox.Expired(-1, 0, 60) || !mailbox.Expired(math.MinInt64, math.MaxInt64, 60) || !mailbox.Expired(math.MinInt64, 0, mailbox.MaxRetentionSeconds) {
		t.Error("a negative arrival time must be swept, without wrapping")
	}
	if mailbox.Expired(0, math.MaxInt64, mailbox.MaxRetentionSeconds) != true {
		t.Error("old entry")
	}
	if mailbox.Expired(1000+60, 1000, 60) || mailbox.Expired(1000+int64(mailbox.MaxRetentionSeconds), 1000, 60) {
		t.Error("an arrival up to the maximum retention ahead (the clock went back) is not expired")
	}
	if mailbox.Expired(mailbox.MaxTime, mailbox.MaxTime, 60) || mailbox.Expired(mailbox.MaxTime, mailbox.MaxTime-1, 60) {
		t.Error("the top of the time range, with a clock that agrees, is not expired")
	}
	if !mailbox.Expired(math.MaxInt64-1, math.MaxInt64, 60) || !mailbox.Expired(mailbox.MaxTime+1, mailbox.MaxTime+1, 60) {
		t.Error("an arrival above the time bound is expired whatever the clock says")
	}
	// A retention of zero fails closed.
	if !mailbox.Expired(100, 100, 0) || !mailbox.Expired(200, 100, 0) {
		t.Error("zero retention fails closed, even for an arrival in the future")
	}
	// Retention never extends beyond the maximum.
	a := int64(5000)
	for _, d := range []int64{-1, 0, 1, 100, int64(mailbox.MaxRetentionSeconds) - 1, int64(mailbox.MaxRetentionSeconds), int64(mailbox.MaxRetentionSeconds) + 1} {
		now := a + d
		for _, r := range []uint64{mailbox.MaxRetentionSeconds + 1, math.MaxUint64} {
			if got, want := mailbox.Expired(a, now, r), mailbox.Expired(a, now, mailbox.MaxRetentionSeconds); got != want {
				t.Errorf("retention %d at +%d: %v, clamped gives %v", r, d, got, want)
			}
		}
	}
	if !mailbox.Expired(a, a+int64(mailbox.MaxRetentionSeconds), math.MaxUint64) {
		t.Error("30 days")
	}
	if mailbox.Expired(a, a+int64(mailbox.MaxRetentionSeconds)-1, math.MaxUint64) {
		t.Error("30 days less a second")
	}
}

// spec: SPO-Xmailbox-OUT-010
func TestExpiresAt(t *testing.T) {
	got, err := mailbox.ExpiresAt(1000, 60)
	if err != nil || got != 1060 {
		t.Errorf("%d, %v", got, err)
	}
	if got, _ := mailbox.ExpiresAt(1000, math.MaxUint64); got != 1000+int64(mailbox.MaxRetentionSeconds) {
		t.Errorf("clamped: %d", got)
	}
	if got, err := mailbox.ExpiresAt(mailbox.MaxTime, math.MaxUint64); err != nil || got != mailbox.MaxTime+int64(mailbox.MaxRetentionSeconds) {
		t.Errorf("the top of the range: %d, %v", got, err)
	}
	for _, c := range []struct {
		a int64
		r uint64
	}{{-1, 60}, {0, 0}, {mailbox.MaxTime + 1, 60}, {math.MaxInt64 - 5, 60}, {math.MaxInt64, 60}} {
		if _, err := mailbox.ExpiresAt(c.a, c.r); err == nil {
			t.Errorf("%v accepted", c)
		}
	}
	// Agreement with Expired.
	for _, now := range []int64{1059, 1060, 1061} {
		e, _ := mailbox.ExpiresAt(1000, 60)
		if mailbox.Expired(1000, now, 60) != (now >= e) {
			t.Errorf("now %d disagrees", now)
		}
	}
}

// A far-future arrival (a clock that jumped ahead and came back, or a planted
// name) must not hold quota for ever: it expires once it is more than the
// maximum retention ahead of now. The arithmetic is exact with a negative or
// extreme now.
//
// spec: SPO-Xmailbox-OUT-010, SPO-Xmailbox-SEC-004, SPO-Xmailbox-SEC-015
func TestExpiredFarFuture(t *testing.T) {
	const max = int64(mailbox.MaxRetentionSeconds)
	for _, c := range []struct {
		name         string
		arrival, now int64
		want         bool
	}{
		{"exactly the maximum ahead", 5000 + max, 5000, false},
		{"one second beyond", 5000 + max + 1, 5000, true},
		{"far ahead", mailbox.MaxTime, 1000, true},
		{"far ahead, any retention", mailbox.MaxTime, 0, true},
		{"negative now, near", 10, -10, false},
		{"negative now, beyond", max - 9, -10, true},
		{"negative now, exactly", max - 10, -10, false},
		{"min now", 0, math.MinInt64, true},
		{"min now, top arrival", mailbox.MaxTime, math.MinInt64, true},
		{"max now, old arrival", 0, math.MaxInt64, true},
	} {
		for _, r := range []uint64{60, mailbox.MaxRetentionSeconds, math.MaxUint64} {
			if got := mailbox.Expired(c.arrival, c.now, r); got != c.want {
				t.Errorf("%s (retention %d): %v, want %v", c.name, r, got, c.want)
			}
		}
	}
}

// Expired and ExpiresAt agree for every arrival that is not in the future, on
// a grid that includes both ends of the range ExpiresAt accepts, and ExpiresAt
// refuses exactly the arrivals that Expired treats as expired by range.
//
// spec: SPO-Xmailbox-OUT-010
func TestExpiredAndExpiresAtAgree(t *testing.T) {
	for _, a := range []int64{0, 1, 1000, mailbox.MaxTime - 1, mailbox.MaxTime} {
		for _, r := range []uint64{1, 60, mailbox.MaxRetentionSeconds, math.MaxUint64} {
			e, err := mailbox.ExpiresAt(a, r)
			if err != nil {
				t.Fatalf("arrival %d retention %d: %v", a, r, err)
			}
			for _, now := range []int64{a, a + 1, e - 1, e, e + 1, math.MaxInt64} {
				if now < a {
					continue
				}
				if got, want := mailbox.Expired(a, now, r), now >= e; got != want {
					t.Errorf("arrival %d retention %d now %d: Expired %v, ExpiresAt %d", a, r, now, got, e)
				}
			}
		}
	}
	for _, a := range []int64{-1, mailbox.MaxTime + 1, math.MaxInt64} {
		if _, err := mailbox.ExpiresAt(a, 60); err == nil {
			t.Errorf("ExpiresAt accepted %d", a)
		}
		if !mailbox.Expired(a, a, 60) || !mailbox.Expired(a, 0, 60) {
			t.Errorf("Expired did not expire %d", a)
		}
	}
}
