package mailbox_test

import (
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
)

// The relay's clock is untrusted: Skew is exact, never negative and saturates
// instead of wrapping, at both ends of the int64 range.
//
// spec: SPO-Xmailbox-SEC-013
func TestSkew(t *testing.T) {
	const max, min = int64(1<<63 - 1), int64(-1 << 63)
	for _, c := range []struct{ relay, now, want int64 }{
		{100, 100, 0}, {100, 40, 60}, {40, 100, 60}, {0, 0, 0},
		{mailbox.MaxTime, 0, mailbox.MaxTime}, {0, mailbox.MaxTime, mailbox.MaxTime},
		{mailbox.MaxTime, -1, mailbox.MaxTime + 1},
		{0, max, max}, {max, 0, max}, {1, max, max - 1},
		{0, min, max}, {mailbox.MaxTime, min, max}, {min, mailbox.MaxTime, max},
		{max, min, max}, {min, max, max}, {-1, max, max}, {max, -1, max},
		{-5, -9, 4}, {-9, -5, 4},
	} {
		if got := mailbox.Skew(c.relay, c.now); got != c.want {
			t.Errorf("Skew(%d, %d) = %d, want %d", c.relay, c.now, got, c.want)
		}
	}
	if mailbox.ClockSkewWarningSeconds != 300 {
		t.Errorf("warning threshold %d seconds", mailbox.ClockSkewWarningSeconds)
	}
}
