package relaybinding

import (
	"math"
	"testing"
	"time"
)

// The duration arithmetic is clamped: the unchecked product of 2.5e11 seconds
// wraps to a negative Duration, which a caller that sleeps would not wait for.
//
// spec: SPO-Xrelaybind-PRE-022
func TestWaitDurationClamps(t *testing.T) {
	const most = math.MaxInt64 / int64(time.Second)
	for sec, want := range map[int64]time.Duration{
		-5: 0, 0: 0, 1: time.Second, 301: 301 * time.Second,
		most:                 time.Duration(most) * time.Second,
		most + 1:             time.Duration(math.MaxInt64),
		253402300799:         time.Duration(math.MaxInt64), // the largest statement time
		math.MaxInt64:        time.Duration(math.MaxInt64),
		int64(math.MinInt64): 0,
	} {
		if got := waitDuration(sec); got != want || got < 0 {
			t.Errorf("waitDuration(%d) = %v, want %v", sec, got, want)
		}
	}
}
