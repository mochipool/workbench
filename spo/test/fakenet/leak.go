package fakenet

import (
	"runtime"
	"testing"
	"time"
)

// CheckLeaks records the number of goroutines now and, at the end of the test,
// fails it if more are still running after a short grace period. Start it
// before the test starts anything, and let the test wait for what it starts.
func CheckLeaks(t testing.TB) {
	t.Helper()
	before := runtime.NumGoroutine()
	t.Cleanup(func() {
		deadline := time.Now().Add(2 * time.Second)
		for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if n := runtime.NumGoroutine(); n > before {
			buf := make([]byte, 1<<16)
			buf = buf[:runtime.Stack(buf, true)]
			t.Errorf("%d goroutines were running at the start, %d are at the end:\n%s", before, n, buf)
		}
	})
}
