package sqlitestore

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/layoutdir"
	"github.com/mochipool/workbench/spo/internal/app/layoutread"
	"github.com/mochipool/workbench/spo/internal/domain/layout"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func vmHWM() string {
	b, _ := os.ReadFile("/proc/self/status")
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "VmHWM") {
			return strings.TrimSpace(strings.TrimPrefix(l, "VmHWM:"))
		}
	}
	return "?"
}

// peakHeap samples the heap in use while f runs.
func peakHeap(f func()) (peak uint64, took time.Duration) {
	var stop atomic.Bool
	done := make(chan uint64)
	go func() {
		var max uint64
		var ms runtime.MemStats
		for !stop.Load() {
			runtime.ReadMemStats(&ms)
			if ms.HeapInuse > max {
				max = ms.HeapInuse
			}
			time.Sleep(10 * time.Millisecond)
		}
		done <- max
	}()
	start := time.Now()
	f()
	took = time.Since(start)
	stop.Store(true)
	return <-done, took
}

// The measurement of the stated bounds on a real layout with 50,000 audit rows and
// 200 records. It is slow (50,000 store writes) and is skipped unless SPO_MEASURE=1:
//
//	SPO_MEASURE=1 go test -v -count=1 -run TestMeasureLargeLayout ./internal/adapters/sqlitestore/
//
// spec: SPO-Xlayout-INV-024
func TestMeasureLargeLayout(t *testing.T) {
	if os.Getenv("SPO_MEASURE") != "1" {
		t.Skip("set SPO_MEASURE=1 to measure a layout with 50,000 audit rows")
	}
	s, path, rec := scratch(t)
	for i := 0; i < 200; i++ {
		put(t, s, rf(fmt.Sprintf("rec%d", i), ports.AddrVKey), "v")
	}
	for n := count(t, s, "audit"); n < 50_000; n++ {
		put(t, s, rf("rec0", ports.AddrVKey), fmt.Sprintf("v%d", n))
	}
	rows := count(t, s, "audit")
	s.Close()
	f := stdFix("measure", path, testPass, rec)

	var un *layoutread.Unlocked
	var lr *layoutread.Locked
	var root string
	exportPeak, exportTook := peakHeap(func() { _, root, _, _ = exportFixture(t, f) })
	t.Logf("export: %d audit rows, peak heap %d MiB, %s", rows, exportPeak>>20, exportTook)
	// read it back
	rd, err := openLayoutRead(t, root, path)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := newestHeadOf(t, root)
	pin, _ := layoutread.ParsePin(h)
	runtime.GC()
	lockedPeak, lockedTook := peakHeap(func() {
		lr, err = layoutread.CheckLocked(context.Background(), layoutread.LockedInput{Reader: rd, Pin: pin, Tables: realTables{}})
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("locked pass: peak heap %d MiB, %s", lockedPeak>>20, lockedTook)
	runtime.GC()
	unlockedPeak, unlockedTook := peakHeap(func() {
		un, err = layoutread.CheckUnlocked(context.Background(), layoutread.UnlockedInput{Reader: rd, Locked: lr, Keys: realKeys{f.cred}})
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("unlocked pass: %d objects, %d bytes, peak heap %d MiB, %s", un.Objects, un.Bytes, unlockedPeak>>20, unlockedTook)
	scratchPath := filepath.Join(t.TempDir(), "scratch.spo")
	writePeak, writeTook := peakHeap(func() { err = WriteLayoutFile(context.Background(), scratchPath, un.Snapshot, f.cred()) })
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("scratch file (full verification): peak heap %d MiB, %s", writePeak>>20, writeTook)
	t.Logf("process VmHWM at the end: %s", vmHWM())
}

func openLayoutRead(t *testing.T, root, wsFile string) (*layoutdir.Dir, error) {
	t.Helper()
	return layoutdir.OpenExisting(root, wsFile)
}

// newestHeadOf is the exact pin of the newest head in a layout directory.
func newestHeadOf(t *testing.T, root string) (string, uint64) {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(root, "heads"))
	if err != nil {
		t.Fatal(err)
	}
	var best string
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".sig") && e.Name() > best {
			best = e.Name()
		}
	}
	note, err := os.ReadFile(filepath.Join(root, "heads", best))
	if err != nil {
		t.Fatal(err)
	}
	hd, err := layout.ParseHead(note)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x:layout:%d:%x", hd.Workspace, hd.Sequence, layout.HeadHash(note)), hd.Sequence
}
