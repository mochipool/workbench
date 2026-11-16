package secret

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

func TestTakeWipesSource(t *testing.T) {
	src := []byte("5820aabbccddeeff")
	s := Take(src)
	defer s.Destroy()
	if !bytes.Equal(src, make([]byte, len(src))) {
		t.Fatal("source was not wiped")
	}
	var got []byte
	if err := s.Use(func(b []byte) error { got = append(got, b...); return nil }); err != nil {
		t.Fatal(err)
	}
	if string(got) != "5820aabbccddeeff" {
		t.Fatalf("content changed: %q", got)
	}
}

// E8: a secret must not leak through formatting or serialisation.
func TestNeverPrintsOrSerialises(t *testing.T) {
	s := Take([]byte("topsecretkey"))
	defer s.Destroy()
	for _, out := range []string{
		fmt.Sprint(s), fmt.Sprintf("%v", s), fmt.Sprintf("%+v", s), fmt.Sprintf("%#v", s), fmt.Sprintf("%s", s),
	} {
		if strings.Contains(out, "topsecret") {
			t.Fatalf("leaked through formatting: %q", out)
		}
	}
	if _, err := json.Marshal(s); err == nil {
		t.Fatal("JSON serialisation of a secret succeeded")
	}
}

func TestUseAfterDestroy(t *testing.T) {
	s := New(32)
	s.Destroy()
	s.Destroy()
	if err := s.Use(func([]byte) error { return nil }); err != ErrDestroyed {
		t.Fatalf("got %v, want ErrDestroyed", err)
	}
}

func TestHardenProcess(t *testing.T) {
	if err := HardenProcess(); err != nil {
		t.Fatal(err)
	}
}

func TestFillWritesInPlace(t *testing.T) {
	s, err := Fill(4, func(b []byte) error { copy(b, "abcd"); return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer s.Destroy()
	s.Use(func(b []byte) error {
		if string(b) != "abcd" {
			t.Errorf("content %q", b)
		}
		return nil
	})
	if _, err := Fill(4, func([]byte) error { return ErrDestroyed }); err != ErrDestroyed {
		t.Fatalf("err = %v", err)
	}
}

// vmLck returns the process's locked memory in bytes from /proc (linux).
func vmLck(t *testing.T) uint64 {
	t.Helper()
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Skip("no /proc/self/status")
	}
	for _, l := range strings.Split(string(raw), "\n") {
		if rest, ok := strings.CutPrefix(l, "VmLck:"); ok {
			var kb uint64
			fmt.Sscanf(strings.TrimSpace(rest), "%d kB", &kb)
			return kb * 1024
		}
	}
	t.Fatal("no VmLck line")
	return 0
}

// M3: the page accounting must match what the kernel locks, so the budget is
// measured, not guessed. memguard locks whole pages and leaves guard pages
// unlocked.
func TestBudgetMatchesLockedPages(t *testing.T) {
	ps := os.Getpagesize()
	for _, n := range []int{1, 32, ps, ps + 1, 3*ps - 1} {
		before, stats := vmLck(t), Budget()
		b, err := TryNew(n)
		if err != nil {
			t.Fatal(err)
		}
		if got := vmLck(t) - before; got != pagesFor(n) {
			t.Errorf("size %d: kernel locked %d bytes, accounting says %d", n, got, pagesFor(n))
		}
		if got := Budget(); got.Used-stats.Used != pagesFor(n) || got.Live != stats.Live+1 {
			t.Errorf("size %d: budget %+v after, %+v before", n, got, stats)
		}
		b.Destroy()
		b.Destroy() // twice: the second must not uncharge again
		if got := Budget(); got != stats {
			t.Errorf("size %d: budget %+v after destroy, want %+v", n, got, stats)
		}
		if vmLck(t) != before {
			t.Errorf("size %d: memory still locked after destroy", n)
		}
	}
}

// M3: exhausting the budget is an error, not a panic that wipes everything.
func TestMemoryLimitIsAnError(t *testing.T) {
	Init()
	acct.mu.Lock()
	saved := acct.stats
	acct.stats.Unlimited = false
	acct.stats.Limit = acct.stats.Used + 3*uint64(os.Getpagesize())
	acct.mu.Unlock()
	defer func() {
		acct.mu.Lock()
		acct.stats.Limit, acct.stats.Unlimited = saved.Limit, saved.Unlimited
		acct.mu.Unlock()
	}()

	var held []*Buffer
	for i := 0; i < 3; i++ {
		b, err := TryNew(8)
		if err != nil {
			t.Fatalf("buffer %d: %v", i, err)
		}
		held = append(held, b)
	}
	if _, err := TryNew(8); !errors.Is(err, ErrMemoryLimit) {
		t.Fatalf("TryNew: %v", err)
	}
	src := []byte("secret")
	if _, err := TryTake(src); !errors.Is(err, ErrMemoryLimit) {
		t.Fatalf("TryTake: %v", err)
	}
	if !bytes.Equal(src, make([]byte, 6)) {
		t.Error("a refused TryTake left the secret in the caller's slice")
	}
	called := false
	if _, err := Fill(8, func([]byte) error { called = true; return nil }); !errors.Is(err, ErrMemoryLimit) || called {
		t.Fatalf("Fill: %v (called=%v)", err, called)
	}
	if _, err := TryRead(strings.NewReader("x")); !errors.Is(err, ErrMemoryLimit) {
		t.Fatalf("TryRead: %v", err)
	}
	func() {
		defer func() {
			r := recover()
			if s, _ := r.(string); !strings.Contains(s, "locked-memory limit") {
				t.Errorf("Take panic = %v, want a message naming the limit", r)
			}
		}()
		Take([]byte("x"))
	}()
	// The buffers made before the limit are intact (memguard did not purge).
	for _, b := range held {
		if err := b.Use(func(x []byte) error { return nil }); err != nil {
			t.Errorf("held buffer lost: %v", err)
		}
	}
	// Releasing one makes room again.
	held[0].Destroy()
	b, err := TryNew(8)
	if err != nil {
		t.Fatal(err)
	}
	b.Destroy()
	for _, h := range held[1:] {
		h.Destroy()
	}
}

func TestFillFailureReleasesBudget(t *testing.T) {
	before := Budget()
	if _, err := Fill(64, func([]byte) error { return ErrDestroyed }); err != ErrDestroyed {
		t.Fatal(err)
	}
	if Budget() != before {
		t.Errorf("budget leaked: %+v -> %+v", before, Budget())
	}
	b, err := TryRead(strings.NewReader("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if Budget().Live != before.Live+1 {
		t.Error("TryRead not counted")
	}
	b.Destroy()
	if Budget() != before {
		t.Errorf("budget leaked: %+v -> %+v", before, Budget())
	}
}

// Finding 10: TryRead reads in guarded memory and charges before it grows.
func TestTryReadContentAtEveryBoundary(t *testing.T) {
	ps := os.Getpagesize()
	for _, n := range []int{0, 1, ps - 1, ps, ps + 1, 2 * ps, 5*ps + 3} {
		want := bytes.Repeat([]byte{0xA5}, n)
		before := Budget()
		b, err := TryRead(bytes.NewReader(want))
		if err != nil {
			t.Fatalf("%d bytes: %v", n, err)
		}
		if b.Len() != n {
			t.Errorf("%d bytes: Len %d", n, b.Len())
		}
		if n > 0 {
			b.Use(func(got []byte) error {
				if !bytes.Equal(got, want) {
					t.Errorf("%d bytes: content differs", n)
				}
				return nil
			})
		}
		b.Destroy()
		if Budget() != before {
			t.Errorf("%d bytes: budget %+v -> %+v", n, before, Budget())
		}
	}
	if _, err := TryRead(failingReader{}); err == nil || errors.Is(err, io.EOF) {
		t.Errorf("a failing reader: %v", err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

// peakReader records the most memory the process had locked while reading.
type peakReader struct {
	t    *testing.T
	left int
	peak uint64
}

func (p *peakReader) Read(b []byte) (int, error) {
	if v := vmLck(p.t); v > p.peak {
		p.peak = v
	}
	if p.left == 0 {
		return 0, io.EOF
	}
	n := min(len(b), p.left)
	clear(b[:n])
	p.left -= n
	return n, nil
}

func TestTryReadNeverLocksBeyondTheBudget(t *testing.T) {
	Init()
	ps := uint64(os.Getpagesize())
	acct.mu.Lock()
	saved := acct.stats
	acct.stats.Unlimited = false
	acct.stats.Limit = acct.stats.Used + 12*ps
	limit := acct.stats.Limit
	acct.mu.Unlock()
	defer func() {
		acct.mu.Lock()
		acct.stats.Limit, acct.stats.Unlimited = saved.Limit, saved.Unlimited
		acct.mu.Unlock()
	}()
	before, usedBefore := vmLck(t), Budget().Used
	r := &peakReader{t: t, left: 1 << 20}
	if _, err := TryRead(r); !errors.Is(err, ErrMemoryLimit) {
		t.Fatalf("a 1 MiB read with %d pages of budget: %v", 12, err)
	}
	if grown := r.peak - before; grown > limit-usedBefore {
		t.Errorf("the read locked %d bytes, the budget allowed %d", grown, limit-usedBefore)
	}
	if vmLck(t) != before || Budget().Used != usedBefore {
		t.Errorf("a refused read leaked: locked %d -> %d, used %d -> %d", before, vmLck(t), usedBefore, Budget().Used)
	}
	// A read that fits works, up to the peak of buffer + double + exact copy.
	if b, err := TryRead(&peakReader{t: t, left: int(2 * ps)}); err != nil {
		t.Errorf("a read that fits: %v", err)
	} else {
		b.Destroy()
	}
}

func TestMinimumBudget(t *testing.T) {
	ps := uint64(os.Getpagesize())
	got := MinimumBudget(1 << 20)
	want := (14)*ps + 3<<20
	if got != want {
		t.Errorf("MinimumBudget(1 MiB) = %d, want %d", got, want)
	}
	if ps == 4096 && got != 3203072 {
		t.Errorf("the documented figure for 4 KiB pages is 3,203,072; got %d", got)
	}
}

func TestFillReleasesTheBufferWhenFnPanics(t *testing.T) {
	before := Budget()
	func() {
		defer func() {
			if recover() == nil {
				t.Error("the panic was swallowed")
			}
		}()
		Fill(4096, func(b []byte) error { copy(b, "k"); panic("boom") })
	}()
	if after := Budget(); after.Used != before.Used || after.Live != before.Live {
		t.Errorf("a panic in fn left the charge behind: before %+v after %+v", before, after)
	}
}

// zeroReader returns (0, nil) forever; after one real chunk if data is set.
type zeroReader struct{ calls int }

func (z *zeroReader) Read([]byte) (int, error) { z.calls++; return 0, nil }

func TestTryReadFailsOnAReaderThatMakesNoProgress(t *testing.T) {
	before := Budget()
	z := &zeroReader{}
	b, err := TryRead(z)
	if !errors.Is(err, io.ErrNoProgress) || b != nil {
		t.Fatalf("TryRead = %v, %v; want io.ErrNoProgress", b, err)
	}
	if z.calls > 1000 {
		t.Errorf("%d reads before giving up", z.calls)
	}
	if after := Budget(); after.Live != before.Live {
		t.Errorf("buffers leaked: %+v -> %+v", before, after)
	}
}

func TestTryReadReleasesTheBufferWhenTheReaderPanics(t *testing.T) {
	before := Budget()
	func() {
		defer func() { recover() }()
		TryRead(panicReader{})
	}()
	if after := Budget(); after.Live != before.Live || after.Used != before.Used {
		t.Errorf("a panicking reader left a buffer: %+v -> %+v", before, after)
	}
}

type panicReader struct{}

func (panicReader) Read([]byte) (int, error) { panic("boom") }
