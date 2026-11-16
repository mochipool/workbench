package pool

import (
	"errors"
	"testing"
)

func ip(n int) *int { return &n }

// spec: SPO-04c-OUT-001
func TestNextNumberWhenNoNextCounterIsStored(t *testing.T) {
	if got := NewKesState(nil, nil).NextNumber(); got != 0 {
		t.Errorf("fresh pool: next = %d, want 0", got)
	}
	if got := NewKesState(ip(4), nil).NextNumber(); got != 5 {
		t.Errorf("current 4, no next: next = %d, want 5", got)
	}
	if got := NewKesState(ip(4), ip(9)).NextNumber(); got != 9 {
		t.Errorf("stored next wins: got %d", got)
	}
}

// spec: SPO-04c-PRE-001, SPO-04c-OUT-003
func TestGenerateStateMachine(t *testing.T) {
	s := NewKesState(nil, nil)
	s, n, err := s.Generate()
	if err != nil || n != 0 {
		t.Fatalf("first generation: n=%d err=%v", n, err)
	}
	if cur, ok := s.Current(); !ok || cur != 0 || s.NextNumber() != 0 {
		t.Fatalf("after generation: current=%d next=%d", cur, s.NextNumber())
	}
	// A second generation without an opcert in between is refused.
	if _, _, err := s.Generate(); !errors.Is(err, ErrKesKeyUnconsumed) {
		t.Fatalf("second generation: err=%v", err)
	}
	// After an opcert consumed key 0 (04d sets next to 1), key 1 can be generated.
	s = NewKesState(ip(0), ip(1))
	s, n, err = s.Generate()
	if err != nil || n != 1 {
		t.Fatalf("after opcert: n=%d err=%v", n, err)
	}
	if cur, _ := s.Current(); cur != 1 {
		t.Fatalf("current = %d", cur)
	}
}

// spec: SPO-04c-INV-001, SPO-04c-IN-001, SPO-04c-IN-002
func TestCounterCodec(t *testing.T) {
	for n, want := range map[int]string{0: "000\n", 7: "007\n", 42: "042\n", 999: "999\n", 1000: "1000\n"} {
		if got := string(FormatCounter(n)); got != want {
			t.Errorf("FormatCounter(%d) = %q, want %q", n, got, want)
		}
	}
	// Leading zeros are decimal, not octal: 010 is ten, 008 is eight.
	for in, want := range map[string]int{"000\n": 0, "010": 10, "008\n": 8, " 12 \n": 12, "1000": 1000} {
		got, err := ParseCounter([]byte(in))
		if err != nil || got != want {
			t.Errorf("ParseCounter(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "\n", "-1", "1 2", "0x10", "1e3", "12a", "99999999999999999999"} {
		if _, err := ParseCounter([]byte(bad)); !errors.Is(err, ErrBadCounter) {
			t.Errorf("ParseCounter(%q) accepted", bad)
		}
	}
}
