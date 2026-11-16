package version

import "testing"

// spec: SPO-Cconf-INV-015, SPO-Chw-INV-001
func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"11.2.3.0", "11.0.0", 1},
		{"11.0.0", "11.0.0", 0},
		{"10.9.9", "11.0.0", -1},
		{"1.20.0", "1.9.0", 1},
		{"1.20", "1.20.0", -1},
		{"1.35.0", "1.35.0", 0},
		{"007.1", "7.1", 0},
		{"1.2.3-rc1", "1.2.3", 1},
		{"", "1.0", -1},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// An unreadable version must fail a minimum gate. Upstream's hardware gate
// lets it pass (quirk in SPO-Chw-INV-001); decision: fixed.
func TestEmptyVersionFailsGates(t *testing.T) {
	if AtLeast("", "1.0.0") {
		t.Error("empty version passed a minimum")
	}
	if AtMost("", "1.0.0") {
		t.Error("empty version passed a maximum")
	}
	if !AtLeast("1.0.0", "") || !AtMost("1.0.0", "") {
		t.Error("an absent bound must pass")
	}
}
