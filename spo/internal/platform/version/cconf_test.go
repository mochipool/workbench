package version

import "testing"

// The check passes when MIN <= CURRENT in version-sort order, equality
// included, and the order is numeric per part (11.10.0 is above 11.9.0).
//
// spec: SPO-Cconf-OUT-003
func TestMinimumCheckIsInclusiveAndNumeric(t *testing.T) {
	for _, c := range []struct {
		min, cur string
		ok       bool
	}{
		{"11.0.0", "11.0.0", true},
		{"11.0.0", "11.2.3.0", true},
		{"11.9.0", "11.10.0", true},
		{"11.10.0", "11.9.0", false},
		{"11.0.0", "10.9.9", false},
	} {
		if got := AtLeast(c.cur, c.min); got != c.ok {
			t.Errorf("AtLeast(%q, %q) = %v, want %v", c.cur, c.min, got, c.ok)
		}
	}
}
