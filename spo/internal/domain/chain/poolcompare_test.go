package chain

import (
	"strings"
	"testing"
)

// spec: ADR 0006 (F1): a retiring pool compared with a source that states it.
func TestDiffPoolReadings(t *testing.T) {
	reg := Value(PoolState{})
	ret9 := Value(PoolState{Status: PoolRetiring, RetiringEpoch: 9})
	ret10 := Value(PoolState{Status: PoolRetiring, RetiringEpoch: 10})
	unst := Value(PoolState{Status: PoolStatusUnstated})
	none := None[PoolState]()
	cases := []struct {
		name string
		a, b Reading[PoolState]
		want string
	}{
		{"same registered", reg, reg, ""},
		{"same retiring", ret9, ret9, ""},
		{"status differs", reg, ret9, "status"},
		{"epoch differs", ret9, ret10, "retiring epoch"},
		{"unstated is not compared", unst, ret9, ""},
		{"unstated other side", reg, unst, ""},
		{"registration", none, reg, "registration"},
		{"both none", none, none, ""},
	}
	for _, c := range cases {
		if got := DiffPoolReadings(c.a, c.b); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	if d := DescribePoolDetailed(ret9); !strings.Contains(d, "retiring at epoch 9") {
		t.Fatal(d)
	}
}
