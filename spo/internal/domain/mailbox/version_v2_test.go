package mailbox_test

import (
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
)

// There is one version. The set of version 2 is valid and announces [2, 2]; the
// empty set, the retired version 1 (bit 1) and every other bit are not valid and
// announce nothing.
//
// spec: SPO-Xmailbox-OUT-050
func TestVersionSets(t *testing.T) {
	for _, c := range []struct {
		v        mailbox.Versions
		valid    bool
		min, max uint
	}{
		{mailbox.V2, true, 2, 2},
		{0, false, 0, 0},
		{1, false, 0, 0}, // the retired version 1
		{3, false, 0, 0}, // both of them: there is no such set any more
		{4, false, 0, 0},
		{mailbox.V2 | 4, false, 0, 0},
		{0x80, false, 0, 0},
	} {
		if c.v.Valid() != c.valid {
			t.Errorf("%b: Valid is %v", c.v, c.v.Valid())
		}
		if lo, hi := c.v.Range(); lo != c.min || hi != c.max {
			t.Errorf("%b: Range %d..%d, want %d..%d", c.v, lo, hi, c.min, c.max)
		}
	}
	for _, c := range []struct {
		v    mailbox.Versions
		n    uint
		want bool
	}{
		{mailbox.V2, 1, false}, {mailbox.V2, 2, true}, {mailbox.V2, 0, false}, {mailbox.V2, 3, false},
		{mailbox.V2, 65536, false}, {0, 2, false}, {1, 1, false}, {3, 2, false},
	} {
		if got := c.v.Has(c.n); got != c.want {
			t.Errorf("%b.Has(%d) = %v", c.v, c.n, got)
		}
	}
	if mailbox.Version2 != 2 {
		t.Error("version number")
	}
}

// The client chooses version 2 when the relay's range holds it, and refuses with
// ErrVersion when it does not (a relay that offers only version 1 is refused).
//
// spec: SPO-Xmailbox-OUT-050
func TestChooseVersionTwoOrRefuse(t *testing.T) {
	for _, r := range [][2]uint{{2, 2}, {1, 2}, {1, 5}, {2, 65535}} {
		if got, err := mailbox.V2.Choose(r[0], r[1]); err != nil || got != 2 {
			t.Errorf("V2 in %d..%d: %d, %v, want 2", r[0], r[1], got, err)
		}
	}
	for _, r := range [][2]uint{{1, 1}, {3, 5}, {3, 65535}} {
		if _, err := mailbox.V2.Choose(r[0], r[1]); !errors.Is(err, mailbox.ErrVersion) {
			t.Errorf("V2 in %d..%d: %v", r[0], r[1], err)
		}
	}
	for _, r := range [][2]uint{{0, 1}, {3, 2}, {0, 0}, {1, 65536}, {2, 1}} {
		if _, err := mailbox.V2.Choose(r[0], r[1]); !errors.Is(err, mailbox.ErrMalformed) {
			t.Errorf("range %v: %v", r, err)
		}
	}
	// An empty or unknown set speaks nothing.
	for _, v := range []mailbox.Versions{0, 1, 3, 4, 0x80} {
		if _, err := v.Choose(1, 2); err == nil {
			t.Errorf("set %b chose a version", v)
		}
	}
}

// spec: SPO-Xmailbox-OUT-051
func TestStages(t *testing.T) {
	all := []mailbox.Stage{mailbox.StageV2PreAuth, mailbox.StageV2Authed}
	seen := map[string]bool{}
	for _, s := range all {
		if !s.Valid() || s.String() == "" || seen[s.String()] {
			t.Errorf("stage %d: valid %v, name %q", s, s.Valid(), s.String())
		}
		seen[s.String()] = true
	}
	for _, s := range []mailbox.Stage{0, 3, 5, 255} {
		if s.Valid() {
			t.Errorf("stage %d is valid", s)
		}
	}
	// The transitions are in stage_transitions_v2_test.go.
}
