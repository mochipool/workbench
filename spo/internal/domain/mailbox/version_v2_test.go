package mailbox_test

import (
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
)

// spec: SPO-Xmailbox-OUT-050
func TestVersionSets(t *testing.T) {
	for _, c := range []struct {
		v        mailbox.Versions
		valid    bool
		min, max uint
	}{
		{mailbox.V1, true, 1, 1},
		{mailbox.V2, true, 2, 2},
		{mailbox.BothVersions, true, 1, 2},
		{0, false, 0, 0},
		{4, false, 0, 0},
		{mailbox.BothVersions | 4, false, 0, 0},
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
		{mailbox.V1, 1, true}, {mailbox.V1, 2, false}, {mailbox.V2, 1, false}, {mailbox.V2, 2, true},
		{mailbox.BothVersions, 1, true}, {mailbox.BothVersions, 2, true}, {mailbox.BothVersions, 0, false},
		{mailbox.BothVersions, 3, false}, {mailbox.BothVersions, 65536, false}, {0, 1, false},
	} {
		if got := c.v.Has(c.n); got != c.want {
			t.Errorf("%b.Has(%d) = %v", c.v, c.n, got)
		}
	}
	if mailbox.Version2 != 2 || mailbox.Version1 != 1 {
		t.Error("version numbers")
	}
}

// The client chooses the highest version that is in both the relay's range and
// its own set.
//
// spec: SPO-Xmailbox-OUT-050
func TestChooseTheHighestCommonVersion(t *testing.T) {
	for _, c := range []struct {
		v        mailbox.Versions
		min, max uint
		want     uint
	}{
		{mailbox.BothVersions, 1, 2, 2},
		{mailbox.BothVersions, 1, 1, 1},
		{mailbox.BothVersions, 2, 2, 2},
		{mailbox.BothVersions, 1, 5, 2},
		{mailbox.BothVersions, 2, 65535, 2},
		{mailbox.V2, 1, 2, 2},
		{mailbox.V2, 2, 2, 2},
		{mailbox.V1, 1, 2, 1},
		{mailbox.V1, 1, 1, 1},
	} {
		if got, err := c.v.Choose(c.min, c.max); err != nil || got != c.want {
			t.Errorf("%b in %d..%d: %d, %v, want %d", c.v, c.min, c.max, got, err, c.want)
		}
	}
	for _, c := range []struct {
		v        mailbox.Versions
		min, max uint
	}{
		{mailbox.V2, 1, 1}, {mailbox.V1, 2, 2}, {mailbox.BothVersions, 3, 5}, {mailbox.V1, 2, 65535},
	} {
		if _, err := c.v.Choose(c.min, c.max); !errors.Is(err, mailbox.ErrVersion) {
			t.Errorf("%b in %d..%d: %v", c.v, c.min, c.max, err)
		}
	}
	for _, r := range [][2]uint{{0, 1}, {3, 2}, {0, 0}, {1, 65536}, {2, 1}} {
		if _, err := mailbox.BothVersions.Choose(r[0], r[1]); !errors.Is(err, mailbox.ErrMalformed) {
			t.Errorf("range %v: %v", r, err)
		}
	}
	// An empty or unknown set speaks nothing.
	for _, v := range []mailbox.Versions{0, 4, 0x80} {
		if _, err := v.Choose(1, 2); err == nil {
			t.Errorf("set %b chose a version", v)
		}
	}
	// The version 1 function is what it was.
	if v, err := mailbox.ChooseVersion(1, 2); err != nil || v != 1 {
		t.Errorf("ChooseVersion(1, 2) = %d, %v", v, err)
	}
}

// spec: SPO-Xmailbox-OUT-051
func TestStages(t *testing.T) {
	all := []mailbox.Stage{mailbox.StageUnversioned, mailbox.StageV1, mailbox.StageV2PreAuth, mailbox.StageV2Authed}
	seen := map[string]bool{}
	for _, s := range all {
		if !s.Valid() || s.String() == "" || seen[s.String()] {
			t.Errorf("stage %d: valid %v, name %q", s, s.Valid(), s.String())
		}
		seen[s.String()] = true
	}
	for _, s := range []mailbox.Stage{0, 5, 255} {
		if s.Valid() {
			t.Errorf("stage %d is valid", s)
		}
	}
	for _, c := range []struct {
		v    mailbox.Versions
		want mailbox.Stage
	}{{mailbox.V1, mailbox.StageV1}, {mailbox.V2, mailbox.StageV2PreAuth}, {mailbox.BothVersions, mailbox.StageUnversioned}} {
		if got, err := mailbox.StageForOffer(c.v); err != nil || got != c.want {
			t.Errorf("offer %b: %v, %v", c.v, got, err)
		}
	}
	for _, v := range []mailbox.Versions{0, 4, 7} {
		if _, err := mailbox.StageForOffer(v); err == nil {
			t.Errorf("offer %b gave a stage", v)
		}
	}
	for _, c := range []struct {
		n    uint
		want mailbox.Stage
	}{{1, mailbox.StageV1}, {2, mailbox.StageV2PreAuth}} {
		if got, err := mailbox.StageAfterChoice(c.n); err != nil || got != c.want {
			t.Errorf("choice %d: %v, %v", c.n, got, err)
		}
	}
	for _, n := range []uint{0, 3, 65535} {
		if _, err := mailbox.StageAfterChoice(n); !errors.Is(err, mailbox.ErrVersion) {
			t.Errorf("choice %d: %v", n, err)
		}
	}
	// The transitions are in stage_transitions_v2_test.go.
}
