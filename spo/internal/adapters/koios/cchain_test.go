package koios

import (
	"context"
	"testing"
)

// In light mode the epoch and the slot of the tip are the `epoch_no` and
// `abs_slot` of the first element of Koios' tip answer. Upstream prints the
// text `null` for a missing field; the port refuses an answer without them
// (TestTipRefusals), never a made-up zero.
//
// spec: SPO-Cchain-MODE-003, SPO-Cchain-MODE-007, SPO-Clight-OUT-003
func TestLightTipIsEpochNoAndAbsSlot(t *testing.T) {
	f := newFake().on("GET /api/v1/tip", ok(fixture(t, "tip.json")))
	tip, err := f.client(t).Tip(context.Background())
	if err != nil || tip.Epoch != 1483 || tip.Slot != 128163362 {
		t.Fatalf("%+v %v", tip, err)
	}
	for name, body := range map[string]string{
		"no epoch_no": `[{"abs_slot":5}]`,
		"no abs_slot": `[{"epoch_no":5}]`,
		"empty":       `[]`,
	} {
		f := newFake().on("GET /api/v1/tip", ok(body))
		if tip, err := f.client(t).Tip(context.Background()); err == nil {
			t.Errorf("%s: accepted, tip %+v", name, tip)
		}
	}
}

// The era is the lower-case `era` of the tip. Upstream prints `auto` when no
// era could be read and then builds with an era flag of its own (or the
// default); the port has no `auto`: an answer without an era is an error and
// the caller does not build (decision: fix). In light mode the era comes from
// Koios' tip, which is the provider the light-mode parameters came from.
//
// spec: SPO-Cconf-OUT-005, SPO-Cconf-MODE-006
func TestEraIsLowerCaseOrAnError(t *testing.T) {
	f := newFake().on("GET /api/v1/tip", ok(fixture(t, "tip.json")))
	if era, err := f.client(t).Era(context.Background()); err != nil || era != "conway" {
		t.Fatalf("%q %v", era, err)
	}
	f = newFake().on("GET /api/v1/tip", ok(`[{"epoch_no":1,"abs_slot":2}]`))
	if era, err := f.client(t).Era(context.Background()); err == nil {
		t.Fatalf("a tip without an era gave %q, not an error", era)
	}
}
