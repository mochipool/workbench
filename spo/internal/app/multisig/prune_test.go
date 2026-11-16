package multisig

import (
	"fmt"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// A flood of short-lived refused requests leaves bounded state: a refused
// request goes at its expiry, not a day after, and one sender keeps at most
// party.MaxReplayPerSender refused entries, the oldest going first (N3).
// spec: SPO-Xparty-INV-029, SPO-Xparty-INV-022
func TestPruneBoundsRefusedRequests(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var st signerState
	// 100 refused requests that expired an hour ago: gone at once.
	for i := range 100 {
		st.Requests = append(st.Requests, storedRequest{ID: fmt.Sprintf("old%d", i), From: "a", State: reqRefused, Expires: now.Unix() - 3600})
	}
	// An answered one expired an hour ago stays: it may be asked again.
	st.Requests = append(st.Requests, storedRequest{ID: "approved", From: "a", State: reqApproved, Expires: now.Unix() - 3600})
	// A flood of live refused requests of one sender, and a few of another.
	total := party.MaxReplayPerSender + 300
	for i := range total {
		st.Requests = append(st.Requests, storedRequest{ID: fmt.Sprintf("live%04d", i), From: "a", State: reqRefused, Expires: now.Unix() + 120})
	}
	for i := range 5 {
		st.Requests = append(st.Requests, storedRequest{ID: fmt.Sprintf("b%d", i), From: "b", State: reqRefused, Expires: now.Unix() + 120})
	}
	st.prune(now)
	var refusedA, refusedB int
	var oldest string
	for _, q := range st.Requests {
		switch {
		case q.State == reqRefused && q.From == "a":
			refusedA++
			if oldest == "" {
				oldest = q.ID
			}
			if q.Expires < now.Unix() {
				t.Fatalf("an expired refused request was kept: %s", q.ID)
			}
		case q.State == reqRefused:
			refusedB++
		}
	}
	if refusedA != party.MaxReplayPerSender || refusedB != 5 {
		t.Fatalf("refused entries: a %d (cap %d), b %d", refusedA, party.MaxReplayPerSender, refusedB)
	}
	if oldest != fmt.Sprintf("live%04d", 300) {
		t.Fatalf("the cap did not drop the oldest first: first kept is %s", oldest)
	}
	if st.byID("approved") == nil {
		t.Fatal("an answered request was pruned at its expiry")
	}
}
