package main

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var newFPRE = regexp.MustCompile(`new fingerprint\s+((?:[a-z2-7]{4}-){7}[a-z2-7]{4})`)

// The whole rotation through the real binary wiring on sealed workspaces: a
// request made to bob's old identity is void after the rotation (bob cannot
// open it any more, and the coordinator drops it when it accepts), the
// coordinator accepts with the first four groups bob reads out, requests
// again, and the registration completes with the new identity. Afterwards the
// coordinator's outbox export carries the closing notice of the submitted
// collection and bob's log records it.
//
// spec: SPO-Xparty-IF-008, SPO-Xparty-INV-031, SPO-Xparty-INV-032, SPO-Xparty-INV-033, SPO-Xparty-PR-006, SPO-Xparty-INV-035
func TestRotationEndToEnd(t *testing.T) {
	w := newPartyWorld(t, false)
	w.register()
	carry1 := filepath.Join(t.TempDir(), "old-request")
	w.coord(nil, "party", "request", "export", "p", "--out", carry1, "--purpose", "register")
	oldReq, _ := filepath.Glob(filepath.Join(carry1, "SigningRequest-*-*.spo"))
	if len(oldReq) != 1 {
		t.Fatalf("request files %v", oldReq)
	}

	// Bob rotates.
	out := mustParty(t, w.bob, []string{"y"}, nil, "party", "rotate", "--label", "bob two")
	m := newFPRE.FindStringSubmatch(out)
	if m == nil || !strings.Contains(out, "announcements sealed for 1 peer(s)") {
		t.Fatalf("rotate:\n%s", out)
	}
	newFP := m[1]
	if show := mustParty(t, w.bob, nil, nil, "party", "show"); !strings.Contains(show, newFP) || !strings.Contains(show, `"bob two"`) {
		t.Fatalf("show:\n%s", show)
	}
	carry2 := filepath.Join(t.TempDir(), "announcement")
	mustParty(t, w.bob, nil, nil, "party", "outbox", "export", carry2)

	// The request made to the old identity cannot be opened any more.
	if out, err := w.bobRun(nil, nil, "party", "inbox", "import", oldReq[0]); err != nil || strings.Contains(out, "is pending") {
		t.Fatalf("the old request: %v\n%s", err, out)
	}
	if reqs := mustParty(t, w.bob, nil, nil, "party", "requests", "--shelley-genesis", w.r.genesis); !strings.Contains(reqs, "No request is waiting") {
		t.Fatalf("requests:\n%s", reqs)
	}

	// The coordinator stores the announcement; nothing changes until it confirms.
	out = mustParty(t, w.r.dir, nil, nil, "party", "inbox", "import", carry2, "--shelley-genesis", w.r.genesis)
	mustHave(t, out, "a rotation announcement", "nothing about the enrollment changed")
	if list := mustParty(t, w.r.dir, nil, nil, "party", "list"); strings.Contains(list, newFP) {
		t.Fatalf("the enrollment changed before the confirmation:\n%s", list)
	}
	rl := mustParty(t, w.r.dir, nil, nil, "party", "rotation", "list")
	mustHave(t, rl, `"bob"`, newFP[20:])
	if strings.Contains(rl, newFP[:19]) {
		t.Fatalf("the groups to type are listed:\n%s", rl)
	}
	// A wrong confirmation changes nothing; the right one replaces the enrollment.
	if _, err := party3(t, w.r.dir, []string{"aaaa-aaaa-aaaa-aaaa"}, nil, "party", "rotation", "accept", "bob"); err == nil {
		t.Fatal("a wrong confirmation was accepted")
	}
	out = mustParty(t, w.r.dir, []string{newFP[:19]}, nil, "party", "rotation", "accept", "bob")
	mustHave(t, out, "Accepted.", "is revoked", "must be requested again")
	list := mustParty(t, w.r.dir, nil, nil, "party", "list")
	mustHave(t, list, newFP, "revoked")

	// Requested again, to the new identity.
	carry3 := filepath.Join(t.TempDir(), "new-request")
	out = w.coord(nil, "party", "request", "export", "p", "--out", carry3, "--purpose", "register")
	mustHave(t, out, "1 request(s) written")
	newReq, _ := filepath.Glob(filepath.Join(carry3, "SigningRequest-*-*.spo"))
	if len(newReq) != 1 {
		t.Fatalf("request files %v", newReq)
	}
	out, err := w.bobRun(nil, nil, "party", "inbox", "import", newReq[0])
	if err != nil || !strings.Contains(out, "1 request(s) are waiting for you") {
		t.Fatalf("the new request: %v\n%s", err, out)
	}
	reqs := mustParty(t, w.bob, nil, nil, "party", "requests", "--shelley-genesis", w.r.genesis)
	id := reqIDRE.FindStringSubmatch(reqs)[1]
	review := mustParty(t, w.bob, nil, nil, "party", "review", id[:12], "--shelley-genesis", w.r.genesis)
	reviewed := bodyHashRE.FindStringSubmatch(review)[1]
	out, err = w.bobRun([]string{"y"}, []string{testPass}, "party", "approve", id)
	if err != nil || !strings.Contains(out, "Signed.") {
		t.Fatalf("approve: %v\n%s", err, out)
	}
	back := filepath.Join(t.TempDir(), "back")
	mustParty(t, w.bob, nil, nil, "party", "outbox", "export", back)
	resp, _ := filepath.Glob(filepath.Join(back, "SigningResponse-*-*.spo"))
	if len(resp) != 1 {
		t.Fatalf("response files %v", resp)
	}
	out = w.coord(nil, "party", "inbox", "import", resp[0])
	mustHave(t, out, "filled", "The collection is complete")
	w.finish(reviewed)

	// The collection was finished offline (queued, no proof it was sent): it is
	// announced at the next export as queued.
	notices := filepath.Join(t.TempDir(), "notices")
	out = w.coord(nil, "party", "outbox", "export", notices)
	mustHave(t, out, "closing notice", "1 CollectionClosed")
	closed, _ := filepath.Glob(filepath.Join(notices, "CollectionClosed-*.spo"))
	if len(closed) != 1 {
		t.Fatalf("notice files %v", closed)
	}
	out = mustParty(t, w.bob, nil, nil, "party", "inbox", "import", closed[0], "--shelley-genesis", w.r.genesis)
	mustHave(t, out, "collection closed by its coordinator")
	ev := mustParty(t, w.bob, nil, nil, "party", "events")
	mustHave(t, ev, "collection-closed", "queued")
}

// A collection the coordinator clears is announced as discarded at its next
// export; bob's pending request is then closed, and review and approve refuse
// it.
//
// spec: SPO-Xparty-INV-035, SPO-Xparty-INV-036
func TestClearedCollectionClosesTheSignersRequest(t *testing.T) {
	w := newPartyWorld(t, false)
	w.register()
	carry := filepath.Join(t.TempDir(), "req")
	w.coord(nil, "party", "request", "export", "p", "--out", carry, "--purpose", "register")
	files, _ := filepath.Glob(filepath.Join(carry, "SigningRequest-*-*.spo"))
	if out, err := w.bobRun(nil, nil, "party", "inbox", "import", files[0]); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	reqs := mustParty(t, w.bob, nil, nil, "party", "requests", "--shelley-genesis", w.r.genesis)
	id := reqIDRE.FindStringSubmatch(reqs)[1]

	w.r.mustG(t, []string{"y"}, "pool", "witness", "clear", "p")
	notices := filepath.Join(t.TempDir(), "notices")
	out := w.coord(nil, "party", "outbox", "export", notices)
	mustHave(t, out, "closing notice")
	closed, _ := filepath.Glob(filepath.Join(notices, "CollectionClosed-*.spo"))
	if len(closed) != 1 {
		t.Fatalf("notice files %v", closed)
	}
	if out, err := w.bobRun(nil, nil, "party", "inbox", "import", closed[0]); err != nil || !strings.Contains(out, "collection closed by its coordinator") {
		t.Fatalf("%v\n%s", err, out)
	}
	reqs = mustParty(t, w.bob, nil, nil, "party", "requests", "--shelley-genesis", w.r.genesis)
	mustHave(t, reqs, "No request is waiting", "closed (discarded)")
	for _, args := range [][]string{{"party", "review", id[:12]}, {"party", "approve", id[:12]}} {
		out, err := w.bobRun([]string{"y"}, []string{testPass}, args...)
		if err == nil || !strings.Contains(err.Error(), "the coordinator closed this collection (discarded)") {
			t.Errorf("%v: %v\n%s", args, err, out)
		}
	}
}
