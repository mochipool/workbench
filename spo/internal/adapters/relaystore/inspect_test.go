package relaystore

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
)

// inspect lists one prefix a page at a time, with names decoded, version ids
// and locks, and never a body.
//
// spec: SPO-Xobjstore-IF-903
func TestInspectDecodesNamesAndPages(t *testing.T) {
	e := newEnv(t)
	p := e.populate()
	e.srv.AdminDeleteMarker(regBucket, testPrefix+pathTombstones+tombName(tombKeyOf(relaybind.ScopePair, p.w.Key, p.revoked)))
	page, err := Inspect(bg(t), e.deps(), InspectOptions{Bucket: "registry", Path: pathTombstones, Versions: true, Locks: true, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Entries) != 2 || page.Next == "" {
		t.Fatalf("a first page of %d entries, next %q", len(page.Entries), page.Next)
	}
	var kinds []string
	for _, en := range page.Entries {
		kinds = append(kinds, en.Kind+":"+en.Detail)
		if !en.DeleteMarker && en.Lock == nil {
			t.Errorf("%s: no lock read", en.Key)
		}
	}
	rest, err := Inspect(bg(t), e.deps(), InspectOptions{Bucket: "registry", Path: pathTombstones, Versions: true, Limit: 2, After: page.Next})
	if err != nil {
		t.Fatal(err)
	}
	if len(rest.Entries) != 1 || rest.Next != "" {
		t.Fatalf("the second page: %d entries, next %q", len(rest.Entries), rest.Next)
	}
	all := strings.Join(kinds, " ") + rest.Entries[0].Kind + ":" + rest.Entries[0].Detail
	for _, want := range []string{"scope pair", "scope device", "delete marker"} {
		if !strings.Contains(all, want) && !(want == "delete marker" && (page.Entries[0].DeleteMarker || page.Entries[1].DeleteMarker || rest.Entries[0].DeleteMarker)) {
			t.Errorf("%q is not in %s", want, all)
		}
	}
	mail, err := Inspect(bg(t), e.deps(), InspectOptions{Bucket: "working", Path: pathMailbox})
	if err != nil {
		t.Fatal(err)
	}
	if len(mail.Entries) != 2 {
		t.Fatalf("%d mailbox entries", len(mail.Entries))
	}
	var b bytes.Buffer
	RenderInspect(&b, mail)
	for _, want := range []string{"recipient " + fp(p.rcpt), "sender " + fp(p.senders[0]), "arrival "} {
		if !has(&b, want) {
			t.Errorf("the rendering lacks %q:\n%s", want, b.String())
		}
	}
	if has(&b, string(p.envelope[0])) {
		t.Error("the rendering holds an envelope body")
	}
}

// inspect refuses a path outside the identity's prefix, a page over 1000, and
// a version listing of the working bucket.
//
// spec: SPO-Xobjstore-IF-903
func TestInspectRefusesWhatItCannotBound(t *testing.T) {
	e := newEnv(t)
	for _, o := range []InspectOptions{
		{Bucket: "registry", Path: "../other/"},
		{Bucket: "registry", Path: "/abs"},
		{Bucket: "working", Path: pathMailbox, Limit: 1001},
		{Bucket: "working", Path: pathMailbox, Versions: true},
		{Bucket: "elsewhere", Path: pathMailbox},
	} {
		if _, err := Inspect(bg(t), e.deps(), o); err == nil {
			t.Errorf("%+v is not refused", o)
		}
	}
}
