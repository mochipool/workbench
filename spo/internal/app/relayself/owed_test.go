package relayself_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/relayself"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// A revoke is owed to each listed relay until that relay recorded it: the book
// learns it per relay (ResultAt), Save keeps it in the encrypted record, Status
// names what each relay still owes, and the revoke-only send (which needs no
// binding) completes it. A refused answer or a relay that is down leaves it
// owed; a revoke recorded everywhere stays pending until it ends (a relay may
// lose state) but is owed to nobody.
//
// spec: SPO-Xmailbox-OUT-111, SPO-Xmailbox-IF-026
func TestARevokeIsOwedToEachRelayUntilItRecordedIt(t *testing.T) {
	r := newRig(t)
	for i, n := range []string{"relay-a", "relay-b", "relay-c"} {
		if err := relayself.AddRelay(ctx, r.store, relayself.Relay{Name: n, Key: party.NodeKey{byte(i + 1)}}, addr(t, "tailcat-address-"+n)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.svc.Bind(ctx, r.key, 30*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	got, err := r.svc.Forget(ctx)
	if err != nil {
		t.Fatal(err)
	}
	owed := func() map[string]int {
		t.Helper()
		s, err := r.svc.Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return s.Owed
	}
	if o := owed(); o["relay-a"] != 1 || o["relay-b"] != 1 || o["relay-c"] != 1 {
		t.Fatalf("a new revoke is owed to every relay: %v", o)
	}
	// the first send: a records it, b refuses, c is down
	r.svc.Send = func(_ context.Context, b relayport.RevokeBook) (map[string]error, error) {
		rb := b.(relayport.RelayRevokeBook)
		for _, p := range b.Pending() {
			rb.ResultAt("relay-a", p, relayport.RevokeRecorded)
			rb.ResultAt("relay-b", p, relayport.RevokeRefused)
		}
		return map[string]error{"relay-a": nil, "relay-b": nil, "relay-c": errors.New("unreachable")}, nil
	}
	rep, err := r.svc.SendPending(ctx)
	if err != nil || rep.Relays["relay-c"] == nil {
		t.Fatalf("send: %+v %v", rep, err)
	}
	if o := owed(); o["relay-a"] != 0 || o["relay-b"] != 1 || o["relay-c"] != 1 {
		t.Fatalf("after one relay recorded it: %v", o)
	}
	s, _ := r.svc.Status(ctx)
	if v := s.Revokes[0]; v.ID != relayself.ShortID(got) || !slices.Equal(v.RecordedAt, []string{"relay-a"}) || !slices.Equal(v.OwedTo, []string{"relay-b", "relay-c"}) {
		t.Fatalf("the view %+v", v)
	}
	// the second send, revoke-only, with no binding: b and c record it
	if st := r.state(); st.Binding != nil {
		t.Fatal("forget kept the binding")
	}
	r.svc.Send = func(_ context.Context, b relayport.RevokeBook) (map[string]error, error) {
		rb := b.(relayport.RelayRevokeBook)
		for _, p := range b.Pending() {
			rb.ResultAt("relay-b", p, relayport.RevokeRecorded)
			rb.ResultAt("relay-c", p, relayport.RevokeRecorded)
		}
		return nil, nil
	}
	if _, err := r.svc.SendPending(ctx); err != nil {
		t.Fatal(err)
	}
	if o := owed(); len(o) != 0 {
		t.Fatalf("recorded everywhere, still owed: %v", o)
	}
	if st := r.state(); len(st.Revokes) != 1 {
		t.Fatalf("a revoke recorded everywhere must stay pending until it ends: %d", len(st.Revokes))
	}
	// a relay added later is owed it
	if err := relayself.AddRelay(ctx, r.store, relayself.Relay{Name: "relay-d", Key: party.NodeKey{9}}, addr(t, "tailcat-address-d")); err != nil {
		t.Fatal(err)
	}
	if o := owed(); o["relay-d"] != 1 || len(o) != 1 {
		t.Fatalf("a relay added later: %v", o)
	}
	// an ended revoke is owed to nobody
	r.clk.advance(200 * 24 * time.Hour)
	if o := owed(); len(o) != 0 {
		t.Fatalf("an ended revoke is still owed: %v", o)
	}
}

// The relays a revoke was recorded at are bounded and checked when the record
// is read: at most eight valid names, none twice; a ninth pushes the oldest out
// (that relay is only owed the revoke again).
//
// spec: SPO-Xmailbox-OUT-111, SPO-Xmailbox-OUT-097
func TestTheRelaysARevokeWasRecordedAtAreBounded(t *testing.T) {
	r := newRig(t)
	if _, err := r.svc.Forget(ctx); err != nil {
		t.Fatal(err)
	}
	var names []string
	for i := range 10 {
		names = append(names, fmt.Sprintf("relay-%d", i))
	}
	r.svc.Send = func(_ context.Context, b relayport.RevokeBook) (map[string]error, error) {
		rb := b.(relayport.RelayRevokeBook)
		for _, p := range b.Pending() {
			for _, n := range names {
				rb.ResultAt(n, p, relayport.RevokeRecorded)
			}
			rb.ResultAt("Not A Name", p, relayport.RevokeRecorded)
			rb.Result(p, relayport.RevokeRecorded)
		}
		return nil, nil
	}
	if _, err := r.svc.SendPending(ctx); err != nil {
		t.Fatal(err)
	}
	st := r.state()
	var at []string
	for _, v := range st.RecordedAt {
		at = v
	}
	if !slices.Equal(at, names[2:]) {
		t.Fatalf("recorded at %v, want the last eight", at)
	}
	// the stored record: a ninth name, a name twice or a bad name is corrupt
	var raw []byte
	if err := r.store.View(ctx, func(rd ports.NamedReader) error {
		var err error
		raw, err = rd.Get(ports.NamedRef{Name: "self", Kind: ports.RelayOwn})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for name, at := range map[string][]string{
		"nine":  append(append([]string(nil), names[:8]...), "relay-x"),
		"twice": {"relay-a", "relay-a"},
		"bad":   {"Relay A"},
	} {
		var j map[string]any
		if err := json.Unmarshal(raw, &j); err != nil {
			t.Fatal(err)
		}
		j["revokes"].([]any)[0].(map[string]any)["recorded_at"] = at
		b, _ := json.Marshal(j)
		if _, err := relayself.Decode(b, relayporttestDevice(r)); !errors.Is(err, relayself.ErrCorrupt) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := relayself.Decode(raw, relayporttestDevice(r)); err != nil {
		t.Fatalf("the record as written: %v", err)
	}
}

func relayporttestDevice(r *rig) party.Fingerprint { return r.svc.Device }
