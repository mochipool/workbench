package partystore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaypeer"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// flipLastHex changes the last hex digit of s.
func flipLastHex(s string) string {
	const d = "0123456789abcdef"
	return s[:len(s)-1] + string(d[(strings.IndexByte(d, s[len(s)-1])+1)%16])
}

// A relay identity whose evidence no longer verifies (a signature that fails, a
// statement the parser of this version refuses) does not lock the registry: the
// party loads without a route and with the reason, the other parties load, and
// the stored bytes are kept as they are through other writes, so nothing strips
// a binding without the operator. A record that says something its evidence
// does not (structure) is still refused.
//
// spec: SPO-Xparty-OUT-007
func TestUnverifiableRelayIdentityLoadsWithoutARoute(t *testing.T) {
	ctx := context.Background()
	a := withRelay(t, mkParty(1, "alice"), 1)
	b := mkParty(3, "bob")
	raw, _ := json.Marshal([]partyJSON{toJSON(a), toJSON(b)})
	var js []map[string]any
	if err := json.Unmarshal(raw, &js); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(r map[string]any){
		"signature bit":       func(r map[string]any) { r["statement"] = flipLastHex(r["statement"].(string)) },
		"truncated statement": func(r map[string]any) { r["statement"] = r["statement"].(string)[:20] },
	} {
		var c []map[string]any
		_ = json.Unmarshal(raw, &c)
		mut(c[0]["relay"].(map[string]any))
		bad, _ := json.Marshal(c)
		s := newMem()
		s.data[recordsRef] = bad
		ps, err := load1(t, s)
		if err != nil {
			t.Fatalf("%s: the registry is refused: %v", name, err)
		}
		if ps[0].Relay == nil || ps[0].Relay.Unverified == "" {
			t.Fatalf("%s: alice's relay identity is not marked: %+v", name, ps[0].Relay)
		}
		if _, _, ok := relaypeer.Route(ps[0]); ok {
			t.Fatalf("%s: an unverifiable relay identity routes", name)
		}
		// another write keeps alice's stored bytes exactly
		if err := s.Update(ctx, func(w ports.NamedWriter) error {
			_, err := Registry{}.SetScope(w, "bob", party.Scope{Unscoped: true})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		var after []map[string]any
		_ = json.Unmarshal(s.data[recordsRef], &after)
		if got, want := after[0]["relay"].(map[string]any)["statement"], c[0]["relay"].(map[string]any)["statement"]; got != want {
			t.Fatalf("%s: a write changed the stored evidence", name)
		}
		// the operator's repair: clear it
		if err := s.Update(ctx, func(w ports.NamedWriter) error { _, err := Registry{}.SetRelay(w, "alice", nil); return err }); err != nil {
			t.Fatal(err)
		}
		if ps, err := load1(t, s); err != nil || ps[0].Relay != nil {
			t.Fatalf("%s: after --clear %+v %v", name, ps[0].Relay, err)
		}
	}
	_ = bytes.Equal
	_ = errors.Is
}
