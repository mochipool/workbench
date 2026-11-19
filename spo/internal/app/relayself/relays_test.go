package relayself_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/app/relayself"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

func addr(t *testing.T, s string) *ports.Secret {
	t.Helper()
	b, err := ports.TakeSecret([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Destroy)
	return b
}

// The relay list: names, pinned keys and ports in one public record, each
// address in a secret record; a name or key twice, a bad name and a ninth relay
// are refused; remove drops both records.
//
// spec: SPO-Xmailbox-IF-025
func TestTheRelayListKeepsPinsAndSealedAddresses(t *testing.T) {
	st, err := plainstore.OpenTestnet(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if rs, err := relayself.Relays(ctx, st); err != nil || len(rs) != 0 {
		t.Fatalf("an empty store: %v %v", rs, err)
	}
	a := relayself.Relay{Name: "relay-a", Key: party.NodeKey{1}}
	if err := relayself.AddRelay(ctx, st, a, addr(t, "tailcat-address-a")); err != nil {
		t.Fatal(err)
	}
	rs, err := relayself.Relays(ctx, st)
	if err != nil || len(rs) != 1 || rs[0].Name != "relay-a" || rs[0].Key != a.Key || rs[0].Port != relayself.DefaultRelayPort {
		t.Fatalf("list %+v %v", rs, err)
	}
	exists := func(name string) bool {
		var ok bool
		if err := st.View(ctx, func(r ports.NamedReader) error {
			var err error
			ok, err = r.Exists(relayself.AddressRef(name))
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !exists("relay-a") {
		t.Fatal("the address was not stored")
	}
	if !ports.RelayAddr.Secret() || ports.RelayList.Secret() {
		t.Fatal("the address must be a secret kind and the list a public one")
	}
	for name, r := range map[string]relayself.Relay{
		"same name":  {Name: "relay-a", Key: party.NodeKey{2}},
		"same key":   {Name: "relay-b", Key: party.NodeKey{1}},
		"bad name":   {Name: "Relay", Key: party.NodeKey{3}},
		"dash first": {Name: "-a", Key: party.NodeKey{3}},
		"long name":  {Name: strings.Repeat("a", 33), Key: party.NodeKey{3}},
		"zero key":   {Name: "relay-z"},
	} {
		if err := relayself.AddRelay(ctx, st, r, addr(t, "x")); err == nil {
			t.Errorf("%s: added", name)
		}
	}
	if err := relayself.AddRelay(ctx, st, relayself.Relay{Name: "big", Key: party.NodeKey{4}}, addr(t, strings.Repeat("x", relayself.MaxAddressBytes+1))); err == nil {
		t.Error("an address over the bound was added")
	}
	for i := 2; i <= relayself.MaxRelays; i++ {
		if err := relayself.AddRelay(ctx, st, relayself.Relay{Name: "r" + string(rune('0'+i)), Key: party.NodeKey{byte(10 + i)}, Port: 7400}, addr(t, "x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := relayself.AddRelay(ctx, st, relayself.Relay{Name: "ninth", Key: party.NodeKey{99}}, addr(t, "x")); !errors.Is(err, relayself.ErrRelayFull) {
		t.Fatalf("a ninth relay: %v", err)
	}
	if err := relayself.RemoveRelay(ctx, st, "relay-a"); err != nil {
		t.Fatal(err)
	}
	if exists("relay-a") {
		t.Fatal("remove left the address")
	}
	if err := relayself.RemoveRelay(ctx, st, "relay-a"); !errors.Is(err, relayself.ErrRelayUnknown) {
		t.Fatalf("a second remove: %v", err)
	}
	rs, _ = relayself.Relays(ctx, st)
	if len(rs) != relayself.MaxRelays-1 || rs[0].Port != 7400 {
		t.Fatalf("after remove: %+v", rs)
	}
}

// Forget over relays keeps the binding until the revoke was sent: ForgetRevoke
// stores the device revoke and leaves the binding, DropBinding deletes it last;
// Forget alone does both in one step, as before.
//
// spec: SPO-Xmailbox-OUT-109, SPO-Xmailbox-SEC-073
func TestForgetOverRelaysDeletesTheBindingLast(t *testing.T) {
	r := newRig(t)
	if _, err := r.svc.Bind(ctx, r.key, 0); err != nil {
		t.Fatal(err)
	}
	rv, err := r.svc.ForgetRevoke(ctx)
	if err != nil {
		t.Fatal(err)
	}
	st := r.state()
	if st.Binding == nil || len(st.Revokes) != 1 || st.Revokes[0].NotBefore != rv.NotBefore {
		t.Fatalf("after ForgetRevoke: binding %v, revokes %d", st.Binding != nil, len(st.Revokes))
	}
	if rv.Until != st.Binding.Until {
		t.Fatalf("the revoke is owed until %d, the binding ends %d", rv.Until, st.Binding.Until)
	}
	if err := r.svc.DropBinding(ctx); err != nil {
		t.Fatal(err)
	}
	if st := r.state(); st.Binding != nil || len(st.Revokes) != 1 {
		t.Fatalf("after DropBinding: %+v", st)
	}
	r2 := newRig(t)
	if _, err := r2.svc.Bind(ctx, r2.key, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := r2.svc.Forget(ctx); err != nil {
		t.Fatal(err)
	}
	if st := r2.state(); st.Binding != nil || len(st.Revokes) != 1 {
		t.Fatalf("Forget: %+v", st)
	}
}

// The decoder of the stored list never panics, and what it accepts encodes back
// to a list that decodes the same.
//
// spec: SPO-Xmailbox-IF-025
func FuzzDecodeRelays(f *testing.F) {
	f.Add([]byte(`{"version":1,"relays":[{"name":"a","node_key":"` + strings.Repeat("ab", 32) + `","port":7346}]}`))
	f.Add([]byte(`{"version":1,"relays":[]}`))
	f.Add([]byte(`{"version":2}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		rs, err := relayself.DecodeRelays(b)
		if err != nil {
			return
		}
		if len(rs) > relayself.MaxRelays {
			t.Fatalf("%d relays", len(rs))
		}
		enc, err := relayself.EncodeRelays(rs)
		if err != nil {
			t.Fatal(err)
		}
		again, err := relayself.DecodeRelays(enc)
		if err != nil || len(again) != len(rs) {
			t.Fatalf("round trip: %v", err)
		}
		for i := range rs {
			if again[i] != rs[i] {
				t.Fatalf("round trip changed %+v to %+v", rs[i], again[i])
			}
		}
	})
}

// The stored list is read strictly.
//
// spec: SPO-Xmailbox-IF-025
func TestTheRelayListIsReadStrictly(t *testing.T) {
	good := `{"version":1,"relays":[{"name":"a","node_key":"` + strings.Repeat("ab", 32) + `","port":7346}]}`
	if rs, err := relayself.DecodeRelays([]byte(good)); err != nil || len(rs) != 1 {
		t.Fatalf("good: %v %v", rs, err)
	}
	b, _ := relayself.EncodeRelays([]relayself.Relay{{Name: "a", Key: party.NodeKey{0xab}, Port: 1}})
	if rs, err := relayself.DecodeRelays(b); err != nil || rs[0].Key != (party.NodeKey{0xab}) {
		t.Fatalf("round trip: %v %v", rs, err)
	}
	for name, s := range map[string]string{
		"unknown key":  strings.Replace(good, `"port"`, `"prot"`, 1),
		"repeated key": strings.Replace(good, `"port":7346`, `"port":7346,"port":7347`, 1),
		"version 2":    strings.Replace(good, `"version":1`, `"version":2`, 1),
		"upper hex":    strings.Replace(good, "abab", "ABAB", 1),
		"short key":    strings.Replace(good, "abab", "ab", 1),
		"port 0":       strings.Replace(good, `"port":7346`, `"port":0`, 1),
		"bad name":     strings.Replace(good, `"name":"a"`, `"name":"A"`, 1),
		"twice":        strings.Replace(good, `}]}`, `},{"name":"a","node_key":"`+strings.Repeat("cd", 32)+`","port":1}]}`, 1),
		"too long":     good + strings.Repeat(" ", relayself.MaxRelayListBytes),
		"key twice":    strings.Replace(good, `}]}`, `},{"name":"b","node_key":"`+strings.Repeat("ab", 32)+`","port":1}]}`, 1),
		"case-folded":  strings.Replace(good, `"name"`, `"Name"`, 1),
	} {
		if _, err := relayself.DecodeRelays([]byte(s)); !errors.Is(err, relayself.ErrRelayList) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
