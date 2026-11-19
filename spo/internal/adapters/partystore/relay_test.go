package partystore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relaypeer"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

func withRelay(t testing.TB, p party.Party, w byte) party.Party {
	t.Helper()
	st := relayporttest.NewWallet(w).BindingStatement(p.Fingerprint, t0.Unix()-60, t0.Unix()+30*24*3600, false)
	ev, err := relaypeer.Verify(st.Sign1, st.COSEKey, p.Fingerprint, t0.Unix(), relaybind.DefaultPolicy(), relaypeer.NetworkAny)
	if err != nil {
		t.Fatal(err)
	}
	p.Relay = &ev.Relay
	return p
}

func load1(t *testing.T, s *memStore) ([]party.Party, error) {
	t.Helper()
	var ps []party.Party
	err := s.View(context.Background(), func(r ports.NamedReader) error {
		var err error
		ps, err = Registry{}.List(r)
		return err
	})
	return ps, err
}

// The relay identity is stored with the party and read back; a record without
// one reads as none.
//
// spec: SPO-Xparty-OUT-007
func TestRelayIdentityRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newMem()
	a := withRelay(t, mkParty(1, "alice"), 1)
	b := mkParty(3, "bob")
	if err := s.Update(ctx, func(w ports.NamedWriter) error {
		return errors.Join(Registry{}.Put(w, a), Registry{}.Put(w, b))
	}); err != nil {
		t.Fatal(err)
	}
	ps, err := load1(t, s)
	if err != nil {
		t.Fatal(err)
	}
	if ps[0].Relay == nil || ps[0].Relay.WalletKey != a.Relay.WalletKey || !bytes.Equal(ps[0].Relay.Statement, a.Relay.Statement) ||
		ps[0].Relay.From != a.Relay.From || ps[0].Relay.Until != a.Relay.Until || ps[0].Relay.Device != a.Fingerprint {
		t.Fatalf("alice's relay identity = %+v", ps[0].Relay)
	}
	if ps[1].Relay != nil {
		t.Fatalf("bob has a relay identity: %+v", ps[1].Relay)
	}
	// a record written before relay identities (no key at all) still loads
	raw, _ := json.Marshal([]partyJSON{toJSON(b)})
	if bytes.Contains(raw, []byte(`"relay"`)) {
		t.Fatal("a party without a relay identity writes the key")
	}
}

// SetRelay sets, replaces and clears the relay identity of one party; one for
// another device is refused and nothing changes.
//
// spec: SPO-Xparty-OUT-007, SPO-Xparty-PRE-008
func TestSetRelay(t *testing.T) {
	ctx := context.Background()
	s := newMem()
	a := mkParty(1, "alice")
	if err := s.Update(ctx, func(w ports.NamedWriter) error { return Registry{}.Put(w, a) }); err != nil {
		t.Fatal(err)
	}
	r := withRelay(t, a, 2).Relay
	if err := s.Update(ctx, func(w ports.NamedWriter) error {
		_, err := Registry{}.SetRelay(w, "alice", r)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	ps, _ := load1(t, s)
	if ps[0].Relay == nil || ps[0].Relay.WalletKey != r.WalletKey {
		t.Fatalf("relay = %+v", ps[0].Relay)
	}
	other := withRelay(t, mkParty(5, "x"), 2).Relay
	err := s.Update(ctx, func(w ports.NamedWriter) error { _, err := Registry{}.SetRelay(w, "alice", other); return err })
	if !errors.Is(err, party.ErrRelayIdentity) {
		t.Fatalf("another device's: %v", err)
	}
	if err := s.Update(ctx, func(w ports.NamedWriter) error { _, err := Registry{}.SetRelay(w, "alice", nil); return err }); err != nil {
		t.Fatal(err)
	}
	if ps, _ := load1(t, s); ps[0].Relay != nil {
		t.Fatal("not cleared")
	}
	if err := s.Update(ctx, func(w ports.NamedWriter) error { _, err := Registry{}.SetRelay(w, "nobody", nil); return err }); !errors.Is(err, ports.ErrNotFound) {
		t.Fatalf("unknown name: %v", err)
	}
}

// A relay identity whose record is damaged in its structure: one whose device is
// another than the record's fingerprint, a field the evidence does not say,
// hex that is not canonical, a key the decoder does not know, refuses the whole
// registry as corrupt. (Evidence that is intact as a record but no longer
// verifies is TestUnverifiableRelayIdentityLoadsWithoutARoute.)
//
// spec: SPO-Xparty-OUT-007
func TestTamperedRelayIdentityIsCorrupt(t *testing.T) {
	a := withRelay(t, mkParty(1, "alice"), 1)
	for name, mut := range map[string]func(j map[string]any){
		"oversize statement": func(j map[string]any) {
			r := j["relay"].(map[string]any)
			r["statement"] = strings.Repeat("00", relaybind.MaxSign1Bytes+1)
		},
		"until moved": func(j map[string]any) { r := j["relay"].(map[string]any); r["until"] = r["until"].(float64) + 1 },
		"wallet key":  func(j map[string]any) { r := j["relay"].(map[string]any); r["wallet_key"] = strings.Repeat("ab", 28) },
		"device":      func(j map[string]any) { r := j["relay"].(map[string]any); r["device"] = strings.Repeat("00", 20) },
		"odd hex":     func(j map[string]any) { r := j["relay"].(map[string]any); r["cose_key"] = "abc" },
		"upper-case hex": func(j map[string]any) {
			r := j["relay"].(map[string]any)
			r["cose_key"] = strings.ToUpper(r["cose_key"].(string))
		},
		"unknown relay key": func(j map[string]any) { j["relay"].(map[string]any)["role"] = "payment" },
		"relay is empty":    func(j map[string]any) { j["relay"] = map[string]any{} },
	} {
		raw, _ := json.Marshal([]partyJSON{toJSON(a)})
		var js []map[string]any
		if err := json.Unmarshal(raw, &js); err != nil {
			t.Fatal(err)
		}
		mut(js[0])
		raw, _ = json.Marshal(js)
		s := newMem()
		s.data[recordsRef] = raw
		if _, err := load1(t, s); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A record with a key this version does not know (written by a newer one) is
// refused, never loaded with the key dropped; the one older key it knows, the
// list "pools" of the records before scopes, is still read.
//
// spec: SPO-Xparty-OUT-007
func TestUnknownPartyFieldIsRefused(t *testing.T) {
	a := mkParty(1, "alice")
	raw, _ := json.Marshal([]partyJSON{toJSON(a)})
	var js []map[string]any
	_ = json.Unmarshal(raw, &js)
	js[0]["relay_v2"] = map[string]any{"x": 1}
	raw, _ = json.Marshal(js)
	s := newMem()
	s.data[recordsRef] = raw
	if _, err := load1(t, s); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("unknown key: %v", err)
	}
	// a duplicate key would let two readers see two records
	delete(js[0], "relay_v2")
	raw, _ = json.Marshal(js)
	s.data[recordsRef] = bytes.Replace(raw, []byte(`"name":"alice"`), []byte(`"name":"alice","name":"mallory"`), 1)
	if _, err := load1(t, s); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("duplicate key: %v", err)
	}
}

// Put, Rotate and SetScope keep the relay identity of the others.
//
// spec: SPO-Xparty-OUT-007
func TestRegistryWritesKeepRelayIdentities(t *testing.T) {
	ctx := context.Background()
	s := newMem()
	a := withRelay(t, mkParty(1, "alice"), 1)
	if err := s.Update(ctx, func(w ports.NamedWriter) error {
		if err := (Registry{}).Put(w, a); err != nil {
			return err
		}
		if err := (Registry{}).Put(w, mkParty(3, "bob")); err != nil {
			return err
		}
		_, err := Registry{}.SetScope(w, "bob", party.Scope{Unscoped: true})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	ps, err := load1(t, s)
	if err != nil || ps[0].Relay == nil {
		t.Fatalf("alice after other writes: %+v %v", ps, err)
	}
}

// FuzzLoad: any bytes as the stored registry either load into records that pass
// their own checks or are refused; nothing panics, and a relay identity that
// loads re-verifies.
func FuzzLoad(f *testing.F) {
	a := withRelay(f, mkParty(1, "alice"), 1)
	good, _ := json.Marshal([]partyJSON{toJSON(a), toJSON(mkParty(3, "bob"))})
	f.Add(good)
	f.Add([]byte(`[]`))
	f.Add([]byte(`[{"name":"x","pools":["p"]}]`))
	f.Add([]byte(`[{"relay":{}}]`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<16 {
			return
		}
		s := newMem()
		s.data[recordsRef] = b
		ps, err := load1(t, s)
		if err != nil {
			return
		}
		for _, p := range ps {
			if p.Identity.Fingerprint() != p.Fingerprint {
				t.Fatal("a fingerprint that does not match the keys loaded")
			}
			if p.Relay != nil && p.Relay.Unverified != "" {
				if _, _, ok := relaypeer.Route(p); ok {
					t.Fatal("an unverifiable relay identity routes")
				}
			} else if p.Relay != nil {
				if err := relaypeer.Reverify(*p.Relay, p.Fingerprint); err != nil {
					t.Fatalf("a relay identity that does not verify loaded: %v", err)
				}
			}
		}
	})
}
