package assets

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

const (
	polA = "aa0000000000000000000000000000000000000000000000000000aa"
	polB = "bb0000000000000000000000000000000000000000000000000000bb"
)

func id(pol, name string) chain.AssetID {
	var a chain.AssetID
	b, _ := hex.DecodeString(pol)
	copy(a.Policy[:], b)
	a.Name = []byte(name)
	return a
}

// spec: SPO-11a-IF-003, SPO-11a-PRE-001, SPO-11b-IF-003, SPO-11a-INV-005
func TestAssetNames(t *testing.T) {
	for _, tc := range []struct {
		in    string
		bytes string
		hexed bool
	}{
		{"mytoken", "mytoken", false}, {"", "", false}, {"A1", "A1", false},
		{"{00010203}", "\x00\x01\x02\x03", true}, {"{FF}", "\xff", true}, {"{" + strings.Repeat("ab", 32) + "}", strings.Repeat("\xab", 32), true},
	} {
		n, err := ParseName(tc.in)
		if err != nil || string(n.Bytes) != tc.bytes || n.HexTyped != tc.hexed {
			t.Errorf("%q: %+v %v", tc.in, n, err)
		}
	}
	for _, bad := range []string{"my token", "tok-en", "tökén", "{0001", "{001}", "{zz}", "{" + strings.Repeat("ab", 33) + "}", strings.Repeat("a", 33), "{}"} {
		if _, err := ParseName(bad); !errors.Is(err, ErrBadAssetName) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if DisplayName([]byte("tok")) != "tok" || DisplayName([]byte{0, 1}) != "0001" || DisplayName(nil) != "" || DisplayName([]byte("a b")) != "612062" {
		t.Error("display names")
	}
}

// spec: SPO-11a-IF-001, SPO-11a-IF-002, SPO-11b-IF-002, SPO-11b-OUT-002
func TestRefsAndRecordNames(t *testing.T) {
	r, err := ParseRef("mypolicy.mytoken.asset")
	if err != nil || r.Policy != "mypolicy" || r.Asset != "mytoken" {
		t.Errorf("%+v %v", r, err)
	}
	if r, err = ParseRef("p.{0001}"); err != nil || r.Asset != "{0001}" {
		t.Errorf("%+v %v", r, err)
	}
	// upstream: no dot mints `mypolicy` under `mypolicy`; more than one dot drops the middle
	for _, bad := range []string{"mypolicy", "a.b.c", ".tok", ""} {
		if _, err := ParseRef(bad); !errors.Is(err, ErrBadAssetRef) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if RecordName("p", "tok") != "p.tok" || RecordName("p", "{00FF}") != "p.hex-00ff" {
		t.Error("record names")
	}
}

// spec: SPO-11a-PRE-002, SPO-11b-IF-003
func TestMintAmounts(t *testing.T) {
	for in, want := range map[string]int64{"1": 1, "100": 100, "9223372036854775807": 1<<63 - 1} {
		if got, err := ParseMintAmount(in); err != nil || got != want {
			t.Errorf("%s: %d %v", in, got, err)
		}
	}
	for _, bad := range []string{"0", "-1", "", "abc", "01", "9223372036854775808", "99999999999999999999", "1.5", "+1"} {
		if _, err := ParseMintAmount(bad); !errors.Is(err, ErrBadAmount) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// spec: SPO-10-OUT-005, SPO-10-IF-003, SPO-10-INV-001, SPO-11a-INV-001
func TestPolicyScripts(t *testing.T) {
	h := strings.Repeat("ab", 28)
	if got := string(PolicyScript(h, 0, false)); got != `{ "keyHash": "`+h+`", "type": "sig" }`+"\n" {
		t.Errorf("%q", got)
	}
	locked := PolicyScript(h, 123, true)
	if string(locked) != `{ "type": "all", "scripts": [ { "slot": 123, "type": "before" }, { "keyHash": "`+h+`", "type": "sig" } ] }`+"\n" {
		t.Errorf("%q", locked)
	}
	if slot, ok := Expiry(locked); !ok || slot != 123 {
		t.Errorf("expiry %d %v", slot, ok)
	}
	for _, none := range []string{string(PolicyScript(h, 0, false)), `not json`, `{"type":"all","scripts":[{"type":"after","slot":5}]}`, ``} {
		if _, ok := Expiry([]byte(none)); ok {
			t.Errorf("%q has no expiry", none)
		}
	}
	// the first before entry of the top-level scripts array
	if slot, ok := Expiry([]byte(`{"type":"all","scripts":[{"type":"sig","keyHash":"x"},{"type":"before","slot":9},{"type":"before","slot":5}]}`)); !ok || slot != 9 {
		t.Errorf("first before: %d %v", slot, ok)
	}
	for in, want := range map[string]uint64{"0": 0, "86400": 86400} {
		if got, err := ParseLifetime(in); err != nil || got != want {
			t.Errorf("%s: %d %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "-1", "abc", "1e3", "99999999999999999999"} {
		if _, err := ParseLifetime(bad); err == nil {
			t.Errorf("lifetime %q accepted", bad)
		}
	}
	if ValidBefore(5, true) != "5" || ValidBefore(0, false) != Unlimited {
		t.Error("valid before")
	}
}

func sel(t *testing.T, word, amt string) []Selection {
	t.Helper()
	s, err := ParseSelections(word, amt)
	if err != nil {
		t.Fatalf("%q %q: %v", word, amt, err)
	}
	return s
}

// spec: SPO-01sendAssets-IF-003, SPO-01sendAssets-IF-004, SPO-01sendAssets-IF-007, SPO-01sendAssets-IF-008,
// spec: SPO-01sendAssets-IF-009, SPO-01sendAssets-IF-010, SPO-01sendAssets-IF-011, SPO-01sendAssets-IF-012,
// spec: SPO-01sendAssets-IF-013, SPO-01sendAssets-IF-014
func TestParseSelections(t *testing.T) {
	fp := Fingerprint(id(polB, "tok"))
	kinds := map[string]Kind{
		fp + " 3":                    KindFingerprint,
		polB + "746f6b 3":            KindHexID,
		polB + " 1":                  KindHexID, // the policy id alone: a nameless asset
		polB + ".tok 3":              KindNamed,
		polB + "74* ALL":             KindBulkHex,
		polB + ".to* all":            KindBulkText,
		polB + ".* ALL":              KindBulkText,
		"ALLASSETS":                  KindAllAssets,
		"forceada":                   KindForceAda,
		"mypolicy.mytoken 5":         KindFile,
		"dir/mypolicy.mytoken.asset": KindFile, // an amount follows below
	}
	for in, kind := range kinds {
		word := in
		if kind == KindFile && !strings.Contains(in, " ") {
			word += " 2"
		}
		got := sel(t, word, "")
		if len(got) != 1 || got[0].Kind != kind {
			t.Errorf("%q: %+v, want kind %d", in, got, kind)
		}
	}
	// the fingerprint and the hex form name the same asset
	a, b, c := sel(t, fp+" 1", "")[0], sel(t, polB+"746f6b 1", "")[0], sel(t, polB+".tok 1", "")[0]
	if a.Fingerprint != b.Fingerprint || b.Fingerprint != c.Fingerprint {
		t.Error("fingerprints differ")
	}
	// the amount: in the word, or as the fourth word; ALL in any case; keywords need none
	if s := sel(t, polB+".tok", "ALL"); !s[0].All {
		t.Error("amount word ALL")
	}
	if s := sel(t, "ALLASSETS", ""); !s[0].All || s[0].Amount != 0 {
		t.Error("keyword amount")
	}
	two := sel(t, polB+".tok 7|"+polA+".A 24", "")
	if len(two) != 2 || two[0].Amount != 7 || two[1].Amount != 24 {
		t.Errorf("%+v", two)
	}
	for _, bad := range []struct{ w, a string }{
		{"", ""}, {polB + ".tok", ""}, {polB + ".tok 0", ""}, {polB + ".tok -1", ""}, {polB + ".tok x", ""}, {polB + ".tok 1 2", ""},
		{polB + ".tok 7|" + polA + ".A", ""}, {polB + ".tok 7", "3"}, {polB + ".* 5", ""}, {polB + "74* 5", ""}, {polB + ".tok 01", ""},
		{"asset1" + strings.Repeat("q", 38), ""}, {"asset1" + strings.Repeat("q", 38) + " 1", ""},
	} {
		if _, err := ParseSelections(bad.w, bad.a); !errors.Is(err, ErrBadSelection) {
			t.Errorf("%q %q: %v", bad.w, bad.a, err)
		}
	}
}

func held(items ...chain.AssetAmount) []Held { return HeldAssets(items) }

func amt(pol, name string, q uint64) chain.AssetAmount {
	return chain.AssetAmount{Asset: id(pol, name), Quantity: q}
}

// spec: SPO-01sendAssets-INV-001, SPO-01sendAssets-INV-002, SPO-01sendAssets-INV-003, SPO-01sendAssets-INV-004,
// spec: SPO-01sendAssets-INV-005, SPO-01sendAssets-PRE-002, SPO-01sendAssets-PRE-003, SPO-01sendAssets-PR-001, SPO-01sendAssets-IF-011,
// spec: SPO-01sendAssets-IF-013
func TestResolve(t *testing.T) {
	h := held(amt(polA, "", 1), amt(polA, "A", 24), amt(polA, "Ab", 2), amt(polB, "tok", 7))
	plan := func(word string, keep [][28]byte, sum bool) (Plan, error) {
		return Resolve(sel(t, word, ""), h, keep, sum)
	}
	show := func(p Plan) string {
		var s []string
		for _, a := range p.Send {
			s = append(s, fmt.Sprintf("%x.%s=%d", a.Asset.Policy[:1], a.Asset.Name, a.Quantity))
		}
		return strings.Join(s, ",")
	}
	ok := func(word string, keep [][28]byte, sum bool, want string) {
		t.Helper()
		p, err := plan(word, keep, sum)
		if err != nil || show(p) != want {
			t.Errorf("%q: %s (%v), want %s", word, show(p), err, want)
		}
	}
	ok(polB+".tok 3", nil, false, "bb.tok=3")
	ok(polB+".tok ALL", nil, false, "bb.tok=7")
	ok(polA+" 1", nil, false, "aa.=1")
	// the same asset named twice is one selection; the amounts add, ALL wins
	ok(polB+".tok 3|"+polB+"746f6b 2", nil, true, "bb.tok=5")
	ok(polB+".tok 3|"+polB+"746f6b ALL", nil, true, "bb.tok=7")
	if _, err := plan(polB+".tok 3|"+polB+"746f6b 2", nil, false); !errors.Is(err, ErrDuplicateAsset) {
		t.Errorf("a duplicate without agreement: %v", err)
	}
	if _, err := plan(polB+".tok 5|"+polB+"746f6b 4", nil, true); !errors.Is(err, ErrAmountTooHigh) {
		t.Errorf("the sum above the total: %v", err)
	}
	// bulk: by text prefix over named assets only, by hex prefix
	ok(polA+".* ALL", nil, false, "aa.A=24,aa.Ab=2")
	ok(polA+".A* ALL", nil, false, "aa.A=24,aa.Ab=2")
	ok(polA+".Ab* ALL", nil, false, "aa.Ab=2")
	ok(polA+"41* ALL", nil, false, "aa.A=24,aa.Ab=2")
	// a bulk selection does not clash with an explicit one
	ok(polA+".A 5|"+polA+".* ALL", nil, false, "aa.A=24,aa.Ab=2")
	// every asset, less the kept policies
	ok("ALLASSETS", nil, false, "aa.=1,aa.A=24,aa.Ab=2,bb.tok=7")
	var keepA [28]byte
	keepA = id(polA, "").Policy
	ok("ALLASSETS", [][28]byte{keepA}, false, "bb.tok=7")
	ok("FORCEADA", [][28]byte{keepA, id(polB, "").Policy}, false, "")
	if _, err := plan("ALLASSETS", [][28]byte{keepA, id(polB, "").Policy}, false); !errors.Is(err, ErrNoAssets) {
		t.Errorf("ALLASSETS without assets: %v", err)
	}
	// the refusals
	for _, w := range []string{polB + ".zzz 1", polA + ".Q* ALL", polB + ".tok 8", "cc00000000000000000000000000000000000000000000000000000c.x 1"} {
		if _, err := plan(w, nil, false); !errors.Is(err, ErrAssetAbsent) && !errors.Is(err, ErrAmountTooHigh) {
			t.Errorf("%q: %v", w, err)
		}
	}
	if d := Duplicates(sel(t, polB+".tok 1|"+polB+"746f6b 1|"+polA+".A 1", "")); len(d) != 1 {
		t.Errorf("duplicates %v", d)
	}
}

// spec: SPO-11a-OUT-002, SPO-11a-OUT-003, SPO-11a-INV-005, SPO-11b-OUT-001, SPO-Pfiles-OUT-033, SPO-01sendAssets-IF-014
func TestRecordUpdates(t *testing.T) {
	date := time.Date(2026, 11, 16, 9, 51, 2, 0, time.FixedZone("", 3600))
	c := Change{Asset: id(polA, "tok"), Delta: 100, ValidBefore: "unlimited", Action: "mint 100", Date: date}
	empty, err := ParseRecord(nil)
	if err != nil {
		t.Fatal(err)
	}
	r1, err := empty.Apply(c)
	if err != nil {
		t.Fatal(err)
	}
	if r1.Get("minted") != "100" || r1.Get("name") != "tok" || r1.Get("hexname") != "" || r1.Get("policyID") != polA ||
		r1.Get("subject") != polA+"746f6b" || r1.Get("lastUpdate") != "Mon, 16 Nov 2026 09:51:02 +0100" || r1.Get("bechName") != Fingerprint(c.Asset) {
		t.Errorf("%s", r1.Marshal())
	}
	if strings.Contains(string(r1.Marshal()), "metaDecimals") || !strings.HasSuffix(string(r1.Marshal()), "}\n") || !strings.HasPrefix(string(r1.Marshal()), "{\n  \"metaName\": \"tok\",\n") {
		t.Errorf("the skeleton: %s", r1.Marshal())
	}
	// the operator's edits win, a burn subtracts, minted may go negative, extra keys survive in place
	edited := strings.Replace(string(r1.Marshal()), `"metaTicker": ""`, `"metaTicker": "TOK"`, 1)
	edited = strings.Replace(edited, "}\n", `, "custom": {"a": [1, 2]}}`, 1)
	rec, err := ParseRecord([]byte(edited))
	if err != nil {
		t.Fatal(err)
	}
	r2, err := rec.Apply(Change{Asset: id(polA, "tok"), Delta: -130, ValidBefore: "unlimited", Action: "burn 130", Date: date})
	if err != nil {
		t.Fatal(err)
	}
	if r2.Get("minted") != "-30" || r2.Get("metaTicker") != "TOK" || r2.Get("lastAction") != "burn 130" {
		t.Errorf("%s", r2.Marshal())
	}
	if !strings.Contains(string(r2.Marshal()), "\"custom\": {\n    \"a\": [\n      1,\n      2\n    ]\n  }") {
		t.Errorf("a key the operator added is kept: %s", r2.Marshal())
	}
	// a hex-typed name keeps its hex; a 64-bit overflow is no problem for the record
	big := Change{Asset: id(polA, "\x00\x01"), HexTyped: true, Delta: 1<<63 - 1, ValidBefore: "5", Action: "mint", Date: date}
	r3, _ := empty.Apply(big)
	r3, _ = r3.Apply(big)
	if r3.Get("hexname") != "0001" || r3.Get("minted") != "18446744073709551614" || r3.Get("name") != "0001" {
		t.Errorf("%s", r3.Marshal())
	}
	// fields for 01_sendAssets
	f := r1.Fields()
	if a, err := f.AssetOf(); err != nil || string(a.Name) != "tok" {
		t.Errorf("%+v %v", a, err)
	}
	if a, err := r3.Fields().AssetOf(); err != nil || string(a.Name) != "\x00\x01" {
		t.Errorf("%+v %v", a, err)
	}
	for _, bad := range []RecordFields{{PolicyID: "zz"}, {PolicyID: polA, Name: "not alnum!", HexName: ""}} {
		if _, err := bad.AssetOf(); !errors.Is(err, ErrBadSelection) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
	if _, err := ParseRecord([]byte(`[1]`)); !errors.Is(err, ErrBadRecord) {
		t.Errorf("a record that is not an object: %v", err)
	}
	// the pending update round-trips
	p := Pending{TxID: "ab", Record: "p.tok", Policy: polA, NameHex: "746f6b", Delta: "-5", ValidBefore: "unlimited", Action: "burn 5 (only Offline proof)"}
	b, _ := p.Marshal()
	back, err := ParsePending(b)
	if err != nil {
		t.Fatal(err)
	}
	cc, err := back.Change(date)
	if err != nil || cc.Delta != -5 || string(cc.Asset.Name) != "tok" || cc.Action != p.Action {
		t.Errorf("%+v %v", cc, err)
	}
}
