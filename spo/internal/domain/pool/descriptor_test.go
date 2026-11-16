package pool

import (
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

const goodDescriptor = `{
  "poolName": "mypool",
  "poolOwner": [
    {
    "ownerName": "alice",
    "ownerWitness": "local"
    },
    {"ownerName": "bob"}
  ],
  "poolRewards": "alice",
  "poolPledge": "100000000000",
  "poolCost": "340000000",
  "poolMargin": "0.10",
  "poolRelays": [
    {"relayType": "ip", "relayEntry": "203.0.113.7", "relayPort": "3001"},
    {"relayType": "SRV", "relayEntry": "_cardano._tcp.example.org"}
  ],
  "poolMetaName": "My Pool",
  "poolMetaDescription": "A pool",
  "poolMetaTicker": "MYPL",
  "poolMetaHomepage": "https://example.org",
  "poolMetaUrl": "https://example.org/mypool.metadata.json",
  "poolExtendedMetaUrl": "",
  "---": "--- DO NOT EDIT OR DELETE BELOW THIS LINE ---"
}
`

func parse(t *testing.T, s string) *Descriptor {
	t.Helper()
	d, err := ParseDescriptor([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// set replaces a field of the descriptor for a test.
func set(t *testing.T, d *Descriptor, key string, v any) *Descriptor {
	t.Helper()
	d.doc.setAny(key, v)
	return d
}

// spec: SPO-05a-PRE-001
func TestUnparsableDescriptorIsRefused(t *testing.T) {
	for _, s := range []string{"", "[]", "{", `{"a":1} x`} {
		if _, err := ParseDescriptor([]byte(s)); !errors.Is(err, ErrBadDescriptor) {
			t.Errorf("%q: %v", s, err)
		}
	}
}

// spec: SPO-05a-IN-001, SPO-05a-IN-002, SPO-05a-OUT-004, SPO-05a-OUT-005
func TestRequiredFieldsAndOwnerForms(t *testing.T) {
	for _, f := range []string{"poolName", "poolOwner", "poolRewards", "poolPledge", "poolCost", "poolMargin", "poolRelays",
		"poolMetaName", "poolMetaTicker", "poolMetaHomepage", "poolMetaUrl", "poolMetaDescription"} {
		d := parse(t, goodDescriptor)
		d.doc.del(f)
		if _, err := d.Check(1, Choices{}); !errors.Is(err, ErrMissingField) || !strings.Contains(err.Error(), f) {
			t.Errorf("without %s: %v", f, err)
		}
		d = set(t, parse(t, goodDescriptor), f, "")
		if _, err := d.Check(1, Choices{}); !errors.Is(err, ErrMissingField) {
			t.Errorf("empty %s: %v", f, err)
		}
	}
	// The legacy single string is an owner, normalised to an array with "local".
	d := set(t, parse(t, goodDescriptor), "poolOwner", "solo")
	reg, err := d.Check(1, Choices{})
	if err != nil || !reg.Legacy || len(reg.Owners) != 1 || reg.Owners[0].Name != "solo" {
		t.Fatalf("legacy owner: %+v %v", reg, err)
	}
	d.NormalizeOwners(reg.Owners)
	if o, legacy, _ := d.Owners(); legacy || len(o) != 1 || o[0].Witness != "local" {
		t.Errorf("normalised owners %+v legacy=%v", o, legacy)
	}
	// An owner without ownerWitness gets "local"; others stay.
	d = parse(t, goodDescriptor)
	reg, _ = d.Check(1, Choices{})
	d.NormalizeOwners(reg.Owners)
	if o, _, _ := d.Owners(); o[0].Witness != "local" || o[1].Witness != "local" {
		t.Errorf("owner witnesses %+v", o)
	}
	for _, w := range []string{"", "local", "LOCAL", "Local"} {
		if !(DescriptorOwner{Witness: w}).IsLocal() {
			t.Errorf("%q should be local", w)
		}
	}
	if (DescriptorOwner{Witness: "external"}).IsLocal() {
		t.Error("external is not local")
	}
}

// spec: SPO-05a-PRE-002
func TestPoolNameMustMatch(t *testing.T) {
	d := parse(t, goodDescriptor)
	if err := d.CheckName("mypool"); err != nil {
		t.Error(err)
	}
	if err := d.CheckName("other"); !errors.Is(err, ErrNameMismatch) {
		t.Errorf("%v", err)
	}
}

// spec: SPO-05a-PRE-004, SPO-05a-PR-001, SPO-05a-OUT-002
func TestCostBelowMinimum(t *testing.T) {
	d := parse(t, goodDescriptor)
	_, err := d.Check(500_000_000, Choices{})
	var ce *CostBelowMinimumError
	if !errors.As(err, &ce) || ce.Cost != 340_000_000 || ce.Min != 500_000_000 || !errors.Is(err, ErrCostBelowMinimum) {
		t.Fatalf("%v", err)
	}
	reg, err := d.Check(500_000_000, Choices{RaiseCost: true})
	if err != nil || reg.Cost != 500_000_000 || len(reg.Corrections) != 1 || reg.Corrections[0] != (Correction{"poolCost", "500000000"}) {
		t.Fatalf("%+v %v", reg, err)
	}
	d.Apply(reg.Corrections)
	if d.Text(FieldCost) != "500000000" {
		t.Errorf("cost %q", d.Text(FieldCost))
	}
	// A non-numeric cost is refused, where bash reads it as 0, which is too low.
	if _, err := set(t, parse(t, goodDescriptor), "poolCost", "abc").Check(1, Choices{}); err == nil {
		t.Error("abc accepted")
	}
}

// spec: SPO-05a-PRE-005
func rat(n, d uint64) chain.Rational { return chain.Rational{Num: n, Den: d} }

func TestMargin(t *testing.T) {
	good := map[string]chain.Rational{"0": rat(0, 1), "0.00": rat(0, 1), "0.01": rat(1, 100), "0.10": rat(1, 10), "1": rat(1, 1), "1.00": rat(1, 1),
		"0.333333": rat(333333, 1000000), "0.5": rat(1, 2), "0.25": rat(1, 4)}
	for in, want := range good {
		if got, err := ParseMargin(in); err != nil || got != want {
			t.Errorf("%q: %v %v, want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", ".5", "1.01", "2", "-0.1", "abc", "1/3", "0.1.2", "0.", "1e-1", "0.12345678901234567890123"} {
		if _, err := ParseMargin(in); !errors.Is(err, ErrBadMargin) {
			t.Errorf("%q accepted: %v", in, err)
		}
	}
}

// spec: SPO-05a-INV-002
func TestPledgeAndCostAreWholeLovelace(t *testing.T) {
	for _, in := range []string{"0", "1", "18446744073709551615"} {
		if _, err := ParseLovelace(in); err != nil {
			t.Errorf("%q: %v", in, err)
		}
	}
	for _, in := range []string{"", "-1", "+1", "1.5", "abc", "18446744073709551616", " 1"} {
		if _, err := ParseLovelace(in); !errors.Is(err, ErrBadLovelace) {
			t.Errorf("%q accepted", in)
		}
	}
}

// spec: SPO-05a-EXT-001, SPO-05a-PRE-006, SPO-05a-PRE-007, SPO-05a-PRE-008
func TestRelays(t *testing.T) {
	ok := map[DescriptorRelay]Relay{
		{"ip", "203.0.113.7", "3001"}:             {Kind: RelayIPv4, Host: "203.0.113.7", Port: 3001, HasPort: true},
		{"IP4", "10.0.0.1", "1"}:                  {Kind: RelayIPv4, Host: "10.0.0.1", Port: 1, HasPort: true},
		{"IPv4", "10.0.0.1", "0"}:                 {Kind: RelayIPv4, Host: "10.0.0.1", HasPort: true},
		{"IPV6", "2001:db8::1", "6000"}:           {Kind: RelayIPv6, Host: "2001:db8::1", Port: 6000, HasPort: true},
		{"ip6", "2001:db8::1", "6000"}:            {Kind: RelayIPv6, Host: "2001:db8::1", Port: 6000, HasPort: true},
		{"dns", "relay.example.org", "3001"}:      {Kind: RelayDNS, Host: "relay.example.org", Port: 3001, HasPort: true},
		{"SRV", "_c._tcp.example.org", ""}:        {Kind: RelaySRV, Host: "_c._tcp.example.org"},
		{"multisrv", "_c._tcp.example.org", "99"}: {Kind: RelaySRV, Host: "_c._tcp.example.org"},
	}
	for in, want := range ok {
		if got, err := ParseRelay(in); err != nil || got != want {
			t.Errorf("%+v: %+v %v", in, got, err)
		}
	}
	bad := []DescriptorRelay{
		{"ip", "", "1"}, {"", "1.2.3.4", "1"}, {"ip", "1.2.3.4", ""}, {"dns", "a.b", ""}, {"ip", "1.2.3.4", "70000"},
		{"ip", "1.2.3.4", "x"}, {"ip", "::1", "1"}, {"ip6", "1.2.3.4", "1"}, {"tor", "a.onion", "1"},
		{"ip", strings.Repeat("1", 129), "1"}, {"dns", strings.Repeat("a", 65), "1"},
	}
	for _, in := range bad {
		if _, err := ParseRelay(in); !errors.Is(err, ErrBadRelay) {
			t.Errorf("%+v accepted: %v", in, err)
		}
	}
	// An empty list is accepted and gives a certificate without relays.
	d := set(t, parse(t, goodDescriptor), "poolRelays", []DescriptorRelay{})
	reg, err := d.Check(1, Choices{})
	if err != nil || len(reg.Relays) != 0 {
		t.Errorf("empty relays: %+v %v", reg.Relays, err)
	}
	if err := CheckRelays([]Relay{{Kind: RelayIPv4}, {Kind: RelayDNS}, {Kind: RelayIPv6}}); err != nil {
		t.Errorf("v4, dns, v6: %v", err)
	}
	if err := CheckRelays([]Relay{{Kind: RelayIPv6}, {Kind: RelayIPv4}}); !errors.Is(err, ErrBadRelay) {
		t.Errorf("v6, v4: %v", err)
	}
}

// spec: SPO-05a-PRE-009, SPO-05a-PRE-010, SPO-05a-PR-002
func TestMetadataLimitsAndTicker(t *testing.T) {
	over := map[string]string{
		"poolMetaName":        strings.Repeat("n", 51),
		"poolMetaDescription": strings.Repeat("d", 256),
		"poolMetaHomepage":    "https://" + strings.Repeat("h", 121),
		"poolMetaUrl":         "https://" + strings.Repeat("u", 121),
		"poolMetaTicker":      "TOOLONG",
	}
	for f, v := range over {
		if _, err := set(t, parse(t, goodDescriptor), f, v).Check(1, Choices{}); !errors.Is(err, ErrMetadataLimit) {
			t.Errorf("%s: %v", f, err)
		}
	}
	atLimit := map[string]string{"poolMetaName": strings.Repeat("n", 50), "poolMetaDescription": strings.Repeat("d", 255), "poolMetaHomepage": "https://" + strings.Repeat("h", 120)}
	for f, v := range atLimit {
		if _, err := set(t, parse(t, goodDescriptor), f, v).Check(1, Choices{}); err != nil {
			t.Errorf("%s at the limit: %v", f, err)
		}
	}
	// The match is unanchored: http:// in the middle passes (SPO-05a-PRE-009).
	if _, err := set(t, parse(t, goodDescriptor), "poolMetaHomepage", "see http://x").Check(1, Choices{}); err != nil {
		t.Errorf("unanchored match: %v", err)
	}
	if _, err := set(t, parse(t, goodDescriptor), "poolMetaHomepage", "ftp://x").Check(1, Choices{}); !errors.Is(err, ErrMetadataLimit) {
		t.Errorf("ftp: %v", err)
	}
	// Ticker: sanitised, never upper-cased; a correction needs the operator.
	if got := SanitizeTicker("a-b c"); got != "a_b_c" {
		t.Errorf("sanitised %q", got)
	}
	d := set(t, parse(t, goodDescriptor), "poolMetaTicker", "ab-c")
	_, err := d.Check(1, Choices{})
	var te *TickerCorrectionError
	if !errors.As(err, &te) || te.To != "ab_c" {
		t.Fatalf("%v", err)
	}
	reg, err := d.Check(1, Choices{AcceptTicker: true})
	if err != nil || reg.Meta.Ticker != "ab_c" || reg.Corrections[0] != (Correction{"poolMetaTicker", "ab_c"}) {
		t.Fatalf("%+v %v", reg, err)
	}
	// 3 to 5 characters after sanitising, counted as characters.
	for tk, ok := range map[string]bool{"ab": false, "abc": true, "abcde": true, "abcdef": false, "äöü": true} {
		_, err := set(t, parse(t, goodDescriptor), "poolMetaTicker", tk).Check(1, Choices{})
		if ok != (err == nil) {
			t.Errorf("ticker %q: %v", tk, err)
		}
	}
}

// spec: SPO-05a-INV-003, SPO-05a-IN-003
func TestExtendedMetadataThreshold(t *testing.T) {
	ext := func(n int) string { return "https://" + strings.Repeat("e", n-8) }
	for n, want := range map[int]bool{64: true, 65: false, 128: false} {
		reg, err := set(t, parse(t, goodDescriptor), "poolExtendedMetaUrl", ext(n)).Check(1, Choices{})
		if err != nil || (reg.ExtendedURL != "") != want {
			t.Errorf("%d characters: %+v %v", n, reg.ExtendedURL, err)
		}
		if !want && len(reg.Warnings) == 0 {
			t.Errorf("%d characters: no warning for the silently dropped extended metadata", n)
		}
	}
	if _, err := set(t, parse(t, goodDescriptor), "poolExtendedMetaUrl", ext(129)).Check(1, Choices{}); !errors.Is(err, ErrMetadataLimit) {
		t.Errorf("129: %v", err)
	}
	// An absent or non-URL value means no extended metadata.
	d := parse(t, goodDescriptor)
	d.doc.del("poolExtendedMetaUrl")
	if reg, err := d.Check(1, Choices{}); err != nil || reg.ExtendedURL != "" {
		t.Errorf("absent: %v", err)
	}
}

// spec: SPO-05a-OUT-007, SPO-05a-PRE-012
func TestMetadataFile(t *testing.T) {
	m := Metadata{Name: "N", Description: "D", Ticker: "TICK", Homepage: "https://h"}
	want := "{\n  \"name\": \"N\",\n  \"description\": \"D\",\n  \"ticker\": \"TICK\",\n  \"homepage\": \"https://h\"\n}\n"
	if got := string(m.Render()); got != want {
		t.Errorf("%q", got)
	}
	m.Extended = "https://e"
	if got := string(m.Render()); !strings.Contains(got, "\"homepage\": \"https://h\",\n  \"extended\": \"https://e\"\n}") {
		t.Errorf("%q", got)
	}
	// Values are escaped, not interpolated.
	m = Metadata{Name: `a "quoted" \ name`, Description: "<b>", Ticker: "TICK", Homepage: "https://h"}
	if got := string(m.Render()); !strings.Contains(got, `"name": "a \"quoted\" \\ name"`) || !strings.Contains(got, `"<b>"`) {
		t.Errorf("%q", got)
	}
	if err := CheckMetadataSize(make([]byte, 512)); err != nil {
		t.Error(err)
	}
	if err := CheckMetadataSize(make([]byte, 513)); !errors.Is(err, ErrMetadataLimit) {
		t.Errorf("513: %v", err)
	}
}

// spec: SPO-05a-OUT-006, SPO-05a-PRE-011
func TestExtendedMetadataRender(t *testing.T) {
	got, err := MergeExtended([]byte(`{"info": {"a": 1}, "list": [1,2]}`))
	if err != nil || string(got) != "{\n  \"info\": {\n    \"a\": 1\n  },\n  \"list\": [\n    1,\n    2\n  ]\n}\n" {
		t.Errorf("%q %v", got, err)
	}
	for _, bad := range []string{"", "{", "[]", `"x"`} {
		if _, err := MergeExtended([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// spec: SPO-05a-OUT-003
func TestAdditionalMetadataTemplateHoldsThePoolID(t *testing.T) {
	got := string(AdditionalMetadataTemplate("abc"))
	if strings.Count(got, `"abc"`) != 2 || !strings.Contains(got, "my-pool-ids") || !strings.Contains(got, "when-satured-then-recommend") {
		t.Errorf("%s", got)
	}
}

// spec: SPO-05a-OUT-009, SPO-05a-OUT-011, SPO-05a-OUT-012, SPO-05a-OUT-013, SPO-05a-OUT-001, SPO-05a-OUT-008
func TestRecordingKeepsOrderAndOtherFields(t *testing.T) {
	d := parse(t, goodDescriptor)
	d.doc.setAny(FieldRegEpoch, "5")
	d.doc.setAny(FieldRegSubmitted, "then")
	d.doc.set(FieldRegWitness, []byte(`{"id": 1}`))
	d.RecordGeneration("aa", "pool1x", "hh", "now", "mypool.pool.cert", "secret")
	out := string(d.Render())
	idx := func(k string) int { return strings.Index(out, `"`+k+`"`) }
	order := []string{"---", "regEpoch", "regSubmitted", "regWitness", "poolID", "poolIDbech", "poolMetaHash", "regCertCreated", "regCertFile", "regProtectionKey"}
	for i := 1; i < len(order); i++ {
		if idx(order[i-1]) >= idx(order[i]) || idx(order[i]) < 0 {
			t.Errorf("%s should come after %s:\n%s", order[i], order[i-1], out)
		}
	}
	if !strings.HasSuffix(out, "}\n") || !strings.Contains(out, "\n  \"poolID\": \"aa\",") {
		t.Errorf("not rendered as jq does:\n%s", out)
	}
	// Running again keeps position and values of regEpoch and regWitness.
	d.RecordGeneration("aa", "pool1x", "h2", "later", "mypool.pool.cert", "")
	if d.Text("regEpoch") != "5" || !d.Has(FieldRegWitness) || d.Text(FieldMetaHash) != "h2" || d.Text(FieldRegProtection) != "secret" {
		t.Errorf("a re-run lost a field:\n%s", d.Render())
	}
	// The descriptor reads back identical.
	if again := parse(t, string(d.Render())); string(again.Render()) != string(d.Render()) {
		t.Errorf("render is not stable")
	}
}

// spec: SPO-07a-OUT-002
func TestRetirementRecordKeepsDeregSubmitted(t *testing.T) {
	d := parse(t, goodDescriptor)
	d.doc.setAny(FieldDeregSubmit, "before")
	d.RecordRetirementCert("now", "mypool.pool.dereg-cert", 42)
	if d.Text(FieldDeregEpoch) != "42" || d.Text(FieldDeregSubmit) != "before" || d.Text(FieldDeregFile) != "mypool.pool.dereg-cert" {
		t.Errorf("%s", d.Render())
	}
	if !strings.Contains(string(d.Render()), `"deregEpoch": "42"`) {
		t.Error("the epoch is a string")
	}
}

// spec: SPO-05c-OUT-005, SPO-07b-OUT-001
func TestSubmissionRecords(t *testing.T) {
	d := parse(t, goodDescriptor)
	d.doc.set(FieldRegWitness, []byte(`{"id": 7}`))
	d.RecordSubmission("12", "when")
	if d.Has(FieldRegWitness) || d.Text(FieldRegEpoch) != "12" || d.Text(FieldRegSubmitted) != "when" {
		t.Errorf("%s", d.Render())
	}
	d.RecordRetirement("then")
	if d.Text(FieldDeregSubmit) != "then" {
		t.Error("deregSubmitted")
	}
}

// spec: SPO-05c-INV-002, SPO-05c-PRE-004, SPO-05c-MODE-001, SPO-05c-MODE-002, SPO-05c-MODE-003
func TestRegistrationTypeDecision(t *testing.T) {
	val := func(s chain.PoolStatus) *chain.Reading[chain.PoolState] {
		r := chain.Value(chain.PoolState{Status: s})
		return &r
	}
	none, unknown := chain.None[chain.PoolState](), chain.Unknown[chain.PoolState]("down")
	cases := []struct {
		name string
		in   TypeInput
		want RegistrationType
		err  error
	}{
		{"forced registration wins over the chain", TypeInput{Forced: PoolRegistration, Chain: val(chain.PoolRegistered)}, PoolRegistration, nil},
		{"forced re-registration after a retirement", TypeInput{Forced: PoolReRegistration, DeregSubmitted: true}, PoolReRegistration, nil},
		{"retired before without a choice", TypeInput{DeregSubmitted: true, Chain: val(chain.PoolRegistered)}, "", ErrChooseType},
		{"registered on chain", TypeInput{Chain: val(chain.PoolRegistered)}, PoolReRegistration, nil},
		{"retiring on chain", TypeInput{Chain: val(chain.PoolRetiring)}, PoolReRegistration, nil},
		{"retired on chain", TypeInput{Chain: val(chain.PoolRetired)}, PoolRegistration, nil},
		{"never registered", TypeInput{Chain: &none}, PoolRegistration, nil},
		{"offline, never queued", TypeInput{}, PoolRegistration, nil},
		{"offline, queued before", TypeInput{DescriptorRegistered: true}, PoolReRegistration, nil},
	}
	for _, c := range cases {
		got, err := DecideType(c.in)
		if got != c.want || !errors.Is(err, c.err) {
			t.Errorf("%s: %q %v", c.name, got, err)
		}
	}
	// Unknown is never "not registered".
	if got, err := DecideType(TypeInput{Chain: &unknown}); err == nil || got != "" {
		t.Errorf("unknown: %q %v", got, err)
	}
}

// spec: SPO-Pfiles-OUT-017
func TestLifecycle(t *testing.T) {
	d := parse(t, goodDescriptor)
	if LifecycleOf(d, nil, 0) != LifecycleDraft {
		t.Error("draft")
	}
	d.RecordGeneration("a", "b", "c", "d", "mypool.pool.cert", "")
	if LifecycleOf(d, nil, 0) != LifecycleCertificateIssued {
		t.Error("issued")
	}
	d.RecordSubmission("1", "t")
	if LifecycleOf(d, nil, 0) != LifecycleRegistered {
		t.Error("registered")
	}
	d.RecordRetirement("t")
	if LifecycleOf(d, nil, 0) != LifecycleRetirementScheduled {
		t.Error("retirement scheduled")
	}
}
