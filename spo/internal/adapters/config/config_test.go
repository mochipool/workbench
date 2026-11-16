package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// spec: SPO-Cconf-INV-004, SPO-Cconf-INV-006, SPO-Cconf-INV-011
//
// The presets are the values the spec states.
func TestPresetsMatchTheSpec(t *testing.T) {
	want := map[string]Preset{
		"mainnet": {Magic: "mainnet", ByronToShelleyEpochs: 208, KoiosURL: "https://api.koios.rest/api/v1", HandleURL: "https://api.handle.me",
			LightParametersURL: "https://uptime.live/data/cardano/parms/mainnet-parameters.json", AddressPrefix: "addr"},
		"preprod": {Magic: "1", ByronToShelleyEpochs: 4, KoiosURL: "https://preprod.koios.rest/api/v1", HandleURL: "https://preprod.api.handle.me",
			LightParametersURL: "https://uptime.live/data/cardano/parms/preprod-parameters.json", AddressPrefix: "addr_test"},
		"preview": {Magic: "2", ByronToShelleyEpochs: 0, KoiosURL: "https://preview.koios.rest/api/v1", HandleURL: "https://preview.api.handle.me",
			LightParametersURL: "https://uptime.live/data/cardano/parms/preview-parameters.json", AddressPrefix: "addr_test"},
	}
	if got := Networks(); strings.Join(got, ",") != "mainnet,preprod,preview" {
		t.Fatalf("networks %v", got)
	}
	for n, w := range want {
		g, ok := PresetFor(n)
		w.Name = n
		if !ok || g != w {
			t.Errorf("%s: got %+v want %+v", n, g, w)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	for _, c := range []Config{
		{Network: "preview", Mode: ModeOffline},
		{Network: "preprod", Mode: ModeLight, Koios: &Koios{}},
		{Network: "mainnet", Mode: ModeLight, Koios: &Koios{URL: "https://koios.example/api/v1"}},
	} {
		b, err := Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Parse(b)
		if err != nil {
			t.Fatalf("%v\n%s", err, b)
		}
		if got.Network != c.Network || got.Mode != c.Mode || (got.Koios == nil) != (c.Koios == nil) ||
			(c.Koios != nil && got.Koios.URL != c.Koios.URL) {
			t.Errorf("got %+v want %+v", got, c)
		}
	}
}

func TestHardwareAndHandlesSections(t *testing.T) {
	c := Config{Network: "preview", Mode: ModeOffline,
		Hardware: &Hardware{WaitSeconds: 120, MinLedger: "8.1.0", MinTrezor: "2.8.0", MinKeystone: "1.8.0"},
		Handles:  &Handles{URL: "https://handles.example"}}
	b, err := Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(b)
	if err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	if *got.Hardware != *c.Hardware || *got.Handles != *c.Handles {
		t.Errorf("got %+v %+v\n%s", got.Hardware, got.Handles, b)
	}
	if got.HandleURL() != "https://handles.example" || (Config{Network: "preprod"}).HandleURL() != "https://preprod.api.handle.me" {
		t.Error("handle url")
	}
	// A bare section keeps every default.
	g, err := Parse([]byte("network = \"preview\"\nmode = \"offline\"\n[hardware]\n"))
	if err != nil || g.Hardware == nil || *g.Hardware != (Hardware{}) {
		t.Errorf("%v %+v", err, g.Hardware)
	}
	for _, c := range []struct{ text, want string }{
		{"[hardware]\nwait_seconds = 0\n", "wait_seconds must be 1 to 3600"},
		{"[hardware]\nwait_seconds = 99999\n", "wait_seconds must be 1 to 3600"},
		{"[hardware]\nwait_seconds = \"5\"\n", "must be a whole number"},
		{"[hardware]\nmin_ledger = \"new\"\n", ""},
		{"[hardware]\nmin_ledger = 8\n", "must be a string"},
		{"[hardware]\nvendor = \"x\"\n", `unknown key "vendor" in [hardware]`},
		{"[handles]\ntoken = \"x\"\n", `unknown key "token" in [handles]`},
	} {
		_, err := Parse([]byte("network = \"preview\"\nmode = \"offline\"\n" + c.text))
		if c.want == "" {
			// min_ledger "new" is checked by Validate, at parse time.
			c.want = "is not a version"
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: got %v, want %q", c.text, err, c.want)
		}
	}
}

func TestStrictSchema(t *testing.T) {
	cases := []struct{ name, text, want string }{
		{"unknown key", "network = \"preview\"\nmode = \"offline\"\ncolour = \"red\"\n", `unknown key "colour"`},
		{"unknown key in section", "network = \"preview\"\nmode = \"light\"\n[koios]\ntoken = \"abc\"\n", `unknown key "token" in [koios]`},
		{"unknown section", "network = \"preview\"\nmode = \"offline\"\n[ogmios]\n", "unknown section [ogmios]"},
		{"missing network", "mode = \"offline\"\n", `missing key "network"`},
		{"missing mode", "network = \"preview\"\n", `missing key "mode"`},
		{"bad network", "network = \"sancho\"\nmode = \"offline\"\n", `network "sancho"`},
		{"bad mode", "network = \"preview\"\nmode = \"fast\"\n", `mode "fast"`},
		{"light without provider", "network = \"preview\"\nmode = \"light\"\n", "[koios]"},
		{"wrong type", "network = 2\nmode = \"offline\"\n", `key "network" must be a string`},
		{"duplicate", "network = \"preview\"\nnetwork = \"preview\"\nmode = \"offline\"\n", `key "network" occurs twice`},
		{"duplicate section", "network = \"preview\"\nmode = \"light\"\n[koios]\n[koios]\n", "occurs twice"},
		{"array", "network = [\"preview\"]\nmode = \"offline\"\n", "not supported"},
		{"dotted key", "koios.url = \"x\"\nnetwork = \"preview\"\nmode = \"offline\"\n", "not a plain key"},
		{"trailing text", "network = \"preview\" extra\nmode = \"offline\"\n", "unexpected text"},
	}
	for _, c := range cases {
		_, err := Parse([]byte(c.text))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want error containing %q", c.name, err, c.want)
		}
	}
}

func TestParserValues(t *testing.T) {
	doc, err := parseDocument([]byte("# c\na = \"x\\\"y\\\\z\" # trailing\nb = 42\nc = -7\nd = true\ne = false\n[s]\nf = \"#not a comment\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	top, s := doc.sections[0], doc.sections[1]
	if top.entries[0].val.s != `x"y\z` || top.entries[1].val.i != 42 || top.entries[2].val.i != -7 ||
		!top.entries[3].val.b || top.entries[4].val.b || s.entries[0].val.s != "#not a comment" {
		t.Errorf("%+v %+v", top.entries, s.entries)
	}
	for _, bad := range []string{"a = 0x10\n", "a = 1.5\n", "a = 007\n", "a = +1\n", "a = 'x'\n", "a = \"open\n", "a = \"\\q\"\n", "a =\n", "a\n", "[s\n", "[[s]]\n", "a = {}\n"} {
		if _, err := parseDocument([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestFiles(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
	c := Config{Network: "preview", Mode: ModeOffline}
	if err := Create(dir, c); err != nil {
		t.Fatal(err)
	}
	if err := Create(dir, c); err == nil {
		t.Fatal("Create replaced a file")
	}
	st, _ := os.Stat(Path(dir))
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
	c.Mode = ModeLight
	c.Koios = &Koios{}
	if err := Save(dir, c); err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir)
	if err != nil || got.Mode != ModeLight || got.Koios == nil {
		t.Fatalf("%+v %v", got, err)
	}
	if st, _ := os.Stat(Path(dir)); st.Mode().Perm() != 0o600 {
		t.Errorf("saved mode %v", st.Mode())
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "*.tmp-*")); len(m) != 0 {
		t.Errorf("leftover %v", m)
	}
	os.WriteFile(Path(dir), []byte("network = \"preview\"\nmode = \"offline\"\nwat = 1\n"), 0o600)
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), `unknown key "wat"`) || !strings.Contains(err.Error(), FileName) {
		t.Errorf("load: %v", err)
	}
}

func TestKoiosURL(t *testing.T) {
	c := Config{Network: "preprod", Mode: ModeLight, Koios: &Koios{}}
	if c.KoiosURL() != "https://preprod.koios.rest/api/v1" {
		t.Error(c.KoiosURL())
	}
	c.Koios.URL = "https://k.example/api/v1"
	if c.KoiosURL() != c.Koios.URL {
		t.Error(c.KoiosURL())
	}
	if (Config{}).KoiosURL() != "" {
		t.Error("no provider, no URL")
	}
}
