package config

import (
	"math/rand/v2"
	"os"
	"strings"
	"testing"
	"unicode/utf8"
)

// A control character in the file is refused, wherever it is. A bare carriage
// return in a comment would hide the next key from a person reading the file
// while the parser read it as a line of its own.
//
// spec: SPO-Xmailbox-SEC-019
func TestControlCharactersAreRefused(t *testing.T) {
	ok := "network = \"preview\"\nmode = \"offline\"\n"
	for name, text := range map[string]string{
		"a bare CR in a comment":      "# old\rnetwork = \"mainnet\"\n" + ok,
		"a bare CR after a value":     "network = \"preview\"\rmode = \"offline\"\n",
		"a CR at the end of the file": ok + "# end\r",
		"a CR before a CR":            "# a\r\r\n" + ok,
		"NUL in a comment":            "# a\x00b\n" + ok,
		"ESC in a comment":            "# \x1b[2K\n" + ok,
		"DEL in a comment":            "# a\x7fb\n" + ok,
		"a C1 control character":      "# a\u0085b\n" + ok,
		"a vertical tab":              "# a\vb\n" + ok,
		"a form feed after a key":     "network\f= \"preview\"\nmode = \"offline\"\n",
	} {
		if _, err := Parse([]byte(text)); err == nil || !strings.Contains(err.Error(), "line") {
			t.Errorf("%s: %v, want a refusal naming the line", name, err)
		}
	}
	// CRLF line endings and tabs as whitespace are fine
	if c, err := Parse([]byte("network = \"preview\"\r\nmode\t=\t\"offline\" # c\r\n")); err != nil || c.Network != "preview" {
		t.Errorf("a CRLF file: %v", err)
	}
}

// What Marshal writes, Parse reads back to the same value, or Marshal refuses
// the value and says which field. A file the tool saved is always one it can
// load.
//
// spec: SPO-Xmailbox-SEC-019
func TestMarshalNeverWritesWhatParseRefuses(t *testing.T) {
	alphabet := []rune{'a', 'Z', '0', ' ', '"', '\\', '#', '=', '[', '\n', '\t', '\r', 0, 0x1b, 0x7f, 0x80, 0x85, 0x9f,
		0xa0, 0xe9, 0x061c, 0x200b, 0x200e, 0x200f, 0x2028, 0x2029, 0x202a, 0x202e, 0x2066, 0x2069, 0xfeff, 0x1f600, utf8.RuneError}
	fields := []struct {
		name string
		set  func(c *Config, v string)
		get  func(c Config) string
	}{
		{"party inbox", func(c *Config, v string) { c.Party = &Party{Inbox: v} }, func(c Config) string { return c.Party.Inbox }},
		{"party outbox", func(c *Config, v string) { c.Party = &Party{Outbox: v} }, func(c Config) string { return c.Party.Outbox }},
		{"tailcat derp_map_url", func(c *Config, v string) { c.Tailcat = &Tailcat{DERPMapURL: v} }, func(c Config) string { return c.Tailcat.DERPMapURL }},
		{"registry url", func(c *Config, v string) { c.Registry = &Registry{URL: v} }, func(c Config) string { return c.Registry.URL }},
		{"handles url", func(c *Config, v string) { c.Handles = &Handles{URL: v} }, func(c Config) string { return c.Handles.URL }},
		{"koios url", func(c *Config, v string) { c.Koios = &Koios{URL: v} }, func(c Config) string { return c.Koios.URL }},
		{"blockfrost url", func(c *Config, v string) { c.Blockfrost = &Blockfrost{URL: v} }, func(c Config) string { return c.Blockfrost.URL }},
		{"node address", func(c *Config, v string) { c.Node = &Node{Address: v} }, func(c Config) string { return c.Node.Address }},
	}
	rng := rand.New(rand.NewPCG(1, 2))
	refused, saved := 0, 0
	for _, f := range fields {
		for range 400 {
			var b strings.Builder
			for range 1 + rng.IntN(6) {
				b.WriteRune(alphabet[rng.IntN(len(alphabet))])
			}
			v := b.String()
			if rng.IntN(8) == 0 {
				v += "\xff" // not UTF-8
			}
			c := Config{Network: "preview", Mode: ModeOffline}
			f.set(&c, v)
			data, err := Marshal(c)
			if err != nil {
				refused++
				continue
			}
			back, err := Parse(data)
			if err != nil {
				t.Fatalf("%s = %q: Marshal wrote a file that Parse refuses: %v\n%s", f.name, v, err, data)
			}
			if got := f.get(back); got != v {
				t.Fatalf("%s = %q came back as %q", f.name, v, got)
			}
			saved++
		}
	}
	if refused == 0 || saved == 0 {
		t.Fatalf("the generator reached only one side: %d refused, %d saved", refused, saved)
	}
}

// A value that cannot be written is refused with a message that names the
// field, for every class of character the reader refuses.
//
// spec: SPO-Xmailbox-SEC-019
func TestMarshalNamesTheFieldItRefuses(t *testing.T) {
	for _, r := range []rune{'\r', 0, 0x7f, 0x85, 0x061c, 0x200e, 0x200f, 0x202a, 0x202e, 0x2066, 0x2069, 0x2028, 0x2029} {
		c := Config{Network: "preview", Mode: ModeOffline, Party: &Party{Inbox: "a" + string(r) + "b"}}
		_, err := Marshal(c)
		if err == nil || !strings.Contains(err.Error(), "[party] inbox") {
			t.Errorf("U+%04X: %v, want a refusal that names [party] inbox", r, err)
		}
	}
	c := Config{Network: "preview", Mode: ModeOffline, Party: &Party{Outbox: "a\xffb"}}
	if _, err := Marshal(c); err == nil || !strings.Contains(err.Error(), "[party] outbox") {
		t.Errorf("invalid UTF-8: %v", err)
	}
	// tab and newline are written as escapes and read back
	c = Config{Network: "preview", Mode: ModeOffline, Party: &Party{Inbox: "a\tb\nc"}}
	if data, err := Marshal(c); err != nil {
		t.Errorf("tab and newline: %v", err)
	} else if back, err := Parse(data); err != nil || back.Party.Inbox != "a\tb\nc" {
		t.Errorf("tab and newline came back as %v, %v", back.Party, err)
	}
	// Save refuses too, and leaves no file
	dir := t.TempDir()
	if err := Save(dir, Config{Network: "preview", Mode: ModeOffline, Party: &Party{Inbox: "x\u0085"}}); err == nil {
		t.Error("Save accepted a C1 control character")
	}
	if _, err := os.Stat(Path(dir)); err == nil {
		t.Error("Save left a file after a refusal")
	}
}
