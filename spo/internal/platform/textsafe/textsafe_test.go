package textsafe

import (
	"strings"
	"testing"
)

// Whatever a terminal could act on is written as an escape: the clear-screen
// sequence, the one-byte CSI of C1, a right-to-left override, a newline that
// would forge a line, and invalid UTF-8.
func TestNothingActiveSurvives(t *testing.T) {
	for name, in := range map[string]string{
		"clear screen":  "\x1b[2J",
		"osc title":     "\x1b]0;owned\x07",
		"c1 csi":        "\u009b2J",
		"c1 osc":        "\u009d0;x\u009c",
		"rtl override":  "https://good.example/‮elif.exe",
		"isolate":       "a⁦b",
		"zero width":    "a​b",
		"newline":       "ok\nTotal: 0",
		"carriage ret":  "a\rb",
		"line sep":      "a b",
		"bell":          "a\ab",
		"invalid utf-8": "a\xffb",
		"del":           "a\x7fb",
	} {
		for fn, got := range map[string]string{"Quote": Quote(in), "Text": Text(in)} {
			for _, r := range got {
				if r < 0x20 || (r >= 0x7f && r <= 0x9f) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) || r == 0x200b || r == 0x2028 {
					t.Errorf("%s of %s: %q still holds U+%04X", fn, name, got, r)
				}
			}
		}
	}
}

func TestQuoteIsOneWordAndTextKeepsProse(t *testing.T) {
	if got := Quote(`a "b" c\d`); got != `"a\u{20}\"b\"\u{20}c\\d"` {
		t.Errorf("Quote: %s", got)
	}
	if got := Quote("https://x.org/a?b=1"); got != `"https://x.org/a?b=1"` {
		t.Errorf("a plain URL changed: %s", got)
	}
	if got := Text(`HTTP 500: "bad" gateway`); got != `HTTP 500: "bad" gateway` {
		t.Errorf("Text: %s", got)
	}
	if got := Text("é ü 日本"); got != "é ü 日本" {
		t.Errorf("printable text changed: %s", got)
	}
	if !strings.Contains(Text("a\xffb"), `\u{fffd}`) {
		t.Error("a byte that is not UTF-8 is not shown")
	}
}

// Runes Go calls printable but that draw nothing are escaped: variation
// selectors, Hangul fillers and the combining grapheme joiner.
func TestInvisibleFillersAreEscaped(t *testing.T) {
	for name, r := range map[string]rune{
		"vs1": 0xFE00, "vs16": 0xFE0F, "vs17": 0xE0100, "vs256": 0xE01EF,
		"hangul filler": 0x3164, "choseong filler": 0x115F, "jungseong filler": 0x1160, "halfwidth filler": 0xFFA0, "cgj": 0x034F,
	} {
		in := "a" + string(r) + "b"
		for fn, got := range map[string]string{"Quote": Quote(in), "Text": Text(in)} {
			if strings.ContainsRune(got, r) {
				t.Errorf("%s of %s: %q still holds U+%04X", fn, name, got, r)
			}
			if !strings.Contains(got, `\u{`) {
				t.Errorf("%s of %s: %q has no escape", fn, name, got)
			}
		}
	}
	// A visible neighbour is untouched.
	if got := Text("e\u0301"); got != "e\u0301" {
		t.Errorf("a combining accent changed: %q", got)
	}
}
