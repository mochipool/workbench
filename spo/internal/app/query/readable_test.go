package query

import "testing"

// A token name is shown as text only when it is plain printable text; anyone
// can send a token with any bytes as its name to an operator's address.
//
// spec: SPO-Cconv-OUT-016
func TestReadableRefusesAnythingATerminalCouldAct(t *testing.T) {
	for name, b := range map[string][]byte{
		"c1":              []byte("a\u009bb"),
		"bidi override":   []byte("a‮b"),
		"escape":          []byte("a\x1b[2Jb"),
		"newline":         []byte("a\nb"),
		"hangul filler":   []byte("aㅤb"),
		"variation":       []byte("a️b"),
		"not utf-8":       []byte{0xff, 0x41},
		"line separator":  []byte("a b"),
		"zero width":      []byte("a​b"),
		"empty":           nil,
		"grapheme joiner": []byte("a͏b"),
	} {
		if got := readable(b); got != "" {
			t.Errorf("%s: %q was shown as text", name, got)
		}
	}
	for _, s := range []string{"HOSKY", "Token 7", "日本"} {
		if got := readable([]byte(s)); got != s {
			t.Errorf("%q became %q", s, got)
		}
	}
}
