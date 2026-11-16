// Package textsafe makes text that a chain, a provider or a file chose safe to
// print in a summary or an error. One scheme: a rune that a terminal could act
// on or that could change what a reader sees is written as `\u{hex}`.
//
// What is escaped: every control character (C0, DEL and C1, so ESC and the
// one-byte CSI and OSC introducers cannot start a sequence), newlines and tabs,
// bidirectional and other invisible format characters (U+202E and the rest of
// Cf, U+2028/2029), every other rune Go does not call printable, and bytes that
// are not UTF-8; also the printable-looking runes that draw nothing or change
// how a neighbour is drawn: variation selectors (U+FE00 to U+FE0F, U+E0100 to
// U+E01EF), the Hangul fillers (U+115F, U+1160, U+3164, U+FFA0) and the
// combining grapheme joiner (U+034F). Nothing but visible printable runes is
// left raw.
package textsafe

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Quote is s in double quotes, safe as one word: a double quote, a backslash,
// a space and everything Text escapes are escaped, so a URL, a host name or a
// ticker stays whole and cannot forge a line or a field.
func Quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	escape(&b, s, true)
	b.WriteByte('"')
	return b.String()
}

// Text is s for a place where free text reads naturally (a provider's error
// message): spaces, quotes and backslashes stay as they are and everything
// else is escaped as Quote does. It is not delimited, so use Quote for a value
// that must be one word.
func Text(s string) string {
	var b strings.Builder
	escape(&b, s, false)
	return b.String()
}

// Plain reports whether Text(s) would leave s as it is: no control, format,
// invisible or non-printable rune and no invalid UTF-8.
func Plain(s string) bool { return Text(s) == s }

func escape(b *strings.Builder, s string, word bool) {
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && n == 1 {
			b.WriteString("\\u{fffd}")
			i++
			continue
		}
		i += n
		switch {
		case word && (r == '"' || r == '\\'):
			b.WriteByte('\\')
			b.WriteRune(r)
		case word && r == ' ':
			b.WriteString("\\u{20}")
		case r == ' ':
			b.WriteByte(' ')
		case r == utf8.RuneError || !strconv.IsPrint(r) || invisible(r):
			fmt.Fprintf(b, "\\u{%x}", r)
		default:
			b.WriteRune(r)
		}
	}
}

// invisible reports a rune that Go calls printable but that draws nothing, so
// it could pad or disguise text: it would look like an empty or a different
// name.
func invisible(r rune) bool {
	switch {
	case r >= 0xFE00 && r <= 0xFE0F, r >= 0xE0100 && r <= 0xE01EF:
		return true
	}
	switch r {
	case 0x3164, 0x115F, 0x1160, 0xFFA0, 0x034F:
		return true
	}
	return false
}
