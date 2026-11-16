package tui

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Clean makes text safe to draw: it removes terminal control sequences
// (CSI, OSC, DCS and the other ESC forms), drops carriage returns and every
// control character except newline, expands tabs, and replaces bidirectional
// controls and invisible format characters with U+FFFD, so nothing a command
// printed (a peer name, on-chain metadata) can move the cursor, restyle the
// screen or reorder what the operator reads. It is applied to everything the
// TUI renders, on top of whatever cleaning the commands already did.
func Clean(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && n == 1 {
			b.WriteRune('�')
			i++
			continue
		}
		switch {
		case r == 0x1b:
			i += skipEscape(s[i:])
			continue
		case r == 0x9b: // C1 CSI
			i += n + skipCSI(s[i+n:])
			continue
		case r == 0x9d || r == 0x90 || r == 0x98 || r == 0x9e || r == 0x9f: // C1 OSC, DCS, SOS, PM, APC
			i += n + skipString(s[i+n:])
			continue
		case r == '\n':
			b.WriteByte('\n')
		case r == '\t':
			b.WriteString("    ")
		case r == '\r':
			// dropped: a carriage return would overwrite what is already drawn
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
			b.WriteRune('�')
		case isBidiOrInvisible(r):
			b.WriteRune('�')
		default:
			b.WriteRune(r)
		}
		i += n
	}
	return b.String()
}

// CleanLine is Clean for a single line: newlines become spaces.
func CleanLine(s string) string {
	return strings.ReplaceAll(Clean(s), "\n", " ")
}

func isBidiOrInvisible(r rune) bool {
	switch {
	case r >= 0x202a && r <= 0x202e, // embeddings and overrides
		r >= 0x2066 && r <= 0x2069,                // isolates
		r == 0x200e || r == 0x200f || r == 0x061c, // marks
		r >= 0x200b && r <= 0x200d,                // zero width
		r == 0x2060, r == 0xfeff, r == 0x2028, r == 0x2029,
		r >= 0xe0000 && r <= 0xe007f: // tag characters
		return true
	}
	return unicode.Is(unicode.Cf, r) && r != 0xad
}

// skipEscape returns the length of the escape sequence at the start of s,
// which begins with ESC.
func skipEscape(s string) int {
	if len(s) < 2 {
		return 1
	}
	switch s[1] {
	case '[':
		return 2 + skipCSI(s[2:])
	case ']', 'P', 'X', '^', '_':
		return 2 + skipString(s[2:])
	}
	// ESC, optional intermediates (0x20-0x2f), a final byte (0x30-0x7e).
	i := 1
	for i < len(s) && s[i] >= 0x20 && s[i] <= 0x2f {
		i++
	}
	if i < len(s) && s[i] >= 0x30 && s[i] <= 0x7e {
		i++
	}
	return i
}

// skipCSI returns the length of a CSI body: parameter bytes, intermediate
// bytes and the final byte.
func skipCSI(s string) int {
	i := 0
	for i < len(s) && s[i] >= 0x30 && s[i] <= 0x3f {
		i++
	}
	for i < len(s) && s[i] >= 0x20 && s[i] <= 0x2f {
		i++
	}
	if i < len(s) && s[i] >= 0x40 && s[i] <= 0x7e {
		i++
	}
	return i
}

// skipString returns the length of a string-type sequence body (OSC, DCS,
// APC...) up to and including its terminator, BEL or ST; an unterminated one
// is dropped to the end of the line.
func skipString(s string) int {
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == 0x07:
			return i + 1
		case s[i] == 0x1b && i+1 < len(s) && s[i+1] == '\\':
			return i + 2
		case s[i] == '\n':
			return i
		}
	}
	return len(s)
}
