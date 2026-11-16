package cli

import (
	"fmt"
	"strings"

	"github.com/mochipool/workbench/spo/internal/platform/textsafe"
)

// shown is s made safe to print in a summary or an error. Use it for every
// string that a chain, a provider, a peer or a file chose (an anchor URL, a
// pool ticker, a title, a handle, an imported name): terminal escapes, C1 and
// bidirectional controls and newlines are written as `\u{hex}` (textsafe). The
// party commands quote the same way with quoted().
func shown(s string) string { return textsafe.Text(s) }

// shownLines is s, which may span several lines (a poll question), made safe to
// print: each line is escaped as shown does and the line breaks are kept, so a
// provider cannot add anything but lines of text.
func shownLines(s string) string {
	lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	for i, l := range lines {
		lines[i] = textsafe.Text(l)
	}
	return strings.Join(lines, "\n")
}

// quotedText is s in double quotes with everything a chain or provider chose
// escaped (textsafe.Quote).
func quotedText(s string) string { return textsafe.Quote(s) }

// SafeMessage is err's text with everything a chain, a provider or a file may
// have put in it escaped (textsafe); line breaks the command itself wrote are
// kept. cmd/spo prints every command error through it, so a refusal that
// quotes a provider's reason cannot carry a terminal escape.
func SafeMessage(err error) string { return shownLines(err.Error()) }

// shownAny is v, printed with fmt.Sprint (a Stringer, a named string type) and
// made safe as shown does.
func shownAny(v any) string { return shown(fmt.Sprint(v)) }

// indentLines puts two spaces before every line, so a multi-line text a
// provider chose reads as one block and cannot pass for a line of ours.
func indentLines(s string) string {
	return "  " + strings.ReplaceAll(s, "\n", "\n  ")
}
