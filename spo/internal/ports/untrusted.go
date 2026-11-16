package ports

import "github.com/mochipool/workbench/spo/internal/platform/textsafe"

// IsPlainText reports whether s is plain printable text a user interface can
// show as it is: nothing a terminal could act on, no bidirectional, invisible or
// filler character, valid UTF-8 (platform/textsafe leaves it unchanged). The
// use cases, which may not import platform packages, use it to decide whether a
// string a chain chose (a token name) is shown as text at all.
func IsPlainText(s string) bool { return textsafe.Plain(s) }

// QuoteText is s quoted as one word with everything a chain or provider chose
// escaped (platform/textsafe.Quote), for the text of a refusal.
func QuoteText(s string) string { return textsafe.Quote(s) }
