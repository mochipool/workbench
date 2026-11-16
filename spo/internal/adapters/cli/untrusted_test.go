package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	dgov "github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/platform/textsafe"
	"github.com/mochipool/workbench/spo/internal/ports"
)

const hostile = "\x1b[2J\u009b2J‮\nTotal: 0 lovelace\x07"

func mustBeInert(t *testing.T, what, out string) {
	t.Helper()
	for _, r := range out {
		if r == '\n' || r == '\t' {
			continue
		}
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			t.Errorf("%s: U+%04X reached the output: %q", what, r, out)
			return
		}
	}
}

// Text a chain, a provider or a stored file chose never reaches the terminal
// raw: the anchor URL of a stored action file (the `action submit`
// confirmation), the lines of the summary, a provider's reason in a reading.
func TestUntrustedTextIsEscapedInSummaries(t *testing.T) {
	var out bytes.Buffer
	anchor := dgov.Anchor{URL: "https://example.com/" + hostile}
	anchor.Hash[0] = 1
	printDetails(&out, []string{"anchor " + anchorText(anchor), "other " + hostile})
	mustBeInert(t, "details", out.String())
	if !strings.Contains(out.String(), `\u{202e}`) || !strings.Contains(out.String(), "https://example.com/") {
		t.Errorf("the URL is not shown escaped: %q", out.String())
	}
	out.Reset()
	printStakeSummary(&out, ports.TxSummary{Attachments: []string{hostile}, Unchecked: []string{hostile}, Message: []string{hostile}})
	mustBeInert(t, "summary", out.String())
	if strings.Contains(out.String(), "\nTotal: 0 lovelace") {
		t.Errorf("a forged line: %q", out.String())
	}
	mustBeInert(t, "reading", readingText(chain.Unknown[int](hostile), "none", func(int) string { return "" }))
	mustBeInert(t, "reading value", readingText(chain.Value(0), "none", func(int) string { return hostile }))
}

// The party summary's quoted() and the shared scheme agree on what is
// escaped: one scheme, not two.
func TestQuotedIsTheSharedScheme(t *testing.T) {
	for _, s := range []string{"https://x.org/a", hostile, "a b\"c\\d", "é日本", "a\xffb"} {
		if quoted(s) != textsafe.Quote(s) {
			t.Errorf("quoted(%q) = %s, textsafe.Quote = %s", s, quoted(s), textsafe.Quote(s))
		}
	}
}
