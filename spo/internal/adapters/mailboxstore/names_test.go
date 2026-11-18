//go:build unix

package mailboxstore

import (
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// spec: SPO-Xmailbox-SEC-007
func TestEntryNamesAreValidatedStrictly(t *testing.T) {
	mid := mailbox.HashOf([]byte("x"))
	var snd party.Fingerprint
	snd[0] = 0x0a
	good := entryName(1_700_000_000, mid, snd)
	a, m, s, err := parseEntry(good)
	if err != nil || a != 1_700_000_000 || m != mid || s != snd {
		t.Fatalf("round trip: %d %v %v %v", a, m, s, err)
	}
	if len(good) != 20+1+64+1+40 {
		t.Fatalf("name is %d long", len(good))
	}
	h, f := mid.String(), recipientName(snd)
	bad := map[string]string{
		"empty":                 "",
		"upper-case mid":        "00000000001700000000-" + strings.ToUpper(h) + "-" + f,
		"upper-case sender":     "00000000001700000000-" + h + "-" + strings.ToUpper(f),
		"short arrival":         "0001700000000-" + h + "-" + f,
		"long arrival":          "000000000001700000000-" + h + "-" + f,
		"signed arrival":        "-0000000001700000000-" + h + "-" + f,
		"overflow arrival":      "99999999999999999999-" + h + "-" + f,
		"no sender":             "00000000001700000000-" + h,
		"short mid":             "00000000001700000000-" + h[2:] + "-" + f,
		"trailing newline":      good + "\n",
		"trailing text":         good + "x",
		"leading space":         " " + good,
		"path separator":        "00000000001700000000-" + h + "-" + f[:39] + "/",
		"dot dot":               "..",
		"temporary name":        ".tmp-0123456789abcdef",
		"non-hex":               "00000000001700000000-" + strings.Repeat("g", 64) + "-" + f,
		"unicode digit arrival": "٠٠٠٠٠٠٠٠٠٠١٧٠٠٠٠٠٠٠٠-" + h + "-" + f,
		"nul":                   good[:10] + "\x00" + good[11:],
	}
	for name, n := range bad {
		if _, _, _, err := parseEntry(n); err == nil {
			t.Errorf("%s: %q was accepted", name, n)
		}
	}
	for name, n := range map[string]string{
		"upper-case": strings.ToUpper(f), "short": f[:38], "long": f + "00", "newline": f + "\n", "dot": ".", "slash": "a/b", "empty": "",
	} {
		if _, err := parseRecipient(n); err == nil {
			t.Errorf("recipient %s: %q was accepted", name, n)
		}
	}
	if got, err := parseRecipient(f); err != nil || got != snd {
		t.Fatalf("parseRecipient = %v, %v", got, err)
	}
	if !tmpRE.MatchString(".tmp-0123456789abcdef") || tmpRE.MatchString(".tmp-0123456789abcdeg") || tmpRE.MatchString(".tmp-0123456789abcdef\n") || tmpRE.MatchString(".tmp-0123456789abcde") {
		t.Fatal("tmpRE is wrong")
	}
}

// the names sort in arrival order
func TestEntryNamesSortByArrival(t *testing.T) {
	var snd party.Fingerprint
	lo := entryName(999, mailbox.Hash{0xff}, snd)
	hi := entryName(1000, mailbox.Hash{0x00}, snd)
	if !(lo < hi) {
		t.Fatalf("%q does not sort before %q", lo, hi)
	}
}
