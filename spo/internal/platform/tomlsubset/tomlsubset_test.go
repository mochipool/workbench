package tomlsubset

import (
	"runtime"
	"strings"
	"testing"
)

var full = Options{ArrayTables: true, Lists: true, Unsigned: true, MaxLineBytes: 1000, MaxArrayTables: 3, MaxListItems: 3}

// spec: SPO-Xmailbox-OUT-024
func TestParsesTheSubset(t *testing.T) {
	doc, err := Parse([]byte("# c\n[relay] # c\na = 5 # c\n[[party]]\nlabel = \"x\\\"y\\\\z\" # t\nsend_to = [\"a\", \"b\"]\n[[party]]\nlabel = \"#no comment\"\nsend_to = []\n"), full)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Tables) != 4 || doc.Tables[0].Name != "" || doc.Tables[1].Name != "relay" || doc.Tables[1].Array || !doc.Tables[2].Array {
		t.Fatalf("tables = %+v", doc.Tables)
	}
	if v := doc.Tables[1].Entries[0].Val; v.Kind != Int || v.Uint != 5 || v.Line != 3 {
		t.Fatalf("a = %+v", v)
	}
	if v := doc.Tables[2].Entries[0].Val; v.Str != `x"y\z` {
		t.Fatalf("label = %q", v.Str)
	}
	if v := doc.Tables[2].Entries[1].Val; v.Kind != List || len(v.List) != 2 || v.List[1] != "b" {
		t.Fatalf("send_to = %+v", v)
	}
	if v := doc.Tables[3].Entries[0].Val; v.Str != "#no comment" {
		t.Fatalf("label = %q", v.Str)
	}
}

// The dialects differ in what they switch on, and what is off is an error.
//
// spec: SPO-Xmailbox-OUT-024
func TestDialectsRefuseWhatIsSwitchedOff(t *testing.T) {
	plain := Options{Escapes: "nt"}
	for name, c := range map[string]struct {
		text string
		o    Options
		want string
	}{
		"array table off":      {"[[a]]\n", plain, "arrays of tables"},
		"list off":             {"a = [\"x\"]\n", plain, "not supported"},
		"inline table":         {"a = {b = 1}\n", full, "not supported"},
		"literal string":       {"a = 'x'\n", full, "not supported"},
		"signed when unsigned": {"a = -5\n", full, "decimal integer"},
		"unsigned too large":   {"a = 99999999999999999999999\n", full, "out of range"},
		"leading zero":         {"a = 05\n", full, "leading zero"},
		"signed leading zero":  {"a = 05\n", plain, "not a string"},
		"plus sign":            {"a = +5\n", plain, "not a string"},
		"bad escape":           {"a = \"\\n\"\n", full, "unsupported escape"},
		"bool in unsigned":     {"a = true\n", full, ""},
		"dotted key":           {"a.b = 1\n", full, "not a plain key"},
		"quoted table":         {"[\"a\"]\n", full, "plain name"},
		"table twice":          {"[a]\n[a]\n", full, "occurs twice"},
		"key twice":            {"a = 1\na = 2\n", full, "occurs twice"},
		"text after table":     {"[a] x\n", full, "unexpected text"},
		"no equals":            {"a\n", full, "expected key"},
		"list of numbers":      {"a = [1]\n", full, "list holds strings"},
		"trailing comma":       {"a = [\"x\",]\n", full, "list holds strings"},
		"unclosed list":        {"a = [\"x\"\n", full, "not closed"},
		"unclosed string":      {"a = \"x\n", full, "not closed"},
		"tab in string":        {"a = \"x\ty\"\n", full, "in a string"},
		"invalid utf-8":        {"# \xff\n", full, "UTF-8"},
	} {
		_, err := Parse([]byte(c.text), c.o)
		if name == "bool in unsigned" { // a boolean parses; the caller refuses the kind
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error with %q", name, err, c.want)
		}
	}
	if doc, err := Parse([]byte("a = \"x\\ny\\tz\"\nb = -7\nc = false\n"), plain); err != nil || doc.Tables[0].Entries[0].Val.Str != "x\ny\tz" || doc.Tables[0].Entries[1].Val.Int != -7 || doc.Tables[0].Entries[2].Val.Bool {
		t.Fatalf("the workspace dialect: %+v, %v", doc, err)
	}
}

// Every control character but tab is refused anywhere in a line, and a CR only
// ends a CRLF line.
//
// spec: SPO-Xmailbox-SEC-019
func TestControlCharacters(t *testing.T) {
	bad := map[string]string{
		"bare CR in a comment":       "# old\rretention = 60\n",
		"bare CR after a value":      "a = 5\rb = 6\n",
		"bare CR in a header":        "[a]\r[b]\n",
		"CR before CRLF":             "# x\r\r\n",
		"CR at the end of the file":  "a = 1\n# end\r",
		"CR alone is the whole file": "\r",
		"NUL":                        "# a\x00b\n",
		"BEL":                        "a = 1 # \a\n",
		"ESC":                        "# \x1b[2K\n",
		"DEL":                        "# a\x7fb\n",
		"vertical tab":               "# a\vb\n",
		"form feed":                  "a\f= 1\n",
		"C1 NEL":                     "# a\u0085b\n",
		"C1 CSI":                     "# a\u009bb\n",
	}
	for name, text := range bad {
		if _, err := Parse([]byte(text), full); err == nil || !strings.Contains(err.Error(), "line") {
			t.Errorf("%s: %v, want a refusal that names the line", name, err)
		}
	}
	if _, err := Parse([]byte("# a\rb\n"), full); err == nil || !strings.Contains(err.Error(), "carriage return") {
		t.Errorf("the refusal of a bare CR does not say so: %v", err)
	}
	// the refusal names the line it is on
	if _, err := Parse([]byte("a = 1\nb = 2\n# x\x01\n"), full); err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Errorf("a control character on line 3: %v", err)
	}
	// good: CRLF endings, tabs as whitespace, tab after a value
	doc, err := Parse([]byte("[a]\r\n\tk\t=\t1\t# c\t\r\n"), full)
	if err != nil || len(doc.Tables) != 2 || doc.Tables[1].Entries[0].Val.Uint != 1 {
		t.Fatalf("a CRLF file with tabs: %v", err)
	}
	// a CR that ends the last line when the file has no final LF is not a CRLF
	if _, err := Parse([]byte("a = 1\r"), full); err == nil {
		t.Error("a final CR with no LF was accepted")
	}
}

// Bounds are checked as the file is read, not after it is built.
//
// spec: SPO-Xmailbox-SEC-019
func TestBounds(t *testing.T) {
	if _, err := Parse([]byte("a = \""+strings.Repeat("x", 1000)+"\"\n"), full); err == nil || !strings.Contains(err.Error(), "line limit") {
		t.Errorf("a line over the bound: %v", err)
	}
	if _, err := Parse([]byte("a = \""+strings.Repeat("x", 1000-len("a = \"\""))+"\"\n"), full); err != nil {
		t.Errorf("a line at the bound: %v", err)
	}
	if _, err := Parse([]byte(strings.Repeat("[[p]]\n", 4)), full); err == nil || !strings.Contains(err.Error(), "3") {
		t.Errorf("four tables with a bound of three: %v", err)
	}
	if _, err := Parse([]byte(strings.Repeat("[[p]]\n", 3)), full); err != nil {
		t.Errorf("three tables: %v", err)
	}
	if _, err := Parse([]byte("a = [\"1\",\"2\",\"3\",\"4\"]\n"), full); err == nil || !strings.Contains(err.Error(), "at most 3") {
		t.Errorf("four list items with a bound of three: %v", err)
	}
	// a file of a million tables claims far more than the bound allows: it is
	// refused at the fourth and allocates little
	huge := []byte(strings.Repeat("[[p]]\n", 1_000_000))
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	_, err := Parse(huge, full)
	runtime.ReadMemStats(&m1)
	if err == nil {
		t.Fatal("a million tables were accepted")
	}
	if got := m1.TotalAlloc - m0.TotalAlloc; got > 32<<20 { // the split of the text itself is most of it
		t.Fatalf("refusing a million tables allocated %d bytes", got)
	}
}

func TestQuoteRoundTrips(t *testing.T) {
	for _, s := range []string{"", "plain", "a\"b", "a\\b", "a\nb", "a\tb", "# not a comment"} {
		q, err := Quote(s)
		if err != nil {
			t.Errorf("%q: %v", s, err)
			continue
		}
		doc, err := Parse([]byte("k = "+q+"\n"), Options{Escapes: "nt"})
		if err != nil || doc.Tables[0].Entries[0].Val.Str != s {
			t.Errorf("%q: %v, %+v", s, err, doc)
		}
	}
}

// The characters that change what a reader sees (bidirectional controls and
// isolates, the line and paragraph separators) are refused anywhere in a line,
// as the control characters are: a comment that reads one way on a terminal and
// parses another is the same attack.
//
// spec: SPO-Xmailbox-SEC-019
func TestBidirectionalAndSeparatorCharactersAreRefused(t *testing.T) {
	var runes []rune
	runes = append(runes, 0x061c, 0x200e, 0x200f, 0x2028, 0x2029)
	for r := rune(0x202a); r <= 0x202e; r++ {
		runes = append(runes, r)
	}
	for r := rune(0x2066); r <= 0x2069; r++ {
		runes = append(runes, r)
	}
	for _, r := range runes {
		for name, text := range map[string]string{
			"in a comment":  "# a" + string(r) + "b\n",
			"after a value": "a = 1 # " + string(r) + "\n",
			"in a string":   "a = \"x" + string(r) + "y\"\n",
			"in a header":   "[a] # " + string(r) + "\n",
		} {
			if _, err := Parse([]byte(text), full); err == nil || !strings.Contains(err.Error(), "line 1") {
				t.Errorf("U+%04X %s: %v, want a refusal that names the line", r, name, err)
			}
		}
	}
	// neighbours of the ranges are text
	for _, r := range []rune{0x061b, 0x061d, 0x200d, 0x2010, 0x2027, 0x202f, 0x2065, 0x206a, 0x00e9} {
		if _, err := Parse([]byte("# a"+string(r)+"b\n"), full); err != nil {
			t.Errorf("U+%04X was refused: %v", r, err)
		}
	}
}

// The writer refuses what the reader refuses inside a string, so that a file it
// helped write is one Parse reads back to the same value.
//
// spec: SPO-Xmailbox-SEC-019
func TestQuoteRefusesWhatParseRefuses(t *testing.T) {
	alphabet := []rune{'a', ' ', '"', '\\', '#', '\n', '\t', '\r', 0, 0x1b, 0x7f, 0x80, 0x85, 0x9f, 0xe9,
		0x061c, 0x200e, 0x200f, 0x202a, 0x202d, 0x202e, 0x2066, 0x2069, 0x2028, 0x2029, 0x1f600, 0xfffd}
	// every class of character is refused by Quote and by Parse alike
	for _, r := range alphabet {
		s := "a" + string(r) + "b"
		q, qerr := Quote(s)
		doc, perr := Parse([]byte("k = "+q+"\n"), Options{Escapes: "nt"})
		switch {
		case qerr != nil && perr == nil && q == "":
			// refused by the writer: nothing to compare
		case qerr == nil && (perr != nil || doc.Tables[0].Entries[0].Val.Str != s):
			t.Errorf("U+%04X: Quote wrote %s, which reads back as %+v, %v", r, q, doc, perr)
		}
		wantRefused := r != 'a' && r != ' ' && r != '"' && r != '\\' && r != '#' && r != '\n' && r != '\t' && r != 0xe9 && r != 0x1f600 && r != 0xfffd
		if (qerr != nil) != wantRefused {
			t.Errorf("U+%04X: Quote error %v, refusal expected %v", r, qerr, wantRefused)
		}
	}
	if _, err := Quote("a\xffb"); err == nil {
		t.Error("Quote accepted text that is not UTF-8")
	}
}
