// Package tomlsubset parses the small subset of TOML that the workspace file
// (adapters/config) and the relay's configuration file (adapters/relayconfig)
// are written in. It is a pure helper with no I/O, in the platform layer so
// that two adapters can share it. The standard library has no TOML parser and
// the files need nothing more.
//
// Supported:
//
//   - blank lines and '#' comments, a whole line or after a value
//   - [table] headers with a bare name, and, with Options.ArrayTables,
//     [[table]] headers that may repeat
//   - key = value with bare keys (letters, digits, '-', '_')
//   - values: a basic string in double quotes with the escapes \" and \\ (and
//     those named in Options.Escapes), a decimal integer, the booleans true and
//     false, and, with Options.Lists, a single-line array of strings
//
// Everything else is an error, never a silent misreading: dotted or quoted
// keys, inline tables, literal and multi-line strings, floats, dates, hex
// integers, arrays of anything but strings, a key that occurs twice in a table,
// a plain table that occurs twice.
//
// Control characters (SPO-Xmailbox-SEC-019): every control character other
// than tab is refused anywhere in a line, comments included. A carriage return
// is accepted only as the CR of a CRLF line ending. A bare CR would hide the
// text after it from a person reading the file on a terminal while the parser
// still reads it as a line of its own, so the person and the parser would see
// different files. A tab is whitespace outside a string and refused inside one.
package tomlsubset

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Kind is the type of a value.
type Kind int

// The kinds of value.
const (
	String Kind = iota + 1
	Int
	Bool
	List
)

// Value is a parsed value. Only the field of its Kind is set; with
// Options.Unsigned an integer is in Uint, otherwise in Int.
type Value struct {
	Kind Kind
	Str  string
	Int  int64
	Uint uint64
	Bool bool
	List []string
	Line int
}

// Entry is one key = value line.
type Entry struct {
	Key string
	Val Value
}

// Table is a table in file order. Tables[0] of a Doc is the top level: no
// name, line 0.
type Table struct {
	Name    string
	Array   bool // a [[name]] table
	Line    int
	Entries []Entry
}

// Doc is a parsed file.
type Doc struct{ Tables []*Table }

// Options select the dialect and the bounds.
type Options struct {
	// ArrayTables accepts [[name]] headers; without it they are an error.
	ArrayTables bool
	// Lists accepts a single-line array of strings; without it an array is an error.
	Lists bool
	// Unsigned makes an integer a decimal number with no sign, in Value.Uint.
	Unsigned bool
	// Escapes names extra escape letters: "nt" adds \n and \t.
	Escapes string
	// MaxLineBytes is the longest line, 0 for no bound. It is checked before
	// the line is read.
	MaxLineBytes int
	// MaxArrayTables is the most [[name]] tables, 0 for no bound.
	MaxArrayTables int
	// MaxListItems is the most strings in a list, 0 for no bound. The count is
	// checked as items are read, so a long list is never built.
	MaxListItems int
}

// Parse reads the text of a file.
func Parse(data []byte, o Options) (*Doc, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("not valid UTF-8")
	}
	doc := &Doc{}
	cur := &Table{}
	doc.Tables = append(doc.Tables, cur)
	seenTable := map[string]bool{}
	seenKey := map[string]bool{}
	arrays := 0
	lines := strings.Split(string(data), "\n")
	for i, raw := range lines {
		n := i + 1
		if o.MaxLineBytes > 0 && len(raw) > o.MaxLineBytes {
			return nil, fmt.Errorf("line %d is over %d bytes (the line limit)", n, o.MaxLineBytes)
		}
		// a CR is the end of a CRLF line; a CR anywhere else is refused below
		if i < len(lines)-1 {
			raw = strings.TrimSuffix(raw, "\r")
		}
		if err := checkControl(raw); err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			name, array, rest, err := parseHeader(line, o)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", n, err)
			}
			if err := onlyComment(rest); err != nil {
				return nil, fmt.Errorf("line %d: %w", n, err)
			}
			if array {
				if arrays++; o.MaxArrayTables > 0 && arrays > o.MaxArrayTables {
					return nil, fmt.Errorf("line %d: more than %d [[%s]] tables (the limit is %d)", n, o.MaxArrayTables, name, o.MaxArrayTables)
				}
			} else {
				if seenTable[name] {
					return nil, fmt.Errorf("line %d: section [%s] occurs twice", n, name)
				}
				seenTable[name] = true
			}
			cur = &Table{Name: name, Array: array, Line: n}
			doc.Tables = append(doc.Tables, cur)
			seenKey = map[string]bool{}
			continue
		}
		key, rest, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected key = value or [section]", n)
		}
		key = strings.TrimSpace(key)
		if !validBare(key) {
			return nil, fmt.Errorf("line %d: %q is not a plain key (letters, digits, '-' and '_' only)", n, key)
		}
		if seenKey[key] {
			return nil, fmt.Errorf("line %d: key %q occurs twice", n, key)
		}
		seenKey[key] = true
		v, err := parseValue(strings.TrimSpace(rest), n, o)
		if err != nil {
			return nil, fmt.Errorf("line %d: key %q: %w", n, key, err)
		}
		cur.Entries = append(cur.Entries, Entry{key, v})
	}
	return doc, nil
}

// ActiveRune is true for a character a terminal acts on or that changes what a
// reader sees: the C0 controls (tab included), DEL, the C1 controls, the
// bidirectional controls and isolates (U+061C, U+200E, U+200F, U+202A to
// U+202E, U+2066 to U+2069) and the line and paragraph separators. It is the one
// set the parser refuses, the writer refuses and the configuration's own checks
// use.
func ActiveRune(r rune) bool {
	switch {
	case r < 0x20, r >= 0x7f && r <= 0x9f:
		return true
	case r == 0x061c, r == 0x200e, r == 0x200f, r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069, r == 0x2028, r == 0x2029:
		return true
	}
	return false
}

// HasActive reports whether s holds an ActiveRune.
func HasActive(s string) bool {
	for _, r := range s {
		if ActiveRune(r) {
			return true
		}
	}
	return false
}

// checkControl refuses every ActiveRune but tab in one line.
func checkControl(line string) error {
	for _, r := range line {
		if r != '\t' && ActiveRune(r) {
			if r == '\r' {
				return fmt.Errorf("a carriage return that is not part of a CRLF line ending is not allowed")
			}
			if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
				return fmt.Errorf("the control character U+%04X is not allowed", r)
			}
			return fmt.Errorf("the bidirectional or separator character U+%04X is not allowed", r)
		}
	}
	return nil
}

func validBare(k string) bool {
	if k == "" {
		return false
	}
	for _, r := range k {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

func parseHeader(line string, o Options) (name string, array bool, rest string, err error) {
	if strings.HasPrefix(line, "[[") {
		if !o.ArrayTables {
			return "", false, "", fmt.Errorf("arrays of tables are not supported")
		}
		end := strings.Index(line, "]]")
		if end < 0 {
			return "", false, "", fmt.Errorf("section header is not closed")
		}
		name = strings.TrimSpace(line[2:end])
		if !validBare(name) {
			return "", false, "", fmt.Errorf("section name %q is not a plain name (dotted and quoted names are not supported)", name)
		}
		return name, true, line[end+2:], nil
	}
	end := strings.IndexByte(line, ']')
	if end < 0 {
		return "", false, "", fmt.Errorf("section header is not closed")
	}
	name = strings.TrimSpace(line[1:end])
	if !validBare(name) {
		return "", false, "", fmt.Errorf("section name %q is not a plain name (dotted and quoted names are not supported)", name)
	}
	return name, false, line[end+1:], nil
}

func onlyComment(rest string) error {
	rest = strings.TrimSpace(rest)
	if rest == "" || strings.HasPrefix(rest, "#") {
		return nil
	}
	return fmt.Errorf("unexpected text %q after the value", rest)
}

func parseValue(s string, line int, o Options) (Value, error) {
	switch {
	case s == "":
		return Value{}, fmt.Errorf("missing value")
	case s[0] == '"':
		str, rest, err := parseString(s, o)
		if err != nil {
			return Value{}, err
		}
		if err := onlyComment(rest); err != nil {
			return Value{}, err
		}
		return Value{Kind: String, Str: str, Line: line}, nil
	case s[0] == '[' && o.Lists:
		v, err := parseList(s, o)
		v.Line = line
		return v, err
	}
	tok, _, _ := strings.Cut(s, "#")
	tok = strings.TrimSpace(tok)
	switch tok {
	case "true":
		return Value{Kind: Bool, Bool: true, Line: line}, nil
	case "false":
		return Value{Kind: Bool, Line: line}, nil
	}
	if strings.HasPrefix(tok, "[") || strings.HasPrefix(tok, "{") || strings.HasPrefix(tok, "'") {
		return Value{}, fmt.Errorf("arrays, inline tables and literal strings are not supported")
	}
	if strings.ContainsAny(tok, " \t") {
		return Value{}, fmt.Errorf("unexpected text after the value")
	}
	if o.Unsigned {
		if tok == "" || strings.Trim(tok, "0123456789") != "" {
			return Value{}, fmt.Errorf("%q is not a string, a decimal integer or a list of strings", tok)
		}
		if len(tok) > 1 && tok[0] == '0' {
			return Value{}, fmt.Errorf("an integer has no leading zero")
		}
		n, err := strconv.ParseUint(tok, 10, 64)
		if err != nil {
			return Value{}, fmt.Errorf("the integer %q is out of range", tok)
		}
		return Value{Kind: Int, Uint: n, Line: line}, nil
	}
	i, err := strconv.ParseInt(tok, 10, 64)
	if err != nil || strings.HasPrefix(tok, "+") || (len(tok) > 1 && strings.HasPrefix(strings.TrimPrefix(tok, "-"), "0")) {
		return Value{}, fmt.Errorf("%q is not a string, a decimal integer or a boolean", tok)
	}
	return Value{Kind: Int, Int: i, Line: line}, nil
}

// parseString reads a basic string at the start of s and returns the rest.
func parseString(s string, o Options) (string, string, error) {
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch c := s[i]; c {
		case '"':
			return b.String(), s[i+1:], nil
		case '\\':
			i++
			if i >= len(s) {
				return "", "", fmt.Errorf("a string is not closed")
			}
			switch {
			case s[i] == '"' || s[i] == '\\':
				b.WriteByte(s[i])
			case s[i] == 'n' && strings.ContainsRune(o.Escapes, 'n'):
				b.WriteByte('\n')
			case s[i] == 't' && strings.ContainsRune(o.Escapes, 't'):
				b.WriteByte('\t')
			default:
				return "", "", fmt.Errorf("unsupported escape \\%c", s[i])
			}
		default:
			if c < 0x20 || c == 0x7f {
				return "", "", fmt.Errorf("a control character in a string")
			}
			b.WriteByte(c)
		}
	}
	return "", "", fmt.Errorf("a string is not closed")
}

func parseList(s string, o Options) (Value, error) {
	rest := strings.TrimSpace(s[1:])
	v := Value{Kind: List}
	if strings.HasPrefix(rest, "]") {
		return v, onlyComment(rest[1:])
	}
	for {
		if !strings.HasPrefix(rest, `"`) {
			return Value{}, fmt.Errorf("a list holds strings on one line")
		}
		str, r, err := parseString(rest, o)
		if err != nil {
			return Value{}, err
		}
		if o.MaxListItems > 0 && len(v.List) >= o.MaxListItems {
			return Value{}, fmt.Errorf("a list holds at most %d items", o.MaxListItems)
		}
		v.List = append(v.List, str)
		rest = strings.TrimSpace(r)
		switch {
		case strings.HasPrefix(rest, "]"):
			return v, onlyComment(rest[1:])
		case strings.HasPrefix(rest, ","):
			rest = strings.TrimSpace(rest[1:])
		default:
			return Value{}, fmt.Errorf("a list is not closed")
		}
	}
}

// Quote writes s as a basic string with the escapes \" \\ \n and \t, the form
// Parse reads with Options.Escapes "nt". It refuses what Parse would refuse
// inside a string, so that a file it helped write can always be read back: text
// that is not UTF-8 and every ActiveRune but tab and newline. The error names
// the character and no field; the caller adds the field.
func Quote(s string) (string, error) {
	if !utf8.ValidString(s) {
		return "", fmt.Errorf("is not valid UTF-8")
	}
	for _, r := range s {
		if r != '\t' && r != '\n' && ActiveRune(r) {
			return "", fmt.Errorf("has the control or bidirectional character U+%04X, which the file cannot hold", r)
		}
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\t", `\t`)
	return `"` + r.Replace(s) + `"`, nil
}
