package config

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The workspace file is a small subset of TOML, parsed here because the
// standard library has none and the schema needs nothing more. Supported:
//
//   - blank lines and '#' comments (a whole line, or after a value)
//   - [section] headers (one level, bare names)
//   - key = value with bare keys (letters, digits, '-', '_')
//   - values: basic strings in double quotes with the escapes \" \\ \n \t,
//     decimal integers, and the booleans true and false
//
// Anything else (arrays, inline tables, dotted keys, literal or multi-line
// strings, floats, dates, hexadecimal integers) is an error, not a silent
// misreading. A key that occurs twice in a section is an error.

type valueKind int

const (
	kindString valueKind = iota
	kindInt
	kindBool
)

type value struct {
	kind valueKind
	s    string
	i    int64
	b    bool
	line int
}

type entry struct {
	key string
	val value
}

// section holds entries in file order.
type section struct {
	name    string // "" for the top level
	line    int
	entries []entry
}

type document struct{ sections []*section }

func parseDocument(data []byte) (*document, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("not valid UTF-8")
	}
	doc := &document{}
	cur := &section{}
	doc.sections = append(doc.sections, cur)
	seenSection := map[string]bool{}
	seenKey := map[string]bool{}
	for i, raw := range strings.Split(string(data), "\n") {
		n := i + 1
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			name, rest, err := parseHeader(line)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", n, err)
			}
			if err := onlyComment(rest); err != nil {
				return nil, fmt.Errorf("line %d: %w", n, err)
			}
			if seenSection[name] {
				return nil, fmt.Errorf("line %d: section [%s] occurs twice", n, name)
			}
			seenSection[name] = true
			cur = &section{name: name, line: n}
			doc.sections = append(doc.sections, cur)
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
		v, err := parseValue(strings.TrimSpace(rest), n)
		if err != nil {
			return nil, fmt.Errorf("line %d: key %q: %w", n, key, err)
		}
		cur.entries = append(cur.entries, entry{key, v})
	}
	return doc, nil
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

func parseHeader(line string) (name, rest string, err error) {
	if strings.HasPrefix(line, "[[") {
		return "", "", fmt.Errorf("arrays of tables are not supported")
	}
	end := strings.IndexByte(line, ']')
	if end < 0 {
		return "", "", fmt.Errorf("section header is not closed")
	}
	name = strings.TrimSpace(line[1:end])
	if !validBare(name) {
		return "", "", fmt.Errorf("section name %q is not a plain name (dotted and quoted names are not supported)", name)
	}
	return name, line[end+1:], nil
}

func onlyComment(rest string) error {
	rest = strings.TrimSpace(rest)
	if rest == "" || strings.HasPrefix(rest, "#") {
		return nil
	}
	return fmt.Errorf("unexpected text %q after the value", rest)
}

func parseValue(s string, line int) (value, error) {
	switch {
	case s == "":
		return value{}, fmt.Errorf("missing value")
	case s[0] == '"':
		str, rest, err := parseString(s)
		if err != nil {
			return value{}, err
		}
		if err := onlyComment(rest); err != nil {
			return value{}, err
		}
		return value{kind: kindString, s: str, line: line}, nil
	}
	tok, rest, _ := strings.Cut(s, "#")
	_ = rest
	tok = strings.TrimSpace(tok)
	switch tok {
	case "true":
		return value{kind: kindBool, b: true, line: line}, nil
	case "false":
		return value{kind: kindBool, b: false, line: line}, nil
	}
	if strings.HasPrefix(tok, "[") || strings.HasPrefix(tok, "{") || strings.HasPrefix(tok, "'") {
		return value{}, fmt.Errorf("arrays, inline tables and literal strings are not supported")
	}
	if strings.ContainsAny(tok, " \t") {
		return value{}, fmt.Errorf("unexpected text after the value")
	}
	i, err := strconv.ParseInt(tok, 10, 64)
	if err != nil || strings.HasPrefix(tok, "+") || (len(tok) > 1 && strings.HasPrefix(strings.TrimPrefix(tok, "-"), "0")) {
		return value{}, fmt.Errorf("%q is not a string, a decimal integer or a boolean", tok)
	}
	return value{kind: kindInt, i: i, line: line}, nil
}

// parseString reads a basic string at the start of s and returns the rest.
func parseString(s string) (string, string, error) {
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch c := s[i]; c {
		case '"':
			return b.String(), s[i+1:], nil
		case '\\':
			i++
			if i >= len(s) {
				return "", "", fmt.Errorf("string is not closed")
			}
			switch s[i] {
			case '"', '\\':
				b.WriteByte(s[i])
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			default:
				return "", "", fmt.Errorf("unsupported escape \\%c", s[i])
			}
		default:
			if c < 0x20 || c == 0x7f {
				return "", "", fmt.Errorf("control character in string")
			}
			b.WriteByte(c)
		}
	}
	return "", "", fmt.Errorf("string is not closed")
}

func quote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\t", `\t`)
	return `"` + r.Replace(s) + `"`
}
