package deploy

// A strict decoder for the subset of YAML the relay's manifests are written in.
//
// Why not a YAML library: go.yaml.in/yaml/v3 is in the module graph (a test
// dependency of bursa) but not a requirement of this module. Importing it would
// add a require line to go.mod and a package to the vendored set, which changes
// the vendorHash of the three Nix derivations in tools/spo.nix; Nix cannot be
// run in the box to compute the new hash. So the manifests keep to a small
// subset, and this decoder refuses everything outside it, so that whatever it
// accepts decodes to the same tree in YAML 1.1 (what kubectl and kustomize use)
// and in YAML 1.2:
//
//   - block mappings and block sequences, indented with spaces only;
//     "- key: value" starts a mapping inside a sequence item;
//   - plain scalars: true, false, decimal integers without a leading zero,
//     resource quantities (100m, 128Mi), and strings that start with a letter,
//     "/", "./" or "../" and hold no ": " and no " #";
//   - double-quoted strings (escapes \" and \\ only) and single-quoted strings;
//   - the empty flow collections [] and {}, and flow sequences of scalars;
//   - block literals "|" and "|-";
//   - "#" comments and "---" between documents.
//
// Refused: tabs, anchors, aliases, tags, directives, "?" keys, folded scalars,
// empty values (null), duplicate keys, YAML 1.1 words (yes, no, on, off, y, n,
// null, ~ in any case), numbers that YAML 1.1 and 1.2 read differently (0440,
// 0o440, 0x1f, 1e3, 1.5, 1:20, dates), and a plain scalar that starts with
// anything but a letter, a digit or "/".

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type yamlParser struct {
	lines []string
	i     int
	base  int // line number of lines[0], for messages
}

var (
	plainKeyRE  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.\-/]*$`)
	decimalRE   = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)
	quantityRE  = regexp.MustCompile(`^[1-9][0-9]*(m|k|M|G|T|Ki|Mi|Gi|Ti)$`)
	yaml11Words = map[string]bool{"yes": true, "no": true, "on": true, "off": true, "y": true, "n": true, "null": true, "~": true}
)

// decodeYAML decodes every document of src; each must be a mapping.
func decodeYAML(src string) ([]map[string]any, error) {
	if strings.ContainsRune(src, '\t') {
		return nil, fmt.Errorf("a tab character (indent with spaces only)")
	}
	if strings.ContainsRune(src, '\r') {
		return nil, fmt.Errorf("a carriage return")
	}
	var docs []map[string]any
	all := strings.Split(src, "\n")
	start := 0
	flush := func(end int) error {
		p := &yamlParser{lines: append([]string(nil), all[start:end]...), base: start + 1}
		p.skipBlank()
		if p.eof() {
			return nil // an empty document (a leading "---")
		}
		if indentOf(p.lines[p.i]) != 0 {
			return p.errf("a document must start at column 1")
		}
		v, err := p.node(0)
		if err != nil {
			return err
		}
		p.skipBlank()
		if !p.eof() {
			return p.errf("unexpected content")
		}
		m, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("line %d: a document must be a mapping", p.base)
		}
		docs = append(docs, m)
		return nil
	}
	for i, l := range all {
		if strings.HasPrefix(l, "%") {
			return nil, fmt.Errorf("line %d: a directive", i+1)
		}
		if l == "---" || strings.HasPrefix(l, "--- ") || l == "..." {
			if strings.HasPrefix(l, "--- ") && strings.TrimSpace(stripComment(l[4:])) != "" {
				return nil, fmt.Errorf("line %d: content after ---", i+1)
			}
			if err := flush(i); err != nil {
				return nil, err
			}
			start = i + 1
		}
	}
	if err := flush(len(all)); err != nil {
		return nil, err
	}
	return docs, nil
}

func (p *yamlParser) eof() bool { return p.i >= len(p.lines) }

func (p *yamlParser) errf(format string, a ...any) error {
	return fmt.Errorf("line %d: %s", p.base+p.i, fmt.Sprintf(format, a...))
}

func indentOf(l string) int { return len(l) - len(strings.TrimLeft(l, " ")) }

// content is a line without its indentation, its comment and trailing spaces.
func content(l string) string { return strings.TrimRight(stripComment(strings.TrimLeft(l, " ")), " ") }

// stripComment cuts a "#" that starts the text or follows a space, outside quotes.
func stripComment(s string) string {
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q == '"' && c == '\\':
			i++
		case q != 0 && c == q:
			q = 0
		case q != 0:
		case c == '"' || c == '\'':
			q = c
		case c == '#' && (i == 0 || s[i-1] == ' '):
			return s[:i]
		}
	}
	return s
}

func (p *yamlParser) skipBlank() {
	for !p.eof() && content(p.lines[p.i]) == "" {
		p.i++
	}
}

func isSeqLine(c string) bool { return c == "-" || strings.HasPrefix(c, "- ") }

// node reads the block that starts at the current line, at its indentation,
// which must be at least min.
func (p *yamlParser) node(min int) (any, error) {
	p.skipBlank()
	if p.eof() {
		return nil, p.errf("a value is missing")
	}
	n := indentOf(p.lines[p.i])
	if n < min {
		return nil, p.errf("a value is missing")
	}
	if isSeqLine(content(p.lines[p.i])) {
		return p.seq(n)
	}
	return p.mapping(n)
}

func (p *yamlParser) mapping(n int) (map[string]any, error) {
	m := map[string]any{}
	for {
		p.skipBlank()
		if p.eof() || indentOf(p.lines[p.i]) < n {
			return m, nil
		}
		if indentOf(p.lines[p.i]) > n {
			return nil, p.errf("indented more than its mapping")
		}
		c := content(p.lines[p.i])
		if isSeqLine(c) {
			return nil, p.errf("a sequence item inside a mapping")
		}
		key, rest, err := splitKey(c)
		if err != nil {
			return nil, p.errf("%v", err)
		}
		if _, dup := m[key]; dup {
			return nil, p.errf("the key %q twice", key)
		}
		p.i++
		var v any
		switch rest {
		case "":
			p.skipBlank()
			if p.eof() {
				return nil, p.errf("the key %q has no value", key)
			}
			next, nc := indentOf(p.lines[p.i]), content(p.lines[p.i])
			switch {
			case next > n:
				v, err = p.node(next)
			case next == n && isSeqLine(nc):
				v, err = p.seq(n)
			default:
				return nil, p.errf("the key %q has no value (an empty value is null: write it out)", key)
			}
		case "|", "|-":
			v, err = p.literal(n, rest == "|")
		default:
			v, err = scalar(rest)
			if err != nil {
				err = fmt.Errorf("line %d: %w", p.base+p.i-1, err)
			}
		}
		if err != nil {
			return nil, err
		}
		m[key] = v
	}
}

func (p *yamlParser) seq(n int) ([]any, error) {
	out := []any{}
	for {
		p.skipBlank()
		if p.eof() || indentOf(p.lines[p.i]) < n {
			return out, nil
		}
		if indentOf(p.lines[p.i]) > n {
			return nil, p.errf("indented more than its sequence")
		}
		c := content(p.lines[p.i])
		if !isSeqLine(c) {
			return out, nil // the mapping that holds this sequence goes on
		}
		rest := strings.TrimPrefix(strings.TrimPrefix(c, "-"), " ")
		if strings.HasPrefix(rest, " ") {
			return nil, p.errf("write \"- \" with one space")
		}
		var v any
		var err error
		switch {
		case rest == "":
			p.i++
			p.skipBlank()
			if p.eof() || indentOf(p.lines[p.i]) <= n {
				return nil, p.errf("an empty sequence item")
			}
			v, err = p.node(n + 1)
		case startsMapping(rest):
			// "- key: value": the item is a mapping whose keys sit two columns in
			p.lines[p.i] = strings.Repeat(" ", n+2) + strings.TrimPrefix(strings.TrimLeft(p.lines[p.i], " "), "- ")
			v, err = p.mapping(n + 2)
		case rest == "|" || rest == "|-":
			p.i++
			v, err = p.literal(n, rest == "|")
		case isSeqLine(rest):
			return nil, p.errf("a nested sequence on a sequence line")
		default:
			v, err = scalar(rest)
			if err != nil {
				err = p.errf("%v", err)
			}
			p.i++
		}
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
}

// literal reads a block literal below a key at indentation n.
func (p *yamlParser) literal(n int, keep bool) (string, error) {
	var body []string
	ind := -1
	for !p.eof() {
		l := p.lines[p.i]
		if strings.TrimSpace(l) == "" {
			body = append(body, "")
			p.i++
			continue
		}
		in := indentOf(l)
		if in <= n {
			break
		}
		if ind < 0 {
			ind = in
		}
		if in < ind {
			return "", p.errf("a literal line indented less than the first")
		}
		body = append(body, l[ind:])
		p.i++
	}
	for len(body) > 0 && body[len(body)-1] == "" {
		body = body[:len(body)-1]
	}
	if len(body) == 0 {
		return "", p.errf("an empty literal")
	}
	s := strings.Join(body, "\n")
	if keep {
		s += "\n"
	}
	return s, nil
}

// startsMapping: the text is "key:" or "key: value".
func startsMapping(s string) bool {
	_, _, err := splitKey(s)
	return err == nil
}

func splitKey(c string) (key, rest string, err error) {
	if strings.HasPrefix(c, `"`) {
		end := strings.Index(c[1:], `"`)
		if end < 0 {
			return "", "", fmt.Errorf("an unterminated key")
		}
		key, c = c[1:end+1], c[end+2:]
		if !strings.HasPrefix(c, ":") {
			return "", "", fmt.Errorf("a quoted key without \":\"")
		}
		return key, strings.TrimSpace(c[1:]), nil
	}
	i := strings.Index(c, ": ")
	if i < 0 {
		if !strings.HasSuffix(c, ":") {
			return "", "", fmt.Errorf("not a \"key: value\" line: %q", c)
		}
		i = len(c) - 1
	}
	key = c[:i]
	if !plainKeyRE.MatchString(key) {
		return "", "", fmt.Errorf("the key %q is not a plain key", key)
	}
	return key, strings.TrimSpace(c[i+1:]), nil
}

func scalar(s string) (any, error) {
	switch {
	case s == "[]":
		return []any{}, nil
	case s == "{}":
		return map[string]any{}, nil
	case strings.HasPrefix(s, "["):
		if !strings.HasSuffix(s, "]") {
			return nil, fmt.Errorf("an unterminated flow sequence %q", s)
		}
		items, err := splitFlow(s[1 : len(s)-1])
		if err != nil {
			return nil, err
		}
		out := []any{}
		for _, it := range items {
			v, err := scalar(it)
			if err != nil {
				return nil, err
			}
			if _, ok := v.(string); !ok {
				if _, ok := v.(int64); !ok {
					return nil, fmt.Errorf("only scalars in a flow sequence: %q", s)
				}
			}
			out = append(out, v)
		}
		return out, nil
	case strings.HasPrefix(s, `"`):
		return doubleQuoted(s)
	case strings.HasPrefix(s, `'`):
		if len(s) < 2 || !strings.HasSuffix(s, `'`) || strings.Contains(strings.ReplaceAll(s[1:len(s)-1], "''", ""), "'") {
			return nil, fmt.Errorf("a bad single-quoted string %q", s)
		}
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'"), nil
	}
	if yaml11Words[strings.ToLower(s)] || (strings.EqualFold(s, "true") && s != "true") || (strings.EqualFold(s, "false") && s != "false") {
		return nil, fmt.Errorf("%q reads differently in YAML 1.1 and 1.2: quote it", s)
	}
	switch s {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	if decimalRE.MatchString(s) {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return nil, err
		}
		return n, nil
	}
	if quantityRE.MatchString(s) {
		return s, nil
	}
	c := s[0]
	if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '/' || strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../")) {
		return nil, fmt.Errorf("the plain scalar %q may be read as a number, a date or a token: quote it", s)
	}
	if strings.Contains(s, ": ") || strings.HasSuffix(s, ":") || strings.Contains(s, " #") || strings.ContainsAny(s, "{}[]`") {
		return nil, fmt.Errorf("the plain scalar %q holds YAML punctuation: quote it", s)
	}
	return s, nil
}

func doubleQuoted(s string) (string, error) {
	if len(s) < 2 || !strings.HasSuffix(s, `"`) {
		return "", fmt.Errorf("an unterminated string %q", s)
	}
	var b strings.Builder
	in := s[1 : len(s)-1]
	for i := 0; i < len(in); i++ {
		c := in[i]
		switch {
		case c == '"':
			return "", fmt.Errorf("an unescaped quote in %q", s)
		case c == '\\':
			if i+1 >= len(in) || (in[i+1] != '"' && in[i+1] != '\\') {
				return "", fmt.Errorf("only the escapes \\\" and \\\\ are taken: %q", s)
			}
			i++
			b.WriteByte(in[i])
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), nil
}

// splitFlow splits the inside of a flow sequence at commas outside quotes.
func splitFlow(s string) ([]string, error) {
	var out []string
	var q byte
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q == '"' && c == '\\':
			i++
		case q != 0 && c == q:
			q = 0
		case q != 0:
		case c == '"' || c == '\'':
			q = c
		case c == '[' || c == '{':
			return nil, fmt.Errorf("a nested flow collection")
		case c == ',':
			out = append(out, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	if q != 0 {
		return nil, fmt.Errorf("an unterminated string in a flow sequence")
	}
	if last := strings.TrimSpace(s[start:]); last != "" || len(out) > 0 {
		out = append(out, last)
	}
	for _, it := range out {
		if it == "" {
			return nil, fmt.Errorf("an empty item in a flow sequence")
		}
	}
	return out, nil
}
