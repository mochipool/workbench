package vaultkms

import (
	"fmt"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// The answers are read by a scanner of this package, not by encoding/json or
// platform/strictjson, for two reasons:
//
//   - A decrypt answer carries B (base64) and a login answer the token. Both
//     standard decoders copy every string they meet into memory of their own
//     (the decoder's read buffer, a Go string per token), which this package
//     cannot zero. The scanner copies nothing: it returns where each wanted
//     value is in the answer, and the secret is decoded from the answer's own
//     bytes into guarded memory, after which the answer is zeroed.
//   - strictjson refuses every key its target does not name, and a Vault or KMS
//     answer has many keys this client does not read (request_id, lease_id,
//     auth, wrap_info, key_version, ...) that differ between server versions.
//
// What strictjson guarantees and matters here the scanner does too: valid JSON
// only, no duplicate key in any object, no escape in a key (so two spellings of
// one key cannot both pass), bounded nesting and key count, nothing after the
// value. The wanted values are then checked for their exact type.

const (
	maxJSONDepth = 16
	maxJSONKeys  = 4096
)

// jsonValue is where one value is in an answer: its kind, and its bytes (a
// string without its quotes).
type jsonValue struct {
	kind       byte // 's' string, 't' true, 'f' false, 'z' null, '0' number, '{' object, '[' array
	start, end int
	escaped    bool        // a string with a backslash escape
	elems      []jsonValue // an array at a wanted path: its elements (not their insides)
}

// bytesIn returns the value's bytes in body.
func (v jsonValue) bytesIn(body []byte) []byte { return body[v.start:v.end] }

// plainString returns the bytes of a string without any escape.
func (v jsonValue) plainString(body []byte) ([]byte, bool) {
	if v.kind != 's' || v.escaped {
		return nil, false
	}
	return body[v.start:v.end], true
}

type jsonScan struct {
	b    []byte
	i    int
	keys int
	want map[string]bool
	got  map[string]jsonValue
}

func scanErr(why string) error {
	return fmt.Errorf("%w: the answer is not the JSON this call returns (%s)", ports.ErrBackendResponse, why)
}

// scanJSON checks body as one JSON object and returns the values at the paths
// asked for, each a dot-joined list of object keys from the top ("data.ttl").
// A path that is not in the answer is missing from the result.
func scanJSON(body []byte, paths ...string) (map[string]jsonValue, error) {
	s := &jsonScan{b: body, want: map[string]bool{}, got: map[string]jsonValue{}}
	for _, p := range paths {
		s.want[p] = true
	}
	s.ws()
	if s.i >= len(s.b) || s.b[s.i] != '{' {
		return nil, scanErr("not an object")
	}
	if err := s.value("", 0); err != nil {
		return nil, err
	}
	s.ws()
	if s.i != len(s.b) {
		return nil, scanErr("data after the value")
	}
	return s.got, nil
}

func (s *jsonScan) ws() {
	for s.i < len(s.b) {
		switch s.b[s.i] {
		case ' ', '\t', '\n', '\r':
			s.i++
		default:
			return
		}
	}
}

// value scans one value at path (the empty string for a place no path names).
func (s *jsonScan) value(path string, depth int) error {
	if depth > maxJSONDepth {
		return scanErr("nested too deep")
	}
	s.ws()
	if s.i >= len(s.b) {
		return scanErr("truncated")
	}
	start := s.i
	var v jsonValue
	switch c := s.b[s.i]; {
	case c == '{':
		if err := s.object(path, depth); err != nil {
			return err
		}
		v = jsonValue{kind: '{', start: start, end: s.i}
	case c == '[':
		elems, err := s.array(path, depth)
		if err != nil {
			return err
		}
		v = jsonValue{kind: '[', start: start, end: s.i, elems: elems}
	case c == '"':
		a, e, esc, err := s.str()
		if err != nil {
			return err
		}
		v = jsonValue{kind: 's', start: a, end: e, escaped: esc}
	case c == 't':
		if err := s.lit("true"); err != nil {
			return err
		}
		v = jsonValue{kind: 't', start: start, end: s.i}
	case c == 'f':
		if err := s.lit("false"); err != nil {
			return err
		}
		v = jsonValue{kind: 'f', start: start, end: s.i}
	case c == 'n':
		if err := s.lit("null"); err != nil {
			return err
		}
		v = jsonValue{kind: 'z', start: start, end: s.i}
	case c == '-' || ('0' <= c && c <= '9'):
		if err := s.number(); err != nil {
			return err
		}
		v = jsonValue{kind: '0', start: start, end: s.i}
	default:
		return scanErr("not a value")
	}
	if path != "" && s.want[path] {
		s.got[path] = v
	}
	return nil
}

func (s *jsonScan) object(path string, depth int) error {
	s.i++ // '{'
	seen := map[string]bool{}
	s.ws()
	if s.i < len(s.b) && s.b[s.i] == '}' {
		s.i++
		return nil
	}
	for {
		s.ws()
		if s.i >= len(s.b) || s.b[s.i] != '"' {
			return scanErr("an object key is not a string")
		}
		a, e, esc, err := s.str()
		if err != nil {
			return err
		}
		if esc {
			return scanErr("an escape in an object key")
		}
		if s.keys++; s.keys > maxJSONKeys {
			return scanErr("too many keys")
		}
		key := string(s.b[a:e]) // a key, never a secret
		if seen[key] {
			return scanErr("a duplicate key")
		}
		seen[key] = true
		s.ws()
		if s.i >= len(s.b) || s.b[s.i] != ':' {
			return scanErr("no colon after a key")
		}
		s.i++
		child := key
		if path != "" {
			child = path + "." + key
		}
		if err := s.value(child, depth+1); err != nil {
			return err
		}
		s.ws()
		if s.i >= len(s.b) {
			return scanErr("truncated")
		}
		switch s.b[s.i] {
		case ',':
			s.i++
		case '}':
			s.i++
			return nil
		default:
			return scanErr("no comma between members")
		}
	}
}

// array scans an array. At a wanted path it returns where its elements are.
func (s *jsonScan) array(path string, depth int) ([]jsonValue, error) {
	s.i++ // '['
	wanted := path != "" && s.want[path]
	var elems []jsonValue
	s.ws()
	if s.i < len(s.b) && s.b[s.i] == ']' {
		s.i++
		return elems, nil
	}
	for {
		s.ws()
		start := s.i
		if err := s.value("", depth+1); err != nil {
			return nil, err
		}
		if wanted {
			if len(elems) >= maxJSONKeys {
				return nil, scanErr("too many elements")
			}
			e := jsonValue{start: start, end: s.i}
			if c := s.b[start]; c == '"' {
				// re-read the string's bounds (value() recorded nothing for an unnamed place)
				save := s.i
				s.i = start
				a, z, esc, _ := s.str()
				s.i = save
				e = jsonValue{kind: 's', start: a, end: z, escaped: esc}
			} else {
				e.kind = kindOf(c)
			}
			elems = append(elems, e)
		}
		s.ws()
		if s.i >= len(s.b) {
			return nil, scanErr("truncated")
		}
		switch s.b[s.i] {
		case ',':
			s.i++
		case ']':
			s.i++
			return elems, nil
		default:
			return nil, scanErr("no comma between elements")
		}
	}
}

func kindOf(c byte) byte {
	switch c {
	case '{', '[', 't', 'f':
		return c
	case 'n':
		return 'z'
	}
	return '0'
}

// str scans a string and returns the bounds of its content.
func (s *jsonScan) str() (start, end int, escaped bool, err error) {
	s.i++ // '"'
	start = s.i
	for s.i < len(s.b) {
		c := s.b[s.i]
		switch {
		case c == '"':
			end = s.i
			s.i++
			return start, end, escaped, nil
		case c == '\\':
			escaped = true
			s.i++
			if s.i >= len(s.b) {
				return 0, 0, false, scanErr("truncated")
			}
			switch s.b[s.i] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				s.i++
			case 'u':
				if s.i+4 >= len(s.b) {
					return 0, 0, false, scanErr("truncated")
				}
				for _, h := range s.b[s.i+1 : s.i+5] {
					if !isHex(h) {
						return 0, 0, false, scanErr("a bad escape")
					}
				}
				s.i += 5
			default:
				return 0, 0, false, scanErr("a bad escape")
			}
		case c < 0x20:
			return 0, 0, false, scanErr("a control character in a string")
		default:
			s.i++
		}
	}
	return 0, 0, false, scanErr("truncated")
}

func isHex(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

func (s *jsonScan) lit(w string) error {
	if len(s.b)-s.i < len(w) || string(s.b[s.i:s.i+len(w)]) != w {
		return scanErr("not a value")
	}
	s.i += len(w)
	return nil
}

// number scans -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?
func (s *jsonScan) number() error {
	digits := func() int {
		n := 0
		for s.i < len(s.b) && '0' <= s.b[s.i] && s.b[s.i] <= '9' {
			s.i++
			n++
		}
		return n
	}
	if s.b[s.i] == '-' {
		s.i++
	}
	if s.i >= len(s.b) {
		return scanErr("a bad number")
	}
	if s.b[s.i] == '0' {
		s.i++
	} else if digits() == 0 {
		return scanErr("a bad number")
	}
	if s.i < len(s.b) && s.b[s.i] == '.' {
		s.i++
		if digits() == 0 {
			return scanErr("a bad number")
		}
	}
	if s.i < len(s.b) && (s.b[s.i] == 'e' || s.b[s.i] == 'E') {
		s.i++
		if s.i < len(s.b) && (s.b[s.i] == '+' || s.b[s.i] == '-') {
			s.i++
		}
		if digits() == 0 {
			return scanErr("a bad number")
		}
	}
	return nil
}

// smallUint reads a number value that is a non-negative whole number of at most
// ten digits.
func smallUint(body []byte, v jsonValue) (uint64, bool) {
	if v.kind != '0' {
		return 0, false
	}
	d := v.bytesIn(body)
	if len(d) == 0 || len(d) > 10 || (len(d) > 1 && d[0] == '0') {
		return 0, false
	}
	var n uint64
	for _, c := range d {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + uint64(c-'0')
	}
	return n, true
}
