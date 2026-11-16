package transfer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// Object is a JSON object that keeps the order of its keys. The transfer
// file is written by `jq`, which keeps insertion order, and a rewrite by the
// port must leave every part it does not change as it was (key order, number
// literals, strings), so a file that went through the port and back stays
// byte-equal to what upstream would have written.
//
// Setting a key that exists changes it in place; a new key goes last; a
// deleted key and a later set of the same key goes last. That is `jq`'s
// `+=`, `del` and `+=` again.
type Object struct {
	keys []string
	vals map[string]json.RawMessage
}

// NewObject returns an empty object.
func NewObject() *Object { return &Object{vals: map[string]json.RawMessage{}} }

// ErrNotObject means a JSON value is not an object.
var ErrNotObject = errors.New("not a JSON object")

// ParseObject reads one JSON object. A key given twice keeps its first
// position and its last value, as `jq` reads it.
func ParseObject(b []byte) (*Object, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	t, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := t.(json.Delim); !ok || d != '{' {
		return nil, ErrNotObject
	}
	o := NewObject()
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		k := kt.(string)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		o.Set(k, v)
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after the JSON document")
	}
	return o, nil
}

// Get returns the raw value of a key.
func (o *Object) Get(k string) (json.RawMessage, bool) {
	v, ok := o.vals[k]
	return v, ok
}

// Has reports whether the key exists (a null value counts as existing).
func (o *Object) Has(k string) bool { _, ok := o.vals[k]; return ok }

// Keys returns the keys in order.
func (o *Object) Keys() []string { return append([]string(nil), o.keys...) }

// Set stores a value: in place when the key exists, last otherwise.
func (o *Object) Set(k string, v json.RawMessage) {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
}

// Delete removes a key.
func (o *Object) Delete(k string) {
	if _, ok := o.vals[k]; !ok {
		return
	}
	delete(o.vals, k)
	for i, kk := range o.keys {
		if kk == k {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			break
		}
	}
}

// Compact renders the object without whitespace.
func (o *Object) Compact() json.RawMessage {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(Str(k))
		buf.WriteByte(':')
		buf.Write(o.vals[k])
	}
	buf.WriteByte('}')
	return buf.Bytes()
}

// Indented renders the object as `jq` does: two spaces, a newline at the end.
func (o *Object) Indented() ([]byte, error) {
	var out bytes.Buffer
	if err := json.Indent(&out, o.Compact(), "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

// Child reads a key as an object; a missing key or null gives an empty one
// (what `jq`'s `+=` on a missing key starts from).
func (o *Object) Child(k string) (*Object, error) {
	v, ok := o.vals[k]
	if !ok || string(bytes.TrimSpace(v)) == "null" {
		return NewObject(), nil
	}
	c, err := ParseObject(v)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", k, err)
	}
	return c, nil
}

// Array reads a key as an array of raw values; missing and null are empty.
func (o *Object) Array(k string) ([]json.RawMessage, error) {
	v, ok := o.vals[k]
	if !ok || string(bytes.TrimSpace(v)) == "null" {
		return nil, nil
	}
	var a []json.RawMessage
	if err := json.Unmarshal(v, &a); err != nil {
		return nil, fmt.Errorf("%s is not an array", k)
	}
	return a, nil
}

// Str renders a string as `jq` prints it: the quote, the backslash and the
// control characters are escaped, the delete character as \u007f, and
// nothing else (no HTML escaping, no escaped U+2028).
func Str(s string) json.RawMessage {
	var b bytes.Buffer
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.Bytes()
}

// Num renders an unsigned integer.
func Num(n uint64) json.RawMessage { return json.RawMessage(strconv.FormatUint(n, 10)) }
