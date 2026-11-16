package pool

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// odoc is a JSON object that keeps its keys in file order, as jq does: a key
// that is set for the first time goes last, a key that exists keeps its
// place. The descriptor is rewritten as a whole after every update
// (SPO-05a-OUT-009), so the order and the formatting are part of what
// parity compares.
type odoc struct {
	keys []string
	vals map[string]json.RawMessage
}

func newODoc() *odoc { return &odoc{vals: map[string]json.RawMessage{}} }

func parseODoc(b []byte) (*odoc, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("not a JSON object")
	}
	o := newODoc()
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		k, _ := kt.(string)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		o.set(k, v)
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data after the JSON object")
	}
	return o, nil
}

func (o *odoc) set(k string, v json.RawMessage) {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
}

func (o *odoc) setAny(k string, v any) {
	b, _ := marshalNoEscape(v)
	o.set(k, b)
}

func (o *odoc) del(k string) {
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

func (o *odoc) clone() *odoc {
	c := newODoc()
	for _, k := range o.keys {
		c.set(k, append(json.RawMessage(nil), o.vals[k]...))
	}
	return c
}

// text reads a value as `jq -r` prints it: a string as is, a number or a
// boolean as its literal. null and absent are "not present".
func (o *odoc) text(k string) (string, bool) {
	raw, ok := o.vals[k]
	if !ok {
		return "", false
	}
	return rawText(raw)
}

func rawText(raw json.RawMessage) (string, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return "", false
	}
	var s string
	if raw[0] == '"' {
		if json.Unmarshal(raw, &s) != nil {
			return "", false
		}
		return s, true
	}
	if raw[0] == '{' || raw[0] == '[' {
		return "", false
	}
	return string(raw), true
}

func marshalNoEscape(v any) (json.RawMessage, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// renderJQ writes the object as `jq .` does: two-space indent, keys in
// order, a trailing newline.
func (o *odoc) renderJQ() []byte {
	var compact bytes.Buffer
	compact.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			compact.WriteByte(',')
		}
		kb, _ := marshalNoEscape(k)
		compact.Write(kb)
		compact.WriteByte(':')
		compact.Write(o.vals[k])
	}
	compact.WriteByte('}')
	var out bytes.Buffer
	if err := json.Indent(&out, compact.Bytes(), "", "  "); err != nil {
		// Every value was valid when it went in.
		panic(fmt.Sprintf("pool: render descriptor: %v", err))
	}
	out.WriteByte('\n')
	return out.Bytes()
}

func quote(s string) string { b, _ := marshalNoEscape(s); return string(b) }

func utoa(n uint64) string { return strconv.FormatUint(n, 10) }
