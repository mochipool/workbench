// Package strictjson decodes JSON records strictly: a duplicate object key at any
// depth, a key the target does not know, trailing data and nesting deeper than a
// bound are refused, so one byte string has one meaning (encoding/json alone takes
// the last of two equal keys and drops unknown ones).
//
// A key must be byte-equal to the JSON name of a field of the target struct.
// encoding/json matches field names without regard to case, with Unicode simple
// folding ("Statement" and "ſtatement" both fill the field tagged "statement"),
// so its own unknown-field check lets two keys that differ only in case both
// reach one field, the last one winning. Unmarshal therefore walks the input
// against the target's type first and refuses any key that is not exactly one of
// the names, at every nesting level whose type it can see (structs, maps,
// slices, arrays and pointers to them). Below a type that decodes itself (a
// json.Unmarshaler, json.RawMessage) or an interface, only duplicates are
// refused: that part has no names to compare.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// MaxDepth bounds the nesting of a record.
const MaxDepth = 16

// ErrStrict is the refusal of a record that is not strict JSON for its target.
var ErrStrict = errors.New("strictjson: not a strict record")

var unmarshalerType = reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()

// Unmarshal decodes b into v (a non-nil pointer) after the input was walked
// against v's type: every object key of a struct is exactly one of its JSON
// names, no object has a key twice, the nesting is at most MaxDepth and nothing
// follows the value. Unknown fields are refused by the decoder as well.
func Unmarshal(b []byte, v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return fmt.Errorf("%w: the target is not a non-nil pointer", ErrStrict)
	}
	if err := check(b, rv.Type().Elem()); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", ErrStrict, err)
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("%w: trailing data", ErrStrict)
	}
	return nil
}

// Check walks b once and refuses a duplicate key in any object, nesting deeper
// than MaxDepth, and anything after the first value. It knows no target, so it
// compares no key with a name: Unmarshal does.
func Check(b []byte) error { return check(b, nil) }

func check(b []byte, t reflect.Type) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := walk(d, t, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("%w: trailing data", ErrStrict)
	}
	return nil
}

// shape is what the walk knows of the type at one place of the input: nil means
// nothing (only duplicates are refused below it).
func shape(t reflect.Type) reflect.Type {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil || t.Kind() == reflect.Interface || t.Implements(unmarshalerType) || reflect.PointerTo(t).Implements(unmarshalerType) {
		return nil
	}
	return t
}

// Names is the set of exact JSON object keys of a struct type, each with the
// type of its field: the tag's name, or the field's name when the tag gives
// none; a field tagged "-" and an unexported field have none; the fields of an
// embedded struct without a name are the struct's own.
func Names(t reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	for i := range t.NumField() {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if name == "" && f.Anonymous {
			et := f.Type
			if et.Kind() == reflect.Pointer {
				et = et.Elem()
			}
			if et.Kind() == reflect.Struct {
				for k, v := range Names(et) {
					if _, taken := out[k]; !taken {
						out[k] = v
					}
				}
				continue
			}
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[name] = f.Type
	}
	return out
}

func walk(d *json.Decoder, t reflect.Type, depth int) error {
	if depth > MaxDepth {
		return fmt.Errorf("%w: nested deeper than %d", ErrStrict, MaxDepth)
	}
	t = shape(t)
	tok, err := d.Token()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStrict, err)
	}
	switch tok {
	case json.Delim('{'):
		var names map[string]reflect.Type
		var elem reflect.Type
		switch {
		case t == nil:
		case t.Kind() == reflect.Struct:
			names = Names(t)
		case t.Kind() == reflect.Map:
			elem = t.Elem()
		default:
			return fmt.Errorf("%w: an object where a %s goes", ErrStrict, t)
		}
		seen := map[string]bool{}
		for d.More() {
			k, err := d.Token()
			if err != nil {
				return fmt.Errorf("%w: %v", ErrStrict, err)
			}
			ks, ok := k.(string)
			if !ok {
				return fmt.Errorf("%w: an object key is not a string", ErrStrict)
			}
			if seen[ks] {
				return fmt.Errorf("%w: duplicate key %q", ErrStrict, ks)
			}
			seen[ks] = true
			next := elem
			if names != nil {
				ft, known := names[ks]
				if !known {
					return fmt.Errorf("%w: unknown key %q (keys are compared byte for byte, case included)", ErrStrict, ks)
				}
				next = ft
			}
			if err := walk(d, next, depth+1); err != nil {
				return err
			}
		}
		if _, err := d.Token(); err != nil { // '}'
			return fmt.Errorf("%w: %v", ErrStrict, err)
		}
	case json.Delim('['):
		var elem reflect.Type
		if t != nil {
			if t.Kind() != reflect.Slice && t.Kind() != reflect.Array {
				return fmt.Errorf("%w: an array where a %s goes", ErrStrict, t)
			}
			elem = t.Elem()
		}
		for d.More() {
			if err := walk(d, elem, depth+1); err != nil {
				return err
			}
		}
		if _, err := d.Token(); err != nil {
			return fmt.Errorf("%w: %v", ErrStrict, err)
		}
	}
	return nil
}
