package strictjson

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type rec struct {
	A int            `json:"a"`
	B map[string]int `json:"b"`
	C []rec          `json:"c"`
}

// A strict record has one meaning: duplicate keys at any depth, unknown keys,
// trailing data and deep nesting are refused.
//
// spec: SPO-Xparty-OUT-007, SPO-Xmailbox-OUT-097
func TestUnmarshalIsStrict(t *testing.T) {
	var r rec
	if err := Unmarshal([]byte(`{"a":1,"b":{"x":2},"c":[{"a":3}]}`), &r); err != nil || r.A != 1 || r.C[0].A != 3 {
		t.Fatalf("%+v %v", r, err)
	}
	for name, in := range map[string]string{
		"duplicate top":    `{"a":1,"a":2}`,
		"duplicate nested": `{"c":[{"a":1,"a":1}]}`,
		"duplicate in map": `{"b":{"x":1,"x":2}}`,
		"unknown":          `{"a":1,"z":0}`,
		"trailing":         `{"a":1} {}`,
		"trailing garbage": `{"a":1}x`,
		"deep":             strings.Repeat(`{"c":[`, 20) + strings.Repeat(`]}`, 20),
		"truncated":        `{"a":1`,
		"empty":            ``,
	} {
		var r rec
		if err := Unmarshal([]byte(in), &r); !errors.Is(err, ErrStrict) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

type stmt struct {
	V         int    `json:"v"`
	Statement string `json:"statement"`
	Inner     *stmt  `json:"inner,omitempty"`
	List      []stmt `json:"list,omitempty"`
}

// A key must be byte-equal to a JSON name of the target: encoding/json matches
// names without case and with Unicode folding, so "Statement" and "ſtatement"
// (long s) would both fill "statement", the last one winning. The reviewer's
// inputs, at the top and nested in a pointer and a slice.
//
// spec: SPO-Xparty-OUT-007, SPO-Xmailbox-OUT-097, SPO-Xparty-IF-009
func TestKeysAreComparedExactly(t *testing.T) {
	for name, in := range map[string]string{
		"three spellings":    `{"v":1,"statement":"aa","Statement":"bb","ſtatement":"cc"}`,
		"upper case":         `{"V":1,"STATEMENT":"aa"}`,
		"one capital":        `{"v":1,"Statement":"aa"}`,
		"long s alone":       `{"v":1,"ſtatement":"aa"}`,
		"kelvin sign":        `{"v":1,"statement":"aa","inner":{"v":1,"statement":"K"},"list":[{"V":2}]}`,
		"nested capital":     `{"v":1,"inner":{"v":1,"Statement":"x"}}`,
		"capital in a slice": `{"v":1,"list":[{"v":1},{"STATEMENT":"x"}]}`,
	} {
		var s stmt
		if err := Unmarshal([]byte(in), &s); !errors.Is(err, ErrStrict) {
			t.Errorf("%s: accepted as %+v (%v)", name, s, err)
		}
	}
	var s stmt
	if err := Unmarshal([]byte(`{"v":1,"statement":"aa","inner":{"v":2,"statement":"bb"},"list":[{"v":3,"statement":"cc"}]}`), &s); err != nil || s.Inner.Statement != "bb" || s.List[0].V != 3 {
		t.Fatalf("an exact record is refused: %+v %v", s, err)
	}
}

// Accepted input has the meaning of its re-encoding and holds no key outside
// the exact names of the target.
//
// spec: SPO-Xparty-OUT-007, SPO-Xmailbox-OUT-097
func FuzzCheck(f *testing.F) {
	f.Add([]byte(`{"a":1,"b":{"x":2},"c":[{"a":3}]}`))
	f.Add([]byte(`{"a":1,"a":2}`))
	f.Add([]byte(`{"v":1,"statement":"aa","Statement":"bb","ſtatement":"cc"}`))
	f.Add([]byte(`{"V":1,"STATEMENT":"aa"}`))
	f.Add([]byte(`{"v":1,"statement":"aa","inner":{"v":2,"statement":"bb"},"list":[{"v":3}]}`))
	names := map[string]bool{"v": true, "statement": true, "inner": true, "list": true}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<14 {
			return
		}
		var r rec
		_ = Unmarshal(b, &r)
		var s stmt
		if err := Unmarshal(b, &s); err != nil {
			return
		}
		var generic any
		if err := json.Unmarshal(b, &generic); err != nil {
			t.Fatalf("accepted input is not JSON: %v", err)
		}
		var bad []string
		visit(generic, func(k string) {
			if !names[k] {
				bad = append(bad, k)
			}
		})
		if len(bad) > 0 {
			t.Fatalf("accepted %q with keys %q outside the names", b, bad)
		}
		again, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		var s2 stmt
		if err := Unmarshal(again, &s2); err != nil || !reflect.DeepEqual(s, s2) {
			t.Fatalf("the re-encoding %s means %+v, the input %+v (%v)", again, s2, s, err)
		}
	})
}

// visit calls fn with every object key of a decoded JSON value.
func visit(v any, fn func(string)) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			fn(k)
			visit(e, fn)
		}
	case []any:
		for _, e := range x {
			visit(e, fn)
		}
	}
}
