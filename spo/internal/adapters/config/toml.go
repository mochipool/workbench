package config

import (
	"fmt"

	"github.com/mochipool/workbench/spo/internal/platform/tomlsubset"
)

// The workspace file is the subset of TOML that internal/platform/tomlsubset
// parses, shared with the relay's configuration file. This dialect has:
// [section] headers (one level, bare names), key = value with bare keys, and
// values that are basic strings with the escapes \" \\ \n \t, decimal integers
// and the booleans true and false. Arrays, arrays of tables, inline tables,
// dotted keys, literal or multi-line strings, floats, dates and hexadecimal
// integers are errors, not silent misreadings, and so is every control
// character but tab (SPO-Xmailbox-SEC-019). A key that occurs twice in a
// section is an error.

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

var dialect = tomlsubset.Options{Escapes: "nt"}

func parseDocument(data []byte) (*document, error) {
	raw, err := tomlsubset.Parse(data, dialect)
	if err != nil {
		return nil, err
	}
	doc := &document{}
	for _, t := range raw.Tables {
		sec := &section{name: t.Name, line: t.Line}
		for _, e := range t.Entries {
			v := value{line: e.Val.Line}
			switch e.Val.Kind {
			case tomlsubset.String:
				v.kind, v.s = kindString, e.Val.Str
			case tomlsubset.Int:
				v.kind, v.i = kindInt, e.Val.Int
			case tomlsubset.Bool:
				v.kind, v.b = kindBool, e.Val.Bool
			}
			sec.entries = append(sec.entries, entry{e.Key, v})
		}
		doc.sections = append(doc.sections, sec)
	}
	return doc, nil
}

// quoter writes strings for Marshal and remembers the first one the file cannot
// hold, with the field that has it.
type quoter struct{ err error }

func (q *quoter) quote(field, s string) string {
	out, err := tomlsubset.Quote(s)
	if err != nil && q.err == nil {
		q.err = fmt.Errorf("%s %w", field, err)
	}
	return out
}
