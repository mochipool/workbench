package native

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strconv"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
)

// Transaction metadata as cardano-cli 11.2.3.0 builds it from the files of
// `--metadata-json-file` (no schema), `--metadata-json-file` with
// `--json-metadata-detailed-schema` and `--metadata-cbor-file`, and the
// auxiliary data it writes: tag 259 over `{0: {label: mdVal}}`. The
// rules below were read off the tool's output in spo/test/parity.

// Errors of metadata composition.
var (
	// ErrMetadata: a metadata file is not valid metadata.
	ErrMetadata = errors.New("invalid transaction metadata")
	// ErrDuplicateLabel: two sources carry the same metadata label.
	// cardano-cli keeps the first silently; the port refuses.
	ErrDuplicateLabel = errors.New("a metadata label is given twice")
)

// mdKind is the kind of a mdVal.
type mdKind uint8

const (
	mdInt mdKind = iota + 1
	mdBytes
	mdText
	mdList
	mdMap
)

type mdPair struct{ k, v mdVal }

// mdVal is one transaction mdVal: an integer within -(2^64-1)..2^64-1,
// at most 64 bytes of bytes or UTF-8 text, a list, or a map that keeps its
// order.
type mdVal struct {
	kind mdKind
	i    *big.Int
	b    []byte
	s    string
	list []mdVal
	m    []mdPair
}

var (
	mdMax = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1))
	mdMin = new(big.Int).Neg(mdMax)
)

func mdText64(s string) (mdVal, error) {
	if len(s) > 64 {
		return mdVal{}, fmt.Errorf("%w: a text string is at most 64 UTF-8 bytes, %q has %d", ErrMetadata, s, len(s))
	}
	return mdVal{kind: mdText, s: s}, nil
}

func mdBytes64(b []byte) (mdVal, error) {
	if len(b) > 64 {
		return mdVal{}, fmt.Errorf("%w: a byte string is at most 64 bytes, this has %d", ErrMetadata, len(b))
	}
	return mdVal{kind: mdBytes, b: b}, nil
}

func mdInteger(n *big.Int) (mdVal, error) {
	if n.Cmp(mdMax) > 0 || n.Cmp(mdMin) < 0 {
		return mdVal{}, fmt.Errorf("%w: the number %s is outside -(2^64-1)..2^64-1", ErrMetadata, n)
	}
	return mdVal{kind: mdInt, i: n}, nil
}

// hexBytes decodes `0x` followed by an even number of lower-case hex digits.
// cardano-cli leaves `0xAb` and `0XAB` as text.
func hexBytes(s string) ([]byte, bool) {
	if !strings.HasPrefix(s, "0x") || s != strings.ToLower(s) {
		return nil, false
	}
	b, err := hex.DecodeString(s[2:])
	if err != nil {
		return nil, false
	}
	return b, true
}

// ---- JSON, no schema -----------------------------------------------------

func jsonNumber(n json.Number) (*big.Int, error) {
	s := n.String()
	if strings.ContainsAny(s, "eE") {
		// An exponent far from the digits is not a metadata number, and
		// expanding it would be a denial of service.
		if _, exp, _ := strings.Cut(strings.ToLower(s), "e"); len(exp) > 3 {
			return nil, fmt.Errorf("%w: the number %s is outside -(2^64-1)..2^64-1", ErrMetadata, s)
		}
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok {
		return nil, fmt.Errorf("%w: %s is not a number", ErrMetadata, s)
	}
	if !r.IsInt() {
		return nil, fmt.Errorf("%w: JSON numbers must be integers, got %s", ErrMetadata, s)
	}
	return new(big.Int).Set(r.Num()), nil
}

// noSchemaKey converts an object key: a signed decimal number without
// leading zeros (`-0` and `+5` included, `007` not) is an integer, `0x` and
// lower-case hex is bytes, anything else text.
func noSchemaKey(k string) (mdVal, error) {
	t := k
	if strings.HasPrefix(t, "-") || strings.HasPrefix(t, "+") {
		t = t[1:]
	}
	if t != "" && strings.Trim(t, "0123456789") == "" && (t == "0" || t[0] != '0') {
		n, _ := new(big.Int).SetString(strings.TrimPrefix(k, "+"), 10)
		return mdInteger(n)
	}
	if b, ok := hexBytes(k); ok {
		return mdBytes64(b)
	}
	return mdText64(k)
}

func noSchemaValue(v any) (mdVal, error) {
	switch x := v.(type) {
	case nil:
		return mdVal{}, fmt.Errorf("%w: JSON null values are not supported", ErrMetadata)
	case bool:
		return mdVal{}, fmt.Errorf("%w: JSON bool values are not supported", ErrMetadata)
	case json.Number:
		n, err := jsonNumber(x)
		if err != nil {
			return mdVal{}, err
		}
		return mdInteger(n)
	case string:
		if b, ok := hexBytes(x); ok {
			return mdBytes64(b)
		}
		return mdText64(x)
	case []any:
		out := mdVal{kind: mdList}
		for _, e := range x {
			m, err := noSchemaValue(e)
			if err != nil {
				return mdVal{}, err
			}
			out.list = append(out.list, m)
		}
		return out, nil
	case orderedObject:
		// cardano-cli sorts an object's entries by the CBOR bytes of the
		// converted key, and a repeated key keeps the first value.
		seen := map[string]bool{}
		type ent struct {
			enc []byte
			p   mdPair
		}
		var ents []ent
		for _, kv := range x {
			if seen[kv.k] {
				continue
			}
			seen[kv.k] = true
			kk, err := noSchemaKey(kv.k)
			if err != nil {
				return mdVal{}, err
			}
			vv, err := noSchemaValue(kv.v)
			if err != nil {
				return mdVal{}, err
			}
			ents = append(ents, ent{kk.encode(nil), mdPair{kk, vv}})
		}
		sort.SliceStable(ents, func(i, j int) bool { return bytes.Compare(ents[i].enc, ents[j].enc) < 0 })
		out := mdVal{kind: mdMap}
		for _, e := range ents {
			out.m = append(out.m, e.p)
		}
		return out, nil
	}
	return mdVal{}, fmt.Errorf("%w: unexpected JSON value", ErrMetadata)
}

// ---- JSON, detailed schema ------------------------------------------------

func detailedValue(v any) (mdVal, error) {
	o, ok := v.(orderedObject)
	if !ok || len(o) != 1 {
		return mdVal{}, fmt.Errorf("%w: a detailed-schema value is an object with one of int, bytes, string, list, map", ErrMetadata)
	}
	k, x := o[0].k, o[0].v
	switch k {
	case "int":
		n, ok := x.(json.Number)
		if !ok {
			return mdVal{}, fmt.Errorf("%w: int needs a number", ErrMetadata)
		}
		i, err := jsonNumber(n)
		if err != nil {
			return mdVal{}, err
		}
		return mdInteger(i)
	case "bytes":
		s, ok := x.(string)
		if !ok {
			return mdVal{}, fmt.Errorf("%w: bytes needs a hex string", ErrMetadata)
		}
		b, err := hex.DecodeString(s)
		if err != nil || s != strings.ToLower(s) {
			return mdVal{}, fmt.Errorf("%w: %q is not lower-case hex", ErrMetadata, s)
		}
		return mdBytes64(b)
	case "string":
		s, ok := x.(string)
		if !ok {
			return mdVal{}, fmt.Errorf("%w: string needs a string", ErrMetadata)
		}
		return mdText64(s)
	case "list":
		l, ok := x.([]any)
		if !ok {
			return mdVal{}, fmt.Errorf("%w: list needs an array", ErrMetadata)
		}
		out := mdVal{kind: mdList}
		for _, e := range l {
			m, err := detailedValue(e)
			if err != nil {
				return mdVal{}, err
			}
			out.list = append(out.list, m)
		}
		return out, nil
	case "map":
		l, ok := x.([]any)
		if !ok {
			return mdVal{}, fmt.Errorf("%w: map needs an array of {k, v}", ErrMetadata)
		}
		out := mdVal{kind: mdMap}
		for _, e := range l {
			kv, ok := e.(orderedObject)
			if !ok || len(kv) != 2 {
				return mdVal{}, fmt.Errorf("%w: a map entry is {\"k\": .., \"v\": ..}", ErrMetadata)
			}
			var kk, vv any
			for _, f := range kv {
				switch f.k {
				case "k":
					kk = f.v
				case "v":
					vv = f.v
				default:
					return mdVal{}, fmt.Errorf("%w: a map entry is {\"k\": .., \"v\": ..}", ErrMetadata)
				}
			}
			km, err := detailedValue(kk)
			if err != nil {
				return mdVal{}, err
			}
			vm, err := detailedValue(vv)
			if err != nil {
				return mdVal{}, err
			}
			out.m = append(out.m, mdPair{km, vm})
		}
		return out, nil
	}
	return mdVal{}, fmt.Errorf("%w: %q is not a detailed-schema key", ErrMetadata, k)
}

// orderedObject is a JSON object that keeps its keys in file order.
type orderedObject []struct {
	k string
	v any
}

// parseJSONOrdered reads one JSON value, keeping object key order and
// numbers exact.
func parseJSONOrdered(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			var o orderedObject
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				v, err := parseJSONOrdered(dec)
				if err != nil {
					return nil, err
				}
				o = append(o, struct {
					k string
					v any
				}{kt.(string), v})
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			if o == nil {
				o = orderedObject{}
			}
			return o, nil
		case '[':
			l := []any{}
			for dec.More() {
				v, err := parseJSONOrdered(dec)
				if err != nil {
					return nil, err
				}
				l = append(l, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return l, nil
		}
	}
	return tok, nil
}

// metadataFromJSON converts a metadata JSON file into label -> mdVal. The
// top level is an object from an unsigned label to a value.
func metadataFromJSON(data []byte, detailed bool) (map[uint64]mdVal, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := parseJSONOrdered(dec)
	if err != nil {
		return nil, fmt.Errorf("%w: not valid JSON: %v", ErrMetadata, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: not valid JSON: trailing data", ErrMetadata)
	}
	top, ok := v.(orderedObject)
	if !ok {
		return nil, fmt.Errorf("%w: the JSON metadata top level must be a map (JSON object) from word to value", ErrMetadata)
	}
	out := map[uint64]mdVal{}
	for _, kv := range top {
		label, err := strconv.ParseUint(kv.k, 10, 64)
		if err != nil || strings.Trim(kv.k, "0123456789") != "" {
			return nil, fmt.Errorf("%w: the JSON metadata top level must be a map with unsigned integer keys, invalid key %q", ErrMetadata, kv.k)
		}
		var m mdVal
		if detailed {
			m, err = detailedValue(kv.v)
		} else {
			m, err = noSchemaValue(kv.v)
		}
		if err != nil {
			return nil, fmt.Errorf("within the metadata item %s: %w", kv.k, err)
		}
		out[label] = m
	}
	return out, nil
}

// ---- CBOR ---------------------------------------------------------------

type mdReader struct {
	b     []byte
	depth int
}

func (r *mdReader) byte() (byte, error) {
	if len(r.b) == 0 {
		return 0, fmt.Errorf("%w: the CBOR ends too early", ErrMetadata)
	}
	c := r.b[0]
	r.b = r.b[1:]
	return c, nil
}

// head reads an initial byte; indefinite is true for additional info 31.
func (r *mdReader) head() (major byte, arg uint64, indefinite bool, err error) {
	c, err := r.byte()
	if err != nil {
		return 0, 0, false, err
	}
	major, ai := c>>5, c&0x1f
	switch {
	case ai < 24:
		return major, uint64(ai), false, nil
	case ai == 31:
		return major, 0, true, nil
	case ai > 27:
		return 0, 0, false, fmt.Errorf("%w: reserved CBOR additional information", ErrMetadata)
	}
	n := 1 << (ai - 24)
	if len(r.b) < n {
		return 0, 0, false, fmt.Errorf("%w: the CBOR ends too early", ErrMetadata)
	}
	for _, c := range r.b[:n] {
		arg = arg<<8 | uint64(c)
	}
	r.b = r.b[n:]
	return major, arg, false, nil
}

func (r *mdReader) isBreak() bool { return len(r.b) > 0 && r.b[0] == 0xff }

func (r *mdReader) chunks(major byte, arg uint64, indef bool) ([]byte, error) {
	if !indef {
		if uint64(len(r.b)) < arg {
			return nil, fmt.Errorf("%w: the CBOR ends too early", ErrMetadata)
		}
		out := r.b[:arg]
		r.b = r.b[arg:]
		return out, nil
	}
	var out []byte
	for !r.isBreak() {
		m, a, ind, err := r.head()
		if err != nil {
			return nil, err
		}
		if m != major || ind {
			return nil, fmt.Errorf("%w: a bad chunk of a string", ErrMetadata)
		}
		c, err := r.chunks(major, a, false)
		if err != nil {
			return nil, err
		}
		out = append(out, c...)
	}
	r.b = r.b[1:]
	return out, nil
}

func (r *mdReader) value() (mdVal, error) {
	if r.depth++; r.depth > 100 {
		return mdVal{}, fmt.Errorf("%w: the metadata is nested too deeply", ErrMetadata)
	}
	defer func() { r.depth-- }()
	major, arg, indef, err := r.head()
	if err != nil {
		return mdVal{}, err
	}
	switch major {
	case 0:
		return mdInteger(new(big.Int).SetUint64(arg))
	case 1:
		n := new(big.Int).SetUint64(arg)
		return mdInteger(n.Neg(n).Sub(n, big.NewInt(1)))
	case 2:
		b, err := r.chunks(2, arg, indef)
		if err != nil {
			return mdVal{}, err
		}
		return mdBytes64(append([]byte(nil), b...))
	case 3:
		b, err := r.chunks(3, arg, indef)
		if err != nil {
			return mdVal{}, err
		}
		return mdText64(string(b))
	case 4:
		out := mdVal{kind: mdList}
		for i := uint64(0); indef && !r.isBreak() || !indef && i < arg; i++ {
			e, err := r.value()
			if err != nil {
				return mdVal{}, err
			}
			out.list = append(out.list, e)
		}
		if indef {
			r.b = r.b[1:]
		}
		return out, nil
	case 5:
		out := mdVal{kind: mdMap}
		for i := uint64(0); indef && !r.isBreak() || !indef && i < arg; i++ {
			k, err := r.value()
			if err != nil {
				return mdVal{}, err
			}
			v, err := r.value()
			if err != nil {
				return mdVal{}, err
			}
			out.m = append(out.m, mdPair{k, v})
		}
		if indef {
			r.b = r.b[1:]
		}
		return out, nil
	}
	return mdVal{}, fmt.Errorf("%w: a mdVal is an integer, bytes, text, list or map", ErrMetadata)
}

// metadataFromCBOR reads a `--metadata-cbor-file`: a map from label to
// mdVal, with nothing after it.
func metadataFromCBOR(data []byte) (map[uint64]mdVal, error) {
	r := &mdReader{b: data}
	major, arg, indef, err := r.head()
	if err != nil {
		return nil, err
	}
	if major != 5 {
		return nil, fmt.Errorf("%w: the CBOR metadata must be a map from label to mdVal", ErrMetadata)
	}
	out := map[uint64]mdVal{}
	for i := uint64(0); indef && !r.isBreak() || !indef && i < arg; i++ {
		lm, la, lind, err := r.head()
		if err != nil {
			return nil, err
		}
		if lm != 0 || lind {
			return nil, fmt.Errorf("%w: a metadata label is an unsigned integer", ErrMetadata)
		}
		v, err := r.value()
		if err != nil {
			return nil, err
		}
		if _, dup := out[la]; dup {
			return nil, fmt.Errorf("%w: label %d appears twice in the file", ErrDuplicateLabel, la)
		}
		out[la] = v
	}
	if indef {
		r.b = r.b[1:]
	}
	if len(r.b) != 0 {
		return nil, fmt.Errorf("%w: data after the metadata map", ErrMetadata)
	}
	return out, nil
}

// ---- encoding -------------------------------------------------------------

func (m mdVal) encode(b []byte) []byte {
	switch m.kind {
	case mdInt:
		if m.i.Sign() >= 0 {
			return cborUint(b, m.i.Uint64())
		}
		n := new(big.Int).Neg(m.i)
		n.Sub(n, big.NewInt(1))
		return cborHead(b, 1, n.Uint64())
	case mdBytes:
		return cborBytes(b, m.b)
	case mdText:
		return cborText(b, m.s)
	case mdList:
		b = cborArray(b, len(m.list))
		for _, e := range m.list {
			b = e.encode(b)
		}
		return b
	default:
		b = cborMap(b, len(m.m))
		for _, p := range m.m {
			b = p.k.encode(b)
			b = p.v.encode(b)
		}
		return b
	}
}

// messageMd is the CIP-20 mdVal of label 674: `{"msg": [lines]}`,
// or `{"enc": "basic", "msg": [lines]}` for an encrypted message.
func messageMd(lines []string, enc string) (mdVal, error) {
	list := mdVal{kind: mdList}
	for _, l := range lines {
		t, err := mdText64(l)
		if err != nil {
			return mdVal{}, err
		}
		list.list = append(list.list, t)
	}
	m := mdVal{kind: mdMap}
	if enc != "" {
		m.m = append(m.m, mdPair{mdVal{kind: mdText, s: "enc"}, mdVal{kind: mdText, s: enc}})
	}
	m.m = append(m.m, mdPair{mdVal{kind: mdText, s: "msg"}, list})
	return m, nil
}

// composeAuxData builds the auxiliary data of a transaction: the user files
// in command-line order, then the message metadata, merged into one map by
// label in ascending order, wrapped as `tag 259 {0: metadata}`. A label that
// two sources carry is refused: cardano-cli keeps the first and drops the
// second without a word (SPO-Pparam-IF-016). Nil when there is no metadata.
//
// spec: SPO-Pparam-IF-014, SPO-Pparam-IF-015, SPO-Pparam-IF-016, SPO-Pparam-OUT-001, SPO-Pparam-OUT-002
func composeAuxData(files []txbuild.MetadataFile, lines []string, enc string) ([]byte, error) {
	labels := map[uint64]mdVal{}
	add := func(src string, m map[uint64]mdVal) error {
		for l, v := range m {
			if _, dup := labels[l]; dup {
				return fmt.Errorf("%w: label %d from %s", ErrDuplicateLabel, l, src)
			}
			labels[l] = v
		}
		return nil
	}
	for _, f := range files {
		var m map[uint64]mdVal
		var err error
		switch f.Format {
		case txbuild.MetadataJSON:
			m, err = metadataFromJSON(f.Data, false)
		case txbuild.MetadataCBOR:
			m, err = metadataFromCBOR(f.Data)
		default:
			err = fmt.Errorf("%w: unknown format %q", ErrMetadata, f.Format)
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.Name, err)
		}
		if err := add(f.Name, m); err != nil {
			return nil, err
		}
	}
	if len(lines) > 0 {
		m, err := messageMd(lines, enc)
		if err != nil {
			return nil, err
		}
		if err := add("the message", map[uint64]mdVal{674: m}); err != nil {
			return nil, err
		}
	}
	if len(labels) == 0 {
		return nil, nil
	}
	keys := make([]uint64, 0, len(labels))
	for l := range labels {
		keys = append(keys, l)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	var b []byte
	b = cborTag(b, 259)
	b = cborMap(b, 1)
	b = cborUint(b, 0)
	b = cborMap(b, len(keys))
	for _, l := range keys {
		b = cborUint(b, l)
		b = labels[l].encode(b)
	}
	return b, nil
}

// ConvertMetadataJSON converts a metadata JSON file with the no-schema or
// the detailed-schema rules and returns the metadata map as CBOR (labels
// ascending), what `--metadata-json-file` produces. It exists for tests and
// for callers that want to check a file before a transaction is built.
func ConvertMetadataJSON(data []byte, detailed bool) ([]byte, error) {
	m, err := metadataFromJSON(data, detailed)
	if err != nil {
		return nil, err
	}
	keys := make([]uint64, 0, len(m))
	for l := range m {
		keys = append(keys, l)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	b := cborMap(nil, len(keys))
	for _, l := range keys {
		b = cborUint(b, l)
		b = m[l].encode(b)
	}
	return b, nil
}
