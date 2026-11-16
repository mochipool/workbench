package native

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// Native scripts as cardano-cli reads them from a script file and hashes them.
// A script is JSON of the forms `sig`, `all`, `any`, `atLeast`, `before` and
// `after`; its CBOR is the array the ledger defines (sig 0, all 1, any 2,
// atLeast 3, after 4, before 5) and its hash, the policy id, is blake2b-224
// over a zero byte and that CBOR.

// ErrScript: a native script file that cannot be read.
var ErrScript = errors.New("invalid native script")

// scriptCBOR converts a native script JSON document to its CBOR.
func scriptCBOR(raw []byte) ([]byte, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("%w: not valid JSON: %v", ErrScript, err)
	}
	return encodeScript(nil, v, 0)
}

func encodeScript(b []byte, v any, depth int) ([]byte, error) {
	if depth > 32 {
		return nil, fmt.Errorf("%w: nested too deeply", ErrScript)
	}
	o, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: a script is a JSON object with a type", ErrScript)
	}
	typ, _ := o["type"].(string)
	subs := func() ([]any, error) {
		l, ok := o["scripts"].([]any)
		if !ok {
			return nil, fmt.Errorf("%w: type %s needs a scripts array", ErrScript, typ)
		}
		return l, nil
	}
	slot := func() (uint64, error) {
		n, ok := o["slot"].(json.Number)
		if !ok {
			return 0, fmt.Errorf("%w: type %s needs a slot number", ErrScript, typ)
		}
		var s uint64
		if _, err := fmt.Sscanf(n.String(), "%d", &s); err != nil || n.String() != fmt.Sprint(s) {
			return 0, fmt.Errorf("%w: %s is not a slot number", ErrScript, n.String())
		}
		return s, nil
	}
	switch typ {
	case "sig":
		h, _ := o["keyHash"].(string)
		raw, err := hex.DecodeString(h)
		if err != nil || len(raw) != 28 {
			return nil, fmt.Errorf("%w: keyHash must be 56 hex characters", ErrScript)
		}
		b = cborArray(b, 2)
		b = cborUint(b, 0)
		return cborBytes(b, raw), nil
	case "all", "any":
		l, err := subs()
		if err != nil {
			return nil, err
		}
		b = cborArray(b, 2)
		b = cborUint(b, map[string]uint64{"all": 1, "any": 2}[typ])
		b = cborArray(b, len(l))
		for _, s := range l {
			if b, err = encodeScript(b, s, depth+1); err != nil {
				return nil, err
			}
		}
		return b, nil
	case "atLeast":
		l, err := subs()
		if err != nil {
			return nil, err
		}
		n, ok := o["required"].(json.Number)
		var req uint64
		if !ok {
			return nil, fmt.Errorf("%w: atLeast needs required", ErrScript)
		}
		if _, err := fmt.Sscanf(n.String(), "%d", &req); err != nil {
			return nil, fmt.Errorf("%w: required is not a number", ErrScript)
		}
		b = cborArray(b, 3)
		b = cborUint(b, 3)
		b = cborUint(b, req)
		b = cborArray(b, len(l))
		for _, s := range l {
			if b, err = encodeScript(b, s, depth+1); err != nil {
				return nil, err
			}
		}
		return b, nil
	case "before", "after":
		s, err := slot()
		if err != nil {
			return nil, err
		}
		b = cborArray(b, 2)
		b = cborUint(b, map[string]uint64{"after": 4, "before": 5}[typ])
		return cborUint(b, s), nil
	}
	return nil, fmt.Errorf("%w: unknown script type %q", ErrScript, typ)
}

// scriptHash is the policy id of a script CBOR.
func scriptHash(cbor []byte) [28]byte {
	h, _ := blake2b.New(28, nil)
	h.Write([]byte{0})
	h.Write(cbor)
	var out [28]byte
	copy(out[:], h.Sum(nil))
	return out
}

// PolicyID implements ports.PolicyIDCalculator.
//
// spec: SPO-10-EXT-004
func (Ledger) PolicyID(scriptJSON []byte) ([28]byte, error) {
	c, err := scriptCBOR(scriptJSON)
	if err != nil {
		return [28]byte{}, err
	}
	return scriptHash(c), nil
}

// mintScriptSet converts the script files of a mint to the witness set entry:
// the scripts as a tag-258 set in ascending order of their hash, which is how
// the ledger orders a script map. A script given twice is one script.
func mintScriptSet(files [][]byte) ([]byte, error) {
	type sc struct {
		h [28]byte
		c []byte
	}
	var list []sc
	seen := map[[28]byte]bool{}
	for _, f := range files {
		c, err := scriptCBOR(f)
		if err != nil {
			return nil, err
		}
		h := scriptHash(c)
		if seen[h] {
			continue
		}
		seen[h] = true
		list = append(list, sc{h, c})
	}
	sort.Slice(list, func(i, j int) bool { return bytes.Compare(list[i].h[:], list[j].h[:]) < 0 })
	var b []byte
	b = cborTag(b, 258)
	b = cborArray(b, len(list))
	for _, s := range list {
		b = append(b, s.c...)
	}
	return b, nil
}

var _ ports.PolicyIDCalculator = Ledger{}
