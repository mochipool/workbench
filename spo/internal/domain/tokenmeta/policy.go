package tokenmeta

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"golang.org/x/crypto/blake2b"
)

// ErrPolicy: a policy script that cannot be read, or whose hash is not the
// subject's policy id.
var ErrPolicy = errors.New("invalid policy script")

// The `policy` property of an entry is the hex of the CBOR array [tag,
// native script]: the tag is 0 for a script without a time lock and 1 for one
// with `before` or `after`. (This is what the reference tool writes; observed
// on 23 policies of the public registry, where the tag follows the time lock
// and the policy id is blake2b-224 of 0x00 and the native script alone.)

type script struct {
	kind  string // sig, all, any, atLeast, before, after
	hash  [28]byte
	n     uint64
	subs  []script
	slot  uint64
	cbor  []byte
	timed bool
}

// ScriptCBOR converts the JSON of a native script (as `cardano-cli` reads it)
// to its CBOR, and reports whether it has a time lock.
func ScriptCBOR(raw []byte) (cbor []byte, timeLocked bool, err error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, false, fmt.Errorf("%w: not valid JSON", ErrPolicy)
	}
	var timed bool
	b, err := encodeScript(nil, v, 0, &timed)
	return b, timed, err
}

func encodeScript(b []byte, v any, depth int, timed *bool) ([]byte, error) {
	if depth > 32 {
		return nil, fmt.Errorf("%w: nested too deeply", ErrPolicy)
	}
	o, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: a script is a JSON object with a type", ErrPolicy)
	}
	typ, _ := o["type"].(string)
	subs := func() ([]any, error) {
		l, ok := o["scripts"].([]any)
		if !ok {
			return nil, fmt.Errorf("%w: type %s needs a scripts array", ErrPolicy, typ)
		}
		return l, nil
	}
	num := func(key string) (uint64, error) {
		n, ok := o[key].(json.Number)
		if !ok {
			return 0, fmt.Errorf("%w: type %s needs a %s number", ErrPolicy, typ, key)
		}
		u, err := strconv.ParseUint(n.String(), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%w: %s is not a whole number", ErrPolicy, n.String())
		}
		return u, nil
	}
	switch typ {
	case "sig":
		h, _ := o["keyHash"].(string)
		raw, err := hex.DecodeString(h)
		if err != nil || len(raw) != 28 {
			return nil, fmt.Errorf("%w: keyHash must be 56 hex characters", ErrPolicy)
		}
		b = append(b, 0x82, 0x00)
		return append(b, cborBytes(raw)...), nil
	case "all", "any":
		l, err := subs()
		if err != nil {
			return nil, err
		}
		b = append(b, 0x82, map[string]byte{"all": 1, "any": 2}[typ])
		b = append(b, head(4, uint64(len(l)))...)
		for _, s := range l {
			if b, err = encodeScript(b, s, depth+1, timed); err != nil {
				return nil, err
			}
		}
		return b, nil
	case "atLeast":
		l, err := subs()
		if err != nil {
			return nil, err
		}
		n, err := num("required")
		if err != nil {
			return nil, err
		}
		b = append(b, 0x83, 0x03)
		b = append(b, cborUint(n)...)
		b = append(b, head(4, uint64(len(l)))...)
		for _, s := range l {
			if b, err = encodeScript(b, s, depth+1, timed); err != nil {
				return nil, err
			}
		}
		return b, nil
	case "after", "before":
		n, err := num("slot")
		if err != nil {
			return nil, err
		}
		*timed = true
		b = append(b, 0x82, map[string]byte{"after": 4, "before": 5}[typ])
		return append(b, cborUint(n)...), nil
	}
	return nil, fmt.Errorf("%w: unknown script type %q", ErrPolicy, typ)
}

func blake224(parts ...[]byte) (out [28]byte) {
	h, _ := blake2b.New(28, nil)
	for _, p := range parts {
		h.Write(p)
	}
	copy(out[:], h.Sum(nil))
	return out
}

// PolicyID is blake2b-224 over a zero byte and the CBOR of the native script.
func PolicyID(scriptCBOR []byte) [28]byte { return blake224([]byte{0}, scriptCBOR) }

// PolicyValue builds the `policy` property of an entry from the JSON of the
// policy script: the hex of [tag, native script], and the policy id it
// hashes to.
func PolicyValue(scriptJSON []byte) (value string, id [28]byte, err error) {
	c, timed, err := ScriptCBOR(scriptJSON)
	if err != nil {
		return "", id, err
	}
	tag := byte(0)
	if timed {
		tag = 1
	}
	return hex.EncodeToString(append([]byte{0x82, tag}, c...)), PolicyID(c), nil
}

// parsePolicy reads the `policy` value: the wrapper, then the native script.
func parsePolicy(value string) (s script, id [28]byte, err error) {
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) < 3 || raw[0] != 0x82 || raw[1] > 1 {
		return s, id, fmt.Errorf("%w: the policy is not the hex of [tag, native script]", ErrPolicy)
	}
	native := raw[2:]
	r := &reader{b: native}
	s, err = readScript(r, 0)
	if err != nil || r.i != len(native) {
		return s, id, fmt.Errorf("%w: the native script is malformed", ErrPolicy)
	}
	return s, PolicyID(native), nil
}

func readScript(r *reader, depth int) (script, error) {
	var s script
	if depth > 32 {
		return s, errCBOR
	}
	n, err := r.array()
	if err != nil {
		return s, err
	}
	tag, err := r.uint()
	if err != nil {
		return s, err
	}
	switch {
	case tag == 0 && n == 2:
		h, err := r.bytes()
		if err != nil || len(h) != 28 {
			return s, errCBOR
		}
		s.kind = "sig"
		copy(s.hash[:], h)
	case (tag == 1 || tag == 2) && n == 2, tag == 3 && n == 3:
		s.kind = map[uint64]string{1: "all", 2: "any", 3: "atLeast"}[tag]
		if tag == 3 {
			if s.n, err = r.uint(); err != nil {
				return s, err
			}
		}
		k, err := r.array()
		if err != nil {
			return s, err
		}
		for i := 0; i < k; i++ {
			sub, err := readScript(r, depth+1)
			if err != nil {
				return s, err
			}
			s.subs = append(s.subs, sub)
		}
	case (tag == 4 || tag == 5) && n == 2:
		s.kind = map[uint64]string{4: "after", 5: "before"}[tag]
		if s.slot, err = r.uint(); err != nil {
			return s, err
		}
	default:
		return s, errCBOR
	}
	return s, nil
}

// satisfied evaluates the script as CIP-26 asks: with the key hashes that
// signed, and irrespective of time constraints.
func (s script) satisfied(signers map[[28]byte]bool) bool {
	switch s.kind {
	case "sig":
		return signers[s.hash]
	case "before", "after":
		return true
	case "all":
		for _, c := range s.subs {
			if !c.satisfied(signers) {
				return false
			}
		}
		return true
	case "any":
		for _, c := range s.subs {
			if c.satisfied(signers) {
				return true
			}
		}
		return false
	case "atLeast":
		var k uint64
		for _, c := range s.subs {
			if c.satisfied(signers) {
				k++
			}
		}
		return k >= s.n
	}
	return false
}

// PolicyKeyHashes lists the key hashes of the signature leaves of a policy
// script given as JSON: the keys that can attest for the policy.
func PolicyKeyHashes(scriptJSON []byte) ([][28]byte, error) {
	value, _, err := PolicyValue(scriptJSON)
	if err != nil {
		return nil, err
	}
	s, _, err := parsePolicy(value)
	if err != nil {
		return nil, err
	}
	var out [][28]byte
	var walk func(script)
	walk = func(n script) {
		if n.kind == "sig" {
			out = append(out, n.hash)
		}
		for _, c := range n.subs {
			walk(c)
		}
	}
	walk(s)
	return out, nil
}
