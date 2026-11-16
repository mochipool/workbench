package blockfrost

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// uintVal is a non-negative integer that Blockfrost sends as a JSON number or
// as a string ("123", the form it uses for amounts). Fractions, exponents,
// signs and anything else are refused: amounts are never floats.
type uintVal uint64

func (u *uintVal) UnmarshalJSON(b []byte) error {
	s := string(bytes.TrimSpace(b))
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || s == "" || (len(s) > 1 && s[0] == '0') {
		return fmt.Errorf("not a non-negative integer: %q", prefix([]byte(s)))
	}
	*u = uintVal(v)
	return nil
}

// optional distinguishes an absent key, an explicit null and a value.
type optional[T any] struct {
	present bool
	null    bool
	val     T
}

func (o *optional[T]) UnmarshalJSON(b []byte) error {
	o.present = true
	if string(bytes.TrimSpace(b)) == "null" {
		o.null = true
		return nil
	}
	return json.Unmarshal(b, &o.val)
}

func strictUnmarshal(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data after JSON value")
	}
	return nil
}

func decodeHex(s string, n int) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("not hex: %w", err)
	}
	if n >= 0 && len(b) != n {
		return nil, fmt.Errorf("want %d bytes, got %d", n, len(b))
	}
	return b, nil
}
