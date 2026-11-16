package koios

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// uint is a non-negative integer that Koios sends either as a JSON number or
// as a string ("123"). Fractions, exponents, signs and anything else are
// refused; amounts are never floats.
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

// strictUnmarshal decodes one JSON value and refuses trailing data.
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

// parseRational reads a plain decimal ("15", "15.5") exactly.
func parseRational(raw string) (chain.Rational, error) {
	whole, frac, _ := strings.Cut(raw, ".")
	if whole == "" || strings.ContainsAny(raw, "eE+-") || len(frac) > 18 {
		return chain.Rational{}, fmt.Errorf("not a plain decimal: %q", prefix([]byte(raw)))
	}
	n, err := strconv.ParseUint(whole+frac, 10, 64)
	if err != nil {
		return chain.Rational{}, fmt.Errorf("not a plain decimal: %q", prefix([]byte(raw)))
	}
	den := uint64(1)
	for range frac {
		den *= 10
	}
	return chain.Rational{Num: n, Den: den}, nil
}

type rationalVal chain.Rational

func (r *rationalVal) UnmarshalJSON(b []byte) error {
	v, err := parseRational(strings.Trim(string(bytes.TrimSpace(b)), `"`))
	*r = rationalVal(v)
	return err
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
