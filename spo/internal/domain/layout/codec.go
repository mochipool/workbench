package layout

import (
	"bytes"
	"errors"
	"math"

	"github.com/mochipool/workbench/spo/internal/domain/identity"
)

// Small helpers over the canonical CBOR value model of domain/identity: a
// decoded value is nil, bool, uint64 (non-negative integers), int64 (negative
// ones), string, []byte or []any.

// decodeCBOR decodes cbor strictly: a single item, no trailing bytes, the
// shortest encodings, no indefinite lengths, no maps in a layout body. The
// codec itself re-encodes to compare.
func decodeCBOR(cbor []byte) (any, error) {
	v, err := identity.DecodeCanonical(cbor)
	if err != nil {
		if errors.Is(err, identity.ErrNotCanonical) {
			return nil, formatErr("the CBOR is not canonical")
		}
		return nil, formatErr("the CBOR does not decode: %v", err)
	}
	return v, nil
}

func encodeCBOR(v any) ([]byte, error) {
	b, err := identity.EncodeCanonical(v)
	if err != nil {
		return nil, formatErr("encoding: %v", err)
	}
	return b, nil
}

// arr returns v as an array of exactly n items.
func arr(v any, n int, what string) ([]any, error) {
	a, ok := v.([]any)
	if !ok || len(a) != n {
		return nil, formatErr("%s is not an array of %d items", what, n)
	}
	return a, nil
}

func text(v any, what string) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", formatErr("%s is not a text string", what)
	}
	return s, nil
}

func bstr(v any, what string) ([]byte, error) {
	b, ok := v.([]byte)
	if !ok {
		return nil, formatErr("%s is not a byte string", what)
	}
	return b, nil
}

// fixed is a byte string of exactly n bytes.
func fixed(v any, n int, what string) ([]byte, error) {
	b, err := bstr(v, what)
	if err != nil {
		return nil, err
	}
	if len(b) != n {
		return nil, formatErr("%s is %d bytes, not %d", what, len(b), n)
	}
	return b, nil
}

func uint64Of(v any, what string) (uint64, error) {
	u, ok := v.(uint64)
	if !ok {
		return 0, formatErr("%s is not a non-negative integer", what)
	}
	return u, nil
}

// int64Of reads a SQLite INTEGER: a CBOR integer that fits 64 bits signed.
func int64Of(v any, what string) (int64, error) {
	switch x := v.(type) {
	case uint64:
		if x > math.MaxInt64 {
			return 0, formatErr("%s is out of range", what)
		}
		return int64(x), nil
	case int64:
		return x, nil
	}
	return 0, formatErr("%s is not an integer", what)
}

// reencodes checks that v encodes to exactly the bytes it was decoded from.
// DecodeCanonical already guarantees it for what it returns; this guards the
// typed objects built from it.
func reencodes(v any, want []byte) error {
	b, err := encodeCBOR(v)
	if err != nil {
		return err
	}
	if !bytes.Equal(b, want) {
		return formatErr("the object does not re-encode to itself")
	}
	return nil
}

func nonEmpty(b []byte, what string) error {
	if len(b) == 0 {
		return formatErr("%s is empty", what)
	}
	return nil
}
