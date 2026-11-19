package ports

import "github.com/mochipool/workbench/spo/internal/platform/strictjson"

// ErrStrictJSON is the refusal of UnmarshalStrict.
var ErrStrictJSON = strictjson.ErrStrict

// UnmarshalStrict decodes a JSON record into v with a duplicate key at any depth,
// an unknown key and trailing data refused (strictjson.Unmarshal), so use cases,
// which may not import the platform layer, read their records with one meaning.
func UnmarshalStrict(b []byte, v any) error { return strictjson.Unmarshal(b, v) }
