package seal

import (
	"bytes"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// EncodeFactors is the stored form of a slot's factor list: the canonical CBOR
// of its factor entries ([kind, id, params] each), the same entries the slot's
// associated data binds. The list is stored beside the slot and, because the
// associated data binds the same entries, a row edited to show other factors
// no longer opens.
func EncodeFactors(f []FactorParams) ([]byte, error) {
	entries := make([]any, len(f))
	for i := range f {
		entries[i] = f[i].entry()
	}
	return EncodeCanonical(entries)
}

// DecodeFactors parses EncodeFactors' output and validates each factor. It
// refuses trailing bytes, an unknown kind and parameters of another kind.
func DecodeFactors(b []byte) ([]FactorParams, error) {
	if len(b) == 0 || len(b) > 64<<10 {
		return nil, fmt.Errorf("%w: factor list size", ErrFormat)
	}
	var raw []cbor.RawMessage
	if err := cbor.Unmarshal(b, &raw); err != nil || len(raw) == 0 || len(raw) > maxFactors {
		return nil, fmt.Errorf("%w: factor list", ErrFormat)
	}
	out := make([]FactorParams, 0, len(raw))
	for _, r := range raw {
		var e []cbor.RawMessage
		if err := cbor.Unmarshal(r, &e); err != nil || len(e) != 3 {
			return nil, fmt.Errorf("%w: factor entry", ErrFormat)
		}
		var kind uint64
		var f FactorParams
		if cbor.Unmarshal(e[0], &kind) != nil || cbor.Unmarshal(e[1], &f.ID) != nil {
			return nil, fmt.Errorf("%w: factor entry", ErrFormat)
		}
		f.Kind = FactorKind(kind)
		var p []cbor.RawMessage
		if err := cbor.Unmarshal(e[2], &p); err != nil {
			return nil, fmt.Errorf("%w: factor parameters", ErrFormat)
		}
		bad := func() ([]FactorParams, error) { return nil, fmt.Errorf("%w: factor parameters", ErrFormat) }
		switch f.Kind {
		case FactorPassphrase:
			var alg string
			var mem, passes, lanes uint64
			if len(p) != 5 || cbor.Unmarshal(p[0], &alg) != nil || alg != AlgKDF ||
				cbor.Unmarshal(p[1], &mem) != nil || cbor.Unmarshal(p[2], &passes) != nil ||
				cbor.Unmarshal(p[3], &lanes) != nil || cbor.Unmarshal(p[4], &f.KDFSalt) != nil ||
				mem > 1<<32-1 || passes > 1<<32-1 || lanes > 255 {
				return bad()
			}
			f.KDF = KDFParams{MemoryKiB: uint32(mem), Passes: uint32(passes), Lanes: uint8(lanes)}
		case FactorFIDO2:
			var touch uint64
			if len(p) != 4 || cbor.Unmarshal(p[0], &f.CredentialID) != nil || cbor.Unmarshal(p[1], &f.RPID) != nil ||
				cbor.Unmarshal(p[2], &f.HMACSalt) != nil || cbor.Unmarshal(p[3], &touch) != nil || touch > 3 {
				return bad()
			}
			f.Touch = uint8(touch)
		case FactorBackend:
			if len(p) != 5 || cbor.Unmarshal(p[0], &f.BackendKind) != nil || cbor.Unmarshal(p[1], &f.BackendAddress) != nil ||
				cbor.Unmarshal(p[2], &f.BackendNamespace) != nil || cbor.Unmarshal(p[3], &f.BackendKeyRef) != nil ||
				cbor.Unmarshal(p[4], &f.BackendBlob) != nil {
				return bad()
			}
		case FactorRecovery:
			if len(p) != 0 {
				return bad()
			}
		default:
			return nil, fmt.Errorf("%w: factor kind %d", ErrFormat, kind)
		}
		if err := f.validate(); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	// Re-encoding must give the stored bytes: one encoding per list.
	if again, err := EncodeFactors(out); err != nil || !bytes.Equal(again, b) {
		return nil, fmt.Errorf("%w: factor list is not canonical", ErrFormat)
	}
	return out, nil
}
