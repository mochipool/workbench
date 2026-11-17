package archtest

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
)

// Two canonical CBOR encoders exist because the domain takes no CBOR library
// and the platform may not import the domain: seal.EncodeCanonical (library
// backed; associated data, audit rows) and identity.EncodeCanonical /
// DecodeCanonical (library-free; object identities). This test lives here
// because only a test outside both layers may import both. It pins that they
// agree on every value of the shared model, and that the domain's canonical
// check agrees with the library's strictest decoder plus a re-encode.
//
// spec: SPO-Xidentity-INV-009

// strictDec is the fxamacker decoder in its strictest mode for this model.
var strictDec = func() cbor.DecMode {
	m, err := cbor.DecOptions{
		DupMapKey:       cbor.DupMapKeyEnforcedAPF,
		IndefLength:     cbor.IndefLengthForbidden,
		TagsMd:          cbor.TagsForbidden,
		UTF8:            cbor.UTF8RejectInvalid,
		MaxNestedLevels: 70,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return m
}()

// libraryAccepts is "decode strictly, then re-encode and require equal
// bytes" with the library, returning the decoded value in the domain's model.
func libraryAccepts(data []byte) (any, bool) {
	var v any
	rest, err := strictDec.UnmarshalFirst(data, &v)
	if err != nil || len(rest) != 0 {
		return nil, false
	}
	dv, ok := toDomain(v)
	if !ok {
		return nil, false
	}
	again, err := seal.EncodeCanonical(v)
	if err != nil || !bytes.Equal(again, data) {
		return nil, false
	}
	return dv, true
}

// toDomain converts a library-decoded value to the domain model; it refuses
// what the domain model does not have (floats, the library's other types).
func toDomain(v any) (any, bool) {
	switch x := v.(type) {
	case nil, bool, uint64, int64, string, []byte:
		return x, true
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			d, ok := toDomain(e)
			if !ok {
				return nil, false
			}
			out[i] = d
		}
		return out, true
	case map[any]any:
		m := identity.Map{}
		for k, e := range x {
			dk, ok1 := toDomain(k)
			de, ok2 := toDomain(e)
			if !ok1 || !ok2 {
				return nil, false
			}
			m = append(m, identity.Pair{K: dk, V: de})
		}
		return m, true
	}
	return nil, false // float64, big.Int, cbor.Tag, ...
}

func hasUnhashableKey(v any) bool {
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			if hasUnhashableKey(e) {
				return true
			}
		}
	case identity.Map:
		for _, p := range x {
			switch p.K.(type) {
			case []byte, []any, identity.Map:
				return true
			}
			if hasUnhashableKey(p.K) || hasUnhashableKey(p.V) {
				return true
			}
		}
	}
	return false
}

func agree(t testing.TB, data []byte) {
	t.Helper()
	dv, derr := identity.DecodeCanonical(data)
	lv, lok := libraryAccepts(data)
	if derr == nil && !lok && hasUnhashableKey(dv) {
		return // the library cannot decode a byte-string, array or map key into a Go map
	}
	if (derr == nil) != lok {
		t.Fatalf("% x: domain err=%v, library accepts=%v", data, derr, lok)
	}
	if derr != nil {
		return
	}
	a, err1 := identity.EncodeCanonical(dv)
	b, err2 := identity.EncodeCanonical(lv)
	if err1 != nil || err2 != nil || !bytes.Equal(a, b) || !bytes.Equal(a, data) {
		t.Fatalf("% x: the decoders disagree on the value", data)
	}
}

// randValue builds a value of the shared model; the library side gets the
// plain Go form, the domain side the identity model.
func randValue(r *rand.Rand, depth int) (lib, dom any) {
	k := r.Intn(9)
	if depth > 3 && k >= 6 {
		k = r.Intn(6)
	}
	switch k {
	case 0:
		return nil, nil
	case 1:
		b := r.Intn(2) == 0
		return b, b
	case 2:
		n := uint64(r.Int63n(1<<62)) >> uint(r.Intn(62))
		return n, n
	case 3:
		n := -1 - r.Int63n(1<<62)>>uint(r.Intn(62))
		return n, n
	case 4:
		s := string(randBytes(r, true))
		return s, s
	case 5:
		b := randBytes(r, false)
		return b, b
	case 6, 7:
		n := r.Intn(4)
		l, d := make([]any, n), make([]any, n)
		for i := range l {
			l[i], d[i] = randValue(r, depth+1)
		}
		return l, d
	default:
		n := r.Intn(4)
		l, d := map[any]any{}, identity.Map{}
		for len(d) < n {
			var kl, kd any
			if r.Intn(2) == 0 {
				kl, kd = randValue(r, 9) // a scalar key
				if _, isSlice := kl.([]byte); isSlice {
					continue // []byte is not a hashable Go map key
				}
			} else {
				s := string(randBytes(r, true))
				kl, kd = s, s
			}
			if _, dup := l[kl]; dup || kl == nil {
				continue
			}
			vl, vd := randValue(r, depth+1)
			l[kl] = vl
			d = append(d, identity.Pair{K: kd, V: vd})
		}
		return l, d
	}
}

func randBytes(r *rand.Rand, text bool) []byte {
	b := make([]byte, []int{0, 1, 5, 23, 24, 30, 300}[r.Intn(7)])
	for i := range b {
		if text {
			b[i] = "abcé世 "[r.Intn(7)]
			if b[i] >= 0x80 { // keep valid UTF-8: use plain ASCII for the bytes
				b[i] = 'x'
			}
		} else {
			b[i] = byte(r.Intn(256))
		}
	}
	return b
}

func TestEncodersAgreeOnRandomValues(t *testing.T) {
	r := rand.New(rand.NewSource(8949))
	for i := 0; i < 3000; i++ {
		lib, dom := randValue(r, 0)
		want, err := seal.EncodeCanonical(lib)
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		got, err := identity.EncodeCanonical(dom)
		if err != nil {
			t.Fatalf("domain: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("encoders differ for %v\n seal   % x\n domain % x", lib, want, got)
		}
		agree(t, got) // decoding what was encoded
		// Mutations: flip a byte, truncate, extend, splice in a head.
		for j := 0; j < 6; j++ {
			m := append([]byte(nil), got...)
			switch r.Intn(4) {
			case 0:
				if len(m) > 0 {
					m[r.Intn(len(m))] ^= byte(1 << uint(r.Intn(8)))
				}
			case 1:
				if len(m) > 0 {
					m = m[:r.Intn(len(m))]
				}
			case 2:
				m = append(m, byte(r.Intn(256)))
			default:
				p := r.Intn(len(m) + 1)
				m = append(m[:p], append([]byte{[]byte{0x18, 0x9f, 0xbf, 0xff, 0xc1, 0xf9, 0x5f, 0x7f}[r.Intn(8)]}, m[p:]...)...)
			}
			agree(t, m)
		}
	}
}

func FuzzCanonicalAgreement(f *testing.F) {
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 40; i++ {
		_, dom := randValue(r, 0)
		b, _ := identity.EncodeCanonical(dom)
		f.Add(b)
	}
	for _, s := range [][]byte{{0x18, 0x00}, {0x9f, 0xff}, {0xa2, 0x61, 0x61, 0x00, 0x61, 0x61, 0x00}, {0x62, 0xc3, 0x28}, {0xf9, 0x00, 0x00}, {0xc0, 0x00}, {0xf7}} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) { agree(t, data) })
}

// Both must refuse text that is not UTF-8, and the library encoder must not be
// the one to allow it into an identity. seal.EncodeCanonical emits it (changing
// that could alter existing associated data, so seal is left as it is); the
// domain encoder refuses, so no spo-defined object can contain such a string.
func TestInvalidUTF8IsRefusedByTheDomainOnly(t *testing.T) {
	bad := "\xff"
	if b, err := seal.EncodeCanonical(bad); err != nil || !bytes.Equal(b, []byte{0x61, 0xff}) {
		t.Fatalf("seal's behaviour changed: % x %v (revisit this test and the spec)", b, err)
	}
	if _, err := identity.EncodeCanonical(bad); err == nil {
		t.Error("the domain encoder accepted invalid UTF-8")
	}
	if _, err := identity.ContentOf(identity.TagAuditEvent, []any{bad}); err == nil {
		t.Error("an identity was derived from invalid UTF-8")
	}
	if _, err := identity.DecodeCanonical([]byte{0x61, 0xff}); err == nil {
		t.Error("the domain decoder accepted invalid UTF-8")
	}
	if _, ok := libraryAccepts([]byte{0x61, 0xff}); ok {
		t.Error("the library's strict decoder accepted invalid UTF-8")
	}
}
