package layout_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/layout"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// rule mirrors the store's kind-to-class rule (sqlitestore classOf) over the
// ports catalogue.
func rule(kind string) (string, bool) {
	k := ports.Kind(kind)
	if !k.Known() {
		return "", false
	}
	if k.Secret() {
		return "secret", true
	}
	return "sensitive", true
}

func sampleInner(ct int) layout.Inner {
	return layout.Inner{Nonce: pat(1, 24), WrappedKey: pat(2, 72), Owner: pat(3, 200), Ciphertext: pat(4, ct)}
}

func sampleRecord(kind, class string, ct int) layout.Record {
	return layout.Record{Kind: kind, Class: class, ID: pat(0xa0, 16), Anchor: append([]byte{0}, pat(0x40, 28)...), Num: 7, Version: 3,
		RecordFormat: 2, UpdatedAt: 1700000000, Inner: sampleInner(ct)}
}

// spec: SPO-Xlayout-OUT-006, SPO-Xlayout-INV-002, SPO-Xlayout-INV-003
func TestRecordBodyRoundTrip(t *testing.T) {
	for _, r := range []layout.Record{sampleRecord("kes.vkey", "sensitive", 300), sampleRecord("node.skey", "secret", 272)} {
		body, err := layout.EncodeBody(r)
		if err != nil {
			t.Fatal(err)
		}
		o, err := layout.DecodeBody(body, rule)
		if err != nil {
			t.Fatal(err)
		}
		got := o.(layout.Record)
		if got.Kind != r.Kind || got.Class != r.Class || !bytes.Equal(got.ID, r.ID) || !bytes.Equal(got.Anchor, r.Anchor) ||
			got.Num != r.Num || got.Version != r.Version || got.RecordFormat != r.RecordFormat || got.UpdatedAt != r.UpdatedAt {
			t.Fatalf("columns changed: %+v", got)
		}
		in, out := r.Inner, got.Inner
		if !bytes.Equal(in.Nonce, out.Nonce) || !bytes.Equal(in.WrappedKey, out.WrappedKey) || !bytes.Equal(in.Owner, out.Owner) || !bytes.Equal(in.Ciphertext, out.Ciphertext) {
			t.Fatal("inner bytes out differ from inner bytes in")
		}
		again, err := layout.EncodeBody(got)
		if err != nil || !bytes.Equal(again, body) {
			t.Fatal("encode(decode(x)) != x")
		}
	}
}

// spec: SPO-Xlayout-PRE-007
func TestDecodeRefusesAnUnknownKindAndAWrongClass(t *testing.T) {
	enc := func(r layout.Record) []byte {
		// The encoder does not know the rule; only the decoder checks it.
		b, err := layout.EncodeBody(r)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	cases := map[string]layout.Record{
		"unknown kind":                   sampleRecord("no.such.kind", "secret", 100),
		"secret kind with sensitive":     sampleRecord("node.skey", "sensitive", 100),
		"sensitive kind with secret":     sampleRecord("kes.vkey", "secret", 100),
		"the cold class is not a column": sampleRecord("node.skey", "secret-cold", 100),
	}
	for name, r := range cases {
		if _, err := layout.DecodeBody(enc(r), rule); err == nil || !errors.Is(err, layout.ErrFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := layout.DecodeBody(enc(sampleRecord("kes.vkey", "sensitive", 100)), nil); err == nil {
		t.Error("a nil rule must refuse, not accept everything")
	}
}

// spec: SPO-Xlayout-OUT-007, SPO-Xlayout-PRE-008
func TestWrappedKeyFieldIsFixedWidth(t *testing.T) {
	hot := sampleRecord("node.skey", "secret", 272)
	cold := hot
	cold.Inner.WrappedKey = pat(9, 1300)
	a, err := layout.EncodeBody(hot)
	if err != nil {
		t.Fatal(err)
	}
	b, err := layout.EncodeBody(cold)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != len(b) {
		t.Fatalf("hot and cold bodies differ in size: %d and %d", len(a), len(b))
	}
	o, err := layout.DecodeBody(b, rule)
	if err != nil || !bytes.Equal(o.(layout.Record).Inner.WrappedKey, cold.Inner.WrappedKey) {
		t.Fatalf("the true wrapped key is not recovered: %v", err)
	}
	// At the very edge of W it still works; one byte more is refused and never
	// moved to a bigger bucket.
	edge := hot
	edge.Inner.WrappedKey = pat(1, layout.WrappedKeyMax)
	if _, err := layout.EncodeBody(edge); err != nil {
		t.Fatalf("a wrapped key of exactly W bytes: %v", err)
	}
	over := hot
	over.Inner.WrappedKey = pat(1, layout.WrappedKeyMax+1)
	if _, err := layout.EncodeBody(over); err == nil || !strings.Contains(err.Error(), "1537") {
		t.Fatalf("a wrapped key of W+1 bytes: %v", err)
	}
	// A decoder refuses a body whose field is not W wide, whose length is
	// beyond W or whose fill is not zero.
	for name, bad := range map[string]func(*layout.WrappedKeyForm){
		"length beyond W": func(f *layout.WrappedKeyForm) { f.Length = layout.WrappedKeyMax + 1 },
		"zero length":     func(f *layout.WrappedKeyForm) { f.Length = 0 },
		"non-zero fill":   func(f *layout.WrappedKeyForm) { f.Field[len(f.Field)-1] = 1 },
		"short field":     func(f *layout.WrappedKeyForm) { f.Field = f.Field[:len(f.Field)-1] },
	} {
		body, err := layout.EncodeBodyWithWrappedKeyForm(hot, bad)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := layout.DecodeBody(body, rule); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Hot and cold records of equal payload size share a bucket at every payload
// size, including the sizes at a bucket edge.
// spec: SPO-Xlayout-INV-004
func TestHotAndColdLandInTheSameBucketAtEverySize(t *testing.T) {
	for ct := 16; ct < 12000; ct++ {
		hot := sampleRecord("node.skey", "secret", ct)
		cold := hot
		cold.Inner.WrappedKey = pat(9, 1000+ct%500)
		a, err1 := layout.EncodeBody(hot)
		b, err2 := layout.EncodeBody(cold)
		if err1 != nil || err2 != nil || len(a) != len(b) {
			t.Fatalf("ciphertext %d: %v %v %d %d", ct, err1, err2, len(a), len(b))
		}
	}
}

func TestDecodeBodyRefusesStructuralDamage(t *testing.T) {
	r := sampleRecord("kes.vkey", "sensitive", 300)
	good, err := layout.EncodeBody(r)
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := layout.UnframeBody(good)
	reframe := func(c []byte) []byte {
		b, err := layout.FrameBody(c)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	cases := map[string][]byte{
		"trailing byte in the CBOR":       reframe(append(append([]byte(nil), cb...), 0)),
		"indefinite-length array":         reframe(append([]byte{0x9f}, append(append([]byte(nil), cb[1:]...), 0xff)...)),
		"non-minimal integer in the head": reframe(append([]byte{0x98, cb[0] & 0x1f}, cb[1:]...)),
		"non-minimal text length":         reframe(append([]byte{cb[0], 0x78, 0x08}, cb[2:]...)),
		"not CBOR":                        reframe([]byte{0xff, 0xff}),
		"a map":                           reframe([]byte{0xa1, 0x01, 0x02}),
		"empty array":                     reframe([]byte{0x80}),
		"wrong arity":                     reframe(mustCBOR(t, []any{"kes.vkey", "sensitive"})),
		"unknown object kind":             reframe(mustCBOR(t, []any{"nonsense", 1})),
	}
	for name, c := range cases {
		if _, err := layout.DecodeBody(c, rule); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func mustCBOR(t *testing.T, v any) []byte {
	t.Helper()
	b, err := identity.EncodeCanonical(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// spec: SPO-Xlayout-OUT-008
func TestAuditBodyRoundTrip(t *testing.T) {
	a := layout.Audit{Seq: 5, At: 1700000001, Kind: "update", Event: pat(1, 256+40), Touched: pat(2, 90), SlotSet: nil, MAC: pat(3, 32), PrevMAC: pat(4, 32)}
	body, err := layout.EncodeBody(a)
	if err != nil {
		t.Fatal(err)
	}
	o, err := layout.DecodeBody(body, rule)
	if err != nil {
		t.Fatal(err)
	}
	got := o.(layout.Audit)
	if got.Seq != 5 || got.At != a.At || got.Kind != "update" || !bytes.Equal(got.Event, a.Event) || !bytes.Equal(got.Touched, a.Touched) ||
		len(got.SlotSet) != 0 || !bytes.Equal(got.MAC, a.MAC) || !bytes.Equal(got.PrevMAC, a.PrevMAC) {
		t.Fatalf("%+v", got)
	}
	again, _ := layout.EncodeBody(got)
	if !bytes.Equal(again, body) {
		t.Fatal("not stable")
	}
	for name, bad := range map[string]layout.Audit{
		"kind":          {Seq: 1, Kind: "other", Event: a.Event, Touched: a.Touched, MAC: a.MAC, PrevMAC: a.PrevMAC},
		"short mac":     {Seq: 1, Kind: "update", Event: a.Event, Touched: a.Touched, MAC: a.MAC[:31], PrevMAC: a.PrevMAC},
		"short prev":    {Seq: 1, Kind: "update", Event: a.Event, Touched: a.Touched, MAC: a.MAC, PrevMAC: a.PrevMAC[:5]},
		"slotset size":  {Seq: 1, Kind: "slots", Event: a.Event, Touched: a.Touched, SlotSet: pat(1, 31), MAC: a.MAC, PrevMAC: a.PrevMAC},
		"sequence zero": {Seq: 0, Kind: "update", Event: a.Event, Touched: a.Touched, MAC: a.MAC, PrevMAC: a.PrevMAC},
	} {
		if b, err := layout.EncodeBody(bad); err == nil {
			if _, err := layout.DecodeBody(b, rule); err == nil {
				t.Errorf("%s: accepted", name)
			}
		}
	}
}

// A record body carries the current record form (2) and a version of at least
// 1, in encode and in decode.
// spec: SPO-Xlayout-PRE-012
func TestRecordFormatAndVersionAreChecked(t *testing.T) {
	good := sampleRecord("kes.vkey", "sensitive", 100)
	if layout.RecordFormat != 2 {
		t.Fatalf("the layout mirrors the store's record format 2, not %d", layout.RecordFormat)
	}
	for name, mut := range map[string]func(*layout.Record){
		"format 1":  func(r *layout.Record) { r.RecordFormat = 1 },
		"format 3":  func(r *layout.Record) { r.RecordFormat = 3 },
		"format 0":  func(r *layout.Record) { r.RecordFormat = 0 },
		"version 0": func(r *layout.Record) { r.Version = 0 },
	} {
		r := good
		mut(&r)
		if _, err := layout.EncodeBody(r); err == nil {
			t.Errorf("%s: encoded", name)
		}
		// and a body a hostile writer built by hand is refused by the decoder
		c := mustCBOR(t, []any{r.Kind, r.Class, r.ID, r.Anchor, r.Num, r.Version, r.RecordFormat, r.UpdatedAt,
			[]any{r.Inner.Nonce, append(append([]byte{0, 72}, r.Inner.WrappedKey...), make([]byte, layout.WrappedKeyMax-72)...), r.Inner.Owner, r.Inner.Ciphertext}})
		body, err := layout.FrameBody(c)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := layout.DecodeBody(body, rule); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	// the control: the same hand-built body with good values decodes
	c := mustCBOR(t, []any{good.Kind, good.Class, good.ID, good.Anchor, good.Num, good.Version, good.RecordFormat, good.UpdatedAt,
		[]any{good.Inner.Nonce, append(append([]byte{0, 72}, good.Inner.WrappedKey...), make([]byte, layout.WrappedKeyMax-72)...), good.Inner.Owner, good.Inner.Ciphertext}})
	body, _ := layout.FrameBody(c)
	if _, err := layout.DecodeBody(body, rule); err != nil {
		t.Fatalf("the control body was refused: %v", err)
	}
}
