package relayself_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/app/relayself"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

// The binding file round-trips and is read strictly: oversize, duplicate or
// unknown keys, another version, upper-case or odd hex and empty or oversize
// fields are refused.
//
// spec: SPO-Xparty-IF-009
func TestBindingFile(t *testing.T) {
	st := relayporttest.NewWallet(1).BindingStatement(relayporttest.Device(1), 1, 3601, false)
	b, err := relayself.EncodeBindingFile(st.Sign1, st.COSEKey)
	if err != nil {
		t.Fatal(err)
	}
	s1, k, err := relayself.DecodeBindingFile(b)
	if err != nil || !bytes.Equal(s1, st.Sign1) || !bytes.Equal(k, st.COSEKey) {
		t.Fatalf("round trip: %v", err)
	}
	good := string(b)
	for name, in := range map[string]string{
		"oversize":       good + strings.Repeat(" ", relayself.MaxBindingFileBytes),
		"duplicate":      strings.Replace(good, `"v":1`, `"v":1,"v":1`, 1),
		"unknown":        strings.Replace(good, `"v":1`, `"v":1,"x":0`, 1),
		"version":        strings.Replace(good, `"v":1`, `"v":2`, 1),
		"upper hex":      strings.Replace(good, `"cose_key":"a4`, `"cose_key":"A4`, 1),
		"odd hex":        strings.Replace(good, `"cose_key":"a4`, `"cose_key":"a`, 1),
		"empty key":      `{"v":1,"statement":"84","cose_key":""}`,
		"oversize field": `{"v":1,"statement":"` + strings.Repeat("00", 513) + `","cose_key":"00"}`,
		"not json":       "spo-relay-binding-v1 device ...",
		"trailing":       good + "{}",
	} {
		if _, _, err := relayself.DecodeBindingFile([]byte(in)); !errors.Is(err, relayself.ErrBindingFile) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := relayself.EncodeBindingFile(nil, st.COSEKey); err == nil {
		t.Error("an empty statement was written")
	}
}

// The binding file and the own record compare keys byte for byte: the
// reviewer's inputs, a key repeated in other cases (the last would win) and a
// key in upper case, are refused.
//
// spec: SPO-Xparty-IF-009, SPO-Xmailbox-OUT-097
func TestStrictReadersCompareKeysExactly(t *testing.T) {
	st := relayporttest.NewWallet(1).BindingStatement(relayporttest.Device(1), 1, 3601, false)
	b, _ := relayself.EncodeBindingFile(st.Sign1, st.COSEKey)
	for name, in := range map[string]string{
		"three spellings": strings.Replace(string(b), `"statement":`, `"statement":"aa","Statement":"bb","ſtatement":`, 1),
		"upper case":      strings.Replace(strings.Replace(string(b), `"v":`, `"V":`, 1), `"statement":`, `"STATEMENT":`, 1),
	} {
		if s1, _, err := relayself.DecodeBindingFile([]byte(in)); !errors.Is(err, relayself.ErrBindingFile) {
			t.Errorf("binding file, %s: accepted %x (%v)", name, s1, err)
		}
	}
	for name, in := range map[string]string{
		"upper version":  `{"V":1}`,
		"two spellings":  `{"v":1,"V":1}`,
		"long s":         `{"v":1,"not_before":[{"device":"` + strings.Repeat("00", 20) + `","at":1,"At":2}]}`,
		"capital nested": `{"v":1,"not_before":[{"Device":"` + strings.Repeat("00", 20) + `","at":1}]}`,
	} {
		if _, err := relayself.Decode([]byte(in), relayporttest.Device(1)); !errors.Is(err, relayself.ErrCorrupt) {
			t.Errorf("own record, %s: %v", name, err)
		}
	}
}

func FuzzDecodeBindingFile(f *testing.F) {
	st := relayporttest.NewWallet(1).BindingStatement(relayporttest.Device(1), 1, 3601, false)
	b, _ := relayself.EncodeBindingFile(st.Sign1, st.COSEKey)
	f.Add(b)
	f.Add([]byte(`{"v":1,"statement":"00","cose_key":"00"}`))
	f.Fuzz(func(t *testing.T, in []byte) {
		s1, k, err := relayself.DecodeBindingFile(in)
		if err != nil {
			return
		}
		out, err := relayself.EncodeBindingFile(s1, k)
		if err != nil {
			t.Fatalf("a decoded file does not encode: %v", err)
		}
		s2, k2, err := relayself.DecodeBindingFile(out)
		if err != nil || !bytes.Equal(s1, s2) || !bytes.Equal(k, k2) {
			t.Fatal("the round trip changed the file")
		}
	})
}
