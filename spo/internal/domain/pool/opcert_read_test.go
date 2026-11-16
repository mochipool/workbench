package pool

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

func testOpCert(counter, period uint64) ([]byte, OpCert) {
	var oc OpCert
	for i := range oc.KesVKey {
		oc.KesVKey[i] = byte(i)
		oc.ColdVKey[i] = byte(0x80 + i)
	}
	for i := range oc.Signature {
		oc.Signature[i] = byte(0x40 + i)
	}
	oc.Counter, oc.KesPeriod = counter, period
	b := []byte{0x82, 0x84}
	b = appendHead(b, 2, 32)
	b = append(b, oc.KesVKey[:]...)
	b = appendHead(b, 0, counter)
	b = appendHead(b, 0, period)
	b = appendHead(b, 2, 64)
	b = append(b, oc.Signature[:]...)
	b = appendHead(b, 2, 32)
	b = append(b, oc.ColdVKey[:]...)
	return MarshalEnvelope(Envelope{Type: TypeOpCert, Description: "", CborHex: hexOf(b)}), oc
}

// spec: SPO-04e-MODE-003, SPO-04e-MODE-004
func TestParseOpCert(t *testing.T) {
	for _, tc := range [][2]uint64{{0, 0}, {5, 23}, {300, 70000}, {1 << 33, 1 << 40}} {
		file, want := testOpCert(tc[0], tc[1])
		got, err := ParseOpCert(file)
		if err != nil || got != want {
			t.Fatalf("%v: %+v %v", tc, got, err)
		}
		id, err := got.PoolID()
		if err != nil {
			t.Fatal(err)
		}
		if exp, _ := chain.PoolIDOf(want.ColdVKey[:]); id != exp {
			t.Errorf("pool id %x", id)
		}
	}
	// Refusals: wrong type, truncated, trailing bytes, other shapes.
	file, _ := testOpCert(1, 1)
	for name, bad := range map[string][]byte{
		"not an envelope": []byte("nope"),
		"wrong type":      bytes.Replace(file, []byte(TypeOpCert), []byte(TypeIssueCounter), 1),
		"truncated":       bytes.Replace(file, []byte(`"cborHex": "8284`), []byte(`"cborHex": "82`), 1),
	} {
		if _, err := ParseOpCert(bad); !errors.Is(err, ErrBadOpCert) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func g() chain.Genesis {
	return chain.Genesis{SlotLength: time.Second, SlotsPerKESPeriod: 129600, MaxKESEvolutions: 62}
}

// spec: SPO-04e-INV-002, SPO-04e-INV-003, SPO-04e-OUT-001
func TestCheckKesWindow(t *testing.T) {
	// Tip in period 10: a certificate that starts at 5 has 62-5 periods left.
	slot := uint64(10*129600 + 100)
	w, err := CheckKesWindow(g(), slot, 5)
	if err != nil || !w.InRange || w.NotYetValid || w.CurrentPeriod != 10 || w.ExpirePeriod != 67 {
		t.Fatalf("%+v %v", w, err)
	}
	if want := time.Duration(67*129600-slot) * time.Second; w.Remaining != want {
		t.Errorf("remaining %s want %s", w.Remaining, want)
	}
	// The last period in range and the first out of it.
	if w, _ := CheckKesWindow(g(), 66*129600, 5); !w.InRange {
		t.Error("period 66 is in range")
	}
	w, _ = CheckKesWindow(g(), 67*129600+10, 5)
	if w.InRange || w.NotYetValid || w.SinceExpiry != 10*time.Second {
		t.Errorf("expired: %+v", w)
	}
	// A certificate that starts in the future is out of range and not expired.
	if w, _ := CheckKesWindow(g(), slot, 11); w.InRange || !w.NotYetValid || w.SinceExpiry != 0 {
		t.Errorf("future: %+v", w)
	}
	// Starting in the current period is in range.
	if w, _ := CheckKesWindow(g(), slot, 10); !w.InRange {
		t.Error("start == current is in range")
	}
	bad := g()
	bad.SlotLength = 1500 * time.Millisecond
	if _, err := CheckKesWindow(bad, slot, 5); !errors.Is(err, ErrSlotLength) {
		t.Errorf("fractional slot length: %v", err)
	}
}
