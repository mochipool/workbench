package objlease

import (
	"bytes"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"
)

func sampleRecord() Record {
	return Record{Node: nodeKey, Holder: "00112233445566778899aabbccddeeff", Generation: 3, Counter: 7,
		Duration: 30 * time.Second, Margin: 10 * time.Second, State: StateHeld}
}

const sampleText = "spo-lease 1\nnode " + nodeKey + "\nholder 00112233445566778899aabbccddeeff\ngeneration 3\ncounter 7\nduration-ms 30000\nmargin-ms 10000\nstate held\n"

// The encoding is the fixed eight lines, and decoding gives the record back.
// The largest record fits the bound.
//
// spec: SPO-Xobjstore-IF-101
func TestTheRecordEncoding(t *testing.T) {
	b, err := Encode(sampleRecord())
	if err != nil || string(b) != sampleText {
		t.Fatalf("Encode: %q %v", b, err)
	}
	r, err := Decode(b)
	if err != nil || r != sampleRecord() {
		t.Fatalf("Decode: %+v %v", r, err)
	}
	big := Record{Node: nodeKey, Holder: strings.Repeat("f", 32), Generation: ^uint64(0), Counter: ^uint64(0),
		Duration: MaxDuration, Margin: MaxDuration - time.Millisecond, State: StateReleased}
	b, err = Encode(big)
	if err != nil || len(b) > MaxRecordBytes {
		t.Fatalf("the largest record: %d bytes, %v", len(b), err)
	}
	if r, err := Decode(b); err != nil || r != big {
		t.Fatalf("the largest record decodes to %+v %v", r, err)
	}
}

// Decoding is strict: every deviation is refused with ErrUnreadable, and
// Encode refuses what Decode would.
//
// spec: SPO-Xobjstore-IF-101, SPO-Xobjstore-PRE-102
func TestTheRecordDecodingIsStrict(t *testing.T) {
	rep := func(old, new string) string { return strings.Replace(sampleText, old, new, 1) }
	bad := map[string]string{
		"empty":                    "",
		"no final newline":         strings.TrimSuffix(sampleText, "\n"),
		"a trailing line":          sampleText + "extra 1\n",
		"a trailing byte":          sampleText + " ",
		"another version":          rep("spo-lease 1", "spo-lease 2"),
		"version 01":               rep("spo-lease 1", "spo-lease 01"),
		"a carriage return":        rep("state held\n", "state held\r\n"),
		"two spaces":               rep("counter 7", "counter  7"),
		"a tab":                    rep("counter 7", "counter\t7"),
		"lines swapped":            rep("generation 3\ncounter 7", "counter 7\ngeneration 3"),
		"a renamed field":          rep("holder ", "owner "),
		"an upper-case node":       rep("node 0123456789abcdef", "node 0123456789ABCDEF"),
		"a short holder":           rep("holder 00112233445566778899aabbccddeeff", "holder 00112233445566778899aabbccddee"),
		"a zero generation":        rep("generation 3", "generation 0"),
		"a zero counter":           rep("counter 7", "counter 0"),
		"a leading zero":           rep("counter 7", "counter 07"),
		"a sign":                   rep("counter 7", "counter +7"),
		"a counter over 64 bits":   rep("counter 7", "counter 18446744073709551616"),
		"a duration under 1 s":     rep("duration-ms 30000", "duration-ms 999"),
		"a duration over 5 min":    rep("duration-ms 30000", "duration-ms 300001"),
		"a margin of the duration": rep("margin-ms 10000", "margin-ms 30000"),
		"a margin under a third":   rep("margin-ms 10000", "margin-ms 9999"),
		"no margin":                rep("margin-ms 10000", "margin-ms 0"),
		// 2^58 + 30000 ms is 30 s once multiplied by a million and wrapped at 2^64
		"a duration that wraps to 30 s": rep("duration-ms 30000", "duration-ms 288230376151741744"),
		"a margin that wraps to 10 s":   rep("margin-ms 10000", "margin-ms 288230376151721744"),
		"an unknown state":              rep("state held", "state taken"),
		"a missing state":               strings.TrimSuffix(sampleText, "state held\n"),
		"oversized":                     sampleText + strings.Repeat("x", MaxRecordBytes),
	}
	for name, s := range bad {
		if _, err := Decode([]byte(s)); !errors.Is(err, ErrUnreadable) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, mod := range map[string]func(*Record){
		"no node":        func(r *Record) { r.Node = "" },
		"a bad holder":   func(r *Record) { r.Holder = "xyz" },
		"generation 0":   func(r *Record) { r.Generation = 0 },
		"counter 0":      func(r *Record) { r.Counter = 0 },
		"a microsecond":  func(r *Record) { r.Duration += time.Microsecond },
		"a long margin":  func(r *Record) { r.Margin = r.Duration },
		"a short margin": func(r *Record) { r.Margin = r.Duration/3 - time.Millisecond },
		"no state":       func(r *Record) { r.State = "" },
	} {
		r := sampleRecord()
		mod(&r)
		if _, err := Encode(r); !errors.Is(err, ErrUnreadable) {
			t.Errorf("Encode %s: %v", name, err)
		}
	}
}

// A body over the bound is refused for its size, before any line is read:
// even one that starts with a valid record. Ten decodes of a 1 MiB body
// allocate less than 256 KiB in all (the errors), nothing in proportion to
// the body.
//
// spec: SPO-Xobjstore-IF-101
func TestAnOversizedRecordIsRefusedBeforeItIsRead(t *testing.T) {
	big := append([]byte(sampleText), bytes.Repeat([]byte{'\n'}, 1<<20)...)
	_, err := Decode(big)
	if !errors.Is(err, ErrUnreadable) || !strings.Contains(err.Error(), "more than 256") {
		t.Fatalf("Decode of %d bytes: %v", len(big), err)
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range 10 {
		_, _ = Decode(big)
	}
	runtime.ReadMemStats(&after)
	if d := after.TotalAlloc - before.TotalAlloc; d > 256<<10 {
		t.Fatalf("ten decodes of an oversized body allocated %d bytes", d)
	}
}

// The decoder of the lease object, which a hostile store controls: it never
// panics, refuses anything longer than the bound, and whatever it accepts is
// the canonical encoding of what it returned.
//
// spec: SPO-Xobjstore-IF-101, SPO-Xobjstore-PRE-102
func FuzzDecode(f *testing.F) {
	f.Add([]byte(sampleText))
	f.Add([]byte(strings.Replace(sampleText, "held", "released", 1)))
	f.Add([]byte("spo-lease 1\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := Decode(b)
		if err != nil {
			if !errors.Is(err, ErrUnreadable) {
				t.Fatalf("a refusal that is not ErrUnreadable: %v", err)
			}
			return
		}
		if len(b) > MaxRecordBytes {
			t.Fatalf("accepted %d bytes", len(b))
		}
		again, err := Encode(r)
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("accepted %q, which is not the encoding %q of %+v (%v)", b, again, r, err)
		}
	})
}
