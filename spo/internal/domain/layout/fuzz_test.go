package layout_test

import (
	"bytes"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/layout"
)

// Fuzz targets: no input makes a parser panic, and whatever a parser accepts
// re-encodes to exactly the input. The seed corpus is the vectors.
//
//	go test ./internal/domain/layout -run '^$' -fuzz FuzzDecodeBody -fuzztime 20s
//
// spec: SPO-Xlayout-INV-002, SPO-Xlayout-INV-005

// FuzzDecodeBody is the framed decoder. Every body is at least 4 KiB (a
// bucket less the envelope). A record body as a seed makes the Go fuzzing
// engine stall for seconds at a time (a few hundred executions in 20 seconds,
// observed with both the fixture and a hand-made record), while the decoder
// itself decodes one in about 4 microseconds; records are fuzzed through
// FuzzDecodeObject below, whose seeds are the records' CBOR. The seeds here are
// the audit row and the manifest objects.
func FuzzDecodeBody(f *testing.F) {
	for _, s := range sampleObjects() {
		o := s.o
		b, err := layout.EncodeBody(o)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		o, err := layout.DecodeBody(body, rule)
		if err != nil {
			return
		}
		again, err := layout.EncodeBody(o)
		if err != nil || !bytes.Equal(again, body) {
			t.Fatalf("accepted a body that does not re-encode to itself: %v", err)
		}
	})
}

// FuzzDecodeObject is the decoder under the framing: canonical CBOR in, an
// object out, and what is accepted encodes back to the same bytes. Its seeds
// are small (the CBOR of each object kind), so it executes far faster.
func FuzzDecodeObject(f *testing.F) {
	_, recs := loadRecords(f)
	seeds := []layout.Object{recs[0]}
	for _, s := range sampleObjects() {
		seeds = append(seeds, s.o)
	}
	for _, o := range seeds {
		c, err := layout.EncodeObject(o)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(c)
	}
	f.Add([]byte{0x80})
	f.Add([]byte{0x81, 0x65, 'a', 'u', 'd', 'i', 't'})
	f.Fuzz(func(t *testing.T, cbor []byte) {
		o, err := layout.DecodeObject(cbor, rule)
		if err != nil {
			return
		}
		again, err := layout.EncodeObject(o)
		if err != nil || !bytes.Equal(again, cbor) {
			t.Fatalf("accepted CBOR that does not re-encode to itself: %v", err)
		}
	})
}

func FuzzParseSlotsObject(f *testing.F) {
	for _, pol := range []string{"standard", "hardware", "strict"} {
		so := samplePolicySlots(pol)
		b, err := layout.EncodeSlotsObject(so.Meta.KeyEpoch, so)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, stored []byte) {
		epoch, so, err := layout.ParseSlotsObject(stored)
		if err != nil {
			return
		}
		again, err := layout.EncodeSlotsObject(epoch, so)
		if err != nil || !bytes.Equal(again, stored) {
			t.Fatalf("accepted a slots object that does not re-encode to itself: %v", err)
		}
	})
}

func FuzzParseHead(f *testing.F) {
	for _, h := range []layout.Head{sampleHead(), func() layout.Head {
		h := sampleHead()
		h.Sequence, h.Previous, h.RecoveryKey, h.CheckpointKey = 1, make([]byte, 32), nil, nil
		return h
	}()} {
		b, err := h.Encode()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, note []byte) {
		h, err := layout.ParseHead(note)
		if err != nil {
			return
		}
		again, err := h.Encode()
		if err != nil || !bytes.Equal(again, note) {
			t.Fatalf("accepted a note that does not re-encode to itself: %v", err)
		}
	})
}
