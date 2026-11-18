package layout_test

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/layout"
)

// Fuzz targets: no input makes a parser panic, and whatever a parser accepts
// re-encodes to exactly the input. The seed corpus is the vectors.
//
//	go test ./internal/domain/layout -run '^$' -fuzz FuzzDecodeBody -fuzztime 20s
//
// spec: SPO-Xlayout-INV-002, SPO-Xlayout-INV-005

// Why FuzzDecodeBody and FuzzParseSlotsObject take the CBOR and a few
// parameters, not the whole body. A body and a slots object are at least 4 KiB.
// With a 4 KiB []byte argument the Go fuzzing engine's minimiser worked for up
// to its default 60 seconds on every input it found interesting, and a worker
// that is minimising reports nothing: about 560 executions in 15 seconds were
// seen (and none after the first 3 seconds), while the decoder takes
// microseconds and the unframed FuzzDecodeObject does millions. Running with
// -fuzzminimizetime=1x made the same target do about 400,000 executions a second,
// so the cause is the minimiser on large arguments, not the decoder. The
// arguments here are small (the CBOR, a mode and three numbers), so a
// minimisation step is cheap, and the framing is built by the target in the
// shapes the decoder must refuse: a wrong length field, a flipped byte (in the
// content or in the padding), a bucket larger than needed, a truncation. What
// the decoders check is unchanged: no panic, and what is accepted re-encodes to
// itself. TestDecodeBodyAndSlotsRandomMutations keeps the old coverage of
// arbitrary edits of the whole 4 KiB in an ordinary test.
const (
	modeValid = iota
	modeLength
	modeFlip
	modeBigger
	modeTruncate
	modeCount
)

// shapeBody frames cbor as FrameBody does and then damages it as mode says.
func shapeBody(cbor []byte, mode uint8, length uint32, at uint16, val byte) ([]byte, bool) {
	body, err := layout.FrameBody(cbor)
	if err != nil {
		return nil, false
	}
	switch mode % modeCount {
	case modeLength:
		binary.BigEndian.PutUint32(body, length)
	case modeFlip:
		body[int(at)%len(body)] ^= val | 1
	case modeBigger:
		body = append(body, make([]byte, len(body)+layout.SealedOverhead)...)
	case modeTruncate:
		body = body[:int(at)%(len(body)+1)]
	}
	return body, true
}

// FuzzDecodeBody is the framed decoder. Its seeds are the audit row and the
// manifest objects in each shape; records are also fuzzed through
// FuzzDecodeObject below.
func FuzzDecodeBody(f *testing.F) {
	for _, s := range sampleObjects() {
		c, err := layout.EncodeObject(s.o)
		if err != nil {
			f.Fatal(err)
		}
		for m := uint8(0); m < modeCount; m++ {
			f.Add(c, m, uint32(len(c)+1), uint16(40), byte(1))
		}
	}
	f.Fuzz(func(t *testing.T, cbor []byte, mode uint8, length uint32, at uint16, val byte) {
		body, ok := shapeBody(cbor, mode, length, at, val)
		if !ok {
			return
		}
		decodesToItself(t, body)
	})
}

func decodesToItself(t *testing.T, body []byte) {
	t.Helper()
	o, err := layout.DecodeBody(body, rule)
	if err != nil {
		return
	}
	again, err := layout.EncodeBody(o)
	if err != nil || !bytes.Equal(again, body) {
		t.Fatalf("accepted a body that does not re-encode to itself: %v", err)
	}
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

// slotsParts splits a stored slots object into its header's epoch and its CBOR.
func slotsParts(stored []byte) (epoch, cbor []byte) {
	n := int(binary.BigEndian.Uint32(stored[layout.HeaderSize:]))
	return stored[1:layout.HeaderSize], stored[layout.HeaderSize+4 : layout.HeaderSize+4+n]
}

// shapeSlots frames cbor under epoch as EncodeSlotsObject does (the smallest
// bucket, zeros after) and then damages it as mode says.
func shapeSlots(epoch, cbor []byte, mode uint8, length uint32, at uint16, val byte) ([]byte, bool) {
	if len(epoch) != layout.EpochSize {
		return nil, false
	}
	bucket, err := layout.BucketFor(layout.HeaderSize + 4 + len(cbor))
	if err != nil {
		return nil, false
	}
	out := make([]byte, bucket)
	out[0] = layout.FormatSlots
	copy(out[1:], epoch)
	binary.BigEndian.PutUint32(out[layout.HeaderSize:], uint32(len(cbor)))
	copy(out[layout.HeaderSize+4:], cbor)
	switch mode % modeCount {
	case modeLength:
		binary.BigEndian.PutUint32(out[layout.HeaderSize:], length)
	case modeFlip:
		out[int(at)%len(out)] ^= val | 1
	case modeBigger:
		out = append(out, make([]byte, len(out))...)
	case modeTruncate:
		out = out[:int(at)%(len(out)+1)]
	}
	return out, true
}

func FuzzParseSlotsObject(f *testing.F) {
	for _, pol := range []string{"standard", "hardware", "strict"} {
		so := samplePolicySlots(pol)
		b, err := layout.EncodeSlotsObject(so.Meta.KeyEpoch, so)
		if err != nil {
			f.Fatal(err)
		}
		ep, c := slotsParts(b)
		for m := uint8(0); m < modeCount; m++ {
			f.Add(ep, c, m, uint32(len(c)+1), uint16(60), byte(1))
		}
	}
	f.Fuzz(func(t *testing.T, epoch, cbor []byte, mode uint8, length uint32, at uint16, val byte) {
		stored, ok := shapeSlots(epoch, cbor, mode, length, at, val)
		if !ok {
			return
		}
		parsesToItself(t, stored)
	})
}

func parsesToItself(t *testing.T, stored []byte) {
	t.Helper()
	epoch, so, err := layout.ParseSlotsObject(stored)
	if err != nil {
		return
	}
	again, err := layout.EncodeSlotsObject(epoch, so)
	if err != nil || !bytes.Equal(again, stored) {
		t.Fatalf("accepted a slots object that does not re-encode to itself: %v", err)
	}
}

// TestDecodeBodyAndSlotsRandomMutations edits the whole 4 KiB of each seed at
// random (one to four bytes, or a run) and requires the same two properties as
// the fuzz targets: no panic, and what is accepted re-encodes to itself.
//
// spec: SPO-Xlayout-INV-005
func TestDecodeBodyAndSlotsRandomMutations(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	mutate := func(b []byte) []byte {
		m := append([]byte(nil), b...)
		switch rng.Intn(3) {
		case 0, 1:
			for k := 0; k < 1+rng.Intn(4); k++ {
				m[rng.Intn(len(m))] = byte(rng.Intn(256))
			}
		default:
			i := rng.Intn(len(m))
			for j := i; j < len(m) && j < i+1+rng.Intn(64); j++ {
				m[j] = byte(rng.Intn(256))
			}
		}
		return m
	}
	n := 5000
	if testing.Short() {
		n = 500
	}
	for _, s := range sampleObjects() {
		b, err := layout.EncodeBody(s.o)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < n; i++ {
			decodesToItself(t, mutate(b))
		}
	}
	for _, pol := range []string{"standard", "hardware", "strict"} {
		so := samplePolicySlots(pol)
		b, err := layout.EncodeSlotsObject(so.Meta.KeyEpoch, so)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < n; i++ {
			parsesToItself(t, mutate(b))
		}
	}
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
