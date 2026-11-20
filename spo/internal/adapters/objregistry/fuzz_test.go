package objregistry

import (
	"bytes"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
)

// The decoders of every object the registry reads are strict, never panic,
// allocate nothing beyond their input's bound, and round-trip what the
// encoders write.
//
// spec: SPO-Xobjstore-SEC-803, SPO-Xobjstore-IF-802

func FuzzDecodeTomb(f *testing.F) {
	f.Add(encodeTomb(0))
	f.Add(encodeTomb(relaybind.MaxTime))
	f.Add(encodeTomb(relaybind.MaxTime + 1))
	f.Add([]byte(tombMagic))
	f.Fuzz(func(t *testing.T, b []byte) {
		nb, err := decodeTomb(b)
		if err != nil {
			return
		}
		if nb < 0 || nb > relaybind.MaxTime || !bytes.Equal(encodeTomb(nb), b) {
			t.Fatalf("%x decoded to %d", b, nb)
		}
	})
}

func FuzzDecodeRecord(f *testing.F) {
	f.Add(encodeRecord(relayregistry.Record{LastAuth: 5, Sign1: []byte{1}, COSEKey: []byte{2}, Senders: []mailbox.WalletKey{{1}, {2}}}))
	f.Add(encodeRecord(relayregistry.Record{Sign1: bytes.Repeat([]byte{1}, relaybind.MaxSign1Bytes), COSEKey: bytes.Repeat([]byte{2}, relaybind.MaxKeyBytes)}))
	f.Add([]byte(recMagic + "\x00\x00\x00\x00\x00\x00\x00\x00\xff"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 2*maxRecordBytes {
			return // a get asks for at most maxRecordBytes
		}
		st, err := decodeRecord(b)
		if err != nil {
			return
		}
		if len(st.sign1) < 1 || len(st.sign1) > relaybind.MaxSign1Bytes || len(st.coseKey) < 1 || len(st.coseKey) > relaybind.MaxKeyBytes || len(st.senders) > mailbox.MaxSenders {
			t.Fatalf("out of bounds: %+v", st)
		}
		if st.sendersOK {
			again := encodeRecord(relayregistry.Record{LastAuth: st.lastAuth, Senders: st.senders, Sign1: st.sign1, COSEKey: st.coseKey})
			if !bytes.Equal(again, b) {
				t.Fatalf("no round trip: %x", b)
			}
		}
	})
}

func FuzzDecodeMarker(f *testing.F) {
	f.Add(encodeMarker(testNode))
	f.Add([]byte(markerMagic))
	f.Fuzz(func(t *testing.T, b []byte) {
		k, err := decodeMarker(b)
		if err == nil && !bytes.Equal(encodeMarker(k), b) {
			t.Fatalf("no round trip: %x", b)
		}
	})
}

func FuzzDecodeRates(f *testing.F) {
	f.Add(encodeRates(relayregistry.RateSnapshot{NewBindings: relayregistry.RateState{Units: 36000, At: t0}, Revokes: relayregistry.RateState{Units: 1, At: 2}}))
	f.Add([]byte(ratesMagic))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := decodeRates(b)
		if err != nil {
			return
		}
		for _, v := range []int64{s.NewBindings.Units, s.NewBindings.At, s.Revokes.Units, s.Revokes.At} {
			if v < 0 || v > relaybind.MaxTime {
				t.Fatalf("out of range: %+v", s)
			}
		}
		if !bytes.Equal(encodeRates(s), b) {
			t.Fatalf("no round trip: %x", b)
		}
	})
}

func FuzzParseTombName(f *testing.F) {
	for _, k := range []relayregistry.TombKey{
		{Scope: relaybind.ScopePair, Key: relaybind.KeyHash{1}, Device: [20]byte{2}},
		{Scope: relaybind.ScopeAll, Key: relaybind.KeyHash{3}},
		{Scope: relaybind.ScopeDevice, Device: [20]byte{4}},
	} {
		f.Add(tombName(k))
	}
	f.Add("selftest-0123456789abcdef")
	f.Fuzz(func(t *testing.T, name string) {
		k, err := parseTombName(name)
		if err != nil {
			return
		}
		if tombName(k) != name {
			t.Fatalf("%q parsed to %+v, which names %q", name, k, tombName(k))
		}
	})
}
