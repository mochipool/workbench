package layout_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"runtime"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/layout"
)

func i64(v int64) *int64 { return &v }

// samplePolicySlots builds a plausible slot table and meta for a policy. The
// columns are opaque to the layout; what matters is that every one survives.
func samplePolicySlots(policy string) layout.SlotsObject {
	meta := layout.Meta{WorkspaceID: pat(0x20, 16), StoreFormat: 3, Policy: policy, KeyEpoch: pat(0xf0, 16), EpochMAC: pat(0x01, 32), CreatedAt: 1700000000}
	var slots []layout.Slot
	switch policy {
	case "standard":
		pub := pat(0x90, 32)
		h := sha256.Sum256(pub)
		meta.RecoveryPub, meta.RecoveryPubHash = pub, h[:]
		slots = []layout.Slot{
			{ID: pat(0x30, 16), Kind: "passphrase", KDFMemoryKiB: i64(65536), KDFPasses: i64(3), KDFLanes: i64(1), Salt: pat(0x70, 16), KeyCommit: pat(1, 32), Nonce: pat(2, 24), WrappedKey: pat(3, 48), Bound: 1, RecHash: h[:]},
			{ID: pat(0x40, 16), Kind: "recovery", Salt: []byte{}, KeyCommit: pat(4, 32), Nonce: pat(5, 24), WrappedKey: pat(6, 48), Bound: 1, RecHash: h[:]},
		}
	case "hardware":
		pub := pat(0x91, 32)
		h := sha256.Sum256(pub)
		meta.RecoveryPub, meta.RecoveryPubHash = pub, h[:]
		slots = []layout.Slot{
			{ID: pat(0x31, 16), Kind: "fido2-hmac", KeyCommit: pat(1, 32), Nonce: pat(2, 24), WrappedKey: pat(3, 48), Bound: 1, RecHash: h[:], Factors: pat(0xc0, 120)},
			{ID: pat(0x41, 16), Kind: "composite", KeyCommit: pat(4, 32), Nonce: pat(5, 24), WrappedKey: pat(6, 48), Bound: 1, RecHash: h[:], Factors: pat(0xd0, 300)},
		}
	default: // strict: no recovery path
		slots = []layout.Slot{
			{ID: pat(0x32, 16), Kind: "fido2-hmac", KeyCommit: pat(1, 32), Nonce: pat(2, 24), WrappedKey: pat(3, 48), Bound: 1, Factors: pat(0xc0, 120)},
			{ID: pat(0x33, 16), Kind: "fido2-hmac", KeyCommit: pat(7, 32), Nonce: pat(8, 24), WrappedKey: pat(9, 48), Bound: 1, Factors: pat(0xc8, 120)},
		}
	}
	return layout.SlotsObject{Meta: meta, Slots: slots}
}

// spec: SPO-Xlayout-OUT-010, SPO-Xlayout-INV-002
func TestSlotsObjectForEachPolicy(t *testing.T) {
	for _, pol := range []string{"standard", "hardware", "strict"} {
		so := samplePolicySlots(pol)
		epoch := so.Meta.KeyEpoch
		stored, err := layout.EncodeSlotsObject(epoch, so)
		if err != nil {
			t.Fatalf("%s: %v", pol, err)
		}
		if stored[0] != layout.FormatSlots || !bytes.Equal(stored[1:17], epoch) {
			t.Fatalf("%s: header %x", pol, stored[:17])
		}
		if h, err := layout.ParseHeader(stored); err != nil || h.Format != 2 {
			t.Fatalf("%s: %v", pol, err)
		}
		if len(stored) != 4096 {
			t.Fatalf("%s: %d bytes, want one 4 KiB bucket", pol, len(stored))
		}
		for _, b := range stored[len(stored)-100:] {
			if b != 0 {
				t.Fatalf("%s: padding is not zero", pol)
			}
		}
		e2, got, err := layout.ParseSlotsObject(stored)
		if err != nil || !bytes.Equal(e2, epoch) {
			t.Fatalf("%s: %v", pol, err)
		}
		again, err := layout.EncodeSlotsObject(e2, got)
		if err != nil || !bytes.Equal(again, stored) {
			t.Fatalf("%s: encode(parse(x)) != x", pol)
		}
		// every column survives, NULL and empty stay different
		if got.Meta.Policy != pol || got.Meta.CreatedAt != 1700000000 || len(got.Slots) != 2 {
			t.Fatalf("%s: %+v", pol, got.Meta)
		}
		if pol == "standard" {
			if got.Slots[0].KDFMemoryKiB == nil || *got.Slots[0].KDFMemoryKiB != 65536 || got.Slots[1].KDFMemoryKiB != nil {
				t.Fatal("NULL and integer kdf columns are mixed up")
			}
			if got.Slots[1].Salt == nil || len(got.Slots[1].Salt) != 0 || got.Slots[1].Factors != nil {
				t.Fatalf("an empty blob and a NULL are not kept apart: %#v %#v", got.Slots[1].Salt, got.Slots[1].Factors)
			}
		}
	}
}

// The slot-set hash is the rule the audit rows of slot changes record:
// SHA-256 of the canonical CBOR of ["spo/slotset/3", policy, rows].
// spec: SPO-Xlayout-OUT-011
func TestSlotSetHashFollowsTheDocumentedRule(t *testing.T) {
	so := samplePolicySlots("standard")
	var rows []any
	for _, s := range so.Slots {
		row := []any{s.ID, s.Kind, nil, nil, nil, nil, s.KeyCommit, s.Nonce, s.WrappedKey, s.Bound, s.RecHash, nil}
		if s.KDFMemoryKiB != nil {
			row[2], row[3], row[4], row[5] = *s.KDFMemoryKiB, *s.KDFPasses, *s.KDFLanes, s.Salt
		} else {
			row[5] = s.Salt
		}
		rows = append(rows, row)
	}
	b, err := identity.EncodeCanonical([]any{"spo/slotset/3", "standard", rows})
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(b)
	got, err := layout.SlotSetHash("standard", so.Slots)
	if err != nil || !bytes.Equal(got, want[:]) {
		t.Fatalf("%x %v", got, err)
	}
	other, _ := layout.SlotSetHash("hardware", so.Slots)
	if bytes.Equal(other, got) {
		t.Fatal("the policy is not in the hash")
	}
}

// spec: SPO-Xlayout-PRE-011
func TestSlotsObjectRefusals(t *testing.T) {
	so := samplePolicySlots("standard")
	epoch := so.Meta.KeyEpoch
	stored, _ := layout.EncodeSlotsObject(epoch, so)
	mut := func(f func(b []byte)) []byte { c := append([]byte(nil), stored...); f(c); return c }
	cases := map[string][]byte{
		"sealed format byte":  mut(func(b []byte) { b[0] = 1 }),
		"unknown format byte": mut(func(b []byte) { b[0] = 9 }),
		"non-zero padding":    mut(func(b []byte) { b[len(b)-1] = 7 }),
		"header epoch":        mut(func(b []byte) { b[3] ^= 1 }),
		"length past the end": mut(func(b []byte) { b[17], b[18] = 0xff, 0xff }),
		"wrong stored length": stored[:4095],
		"trailing byte":       append(append([]byte(nil), stored...), 0),
		"empty":               nil,
		"cbor damage":         mut(func(b []byte) { b[21] = 0x9f }),
	}
	for name, c := range cases {
		if _, _, err := layout.ParseSlotsObject(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for n := 0; n < len(stored); n++ {
		if _, _, err := layout.ParseSlotsObject(stored[:n]); err == nil {
			t.Fatalf("truncated to %d bytes: accepted", n)
		}
	}
	bad := map[string]func(*layout.SlotsObject){
		"policy":                 func(s *layout.SlotsObject) { s.Meta.Policy = "lax" },
		"store format":           func(s *layout.SlotsObject) { s.Meta.StoreFormat = 2 },
		"epoch not the header's": func(s *layout.SlotsObject) { s.Meta.KeyEpoch = pat(1, 16) },
		"recovery hash":          func(s *layout.SlotsObject) { s.Meta.RecoveryPubHash = pat(1, 32) },
		"hash without key":       func(s *layout.SlotsObject) { s.Meta.RecoveryPub = nil },
		"slot kind":              func(s *layout.SlotsObject) { s.Slots[0].Kind = "magic" },
		"slots unsorted":         func(s *layout.SlotsObject) { s.Slots[0], s.Slots[1] = s.Slots[1], s.Slots[0] },
		"duplicate slot id":      func(s *layout.SlotsObject) { s.Slots[1].ID = s.Slots[0].ID },
		"bound":                  func(s *layout.SlotsObject) { s.Slots[0].Bound = 2 },
		"no slots":               func(s *layout.SlotsObject) { s.Slots = nil },
		"workspace id length":    func(s *layout.SlotsObject) { s.Meta.WorkspaceID = pat(1, 15) },
	}
	for name, f := range bad {
		s := samplePolicySlots("standard")
		f(&s)
		if b, err := layout.EncodeSlotsObject(epoch, s); err == nil {
			if _, _, err := layout.ParseSlotsObject(b); err == nil {
				t.Errorf("%s: encoded and parsed", name)
			}
		}
	}
}

// The slots object is plaintext, decoded from the directory before anything is
// known about it, so its size is bounded: 64 slots (the snapshot limit) of 4 KiB.
//
// spec: SPO-Xlayout-PRE-027
func TestTheSlotsObjectHasAStatedSizeBound(t *testing.T) {
	if layout.MaxSlotsObject != 256<<10 || !layout.IsBucket(layout.MaxSlotsObject) {
		t.Fatalf("layout.MaxSlotsObject %d", layout.MaxSlotsObject)
	}
	pub := bytes.Repeat([]byte{9}, 32)
	hash := sha256.Sum256(pub)
	meta := layout.Meta{WorkspaceID: bytes.Repeat([]byte{1}, 16), StoreFormat: 3, Policy: "hardware", KeyEpoch: bytes.Repeat([]byte{2}, 16), EpochMAC: bytes.Repeat([]byte{3}, 32), CreatedAt: 5, RecoveryPub: pub, RecoveryPubHash: hash[:]}
	mk := func(n, factors int) layout.SlotsObject {
		so := layout.SlotsObject{Meta: meta}
		for i := 0; i < n; i++ {
			id := make([]byte, 16)
			id[0], id[1] = byte(i>>8), byte(i)
			so.Slots = append(so.Slots, layout.Slot{ID: id, Kind: "fido2-hmac", KeyCommit: make([]byte, 32), Nonce: make([]byte, 24), WrappedKey: make([]byte, 48), Bound: 1, Factors: bytes.Repeat([]byte{7}, factors)})
		}
		return so
	}
	// the largest legal table (64 slots, 3 KiB of factors each) fits and round-trips
	big := mk(64, 3<<10)
	stored, err := layout.EncodeSlotsObject(meta.KeyEpoch, big)
	if err != nil || len(stored) > layout.MaxSlotsObject {
		t.Fatalf("the largest legal table: %v (%d bytes)", err, len(stored))
	}
	if _, _, err := layout.ParseSlotsObject(stored); err != nil {
		t.Fatal(err)
	}
	// one that would not fit is refused by the writer
	if _, err := layout.EncodeSlotsObject(meta.KeyEpoch, mk(64, 4<<10)); err == nil {
		t.Fatal("a slots object above the bound was written")
	}
	// and by the reader before it decodes anything: a 4 MiB object of nils
	huge := make([]byte, layout.MaxBucket)
	huge[0] = layout.FormatSlots
	copy(huge[1:], meta.KeyEpoch)
	n := layout.MaxBucket - layout.HeaderSize - 4
	binary.BigEndian.PutUint32(huge[layout.HeaderSize:], uint32(n))
	body := huge[layout.HeaderSize+4:]
	body[0] = 0x83 // array(3)
	body[1] = 0x6b // "spo/slots/1"
	copy(body[2:], "spo/slots/1")
	body[13] = 0x80
	body[14] = 0x9a // an array of a million nils
	binary.BigEndian.PutUint32(body[15:], 1_000_000)
	for i := 19; i < 19+1_000_000 && i < len(body); i++ {
		body[i] = 0xf6
	}
	var perr error
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	_, _, perr = layout.ParseSlotsObject(huge)
	runtime.ReadMemStats(&b)
	if perr == nil || !strings.Contains(perr.Error(), "larger than") {
		t.Fatalf("%v", perr)
	}
	if grew := b.TotalAlloc - a.TotalAlloc; grew > 1<<20 {
		t.Errorf("%d bytes allocated to refuse an oversized slots object", grew)
	}
}
