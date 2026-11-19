package mailbox_test

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
)

// spec: SPO-Xmailbox-OUT-003, SPO-Xmailbox-INV-002
func TestEveryFrameRoundTrips(t *testing.T) {
	for _, m := range samples() {
		b := mustEncode(t, m)
		got, err := mailbox.DecodeAny(b)
		if err != nil {
			t.Fatalf("%T: Decode: %v", m, err)
		}
		if !reflect.DeepEqual(got, m) {
			t.Errorf("%T: got %#v, want %#v", m, got, m)
		}
		if again := mustEncode(t, got); !bytes.Equal(again, b) {
			t.Errorf("%T: re-encode differs", m)
		}
	}
}

// The first array element is the type; the rest is exactly the shape of the table.
//
// spec: SPO-Xmailbox-OUT-003, SPO-Xmailbox-OUT-004
func TestFrameShapes(t *testing.T) {
	h1, h2 := hash(1), hash(2)
	cases := []struct {
		m    mailbox.Message
		want []byte
	}{
		{mailbox.Challenge{Min: 2, Max: 2, Nonce: nonce(1), RelayKey: nk(2), RelayTime: 5},
			cbor(t, 0, 2, 2, bs32(nonce(1)), bs32(nk(2)), 5)},
		{mailbox.AuthOKV2{MaxEnvelope: 10, MaxEntries: 11, MaxBytes: 12, RetentionSeconds: 13, Until: 14},
			cbor(t, 2, 2, 10, 11, 12, 13, 14)},
		{mailbox.PutV2{RequestID: 7, WalletKey: wk(1), To: fp(4), Mid: h1, Size: 99},
			cbor(t, 3, 7, wkb(1), fpb(4), h1[:], 99)},
		{mailbox.PutResult{RequestID: 7, Status: mailbox.StatusFull}, cbor(t, 4, 7, 3)},
		{mailbox.PutResult{RequestID: 7, Status: mailbox.StatusUnbound}, cbor(t, 4, 7, 8)},
		{mailbox.Fetch{RequestID: 1, MaxItems: 16, WaitSeconds: 20}, cbor(t, 5, 1, []byte{}, 16, 20)},
		{mailbox.Fetch{RequestID: 1, After: &h2, MaxItems: 1}, cbor(t, 5, 1, h2[:], 1, 0)},
		{mailbox.Items{RequestID: 2, Entries: []mailbox.Item{{Mid: h1, Size: 3}}, More: true},
			cbor(t, 6, 2, []any{[]any{h1[:], 3}}, true)},
		{mailbox.Ack{RequestID: 3, Mids: []mailbox.Hash{h1, h2}}, cbor(t, 7, 3, []any{h1[:], h2[:]})},
		{mailbox.AckResult{RequestID: 3, Deleted: 2}, cbor(t, 8, 3, 2)},
		{mailbox.Error{Code: mailbox.CodeShuttingDown}, cbor(t, 9, 5)},
		{mailbox.Error{Code: mailbox.CodeBinding}, cbor(t, 9, 7)},
		{mailbox.RevokeResult{RequestID: 3, Status: mailbox.RevokeRefused}, cbor(t, 11, 3, 2)},
	}
	for _, c := range cases {
		if got := mustEncode(t, c.m); !bytes.Equal(got, c.want) {
			t.Errorf("%T: got %x, want %x", c.m, got, c.want)
		}
	}
}

func bs32(a [32]byte) []byte { return a[:] }

// spec: SPO-Xmailbox-PRE-003
func TestDecodeRefusesNonCanonical(t *testing.T) {
	cases := map[string][]byte{
		"non-shortest integer":    {0x83, 0x04, 0x18, 0x07, 0x00},
		"trailing byte":           append(mustEncode(t, mailbox.PutResult{RequestID: 1}), 0x00),
		"indefinite array":        {0x9f, 0x04, 0x07, 0x00, 0xff},
		"tag over the array":      append([]byte{0xc1}, mustEncode(t, mailbox.PutResult{RequestID: 1})...),
		"float item":              {0x83, 0x04, 0xfa, 0, 0, 0, 0, 0x00},
		"indefinite byte string":  append(append([]byte{0x84, 0x05, 0x01, 0x5f}, bs(32, 1)...), 0xff),
		"two items":               append(mustEncode(t, mailbox.PutResult{RequestID: 1}), mustEncode(t, mailbox.PutResult{RequestID: 1})...),
		"trailing after an array": append(mustEncode(t, mailbox.Error{Code: 1}), 0xf6),
	}
	for name, b := range cases {
		_, err := mailbox.DecodeAny(b)
		if !errors.Is(err, mailbox.ErrNotCanonical) {
			t.Errorf("%s: got %v, want ErrNotCanonical", name, err)
		}
	}
}

// spec: SPO-Xmailbox-PRE-003
func TestDecodeRefusesEveryTruncationAndExtension(t *testing.T) {
	for _, m := range samples() {
		b := mustEncode(t, m)
		for i := 0; i < len(b); i++ {
			if _, err := mailbox.DecodeAny(b[:i]); err == nil {
				t.Fatalf("%T cut at %d decoded", m, i)
			}
		}
		for _, extra := range []byte{0x00, 0xff, 0x80} {
			if _, err := mailbox.DecodeAny(append(append([]byte{}, b...), extra)); err == nil {
				t.Fatalf("%T plus byte %#x decoded", m, extra)
			}
		}
	}
}

// Whatever a single flipped bit decodes to must re-encode to exactly the
// mutated bytes: nothing non-canonical is ever accepted.
//
// spec: SPO-Xmailbox-INV-002, SPO-Xmailbox-PRE-003
func TestBitFlipsAreRefusedOrCanonical(t *testing.T) {
	for _, m := range samples() {
		b := mustEncode(t, m)
		for i := range b {
			for bit := 0; bit < 8; bit++ {
				c := append([]byte{}, b...)
				c[i] ^= 1 << bit
				got, err := mailbox.DecodeAny(c)
				if err != nil {
					continue
				}
				if again, err := mailbox.Encode(got); err != nil || !bytes.Equal(again, c) {
					t.Fatalf("%T byte %d bit %d: accepted %x but re-encodes to %x (%v)", m, i, bit, c, again, err)
				}
			}
		}
	}
}

// spec: SPO-Xmailbox-PRE-004
func TestDecodeRefusesUnknownFieldsAndMissingFields(t *testing.T) {
	h := hash(1)
	valid := [][]any{
		{0, 2, 2, nonceb(1), nkb(2), 5},
		{1, 2, fpb(3), sigb(4), []any{edb(5), xkb(6), bs(10, 1), bs(10, 2)}, []any{}},
		{2, 2, 10, 11, 12, 13, 14},
		{3, 7, wkb(1), fpb(4), h[:], 99},
		{4, 7, 0},
		{5, 1, []byte{}, 16, 20},
		{6, 2, []any{}, false},
		{7, 3, []any{h[:]}},
		{8, 3, 2},
		{9, 5},
		{10, 3, 0, edb(5), xkb(6), 5, sigb(4)},
		{10, 3, 1, bs(10, 1), bs(10, 2)},
		{11, 3, 0},
	}
	for _, v := range valid {
		if _, err := mailbox.DecodeAny(cbor(t, v...)); err != nil {
			t.Fatalf("type %v: the valid shape is refused: %v", v[0], err)
		}
		if _, err := mailbox.DecodeAny(cbor(t, append(append([]any{}, v...), 0)...)); !errors.Is(err, mailbox.ErrMalformed) {
			t.Errorf("type %v with an extra field: %v", v[0], err)
		}
		if _, err := mailbox.DecodeAny(cbor(t, v[:len(v)-1]...)); !errors.Is(err, mailbox.ErrMalformed) {
			t.Errorf("type %v with a missing field: %v", v[0], err)
		}
	}
}

// spec: SPO-Xmailbox-PRE-004
func TestDecodeRefusesWrongKinds(t *testing.T) {
	h := hash(1)
	cases := map[string][]any{
		"type as text":        {"0", 2, 2, nonceb(1), nkb(2), 5},
		"type negative":       {-1},
		"type 12":             {12},
		"type 99":             {99},
		"version as bytes":    {1, []byte{2}, fpb(3), sigb(4), []any{}, []any{}},
		"fingerprint as text": {1, 2, "xxxxxxxxxxxxxxxxxxxx", sigb(4), []any{edb(5), xkb(6), bs(1, 1), bs(1, 2)}, []any{}},
		"id negative":         {4, -1, 0},
		"after as text":       {5, 1, "", 16, 20},
		"more as integer":     {6, 2, []any{}, 1},
		"items not array":     {6, 2, h[:], false},
		"item not a pair":     {6, 2, []any{h[:]}, false},
		"item triple":         {6, 2, []any{[]any{h[:], 3, 3}}, false},
		"ack not array":       {7, 3, h[:]},
		"null":                {4, nil, 0},
	}
	for name, v := range cases {
		_, err := mailbox.DecodeAny(cbor(t, v...))
		if err == nil {
			t.Errorf("%s decoded", name)
		}
	}
	if _, err := mailbox.DecodeAny([]byte{0xa0}); !errors.Is(err, mailbox.ErrMalformed) {
		t.Errorf("a map at the top: %v", err)
	}
	if _, err := mailbox.DecodeAny([]byte{0x01}); !errors.Is(err, mailbox.ErrMalformed) {
		t.Errorf("an integer at the top: %v", err)
	}
	if _, err := mailbox.DecodeAny([]byte{0x80}); !errors.Is(err, mailbox.ErrMalformed) {
		t.Errorf("an empty array: %v", err)
	}
	if _, err := mailbox.DecodeAny(cbor(t, 12)); !errors.Is(err, mailbox.ErrUnknownType) {
		t.Errorf("type 12: %v", err)
	}
}

// spec: SPO-Xmailbox-PRE-006
func TestDecodeRefusesWrongLengths(t *testing.T) {
	h := hash(1)
	for _, n := range []int{0, 31, 33} {
		if _, err := mailbox.DecodeAny(cbor(t, 0, 2, 2, bs(n, 1), nkb(2), 5)); !errors.Is(err, mailbox.ErrMalformed) {
			t.Errorf("nonce of %d bytes: %v", n, err)
		}
		if _, err := mailbox.DecodeAny(cbor(t, 0, 2, 2, nonceb(1), bs(n, 1), 5)); !errors.Is(err, mailbox.ErrMalformed) {
			t.Errorf("relay key of %d bytes: %v", n, err)
		}
		if _, err := mailbox.DecodeAny(cbor(t, 3, 7, wkb(1), fpb(4), bs(n, 1), 99)); !errors.Is(err, mailbox.ErrMalformed) {
			t.Errorf("mid of %d bytes: %v", n, err)
		}
		if _, err := mailbox.DecodeAny(cbor(t, 7, 3, []any{bs(n, 1)})); !errors.Is(err, mailbox.ErrMalformed) {
			t.Errorf("ack hash of %d bytes: %v", n, err)
		}
	}
	for _, n := range []int{0, 19, 21} {
		if _, err := mailbox.DecodeAny(cbor(t, 3, 7, wkb(1), bs(n, 1), h[:], 99)); !errors.Is(err, mailbox.ErrMalformed) {
			t.Errorf("to of %d bytes: %v", n, err)
		}
	}
	for _, n := range []int{0, 27, 29} {
		if _, err := mailbox.DecodeAny(cbor(t, 3, 7, bs(n, 1), fpb(4), h[:], 99)); !errors.Is(err, mailbox.ErrMalformed) {
			t.Errorf("wallet key of %d bytes: %v", n, err)
		}
	}
	for _, n := range []int{1, 31, 33} {
		if _, err := mailbox.DecodeAny(cbor(t, 5, 1, bs(n, 1), 16, 20)); !errors.Is(err, mailbox.ErrMalformed) {
			t.Errorf("after of %d bytes: %v", n, err)
		}
	}
}

// spec: SPO-Xmailbox-PRE-005, SPO-Xmailbox-PRE-016, SPO-Xmailbox-OUT-008
func TestDecodeRefusesOutOfRangeValues(t *testing.T) {
	h := hash(1)
	big := uint64(1) << 32
	var seventeen []any
	for i := 0; i < 17; i++ {
		x := hash(byte(i))
		seventeen = append(seventeen, []any{x[:], 1})
	}
	cases := map[string][]any{
		"challenge min 0":         {0, 0, 2, nonceb(1), nkb(2), 5},
		"challenge min above max": {0, 3, 2, nonceb(1), nkb(2), 5},
		"challenge max 65536":     {0, 1, 65536, nonceb(1), nkb(2), 5},
		"challenge time over i64": {0, 2, 2, nonceb(1), nkb(2), uint64(1) << 63},
		"challenge time i64 max":  {0, 2, 2, nonceb(1), nkb(2), uint64(1)<<63 - 1},
		"challenge time bound+1":  {0, 2, 2, nonceb(1), nkb(2), uint64(mailbox.MaxTime) + 1},
		"authok max envelope 0":   {2, 2, 0, 11, 12, 13, 14},
		"authok envelope 1MiB+1":  {2, 2, mailbox.MaxEnvelopeBytes + 1, 11, 12, 13, 14},
		"authok entries 0":        {2, 2, 10, 0, 12, 13, 14},
		"authok entries 257":      {2, 2, 10, 257, 12, 13, 14},
		"authok bytes 0":          {2, 2, 10, 11, 0, 13, 14},
		"authok bytes 64MiB+1":    {2, 2, 10, 11, mailbox.MaxMailboxBytes + 1, 13, 14},
		"authok retention 0":      {2, 2, 10, 11, 12, 0, 14},
		"authok retention 30d+1":  {2, 2, 10, 11, 12, mailbox.MaxRetentionSeconds + 1, 14},
		"put id 2^32":             {3, big, wkb(1), fpb(4), h[:], 99},
		"put size 0":              {3, 7, wkb(1), fpb(4), h[:], 0},
		"put size 1MiB+1":         {3, 7, wkb(1), fpb(4), h[:], mailbox.MaxEnvelopeBytes + 1},
		"put size 2^32":           {3, 7, wkb(1), fpb(4), h[:], big},
		"put result status 9":     {4, 7, 9},
		"fetch max items 0":       {5, 1, []byte{}, 0, 20},
		"fetch max items 17":      {5, 1, []byte{}, 17, 20},
		"fetch wait 21":           {5, 1, []byte{}, 16, 21},
		"items entry size 0":      {6, 2, []any{[]any{h[:], 0}}, false},
		"items entry 1MiB+1":      {6, 2, []any{[]any{h[:], mailbox.MaxEnvelopeBytes + 1}}, false},
		"items more but none":     {6, 2, []any{}, true},
		"ack empty":               {7, 3, []any{}},
		"items 17 entries":        {6, 2, seventeen, true},
		"ack duplicate":           {7, 3, []any{h[:], h[:]}},
		"ackresult 65":            {8, 3, 65},
		"error code 8":            {9, 8},
	}
	for name, v := range cases {
		if _, err := mailbox.DecodeAny(cbor(t, v...)); err == nil {
			t.Errorf("%s decoded", name)
		}
	}
	// 16 items and 64 hashes are the bounds and are accepted.
	var items, acks []any
	for i := 0; i < 16; i++ {
		x := hash(byte(i))
		items = append(items, []any{x[:], 1})
	}
	for i := 0; i < 64; i++ {
		x := hash(byte(i))
		acks = append(acks, x[:])
	}
	if _, err := mailbox.DecodeAny(cbor(t, 6, 2, items, true)); err != nil {
		t.Errorf("16 items: %v", err)
	}
	if _, err := mailbox.DecodeAny(cbor(t, 7, 3, acks)); err != nil {
		t.Errorf("64 hashes: %v", err)
	}
	// Values at their limits are accepted.
	for name, v := range map[string][]any{
		"put size 1":    {3, 7, wkb(1), fpb(4), h[:], 1},
		"put size 1MiB": {3, 7, wkb(1), fpb(4), h[:], mailbox.MaxEnvelopeBytes},
		"put id max":    {3, uint64(1)<<32 - 1, wkb(1), fpb(4), h[:], 1},
		"wait 20":       {5, 1, []byte{}, 16, 20},
		"status 8":      {4, 7, 8},
		"code 7":        {9, 7},
		"ackresult 64":  {8, 3, 64},
		"time bound":    {0, 2, 2, nonceb(1), nkb(2), uint64(mailbox.MaxTime)},
		"time 0":        {0, 2, 2, nonceb(1), nkb(2), 0},
	} {
		if _, err := mailbox.DecodeAny(cbor(t, v...)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The structural bounds apply to what is read, before the typed checks.
//
// spec: SPO-Xmailbox-PRE-004, SPO-Xmailbox-OUT-008
func TestDecodeRefusesStructuralBounds(t *testing.T) {
	deep := cbor(t, 4, 7, []any{[]any{[]any{[]any{0}}}}) // nesting 5
	if _, err := mailbox.DecodeAny(deep); !errors.Is(err, mailbox.ErrShape) {
		t.Errorf("nesting 5: %v", err)
	}
	// An array of 65 items at the top.
	many := make([]any, 65)
	for i := range many {
		many[i] = 0
	}
	if _, err := mailbox.DecodeAny(cbor(t, many...)); !errors.Is(err, mailbox.ErrShape) {
		t.Errorf("array of 66: %v", err)
	}
	hs := make([]any, 65)
	for i := range hs {
		x := hash(byte(i))
		hs[i] = x[:]
	}
	if _, err := mailbox.DecodeAny(cbor(t, 7, 3, hs)); !errors.Is(err, mailbox.ErrShape) {
		t.Errorf("65 hashes: %v", err)
	}
	// A map of 9 pairs (a map of 8 is within the bound and refused by type).
	m9 := []byte{0x84, 0x04, 0x07, 0x00, 0xa9}
	for i := 0; i < 9; i++ {
		m9 = append(m9, byte(i), byte(i))
	}
	if _, err := mailbox.DecodeAny(m9); !errors.Is(err, mailbox.ErrShape) {
		t.Errorf("map of 9 pairs: %v", err)
	}
	m8 := []byte{0x84, 0x04, 0x07, 0x00, 0xa8}
	for i := 0; i < 8; i++ {
		m8 = append(m8, byte(i), byte(i))
	}
	if _, err := mailbox.DecodeAny(m8); errors.Is(err, mailbox.ErrShape) || err == nil {
		t.Errorf("map of 8 pairs: want a type refusal, got %v", err)
	}
	// Nesting 4 is the bound.
	ok4 := cbor(t, 6, 2, []any{[]any{hashb(1), 3}}, false)
	if _, err := mailbox.DecodeAny(ok4); err != nil {
		t.Errorf("nesting 3: %v", err)
	}
	if _, err := mailbox.DecodeAny(cbor(t, 6, 2, []any{[]any{[]any{[]any{}}}}, false)); !errors.Is(err, mailbox.ErrShape) {
		t.Errorf("nesting 5 in items: %v", err)
	}
	if _, err := mailbox.DecodeAny(cbor(t, 6, 2, []any{[]any{[]any{}}}, false)); errors.Is(err, mailbox.ErrShape) {
		t.Errorf("nesting 4 is within the bound: %v", err)
	}
}

// Frames that claim a huge length refuse before anything of that size is
// allocated, and each refusal names the check that made it: the truncated head
// and the string longer than the input are the pre-scan's (the canonical
// decoder would index past the end, or build a value, for them).
//
// spec: SPO-Xmailbox-SEC-003
func TestDecodeAllocatesNothingForClaimedLengths(t *testing.T) {
	claims := map[string][]byte{
		"array of 4G":        {0x9a, 0xff, 0xff, 0xff, 0xff},
		"array of 2^64-1":    {0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"nested array of 4G": {0x84, 0x07, 0x01, 0x9a, 0xff, 0xff, 0xff, 0xff},
		"bytes of 4G":        {0x84, 0x05, 0x01, 0x5a, 0xff, 0xff, 0xff, 0xff},
		"bytes of 2^64-1":    {0x82, 0x01, 0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"text of 4G":         {0x82, 0x01, 0x7a, 0xff, 0xff, 0xff, 0xff},
		"map of 4G":          {0x82, 0x01, 0xba, 0xff, 0xff, 0xff, 0xff},
	}
	for name, b := range claims {
		var err error
		n := allocated(func() { _, err = mailbox.DecodeAny(b) })
		if err == nil {
			t.Errorf("%s decoded", name)
		}
		if n > 16<<10 {
			t.Errorf("%s: allocated %d bytes for a refused frame", name, n)
		}
	}
	// An over-long frame is refused on its length alone.
	big := make([]byte, mailbox.MaxHeaderFrame+1)
	var err error
	n := allocated(func() { _, err = mailbox.DecodeAny(big) })
	if !errors.Is(err, mailbox.ErrFrameSize) || n > 16<<10 {
		t.Errorf("a %d byte frame: %v, %d bytes allocated", len(big), err, n)
	}
	if _, err := mailbox.DecodeAny(nil); !errors.Is(err, mailbox.ErrFrameSize) {
		t.Errorf("empty: %v", err)
	}
	// A frame of 4095 nested arrays: refused at the fifth level by the
	// pre-scan, with an allocation that does not grow with the depth. Without
	// the pre-scan the decoder would build the whole tower.
	deep := append(bs(mailbox.MaxHeaderFrame-1, 0x81), 0x00)
	n = allocated(func() { _, err = mailbox.DecodeAny(deep) })
	if !errors.Is(err, mailbox.ErrShape) || n > 8<<10 {
		t.Errorf("a tower of %d arrays: %v, %d bytes allocated", len(deep), err, n)
	}
	// 4095 one-pair maps likewise.
	deepMap := append(bs(mailbox.MaxHeaderFrame-1, 0xa1), 0x00)
	n = allocated(func() { _, err = mailbox.DecodeAny(deepMap) })
	if !errors.Is(err, mailbox.ErrShape) || n > 8<<10 {
		t.Errorf("a tower of maps: %v, %d bytes allocated", err, n)
	}
}

// The two length checks of the pre-scan (codec.go, scanItem). Without them a
// hostile head indexes past the end of the input, or a claimed string length
// wraps a position to a negative number, before the canonical decoder runs.
// Each input must be refused as not canonical (a truncation) and must not
// panic; the boundary inputs just inside must pass the pre-scan and be refused
// later, as a message, not as a truncation.
//
// spec: SPO-Xmailbox-PRE-003, SPO-Xmailbox-SEC-003
func TestScanShapeLengthChecks(t *testing.T) {
	refused := func(name string, b []byte, want error) {
		t.Helper()
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("%s: panic: %v", name, r)
			}
		}()
		if _, err := mailbox.DecodeAny(b); !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", name, err, want)
		}
	}
	// A head that claims more argument bytes than remain: every width, with
	// zero and with one byte too few.
	for _, c := range []struct {
		info byte
		w    int
	}{{24, 1}, {25, 2}, {26, 4}, {27, 8}} {
		for have := 0; have < c.w; have++ {
			b := append([]byte{0x82, 0x04, 0x00<<5 | c.info}, bs(have, 0)...)
			refused("truncated head width "+string(rune('0'+c.w)), b, mailbox.ErrNotCanonical)
		}
	}
	// A head at the very end with exactly its bytes is not a truncation: the
	// frame is then refused for what it is (a PutResult with 1 field).
	for _, b := range [][]byte{{0x82, 0x04, 0x18, 0x18}, {0x82, 0x04, 0x19, 0x01, 0x00}, {0x82, 0x04, 0x1a, 0, 1, 0, 0}, {0x82, 0x04, 0x1b, 0, 0, 0, 1, 0, 0, 0, 0}} {
		refused("a complete head", b, mailbox.ErrMalformed)
	}
	// The input of the review: a byte string whose length is 0x8000000000000001
	// with the input ending after 1 byte. Its position would wrap negative.
	refused("negative position", []byte{0x83, 0x04, 0x5b, 0x80, 0, 0, 0, 0, 0, 0, 0x01}, mailbox.ErrNotCanonical)
	refused("review input, one byte follows", []byte{0x83, 0x04, 0x5b, 0x80, 0, 0, 0, 0, 0, 0, 0x01, 0x00}, mailbox.ErrNotCanonical)
	// A string longer than what is left: by one, for bytes and for text, and
	// with the length in each width.
	for _, major := range []byte{0x40, 0x60} {
		refused("string longer by one", []byte{0x82, 0x04, major | 3, 'a', 'b'}, mailbox.ErrNotCanonical)
		refused("string 24 longer by one", append([]byte{0x82, 0x04, major | 24, 24}, bs(23, 'a')...), mailbox.ErrNotCanonical)
		refused("string, 4 byte length", append([]byte{0x82, 0x04, major | 26, 0, 0, 1, 0}, bs(255, 'a')...), mailbox.ErrNotCanonical)
	}
	// A string that is exactly what is left passes the pre-scan: the frame is
	// then refused as a message (a PutResult with a string), not as a truncation.
	for _, major := range []byte{0x40, 0x60} {
		refused("string exactly fits", []byte{0x82, 0x04, major | 2, 'a', 'b'}, mailbox.ErrMalformed)
	}
	refused("empty string at the end", []byte{0x82, 0x04, 0x40}, mailbox.ErrMalformed)
}

// spec: SPO-Xmailbox-PRE-005
func TestEncodeRefusesInvalidMessages(t *testing.T) {
	var many []mailbox.Hash
	for i := 0; i <= mailbox.MaxAckHashes; i++ {
		many = append(many, hash(byte(i)))
	}
	var items []mailbox.Item
	for i := 0; i <= mailbox.MaxItemsPerFetch; i++ {
		items = append(items, mailbox.Item{Mid: hash(byte(i)), Size: 1})
	}
	bad := map[string]mailbox.Message{
		"challenge min 0":    mailbox.Challenge{Min: 0, Max: 2},
		"challenge min>max":  mailbox.Challenge{Min: 3, Max: 2},
		"challenge negative": mailbox.Challenge{Min: 2, Max: 2, RelayTime: -1},
		"authok zero":        mailbox.AuthOKV2{},
		"put size 0":         mailbox.PutV2{Size: 0},
		"put size 1MiB+1":    mailbox.PutV2{Size: mailbox.MaxEnvelopeBytes + 1},
		"status 9":           mailbox.PutResult{Status: 9},
		"fetch 0 items":      mailbox.Fetch{MaxItems: 0},
		"fetch 17 items":     mailbox.Fetch{MaxItems: 17},
		"fetch wait 21":      mailbox.Fetch{MaxItems: 1, WaitSeconds: 21},
		"items 17":           mailbox.Items{Entries: items},
		"items size 0":       mailbox.Items{Entries: []mailbox.Item{{Size: 0}}},
		"items more, none":   mailbox.Items{More: true},
		"ack empty":          mailbox.Ack{},
		"ack 65":             mailbox.Ack{Mids: many},
		"ack duplicate":      mailbox.Ack{Mids: []mailbox.Hash{hash(1), hash(1)}},
		"ackresult 65":       mailbox.AckResult{Deleted: 65},
		"error code 8":       mailbox.Error{Code: 8},
		"authok retention":   mailbox.AuthOKV2{MaxEnvelope: 1, MaxEntries: 1, MaxBytes: 1, RetentionSeconds: mailbox.MaxRetentionSeconds + 1, Until: 1},
		"authok entries 257": mailbox.AuthOKV2{MaxEnvelope: 1, MaxEntries: 257, MaxBytes: 1, RetentionSeconds: 1, Until: 1},
		"authok bytes":       mailbox.AuthOKV2{MaxEnvelope: 1, MaxEntries: 1, MaxBytes: mailbox.MaxMailboxBytes + 1, RetentionSeconds: 1, Until: 1},
		"authok envelope":    mailbox.AuthOKV2{MaxEnvelope: mailbox.MaxEnvelopeBytes + 1, MaxEntries: 1, MaxBytes: 1, RetentionSeconds: 1, Until: 1},
		"authok no until":    mailbox.AuthOKV2{MaxEnvelope: 1, MaxEntries: 1, MaxBytes: 1, RetentionSeconds: 1},
	}
	for name, m := range bad {
		if _, err := mailbox.Encode(m); err == nil {
			t.Errorf("%s encoded", name)
		}
	}
	if _, err := mailbox.Encode(nil); !errors.Is(err, mailbox.ErrMalformed) {
		t.Errorf("no message: %v", err)
	}
}

// There is one version: EncodeV writes version 2 and refuses every other number,
// and Encode is EncodeV(2).
//
// spec: SPO-Xmailbox-OUT-052, SPO-Xmailbox-PRE-029
func TestOnlyVersionTwoIsWritten(t *testing.T) {
	m := mailbox.Fetch{RequestID: 1, MaxItems: 1}
	want, err := mailbox.EncodeV(mailbox.Version2, m)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := mailbox.Encode(m); err != nil || !bytes.Equal(got, want) {
		t.Errorf("Encode = %x, %v; want EncodeV(2) = %x", got, err, want)
	}
	for _, v := range []uint{0, 1, 3, 65535, 1 << 20} {
		if b, err := mailbox.EncodeV(v, m); !errors.Is(err, mailbox.ErrVersion) || b != nil {
			t.Errorf("EncodeV(%d) = %x, %v; want ErrVersion", v, b, err)
		}
	}
}

// spec: SPO-Xmailbox-OUT-005
func TestStatusAndCodeValues(t *testing.T) {
	st := []mailbox.Status{mailbox.StatusStored, mailbox.StatusDuplicate, mailbox.StatusRefused, mailbox.StatusFull, mailbox.StatusTooLarge, mailbox.StatusBadHash, mailbox.StatusBusy, mailbox.StatusUnavailable, mailbox.StatusUnbound}
	for i, s := range st {
		if uint(s) != uint(i) || !s.Valid() {
			t.Errorf("status %d is %d", i, s)
		}
	}
	if mailbox.Status(9).Valid() {
		t.Error("status 9 is valid")
	}
	cs := []mailbox.Code{mailbox.CodeVersion, mailbox.CodeAuth, mailbox.CodeProtocol, mailbox.CodeLimit, mailbox.CodeRevoked, mailbox.CodeShuttingDown, mailbox.CodeNotAllowed, mailbox.CodeBinding}
	for i, c := range cs {
		if uint(c) != uint(i) || !c.Valid() {
			t.Errorf("code %d is %d", i, c)
		}
	}
	if mailbox.Code(8).Valid() {
		t.Error("code 8 is valid")
	}
	mt := []mailbox.MsgType{mailbox.MsgChallenge, mailbox.MsgAuth, mailbox.MsgAuthOK, mailbox.MsgPut, mailbox.MsgPutResult, mailbox.MsgFetch, mailbox.MsgItems, mailbox.MsgAck, mailbox.MsgAckResult, mailbox.MsgError, mailbox.MsgRevoke, mailbox.MsgRevokeResult}
	for i, m := range mt {
		if uint(m) != uint(i) {
			t.Errorf("type %d is %d", i, m)
		}
	}
}

// Encoding refuses a relay time outside 0 to MaxTime, as decoding does.
//
// spec: SPO-Xmailbox-PRE-016
func TestEncodeRefusesRelayTimeOutOfRange(t *testing.T) {
	for _, rt := range []int64{-1, mailbox.MaxTime + 1, 1<<63 - 1, -1 << 63} {
		if _, err := mailbox.Encode(mailbox.Challenge{Min: 2, Max: 2, RelayTime: rt}); !errors.Is(err, mailbox.ErrRange) {
			t.Errorf("relay time %d: %v", rt, err)
		}
	}
	for _, rt := range []int64{0, mailbox.MaxTime} {
		if _, err := mailbox.Encode(mailbox.Challenge{Min: 2, Max: 2, RelayTime: rt}); err != nil {
			t.Errorf("relay time %d: %v", rt, err)
		}
	}
}
