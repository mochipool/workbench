package mailbox_test

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
)

// spec: SPO-Xmailbox-OUT-049, SPO-Xmailbox-INV-029
func TestEveryV2FrameRoundTrips(t *testing.T) {
	for _, s := range samplesV2() {
		b := mustEncodeV(t, 2, s.m)
		got, err := decodeIn(s.w, b)
		if err != nil {
			t.Fatalf("%T: decode: %v", s.m, err)
		}
		if !reflect.DeepEqual(got, s.m) {
			t.Errorf("%T: got %#v, want %#v", s.m, got, s.m)
		}
		if again := mustEncodeV(t, 2, got); !bytes.Equal(again, b) {
			t.Errorf("%T: re-encode differs", s.m)
		}
	}
}

// The shapes of ADR 0014 decision 7, written out by hand.
//
// spec: SPO-Xmailbox-OUT-049
func TestV2FrameShapes(t *testing.T) {
	h := hash(5)
	cases := []struct {
		m    mailbox.Message
		want []byte
	}{
		{mailbox.AuthV2{Fingerprint: fp(3), Signature: sig(4), Keys: mailbox.DeviceKeys{Ed25519: edk(5), X25519: xk(6)}, Sign1: bs(10, 7), Key: bs(5, 8), Senders: []mailbox.WalletKey{wk(1), wk(2)}},
			cbor(t, 1, 2, fpb(3), sigb(4), []any{edb(5), xkb(6), bs(10, 7), bs(5, 8)}, []any{wkb(1), wkb(2)})},
		{mailbox.AuthV2{Fingerprint: fp(3), Signature: sig(4), Keys: mailbox.DeviceKeys{Ed25519: edk(5), X25519: xk(6)}, Sign1: bs(10, 7), Key: bs(5, 8)},
			cbor(t, 1, 2, fpb(3), sigb(4), []any{edb(5), xkb(6), bs(10, 7), bs(5, 8)}, []any{})},
		{mailbox.AuthOKV2{MaxEnvelope: 10, MaxEntries: 11, MaxBytes: 12, RetentionSeconds: 13, Until: 14},
			cbor(t, 2, 2, 10, 11, 12, 13, 14)},
		{mailbox.PutV2{RequestID: 7, WalletKey: wk(3), To: fp(4), Mid: h, Size: 99},
			cbor(t, 3, 7, wkb(3), fpb(4), h[:], 99)},
		{mailbox.PutResult{RequestID: 7, Status: mailbox.StatusUnbound}, cbor(t, 4, 7, 8)},
		{mailbox.Error{Code: mailbox.CodeNotAllowed}, cbor(t, 9, 6)},
		{mailbox.Error{Code: mailbox.CodeBinding}, cbor(t, 9, 7)},
		{mailbox.RevokeByDevice{RequestID: 3, Keys: mailbox.DeviceKeys{Ed25519: edk(5), X25519: xk(6)}, NotBefore: 1700000000, Signature: sig(9)},
			cbor(t, 10, 3, 0, edb(5), xkb(6), 1700000000, sigb(9))},
		{mailbox.RevokeByWallet{RequestID: 4, Sign1: bs(10, 3), Key: bs(5, 4)},
			cbor(t, 10, 4, 1, bs(10, 3), bs(5, 4))},
		{mailbox.RevokeResult{RequestID: 3, Status: mailbox.RevokeRecorded}, cbor(t, 11, 3, 0)},
		{mailbox.RevokeResult{RequestID: 3, Status: mailbox.RevokeRefused}, cbor(t, 11, 3, 2)},
	}
	for _, c := range cases {
		if got := mustEncodeV(t, 2, c.m); !bytes.Equal(got, c.want) {
			t.Errorf("%T: got %x, want %x", c.m, got, c.want)
		}
	}
	if mailbox.MsgRevoke != 10 || mailbox.MsgRevokeResult != 11 {
		t.Error("message type numbers")
	}
	if mailbox.StatusUnbound != 8 || mailbox.CodeNotAllowed != 6 || mailbox.CodeBinding != 7 {
		t.Error("status and code numbers")
	}
	if mailbox.RevokeRecorded != 0 || mailbox.RevokeRefused != 2 {
		t.Error("revoke status numbers")
	}
}

// Every frame of the protocol encodes in version 2 and in no other: EncodeV
// refuses every other version number, including the retired 1. (The round trips
// and the shapes are above; TestOnlyVersionTwoIsWritten has the numbers.)
//
// spec: SPO-Xmailbox-OUT-052
func TestEveryFrameEncodesInVersionTwoOnly(t *testing.T) {
	for _, m := range samples() {
		if _, err := mailbox.EncodeV(2, m); err != nil {
			t.Errorf("%T in version 2: %v", m, err)
		}
		for _, v := range []uint{0, 1, 3, 65535} {
			if _, err := mailbox.EncodeV(v, m); !errors.Is(err, mailbox.ErrVersion) {
				t.Errorf("%T: EncodeV(%d): %v", m, v, err)
			}
		}
	}
	if _, err := mailbox.EncodeV(2, nil); err == nil {
		t.Error("a nil message encoded")
	}
}

// Truncations and extensions of every version 2 frame are refused.
//
// spec: SPO-Xmailbox-PRE-003, SPO-Xmailbox-INV-029
func TestV2DecodeRefusesEveryTruncationAndExtension(t *testing.T) {
	for _, s := range samplesV2() {
		b := mustEncodeV(t, 2, s.m)
		for i := 0; i < len(b); i++ {
			if _, err := decodeIn(s.w, b[:i]); err == nil {
				t.Fatalf("%T cut at %d decoded", s.m, i)
			}
		}
		for _, extra := range []byte{0x00, 0xff, 0x80} {
			if _, err := decodeIn(s.w, append(append([]byte{}, b...), extra)); err == nil {
				t.Fatalf("%T plus byte %#x decoded", s.m, extra)
			}
		}
	}
}

// Whatever a single flipped bit decodes to, at any stage and from either side,
// must re-encode to exactly the mutated bytes: nothing non-canonical is ever
// accepted.
//
// spec: SPO-Xmailbox-INV-029, SPO-Xmailbox-PRE-003
func TestV2BitFlipsAreRefusedOrCanonical(t *testing.T) {
	stages := []mailbox.Stage{mailbox.StageV2PreAuth, mailbox.StageV2Authed}
	for _, s := range samplesV2() {
		b := mustEncodeV(t, 2, s.m)
		for i := range b {
			for bit := 0; bit < 8; bit++ {
				c := append([]byte{}, b...)
				c[i] ^= 1 << bit
				for _, st := range stages {
					for _, client := range []bool{true, false} {
						got, err := decodeIn(where{st, client}, c)
						if err != nil {
							continue
						}
						if again, err := reencode(got); err != nil || !bytes.Equal(again, c) {
							t.Fatalf("%T byte %d bit %d stage %v: accepted %x but re-encodes to %x (%v)", s.m, i, bit, st, c, again, err)
						}
					}
				}
			}
		}
	}
}

// Structured mutations of a maximal Auth, the largest frame.
//
// spec: SPO-Xmailbox-INV-029
func TestV2StructuredMutationsOfTheLargestAuth(t *testing.T) {
	b := mustEncodeV(t, 2, maxAuthV2())
	w := where{mailbox.StageV2PreAuth, true}
	// Every byte replaced by every one of a few values, and every byte removed
	// and doubled.
	for i := 0; i < len(b); i += 7 {
		for _, v := range []byte{0x00, 0x01, 0x18, 0x40, 0x58, 0x59, 0x80, 0x98, 0xff} {
			c := append([]byte{}, b...)
			c[i] = v
			if got, err := decodeIn(w, c); err == nil {
				if again, err := reencode(got); err != nil || !bytes.Equal(again, c) {
					t.Fatalf("byte %d = %#x: accepted but re-encodes differently (%v)", i, v, err)
				}
			}
		}
		del := append(append([]byte{}, b[:i]...), b[i+1:]...)
		if _, err := decodeIn(w, del); err == nil {
			t.Fatalf("byte %d removed: decoded", i)
		}
		dup := append(append(append([]byte{}, b[:i+1]...), b[i]), b[i+1:]...)
		if got, err := decodeIn(w, dup); err == nil {
			if again, err := reencode(got); err != nil || !bytes.Equal(again, dup) {
				t.Fatalf("byte %d doubled: accepted but re-encodes differently (%v)", i, err)
			}
		}
	}
}

// The largest Auth is 2726 bytes: under the 4 KiB header bound and under the
// 3 KiB of the ADR, so the bound of 4096 does not move.
//
// spec: SPO-Xmailbox-OUT-049, SPO-Xmailbox-PRE-027
func TestTheLargestAuthFitsTheHeaderBound(t *testing.T) {
	m := maxAuthV2()
	b := mustEncodeV(t, 2, m)
	// By hand: array(6) 1, type 1, version 1, fingerprint 1+20, signature 2+64,
	// binding 1 + (2+32) + (2+32) + (3+512) + (2+128), senders 2 + 64*(2+28).
	want := 1 + 1 + 1 + 21 + 66 + (1 + 34 + 34 + 515 + 130) + (2 + 64*30)
	if len(b) != want || want != 2726 {
		t.Fatalf("the frame is %d bytes, by hand %d", len(b), want)
	}
	if len(b) > 3<<10 || len(b) > mailbox.MaxHeaderFrame {
		t.Errorf("the frame is %d bytes", len(b))
	}
	if got, err := mailbox.DecodeFromClientIn(mailbox.StageV2PreAuth, b); err != nil || !reflect.DeepEqual(got, m) {
		t.Errorf("the largest Auth does not decode: %v", err)
	}
	fr, err := mailbox.AppendFrame(nil, b)
	if err != nil || len(fr) != 4+want {
		t.Errorf("framing: %d, %v", len(fr), err)
	}
}

// Under, at and over every new bound. The over-bound frames are real (a few
// hundred bytes) and the refusal names the bound.
//
// spec: SPO-Xmailbox-PRE-027, SPO-Xmailbox-SEC-040
func TestV2BoundsUnderAtAndOver(t *testing.T) {
	auth := func(sign1, key int, senders []any) []byte {
		return cbor(t, 1, 2, fpb(3), sigb(4), []any{edb(5), xkb(6), bs(sign1, 7), bs(key, 8)}, senders)
	}
	pre := mailbox.StageV2PreAuth
	senders := func(n int) []any {
		var l []any
		for i := 0; i < n; i++ {
			l = append(l, wkb(byte(i)))
		}
		return l
	}
	for _, c := range []struct {
		name string
		b    []byte
		want error // nil: accepted
	}{
		{"sign1 1", auth(1, 1, nil), nil},
		{"sign1 0", auth(0, 1, nil), mailbox.ErrRange},
		{"sign1 511", auth(511, 1, nil), nil},
		{"sign1 512", auth(512, 1, nil), nil},
		{"sign1 513", auth(513, 1, nil), mailbox.ErrRange},
		{"sign1 1000", auth(1000, 1, nil), mailbox.ErrRange},
		{"key 0", auth(1, 0, nil), mailbox.ErrRange},
		{"key 127", auth(1, 127, nil), nil},
		{"key 128", auth(1, 128, nil), nil},
		{"key 129", auth(1, 129, nil), mailbox.ErrRange},
		{"key 500", auth(1, 500, nil), mailbox.ErrRange},
		{"senders 0", auth(1, 1, senders(0)), nil},
		{"senders 63", auth(1, 1, senders(63)), nil},
		{"senders 64", auth(1, 1, senders(64)), nil},
		{"senders 65", auth(1, 1, senders(65)), mailbox.ErrShape},
	} {
		_, err := mailbox.DecodeFromClientIn(pre, c.b)
		if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	// The encoder holds the same bounds.
	enc := func(m mailbox.AuthV2) error { _, err := mailbox.EncodeV(2, m); return err }
	base := func() mailbox.AuthV2 {
		return mailbox.AuthV2{Fingerprint: fp(3), Signature: sig(4), Sign1: bs(1, 1), Key: bs(1, 1)}
	}
	m := base()
	m.Sign1 = bs(513, 1)
	if err := enc(m); !errors.Is(err, mailbox.ErrRange) {
		t.Errorf("encode sign1 513: %v", err)
	}
	m = base()
	m.Sign1 = nil
	if err := enc(m); !errors.Is(err, mailbox.ErrRange) {
		t.Errorf("encode sign1 0: %v", err)
	}
	m = base()
	m.Key = bs(129, 1)
	if err := enc(m); !errors.Is(err, mailbox.ErrRange) {
		t.Errorf("encode key 129: %v", err)
	}
	m = base()
	m.Key = nil
	if err := enc(m); !errors.Is(err, mailbox.ErrRange) {
		t.Errorf("encode key 0: %v", err)
	}
	m = base()
	for i := 0; i < 65; i++ {
		m.Senders = append(m.Senders, wk(byte(i)))
	}
	if err := enc(m); !errors.Is(err, mailbox.ErrRange) {
		t.Errorf("encode 65 senders: %v", err)
	}
	m.Senders = m.Senders[:64]
	if err := enc(m); err != nil {
		t.Errorf("encode 64 senders: %v", err)
	}
	// The wallet revoke carries the same two bounds.
	rev := func(sign1, key int) []byte { return cbor(t, 10, 1, 1, bs(sign1, 3), bs(key, 4)) }
	for _, c := range []struct {
		name       string
		sign1, key int
		want       error
	}{
		{"revoke sign1 512 key 128", 512, 128, nil}, {"revoke sign1 513", 513, 1, mailbox.ErrRange},
		{"revoke key 129", 1, 129, mailbox.ErrRange}, {"revoke sign1 0", 0, 1, mailbox.ErrRange}, {"revoke key 0", 1, 0, mailbox.ErrRange},
	} {
		_, err := mailbox.DecodeFromClientIn(pre, rev(c.sign1, c.key))
		if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	for _, mm := range []mailbox.RevokeByWallet{{RequestID: 1, Sign1: bs(513, 1), Key: bs(1, 1)}, {RequestID: 1, Sign1: bs(1, 1), Key: bs(129, 1)}, {RequestID: 1, Key: bs(1, 1)}, {RequestID: 1, Sign1: bs(1, 1)}} {
		if _, err := mailbox.EncodeV(2, mm); !errors.Is(err, mailbox.ErrRange) {
			t.Errorf("encode revoke sign1 %d key %d: %v", len(mm.Sign1), len(mm.Key), err)
		}
	}
}

// Small frames that claim large sizes are refused before anything of that size
// is allocated.
//
// spec: SPO-Xmailbox-SEC-040
func TestV2DecodeAllocatesNothingForClaimedLengths(t *testing.T) {
	pre := mailbox.StageV2PreAuth
	head := func(items ...[]byte) []byte { // an Auth array of 6 whose last items are given by hand
		out := []byte{0x86, 0x01, 0x02}
		out = append(out, 0x54)
		out = append(out, bs(20, 1)...)
		out = append(out, 0x58, 64)
		out = append(out, bs(64, 1)...)
		for _, it := range items {
			out = append(out, it...)
		}
		return out
	}
	claims := map[string][]byte{
		"sign1 of 4G":     head([]byte{0x84, 0x58, 32}, bs(32, 1), []byte{0x58, 32}, bs(32, 1), []byte{0x5a, 0xff, 0xff, 0xff, 0xff}),
		"sign1 of 2^64-1": head([]byte{0x84, 0x58, 32}, bs(32, 1), []byte{0x58, 32}, bs(32, 1), []byte{0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}),
		"key of 4G":       head([]byte{0x84, 0x58, 32}, bs(32, 1), []byte{0x58, 32}, bs(32, 1), []byte{0x41, 1, 0x5a, 0xff, 0xff, 0xff, 0xff}),
		"senders of 4G":   head([]byte{0x84, 0x58, 32}, bs(32, 1), []byte{0x58, 32}, bs(32, 1), []byte{0x41, 1, 0x41, 1, 0x9a, 0xff, 0xff, 0xff, 0xff}),
		"binding of 4G":   head([]byte{0x9a, 0xff, 0xff, 0xff, 0xff}),
		"sender of 4G":    head([]byte{0x84, 0x58, 32}, bs(32, 1), []byte{0x58, 32}, bs(32, 1), []byte{0x41, 1, 0x41, 1, 0x81, 0x5a, 0xff, 0xff, 0xff, 0xff}),
	}
	for name, b := range claims {
		var err error
		n := allocated(func() { _, err = mailbox.DecodeFromClientIn(pre, b) })
		if err == nil {
			t.Errorf("%s decoded", name)
		}
		if n > 16<<10 {
			t.Errorf("%s: allocated %d bytes for a refused frame", name, n)
		}
	}
	// A wallet revoke and a device revoke likewise.
	for name, b := range map[string][]byte{
		"revoke sign1 of 4G": {0x85, 0x0a, 0x01, 0x01, 0x5a, 0xff, 0xff, 0xff, 0xff},
		"revoke key of 4G":   {0x85, 0x0a, 0x01, 0x01, 0x41, 0x01, 0x5a, 0xff, 0xff, 0xff, 0xff},
		"revoke keys of 4G":  {0x87, 0x0a, 0x01, 0x00, 0x5a, 0xff, 0xff, 0xff, 0xff},
	} {
		var err error
		n := allocated(func() { _, err = mailbox.DecodeFromClientIn(pre, b) })
		if err == nil || n > 16<<10 {
			t.Errorf("%s: %v, %d bytes allocated", name, err, n)
		}
	}
	// A real frame over the sign1 bound is refused for its size, and what it
	// costs is bounded by the frame, not by what it could have claimed.
	over := cbor(t, 1, 2, fpb(3), sigb(4), []any{edb(5), xkb(6), bs(513, 7), bs(1, 8)}, []any{})
	var err error
	n := allocated(func() { _, err = mailbox.DecodeFromClientIn(pre, over) })
	if !errors.Is(err, mailbox.ErrRange) || n > 16<<10 {
		t.Errorf("sign1 513: %v, %d bytes allocated", err, n)
	}
	// A header frame over 4 KiB is refused on its length alone.
	big := make([]byte, mailbox.MaxHeaderFrame+1)
	n = allocated(func() { _, err = mailbox.DecodeFromClientIn(pre, big) })
	if !errors.Is(err, mailbox.ErrFrameSize) || n > 16<<10 {
		t.Errorf("a %d byte frame: %v, %d bytes allocated", len(big), err, n)
	}
	// The largest legitimate Auth costs a bounded amount too.
	ok := mustEncodeV(t, 2, maxAuthV2())
	n = allocated(func() { _, err = mailbox.DecodeFromClientIn(pre, ok) })
	if err != nil || n > 64<<10 {
		t.Errorf("the largest Auth: %v, %d bytes allocated", err, n)
	}
}

// Fields of the wrong kind, length or range in version 2 frames.
//
// spec: SPO-Xmailbox-PRE-028
func TestV2DecodeRefusesBadFields(t *testing.T) {
	h := hash(1)
	pre, authed := mailbox.StageV2PreAuth, mailbox.StageV2Authed
	big := uint64(1) << 32
	senders := []any{wkb(1), wkb(2)}
	binding := []any{edb(5), xkb(6), bs(10, 7), bs(5, 8)}
	cases := []struct {
		name   string
		stage  mailbox.Stage
		client bool
		v      []any
		want   error
	}{
		{"auth ok", pre, true, []any{1, 2, fpb(3), sigb(4), binding, senders}, nil},
		{"auth version 3", pre, true, []any{1, 3, fpb(3), sigb(4), binding, senders}, mailbox.ErrVersion},
		{"auth version 1", pre, true, []any{1, 1, fpb(3), sigb(4), binding, senders}, mailbox.ErrVersion},
		{"auth version 0", pre, true, []any{1, 0, fpb(3), sigb(4), binding, senders}, mailbox.ErrVersion},
		{"auth version text", pre, true, []any{1, "2", fpb(3), sigb(4), binding, senders}, mailbox.ErrMalformed},
		{"auth fingerprint 19", pre, true, []any{1, 2, bs(19, 1), sigb(4), binding, senders}, mailbox.ErrMalformed},
		{"auth fingerprint 21", pre, true, []any{1, 2, bs(21, 1), sigb(4), binding, senders}, mailbox.ErrMalformed},
		{"auth signature 63", pre, true, []any{1, 2, fpb(3), bs(63, 1), binding, senders}, mailbox.ErrMalformed},
		{"auth signature 65", pre, true, []any{1, 2, fpb(3), bs(65, 1), binding, senders}, mailbox.ErrMalformed},
		{"auth ed25519 31", pre, true, []any{1, 2, fpb(3), sigb(4), []any{bs(31, 1), xkb(6), bs(10, 7), bs(5, 8)}, senders}, mailbox.ErrMalformed},
		{"auth ed25519 33", pre, true, []any{1, 2, fpb(3), sigb(4), []any{bs(33, 1), xkb(6), bs(10, 7), bs(5, 8)}, senders}, mailbox.ErrMalformed},
		{"auth x25519 31", pre, true, []any{1, 2, fpb(3), sigb(4), []any{edb(5), bs(31, 1), bs(10, 7), bs(5, 8)}, senders}, mailbox.ErrMalformed},
		{"auth x25519 33", pre, true, []any{1, 2, fpb(3), sigb(4), []any{edb(5), bs(33, 1), bs(10, 7), bs(5, 8)}, senders}, mailbox.ErrMalformed},
		{"auth binding of 3", pre, true, []any{1, 2, fpb(3), sigb(4), []any{edb(5), xkb(6), bs(10, 7)}, senders}, mailbox.ErrMalformed},
		{"auth binding of 5", pre, true, []any{1, 2, fpb(3), sigb(4), []any{edb(5), xkb(6), bs(10, 7), bs(5, 8), 1}, senders}, mailbox.ErrMalformed},
		{"auth binding as bytes", pre, true, []any{1, 2, fpb(3), sigb(4), bs(10, 7), senders}, mailbox.ErrMalformed},
		{"auth sign1 as text", pre, true, []any{1, 2, fpb(3), sigb(4), []any{edb(5), xkb(6), "sign1", bs(5, 8)}, senders}, mailbox.ErrMalformed},
		{"auth key as integer", pre, true, []any{1, 2, fpb(3), sigb(4), []any{edb(5), xkb(6), bs(10, 7), 5}, senders}, mailbox.ErrMalformed},
		{"auth senders as bytes", pre, true, []any{1, 2, fpb(3), sigb(4), binding, wkb(1)}, mailbox.ErrMalformed},
		{"auth sender 27", pre, true, []any{1, 2, fpb(3), sigb(4), binding, []any{bs(27, 1)}}, mailbox.ErrMalformed},
		{"auth sender 29", pre, true, []any{1, 2, fpb(3), sigb(4), binding, []any{bs(29, 1)}}, mailbox.ErrMalformed},
		{"auth sender as text", pre, true, []any{1, 2, fpb(3), sigb(4), binding, []any{"abcdefghijklmnopqrstuvwxyz12"}}, mailbox.ErrMalformed},
		{"auth senders unsorted", pre, true, []any{1, 2, fpb(3), sigb(4), binding, []any{wkb(2), wkb(1)}}, mailbox.ErrRange},
		{"auth senders repeated", pre, true, []any{1, 2, fpb(3), sigb(4), binding, []any{wkb(1), wkb(1)}}, mailbox.ErrRange},
		{"auth senders repeated apart", pre, true, []any{1, 2, fpb(3), sigb(4), binding, []any{wkb(1), wkb(2), wkb(1)}}, mailbox.ErrRange},
		{"auth senders last byte order", pre, true, []any{1, 2, fpb(3), sigb(4), binding, []any{append(wkb(1)[:27], 5), append(wkb(1)[:27], 4)}}, mailbox.ErrRange},
		{"auth senders ascending by last byte", pre, true, []any{1, 2, fpb(3), sigb(4), binding, []any{append(wkb(1)[:27], 4), append(wkb(1)[:27], 5)}}, nil},
		{"auth missing field", pre, true, []any{1, 2, fpb(3), sigb(4), binding}, mailbox.ErrMalformed},
		{"auth extra field", pre, true, []any{1, 2, fpb(3), sigb(4), binding, senders, 0}, mailbox.ErrMalformed},
		{"authok ok", pre, false, []any{2, 2, 10, 11, 12, 13, 14}, nil},
		{"authok version 1", pre, false, []any{2, 1, 10, 11, 12, 13, 14}, mailbox.ErrVersion},
		{"authok version 3", pre, false, []any{2, 3, 10, 11, 12, 13, 14}, mailbox.ErrVersion},
		{"authok envelope 0", pre, false, []any{2, 2, 0, 11, 12, 13, 14}, mailbox.ErrRange},
		{"authok entries 257", pre, false, []any{2, 2, 10, 257, 12, 13, 14}, mailbox.ErrRange},
		{"authok bytes 0", pre, false, []any{2, 2, 10, 11, 0, 13, 14}, mailbox.ErrRange},
		{"authok retention 0", pre, false, []any{2, 2, 10, 11, 12, 0, 14}, mailbox.ErrRange},
		{"authok until 0", pre, false, []any{2, 2, 10, 11, 12, 13, 0}, mailbox.ErrRange},
		{"authok until 1", pre, false, []any{2, 2, 10, 11, 12, 13, 1}, nil},
		{"authok until max", pre, false, []any{2, 2, 10, 11, 12, 13, uint64(mailbox.MaxTime)}, nil},
		{"authok until max+1", pre, false, []any{2, 2, 10, 11, 12, 13, uint64(mailbox.MaxTime) + 1}, mailbox.ErrRange},
		{"authok until negative", pre, false, []any{2, 2, 10, 11, 12, 13, -1}, mailbox.ErrMalformed},
		{"authok v1 shape", pre, false, []any{2, 2, 10, 11, 12, 13}, mailbox.ErrMalformed},
		{"put ok", authed, true, []any{3, 7, wkb(3), fpb(4), h[:], 99}, nil},
		{"put id 2^32", authed, true, []any{3, big, wkb(3), fpb(4), h[:], 99}, mailbox.ErrRange},
		{"put key 27", authed, true, []any{3, 7, bs(27, 1), fpb(4), h[:], 99}, mailbox.ErrMalformed},
		{"put key 29", authed, true, []any{3, 7, bs(29, 1), fpb(4), h[:], 99}, mailbox.ErrMalformed},
		{"put key 20", authed, true, []any{3, 7, fpb(3), fpb(4), h[:], 99}, mailbox.ErrMalformed},
		{"put to 28", authed, true, []any{3, 7, wkb(3), wkb(4), h[:], 99}, mailbox.ErrMalformed},
		{"put to 19", authed, true, []any{3, 7, wkb(3), bs(19, 1), h[:], 99}, mailbox.ErrMalformed},
		{"put mid 31", authed, true, []any{3, 7, wkb(3), fpb(4), bs(31, 1), 99}, mailbox.ErrMalformed},
		{"put size 0", authed, true, []any{3, 7, wkb(3), fpb(4), h[:], 0}, mailbox.ErrRange},
		{"put size 1MiB+1", authed, true, []any{3, 7, wkb(3), fpb(4), h[:], mailbox.MaxEnvelopeBytes + 1}, mailbox.ErrRange},
		{"put size 1MiB", authed, true, []any{3, 7, wkb(3), fpb(4), h[:], mailbox.MaxEnvelopeBytes}, nil},
		{"put v1 shape", authed, true, []any{3, 7, fpb(4), h[:], 99}, mailbox.ErrMalformed},
		{"put result status 8", authed, false, []any{4, 7, 8}, nil},
		{"put result status 9", authed, false, []any{4, 7, 9}, mailbox.ErrRange},
		{"put result status 2^32+8", authed, false, []any{4, 7, big + 8}, mailbox.ErrRange},
		{"error code 6", pre, false, []any{9, 6}, nil},
		{"error code 7", authed, false, []any{9, 7}, nil},
		{"error code 8", pre, false, []any{9, 8}, mailbox.ErrRange},
		{"error code 2^32+7", pre, false, []any{9, big + 7}, mailbox.ErrRange},
		{"revoke device ok", pre, true, []any{10, 3, 0, edb(5), xkb(6), 1700000000, sigb(9)}, nil},
		{"revoke device not-before 0", pre, true, []any{10, 3, 0, edb(5), xkb(6), 0, sigb(9)}, nil},
		{"revoke device not-before max", pre, true, []any{10, 3, 0, edb(5), xkb(6), uint64(mailbox.MaxTime), sigb(9)}, nil},
		{"revoke device not-before max+1", pre, true, []any{10, 3, 0, edb(5), xkb(6), uint64(mailbox.MaxTime) + 1, sigb(9)}, mailbox.ErrRange},
		{"revoke device not-before negative", pre, true, []any{10, 3, 0, edb(5), xkb(6), -1, sigb(9)}, mailbox.ErrMalformed},
		{"revoke device id 2^32", pre, true, []any{10, big, 0, edb(5), xkb(6), 5, sigb(9)}, mailbox.ErrRange},
		{"revoke device ed25519 31", pre, true, []any{10, 3, 0, bs(31, 1), xkb(6), 5, sigb(9)}, mailbox.ErrMalformed},
		{"revoke device x25519 33", pre, true, []any{10, 3, 0, edb(5), bs(33, 1), 5, sigb(9)}, mailbox.ErrMalformed},
		{"revoke device signature 63", pre, true, []any{10, 3, 0, edb(5), xkb(6), 5, bs(63, 1)}, mailbox.ErrMalformed},
		{"revoke device signature 65", pre, true, []any{10, 3, 0, edb(5), xkb(6), 5, bs(65, 1)}, mailbox.ErrMalformed},
		{"revoke device extra field", pre, true, []any{10, 3, 0, edb(5), xkb(6), 5, sigb(9), 0}, mailbox.ErrMalformed},
		{"revoke device missing field", pre, true, []any{10, 3, 0, edb(5), xkb(6), 5}, mailbox.ErrMalformed},
		{"revoke device with the wallet arity", pre, true, []any{10, 3, 0, bs(10, 3), bs(5, 4)}, mailbox.ErrMalformed},
		{"revoke wallet ok", pre, true, []any{10, 4, 1, bs(10, 3), bs(5, 4)}, nil},
		{"revoke wallet with the device arity", pre, true, []any{10, 3, 1, edb(5), xkb(6), 5, sigb(9)}, mailbox.ErrMalformed},
		{"revoke wallet extra field", pre, true, []any{10, 4, 1, bs(10, 3), bs(5, 4), 0}, mailbox.ErrMalformed},
		{"revoke wallet sign1 as text", pre, true, []any{10, 4, 1, "sign1", bs(5, 4)}, mailbox.ErrMalformed},
		{"revoke wallet key as integer", pre, true, []any{10, 4, 1, bs(10, 3), 4}, mailbox.ErrMalformed},
		{"revoke wallet id 2^32", pre, true, []any{10, big, 1, bs(10, 3), bs(5, 4)}, mailbox.ErrRange},
		{"revoke kind 2", pre, true, []any{10, 3, 2, bs(10, 3), bs(5, 4)}, mailbox.ErrRange},
		{"revoke kind 255", pre, true, []any{10, 3, 255, bs(10, 3), bs(5, 4)}, mailbox.ErrRange},
		{"revoke kind 2^32", pre, true, []any{10, 3, big, bs(10, 3), bs(5, 4)}, mailbox.ErrRange},
		{"revoke kind as text", pre, true, []any{10, 3, "0", bs(10, 3), bs(5, 4)}, mailbox.ErrMalformed},
		{"revoke kind as bytes", pre, true, []any{10, 3, []byte{1}, bs(10, 3), bs(5, 4)}, mailbox.ErrMalformed},
		{"revoke without a kind", pre, true, []any{10, 3}, mailbox.ErrMalformed},
		{"revoke without an id", pre, true, []any{10}, mailbox.ErrMalformed},
		{"revoke id as text", pre, true, []any{10, "3", 1, bs(10, 3), bs(5, 4)}, mailbox.ErrMalformed},
		{"revoke result recorded", pre, false, []any{11, 3, 0}, nil},
		{"revoke result refused", pre, false, []any{11, 3, 2}, nil},
		{"revoke result status 1", pre, false, []any{11, 3, 1}, mailbox.ErrRange},
		{"revoke result status 3", pre, false, []any{11, 3, 3}, mailbox.ErrRange},
		{"revoke result status 2^32", pre, false, []any{11, 3, big}, mailbox.ErrRange},
		{"revoke result id 2^32", pre, false, []any{11, big, 0}, mailbox.ErrRange},
		{"revoke result missing status", pre, false, []any{11, 3}, mailbox.ErrMalformed},
		{"revoke result extra field", pre, false, []any{11, 3, 0, 0}, mailbox.ErrMalformed},
	}
	for _, c := range cases {
		_, err := decodeIn(where{c.stage, c.client}, cbor(t, c.v...))
		if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	// The same range checks hold when encoding.
	for name, m := range map[string]mailbox.Message{
		"put size 0":              mailbox.PutV2{Size: 0},
		"put size 1MiB+1":         mailbox.PutV2{Size: mailbox.MaxEnvelopeBytes + 1},
		"authok until max+1":      mailbox.AuthOKV2{MaxEnvelope: 1, MaxEntries: 1, MaxBytes: 1, RetentionSeconds: 1, Until: mailbox.MaxTime + 1},
		"authok until negative":   mailbox.AuthOKV2{MaxEnvelope: 1, MaxEntries: 1, MaxBytes: 1, RetentionSeconds: 1, Until: -1},
		"authok until 0":          mailbox.AuthOKV2{MaxEnvelope: 1, MaxEntries: 1, MaxBytes: 1, RetentionSeconds: 1, Until: 0},
		"authok zero":             mailbox.AuthOKV2{},
		"authok entries 257":      mailbox.AuthOKV2{MaxEnvelope: 1, MaxEntries: 257, MaxBytes: 1, RetentionSeconds: 1},
		"status 9":                mailbox.PutResult{Status: 9},
		"code 8":                  mailbox.Error{Code: 8},
		"revoke result 1":         mailbox.RevokeResult{Status: 1},
		"revoke result 3":         mailbox.RevokeResult{Status: 3},
		"device not-before -1":    mailbox.RevokeByDevice{NotBefore: -1},
		"device not-before max+1": mailbox.RevokeByDevice{NotBefore: mailbox.MaxTime + 1},
	} {
		if _, err := mailbox.EncodeV(2, m); err == nil {
			t.Errorf("%s encoded", name)
		}
	}
	for name, m := range map[string]mailbox.Message{
		"device not-before 0":   mailbox.RevokeByDevice{NotBefore: 0},
		"device not-before max": mailbox.RevokeByDevice{NotBefore: mailbox.MaxTime},
		"authok until 1":        mailbox.AuthOKV2{MaxEnvelope: 1, MaxEntries: 1, MaxBytes: 1, RetentionSeconds: 1, Until: 1},
		"authok until max":      mailbox.AuthOKV2{MaxEnvelope: 1, MaxEntries: 1, MaxBytes: 1, RetentionSeconds: 1, Until: mailbox.MaxTime},
	} {
		if _, err := mailbox.EncodeV(2, m); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Unsorted and repeated senders do not encode either.
	for name, l := range map[string][]mailbox.WalletKey{
		"unsorted": {wk(2), wk(1)}, "repeated": {wk(1), wk(1)}, "repeated apart": {wk(1), wk(2), wk(1)},
	} {
		if _, err := mailbox.EncodeV(2, mailbox.AuthV2{Fingerprint: fp(3), Sign1: bs(1, 1), Key: bs(1, 1), Senders: l}); !errors.Is(err, mailbox.ErrRange) {
			t.Errorf("senders %s: %v", name, err)
		}
	}
}

// The new constructors.
//
// spec: SPO-Xmailbox-OUT-049
func TestPutV2Constructors(t *testing.T) {
	env := []byte("a sealed envelope")
	p, err := mailbox.NewPutV2Of(5, wk(3), fp(4), env)
	if err != nil || p.RequestID != 5 || p.WalletKey != wk(3) || p.To != fp(4) || p.Mid != mailbox.HashOf(env) || p.Size != uint32(len(env)) {
		t.Fatalf("%+v, %v", p, err)
	}
	if _, err := mailbox.EncodeV(2, p); err != nil {
		t.Errorf("the put does not encode: %v", err)
	}
	for name, e := range map[string][]byte{"nil": nil, "empty": {}, "too large": make([]byte, mailbox.MaxEnvelopeBytes+1)} {
		if _, err := mailbox.NewPutV2Of(1, wk(3), fp(4), e); !errors.Is(err, mailbox.ErrRange) {
			t.Errorf("%s: %v", name, err)
		}
	}
	h := hash(3)
	q, err := mailbox.NewPutV2(6, wk(3), fp(4), h, 1000)
	if err != nil || q != (mailbox.PutV2{RequestID: 6, WalletKey: wk(3), To: fp(4), Mid: h, Size: 1000}) {
		t.Errorf("%+v, %v", q, err)
	}
	for _, size := range []uint32{0, mailbox.MaxEnvelopeBytes + 1, 1<<32 - 1} {
		if _, err := mailbox.NewPutV2(6, wk(3), fp(4), h, size); !errors.Is(err, mailbox.ErrRange) {
			t.Errorf("size %d: %v", size, err)
		}
	}
	for _, size := range []uint32{1, mailbox.MaxEnvelopeBytes} {
		if _, err := mailbox.NewPutV2(6, wk(3), fp(4), h, size); err != nil {
			t.Errorf("size %d: %v", size, err)
		}
	}
}

// The status and code ranges of the one version.
//
// spec: SPO-Xmailbox-OUT-055
func TestStatusAndCodeRanges(t *testing.T) {
	for s := mailbox.Status(0); s <= 8; s++ {
		if !s.Valid() || !s.ValidIn(2) || s.ValidIn(1) {
			t.Errorf("status %d", s)
		}
	}
	if mailbox.StatusUnbound != 8 {
		t.Error("status 8 is unbound")
	}
	for _, s := range []mailbox.Status{9, 100, 1 << 40} {
		if s.Valid() || s.ValidIn(2) {
			t.Errorf("status %d is valid", s)
		}
	}
	for c := mailbox.Code(0); c <= 7; c++ {
		if !c.Valid() || !c.ValidIn(2) || c.ValidIn(1) {
			t.Errorf("code %d", c)
		}
	}
	for _, c := range []mailbox.Code{8, 100, 1 << 40} {
		if c.Valid() || c.ValidIn(2) {
			t.Errorf("code %d is valid", c)
		}
	}
	for _, v := range []uint{0, 1, 3} {
		if mailbox.Status(0).ValidIn(v) || mailbox.Code(0).ValidIn(v) {
			t.Errorf("version %d knows a status or code", v)
		}
	}
	if !mailbox.RevokeRecorded.Valid() || !mailbox.RevokeRefused.Valid() || mailbox.RevokeStatus(1).Valid() || mailbox.RevokeStatus(3).Valid() {
		t.Error("revoke statuses are 0 and 2")
	}
	// PutResult and Error carry the range through the decoders, at both stages.
	for _, st := range []mailbox.Stage{mailbox.StageV2PreAuth, mailbox.StageV2Authed} {
		if _, err := mailbox.DecodeFromRelayIn(st, cbor(t, 9, 8)); !errors.Is(err, mailbox.ErrRange) {
			t.Errorf("code 8 at %v: %v", st, err)
		}
		if _, err := mailbox.DecodeFromRelayIn(st, cbor(t, 9, 6)); err != nil {
			t.Errorf("code 6 at %v: %v", st, err)
		}
	}
	if _, err := mailbox.DecodeFromRelayIn(mailbox.StageV2Authed, cbor(t, 4, 7, 9)); !errors.Is(err, mailbox.ErrRange) {
		t.Errorf("status 9: %v", err)
	}
	if _, err := mailbox.DecodeFromRelayIn(mailbox.StageV2Authed, cbor(t, 4, 7, 8)); err != nil {
		t.Errorf("status 8: %v", err)
	}
}
