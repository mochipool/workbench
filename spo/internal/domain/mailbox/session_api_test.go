package mailbox_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
)

// who may send what, from the table in the spec (SPO-Xmailbox-OUT-018).
var clientSends = map[mailbox.MsgType]bool{
	mailbox.MsgAuth: true, mailbox.MsgPut: true, mailbox.MsgFetch: true, mailbox.MsgAck: true,
}
var relaySends = map[mailbox.MsgType]bool{
	mailbox.MsgChallenge: true, mailbox.MsgAuthOK: true, mailbox.MsgPutResult: true,
	mailbox.MsgItems: true, mailbox.MsgAckResult: true, mailbox.MsgError: true,
}

// Every type is accepted from exactly one side and refused from the other with
// ErrDirection, before its fields are looked at; each sample round-trips
// through the decoder of its side.
//
// spec: SPO-Xmailbox-OUT-018
func TestDirectionTable(t *testing.T) {
	if len(clientSends)+len(relaySends) != 10 {
		t.Fatal("the table does not cover the ten types")
	}
	for _, m := range samples() {
		typ := m.Type()
		frame := mustEncode(t, m)
		fromClient, errC := mailbox.DecodeFromClient(frame)
		fromRelay, errR := mailbox.DecodeFromRelay(frame)
		switch {
		case clientSends[typ] && !relaySends[typ]:
			if errC != nil || !bytes.Equal(mustEncode(t, fromClient), frame) {
				t.Errorf("type %d from the client: %v", typ, errC)
			}
			if !errors.Is(errR, mailbox.ErrDirection) || fromRelay != nil {
				t.Errorf("type %d from the relay: %v", typ, errR)
			}
		case relaySends[typ] && !clientSends[typ]:
			if errR != nil || !bytes.Equal(mustEncode(t, fromRelay), frame) {
				t.Errorf("type %d from the relay: %v", typ, errR)
			}
			if !errors.Is(errC, mailbox.ErrDirection) || fromClient != nil {
				t.Errorf("type %d from the client: %v", typ, errC)
			}
		default:
			t.Errorf("type %d is in neither or both sides of the table", typ)
		}
	}
}

// The direction is decided by the type alone: a frame of a refused type whose
// fields are also wrong is ErrDirection, not a field error; an unknown type is
// ErrUnknownType from both sides.
//
// spec: SPO-Xmailbox-OUT-018, SPO-Xmailbox-PRE-004
func TestDirectionIsDecidedByTheTypeAlone(t *testing.T) {
	for typ := uint64(0); typ <= 9; typ++ {
		junk := cbor(t, typ, "junk")
		_, errC := mailbox.DecodeFromClient(junk)
		_, errR := mailbox.DecodeFromRelay(junk)
		wrong := errC
		if clientSends[mailbox.MsgType(typ)] {
			wrong = errR
			if errors.Is(errC, mailbox.ErrDirection) {
				t.Errorf("type %d junk from its own side: %v", typ, errC)
			}
		} else if errors.Is(errR, mailbox.ErrDirection) {
			t.Errorf("type %d junk from its own side: %v", typ, errR)
		}
		if !errors.Is(wrong, mailbox.ErrDirection) {
			t.Errorf("type %d junk from the wrong side: %v", typ, wrong)
		}
	}
	for _, typ := range []uint64{10, 11, 255, 1 << 32, 1<<32 + 1, 1<<63 + 3, 1<<64 - 1} {
		b := cbor(t, typ)
		if _, err := mailbox.DecodeFromClient(b); !errors.Is(err, mailbox.ErrUnknownType) {
			t.Errorf("type %d from the client: %v", typ, err)
		}
		if _, err := mailbox.DecodeFromRelay(b); !errors.Is(err, mailbox.ErrUnknownType) {
			t.Errorf("type %d from the relay: %v", typ, err)
		}
	}
}

// A type number that equals a real one in its low 32 bits is not that type
// (nothing is truncated on a 32-bit build).
//
// spec: SPO-Xmailbox-OUT-003
func TestTypeNumbersAreNotTruncated(t *testing.T) {
	for _, hi := range []uint64{1 << 32, 1 << 63, 1<<64 - 1 - 9} {
		b := cbor(t, hi+uint64(mailbox.MsgError), uint64(1))
		if _, err := mailbox.DecodeFromRelay(b); !errors.Is(err, mailbox.ErrUnknownType) {
			t.Errorf("%#x: %v", hi+9, err)
		}
	}
	for _, hi := range []uint64{1 << 32, 1 << 63} {
		b := cbor(t, uint64(mailbox.MsgPutResult), uint64(1), hi+uint64(mailbox.StatusStored))
		if _, err := mailbox.DecodeFromRelay(b); !errors.Is(err, mailbox.ErrRange) {
			t.Errorf("status %#x: %v", hi, err)
		}
		b = cbor(t, uint64(mailbox.MsgError), hi+uint64(mailbox.CodeAuth))
		if _, err := mailbox.DecodeFromRelay(b); !errors.Is(err, mailbox.ErrRange) {
			t.Errorf("code %#x: %v", hi, err)
		}
	}
}

// An Items reply with one mid twice is refused when decoding and when
// encoding, whatever the sizes say.
//
// spec: SPO-Xmailbox-PRE-005, SPO-Xmailbox-PRE-015
func TestItemsRefuseARepeatedMid(t *testing.T) {
	a, b := hash(1), hash(2)
	if _, err := mailbox.DecodeFromRelay(cbor(t, 6, 1, []any{[]any{a[:], 10}, []any{b[:], 10}, []any{a[:], 20}}, false)); !errors.Is(err, mailbox.ErrRange) {
		t.Errorf("repeated mid: %v", err)
	}
	if _, err := mailbox.DecodeFromRelay(cbor(t, 6, 1, []any{[]any{a[:], 10}, []any{a[:], 10}}, false)); !errors.Is(err, mailbox.ErrRange) {
		t.Errorf("repeated mid and size: %v", err)
	}
	if _, err := mailbox.DecodeFromRelay(cbor(t, 6, 1, []any{[]any{a[:], 10}, []any{b[:], 10}}, false)); err != nil {
		t.Errorf("two different mids: %v", err)
	}
	if _, err := mailbox.Encode(mailbox.Items{RequestID: 1, Entries: []mailbox.Item{{Mid: a, Size: 1}, {Mid: b, Size: 1}, {Mid: a, Size: 2}}}); !errors.Is(err, mailbox.ErrRange) {
		t.Errorf("encode: %v", err)
	}
	// Only the first and last of 16 entries equal.
	var many []mailbox.Item
	for i := 0; i < mailbox.MaxItemsPerFetch; i++ {
		many = append(many, mailbox.Item{Mid: hash(byte(10 + i)), Size: 1})
	}
	many[15].Mid = many[0].Mid
	if _, err := mailbox.Encode(mailbox.Items{RequestID: 1, Entries: many}); !errors.Is(err, mailbox.ErrRange) {
		t.Errorf("first and last equal: %v", err)
	}
}

// NewPut checks what the package can; NewPutOf cannot be inconsistent.
//
// spec: SPO-Xmailbox-OUT-019
func TestNewPut(t *testing.T) {
	env := []byte("a sealed envelope")
	p, err := mailbox.NewPutOf(5, fp(4), env)
	if err != nil || p.RequestID != 5 || p.To != fp(4) || p.Mid != mailbox.HashOf(env) || p.Size != uint32(len(env)) {
		t.Fatalf("%+v, %v", p, err)
	}
	if _, err := mailbox.Encode(p); err != nil {
		t.Errorf("the put does not encode: %v", err)
	}
	for name, e := range map[string][]byte{"nil": nil, "empty": {}, "too large": make([]byte, mailbox.MaxEnvelopeBytes+1)} {
		if _, err := mailbox.NewPutOf(1, fp(4), e); !errors.Is(err, mailbox.ErrRange) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := mailbox.NewPutOf(1, fp(4), make([]byte, mailbox.MaxEnvelopeBytes)); err != nil {
		t.Errorf("1 MiB: %v", err)
	}
	if _, err := mailbox.NewPutOf(1, fp(4), []byte{1}); err != nil {
		t.Errorf("1 byte: %v", err)
	}
	h := hash(3)
	q, err := mailbox.NewPut(6, fp(4), h, 1000)
	if err != nil || (q != mailbox.Put{RequestID: 6, To: fp(4), Mid: h, Size: 1000}) {
		t.Errorf("%+v, %v", q, err)
	}
	for _, size := range []uint32{0, mailbox.MaxEnvelopeBytes + 1, 1<<32 - 1} {
		if _, err := mailbox.NewPut(6, fp(4), h, size); !errors.Is(err, mailbox.ErrRange) {
			t.Errorf("size %d: %v", size, err)
		}
	}
	for _, size := range []uint32{1, mailbox.MaxEnvelopeBytes} {
		if _, err := mailbox.NewPut(6, fp(4), h, size); err != nil {
			t.Errorf("size %d: %v", size, err)
		}
	}
}
