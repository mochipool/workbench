package mailbox_test

import (
	"errors"
	"reflect"
	"testing"

	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
)

// The canonical form of the expected-sender list: strictly ascending bytes, no
// duplicates, at most 64. The ADR names no order; this is the choice.
//
// spec: SPO-Xmailbox-OUT-054
func TestCanonicalSenders(t *testing.T) {
	in := []mailbox.WalletKey{wk(30), wk(10), wk(20), wk(10), wk(30)}
	orig := append([]mailbox.WalletKey{}, in...)
	got, err := mailbox.CanonicalSenders(in)
	if err != nil {
		t.Fatal(err)
	}
	if want := []mailbox.WalletKey{wk(10), wk(20), wk(30)}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if !reflect.DeepEqual(in, orig) {
		t.Error("the input was changed")
	}
	if &got[0] == &in[0] {
		t.Error("the result aliases the input")
	}
	// Order is by bytes from the first: a difference only in the last byte.
	a, b := wk(1), wk(1)
	a[27], b[27] = 9, 3
	if got, _ := mailbox.CanonicalSenders([]mailbox.WalletKey{a, b}); !reflect.DeepEqual(got, []mailbox.WalletKey{b, a}) {
		t.Errorf("last byte order: %v", got)
	}
	a, b = wk(1), wk(1)
	a[0], b[0] = 9, 3
	b[27] = 200
	if got, _ := mailbox.CanonicalSenders([]mailbox.WalletKey{a, b}); !reflect.DeepEqual(got, []mailbox.WalletKey{b, a}) {
		t.Errorf("first byte order: %v", got)
	}
	// Empty and nil are an empty list.
	for _, l := range [][]mailbox.WalletKey{nil, {}} {
		if got, err := mailbox.CanonicalSenders(l); err != nil || len(got) != 0 {
			t.Errorf("%v: %v, %v", l, got, err)
		}
	}
	// 64 distinct are the bound; 65 are refused; 65 with a repeat are 64.
	var l []mailbox.WalletKey
	for i := 0; i < 64; i++ {
		l = append(l, wk(byte(200-i)))
	}
	if got, err := mailbox.CanonicalSenders(l); err != nil || len(got) != 64 {
		t.Errorf("64 senders: %d, %v", len(got), err)
	}
	l65 := append(append([]mailbox.WalletKey{}, l...), wk(1))
	if _, err := mailbox.CanonicalSenders(l65); !errors.Is(err, mailbox.ErrRange) {
		t.Errorf("65 senders: %v", err)
	}
	if got, err := mailbox.CanonicalSenders(append(append([]mailbox.WalletKey{}, l...), l[0])); err != nil || len(got) != 64 {
		t.Errorf("64 senders and a repeat: %d, %v", len(got), err)
	}
	// An input far over the bound is refused without being sorted to the end.
	huge := make([]mailbox.WalletKey, 100000)
	if _, err := mailbox.CanonicalSenders(huge); err != nil {
		// 100000 equal keys are one sender.
		t.Errorf("100000 equal keys: %v", err)
	}
}

// spec: SPO-Xmailbox-OUT-054
func TestSendersHash(t *testing.T) {
	list := []mailbox.WalletKey{wk(10), wk(20)}
	// By hand: an array of two byte strings of 28 bytes (0x58 0x1c).
	enc := []byte{0x82}
	for _, k := range list {
		enc = append(enc, 0x58, 28)
		enc = append(enc, k[:]...)
	}
	want := blake2b.Sum256(enc)
	got, err := mailbox.SendersHash(list)
	if err != nil || got != want {
		t.Fatalf("got %x, %v, want %x", got, err, want)
	}
	// The empty list is the hash of the empty array, 0x80.
	if got, err := mailbox.SendersHash(nil); err != nil || got != blake2b.Sum256([]byte{0x80}) {
		t.Errorf("the empty list: %x, %v", got, err)
	}
	// A different list, order or key is a different hash.
	for name, l := range map[string][]mailbox.WalletKey{
		"another key":   {wk(10), wk(21)},
		"one more":      {wk(10), wk(20), wk(30)},
		"one fewer":     {wk(10)},
		"first changed": {wk(11), wk(20)},
	} {
		if h, err := mailbox.SendersHash(l); err != nil || h == want {
			t.Errorf("%s: %x, %v", name, h, err)
		}
	}
	// A list that is not canonical has no hash.
	for name, l := range map[string][]mailbox.WalletKey{
		"unsorted": {wk(20), wk(10)}, "repeated": {wk(10), wk(10)}, "repeated apart": {wk(10), wk(20), wk(10)},
	} {
		if _, err := mailbox.SendersHash(l); !errors.Is(err, mailbox.ErrRange) {
			t.Errorf("%s: %v", name, err)
		}
	}
	var l []mailbox.WalletKey
	for i := 0; i < 65; i++ {
		l = append(l, wk(byte(i)))
	}
	if _, err := mailbox.SendersHash(l); !errors.Is(err, mailbox.ErrRange) {
		t.Errorf("65 senders: %v", err)
	}
	if _, err := mailbox.SendersHash(l[:64]); err != nil {
		t.Errorf("64 senders: %v", err)
	}
	// The hash of what CanonicalSenders returns always exists.
	c, _ := mailbox.CanonicalSenders([]mailbox.WalletKey{wk(5), wk(1), wk(3)})
	if _, err := mailbox.SendersHash(c); err != nil {
		t.Error(err)
	}
}
