package objmailbox

import (
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// The key of an entry is the directory store's entry name under
// relays/<node key>/mailbox/<recipient>/, followed by the put's nonce; it is
// in the client's alphabet, it round-trips, its order is arrival order, two
// puts of the same entry at the same arrival have two keys, and anything that
// deviates is refused.
//
// spec: SPO-Xobjstore-IF-701, SPO-Xobjstore-SEC-701, SPO-Xobjstore-OUT-707
func TestEntryKeys(t *testing.T) {
	p := mailboxPrefix(testNode)
	if p != "relays/"+testNode+"/mailbox/" {
		t.Fatalf("prefix %q", p)
	}
	r, x := fp(0xA1), fp(0x0B)
	mid := mailbox.HashOf([]byte("m"))
	const nonce = 0x0123456789abcdef
	k := entryKey(p, r, 1_700_000_000, mid, x, nonce)
	if !s3client.ValidKey(k) || len(k) != len(p)+entryLen || !strings.HasSuffix(k, "-0123456789abcdef") {
		t.Fatalf("%q is not a valid key of the expected length", k)
	}
	gr, ga, gm, gx, gn, err := parseKey(p, k)
	if err != nil || gr != r || ga != 1_700_000_000 || gm != mid || gx != x || gn != nonce {
		t.Fatalf("parse = %v %v %v %v %x %v", gr, ga, gm, gx, gn, err)
	}
	if a, b := entryKey(p, r, 9, mid, x, ^uint64(0)), entryKey(p, r, 10, mid, x, 0); a >= b {
		t.Fatal("key order is not arrival order")
	}
	if entryKey(p, r, 9, mid, x, 1) == entryKey(p, r, 9, mid, x, 2) {
		t.Fatal("two nonces give one key")
	}
	if ka, kb := entryKey(p, r, mailbox.MaxTime, mid, x, ^uint64(0)), entryKey(p, r, 0, mid, x, 0); !s3client.ValidKey(ka) || !s3client.ValidKey(kb) {
		t.Fatal("an arrival or a nonce at a bound gives an invalid key")
	}
	for _, bad := range []string{
		"", p, k[:len(k)-1], k + "0", k + "\n", strings.ToUpper(k[:len(p)]) + k[len(p):],
		strings.Replace(k, "/", "-", strings.Count(k, "/")), "relays/" + strings.Repeat("cd", 32) + "/mailbox/" + k[len(p):],
		p + strings.Replace(k[len(p):], "a1", "A1", 1), p + strings.Replace(k[len(p):], "0", "x", 1),
		p + k[len(p):len(p)+41] + "9" + k[len(p)+42:len(p)+61] + "_" + k[len(p)+62:],
		p + k[len(p):len(p)+41] + "99999999999999999999" + k[len(p)+61:],
		k[:len(k)-nonceLen-1],                             // the key without a nonce (the directory store's name)
		k[:len(k)-nonceLen-1] + "_" + k[len(k)-nonceLen:], // another separator before the nonce
		k[:len(k)-nonceLen] + "0123456789ABCDEF",          // an upper-case nonce
	} {
		if _, _, _, _, _, err := parseKey(p, bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	for _, n := range []string{testNode, strings.Repeat("0", 64)} {
		if !validNodeKey(n) {
			t.Errorf("%q refused", n)
		}
	}
	for _, n := range []string{"", strings.Repeat("A", 64), strings.Repeat("0", 63), strings.Repeat("0", 65), strings.Repeat("g", 64)} {
		if validNodeKey(n) {
			t.Errorf("%q accepted", n)
		}
	}
}

// The key decoder never panics and accepts only what it would write.
//
// spec: SPO-Xobjstore-SEC-701
func FuzzParseKey(f *testing.F) {
	p := mailboxPrefix(testNode)
	f.Add(entryKey(p, party.Fingerprint{1}, 1_700_000_000, mailbox.Hash{2}, party.Fingerprint{3}, 4))
	f.Add(p + "x")
	f.Add(entryKey(p, party.Fingerprint{}, 0, mailbox.Hash{}, party.Fingerprint{}, ^uint64(0)) + "/")
	f.Fuzz(func(t *testing.T, key string) {
		r, a, m, x, n, err := parseKey(p, key)
		if err != nil {
			return
		}
		if got := entryKey(p, r, a, m, x, n); got != key {
			t.Fatalf("%q decodes to %v %d %v %v %x, which encodes as %q", key, r, a, m, x, n, got)
		}
		if !s3client.ValidKey(key) {
			t.Fatalf("%q decoded but is outside the client's alphabet", key)
		}
	})
}
